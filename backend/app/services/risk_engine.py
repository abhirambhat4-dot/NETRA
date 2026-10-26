import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models.authorization import Authorization
from app.models.enums import AuthorizationStatus, Criticality, IncidentState, Severity
from app.models.incident import Incident, IncidentHistory
from app.models.risk_evaluation import RiskEvaluation
from app.schemas.enrichment import EventContext, IncidentContextBundle, ThreatMatchContext
from app.schemas.risk import (
    RiskFactorExplanation,
    RiskScoreResult,
    RiskStateTransition,
)
from app.services.context_enrichment import enrich_incident_context
from app.services.incident_locking import locked_incident_statement, serialized_timestamp

#: The scoring methodology below: weights, normalisations, rounding and thresholds. Change any of them only
#: under a new version. tests/risk_engine_v1_snapshots.json pins risk-v1's numbers and its evidence wording;
#: a wording change that leaves every number unchanged is reviewed against that snapshot, not versioned.
RISK_METHODOLOGY_VERSION = "risk-v1"
#: risk-v2 changes one rule of risk-v1: only OPEN vulnerabilities feed the vulnerability factor. Everything
#: else is identical. tests/test_risk_v2_and_reevaluation.py pins it; every new calculation uses it.
RISK_V2_METHODOLOGY_VERSION = "risk-v2"
#: Vulnerability statuses that count in risk-v2. MITIGATED, ACCEPTED and FALSE_POSITIVE do not; ACCEPTED means
#: the risk was accepted, not that the vulnerability is gone, so the evidence says so.
V2_COUNTED_VULNERABILITY_STATUSES = frozenset({"OPEN"})

FACTOR_WEIGHTS = {
    "asset_criticality": 0.25,
    "vulnerability": 0.20,
    "anomaly": 0.20,
    "detection": 0.15,
    "threat_intelligence": 0.10,
    "attack_context": 0.10,
}

CRITICALITY_VALUES = {
    "LOW": 25.0,
    "MEDIUM": 50.0,
    "HIGH": 75.0,
    "CRITICAL": 100.0,
}

SEVERITY_VALUES = {
    "INFO": 0.0,
    "LOW": 25.0,
    "MEDIUM": 50.0,
    "HIGH": 75.0,
    "CRITICAL": 100.0,
}

# V1 confidence proxy by existing source semantics: signature-based Suricata and
# IOC matches are strong signals; ML anomalies are probabilistic; vulnerability
# scans indicate exposure, not exploitation; manual events are unverified input.
DETECTION_SOURCE_CONFIDENCE = {
    "SURICATA": 85.0,
    "ML_ANOMALY": 70.0,
    "THREAT_INTEL": 80.0,
    "VULNERABILITY_SCAN": 60.0,
    "MANUAL": 50.0,
}
DETECTION_SOURCE_RATIONALE = {
    "SURICATA": "signature-based network alert; strong signal, not confirmed compromise",
    "ML_ANOMALY": "probabilistic anomaly signal",
    "THREAT_INTEL": "indicator/feed-backed detection",
    "VULNERABILITY_SCAN": "asset exposure finding, not evidence of exploitation",
    "MANUAL": "operator-provided signal, not independently corroborated",
}

ATTACK_STAGE_PATTERNS = {
    "reconnaissance": re.compile(r"\b(scan|recon|probe)\b"),
    "authentication": re.compile(r"\b(ssh|auth|authentication|login|brute\s*force|password)\b"),
    "outbound_activity": re.compile(r"\b(outbound|egress|beacon)\b"),
}


def _bounded(value: float) -> float:
    return round(min(100.0, max(0.0, value)), 2)


def _factor(
    normalized_value: float,
    weight: float,
    evidence: list[str],
    reason: str,
) -> RiskFactorExplanation:
    normalized = _bounded(normalized_value)
    return RiskFactorExplanation(
        normalized_value=normalized,
        weight=weight,
        contribution=round(normalized * weight, 2),
        evidence=evidence,
        reason=reason,
    )


def _attack_stages(event: EventContext) -> set[str]:
    text = re.sub(r"[^a-z0-9]+", " ", f"{event.event_type} {event.signature or ''}".lower())
    return {
        stage
        for stage, pattern in ATTACK_STAGE_PATTERNS.items()
        if pattern.search(text)
    }


def _attack_context(events: Iterable[EventContext]) -> tuple[float, list[str], str]:
    linked_events = list(events)
    event_count = len(linked_events)
    event_types = {event.event_type.casefold() for event in linked_events}
    signatures = {
        event.signature.casefold()
        for event in linked_events
        if event.signature is not None and event.signature.strip()
    }
    stages = set().union(*(_attack_stages(event) for event in linked_events)) if linked_events else set()

    related_event_points = min(45, max(0, event_count - 1) * 15)
    diversity_points = min(
        20,
        max(0, len(event_types) - 1) * 10 + max(0, len(signatures) - 1) * 5,
    )
    stage_points = 35 if len(stages) >= 3 else 20 if len(stages) == 2 else 0
    score = min(100, related_event_points + diversity_points + stage_points)
    evidence = [
        f"{event_count} linked events; {max(0, event_count - 1)} related events beyond the first.",
        f"{len(event_types)} distinct event types and {len(signatures)} distinct signatures.",
        f"Recognized event-context stages: {', '.join(sorted(stages)) or 'none'}.",
        (
            f"Points: event count {related_event_points}, signal diversity {diversity_points}, "
            f"stage coverage {stage_points}."
        ),
    ]
    reason = (
        "Attack context adds 15 points per related event beyond the first (cap 45), "
        "10 per additional event type and 5 per additional signature (combined cap 20), "
        "then 20 points for two recognized stages or 35 for all three. It uses no MITRE mapping."
    )
    return float(score), evidence, reason


#: A threat-intelligence match with its combined 0-100 value and how that value was formed.
ScoredMatch = tuple[ThreatMatchContext, float, str]


def _indicator_identity(match: ThreatMatchContext) -> tuple[str, str]:
    """(type, value) as enrichment matches it: IP addresses in canonical form, other values case-folded."""
    if match.indicator_type == "IP":
        try:
            return match.indicator_type, str(ipaddress.ip_address(match.value))
        except ValueError:
            pass
    return match.indicator_type, match.value.casefold()


def _threat_evidence(scored_matches: list[ScoredMatch]) -> list[str]:
    """Threat-intelligence evidence, one entry per indicator; explanation only, never part of the score.

    An indicator in one record keeps its single line. One indicator in several records (several sources, or
    duplicate records of one source) is listed once with every source and record ID, and each source once,
    at its highest report: the factor uses the highest single report, so more reports add no points.
    """
    groups: dict[tuple[str, str], list[ScoredMatch]] = {}
    for scored in scored_matches:
        groups.setdefault(_indicator_identity(scored[0]), []).append(scored)

    evidence: list[str] = []
    for (indicator_type, value), records in groups.items():
        if len(records) == 1:
            match, combined_value, combination = records[0]
            evidence.append(
                f"{match.indicator_type} {match.value} from {match.source}: {combination} = {combined_value:g}/100."
            )
            continue
        by_source: dict[str, list[ScoredMatch]] = {}
        for scored in records:
            by_source.setdefault(scored[0].source, []).append(scored)
        sources = sorted(by_source)
        highest = max(combined_value for _, combined_value, _ in records)
        evidence.append(
            f"{indicator_type} {value} is reported by {len(sources)} source{'' if len(sources) == 1 else 's'} "
            f"({', '.join(sources)}) in {len(records)} active records. This indicator is considered once, using its "
            f"highest report ({highest:g}/100); additional sources or records add no points."
        )
        ranked = sorted(by_source.items(), key=lambda item: (-max(scored[1] for scored in item[1]), item[0]))
        for source, source_records in ranked:
            match, combined_value, combination = max(source_records, key=lambda scored: scored[1])
            ids = ", ".join(sorted(str(scored[0].id) for scored in source_records))
            label = (
                f"indicator {ids}"
                if len(source_records) == 1
                else f"{len(source_records)} records, indicators {ids}; highest shown"
            )
            evidence.append(f"{indicator_type} {value} from {source}: {combination} = {combined_value:g}/100 ({label}).")
    return evidence


def _v2_vulnerability_note(status: str) -> str:
    if status in V2_COUNTED_VULNERABILITY_STATUSES:
        return ""
    if status == "ACCEPTED":
        return " Not counted in risk-v2: the risk was accepted; the vulnerability may still be present."
    return " Not counted in risk-v2: only OPEN vulnerabilities count."


def _calculate_factors(
    context: IncidentContextBundle, *, open_vulnerabilities_only: bool = False
) -> tuple[dict[str, RiskFactorExplanation], list[str]]:
    """The risk-v1 factors; ``open_vulnerabilities_only`` applies risk-v2's single change to the vulnerability factor."""
    missing: list[str] = []

    if context.asset is None:
        criticality_value = 0.0
        criticality_evidence = ["No asset is associated with the incident."]
        criticality_reason = "Asset criticality evidence is unavailable, so this factor contributes zero."
        missing.append("Asset criticality evidence is unavailable.")
    else:
        criticality_value = CRITICALITY_VALUES[context.asset.criticality]
        criticality_evidence = [
            f"Asset {context.asset.asset_key} criticality is {context.asset.criticality}."
        ]
        # risk-v1's wording is pinned by its snapshot; risk-v2 uses the same factor and says so without "V1".
        criticality_reason = (
            f"Asset criticality {context.asset.criticality} maps to {criticality_value:g}/100; "
            + ("exposure and status are context only in this factor, unchanged from risk-v1."
               if open_vulnerabilities_only else "exposure and status are context only in this V1 factor.")
        )

    scored_vulnerabilities = [
        vulnerability
        for vulnerability in context.vulnerabilities
        if vulnerability.cvss_score is not None
        and (not open_vulnerabilities_only or vulnerability.status in V2_COUNTED_VULNERABILITY_STATUSES)
    ]
    if open_vulnerabilities_only:
        vulnerability_evidence = [
            f"{item.cve_id or item.title}: CVSS {item.cvss_score}, severity {item.severity}, status {item.status}."
            + _v2_vulnerability_note(item.status)
            for item in context.vulnerabilities
        ] or ["No vulnerabilities are linked to the asset."]
        if scored_vulnerabilities:
            selected_vulnerability = max(scored_vulnerabilities, key=lambda item: item.cvss_score or 0)
            vulnerability_value = _bounded((selected_vulnerability.cvss_score or 0) * 10)
            vulnerability_reason = (
                f"The highest CVSS score among OPEN vulnerabilities ({selected_vulnerability.cvss_score:g}) is "
                "normalized by multiplying by 10; MITIGATED, ACCEPTED and FALSE_POSITIVE vulnerabilities are not counted."
            )
        else:
            vulnerability_value = 0.0
            vulnerability_reason = (
                "No OPEN vulnerability has a CVSS score, so this factor contributes zero; "
                "MITIGATED, ACCEPTED and FALSE_POSITIVE vulnerabilities are not counted."
            )
            missing.append("No OPEN vulnerability with a CVSS score is available.")
    elif scored_vulnerabilities:
        selected_vulnerability = max(scored_vulnerabilities, key=lambda item: item.cvss_score or 0)
        vulnerability_value = _bounded((selected_vulnerability.cvss_score or 0) * 10)
        vulnerability_evidence = [
            f"{item.cve_id or item.title}: CVSS {item.cvss_score}, severity {item.severity}, status {item.status}."
            for item in context.vulnerabilities
        ]
        vulnerability_reason = (
            f"The highest available CVSS score ({selected_vulnerability.cvss_score:g}) is normalized by multiplying by 10."
        )
    else:
        vulnerability_value = 0.0
        vulnerability_evidence = [
            "No vulnerabilities are linked to the asset."
            if not context.vulnerabilities
            else "Vulnerability records exist, but none has a CVSS score."
        ]
        vulnerability_reason = "No relevant CVSS evidence is available, so this factor contributes zero."
        missing.append("Vulnerability CVSS evidence is unavailable.")

    anomaly_events = [event for event in context.events if event.anomaly_score is not None]
    if anomaly_events:
        selected_anomaly = max(anomaly_events, key=lambda event: event.anomaly_score or 0)
        anomaly_value = _bounded((selected_anomaly.anomaly_score or 0) * 100)
        anomaly_evidence = [
            f"{event.event_uid}: anomaly score {event.anomaly_score}."
            for event in anomaly_events
        ]
        anomaly_reason = "The highest linked-event anomaly score is normalized by multiplying by 100."
    else:
        anomaly_value = 0.0
        anomaly_evidence = ["No linked event contains an anomaly score."]
        anomaly_reason = "Anomaly evidence is unavailable, so no anomaly score is invented and this factor contributes zero."
        missing.append("Behavioral anomaly evidence is unavailable.")

    detection_events = [
        (event, DETECTION_SOURCE_CONFIDENCE.get(event.detection_source, 0.0))
        for event in context.events
    ]
    if detection_events:
        detection_value = max(value for _, value in detection_events)
        detection_evidence = [
            f"{event.detection_source}: {value:g}/100 ({DETECTION_SOURCE_RATIONALE.get(event.detection_source, 'unmapped source')})."
            for event, value in detection_events
        ]
        detection_reason = (
            ("The highest linked-event source mapping is used as a confidence proxy, unchanged from risk-v1; "
             if open_vulnerabilities_only else "The highest linked-event source mapping is used as a V1 confidence proxy; ")
            + "the mapping is heuristic, not a calibrated probability."
        )
    else:
        detection_value = 0.0
        detection_evidence = ["No linked event detection source is available."]
        detection_reason = "Detection-source evidence is unavailable, so this factor contributes zero."
        missing.append("Detection-source evidence is unavailable.")

    severity_values = SEVERITY_VALUES
    threat_scores: list[tuple[float, str]] = []
    scored_matches: list[ScoredMatch] = []
    for match in context.threat_intelligence_matches:
        severity_value = severity_values[match.severity]
        if match.confidence is None:
            combined_value = severity_value
            combination = "severity only; confidence unavailable"
        else:
            confidence_value = _bounded(match.confidence * 100)
            combined_value = round(confidence_value * 0.7 + severity_value * 0.3, 2)
            combination = f"70% confidence ({confidence_value:g}) + 30% severity ({severity_value:g})"
        threat_scores.append((combined_value, match.value))
        scored_matches.append((match, combined_value, combination))
    threat_evidence = _threat_evidence(scored_matches)
    if threat_scores:
        threat_value = max(value for value, _ in threat_scores)
        threat_reason = "Each active match combines confidence and severity; the highest combined match is used."
    else:
        threat_value = 0.0
        threat_evidence = ["No active threat-intelligence match is present in the enrichment context."]
        threat_reason = "No active match contributes zero; absence of threat intelligence is not evidence of benign activity."
        missing.append("No active threat-intelligence match is available; absence is not evidence of benign activity.")

    attack_value, attack_evidence, attack_reason = _attack_context(context.events)
    if not context.events:
        missing.append("No linked event context is available for attack-context scoring.")

    factors = {
        "asset_criticality": _factor(
            criticality_value,
            FACTOR_WEIGHTS["asset_criticality"],
            criticality_evidence,
            criticality_reason,
        ),
        "vulnerability": _factor(
            vulnerability_value,
            FACTOR_WEIGHTS["vulnerability"],
            vulnerability_evidence,
            vulnerability_reason,
        ),
        "anomaly": _factor(
            anomaly_value,
            FACTOR_WEIGHTS["anomaly"],
            anomaly_evidence,
            anomaly_reason,
        ),
        "detection": _factor(
            detection_value,
            FACTOR_WEIGHTS["detection"],
            detection_evidence,
            detection_reason,
        ),
        "threat_intelligence": _factor(
            threat_value,
            FACTOR_WEIGHTS["threat_intelligence"],
            threat_evidence,
            threat_reason,
        ),
        "attack_context": _factor(
            attack_value,
            FACTOR_WEIGHTS["attack_context"],
            attack_evidence,
            attack_reason,
        ),
    }
    return factors, missing


def _risk_severity(score: float) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


@dataclass(frozen=True)
class ContextRiskScore:
    """What ``score_context`` derives from an incident context; ``calculate_incident_risk`` reports it."""

    methodology_version: str
    risk_score: float
    severity: str
    factors: dict[str, RiskFactorExplanation]
    missing_evidence: list[str]

    @property
    def reasons(self) -> list[str]:
        return [factor.reason for factor in self.factors.values()]


def score_context(context: IncidentContextBundle) -> ContextRiskScore:
    """Score an already-gathered incident context with risk-v1.

    Pure: it reads only ``context``; no database, clock, settings or network access, and no state change.
    """
    factors, missing_evidence = _calculate_factors(context)
    risk_score = round(
        min(100.0, max(0.0, sum(factor.contribution for factor in factors.values()))),
        2,
    )
    return ContextRiskScore(
        methodology_version=RISK_METHODOLOGY_VERSION,
        risk_score=risk_score,
        severity=_risk_severity(risk_score),
        factors=factors,
        missing_evidence=missing_evidence,
    )


def score_context_v2(context: IncidentContextBundle) -> ContextRiskScore:
    """Score an already-gathered incident context with risk-v2 (risk-v1 with OPEN-only vulnerabilities).

    Pure, like ``score_context``. Every new calculation and re-evaluation uses this; stored risk-v1 evaluations
    keep their recorded version and values and are never recalculated.
    """
    factors, missing_evidence = _calculate_factors(context, open_vulnerabilities_only=True)
    risk_score = round(
        min(100.0, max(0.0, sum(factor.contribution for factor in factors.values()))),
        2,
    )
    return ContextRiskScore(
        methodology_version=RISK_V2_METHODOLOGY_VERSION,
        risk_score=risk_score,
        severity=_risk_severity(risk_score),
        factors=factors,
        missing_evidence=missing_evidence,
    )


def _matched_indicator_snapshot(context: IncidentContextBundle) -> list[dict[str, object]]:
    """The active indicators an evaluation used, as identifiers and attribution (inactive ones never match)."""
    return [
        {
            "id": str(match.id),
            "indicatorType": match.indicator_type,
            "value": match.value,
            "source": match.source,
            "confidence": match.confidence,
            "severity": match.severity,
            "matchedEventIds": [str(event_id) for event_id in match.matched_event_ids],
        }
        for match in context.threat_intelligence_matches
    ]


def _evaluation_record(
    incident_id: UUID,
    scored: ContextRiskScore,
    result: RiskScoreResult,
    context: IncidentContextBundle,
    *,
    previous_risk_score: float | None,
    trigger: str,
    actor: str,
) -> RiskEvaluation:
    """A RiskEvaluation snapshot of one scoring run; the caller adds it in the same transaction as its other writes."""
    return RiskEvaluation(
        incident_id=incident_id,
        # Ordered by the incident lock, so the latest evaluation is the one written last (see serialized_timestamp).
        created_at=serialized_timestamp(RiskEvaluation.created_at, RiskEvaluation.incident_id == incident_id),
        methodology_version=scored.methodology_version,  # RISK_METHODOLOGY_VERSION when the score was computed
        risk_score=scored.risk_score,
        risk_level=scored.severity,
        previous_risk_score=previous_risk_score,
        # The factor breakdown exactly as the risk API reports it.
        factors=result.model_dump(mode="json", by_alias=True)["factors"],
        missing_evidence=list(scored.missing_evidence),
        matched_indicators=_matched_indicator_snapshot(context),
        trigger=trigger,
        actor=actor,
    )


def _serialized_history_time(incident_id: UUID) -> Any:
    """A risk history entry's time, ordered by the incident lock: decisions cite the latest one by this time."""
    return serialized_timestamp(IncidentHistory.occurred_at, IncidentHistory.incident_id == incident_id)


def _locked_incident(incident_id: UUID) -> Select[tuple[Incident]]:
    """The incident row, locked until the calculation commits or rolls back (the shared workflow lock).

    A second calculation of the same incident waits for the lock, then reads the committed PRIORITISED
    state and is refused (409), so it cannot add a second risk_calculated entry or evaluation.
    """
    return locked_incident_statement(incident_id)


def calculate_incident_risk(db: Session, incident_id: UUID, *, actor: str) -> RiskScoreResult:
    incident = db.scalars(_locked_incident(incident_id)).one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.state != IncidentState.UNDERSTOOD:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must be UNDERSTOOD before risk calculation",
        )

    context = enrich_incident_context(db, incident_id, actor=actor, record_history=False)
    scored = score_context_v2(context)
    risk_score = scored.risk_score
    transition = RiskStateTransition(
        from_state=IncidentState.UNDERSTOOD.name,
        to_state=IncidentState.PRIORITISED.name,
        action="risk_calculated",
    )
    result = RiskScoreResult(
        incident_id=incident.id,
        risk_score=risk_score,
        severity=scored.severity,
        factors=scored.factors,
        reasons=scored.reasons,
        missing_evidence=scored.missing_evidence,
        state_transition=transition,
    )

    previous_risk_score = incident.risk_score
    incident.risk_score = risk_score
    incident.state = IncidentState.PRIORITISED
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=IncidentState.UNDERSTOOD,
            to_state=IncidentState.PRIORITISED,
            action="risk_calculated",
            actor=actor,
            occurred_at=_serialized_history_time(incident.id),
            details={"risk_calculation": result.model_dump(mode="json")},
        )
    )
    # Committed together with the score, the state change and the history entry, or not at all. The state
    # check above makes this the incident's only initial evaluation: a repeat call is refused with 409.
    db.add(
        _evaluation_record(
            incident.id,
            scored,
            result,
            context,
            previous_risk_score=previous_risk_score,
            trigger="initial",
            actor=actor,
        )
    )
    db.commit()
    return result


#: States in which an operator may re-evaluate a scored incident (risk_reevaluated).
REEVALUATION_STATES = (IncidentState.PRIORITISED, IncidentState.VERIFIED)


def reevaluate_incident_risk(db: Session, incident_id: UUID, *, actor: str) -> RiskScoreResult:
    """Score a PRIORITISED or VERIFIED incident again with the current methodology and append the result.

    The previous evaluations, decisions and authorizations are kept unchanged. Refused while an authorization
    request is open, so no request can be approved, or containment run, against a score it was not made for.
    A changed score makes earlier decisions stale (their score no longer matches): a VERIFIED incident returns
    to PRIORITISED, so a new decision, a new authorization request and a new verification are needed before an
    approval. An unchanged score changes no state, decision or authorization.
    """
    incident = db.scalars(_locked_incident(incident_id)).one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.state not in REEVALUATION_STATES or incident.risk_score is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Risk can be re-evaluated only for a scored PRIORITISED or VERIFIED incident",
        )
    open_request = db.scalar(
        select(Authorization.id)
        .where(
            Authorization.incident_id == incident.id,
            Authorization.status.in_((AuthorizationStatus.PENDING, AuthorizationStatus.APPROVED)),
        )
        .limit(1)
    )
    if open_request is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Risk cannot be re-evaluated while an authorization request is open",
        )

    context = enrich_incident_context(db, incident_id, actor=actor, record_history=False)
    scored = score_context_v2(context)
    previous_risk_score = float(incident.risk_score)
    score_changed = scored.risk_score != previous_risk_score
    previous_state = incident.state
    next_state = IncidentState.PRIORITISED if score_changed else previous_state
    result = RiskScoreResult(
        incident_id=incident.id,
        risk_score=scored.risk_score,
        severity=scored.severity,
        factors=scored.factors,
        reasons=scored.reasons,
        missing_evidence=scored.missing_evidence,
        state_transition=RiskStateTransition(
            from_state=previous_state.name, to_state=next_state.name, action="risk_reevaluated"
        ),
    )

    incident.risk_score = scored.risk_score
    incident.state = next_state
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=previous_state,
            to_state=next_state,
            action="risk_reevaluated",
            actor=actor,
            occurred_at=_serialized_history_time(incident.id),
            details={
                "risk_calculation": result.model_dump(mode="json"),
                "previous_risk_score": previous_risk_score,
                "score_changed": score_changed,
                "methodology_version": scored.methodology_version,
            },
        )
    )
    # One commit for the score, the state, the history entry and the appended evaluation, or none of them.
    db.add(
        _evaluation_record(
            incident.id,
            scored,
            result,
            context,
            previous_risk_score=previous_risk_score,
            trigger="reevaluation",
            actor=actor,
        )
    )
    db.commit()
    return result
