import re
from typing import Iterable
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import Criticality, IncidentState, Severity
from app.models.incident import Incident, IncidentHistory
from app.schemas.enrichment import EventContext, IncidentContextBundle
from app.schemas.risk import (
    RiskFactorExplanation,
    RiskScoreResult,
    RiskStateTransition,
)
from app.services.context_enrichment import enrich_incident_context

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


def _calculate_factors(context: IncidentContextBundle) -> tuple[dict[str, RiskFactorExplanation], list[str]]:
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
        criticality_reason = (
            f"Asset criticality {context.asset.criticality} maps to {criticality_value:g}/100; "
            "exposure and status are context only in this V1 factor."
        )

    scored_vulnerabilities = [
        vulnerability
        for vulnerability in context.vulnerabilities
        if vulnerability.cvss_score is not None
    ]
    if scored_vulnerabilities:
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
            "The highest linked-event source mapping is used as a V1 confidence proxy; "
            "the mapping is heuristic, not a calibrated probability."
        )
    else:
        detection_value = 0.0
        detection_evidence = ["No linked event detection source is available."]
        detection_reason = "Detection-source evidence is unavailable, so this factor contributes zero."
        missing.append("Detection-source evidence is unavailable.")

    severity_values = SEVERITY_VALUES
    threat_scores: list[tuple[float, str]] = []
    threat_evidence: list[str] = []
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
        threat_evidence.append(
            f"{match.indicator_type} {match.value} from {match.source}: {combination} = {combined_value:g}/100."
        )
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


def calculate_incident_risk(db: Session, incident_id: UUID, *, actor: str) -> RiskScoreResult:
    incident = db.scalars(select(Incident).where(Incident.id == incident_id)).one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.state != IncidentState.UNDERSTOOD:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must be UNDERSTOOD before risk calculation",
        )

    context = enrich_incident_context(db, incident_id, actor=actor, record_history=False)
    factors, missing_evidence = _calculate_factors(context)
    risk_score = round(
        min(100.0, max(0.0, sum(factor.contribution for factor in factors.values()))),
        2,
    )
    severity = _risk_severity(risk_score)
    transition = RiskStateTransition(
        from_state=IncidentState.UNDERSTOOD.name,
        to_state=IncidentState.PRIORITISED.name,
        action="risk_calculated",
    )
    result = RiskScoreResult(
        incident_id=incident.id,
        risk_score=risk_score,
        severity=severity,
        factors=factors,
        reasons=[factor.reason for factor in factors.values()],
        missing_evidence=missing_evidence,
        state_transition=transition,
    )

    incident.risk_score = risk_score
    incident.state = IncidentState.PRIORITISED
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=IncidentState.UNDERSTOOD,
            to_state=IncidentState.PRIORITISED,
            action="risk_calculated",
            actor=actor,
            details={"risk_calculation": result.model_dump(mode="json")},
        )
    )
    db.commit()
    return result