from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.authorization import Authorization
from app.models.decision import Decision
from app.models.enums import (
    AuthorizationStatus,
    IncidentState,
    ResponseAction,
    Severity,
)
from app.models.incident import Incident, IncidentHistory
from app.schemas.enrichment import IncidentContextBundle
from app.services.context_enrichment import enrich_incident_context
from app.services.prioritization import get_prioritized_incidents


def verify_incident(db: Session, incident_id: UUID, *, actor: str) -> Incident:
    incident = db.scalars(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.events), selectinload(Incident.decisions))
    ).unique().one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.state != IncidentState.PRIORITISED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must be PRIORITISED before verification",
        )

    previous_state = incident.state
    incident.state = IncidentState.VERIFIED
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=previous_state,
            to_state=incident.state,
            action="incident_verified",
            actor=actor,
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


def _confidence(context: IncidentContextBundle, risk_score: float) -> float:
    """Score evidence coverage, not risk magnitude: risk .25, events .10/.25, TI .20, CVSS .10, anomaly .10, source .10; cap at 1."""
    score = 0.25 if risk_score is not None else 0.0
    events = context.events
    if len(events) > 1:
        score += 0.25
    elif events:
        score += 0.10
    if context.threat_intelligence_matches:
        score += 0.20
    if any(item.cvss_score is not None for item in context.vulnerabilities):
        score += 0.10
    if any(event.anomaly_score is not None for event in events):
        score += 0.10
    if any(event.detection_source for event in events):
        score += 0.10
    return round(min(1.0, score), 2)


def _supporting_evidence(
    context: IncidentContextBundle,
    risk_score: float,
    risk_calculation: dict[str, object],
) -> list[str]:
    evidence = [f"Stored Phase 4 risk score is {risk_score:.2f}."]
    if context.asset is not None:
        evidence.append(
            f"Incident asset {context.asset.asset_key} has {context.asset.criticality} criticality."
        )
    else:
        evidence.append("No incident asset is associated.")

    evidence.append(f"{len(context.events)} linked events are available.")
    for event in context.events:
        evidence.append(
            f"Event {event.event_uid}: {event.event_type} ({event.detection_source})"
            f"{f', signature {event.signature}' if event.signature else ''}"
            f"{f', source IP {event.source_ip}' if event.source_ip else ''}"
            f"{f', destination IP {event.destination_ip}' if event.destination_ip else ''}."
        )

    scored_vulnerabilities = [item for item in context.vulnerabilities if item.cvss_score is not None]
    if scored_vulnerabilities:
        evidence.extend(
            f"Vulnerability {item.cve_id or item.title} has CVSS {item.cvss_score:.1f}."
            for item in scored_vulnerabilities
        )
    else:
        evidence.append("No vulnerability with a CVSS score was found.")

    anomalous_events = [event for event in context.events if event.anomaly_score is not None]
    if anomalous_events:
        evidence.extend(
            f"Event {event.event_uid} has anomaly score {event.anomaly_score:.2f}."
            for event in anomalous_events
        )
    else:
        evidence.append("No linked event has an anomaly score.")

    for match in context.threat_intelligence_matches:
        evidence.append(
            f"Active {match.indicator_type} indicator {match.value} from {match.source} "
            f"matches {len(match.matched_event_ids)} event(s)."
        )
    if not context.threat_intelligence_matches:
        evidence.append("No active threat-intelligence match is present.")
    factors = risk_calculation.get("factors")
    if isinstance(factors, dict):
        ranked_factors = sorted(
            factors.items(),
            key=lambda item: (
                -float(item[1].get("contribution", 0)) if isinstance(item[1], dict) else 0,
                item[0],
            ),
        )
        for name, details in ranked_factors[:2]:
            if isinstance(details, dict):
                evidence.append(
                    f"Phase 4 factor {name} contributed "
                    f"{float(details.get('contribution', 0)):.2f} points."
                )
    return evidence


def _select_action(
    context: IncidentContextBundle,
    risk_score: float,
) -> tuple[ResponseAction, str]:
    event_count = len(context.events)
    criticality = context.asset.criticality if context.asset is not None else None
    source_ips = {event.source_ip for event in context.events if event.source_ip is not None}
    strong_source_match = any(
        match.indicator_type == "IP"
        and match.value in source_ips
        and (
            (match.confidence is not None and match.confidence >= 0.8)
            or match.severity in (Severity.HIGH.name, Severity.CRITICAL.name)
        )
        for match in context.threat_intelligence_matches
    )

    if (
        risk_score >= 75
        and context.asset is not None
        and criticality in ("HIGH", "CRITICAL")
        and event_count >= 2
    ):
        return (
            ResponseAction.ISOLATE_HOST,
            "High calculated risk on a high-or-critical asset with multiple linked events supports an isolation recommendation.",
        )
    if strong_source_match:
        return (
            ResponseAction.BLOCK_IP,
            "An active high-confidence or high-severity threat indicator matches an observed event source IP.",
        )
    if risk_score >= 50 or event_count >= 2:
        return (
            ResponseAction.INVESTIGATE,
            "The calculated risk or repeated linked-event evidence warrants further investigation.",
        )
    return (
        ResponseAction.MONITOR,
        "Available evidence is limited and does not meet the deterministic escalation thresholds; continue monitoring.",
    )


def recommend_incident_decision(db: Session, incident_id: UUID, *, actor: str) -> Decision:
    incident = db.scalars(
        select(Incident).where(Incident.id == incident_id)
    ).one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.state != IncidentState.PRIORITISED or incident.risk_score is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must complete risk calculation and be PRIORITISED before decision recommendation",
        )

    risk_history = db.scalars(
        select(IncidentHistory)
        .where(
            IncidentHistory.incident_id == incident.id,
            IncidentHistory.action == "risk_calculated",
        )
        .order_by(desc(IncidentHistory.occurred_at), desc(IncidentHistory.id))
        .limit(1)
    ).first()
    if risk_history is None or not (risk_history.details or {}).get("risk_calculation"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A persisted Phase 4 risk calculation is required before decision recommendation",
        )

    existing = db.scalar(select(Decision.id).where(Decision.incident_id == incident.id).limit(1))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A decision already exists for this incident",
        )

    context = enrich_incident_context(db, incident.id, actor=actor, record_history=False)
    risk_score = float(incident.risk_score)
    risk_calculation = risk_history.details["risk_calculation"]
    action, action_reason = _select_action(context, risk_score)
    confidence = _confidence(context, risk_score)
    evidence = _supporting_evidence(context, risk_score, risk_calculation)

    priority_entry = next(
        (
            item
            for item in get_prioritized_incidents(db)
            if item["incidentId"] == str(incident.id)
        ),
        None,
    )
    if priority_entry is not None:
        evidence.append(
            f"Phase 5 prioritisation placed this incident at rank {priority_entry['priorityRank']}: "
            f"{priority_entry['priorityReason']}"
        )

    rationale_evidence = evidence[:4]
    rationale_evidence.extend(
        item
        for item in evidence[4:]
        if item.startswith(("Vulnerability ", "Active ", "Event ", "Phase 4 factor "))
    )
    observed = "; ".join(rationale_evidence)
    rationale = (
        f"Observed: {observed}. This incident merits attention based on its persisted risk score and "
        "the supporting asset/event context. "
        f"Action basis: {action_reason} NETRA recommends {action.name}; this is a recommendation, "
        "not a claim of confirmed compromise or completed response."
    )
    recommendation = (
        f"Recommended action: {action.name}. Supporting evidence: {' '.join(evidence)} "
        "Authorization is required before any impactful action; this recommendation does not execute containment."
    )

    decision = Decision(
        incident_id=incident.id,
        action=action,
        rationale=rationale,
        risk_score=risk_score,
        confidence=confidence,
        recommendation=recommendation,
    )
    db.add(decision)
    db.flush()
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=incident.state,
            to_state=incident.state,
            action="decision_recommended",
            actor=actor,
            details={
                "decision_id": str(decision.id),
                "action": action.name,
                "risk_score": risk_score,
                "confidence": confidence,
                "rationale": rationale,
                "supporting_evidence": evidence,
                "risk_history_id": str(risk_history.id),
                "priority_rank": priority_entry["priorityRank"] if priority_entry else None,
            },
        )
    )
    db.commit()
    db.refresh(decision)
    return decision


def request_decision_authorization(
    db: Session,
    decision_id: UUID,
    *,
    actor: str,
) -> Authorization:
    decision = db.scalars(
        select(Decision)
        .where(Decision.id == decision_id)
        .options(joinedload(Decision.incident))
    ).unique().one_or_none()
    if decision is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
    incident = decision.incident
    if incident.state not in (IncidentState.PRIORITISED, IncidentState.VERIFIED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authorization can only be requested for a PRIORITISED or VERIFIED incident",
        )
    if decision.risk_score != incident.risk_score:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Decision risk score no longer matches the incident risk score",
        )
    existing = db.scalar(
        select(Authorization.id).where(Authorization.decision_id == decision.id).limit(1)
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An authorization request already exists for this decision",
        )
    if decision.action not in ResponseAction:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Decision action is invalid")

    authorization = Authorization(
        incident_id=incident.id,
        decision_id=decision.id,
        requested_action=decision.action,
        status=AuthorizationStatus.PENDING,
        requested_by=actor,
        approved_by=None,
        reason=None,
        approved_at=None,
    )
    db.add(authorization)
    db.flush()
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=incident.state,
            to_state=incident.state,
            action="authorization_requested",
            actor=actor,
            details={
                "authorization_id": str(authorization.id),
                "decision_id": str(decision.id),
                "requested_action": decision.action.name,
                "status": AuthorizationStatus.PENDING.name,
            },
        )
    )
    db.commit()
    db.refresh(authorization)
    return authorization


def _load_authorization(db: Session, authorization_id: UUID) -> Authorization:
    authorization = db.scalars(
        select(Authorization)
        .where(Authorization.id == authorization_id)
        .options(
            joinedload(Authorization.incident),
            joinedload(Authorization.decision),
        )
    ).unique().one_or_none()
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization not found")
    if authorization.status != AuthorizationStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Authorization in {authorization.status.name.upper()} state cannot be resolved",
        )
    if authorization.decision is None or authorization.decision_id is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Authorization has no valid decision")
    if authorization.requested_action != authorization.decision.action:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Requested action does not match the persisted decision action",
        )
    return authorization


def approve_decision_authorization(
    db: Session,
    authorization_id: UUID,
    *,
    actor: str,
) -> Authorization:
    authorization = _load_authorization(db, authorization_id)
    incident = authorization.incident
    if incident.state != IncidentState.VERIFIED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must be VERIFIED before authorization approval",
        )

    authorization.status = AuthorizationStatus.APPROVED
    authorization.approved_by = actor
    authorization.approved_at = datetime.now(UTC)
    previous_state = incident.state
    incident.state = IncidentState.AUTHORIZED
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=previous_state,
            to_state=IncidentState.AUTHORIZED,
            action="authorization_approved",
            actor=actor,
            details={
                "authorization_id": str(authorization.id),
                "decision_id": str(authorization.decision_id),
                "requested_action": authorization.requested_action.name,
                "status": AuthorizationStatus.APPROVED.name,
            },
        )
    )
    db.commit()
    db.refresh(authorization)
    return authorization


def reject_decision_authorization(
    db: Session,
    authorization_id: UUID,
    *,
    actor: str,
    reason: str,
) -> Authorization:
    authorization = _load_authorization(db, authorization_id)
    rejection_reason = reason.strip()
    if not rejection_reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Rejection reason is required",
        )

    authorization.status = AuthorizationStatus.REJECTED
    authorization.approved_by = actor
    authorization.approved_at = datetime.now(UTC)
    authorization.reason = rejection_reason
    incident = authorization.incident
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=incident.state,
            to_state=incident.state,
            action="authorization_rejected",
            actor=actor,
            details={
                "authorization_id": str(authorization.id),
                "decision_id": str(authorization.decision_id),
                "requested_action": authorization.requested_action.name,
                "status": AuthorizationStatus.REJECTED.name,
                "reason": rejection_reason,
            },
        )
    )
    db.commit()
    db.refresh(authorization)
    return authorization