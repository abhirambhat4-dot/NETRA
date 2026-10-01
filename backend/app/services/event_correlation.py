import re
from datetime import timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.enums import IncidentState
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent, IncidentHistory

CORRELATION_WINDOW = timedelta(minutes=30)
FAMILY_PATTERNS = {
    "scan": re.compile(r"\b(scan|recon|probe)\b"),
    "ssh": re.compile(r"\bssh\b"),
    "authentication": re.compile(r"\b(auth|authentication|login|brute\s*force|password)\b"),
    "outbound": re.compile(r"\b(outbound|egress)\b"),
    "connection": re.compile(r"\b(connection|connect)\b"),
}


def _event_ips(event: SecurityEvent) -> set[str]:
    return {
        str(address)
        for address in (event.src_ip, event.dest_ip)
        if address is not None
    }


def _event_families(event: SecurityEvent) -> set[str]:
    description = f"{event.event_type} {event.signature or ''}".lower().replace("_", " ").replace("-", " ")
    return {family for family, pattern in FAMILY_PATTERNS.items() if pattern.search(description)}


def _event_response(event: SecurityEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "eventUid": event.event_uid,
        "occurredAt": event.occurred_at.isoformat(),
        "eventType": event.event_type,
        "signature": event.signature,
        "severity": event.severity.name.upper(),
        "detectionSource": event.source.name.upper(),
        "sourceIp": str(event.src_ip) if event.src_ip is not None else None,
        "destinationIp": str(event.dest_ip) if event.dest_ip is not None else None,
        "assetId": str(event.asset_id) if event.asset_id is not None else None,
    }


def correlate_incident_events(db: Session, incident_id: UUID, *, actor: str) -> dict[str, Any]:
    incident = db.scalars(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.events))
    ).unique().one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.state not in (IncidentState.DETECTED, IncidentState.UNDERSTOOD):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident in {incident.state.name.upper()} state cannot be correlated",
        )

    linked_events = sorted(incident.events, key=lambda event: (event.occurred_at, str(event.id)))
    if not linked_events:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must have at least one linked event before correlation",
        )

    linked_ids = {event.id for event in linked_events}
    known_asset_ids = {event.asset_id for event in linked_events if event.asset_id is not None}
    if incident.asset_id is not None:
        known_asset_ids.add(incident.asset_id)

    lower_bound = min(event.occurred_at for event in linked_events) - CORRELATION_WINDOW
    upper_bound = max(event.occurred_at for event in linked_events) + CORRELATION_WINDOW
    candidates = db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.id.not_in(linked_ids),
            SecurityEvent.occurred_at >= lower_bound,
            SecurityEvent.occurred_at <= upper_bound,
        )
        .order_by(SecurityEvent.occurred_at, SecurityEvent.id)
    ).all()

    correlated: list[SecurityEvent] = []
    correlation_details: list[dict[str, Any]] = []
    excluded_counts: dict[str, int] = {}
    for candidate in candidates:
        matched_seed: SecurityEvent | None = None
        matched_criteria: list[str] = []
        best_reasons: list[str] | None = None

        for seed in linked_events:
            reasons: list[str] = []
            same_asset = not known_asset_ids or (
                candidate.asset_id is not None and candidate.asset_id in known_asset_ids
            )
            shared_ips = _event_ips(candidate) & _event_ips(seed)
            within_window = abs(candidate.occurred_at - seed.occurred_at) <= CORRELATION_WINDOW
            same_source = candidate.source == seed.source
            shared_families = _event_families(candidate) & _event_families(seed)
            related_detection = same_source or bool(shared_families)

            if not same_asset:
                reasons.append("different_asset")
            if not shared_ips:
                reasons.append("no_shared_ip")
            if not within_window:
                reasons.append("outside_time_window")
            if not related_detection:
                reasons.append("unrelated_detection_source_and_family")

            if not reasons:
                matched_seed = seed
                matched_criteria = ["same_asset"] if known_asset_ids else []
                matched_criteria.extend(("shared_ip", "within_time_window"))
                matched_criteria.append("same_detection_source" if same_source else "related_event_family")
                break
            if best_reasons is None or len(reasons) < len(best_reasons):
                best_reasons = reasons

        if matched_seed is None:
            for reason in best_reasons or ["no_matching_linked_event"]:
                excluded_counts[reason] = excluded_counts.get(reason, 0) + 1
            continue

        correlated.append(candidate)
        correlation_details.append(
            {
                "event_id": str(candidate.id),
                "related_to_event_id": str(matched_seed.id),
                "matched_criteria": matched_criteria,
            }
        )

    for event in correlated:
        db.add(IncidentEvent(incident_id=incident.id, event_id=event.id))

    previous_state = incident.state
    next_state = previous_state
    if correlated and previous_state == IncidentState.DETECTED:
        next_state = IncidentState.UNDERSTOOD
        incident.state = next_state

    findings: list[dict[str, Any]] = [
        {
            "type": "correlation_window",
            "message": f"Candidates were checked within {int(CORRELATION_WINDOW.total_seconds() // 60)} minutes of linked events.",
        }
    ]
    findings.extend(
        {
            "type": "event_correlated",
            "eventId": detail["event_id"],
            "relatedToEventId": detail["related_to_event_id"],
            "matchedCriteria": detail["matched_criteria"],
        }
        for detail in correlation_details
    )
    if excluded_counts:
        findings.append({"type": "candidates_excluded", "countsByReason": excluded_counts})
    if not correlated:
        findings.append(
            {
                "type": "no_correlation",
                "message": "No candidate events satisfied all v1 correlation criteria.",
            }
        )

    transition = None
    if correlated:
        history = IncidentHistory(
            incident_id=incident.id,
            from_state=previous_state,
            to_state=next_state,
            action="events_correlated",
            actor=actor,
            details={
                "correlation_window_minutes": int(CORRELATION_WINDOW.total_seconds() // 60),
                "correlated_event_ids": [str(event.id) for event in correlated],
                "correlations": correlation_details,
                "excluded_candidate_counts": excluded_counts,
            },
        )
        db.add(history)
        if previous_state != next_state:
            transition = {
                "fromState": previous_state.name.upper(),
                "toState": next_state.name.upper(),
                "action": "events_correlated",
            }

    db.commit()
    return {
        "incidentId": str(incident.id),
        "state": incident.state.name.upper(),
        "stateTransition": transition,
        "correlatedEvents": [_event_response(event) for event in correlated],
        "findings": findings,
    }