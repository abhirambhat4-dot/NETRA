import uuid
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.attack_technique import (
    ATTACK_EVIDENCE_ORIGINS,
    EventAttackTechnique,
    normalize_attack_technique_ids,
)
from app.models.enums import DetectionSource, IncidentState, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent, IncidentHistory
from app.services.incident_locking import lock_incident

# Completed incidents accept no new events; there is no reopening workflow.
CLOSED_STATES = (IncidentState.CONTAINED, IncidentState.LEARNED)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value") and isinstance(value.value, (str, int, float, bool)):
        return value.value
    return str(value)


def _to_enum(enum_type: type, raw_value: Any, field_name: str):
    if raw_value is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} is required")
    if isinstance(raw_value, enum_type):
        return raw_value

    candidate = str(raw_value).strip()
    if not candidate:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{field_name} is required")

    normalized = candidate.upper()
    for member in enum_type:
        if member.name == normalized or member.value == candidate.lower():
            return member

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"Invalid {field_name}: {raw_value}",
    )


def _to_uuid(raw_value: Any, field_name: str) -> UUID | None:
    if raw_value is None:
        return None
    try:
        return UUID(str(raw_value))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid {field_name}") from exc


def _to_ip(raw_value: Any, field_name: str) -> str | None:
    if raw_value is None:
        return None
    try:
        return str(ip_address(str(raw_value)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid {field_name}") from exc


def create_event(
    db: Session, payload: dict[str, Any], *, attack_technique_origin: str = "ingest_field"
) -> SecurityEvent:
    """Store one event; with ``attack_technique_ids`` in the payload, also its source-supplied ATT&CK technique
    IDs (origin ``attack_technique_origin``), in the same transaction. IDs are read only from that field."""
    if not payload.get("event_uid"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="event_uid is required")
    if attack_technique_origin not in ATTACK_EVIDENCE_ORIGINS:
        raise ValueError(f"unknown ATT&CK evidence origin {attack_technique_origin!r}")
    try:
        # Validated again here (the request models already did): intake never trusts its caller.
        technique_ids = normalize_attack_technique_ids(payload.get("attack_technique_ids"))
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"attack_technique_ids: {error}"
        ) from None

    event_uid = str(payload["event_uid"]).strip()
    if db.scalar(select(SecurityEvent).where(SecurityEvent.event_uid == event_uid)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Event UID already exists")

    asset_id = _to_uuid(payload.get("asset_id"), "asset_id")
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    raw_data = payload.get("raw_data")
    if raw_data is None:
        raw_data = {key: value for key, value in payload.items() if key != "raw_data"}
    elif not isinstance(raw_data, dict):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="raw_data must be an object")

    raw_data = _json_safe(raw_data)

    source = _to_enum(DetectionSource, payload.get("source"), "source")
    if source == DetectionSource.DATASET_IMPORT:
        # Reserved for events normalised from an import batch, which carry their batch and row.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="source DATASET_IMPORT is assigned only by dataset imports",
        )

    event = SecurityEvent(
        event_uid=event_uid,
        occurred_at=payload["occurred_at"],
        source=source,
        event_type=str(payload["event_type"]).strip(),
        signature=(payload.get("signature") or None),
        severity=_to_enum(Severity, payload.get("severity"), "severity"),
        src_ip=_to_ip(payload.get("src_ip"), "src_ip"),
        dest_ip=_to_ip(payload.get("dest_ip"), "dest_ip"),
        src_port=payload.get("src_port"),
        dest_port=payload.get("dest_port"),
        protocol=(payload.get("protocol") or None),
        anomaly_score=payload.get("anomaly_score"),
        raw_data=raw_data,
        asset_id=asset_id,
    )

    db.add(event)
    if technique_ids:
        db.flush()  # assigns event.id inside this transaction; nothing is committed yet
        db.add_all(
            EventAttackTechnique(
                event_id=event.id,
                technique_id=technique_id,
                evidence_kind="source_supplied",
                evidence_origin=attack_technique_origin,
            )
            for technique_id in technique_ids
        )
    # One commit for the event and its technique IDs: both are stored, or neither is.
    db.commit()
    db.refresh(event)
    return event


def _link_existing_event(db: Session, incident: Incident, event: SecurityEvent, *, actor: str) -> IncidentEvent:
    existing = db.scalar(
        select(IncidentEvent).where(
            IncidentEvent.incident_id == incident.id,
            IncidentEvent.event_id == event.id,
        )
    )
    if existing is not None:
        return existing
    if incident.state in CLOSED_STATES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident in {incident.state.name.upper()} state cannot accept new events",
        )

    link = IncidentEvent(incident_id=incident.id, event_id=event.id, linked_at=datetime.now(UTC))
    db.add(link)
    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=incident.state,
            to_state=incident.state,
            action="event_linked",
            actor=actor,
            details={"event_id": str(event.id), "event_uid": event.event_uid},
        )
    )
    db.flush()
    return link


def link_event_to_incident(
    db: Session, incident_id: UUID, event_id: UUID, *, commit: bool = True, actor: str = "system"
) -> IncidentEvent:
    # Locked first, as in correlation: identical concurrent requests then run one at a time, and the second
    # finds the first one's link and returns it instead of inserting a duplicate.
    incident = lock_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    link = _link_existing_event(db, incident, event, actor=actor)
    if commit:
        db.commit()
        db.refresh(link)
    return link


def create_incident(db: Session, payload: dict[str, Any], *, actor: str = "system") -> Incident:
    title = str(payload.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="title is required")
    asset_id = _to_uuid(payload.get("asset_id"), "asset_id")
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    incident = Incident(
        incident_key=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title=title,
        description=payload.get("description"),
        severity=_to_enum(Severity, payload.get("severity") or Severity.MEDIUM, "severity"),
        risk_score=None,
        state=IncidentState.DETECTED,
        detection_source=_to_enum(DetectionSource, payload.get("detection_source") or DetectionSource.MANUAL, "detection_source"),
        recommended_action=None,
        asset_id=asset_id,
    )
    db.add(incident)
    db.flush()

    db.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=None,
            to_state=IncidentState.DETECTED,
            action="incident_created",
            actor=actor,
            details={"title": title},
        )
    )

    for raw_event_id in payload.get("event_ids") or []:
        event_id = _to_uuid(raw_event_id, "event_id")
        if event_id is not None:
            link_event_to_incident(db, incident.id, event_id, commit=False, actor=actor)

    db.commit()
    db.refresh(incident)
    return incident
