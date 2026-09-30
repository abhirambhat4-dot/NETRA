import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, case, func, or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.api.auth import get_current_user
from app.api.core_serializers import (
    asset_response,
    authorization_response,
    containment_response,
    cyber_memory_reference,
    decision_response,
    enum_text,
    event_response,
    incident_response,
)
from app.db.dependencies import get_db
from app.models.asset import Asset
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.enums import IncidentState, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent, IncidentHistory
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.core import (
    IncidentDetailResponse,
    IncidentResponse,
    PageResponse,
    TimelineEntryResponse,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
ACTIVE_STATES = tuple(state for state in IncidentState if state not in (IncidentState.CONTAINED, IncidentState.LEARNED))
SEVERITY_ORDER = (
    (Incident.severity == Severity.CRITICAL, 0),
    (Incident.severity == Severity.HIGH, 1),
    (Incident.severity == Severity.MEDIUM, 2),
    (Incident.severity == Severity.LOW, 3),
    (Incident.severity == Severity.INFO, 4),
)


def build_timeline(db: Session, incident_id: UUID) -> list[TimelineEntryResponse]:
    history = db.scalars(
        select(IncidentHistory)
        .where(IncidentHistory.incident_id == incident_id)
        .order_by(IncidentHistory.occurred_at.asc(), IncidentHistory.id.asc())
    ).all()
    linked_events = db.execute(
        select(IncidentEvent, SecurityEvent)
        .join(SecurityEvent, IncidentEvent.event_id == SecurityEvent.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.linked_at.asc(), IncidentEvent.event_id.asc())
    ).all()
    entries = [
        TimelineEntryResponse(
            id=event.id,
            timestamp=association.linked_at,
            source="event",
            stage=None,
            title="Security event linked",
            description=event.signature or event.event_type,
            actor=None,
            event_id=event.id,
        )
        for association, event in linked_events
    ]
    entries.extend(
        TimelineEntryResponse(
            id=row.id,
            timestamp=row.occurred_at,
            source="history",
            stage=enum_text(row.to_state),
            title=row.action,
            description=json.dumps(row.details, sort_keys=True, default=str) if row.details else row.action,
            actor=row.actor,
        )
        for row in history
    )
    return sorted(entries, key=lambda entry: (entry.timestamp, str(entry.id)))


@router.get("", response_model=PageResponse[IncidentResponse])
def list_incidents(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] | None = None,
    state: Literal["DETECTED", "UNDERSTOOD", "PRIORITISED", "VERIFIED", "AUTHORIZED", "CONTAINED", "LEARNED"] | None = None,
    active: bool | None = None,
    search: str | None = None,
    sort_by: Annotated[Literal["createdAt", "updatedAt", "riskScore", "severity"], Query(alias="sortBy")] = "updatedAt",
    sort_order: Annotated[Literal["asc", "desc"], Query(alias="sortOrder")] = "desc",
) -> PageResponse[IncidentResponse]:
    conditions = []
    if severity is not None:
        conditions.append(Incident.severity == Severity[severity])
    if state is not None:
        conditions.append(Incident.state == IncidentState[state])
    if active is True:
        conditions.append(Incident.state.in_(ACTIVE_STATES))
    elif active is False:
        conditions.append(Incident.state.in_((IncidentState.CONTAINED, IncidentState.LEARNED)))
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                Incident.incident_key.ilike(pattern),
                Incident.title.ilike(pattern),
                Incident.description.ilike(pattern),
                Incident.asset.has(
                    or_(
                        Asset.name.ilike(pattern),
                        Asset.asset_key.ilike(pattern),
                        Asset.hostname.ilike(pattern),
                    )
                ),
            )
        )

    event_count = (
        select(func.count(IncidentEvent.event_id))
        .where(IncidentEvent.incident_id == Incident.id)
        .scalar_subquery()
    )
    total = int(db.scalar(select(func.count()).select_from(Incident).where(*conditions)) or 0)
    sort_columns = {
        "createdAt": Incident.created_at,
        "updatedAt": Incident.updated_at,
        "riskScore": Incident.risk_score,
        "severity": case(*SEVERITY_ORDER, else_=99),
    }
    sort_column = sort_columns[sort_by]
    sort_expression = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    statement = (
        select(Incident, event_count.label("event_count"))
        .where(*conditions)
        .options(joinedload(Incident.asset), selectinload(Incident.decisions))
        .order_by(sort_expression, Incident.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    records = db.execute(statement).all()
    return PageResponse[IncidentResponse](
        items=[incident_response(incident, count) for incident, count in records],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{incident_id}/timeline",
    response_model=list[TimelineEntryResponse],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Incident not found"}},
)
def get_incident_timeline(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> list[TimelineEntryResponse]:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return build_timeline(db, incident_id)


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Incident not found"}},
)
def get_incident(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> IncidentDetailResponse:
    statement = (
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            joinedload(Incident.asset),
            selectinload(Incident.events).joinedload(SecurityEvent.asset),
            selectinload(Incident.events).selectinload(SecurityEvent.incidents),
            selectinload(Incident.history),
            selectinload(Incident.decisions),
            selectinload(Incident.authorizations),
            selectinload(Incident.containment_actions),
            selectinload(Incident.memories),
        )
    )
    incident = db.scalars(statement).unique().one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    vulnerability_count = int(
        db.scalar(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.asset_id == incident.asset_id)
        )
        or 0
    ) if incident.asset_id is not None else 0
    decisions = sorted(incident.decisions, key=lambda row: (row.created_at, str(row.id)))
    authorizations = sorted(incident.authorizations, key=lambda row: (row.requested_at, str(row.id)))
    actions = sorted(incident.containment_actions, key=lambda row: (row.created_at, str(row.id)))
    memories = sorted(incident.memories, key=lambda row: (row.created_at, str(row.id)))
    return IncidentDetailResponse(
        incident=incident_response(incident, len(incident.events)),
        asset=asset_response(incident.asset, vulnerability_count) if incident.asset is not None else None,
        events=[event_response(event) for event in sorted(incident.events, key=lambda row: (row.occurred_at, str(row.id)))],
        timeline=build_timeline(db, incident.id),
        decisions=[decision_response(row) for row in decisions],
        authorizations=[authorization_response(row) for row in authorizations],
        containment_actions=[containment_response(row) for row in actions],
        cyber_memories=[cyber_memory_reference(row) for row in memories],
    )