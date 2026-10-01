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
        cyber_memory_response,
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
        CyberMemoryResponse,
    DecisionResponse,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentEventLinkRequest,
    IncidentEventLinkResponse,
    IncidentResponse,
    PageResponse,
    TimelineEntryResponse,
)
from app.schemas.enrichment import IncidentContextBundle
from app.schemas.risk import RiskScoreResult
from app.services.context_enrichment import enrich_incident_context
from app.services.controlled_response import create_incident_cyber_memory
from app.services.decision_workflow import recommend_incident_decision, verify_incident
from app.services.event_correlation import correlate_incident_events
from app.services.intake import create_incident, link_event_to_incident
from app.services.prioritization import get_prioritized_incidents
from app.services.risk_engine import calculate_incident_risk

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


@router.get("/prioritized")
def list_prioritized_incidents(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, object]]:
    return get_prioritized_incidents(db)


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident_endpoint(
    request: IncidentCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> IncidentResponse:
    incident = create_incident(db, request.model_dump(exclude_none=True))
    return incident_response(incident, event_count=len(incident.events))


@router.post(
    "/{incident_id}/events",
    response_model=IncidentEventLinkResponse,
    status_code=status.HTTP_201_CREATED,
)
def link_event_to_incident_endpoint(
    incident_id: UUID,
    request: IncidentEventLinkRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> IncidentEventLinkResponse:
    link = link_event_to_incident(db, incident_id, request.event_id)
    return IncidentEventLinkResponse(
        incident_id=link.incident_id,
        event_id=link.event_id,
        linked_at=link.linked_at,
        status="linked",
    )


@router.post(
    "/{incident_id}/enrich",
    response_model=IncidentContextBundle,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Incident not found"}},
)
def enrich_incident(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> IncidentContextBundle:
    return enrich_incident_context(db, incident_id, actor=current_user.email)


@router.post(
    "/{incident_id}/correlate",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Incident not found"},
        status.HTTP_409_CONFLICT: {"description": "Incident is not eligible for correlation"},
    },
)
def correlate_incident(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, object]:
    return correlate_incident_events(db, incident_id, actor=current_user.email)


@router.post(
    "/{incident_id}/risk-score",
    response_model=RiskScoreResult,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Incident not found"},
        status.HTTP_409_CONFLICT: {"description": "Incident must be UNDERSTOOD before risk calculation"},
    },
)
def calculate_incident_risk_endpoint(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> RiskScoreResult:
    return calculate_incident_risk(db, incident_id, actor=current_user.email)


@router.post(
    "/{incident_id}/verify",
    response_model=IncidentResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Incident not found"},
        status.HTTP_409_CONFLICT: {"description": "Incident must be PRIORITISED before verification"},
    },
)
def verify_incident_endpoint(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> IncidentResponse:
    incident = verify_incident(db, incident_id, actor=current_user.email)
    return incident_response(incident, event_count=len(incident.events))


@router.post(
    "/{incident_id}/decision",
    response_model=DecisionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Incident not found"},
        status.HTTP_409_CONFLICT: {"description": "Incident is not eligible for a decision recommendation"},
    },
)
def recommend_incident_decision_endpoint(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> DecisionResponse:
    decision = recommend_incident_decision(db, incident_id, actor=current_user.email)
    return decision_response(decision)


@router.post(
    "/{incident_id}/cyber-memory",
    response_model=CyberMemoryResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Incident not found"},
        status.HTTP_409_CONFLICT: {"description": "Incident is not eligible for Cyber Memory"},
    },
)
def create_cyber_memory_endpoint(
    incident_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> CyberMemoryResponse:
    memory = create_incident_cyber_memory(db, incident_id, actor=current_user.email)
    return cyber_memory_response(memory)


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