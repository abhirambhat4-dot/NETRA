from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, case, func, or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.api.auth import get_current_user
from app.api.core_serializers import event_response
from app.db.dependencies import get_db
from app.models.enums import DetectionSource, Severity
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.core import EventIngestRequest, EventResponse, PageResponse
from app.services.intake import create_event

router = APIRouter(prefix="/events", tags=["events"])
SEVERITY_ORDER = (
    (SecurityEvent.severity == Severity.CRITICAL, 0),
    (SecurityEvent.severity == Severity.HIGH, 1),
    (SecurityEvent.severity == Severity.MEDIUM, 2),
    (SecurityEvent.severity == Severity.LOW, 3),
    (SecurityEvent.severity == Severity.INFO, 4),
)


@router.get("", response_model=PageResponse[EventResponse])
def list_events(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] | None = None,
    status_filter: Annotated[Literal["NEW", "CORRELATED"] | None, Query(alias="status")] = None,
    source: Literal["SURICATA", "ML_ANOMALY", "THREAT_INTEL", "VULNERABILITY_SCAN", "MANUAL"] | None = None,
    asset_id: Annotated[UUID | None, Query(alias="assetId")] = None,
    search: str | None = None,
    sort_by: Annotated[Literal["timestamp", "risk", "severity"], Query(alias="sortBy")] = "timestamp",
    sort_order: Annotated[Literal["asc", "desc"], Query(alias="sortOrder")] = "desc",
) -> PageResponse[EventResponse]:
    conditions = []
    if severity is not None:
        conditions.append(SecurityEvent.severity == Severity[severity])
    if source is not None:
        conditions.append(SecurityEvent.source == DetectionSource[source])
    if asset_id is not None:
        conditions.append(SecurityEvent.asset_id == asset_id)
    if status_filter == "NEW":
        conditions.append(~SecurityEvent.incidents.any())
    elif status_filter == "CORRELATED":
        conditions.append(SecurityEvent.incidents.any())
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                SecurityEvent.event_uid.ilike(pattern),
                SecurityEvent.event_type.ilike(pattern),
                SecurityEvent.signature.ilike(pattern),
                SecurityEvent.src_ip.cast(String).ilike(pattern),
                SecurityEvent.dest_ip.cast(String).ilike(pattern),
            )
        )

    total = int(db.scalar(select(func.count()).select_from(SecurityEvent).where(*conditions)) or 0)
    if sort_by == "risk":
        sort_column = SecurityEvent.anomaly_score
    elif sort_by == "severity":
        sort_column = case(*SEVERITY_ORDER, else_=99)
    else:
        sort_column = SecurityEvent.occurred_at
    sort_expression = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    statement = (
        select(SecurityEvent)
        .where(*conditions)
        .options(joinedload(SecurityEvent.asset), selectinload(SecurityEvent.incidents))
        .order_by(sort_expression, SecurityEvent.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    records = db.scalars(statement).unique().all()
    return PageResponse[EventResponse](
        items=[event_response(record) for record in records],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/ingest", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
def ingest_event(
    request: EventIngestRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> EventResponse:
    event = create_event(db, request.model_dump(exclude_none=True))
    return event_response(event)


@router.get(
    "/{event_id}",
    response_model=EventResponse,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Event not found"}},
)
def get_event(
    event_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> EventResponse:
    statement = (
        select(SecurityEvent)
        .where(SecurityEvent.id == event_id)
        .options(joinedload(SecurityEvent.asset), selectinload(SecurityEvent.incidents))
    )
    event = db.scalars(statement).unique().one_or_none()
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event_response(event)