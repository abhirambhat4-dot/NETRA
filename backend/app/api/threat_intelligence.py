from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.core_serializers import threat_indicator_response
from app.db.dependencies import get_db
from app.models.attack_technique import normalize_attack_technique_ids
from app.models.enums import DetectionSource, IndicatorType, Severity
from app.models.threat_indicator import ThreatIndicator
from app.models.user import User
from app.schemas.attack import ObservedTechniquePage, ObservedTechniqueResponse, TechniqueCatalogueEntry
from app.schemas.core import PageResponse, ThreatIndicatorResponse
from app.services.attack_observations import ObservationQuery, observed_techniques

router = APIRouter(prefix="/threat-intelligence", tags=["threat-intelligence"])


@router.get("", response_model=PageResponse[ThreatIndicatorResponse])
def list_threat_indicators(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    indicator_type: Annotated[Literal["IP", "DOMAIN", "URL", "HASH"] | None, Query(alias="indicatorType")] = None,
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] | None = None,
    min_confidence: Annotated[float | None, Query(alias="minConfidence", ge=0, le=1)] = None,
    max_confidence: Annotated[float | None, Query(alias="maxConfidence", ge=0, le=1)] = None,
    source: str | None = None,
    search: str | None = None,
    sort_by: Annotated[Literal["firstSeen", "lastSeen", "confidence", "severity"], Query(alias="sortBy")] = "lastSeen",
    sort_order: Annotated[Literal["asc", "desc"], Query(alias="sortOrder")] = "desc",
) -> PageResponse[ThreatIndicatorResponse]:
    conditions = []
    if indicator_type is not None:
        conditions.append(ThreatIndicator.indicator_type == IndicatorType[indicator_type])
    if severity is not None:
        conditions.append(ThreatIndicator.severity == Severity[severity])
    if min_confidence is not None:
        conditions.append(ThreatIndicator.confidence >= min_confidence)
    if max_confidence is not None:
        conditions.append(ThreatIndicator.confidence <= max_confidence)
    if source:
        conditions.append(ThreatIndicator.source.ilike(f"%{source.strip()}%"))
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(or_(ThreatIndicator.value.ilike(pattern), ThreatIndicator.source.ilike(pattern)))

    total = int(db.scalar(select(func.count()).select_from(ThreatIndicator).where(*conditions)) or 0)
    sort_columns = {
        "firstSeen": ThreatIndicator.first_seen,
        "lastSeen": ThreatIndicator.last_seen,
        "confidence": ThreatIndicator.confidence,
        "severity": ThreatIndicator.severity,
    }
    column = sort_columns[sort_by]
    ordering = column.desc() if sort_order == "desc" else column.asc()
    statement = (
        select(ThreatIndicator)
        .where(*conditions)
        .order_by(ordering, ThreatIndicator.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    records = db.scalars(statement).all()
    return PageResponse[ThreatIndicatorResponse](
        items=[threat_indicator_response(record) for record in records],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{indicator_id}",
    response_model=ThreatIndicatorResponse,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Threat indicator not found"}},
)
def get_threat_indicator(
    indicator_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> ThreatIndicatorResponse:
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat indicator not found")
    return threat_indicator_response(indicator)


def _utc_now() -> datetime:
    return datetime.now(UTC)


@router.get("/techniques/observed", response_model=ObservedTechniquePage)
def list_observed_techniques(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    days: Annotated[int, Query(ge=1, le=90)] = 7,
    source: Literal["SURICATA", "ML_ANOMALY", "THREAT_INTEL", "VULNERABILITY_SCAN", "MANUAL", "DATASET_IMPORT"] | None = None,
    origin: Literal["ingest_field", "collector_field"] | None = None,
    technique_id: Annotated[str | None, Query(alias="techniqueId", max_length=32)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    sort_by: Annotated[Literal["eventCount", "lastSeen", "techniqueId"], Query(alias="sortBy")] = "eventCount",
    sort_order: Annotated[Literal["asc", "desc"], Query(alias="sortOrder")] = "desc",
) -> ObservedTechniquePage:
    """ATT&CK technique IDs reported by detection sources (source-supplied evidence only; never inferred).

    Read-only. Counts persisted event_attack_techniques rows for events with asOf - days <= occurredAt <= asOf;
    every figure in a row describes the same filtered events. No ATT&CK catalogue is bundled, so catalogue
    metadata is "unknown" and never invented.
    """
    try:
        technique = normalize_attack_technique_ids([technique_id])[0] if technique_id is not None else None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="techniqueId must be an ATT&CK technique ID such as T1110 or T1110.001",
        ) from None
    as_of = _utc_now()  # one instant per request: the window and the response both use it
    observations, total = observed_techniques(
        db,
        ObservationQuery(
            as_of=as_of,
            days=days,
            source=DetectionSource[source] if source else None,
            origin=origin,
            technique_id=technique,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        ),
    )
    return ObservedTechniquePage(
        items=[
            ObservedTechniqueResponse(
                technique_id=item.technique_id,
                event_count=item.event_count,
                incident_count=item.incident_count,
                active_incident_count=item.active_incident_count,
                incident_ids=item.incident_ids,
                highest_severity=item.highest_severity,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                sources=item.sources,
                origins=item.origins,
                catalogue=TechniqueCatalogueEntry(),
            )
            for item in observations
        ],
        total=total,
        page=page,
        page_size=page_size,
        as_of=as_of,
        window_days=days,
        catalogue=None,
    )
