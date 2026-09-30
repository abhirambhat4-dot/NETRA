from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.db.dependencies import get_db
from app.models.asset import Asset
from app.models.enums import AssetStatus, Criticality, IncidentState, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.threat_indicator import ThreatIndicator
from app.models.user import User
from app.schemas.core import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
ACTIVE_STATES = tuple(state for state in IncidentState if state not in (IncidentState.CONTAINED, IncidentState.LEARNED))


def _count(db: Session, statement: object) -> int:
    return int(db.scalar(statement) or 0)  # type: ignore[arg-type]


@router.get("/stats", response_model=DashboardStats)
def dashboard_stats(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> DashboardStats:
    recent_since = datetime.now(UTC) - timedelta(hours=24)
    active_filter = Incident.state.in_(ACTIVE_STATES)
    average_active_risk = db.scalar(
        select(func.avg(Incident.risk_score)).where(active_filter, Incident.risk_score.is_not(None))
    )

    return DashboardStats(
        total_security_events=_count(db, select(func.count()).select_from(SecurityEvent)),
        critical_events=_count(
            db,
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.severity == Severity.CRITICAL),
        ),
        high_events=_count(
            db,
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.severity == Severity.HIGH),
        ),
        active_incidents=_count(
            db,
            select(func.count()).select_from(Incident).where(active_filter),
        ),
        critical_incidents=_count(
            db,
            select(func.count()).select_from(Incident).where(active_filter, Incident.severity == Severity.CRITICAL),
        ),
        average_risk_score=float(average_active_risk) if average_active_risk is not None else None,
        current_risk_score=None,
        asset_count=_count(db, select(func.count()).select_from(Asset)),
        critical_asset_count=_count(
            db,
            select(func.count()).select_from(Asset).where(Asset.criticality == Criticality.CRITICAL),
        ),
        threat_indicator_count=_count(db, select(func.count()).select_from(ThreatIndicator)),
        recent_events_24h=_count(
            db,
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.occurred_at >= recent_since),
        ),
        recent_incidents_24h=_count(
            db,
            select(func.count()).select_from(Incident).where(Incident.created_at >= recent_since),
        ),
    )