from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.api.auth import get_current_user
from app.api.core_serializers import cyber_memory_response
from app.db.dependencies import get_db
from app.models.cyber_memory import CyberMemory
from app.models.enums import Effectiveness, ResponseAction
from app.models.incident import Incident
from app.models.user import User
from app.schemas.core import CyberMemoryResponse, PageResponse

router = APIRouter(prefix="/cyber-memory", tags=["cyber-memory"])


@router.get("", response_model=PageResponse[CyberMemoryResponse])
def list_cyber_memory(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    incident_id: Annotated[UUID | None, Query(alias="incidentId")] = None,
    effectiveness: Literal["EFFECTIVE", "PARTIALLY_EFFECTIVE", "INEFFECTIVE", "UNKNOWN"] | None = None,
    action_taken: Annotated[Literal["MONITOR", "INVESTIGATE", "ESCALATE", "BLOCK_IP", "ISOLATE_HOST", "DISABLE_ACCOUNT", "KILL_PROCESS", "QUARANTINE_FILE", "NO_ACTION"] | None, Query(alias="actionTaken")] = None,
    search: str | None = None,
) -> PageResponse[CyberMemoryResponse]:
    conditions = []
    if incident_id is not None:
        conditions.append(CyberMemory.incident_id == incident_id)
    if effectiveness is not None:
        conditions.append(CyberMemory.effectiveness == Effectiveness[effectiveness])
    if action_taken is not None:
        conditions.append(CyberMemory.action_taken == ResponseAction[action_taken])
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                CyberMemory.lesson.ilike(pattern),
                CyberMemory.outcome.ilike(pattern),
                CyberMemory.incident.has(
                    or_(Incident.incident_key.ilike(pattern), Incident.title.ilike(pattern))
                ),
            )
        )

    total = int(db.scalar(select(func.count()).select_from(CyberMemory).where(*conditions)) or 0)
    statement = (
        select(CyberMemory)
        .where(*conditions)
        .options(
            joinedload(CyberMemory.decision),
            selectinload(CyberMemory.incident).selectinload(Incident.authorizations),
            selectinload(CyberMemory.incident).selectinload(Incident.containment_actions),
        )
        .order_by(CyberMemory.created_at.desc(), CyberMemory.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    records = db.scalars(statement).unique().all()
    return PageResponse[CyberMemoryResponse](
        items=[cyber_memory_response(record) for record in records],
        total=total,
        page=page,
        page_size=page_size,
    )