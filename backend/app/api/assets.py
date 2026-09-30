from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import String, case, func, or_, select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.core_serializers import asset_response
from app.db.dependencies import get_db
from app.models.asset import Asset
from app.models.enums import AssetStatus, Criticality, Exposure
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.core import AssetResponse, PageResponse

router = APIRouter(prefix="/assets", tags=["assets"])
CRITICALITY_ORDER = (
    (Asset.criticality == Criticality.CRITICAL, 0),
    (Asset.criticality == Criticality.HIGH, 1),
    (Asset.criticality == Criticality.MEDIUM, 2),
    (Asset.criticality == Criticality.LOW, 3),
)


def _vulnerability_count():
    return (
        select(func.count(Vulnerability.id))
        .where(Vulnerability.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
    )


@router.get("", response_model=PageResponse[AssetResponse])
def list_assets(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    search: str | None = None,
    asset_status: Annotated[Literal["ACTIVE", "INACTIVE", "DECOMMISSIONED"] | None, Query(alias="status")] = None,
    criticality: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None,
    exposure: Literal["INTERNAL", "DMZ", "INTERNET_FACING"] | None = None,
    sort_by: Annotated[Literal["name", "criticality", "createdAt", "updatedAt"], Query(alias="sortBy")] = "name",
    sort_order: Annotated[Literal["asc", "desc"], Query(alias="sortOrder")] = "asc",
) -> PageResponse[AssetResponse]:
    conditions = []
    if asset_status is not None:
        conditions.append(Asset.status == AssetStatus[asset_status])
    if criticality is not None:
        conditions.append(Asset.criticality == Criticality[criticality])
    if exposure is not None:
        conditions.append(Asset.exposure == Exposure[exposure])
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                Asset.asset_key.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.owner.ilike(pattern),
                Asset.ip_address.cast(String).ilike(pattern),
            )
        )

    total = int(db.scalar(select(func.count()).select_from(Asset).where(*conditions)) or 0)
    sort_columns = {
        "name": Asset.name,
        "criticality": case(*CRITICALITY_ORDER, else_=99),
        "createdAt": Asset.created_at,
        "updatedAt": Asset.updated_at,
    }
    column = sort_columns[sort_by]
    ordering = column.desc() if sort_order == "desc" else column.asc()
    statement = (
        select(Asset, _vulnerability_count().label("vulnerability_count"))
        .where(*conditions)
        .order_by(ordering, Asset.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    records = db.execute(statement).all()
    return PageResponse[AssetResponse](
        items=[asset_response(asset, count) for asset, count in records],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Asset not found"}},
)
def get_asset(
    asset_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> AssetResponse:
    statement = select(Asset, _vulnerability_count().label("vulnerability_count")).where(Asset.id == asset_id)
    row = db.execute(statement).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    asset, vulnerability_count = row
    return asset_response(asset, vulnerability_count)