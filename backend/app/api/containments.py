from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.core_serializers import containment_response
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.core import ContainmentResponse
from app.services.controlled_response import verify_containment

router = APIRouter(prefix="/containments", tags=["containments"])


@router.post(
    "/{containment_id}/verify",
    response_model=ContainmentResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Containment action not found"},
        status.HTTP_409_CONFLICT: {"description": "Containment cannot be verified in its current state"},
    },
)
def verify_containment_endpoint(
    containment_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> ContainmentResponse:
    containment = verify_containment(db, containment_id, actor=current_user.email)
    return containment_response(containment)