from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.core_serializers import authorization_response
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.core import AuthorizationResponse
from app.services.decision_workflow import request_decision_authorization

router = APIRouter(prefix="/decisions", tags=["decisions"])


@router.post(
    "/{decision_id}/authorize",
    response_model=AuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Decision not found"},
        status.HTTP_409_CONFLICT: {"description": "Decision is not eligible for authorization"},
    },
)
def authorize_decision(
    decision_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> AuthorizationResponse:
    authorization = request_decision_authorization(db, decision_id, actor=current_user.email)
    return authorization_response(authorization)