from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.core_serializers import authorization_response, containment_response
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.core import AuthorizationResponse, ContainmentResponse
from app.services.controlled_response import simulate_authorized_containment
from app.services.decision_workflow import (
    approve_decision_authorization,
    reject_decision_authorization,
)

router = APIRouter(prefix="/authorizations", tags=["authorizations"])


@router.post(
    "/{authorization_id}/approve",
    response_model=AuthorizationResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Authorization not found"},
        status.HTTP_409_CONFLICT: {"description": "Authorization cannot be approved in its current state"},
    },
)
def approve_authorization(
    authorization_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> AuthorizationResponse:
    authorization = approve_decision_authorization(
        db,
        authorization_id,
        actor=current_user.email,
    )
    return authorization_response(authorization)


@router.post(
    "/{authorization_id}/reject",
    response_model=AuthorizationResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Authorization not found"},
        status.HTTP_409_CONFLICT: {"description": "Authorization cannot be rejected in its current state"},
    },
)
def reject_authorization(
    authorization_id: UUID,
    reason: Annotated[str, Body(embed=True, min_length=1)],
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> AuthorizationResponse:
    authorization = reject_decision_authorization(
        db,
        authorization_id,
        actor=current_user.email,
        reason=reason,
    )
    return authorization_response(authorization)


@router.post(
    "/{authorization_id}/contain",
    response_model=ContainmentResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Authorization not found"},
        status.HTTP_409_CONFLICT: {"description": "Authorization is not eligible for containment"},
    },
)
def contain_authorized_action(
    authorization_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    simulate_failure: bool = Body(default=False, embed=True, alias="simulateFailure"),
) -> ContainmentResponse:
    containment = simulate_authorized_containment(
        db,
        authorization_id,
        actor=current_user.email,
        simulate_failure=simulate_failure,
    )
    return containment_response(containment)