import logging
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.auth import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth import create_access_token, hash_password, verify_password
from app.services.mail import MailService, get_mail_service
from app.services.password_reset import (
    PasswordResetError,
    build_reset_message,
    deliver_reset_email,
    forgot_password_client_limiter,
    forgot_password_email_limiter,
    issue_reset_token,
    reset_password,
    reset_password_client_limiter,
)

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise unauthorized()

    settings = get_settings()
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "email", "role", "exp"]},
        )
        user_id = UUID(claims["sub"])
    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
        raise unauthorized() from None

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized()
    return user


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    request: RegisterRequest,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    existing = db.scalar(select(User).where(User.email == request.email))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")

    user = User(
        email=str(request.email),
        full_name=request.full_name,
        password_hash=hash_password(request.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        ) from None
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == request.email))
    if user is None or not verify_password(request.password, user.password_hash) or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(access_token=create_access_token(user))


@router.get("/me", response_model=UserResponse)
def read_current_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    return current_user


# Identical for existing and unknown accounts so the endpoint never reveals which emails are registered.
PASSWORD_RESET_REQUESTED = "If an account exists for this email, password reset instructions have been sent."
RESET_ERRORS = {
    "missing": (status.HTTP_422_UNPROCESSABLE_CONTENT, "A reset token and new password are required."),
    "invalid": (status.HTTP_400_BAD_REQUEST, "This password reset link is invalid or has already been used."),
    "expired": (status.HTTP_410_GONE, "This password reset link has expired. Request a new one."),
    "password_policy": (
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        f"Password must be between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH} characters.",
    ),
}


def too_many_requests() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many password reset attempts. Try again later.",
    )


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/forgot-password", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    request: ForgotPasswordRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    mail: Annotated[MailService | None, Depends(get_mail_service)],
) -> MessageResponse:
    if not forgot_password_client_limiter.allow(client_key(http_request)):
        raise too_many_requests()
    if mail is None or not settings.frontend_base_url:
        logger.warning("Password reset requested but email delivery is not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset is temporarily unavailable.",
        )

    if forgot_password_email_limiter.allow(request.email):
        user = db.scalar(select(User).where(User.email == request.email))
        if user is not None and user.is_active:
            raw_token = issue_reset_token(db, user, settings.password_reset_token_expire_minutes)
            db.commit()
            # Sent after the response so delivery time does not reveal that the account exists.
            background_tasks.add_task(
                deliver_reset_email,
                mail,
                build_reset_message(
                    user.email, raw_token, settings.frontend_base_url, settings.password_reset_token_expire_minutes
                ),
            )
    return MessageResponse(message=PASSWORD_RESET_REQUESTED)


@router.post("/reset-password", response_model=MessageResponse)
def reset_password_with_token(
    request: ResetPasswordRequest,
    http_request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> MessageResponse:
    if not reset_password_client_limiter.allow(client_key(http_request)):
        raise too_many_requests()
    try:
        reset_password(db, request.token, request.new_password)
    except PasswordResetError as error:
        status_code, detail = RESET_ERRORS[error.reason]
        raise HTTPException(status_code=status_code, detail=detail) from None
    return MessageResponse(message="Password reset successfully. Sign in with your new password.")
