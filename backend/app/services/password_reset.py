"""Password reset tokens: issued per request, stored as SHA-256 digests, single-use and short-lived."""

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlencode

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.schemas.auth import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH
from app.services.auth import hash_password
from app.services.mail import MailMessage, MailService
from app.services.rate_limit import SlidingWindowRateLimiter

logger = logging.getLogger(__name__)

RESET_TOKEN_BYTES = 32  # 256 bits of entropy from the OS CSPRNG
MAX_RESET_TOKEN_LENGTH = 256
RATE_WINDOW_SECONDS = 15 * 60

# Requests over the per-client limit are refused with 429; requests over the per-email limit
# still receive the neutral response but no email, so the limit never signals account existence.
forgot_password_client_limiter = SlidingWindowRateLimiter(limit=10, window_seconds=RATE_WINDOW_SECONDS)
forgot_password_email_limiter = SlidingWindowRateLimiter(limit=3, window_seconds=RATE_WINDOW_SECONDS)
reset_password_client_limiter = SlidingWindowRateLimiter(limit=10, window_seconds=RATE_WINDOW_SECONDS)


class PasswordResetError(Exception):
    def __init__(self, reason: Literal["missing", "invalid", "expired", "password_policy"]) -> None:
        super().__init__(reason)
        self.reason = reason


def hash_reset_token(raw_token: str) -> str:
    """Tokens are 256-bit random values, so a fast unsalted digest is sufficient and enables lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_reset_token(db: Session, user: User, lifetime_minutes: int) -> str:
    """Create a reset token for ``user`` and return the raw value; only its digest is persisted."""
    now = datetime.now(UTC)
    # Only the most recently emailed link stays valid.
    _invalidate_outstanding_tokens(db, user, now)
    raw_token = secrets.token_urlsafe(RESET_TOKEN_BYTES)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(raw_token),
            expires_at=now + timedelta(minutes=lifetime_minutes),
        )
    )
    return raw_token


def build_reset_message(email: str, raw_token: str, frontend_base_url: str, lifetime_minutes: int) -> MailMessage:
    reset_url = f"{frontend_base_url.rstrip('/')}/reset-password?{urlencode({'token': raw_token})}"
    body = (
        "A password reset was requested for your NETRA account.\n\n"
        f"Reset your password within {lifetime_minutes} minutes using this link:\n{reset_url}\n\n"
        "The link can be used once. If you did not request a reset, you can ignore this email; "
        "your password will not change.\n"
    )
    return MailMessage(to=email, subject="Reset your NETRA password", body=body)


def deliver_reset_email(mail: MailService, message: MailMessage) -> None:
    """Background task. Failures are logged by type only: messages may contain the reset link."""
    try:
        mail.send(message)
    except Exception as error:  # noqa: BLE001 - delivery must never surface to the client
        logger.error("Password reset email delivery failed (%s)", type(error).__name__)


def reset_password(db: Session, raw_token: str, new_password: str) -> None:
    """Consume a reset token and set the new password, or raise PasswordResetError."""
    if not raw_token or not new_password:
        raise PasswordResetError("missing")
    if len(raw_token) > MAX_RESET_TOKEN_LENGTH:
        raise PasswordResetError("invalid")

    now = datetime.now(UTC)
    token = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_reset_token(raw_token)))
    if token is None or token.used_at is not None:
        raise PasswordResetError("invalid")
    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        raise PasswordResetError("invalid")
    if _as_utc(token.expires_at) <= now:
        raise PasswordResetError("expired")
    if not PASSWORD_MIN_LENGTH <= len(new_password) <= PASSWORD_MAX_LENGTH:
        raise PasswordResetError("password_policy")

    # Conditional update claims the token atomically, so concurrent requests cannot both use it.
    claimed = db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.id == token.id, PasswordResetToken.used_at.is_(None))
        .values(used_at=now)
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise PasswordResetError("invalid")

    user.password_hash = hash_password(new_password)
    _invalidate_outstanding_tokens(db, user, now)
    db.commit()


def _invalidate_outstanding_tokens(db: Session, user: User, now: datetime) -> None:
    db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
        .values(used_at=now)
    )


def _as_utc(value: datetime) -> datetime:
    # SQLite (used in tests) returns naive datetimes; stored values are always UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
