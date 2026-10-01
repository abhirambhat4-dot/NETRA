import hashlib
import logging
import re
import smtplib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.api.auth import PASSWORD_RESET_REQUESTED
from app.core.config import get_settings
from app.main import app
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services import mail as mail_module
from app.services.mail import InMemoryMailService, MailMessage, SmtpMailService, get_mail_service
from app.services.password_reset import (
    forgot_password_client_limiter,
    forgot_password_email_limiter,
    reset_password_client_limiter,
)

AUTH_URL = "/api/auth"
FRONTEND_BASE_URL = "https://netra.example.com"
EMAIL = "operator@example.com"
OLD_PASSWORD = "original-password-123"
NEW_PASSWORD = "replacement-password-456"
TOKEN_PATTERN = re.compile(r"/reset-password\?token=([A-Za-z0-9_-]+)")


@pytest.fixture(autouse=True)
def clear_rate_limits() -> Any:
    for limiter in (forgot_password_client_limiter, forgot_password_email_limiter, reset_password_client_limiter):
        limiter.clear()
    yield
    for limiter in (forgot_password_client_limiter, forgot_password_email_limiter, reset_password_client_limiter):
        limiter.clear()


@pytest.fixture
def outbox(auth_client: TestClient) -> Any:
    """Route reset email to memory and point links at a test frontend; no SMTP server is involved."""
    mail = InMemoryMailService()
    settings = get_settings().model_copy(update={"frontend_base_url": FRONTEND_BASE_URL})
    app.dependency_overrides[get_mail_service] = lambda: mail
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        yield mail.outbox
    finally:
        app.dependency_overrides.pop(get_mail_service, None)
        app.dependency_overrides.pop(get_settings, None)


def register(client: TestClient, email: str = EMAIL, password: str = OLD_PASSWORD) -> None:
    response = client.post(f"{AUTH_URL}/register", json={"email": email, "full_name": "Operator", "password": password})
    assert response.status_code == 201


def login(client: TestClient, password: str, email: str = EMAIL) -> int:
    return client.post(f"{AUTH_URL}/login", json={"email": email, "password": password}).status_code


def request_reset(client: TestClient, email: str = EMAIL) -> Any:
    return client.post(f"{AUTH_URL}/forgot-password", json={"email": email})


def token_from(message: MailMessage) -> str:
    match = TOKEN_PATTERN.search(message.body)
    assert match is not None
    return match.group(1)


def reset(client: TestClient, token: str, password: str = NEW_PASSWORD) -> Any:
    return client.post(f"{AUTH_URL}/reset-password", json={"token": token, "new_password": password})


def stored_tokens(auth_db: sessionmaker[Session]) -> list[PasswordResetToken]:
    with auth_db() as session:
        return list(session.scalars(select(PasswordResetToken)))


def test_existing_account_gets_neutral_response_and_reset_email(auth_client: TestClient, outbox: list[MailMessage]) -> None:
    register(auth_client)

    response = request_reset(auth_client)

    assert response.status_code == 202
    assert response.json() == {"message": PASSWORD_RESET_REQUESTED}
    assert len(outbox) == 1
    assert outbox[0].to == EMAIL
    assert outbox[0].subject == "Reset your NETRA password"
    assert f"{FRONTEND_BASE_URL}/reset-password?token=" in outbox[0].body


def test_unknown_account_gets_identical_response_and_no_email(
    auth_client: TestClient, outbox: list[MailMessage], auth_db: sessionmaker[Session]
) -> None:
    register(auth_client)
    known = request_reset(auth_client)

    unknown = request_reset(auth_client, "nobody@example.com")

    assert unknown.status_code == known.status_code == 202
    assert unknown.json() == known.json()
    assert unknown.headers.get("content-length") == known.headers.get("content-length")
    assert [message.to for message in outbox] == [EMAIL]
    assert len(stored_tokens(auth_db)) == 1


def test_reset_token_is_stored_only_as_hash(
    auth_client: TestClient, outbox: list[MailMessage], auth_db: sessionmaker[Session]
) -> None:
    register(auth_client)
    request_reset(auth_client)
    raw_token = token_from(outbox[0])

    [record] = stored_tokens(auth_db)

    assert len(raw_token) >= 43  # 32 random bytes, URL-safe base64
    assert record.token_hash == hashlib.sha256(raw_token.encode()).hexdigest()
    assert all(raw_token not in str(value) for value in vars(record).values())
    assert record.used_at is None
    expires_at = record.expires_at.replace(tzinfo=UTC)
    lifetime = timedelta(minutes=get_settings().password_reset_token_expire_minutes)
    assert datetime.now(UTC) < expires_at <= datetime.now(UTC) + lifetime


def test_valid_token_resets_password_with_argon2(
    auth_client: TestClient, outbox: list[MailMessage], auth_db: sessionmaker[Session]
) -> None:
    register(auth_client)
    request_reset(auth_client)

    response = reset(auth_client, token_from(outbox[0]))

    assert response.status_code == 200
    assert login(auth_client, OLD_PASSWORD) == 401
    assert login(auth_client, NEW_PASSWORD) == 200
    with auth_db() as session:
        user = session.scalar(select(User).where(User.email == EMAIL))
    assert user is not None
    assert user.password_hash.startswith("$argon2")
    assert NEW_PASSWORD not in user.password_hash
    assert stored_tokens(auth_db)[0].used_at is not None


def test_used_token_cannot_be_reused(auth_client: TestClient, outbox: list[MailMessage]) -> None:
    register(auth_client)
    request_reset(auth_client)
    token = token_from(outbox[0])
    assert reset(auth_client, token).status_code == 200

    replay = reset(auth_client, token, "another-password-789")

    assert replay.status_code == 400
    assert login(auth_client, "another-password-789") == 401
    assert login(auth_client, NEW_PASSWORD) == 200


def test_invalid_token_is_rejected(auth_client: TestClient, outbox: list[MailMessage]) -> None:
    register(auth_client)

    for token in ("not-a-real-token", "x" * 300):
        response = reset(auth_client, token)
        assert response.status_code == 400
        assert response.json() == {"detail": "This password reset link is invalid or has already been used."}
    assert login(auth_client, OLD_PASSWORD) == 200


def test_expired_token_is_rejected(
    auth_client: TestClient, outbox: list[MailMessage], auth_db: sessionmaker[Session]
) -> None:
    register(auth_client)
    request_reset(auth_client)
    with auth_db() as session:
        session.execute(update(PasswordResetToken).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        session.commit()

    response = reset(auth_client, token_from(outbox[0]))

    assert response.status_code == 410
    assert login(auth_client, OLD_PASSWORD) == 200


def test_password_policy_matches_registration_and_keeps_token_usable(
    auth_client: TestClient, outbox: list[MailMessage]
) -> None:
    register(auth_client)
    request_reset(auth_client)
    token = token_from(outbox[0])

    for weak in ("short", "x" * 129):
        response = reset(auth_client, token, weak)
        assert response.status_code == 422
        assert response.json() == {"detail": "Password must be between 8 and 128 characters."}
    assert login(auth_client, OLD_PASSWORD) == 200
    assert reset(auth_client, token).status_code == 200


def test_missing_fields_are_rejected_without_echoing_the_token(auth_client: TestClient) -> None:
    token = "secret-token-value-that-must-not-echo"

    for body in ({"token": token}, {"new_password": NEW_PASSWORD}, {}):
        response = auth_client.post(f"{AUTH_URL}/reset-password", json=body)
        assert response.status_code == 422
        assert token not in response.text
        assert NEW_PASSWORD not in response.text


def test_new_request_invalidates_previous_link(auth_client: TestClient, outbox: list[MailMessage]) -> None:
    register(auth_client)
    request_reset(auth_client)
    request_reset(auth_client)
    first, second = token_from(outbox[0]), token_from(outbox[1])

    assert reset(auth_client, first).status_code == 400
    assert reset(auth_client, second).status_code == 200


def test_inactive_account_receives_no_email(
    auth_client: TestClient, outbox: list[MailMessage], auth_db: sessionmaker[Session]
) -> None:
    register(auth_client)
    with auth_db() as session:
        session.execute(update(User).values(is_active=False))
        session.commit()

    response = request_reset(auth_client)

    assert response.json() == {"message": PASSWORD_RESET_REQUESTED}
    assert outbox == []


def test_per_email_limit_stays_neutral_and_per_client_limit_returns_429(
    auth_client: TestClient, outbox: list[MailMessage]
) -> None:
    register(auth_client)

    responses = [request_reset(auth_client) for _ in range(4)]
    assert [r.status_code for r in responses] == [202] * 4
    assert all(r.json() == {"message": PASSWORD_RESET_REQUESTED} for r in responses)
    assert len(outbox) == 3

    for index in range(6):
        assert request_reset(auth_client, f"other{index}@example.com").status_code == 202
    assert request_reset(auth_client, "one-more@example.com").status_code == 429


def test_reset_attempts_are_rate_limited(auth_client: TestClient) -> None:
    statuses = [reset(auth_client, f"guess-{index}").status_code for index in range(11)]

    assert statuses[:10] == [400] * 10
    assert statuses[10] == 429


def test_unconfigured_email_fails_safely(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    register(auth_client)
    unconfigured = get_settings().model_copy(update={"email_host": None, "email_from": None, "frontend_base_url": None})
    monkeypatch.setattr(mail_module, "get_settings", lambda: unconfigured)
    assert get_mail_service() is None

    app.dependency_overrides[get_settings] = lambda: unconfigured
    try:
        response = request_reset(auth_client)
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 503
    assert response.json() == {"detail": "Password reset is temporarily unavailable."}


def test_reset_flow_never_contacts_smtp_or_logs_secrets(
    auth_client: TestClient,
    outbox: list[MailMessage],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("tests must not open SMTP connections")

    monkeypatch.setattr(smtplib, "SMTP", refuse)
    monkeypatch.setattr(smtplib, "SMTP_SSL", refuse)
    register(auth_client)

    with caplog.at_level(logging.DEBUG):
        request_reset(auth_client)
        token = token_from(outbox[0])
        assert reset(auth_client, token).status_code == 200

    logged = caplog.text
    assert token not in logged
    assert NEW_PASSWORD not in logged
    assert OLD_PASSWORD not in logged


def test_smtp_service_requires_starttls_before_login(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class FakeSmtp:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            calls.append(f"connect {host}:{port}")

        def __enter__(self) -> "FakeSmtp":
            return self

        def __exit__(self, *_: object) -> None:
            calls.append("quit")

        def starttls(self, context: object) -> None:
            calls.append("starttls")

        def login(self, username: str, password: str) -> None:
            calls.append(f"login {username}")

        def send_message(self, message: Any) -> None:
            calls.append(f"send {message['To']} {message['Subject']}")

    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    service = SmtpMailService("smtp.example.com", 587, "NETRA <no-reply@example.com>", "mailer", "app-password")

    service.send(MailMessage(to=EMAIL, subject="Subject", body="Body"))

    assert calls == ["connect smtp.example.com:587", "starttls", "login mailer", f"send {EMAIL} Subject", "quit"]


def test_existing_login_and_jwt_still_work(auth_client: TestClient) -> None:
    register(auth_client)

    response = auth_client.post(f"{AUTH_URL}/login", json={"email": EMAIL, "password": OLD_PASSWORD})
    me = auth_client.get(f"{AUTH_URL}/me", headers={"Authorization": f"Bearer {response.json()['access_token']}"})

    assert response.status_code == 200
    assert me.status_code == 200
    assert me.json()["email"] == EMAIL
