"""ALLOW_PUBLIC_REGISTRATION: closed by default, and closing it changes nothing for existing accounts.

Runs against the in-memory SQLite user store (``auth_db``); no PostgreSQL database is involved.
"""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.auth import REGISTRATION_DISABLED, registration_enabled
from app.core.config import Settings
from app.main import app
from app.models.user import User
from app.services.auth import create_access_token, hash_password
from tests.test_password_reset import (  # noqa: F401  (fixtures: clear_rate_limits is autouse)
    NEW_PASSWORD,
    clear_rate_limits,
    outbox,
    request_reset,
    token_from,
)
from tests.test_workflow_permissions import PUBLIC_WRITES, api_routes, required_permissions

AUTH_URL = "/api/auth"
EXISTING_EMAIL = "existing-operator@example.com"
EXISTING_PASSWORD = "existing-password-123"
NEW_ACCOUNT = {"email": "newcomer@example.com", "full_name": "Newcomer", "password": "a-long-test-password"}


@pytest.fixture
def existing_user(auth_db: sessionmaker[Session]) -> User:
    """An account created before registration closed (as an administrator would create it)."""
    with auth_db() as session:
        user = User(
            email=EXISTING_EMAIL,
            full_name="Existing Operator",
            password_hash=hash_password(EXISTING_PASSWORD),
            role="operator",
        )
        session.add(user)
        session.commit()
        return user


def user_count(auth_db: sessionmaker[Session]) -> int:
    with auth_db() as session:
        return session.scalar(select(func.count()).select_from(User)) or 0


def login(client: TestClient, email: str, password: str) -> Any:
    return client.post(f"{AUTH_URL}/login", json={"email": email, "password": password})


def settings_from_environment() -> Settings:
    """Settings from the environment only; the values below are inert placeholders, never connected to."""
    return Settings(_env_file=None, database_url="sqlite://", jwt_secret_key="k" * 32)


def test_registration_is_closed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOW_PUBLIC_REGISTRATION", raising=False)
    settings = settings_from_environment()

    assert settings.allow_public_registration is False


@pytest.mark.parametrize(("value", "expected"), [("true", True), ("false", False)])
def test_registration_setting_is_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    monkeypatch.setenv("ALLOW_PUBLIC_REGISTRATION", value)
    settings = settings_from_environment()

    assert settings.allow_public_registration is expected


def test_closed_registration_is_refused_and_creates_no_user(
    auth_client: TestClient, auth_db: sessionmaker[Session]
) -> None:
    response = auth_client.post(f"{AUTH_URL}/register", json=NEW_ACCOUNT)

    assert response.status_code == 403
    assert response.json() == {"detail": REGISTRATION_DISABLED}
    assert user_count(auth_db) == 0


def test_closed_registration_ignores_a_supplied_role(auth_client: TestClient, auth_db: sessionmaker[Session]) -> None:
    response = auth_client.post(f"{AUTH_URL}/register", json={**NEW_ACCOUNT, "role": "admin", "is_active": True})

    assert response.status_code == 403
    assert user_count(auth_db) == 0


def test_closed_registration_does_not_reveal_registered_emails(
    auth_client: TestClient, auth_db: sessionmaker[Session], existing_user: User
) -> None:
    taken = auth_client.post(f"{AUTH_URL}/register", json={**NEW_ACCOUNT, "email": EXISTING_EMAIL})
    unused = auth_client.post(f"{AUTH_URL}/register", json=NEW_ACCOUNT)

    assert taken.status_code == unused.status_code == 403
    assert taken.json() == unused.json() == {"detail": REGISTRATION_DISABLED}
    assert user_count(auth_db) == 1


@pytest.mark.usefixtures("open_registration")
def test_open_registration_still_creates_an_operator(auth_client: TestClient, auth_db: sessionmaker[Session]) -> None:
    response = auth_client.post(f"{AUTH_URL}/register", json=NEW_ACCOUNT)

    assert response.status_code == 201
    assert response.json()["role"] == "operator"
    assert user_count(auth_db) == 1


def test_existing_user_can_log_in_and_use_me_while_registration_is_closed(
    auth_client: TestClient, existing_user: User
) -> None:
    response = login(auth_client, EXISTING_EMAIL, EXISTING_PASSWORD)
    assert response.status_code == 200

    me = auth_client.get(f"{AUTH_URL}/me", headers={"Authorization": f"Bearer {response.json()['access_token']}"})

    assert me.status_code == 200
    assert me.json()["email"] == EXISTING_EMAIL


def test_tokens_issued_before_closing_registration_stay_valid(auth_client: TestClient, existing_user: User) -> None:
    token = create_access_token(existing_user)

    me = auth_client.get(f"{AUTH_URL}/me", headers={"Authorization": f"Bearer {token}"})

    assert me.status_code == 200
    assert me.json()["email"] == EXISTING_EMAIL


def test_password_reset_still_works_while_registration_is_closed(
    auth_client: TestClient, existing_user: User, outbox: list[Any]
) -> None:
    assert request_reset(auth_client, EXISTING_EMAIL).status_code == 202
    token = token_from(outbox[0])

    reset = auth_client.post(f"{AUTH_URL}/reset-password", json={"token": token, "new_password": NEW_PASSWORD})

    assert reset.status_code == 200
    assert login(auth_client, EXISTING_EMAIL, NEW_PASSWORD).status_code == 200
    assert login(auth_client, EXISTING_EMAIL, EXISTING_PASSWORD).status_code == 401


def test_register_stays_a_public_route_without_a_permission_gate() -> None:
    route = api_routes()[("POST", "/api/auth/register")]

    assert ("POST", "/api/auth/register") in PUBLIC_WRITES
    assert required_permissions(route) == set()


def test_open_registration_override_is_removed_after_each_test() -> None:
    assert registration_enabled not in app.dependency_overrides
