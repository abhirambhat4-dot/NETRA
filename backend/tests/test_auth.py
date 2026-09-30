from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.user import User

AUTH_URL = "/api/auth"
REGISTER_DATA = {
    "email": "operator@example.com",
    "full_name": "NETRA Operator",
    "password": "a-long-test-password",
}


def register_user(client: TestClient) -> dict[str, Any]:
    response = client.post(f"{AUTH_URL}/register", json=REGISTER_DATA)
    assert response.status_code == 201
    return response.json()


def test_successful_registration_returns_safe_user(auth_client: TestClient) -> None:
    data = register_user(auth_client)

    assert data["email"] == REGISTER_DATA["email"]
    assert data["role"] == "operator"
    assert data["is_active"] is True
    assert "password_hash" not in data
    assert "password" not in data


def test_duplicate_registration_is_rejected(auth_client: TestClient) -> None:
    register_user(auth_client)

    response = auth_client.post(f"{AUTH_URL}/register", json=REGISTER_DATA)

    assert response.status_code == 409


def test_password_is_hashed(auth_client: TestClient, auth_db: sessionmaker[Session]) -> None:
    data = register_user(auth_client)
    with auth_db() as session:
        user = session.get(User, UUID(data["id"]))

    assert user is not None
    assert user.password_hash != REGISTER_DATA["password"]
    assert user.password_hash.startswith("$argon2")


def test_successful_login_returns_jwt(auth_client: TestClient) -> None:
    register_user(auth_client)

    response = auth_client.post(
        f"{AUTH_URL}/login",
        json={"email": REGISTER_DATA["email"], "password": REGISTER_DATA["password"]},
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    claims = jwt.decode(
        response.json()["access_token"],
        get_settings().jwt_secret_key.get_secret_value(),
        algorithms=["HS256"],
    )
    assert claims["sub"]
    assert claims["email"] == REGISTER_DATA["email"]
    assert claims["role"] == "operator"
    assert "exp" in claims


def test_incorrect_and_nonexistent_credentials_are_generic(auth_client: TestClient) -> None:
    register_user(auth_client)
    wrong_password = auth_client.post(
        f"{AUTH_URL}/login",
        json={"email": REGISTER_DATA["email"], "password": "wrong-password"},
    )
    nonexistent_user = auth_client.post(
        f"{AUTH_URL}/login",
        json={"email": "missing@example.com", "password": "wrong-password"},
    )

    assert wrong_password.status_code == nonexistent_user.status_code == 401
    assert wrong_password.json() == nonexistent_user.json()


def test_auth_me_returns_current_user(auth_client: TestClient) -> None:
    user = register_user(auth_client)
    token_response = auth_client.post(
        f"{AUTH_URL}/login",
        json={"email": REGISTER_DATA["email"], "password": REGISTER_DATA["password"]},
    )

    response = auth_client.get(
        f"{AUTH_URL}/me",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == user["id"]
    assert "password_hash" not in response.json()


def test_auth_me_rejects_invalid_jwt(auth_client: TestClient) -> None:
    response = auth_client.get(
        f"{AUTH_URL}/me",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 401


def test_auth_me_rejects_expired_jwt(auth_client: TestClient) -> None:
    user = register_user(auth_client)
    claims = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.now(UTC) - timedelta(seconds=1),
    }
    token = jwt.encode(
        claims,
        get_settings().jwt_secret_key.get_secret_value(),
        algorithm="HS256",
    )

    response = auth_client.get(f"{AUTH_URL}/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_inactive_user_cannot_login_or_use_token(
    auth_client: TestClient,
    auth_db: sessionmaker[Session],
) -> None:
    user_data = register_user(auth_client)
    claims = {
        "sub": user_data["id"],
        "email": user_data["email"],
        "role": user_data["role"],
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }
    token = jwt.encode(
        claims,
        get_settings().jwt_secret_key.get_secret_value(),
        algorithm="HS256",
    )
    with auth_db() as session:
        user = session.get(User, UUID(user_data["id"]))
        assert user is not None
        user.is_active = False
        session.commit()

    login_response = auth_client.post(
        f"{AUTH_URL}/login",
        json={"email": REGISTER_DATA["email"], "password": REGISTER_DATA["password"]},
    )
    me_response = auth_client.get(f"{AUTH_URL}/me", headers={"Authorization": f"Bearer {token}"})

    assert login_response.status_code == 401
    assert me_response.status_code == 401


def test_openapi_exposes_bearer_authentication(auth_client: TestClient) -> None:
    response = auth_client.get("/openapi.json")

    assert response.status_code == 200
    assert "BearerAuth" in response.json()["components"]["securitySchemes"]


def test_cors_allows_local_frontend_origin(auth_client: TestClient) -> None:
    response = auth_client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"