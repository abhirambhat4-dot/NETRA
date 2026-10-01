import asyncio
import json
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema
from sqlalchemy.pool import StaticPool

# Provide an ephemeral key when a developer has not configured one locally.
os.environ.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(32))

from app.db.dependencies import get_db
from app.db.base import Base
from app.db.session import engine as postgres_engine
from app.models import *  # noqa: F403
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.main import app
from app.services.auth import create_access_token

AsgiGet = Callable[[str], tuple[int, dict[str, Any]]]


def _asgi_get(path: str) -> tuple[int, dict[str, Any]]:
    """Send a GET request straight to the ASGI app (no HTTP client dependency)."""
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))

    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(body)


@pytest.fixture
def asgi_get() -> AsgiGet:
    return _asgi_get


@pytest.fixture
def auth_db() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    User.__table__.create(engine)
    PasswordResetToken.__table__.create(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    yield factory
    engine.dispose()


@pytest.fixture
def auth_client(auth_db: sessionmaker[Session]) -> Any:
    def override_db() -> Any:
        with auth_db() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


@dataclass
class CoreApi:
    client: TestClient
    headers: dict[str, str]
    session_factory: sessionmaker[Session]


@pytest.fixture
def core_api() -> Any:
    schema = f"netra_api_test_{uuid4().hex[:12]}"
    with postgres_engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            isolated_connection = connection.execution_options(schema_translate_map={None: schema})
            Base.metadata.create_all(isolated_connection)
            factory: sessionmaker[Session] = sessionmaker(
                bind=isolated_connection,
                autoflush=False,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            )
            with factory() as session:
                user = User(
                    email="core-api-test@example.com",
                    full_name="Core API Test User",
                    password_hash="not-used-by-api-tests",
                )
                session.add(user)
                session.flush()
                token = create_access_token(user)
                session.commit()

            def override_db() -> Any:
                with factory() as session:
                    yield session

            previous_override = app.dependency_overrides.get(get_db)
            app.dependency_overrides[get_db] = override_db
            try:
                with TestClient(app) as client:
                    yield CoreApi(
                        client=client,
                        headers={"Authorization": f"Bearer {token}"},
                        session_factory=factory,
                    )
            finally:
                if previous_override is None:
                    app.dependency_overrides.pop(get_db, None)
                else:
                    app.dependency_overrides[get_db] = previous_override
        finally:
            transaction.rollback()
