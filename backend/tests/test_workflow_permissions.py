"""Workflow and intake writes require Permission.OPERATE_WORKFLOW.

These tests need no PostgreSQL: route coverage is read from the application's dependency graph, and the
HTTP checks run against the in-memory SQLite user store (``auth_db``). The permission dependency rejects
the request before any route logic, so no other table is touched.
"""

import importlib
import pkgutil
from typing import Annotated, Any
from uuid import uuid4

import pytest
from fastapi import APIRouter, Depends
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

import app.api
from app.api.auth import require_permission
from app.core.permissions import Permission, Role, has_permission
from app.main import app as application
from app.models.user import User
from app.services.auth import create_access_token

ROLE_FORBIDDEN = "Your role does not permit this action"
ID = "{id}"
WORKFLOW_ROUTES = [
    "/api/incidents",
    f"/api/incidents/{ID}/events",
    f"/api/incidents/{ID}/enrich",
    f"/api/incidents/{ID}/correlate",
    f"/api/incidents/{ID}/risk-score",
    f"/api/incidents/{ID}/verify",
    f"/api/incidents/{ID}/decision",
    f"/api/incidents/{ID}/cyber-memory",
    "/api/events/ingest",
    "/api/collector/events",
    "/api/imports",
    "/api/assessments",
]
# Writes that are public by design: account creation and recovery. Exempt by method and path, so another
# method added on one of these paths is still scanned.
PUBLIC_WRITES = {
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/forgot-password"),
    ("POST", "/api/auth/reset-password"),
}
# Every other method counts as a write for the coverage scan.
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def required_permissions(route: APIRoute) -> set[Permission]:
    found: set[Permission] = set()
    pending = list(route.dependant.dependencies)
    while pending:
        dependant = pending.pop()
        permission = getattr(dependant.call, "required_permission", None)
        if permission is not None:
            found.add(permission)
        pending.extend(dependant.dependencies)
    return found


def api_route_entries() -> list[tuple[str, str, APIRoute]]:
    """(method, served path, route) for every method of every route declared by an ``app.api`` module router.

    Read from the public module routers: newer FastAPI versions keep included routers as lazy wrappers
    in ``app.routes``. All routers are mounted under ``/api`` (app/main.py). Duplicates are kept, so a
    second declaration of the same method and path cannot hide the first from the scan.
    """
    entries: list[tuple[str, str, APIRoute]] = []
    for module in pkgutil.iter_modules(app.api.__path__):
        router = getattr(importlib.import_module(f"app.api.{module.name}"), "router", None)
        for route in getattr(router, "routes", []):
            if isinstance(route, APIRoute):
                entries.extend((method, f"/api{route.path}", route) for method in route.methods)
    return entries


def api_routes() -> dict[tuple[str, str], APIRoute]:
    """Every declared route, keyed by (method, served path)."""
    return {(method, path): route for method, path, route in api_route_entries()}


def post_routes() -> dict[str, APIRoute]:
    return {path.replace("{incident_id}", ID): route for (method, path), route in api_routes().items() if method == "POST"}


def ungated_writes(routes: dict[tuple[str, str], APIRoute]) -> list[str]:
    """Non-public write routes (any method but GET, HEAD and OPTIONS) that require no permission."""
    return sorted(
        f"{method} {path}"
        for (method, path), route in routes.items()
        if method not in READ_METHODS and (method, path) not in PUBLIC_WRITES and not required_permissions(route)
    )


def test_route_scan_covers_every_served_route() -> None:
    served = {(method.upper(), path) for path, operations in application.openapi()["paths"].items() for method in operations}

    assert served <= set(api_routes())


def test_operate_workflow_is_granted_to_every_recognised_role_only() -> None:
    for role in Role:
        assert has_permission(role, Permission.OPERATE_WORKFLOW)
    for role in ("viewer", "Operator", "", None):
        assert not has_permission(role, Permission.OPERATE_WORKFLOW)


@pytest.mark.parametrize("path", WORKFLOW_ROUTES)
def test_workflow_route_requires_operate_workflow(path: str) -> None:
    assert Permission.OPERATE_WORKFLOW in required_permissions(post_routes()[path])


def test_role_gated_routes_outside_the_workflow_keep_their_own_permissions() -> None:
    routes = post_routes()

    assert required_permissions(routes["/api/decisions/{decision_id}/authorize"]) == {Permission.REQUEST_AUTHORIZATION}
    for path in ("/api/authorizations/{authorization_id}/approve", "/api/authorizations/{authorization_id}/reject"):
        assert required_permissions(routes[path]) == {Permission.RESOLVE_AUTHORIZATION}
    for path in ("/api/authorizations/{authorization_id}/contain", "/api/containments/{containment_id}/verify"):
        assert required_permissions(routes[path]) == {Permission.EXECUTE_CONTAINMENT}


def test_every_non_public_write_route_requires_a_permission() -> None:
    keys = [(method, path) for method, path, _ in api_route_entries()]
    routes = api_routes()

    # A duplicate (method, path) would let one declaration hide the other from the scan.
    assert sorted({f"{method} {path}" for method, path in keys if keys.count((method, path)) > 1}) == []
    assert PUBLIC_WRITES <= set(routes)  # every exemption still names a real route
    assert ungated_writes(routes) == []


def test_write_scan_flags_ungated_routes_of_every_write_method() -> None:
    gate = Depends(require_permission(Permission.OPERATE_WORKFLOW))

    def endpoint() -> None:
        return None

    def gated_endpoint(_: Annotated[User, gate]) -> None:
        return None

    probe = APIRouter()
    probe.add_api_route("/probe", endpoint, methods=["GET", "HEAD", "OPTIONS"])  # reads are never flagged
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        probe.add_api_route("/probe", endpoint, methods=[method])
        probe.add_api_route("/probe/gated", gated_endpoint, methods=[method])
    probe.add_api_route("/auth/login", endpoint, methods=["POST"])  # a real public exemption
    probe.add_api_route("/auth/register", endpoint, methods=["PUT"])  # public only for POST
    routes = {
        (method, f"/api{route.path}"): route
        for route in probe.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }

    assert ungated_writes(routes) == [
        "DELETE /api/probe",
        "PATCH /api/probe",
        "POST /api/probe",
        "PUT /api/auth/register",
        "PUT /api/probe",
    ]


@pytest.fixture
def role_headers(auth_db: sessionmaker[Session]) -> Any:
    def make(role: str) -> dict[str, str]:
        with auth_db() as session:
            user = User(
                email=f"{uuid4().hex[:8]}@example.com",
                full_name="Permission Test",
                password_hash="not-used-by-api-tests",
                role=role,
            )
            session.add(user)
            session.commit()
            return {"Authorization": f"Bearer {create_access_token(user)}"}

    return make


@pytest.mark.parametrize("role", ["viewer", "Operator", ""])
@pytest.mark.parametrize("path", WORKFLOW_ROUTES)
def test_unrecognised_role_is_forbidden(auth_client: TestClient, role_headers: Any, path: str, role: str) -> None:
    response = auth_client.post(path.replace(ID, str(uuid4())), headers=role_headers(role), json={})

    assert response.status_code == 403
    assert response.json()["detail"] == ROLE_FORBIDDEN


@pytest.mark.parametrize("path", WORKFLOW_ROUTES)
def test_missing_token_is_unauthorized(auth_client: TestClient, path: str) -> None:
    response = auth_client.post(path.replace(ID, str(uuid4())), json={})

    assert response.status_code == 401


def test_unrecognised_role_cannot_verify_an_incident(auth_client: TestClient, role_headers: Any) -> None:
    response = auth_client.post(f"/api/incidents/{uuid4()}/verify", headers=role_headers("viewer"))

    assert response.status_code == 403
    assert response.json()["detail"] == ROLE_FORBIDDEN
