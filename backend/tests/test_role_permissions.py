from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.permissions import Permission, Role, has_permission
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.enums import AuthorizationStatus, IncidentState
from app.models.incident import Incident, IncidentHistory
from app.models.user import User
from app.services.auth import create_access_token
from app.services.decision_workflow import approve_decision_authorization
from tests.conftest import APPROVER_EMAIL, CoreApi
from tests.test_authorization import create_decision, request_authorization
from tests.test_containment import contain, create_pending_authorization
from tests.test_incident_verification import request_incident_verification
from tests.test_verification import verify

SELF_APPROVAL = "An authorization cannot be approved by the user who requested it"
ROLE_FORBIDDEN = "Your role does not permit this action"


def headers_for(core_api: CoreApi, *, role: str, active: bool = True) -> dict[str, str]:
    with core_api.session_factory() as session:
        user = User(
            email=f"{role}-{uuid4().hex[:8]}@example.com",
            full_name=f"Test {role}",
            password_hash="not-used-by-api-tests",
            role=role,
            is_active=active,
        )
        session.add(user)
        session.flush()
        token = create_access_token(user)
        session.commit()
    return {"Authorization": f"Bearer {token}"}


def approve(core_api: CoreApi, authorization_id: UUID, headers: dict[str, str] | None):
    return core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=headers)


def reject(core_api: CoreApi, authorization_id: UUID, headers: dict[str, str] | None):
    return core_api.client.post(
        f"/api/authorizations/{authorization_id}/reject",
        headers=headers,
        json={"reason": "Not justified."},
    )


def verified_pending_authorization(core_api: CoreApi, requester: dict[str, str]) -> tuple[UUID, UUID]:
    """A PENDING authorization on a VERIFIED incident, requested by ``requester``."""
    incident_id, decision_id, _ = create_decision(core_api)
    requested = core_api.client.post(f"/api/decisions/{decision_id}/authorize", headers=requester)
    assert requested.status_code == 201
    assert request_incident_verification(core_api, incident_id).status_code == 200
    return incident_id, UUID(requested.json()["id"])


def assert_still_pending(core_api: CoreApi, incident_id: UUID, authorization_id: UUID) -> None:
    with core_api.session_factory() as session:
        authorization = session.get(Authorization, authorization_id)
        incident = session.get(Incident, incident_id)
        resolutions = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id,
                IncidentHistory.action.in_(("authorization_approved", "authorization_rejected")),
            )
        ).all()
    assert authorization.status == AuthorizationStatus.PENDING
    assert authorization.approved_by is None
    assert incident.state == IncidentState.VERIFIED
    assert resolutions == []


# Role mapping


def test_role_permission_matrix() -> None:
    assert has_permission(Role.OPERATOR, Permission.REQUEST_AUTHORIZATION)
    assert has_permission(Role.OPERATOR, Permission.EXECUTE_CONTAINMENT)
    assert not has_permission(Role.OPERATOR, Permission.RESOLVE_AUTHORIZATION)
    for role in (Role.APPROVER, Role.ADMIN):
        assert all(has_permission(role, permission) for permission in Permission)


@pytest.mark.parametrize("role", ["viewer", "Admin", "", None])
def test_unknown_roles_grant_nothing(role: str | None) -> None:
    assert not any(has_permission(role, permission) for permission in Permission)


# Self-approval


@pytest.mark.parametrize("role", ["approver", "admin"])
def test_requester_cannot_approve_their_own_authorization(core_api: CoreApi, role: str) -> None:
    requester = headers_for(core_api, role=role)
    incident_id, authorization_id = verified_pending_authorization(core_api, requester)

    response = approve(core_api, authorization_id, requester)

    assert response.status_code == 403
    assert response.json()["detail"] == SELF_APPROVAL
    assert_still_pending(core_api, incident_id, authorization_id)


def test_self_approval_is_refused_by_the_service_for_any_caller(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_pending_authorization(core_api)
    assert request_incident_verification(core_api, incident_id).status_code == 200

    with core_api.session_factory() as session:
        with pytest.raises(HTTPException) as refused:
            # Requested by core-api-test@example.com; actor casing must not bypass the check.
            approve_decision_authorization(session, authorization_id, actor=" Core-API-Test@Example.com ")

    assert refused.value.status_code == 403
    assert refused.value.detail == SELF_APPROVAL
    assert_still_pending(core_api, incident_id, authorization_id)


# Approval by a different authorized user


@pytest.mark.parametrize("role", ["approver", "admin"])
def test_different_authorized_user_can_approve(core_api: CoreApi, role: str) -> None:
    incident_id, authorization_id = verified_pending_authorization(core_api, core_api.headers)
    approver = headers_for(core_api, role=role)

    response = approve(core_api, authorization_id, approver)

    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"
    assert response.json()["requestedBy"] == "core-api-test@example.com"
    assert response.json()["approvedBy"] != response.json()["requestedBy"]
    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == IncidentState.AUTHORIZED


def test_full_lifecycle_with_separate_requester_and_approver(core_api: CoreApi) -> None:
    incident_id, authorization_id = verified_pending_authorization(core_api, core_api.headers)

    approval = approve(core_api, authorization_id, core_api.approver_headers)
    execution = contain(core_api, authorization_id)  # executed by the operator who requested it
    verification = verify(core_api, UUID(execution.json()["id"]))
    memory = core_api.client.post(f"/api/incidents/{incident_id}/cyber-memory", headers=core_api.headers)

    assert approval.status_code == 200
    assert approval.json()["approvedBy"] == APPROVER_EMAIL
    assert execution.status_code == 201
    assert verification.status_code == 200
    assert memory.status_code == 201
    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == IncidentState.LEARNED


# Users without the required role


def test_operator_cannot_approve_or_reject(core_api: CoreApi) -> None:
    requester = headers_for(core_api, role="operator")
    incident_id, authorization_id = verified_pending_authorization(core_api, requester)

    responses = [
        approve(core_api, authorization_id, core_api.headers),
        reject(core_api, authorization_id, core_api.headers),
        approve(core_api, authorization_id, requester),
    ]

    assert [response.status_code for response in responses] == [403, 403, 403]
    assert all(response.json()["detail"] == ROLE_FORBIDDEN for response in responses)
    assert_still_pending(core_api, incident_id, authorization_id)


def test_user_without_a_recognised_role_cannot_request_resolve_or_contain(core_api: CoreApi) -> None:
    viewer = headers_for(core_api, role="viewer")
    _, decision_id, _ = create_decision(core_api)
    incident_id, authorization_id = verified_pending_authorization(core_api, core_api.headers)

    request = core_api.client.post(f"/api/decisions/{decision_id}/authorize", headers=viewer)
    approval = approve(core_api, authorization_id, viewer)
    rejection = reject(core_api, authorization_id, viewer)
    assert approve(core_api, authorization_id, core_api.approver_headers).status_code == 200
    execution = core_api.client.post(
        f"/api/authorizations/{authorization_id}/contain", headers=viewer, json={"simulateFailure": False}
    )

    assert [r.status_code for r in (request, approval, rejection, execution)] == [403, 403, 403, 403]
    with core_api.session_factory() as session:
        assert session.scalar(select(Authorization).where(Authorization.decision_id == decision_id)) is None
        actions = session.scalars(
            select(ContainmentAction).where(ContainmentAction.incident_id == incident_id)
        ).all()
    assert actions == []


def test_user_without_a_recognised_role_cannot_verify_containment(core_api: CoreApi) -> None:
    viewer = headers_for(core_api, role="viewer")
    _, authorization_id = verified_pending_authorization(core_api, core_api.headers)
    assert approve(core_api, authorization_id, core_api.approver_headers).status_code == 200
    execution = contain(core_api, authorization_id)
    assert execution.status_code == 201

    response = core_api.client.post(f"/api/containments/{execution.json()['id']}/verify", headers=viewer)

    assert response.status_code == 403
    assert response.json()["detail"] == ROLE_FORBIDDEN


def test_inactive_approver_and_missing_token_are_unauthorized(core_api: CoreApi) -> None:
    inactive = headers_for(core_api, role="approver", active=False)
    _, authorization_id = verified_pending_authorization(core_api, core_api.headers)

    assert approve(core_api, authorization_id, inactive).status_code == 401
    assert approve(core_api, authorization_id, None).status_code == 401
    assert reject(core_api, authorization_id, None).status_code == 401


def test_role_change_applies_to_existing_tokens(core_api: CoreApi) -> None:
    """The role is read from the database on every request, not trusted from the token."""
    _, authorization_id = verified_pending_authorization(core_api, core_api.headers)
    demoted = core_api.approver_headers
    with core_api.session_factory() as session:
        session.scalar(select(User).where(User.email == APPROVER_EMAIL)).role = "operator"
        session.commit()

    assert approve(core_api, authorization_id, demoted).status_code == 403


# Registration


def test_registration_assigns_operator_even_when_a_role_is_supplied(
    auth_client: TestClient, auth_db: sessionmaker[Session]
) -> None:
    response = auth_client.post(
        "/api/auth/register",
        json={
            "email": "escalate@example.com",
            "full_name": "Would-be Admin",
            "password": "a-long-test-password",
            "role": "admin",
            "is_active": True,
        },
    )

    assert response.status_code == 201
    assert response.json()["role"] == "operator"
    with auth_db() as session:
        stored = session.scalar(select(User).where(User.email == "escalate@example.com"))
    assert stored.role == Role.OPERATOR


def test_newly_registered_user_cannot_approve(core_api: CoreApi) -> None:
    credentials = {"email": "new-user@example.com", "password": "a-long-test-password"}
    registered = core_api.client.post(
        "/api/auth/register", json={**credentials, "full_name": "New User", "role": "approver"}
    )
    login = core_api.client.post("/api/auth/login", json=credentials)
    new_user = {"Authorization": f"Bearer {login.json()['access_token']}"}
    incident_id, authorization_id = verified_pending_authorization(core_api, core_api.headers)

    response = approve(core_api, authorization_id, new_user)

    assert registered.status_code == 201
    assert registered.json()["role"] == "operator"
    assert response.status_code == 403
    assert_still_pending(core_api, incident_id, authorization_id)


def test_newly_registered_operator_can_still_request_authorization(core_api: CoreApi) -> None:
    credentials = {"email": "requester@example.com", "password": "a-long-test-password"}
    core_api.client.post("/api/auth/register", json={**credentials, "full_name": "Requester"})
    login = core_api.client.post("/api/auth/login", json=credentials)
    _, decision_id, _ = create_decision(core_api)

    response = request_authorization(
        CoreApi(
            client=core_api.client,
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            session_factory=core_api.session_factory,
            approver_headers=core_api.approver_headers,
        ),
        decision_id,
    )

    assert response.status_code == 201
    assert response.json()["requestedBy"] == "requester@example.com"
