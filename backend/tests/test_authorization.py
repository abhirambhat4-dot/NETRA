from uuid import UUID

from sqlalchemy import select

from app.models.authorization import Authorization
from app.models.enums import AuthorizationStatus, IncidentState
from app.models.incident import Incident, IncidentHistory
from app.models.containment import ContainmentAction
from tests.conftest import CoreApi
from tests.test_decision import request_decision, seed_prioritised_incident
from tests.test_incident_verification import request_incident_verification


def create_decision(core_api: CoreApi, *, state: IncidentState = IncidentState.PRIORITISED):
    incident_id = seed_prioritised_incident(core_api, state=state)
    response = request_decision(core_api, incident_id)
    assert response.status_code == 201
    return incident_id, UUID(response.json()["id"]), response.json()["action"]


def request_authorization(core_api: CoreApi, decision_id: UUID):
    return core_api.client.post(
        f"/api/decisions/{decision_id}/authorize",
        headers=core_api.headers,
    )


def test_authorization_endpoints_require_authentication(core_api: CoreApi) -> None:
    _, decision_id, _ = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])

    responses = [
        core_api.client.post(f"/api/decisions/{decision_id}/authorize"),
        core_api.client.post(f"/api/authorizations/{authorization_id}/approve"),
        core_api.client.post(
            f"/api/authorizations/{authorization_id}/reject",
            json={"reason": "Not approved"},
        ),
    ]

    assert pending.status_code == 201
    assert [response.status_code for response in responses] == [401, 401, 401]


def test_valid_decision_creates_pending_authorization_with_matching_action(core_api: CoreApi) -> None:
    incident_id, decision_id, action = create_decision(core_api)

    response = request_authorization(core_api, decision_id)

    assert response.status_code == 201
    assert response.json()["incidentId"] == str(incident_id)
    assert response.json()["decisionId"] == str(decision_id)
    assert response.json()["requestedAction"] == action
    assert response.json()["status"] == "PENDING"
    assert response.json()["requestedBy"] == "core-api-test@example.com"
    assert response.json()["requestedAt"]


def test_approval_requires_verified_state_and_then_authorizes_incident(core_api: CoreApi) -> None:
    incident_id, decision_id, _ = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])

    before_verification = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )
    verification = request_incident_verification(core_api, incident_id)

    approved = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )

    assert before_verification.status_code == 409
    assert verification.status_code == 200
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["approvedBy"] == "core-api-test@example.com"
    assert approved.json()["approvedAt"]
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        authorization = session.get(Authorization, authorization_id)
    assert incident.state == IncidentState.AUTHORIZED
    assert authorization.status == AuthorizationStatus.APPROVED


def test_rejection_requires_reason_and_sets_rejected_state(core_api: CoreApi) -> None:
    _, decision_id, _ = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])

    missing_reason = core_api.client.post(
        f"/api/authorizations/{authorization_id}/reject",
        headers=core_api.headers,
        json={"reason": "   "},
    )
    rejected = core_api.client.post(
        f"/api/authorizations/{authorization_id}/reject",
        headers=core_api.headers,
        json={"reason": "Insufficient evidence for the requested action."},
    )

    assert missing_reason.status_code == 422
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert rejected.json()["approvedBy"] == "core-api-test@example.com"
    assert rejected.json()["reason"] == "Insufficient evidence for the requested action."
    assert rejected.json()["approvedAt"]


def test_approved_authorization_cannot_be_approved_twice(core_api: CoreApi) -> None:
    incident_id, decision_id, _ = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])
    verification = request_incident_verification(core_api, incident_id)

    first = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )
    second = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )

    assert first.status_code == 200
    assert verification.status_code == 200
    assert second.status_code == 409


def test_rejected_authorization_cannot_be_approved_later(core_api: CoreApi) -> None:
    _, decision_id, _ = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])
    rejected = core_api.client.post(
        f"/api/authorizations/{authorization_id}/reject",
        headers=core_api.headers,
        json={"reason": "Rejected for testing."},
    )

    approval = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )

    assert rejected.status_code == 200
    assert approval.status_code == 409


def test_duplicate_authorization_request_is_rejected(core_api: CoreApi) -> None:
    _, decision_id, _ = create_decision(core_api)

    first = request_authorization(core_api, decision_id)
    second = request_authorization(core_api, decision_id)

    assert first.status_code == 201
    assert second.status_code == 409


def test_missing_decision_cannot_be_authorized(core_api: CoreApi) -> None:
    response = request_authorization(core_api, UUID(int=0))

    assert response.status_code == 404


def test_authorization_history_records_request_approval_and_transition(core_api: CoreApi) -> None:
    incident_id, decision_id, action = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])
    verification = request_incident_verification(core_api, incident_id)
    approved = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )

    with core_api.session_factory() as session:
        histories = session.scalars(
            select(IncidentHistory)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.occurred_at)
        ).all()
    actions = [history.action for history in histories]
    request_history = next(row for row in histories if row.action == "authorization_requested")
    approval_history = next(row for row in histories if row.action == "authorization_approved")
    assert approved.status_code == 200
    assert verification.status_code == 200
    assert "authorization_requested" in actions
    assert "authorization_approved" in actions
    assert request_history.actor == "core-api-test@example.com"
    assert request_history.details["decision_id"] == str(decision_id)
    assert request_history.details["requested_action"] == action
    assert approval_history.from_state == IncidentState.VERIFIED
    assert approval_history.to_state == IncidentState.AUTHORIZED
    assert approval_history.details["authorization_id"] == str(authorization_id)


def test_authorization_never_creates_or_executes_containment(core_api: CoreApi) -> None:
    incident_id, decision_id, _ = create_decision(core_api)
    pending = request_authorization(core_api, decision_id)
    authorization_id = UUID(pending.json()["id"])
    verification = request_incident_verification(core_api, incident_id)

    approved = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )

    with core_api.session_factory() as session:
        actions = session.scalars(
            select(ContainmentAction).where(ContainmentAction.incident_id == incident_id)
        ).all()
    assert approved.status_code == 200
    assert verification.status_code == 200
    assert actions == []
