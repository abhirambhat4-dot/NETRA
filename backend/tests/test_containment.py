from uuid import UUID

from sqlalchemy import select

from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.decision import Decision
from app.models.enums import (
    AuthorizationStatus,
    ContainmentStatus,
    IncidentState,
    ResponseAction,
)
from app.models.incident import Incident, IncidentHistory
from tests.conftest import CoreApi
from tests.test_authorization import request_authorization
from tests.test_decision import request_decision, seed_prioritised_incident
from tests.test_incident_verification import request_incident_verification


def create_pending_authorization(core_api: CoreApi):
    incident_id = seed_prioritised_incident(core_api)
    decision_response = request_decision(core_api, incident_id)
    assert decision_response.status_code == 201
    decision_id = UUID(decision_response.json()["id"])
    authorization_response = request_authorization(core_api, decision_id)
    assert authorization_response.status_code == 201
    return incident_id, decision_id, UUID(authorization_response.json()["id"])


def approve_authorization(core_api: CoreApi, incident_id: UUID, authorization_id: UUID) -> None:
    verification = request_incident_verification(core_api, incident_id)
    assert verification.status_code == 200
    response = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )
    assert response.status_code == 200


def create_approved_authorization(core_api: CoreApi):
    incident_id, decision_id, authorization_id = create_pending_authorization(core_api)
    approve_authorization(core_api, incident_id, authorization_id)
    return incident_id, decision_id, authorization_id


def contain(core_api: CoreApi, authorization_id: UUID, *, simulate_failure: bool = False):
    return core_api.client.post(
        f"/api/authorizations/{authorization_id}/contain",
        headers=core_api.headers,
        json={"simulateFailure": simulate_failure},
    )


def test_containment_endpoint_requires_authentication(core_api: CoreApi) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)

    response = core_api.client.post(f"/api/authorizations/{authorization_id}/contain")

    assert response.status_code == 401


def test_missing_authorization_is_rejected(core_api: CoreApi) -> None:
    response = contain(core_api, UUID(int=0))

    assert response.status_code == 404


def test_pending_and_rejected_authorizations_cannot_contain(core_api: CoreApi) -> None:
    pending_incident_id, _, pending_id = create_pending_authorization(core_api)
    rejected_incident_id, _, rejected_id = create_pending_authorization(core_api)
    rejection = core_api.client.post(
        f"/api/authorizations/{rejected_id}/reject",
        headers=core_api.headers,
        json={"reason": "Not approved for containment."},
    )

    pending_response = contain(core_api, pending_id)
    rejected_response = contain(core_api, rejected_id)

    assert pending_incident_id != rejected_incident_id
    assert rejection.status_code == 200
    assert pending_response.status_code == rejected_response.status_code == 409


def test_approved_authorization_runs_controlled_containment(core_api: CoreApi) -> None:
    incident_id, decision_id, authorization_id = create_approved_authorization(core_api)

    response = contain(core_api, authorization_id)

    assert response.status_code == 201
    assert response.json()["incidentId"] == str(incident_id)
    assert response.json()["authorizationId"] == str(authorization_id)
    assert response.json()["actionType"] == "ISOLATE_HOST"
    assert response.json()["target"] == "decision-server"
    assert response.json()["status"] == "SUCCEEDED"
    assert "Simulated" in response.json()["result"]
    assert "no real system or network changes" in response.json()["result"]
    assert response.json()["executedAt"]
    with core_api.session_factory() as session:
        containment = session.get(ContainmentAction, UUID(response.json()["id"]))
        decision = session.get(Decision, decision_id)
        incident = session.get(Incident, incident_id)
    assert containment is not None
    assert containment.authorization_id == authorization_id
    assert containment.action_type == decision.action
    assert incident.state == IncidentState.AUTHORIZED


def test_containment_rejects_action_mismatch(core_api: CoreApi) -> None:
    incident_id, decision_id, authorization_id = create_approved_authorization(core_api)
    with core_api.session_factory() as session:
        authorization = session.get(Authorization, authorization_id)
        authorization.requested_action = ResponseAction.BLOCK_IP
        session.commit()

    response = contain(core_api, authorization_id)

    assert response.status_code == 409
    assert "must match" in response.json()["detail"]
    with core_api.session_factory() as session:
        records = session.scalars(
            select(ContainmentAction).where(ContainmentAction.incident_id == incident_id)
        ).all()
    assert records == []
    assert decision_id is not None


def test_containment_requires_authorized_incident_state(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    with core_api.session_factory() as session:
        session.get(Incident, incident_id).state = IncidentState.VERIFIED
        session.commit()

    response = contain(core_api, authorization_id)

    assert response.status_code == 409
    assert "AUTHORIZED" in response.json()["detail"]


def test_simulated_failure_is_recorded_for_verification(core_api: CoreApi) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)

    response = contain(core_api, authorization_id, simulate_failure=True)

    assert response.status_code == 201
    assert response.json()["status"] == "FAILED"
    assert response.json()["executedAt"]
    assert "failure requested" in response.json()["errorMessage"]
    assert "no real system or network changes" in response.json()["result"]


def test_duplicate_containment_is_rejected_and_history_is_recorded(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)

    first = contain(core_api, authorization_id)
    second = contain(core_api, authorization_id)

    assert first.status_code == 201
    assert second.status_code == 409
    with core_api.session_factory() as session:
        actions = session.scalars(
            select(ContainmentAction).where(ContainmentAction.authorization_id == authorization_id)
        ).all()
        history = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id,
                IncidentHistory.action.in_(("containment_requested", "containment_executed")),
            )
        ).all()
    assert len(actions) == 1
    assert {row.action for row in history} == {"containment_requested", "containment_executed"}
    assert all(row.actor == "core-api-test@example.com" for row in history)
    assert all(row.occurred_at is not None for row in history)


def test_unapproved_action_cannot_be_used_as_containment(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)
    decision_response = request_decision(core_api, incident_id)
    decision_id = UUID(decision_response.json()["id"])
    authorization_response = request_authorization(core_api, decision_id)
    authorization_id = UUID(authorization_response.json()["id"])
    with core_api.session_factory() as session:
        session.get(Incident, incident_id).state = IncidentState.AUTHORIZED
        session.commit()

    response = contain(core_api, authorization_id)

    assert authorization_response.status_code == 201
    assert response.status_code == 409
    assert response.json()["detail"] == "Authorization must be APPROVED before containment"