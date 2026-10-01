from uuid import UUID

from app.models.containment import ContainmentAction
from app.models.enums import ContainmentStatus, IncidentState, ResponseAction
from app.models.incident import Incident
from tests.conftest import CoreApi
from tests.test_containment import contain, create_approved_authorization


def verify(core_api: CoreApi, containment_id: UUID, *, authenticated: bool = True):
    headers = core_api.headers if authenticated else None
    return core_api.client.post(
        f"/api/containments/{containment_id}/verify",
        headers=headers,
    )


def test_verification_endpoint_requires_authentication(core_api: CoreApi) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)
    containment_response = contain(core_api, authorization_id)

    response = verify(core_api, UUID(containment_response.json()["id"]), authenticated=False)

    assert response.status_code == 401


def test_missing_containment_is_rejected(core_api: CoreApi) -> None:
    response = verify(core_api, UUID(int=0))

    assert response.status_code == 404


def test_unexecuted_containment_cannot_be_verified(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    with core_api.session_factory() as session:
        containment = ContainmentAction(
            incident_id=incident_id,
            authorization_id=authorization_id,
            action_type=ResponseAction.ISOLATE_HOST,
            target="test target",
            status=ContainmentStatus.PENDING,
            executed_at=None,
            verified_at=None,
        )
        session.add(containment)
        session.commit()
        containment_id = containment.id

    response = verify(core_api, containment_id)

    assert response.status_code == 409
    assert "execution" in response.json()["detail"].lower()


def test_successful_verification_records_result_and_contains_incident(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    execution = contain(core_api, authorization_id)
    containment_id = UUID(execution.json()["id"])

    response = verify(core_api, containment_id)

    assert execution.status_code == 201
    assert response.status_code == 200
    assert response.json()["status"] == "VERIFIED"
    assert response.json()["verifiedAt"]
    assert "Verification succeeded" in response.json()["result"]
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        containment = session.get(ContainmentAction, containment_id)
    assert incident.state == IncidentState.CONTAINED
    assert containment.status == ContainmentStatus.VERIFIED


def test_failed_verification_preserves_failure_and_does_not_contain(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    execution = contain(core_api, authorization_id, simulate_failure=True)
    containment_id = UUID(execution.json()["id"])
    original_error = execution.json()["errorMessage"]

    response = verify(core_api, containment_id)

    assert execution.status_code == 201
    assert response.status_code == 200
    assert response.json()["status"] == "FAILED"
    assert response.json()["verifiedAt"]
    assert response.json()["errorMessage"] == original_error
    assert "Verification failed" in response.json()["result"]
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
    assert incident.state == IncidentState.AUTHORIZED


def test_verification_cannot_be_repeated_after_success(core_api: CoreApi) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)
    execution = contain(core_api, authorization_id)
    containment_id = UUID(execution.json()["id"])
    first = verify(core_api, containment_id)

    second = verify(core_api, containment_id)

    assert first.status_code == 200
    assert second.status_code == 409