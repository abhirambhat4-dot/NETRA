from uuid import UUID

from app.models.enums import IncidentState
from app.models.incident import Incident, IncidentHistory
from tests.conftest import CoreApi
from tests.test_decision import seed_prioritised_incident


def request_incident_verification(
    core_api: CoreApi,
    incident_id: UUID,
    *,
    authenticated: bool = True,
):
    headers = core_api.headers if authenticated else None
    return core_api.client.post(
        f"/api/incidents/{incident_id}/verify",
        headers=headers,
    )


def test_prioritised_incident_can_be_verified_and_persisted(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = request_incident_verification(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["id"] == str(incident_id)
    assert response.json()["state"] == "VERIFIED"
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        history = session.query(IncidentHistory).filter_by(
            incident_id=incident_id,
            action="incident_verified",
        ).one()
    assert incident.state == IncidentState.VERIFIED
    assert history.from_state == IncidentState.PRIORITISED
    assert history.to_state == IncidentState.VERIFIED
    assert history.actor == "core-api-test@example.com"


def test_incident_verification_rejects_wrong_starting_state(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api, state=IncidentState.UNDERSTOOD)

    response = request_incident_verification(core_api, incident_id)

    assert response.status_code == 409
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        history = session.query(IncidentHistory).filter_by(
            incident_id=incident_id,
            action="incident_verified",
        ).first()
    assert incident.state == IncidentState.UNDERSTOOD
    assert history is None


def test_incident_verification_requires_authentication(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = request_incident_verification(core_api, incident_id, authenticated=False)

    assert response.status_code == 401


def test_incident_verification_rejects_missing_incident(core_api: CoreApi) -> None:
    response = request_incident_verification(core_api, UUID(int=0))

    assert response.status_code == 404