"""Cyber Memory effectiveness for simulated containment, source references, and what responses do not expose."""

import json
from uuid import UUID

from sqlalchemy import select

from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.enums import Effectiveness, ResponseAction
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentHistory
from tests.conftest import CoreApi
from tests.test_authorization import request_authorization
from tests.test_containment import contain, create_pending_authorization
from tests.test_cyber_memory import create_memory, create_verified_containment
from tests.test_incident_verification import request_incident_verification
from tests.test_verification import verify
from tests.test_workflow_policies import approve, failed_and_verified, reject

SECRET_MARKER = "raw-payload-marker-7f3a"


def listed(core_api: CoreApi, **params: str) -> list[dict]:
    response = core_api.client.get("/api/cyber-memory", params=params, headers=core_api.headers)
    assert response.status_code == 200
    return response.json()["items"]


# --- effectiveness of a simulated containment ------------------------------------------------------------


def test_a_simulated_success_is_never_recorded_as_effective(core_api: CoreApi) -> None:
    incident_id, _, _, _ = create_verified_containment(core_api)

    created = create_memory(core_api, incident_id).json()

    assert created["effectiveness"] == "UNKNOWN"
    assert "Simulated containment action" in created["outcome"]
    assert "Effectiveness is unknown: the containment was simulated" in created["outcome"]
    with core_api.session_factory() as session:
        memory = session.scalars(select(CyberMemory).where(CyberMemory.incident_id == incident_id)).one()
        entry = session.scalars(
            select(IncidentHistory).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == "cyber_memory_created")
        ).one()
    assert memory.effectiveness == Effectiveness.UNKNOWN and entry.details["effectiveness"] == "UNKNOWN"
    # The list filters agree with the stored value.
    assert [item["id"] for item in listed(core_api, incidentId=str(incident_id), effectiveness="UNKNOWN")] == [created["id"]]
    assert listed(core_api, incidentId=str(incident_id), effectiveness="EFFECTIVE") == []


# --- which authorization and containment a memory came from ---------------------------------------------


def test_a_memory_names_the_authorization_and_containment_it_was_created_from(core_api: CoreApi) -> None:
    incident_id, _, authorization_id, containment_id = create_verified_containment(core_api)

    created = create_memory(core_api, incident_id).json()
    (item,) = listed(core_api, incidentId=str(incident_id))

    for body in (created, item):
        assert (body["authorizationId"], body["containmentId"]) == (str(authorization_id), str(containment_id))


def test_after_a_failed_attempt_the_memory_names_the_successful_retry(core_api: CoreApi) -> None:
    incident_id, authorization_id, failed_id = failed_and_verified(core_api)
    retry_id = UUID(contain(core_api, authorization_id).json()["id"])
    assert verify(core_api, retry_id).status_code == 200

    assert create_memory(core_api, incident_id).status_code == 201
    (item,) = listed(core_api, incidentId=str(incident_id))

    assert (item["authorizationId"], item["containmentId"]) == (str(authorization_id), str(retry_id))
    statuses = {action["id"]: action["status"] for action in item["containmentActions"]}
    assert statuses == {str(failed_id): "FAILED", str(retry_id): "VERIFIED"}  # the failed attempt stays distinguishable


def test_after_a_rejected_request_the_memory_names_the_approved_one(core_api: CoreApi) -> None:
    incident_id, decision_id, rejected_id = create_pending_authorization(core_api)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    assert reject(core_api, rejected_id).status_code == 200
    approved_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert approve(core_api, approved_id).status_code == 200
    containment_id = UUID(contain(core_api, approved_id).json()["id"])
    assert verify(core_api, containment_id).status_code == 200

    item = create_memory(core_api, incident_id).json()

    assert (item["authorizationId"], item["containmentId"]) == (str(approved_id), str(containment_id))
    assert {row["id"]: row["status"] for row in item["authorizations"]} == {str(rejected_id): "REJECTED", str(approved_id): "APPROVED"}


def test_a_memory_without_a_creation_record_has_no_invented_references(core_api: CoreApi) -> None:
    incident_id, decision_id, _, _ = create_verified_containment(core_api)
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        session.add(
            CyberMemory(
                incident=incident, decision=session.get(Decision, decision_id), lesson="Recorded elsewhere.", outcome=None,
                action_taken=ResponseAction.ISOLATE_HOST, effectiveness=Effectiveness.UNKNOWN,
            )
        )
        session.commit()

    (item,) = listed(core_api, incidentId=str(incident_id))

    assert (item["authorizationId"], item["containmentId"]) == (None, None)


# --- what a memory response does not expose --------------------------------------------------------------


def test_memory_responses_expose_no_raw_event_payload(core_api: CoreApi) -> None:
    incident_id, _, _, _ = create_verified_containment(core_api)
    with core_api.session_factory() as session:
        for event in session.get(Incident, incident_id).events:
            event.raw_data = {"note": SECRET_MARKER, "password": SECRET_MARKER, "api_key": SECRET_MARKER}
        session.commit()
        assert session.scalars(select(SecurityEvent.raw_data)).first() is not None

    created = create_memory(core_api, incident_id)
    page = core_api.client.get("/api/cyber-memory", params={"incidentId": str(incident_id)}, headers=core_api.headers)

    for response in (created, page):
        text = json.dumps(response.json())
        assert SECRET_MARKER not in text
        assert "rawData" not in text and "raw_data" not in text
