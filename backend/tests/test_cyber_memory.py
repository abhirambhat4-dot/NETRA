from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from app.models.cyber_memory import CyberMemory
from app.models.event import SecurityEvent
from app.models.enums import IncidentState
from app.models.incident import Incident, IncidentHistory
from tests.conftest import CoreApi
from tests.test_containment import contain, create_approved_authorization
from tests.test_decision import request_decision, seed_prioritised_incident
from tests.test_authorization import request_authorization
from tests.test_incident_verification import request_incident_verification
from tests.test_verification import verify


def create_verified_containment(core_api: CoreApi):
    incident_id, decision_id, authorization_id = create_approved_authorization(core_api)
    execution = contain(core_api, authorization_id)
    verification = verify(core_api, UUID(execution.json()["id"]))
    assert execution.status_code == 201
    assert verification.status_code == 200
    return incident_id, decision_id, authorization_id, UUID(execution.json()["id"])


def create_memory(core_api: CoreApi, incident_id: UUID, *, authenticated: bool = True):
    headers = core_api.headers if authenticated else None
    return core_api.client.post(
        f"/api/incidents/{incident_id}/cyber-memory",
        headers=headers,
    )


def test_cyber_memory_endpoint_requires_authentication(core_api: CoreApi) -> None:
    incident_id, _, _, _ = create_verified_containment(core_api)

    response = create_memory(core_api, incident_id, authenticated=False)

    assert response.status_code == 401


def test_memory_cannot_be_created_before_successful_verification(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    execution = contain(core_api, authorization_id)

    response = create_memory(core_api, incident_id)

    assert execution.status_code == 201
    assert response.status_code == 409


def test_failed_containment_cannot_produce_cyber_memory(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    execution = contain(core_api, authorization_id, simulate_failure=True)
    verification = verify(core_api, UUID(execution.json()["id"]))

    response = create_memory(core_api, incident_id)

    assert verification.status_code == 200
    assert response.status_code == 409


def test_memory_records_actual_incident_decision_and_containment_evidence(core_api: CoreApi) -> None:
    incident_id, decision_id, authorization_id, containment_id = create_verified_containment(core_api)

    response = create_memory(core_api, incident_id)

    assert response.status_code == 201
    data = response.json()
    assert data["incidentId"] == str(incident_id)
    assert data["decisionId"] == str(decision_id)
    assert data["actionTaken"] == "ISOLATE_HOST"
    assert data["effectiveness"] == "EFFECTIVE"
    assert "ssh_bruteforce" in data["lesson"]
    assert "CRITICAL" in data["lesson"]
    assert "Simulated containment action ISOLATE_HOST" in data["outcome"]
    assert "verification succeeded" in data["outcome"].lower()
    assert data["incident"]["state"] == "LEARNED"
    assert data["containmentActions"][0]["id"] == str(containment_id)


def test_memory_is_persisted_and_moves_contained_to_learned(core_api: CoreApi) -> None:
    incident_id, decision_id, _, _ = create_verified_containment(core_api)

    response = create_memory(core_api, incident_id)

    with core_api.session_factory() as session:
        memory = session.get(CyberMemory, UUID(response.json()["id"]))
        incident = session.get(Incident, incident_id)
    assert response.status_code == 201
    assert memory is not None
    assert memory.decision_id == decision_id
    assert memory.incident_id == incident_id
    assert incident.state == IncidentState.LEARNED


def test_duplicate_memory_is_rejected_and_history_is_written(core_api: CoreApi) -> None:
    incident_id, _, _, _ = create_verified_containment(core_api)

    first = create_memory(core_api, incident_id)
    second = create_memory(core_api, incident_id)

    assert first.status_code == 201
    assert second.status_code == 409
    with core_api.session_factory() as session:
        histories = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id,
                IncidentHistory.action == "cyber_memory_created",
            )
        ).all()
    assert len(histories) == 1
    assert histories[0].actor == "core-api-test@example.com"
    assert histories[0].details["memory_id"] == first.json()["id"]


def test_full_batch_three_workflow_obeys_lifecycle(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(
        core_api,
        state=IncidentState.DETECTED,
        with_risk_history=False,
    )
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        seed_event = incident.events[0]
        session.add(
            SecurityEvent(
                event_uid=f"evt-lifecycle-{incident_id}",
                occurred_at=datetime.now(UTC),
                source=seed_event.source,
                event_type=seed_event.event_type,
                signature=seed_event.signature,
                severity=seed_event.severity,
                src_ip=seed_event.src_ip,
                dest_ip=seed_event.dest_ip,
                dest_port=seed_event.dest_port,
                protocol=seed_event.protocol,
                asset_id=incident.asset_id,
            )
        )
        session.commit()
    correlation = core_api.client.post(
        f"/api/incidents/{incident_id}/correlate",
        headers=core_api.headers,
    )
    risk = core_api.client.post(
        f"/api/incidents/{incident_id}/risk-score",
        headers=core_api.headers,
    )
    decision_response = request_decision(core_api, incident_id)
    decision_id = UUID(decision_response.json()["id"])
    incident_verification = request_incident_verification(core_api, incident_id)
    authorization_response = request_authorization(core_api, decision_id)
    authorization_id = UUID(authorization_response.json()["id"])
    approval = core_api.client.post(
        f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers
    )
    execution = contain(core_api, authorization_id)
    containment_verification = verify(core_api, UUID(execution.json()["id"]))
    memory_response = create_memory(core_api, incident_id)

    assert correlation.status_code == 200
    assert risk.status_code == 200
    assert decision_response.status_code == 201
    assert incident_verification.status_code == 200
    assert authorization_response.status_code == 201
    assert approval.status_code == 200
    assert execution.status_code == 201
    assert containment_verification.status_code == 200
    assert memory_response.status_code == 201
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        histories = session.scalars(
            select(IncidentHistory)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.occurred_at, IncidentHistory.id)
        ).all()
    assert incident.state == IncidentState.LEARNED
    transitions = [(row.from_state, row.to_state) for row in histories if row.from_state != row.to_state]
    required_transitions = [
        (IncidentState.DETECTED, IncidentState.UNDERSTOOD),
        (IncidentState.UNDERSTOOD, IncidentState.PRIORITISED),
        (IncidentState.PRIORITISED, IncidentState.VERIFIED),
        (IncidentState.VERIFIED, IncidentState.AUTHORIZED),
        (IncidentState.AUTHORIZED, IncidentState.CONTAINED),
        (IncidentState.CONTAINED, IncidentState.LEARNED),
    ]
    assert len(transitions) == len(required_transitions)
    assert set(transitions) == set(required_transitions)