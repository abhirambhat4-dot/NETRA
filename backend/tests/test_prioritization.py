from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.models.asset import Asset
from app.models.enums import (
    AssetEnvironment,
    AssetStatus,
    AssetType,
    Criticality,
    DetectionSource,
    Exposure,
    IncidentState,
    Severity,
)
from app.models.event import SecurityEvent
from app.models.incident import Incident
from tests.conftest import CoreApi


def add_incident(
    core_api: CoreApi,
    *,
    risk_score: float | None,
    severity: Severity = Severity.MEDIUM,
    criticality: Criticality = Criticality.MEDIUM,
    event_count: int = 1,
    state: IncidentState = IncidentState.UNDERSTOOD,
    updated_at: datetime | None = None,
) -> UUID:
    timestamp = updated_at or datetime.now(UTC)
    asset = Asset(
        asset_key=f"AST-{uuid4().hex[:8]}",
        name="Prioritisation test asset",
        hostname=f"host-{uuid4().hex[:6]}",
        ip_address=f"10.70.{uuid4().int % 255}.{uuid4().int % 255}",
        asset_type=AssetType.SERVER,
        environment=AssetEnvironment.PRODUCTION,
        criticality=criticality,
        exposure=Exposure.INTERNAL,
        owner="operations",
        status=AssetStatus.ACTIVE,
    )
    events = [
        SecurityEvent(
            event_uid=f"evt-{uuid4().hex}",
            occurred_at=timestamp,
            source=DetectionSource.MANUAL,
            event_type="prioritisation_test_event",
            signature="Stored test signature",
            severity=severity,
            asset=asset,
        )
        for _ in range(event_count)
    ]
    incident = Incident(
        incident_key=f"INC-{uuid4().hex[:8]}",
        title="Prioritisation test incident",
        description="Stored test data",
        severity=severity,
        risk_score=risk_score,
        state=state,
        detection_source=DetectionSource.MANUAL,
        asset=asset,
        events=events,
        updated_at=timestamp,
    )
    with core_api.session_factory() as session:
        session.add(incident)
        session.commit()
        return incident.id


def prioritized(core_api: CoreApi):
    return core_api.client.get("/api/incidents/prioritized", headers=core_api.headers)


def test_higher_risk_score_ranks_first(core_api: CoreApi) -> None:
    lower_id = add_incident(core_api, risk_score=64.0)
    higher_id = add_incident(core_api, risk_score=91.5)

    response = prioritized(core_api)

    assert response.status_code == 200
    assert [row["incidentId"] for row in response.json()] == [str(higher_id), str(lower_id)]


def test_equal_risk_uses_severity_tie_breaker(core_api: CoreApi) -> None:
    medium_id = add_incident(core_api, risk_score=75, severity=Severity.MEDIUM)
    critical_id = add_incident(core_api, risk_score=75, severity=Severity.CRITICAL)

    response = prioritized(core_api)

    assert [row["incidentId"] for row in response.json()] == [str(critical_id), str(medium_id)]


def test_equal_risk_and_severity_use_asset_criticality(core_api: CoreApi) -> None:
    high_asset_id = add_incident(
        core_api, risk_score=70, severity=Severity.HIGH, criticality=Criticality.HIGH
    )
    critical_asset_id = add_incident(
        core_api, risk_score=70, severity=Severity.HIGH, criticality=Criticality.CRITICAL
    )

    response = prioritized(core_api)

    assert [row["incidentId"] for row in response.json()] == [str(critical_asset_id), str(high_asset_id)]


def test_equal_previous_factors_use_event_count(core_api: CoreApi) -> None:
    one_event_id = add_incident(core_api, risk_score=60, event_count=1)
    three_events_id = add_incident(core_api, risk_score=60, event_count=3)

    response = prioritized(core_api)

    assert [row["incidentId"] for row in response.json()] == [str(three_events_id), str(one_event_id)]


def test_final_ordering_tie_breaker_uses_updated_at(core_api: CoreApi) -> None:
    now = datetime.now(UTC)
    older_id = add_incident(core_api, risk_score=55, updated_at=now - timedelta(hours=1))
    newer_id = add_incident(core_api, risk_score=55, updated_at=now)

    response = prioritized(core_api)

    assert [row["incidentId"] for row in response.json()] == [str(newer_id), str(older_id)]


def test_terminal_and_learned_incidents_are_excluded(core_api: CoreApi) -> None:
    active_id = add_incident(core_api, risk_score=30, state=IncidentState.UNDERSTOOD)
    contained_id = add_incident(core_api, risk_score=100, state=IncidentState.CONTAINED)
    learned_id = add_incident(core_api, risk_score=100, state=IncidentState.LEARNED)

    response = prioritized(core_api)

    returned_ids = {row["incidentId"] for row in response.json()}
    assert str(active_id) in returned_ids
    assert str(contained_id) not in returned_ids
    assert str(learned_id) not in returned_ids


def test_missing_risk_is_placed_after_scored_incidents_and_identified(core_api: CoreApi) -> None:
    missing_id = add_incident(
        core_api,
        risk_score=None,
        severity=Severity.CRITICAL,
        criticality=Criticality.CRITICAL,
    )
    scored_id = add_incident(core_api, risk_score=0)

    response = prioritized(core_api)

    rows = response.json()
    assert [row["incidentId"] for row in rows] == [str(scored_id), str(missing_id)]
    assert rows[1]["riskScore"] is None
    assert "risk not calculated" in rows[1]["priorityReason"].lower()


def test_priority_reason_uses_actual_stored_factors(core_api: CoreApi) -> None:
    incident_id = add_incident(
        core_api,
        risk_score=82.4,
        severity=Severity.HIGH,
        criticality=Criticality.CRITICAL,
        event_count=4,
    )

    response = prioritized(core_api)

    row = response.json()[0]
    assert row["incidentId"] == str(incident_id)
    assert row["priorityRank"] == 1
    assert row["state"] == "UNDERSTOOD"
    assert row["riskScore"] == 82.4
    assert row["severity"] == "HIGH"
    assert row["assetCriticality"] == "CRITICAL"
    assert row["eventCount"] == 4
    assert "82.40" in row["priorityReason"]
    assert "CRITICAL asset" in row["priorityReason"]
    assert "multiple correlated events (4)" in row["priorityReason"]


def test_prioritized_endpoint_requires_authentication(core_api: CoreApi) -> None:
    response = core_api.client.get("/api/incidents/prioritized")

    assert response.status_code == 401


def test_prioritized_endpoint_order_is_deterministic(core_api: CoreApi) -> None:
    now = datetime.now(UTC)
    add_incident(core_api, risk_score=50, updated_at=now)
    add_incident(core_api, risk_score=50, updated_at=now)

    first = prioritized(core_api)
    second = prioritized(core_api)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()


def test_prioritisation_does_not_mutate_state_and_phase_four_still_works(core_api: CoreApi) -> None:
    incident_id = add_incident(core_api, risk_score=None, state=IncidentState.UNDERSTOOD)

    risk_response = core_api.client.post(
        f"/api/incidents/{incident_id}/risk-score", headers=core_api.headers
    )
    with core_api.session_factory() as session:
        state_after_risk_calculation = session.get(Incident, incident_id).state
    queue_response = prioritized(core_api)
    with core_api.session_factory() as session:
        state_after_prioritisation = session.get(Incident, incident_id).state

    assert risk_response.status_code == 200
    assert state_after_risk_calculation == IncidentState.PRIORITISED
    assert queue_response.status_code == 200
    assert state_after_prioritisation == IncidentState.PRIORITISED
    assert any(row["incidentId"] == str(incident_id) for row in queue_response.json())