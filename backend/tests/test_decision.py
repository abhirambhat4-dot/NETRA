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
    IndicatorType,
    Severity,
    VulnerabilityStatus,
)
from app.models.event import SecurityEvent
from app.models.decision import Decision
from app.models.incident import Incident, IncidentHistory
from app.models.threat_indicator import ThreatIndicator
from app.models.vulnerability import Vulnerability
from tests.conftest import CoreApi


def seed_prioritised_incident(
    core_api: CoreApi,
    *,
    state: IncidentState = IncidentState.PRIORITISED,
    risk_score: float | None = 82.4,
    event_count: int = 2,
    criticality: Criticality = Criticality.CRITICAL,
    with_threat: bool = True,
    with_vulnerability: bool = True,
    with_anomaly: bool = True,
    with_risk_history: bool = True,
) -> UUID:
    now = datetime.now(UTC)
    asset = Asset(
        asset_key=f"AST-{uuid4().hex[:8]}",
        name="Decision test server",
        hostname="decision-server",
        ip_address="10.80.0.10",
        asset_type=AssetType.SERVER,
        environment=AssetEnvironment.PRODUCTION,
        criticality=criticality,
        exposure=Exposure.INTERNET_FACING,
        owner="security",
        status=AssetStatus.ACTIVE,
    )
    events = [
        SecurityEvent(
            event_uid=f"evt-{uuid4().hex}",
            occurred_at=now + timedelta(minutes=index),
            source=DetectionSource.SURICATA,
            event_type="ssh_bruteforce",
            signature="Repeated SSH authentication failures",
            severity=Severity.HIGH,
            src_ip="203.0.113.81",
            dest_ip="10.80.0.10",
            dest_port=22,
            protocol="TCP",
            anomaly_score=0.88 if with_anomaly else None,
            asset=asset,
        )
        for index in range(event_count)
    ]
    incident = Incident(
        incident_key=f"INC-{uuid4().hex[:8]}",
        title="Repeated SSH attempts on critical server",
        description="Decision service fixture",
        severity=Severity.HIGH,
        risk_score=risk_score,
        state=state,
        detection_source=DetectionSource.SURICATA,
        asset=asset,
        events=events,
    )
    with core_api.session_factory() as session:
        session.add(incident)
        if with_vulnerability:
            session.add(
                Vulnerability(
                    asset=asset,
                    cve_id="CVE-2026-54321",
                    title="Decision test vulnerability",
                    cvss_score=8.2,
                    severity=Severity.HIGH,
                    status=VulnerabilityStatus.OPEN,
                )
            )
        if with_threat:
            session.add(
                ThreatIndicator(
                    value="203.0.113.81",
                    indicator_type=IndicatorType.IP,
                    source=f"decision-test-feed-{asset.asset_key}",
                    confidence=0.96,
                    severity=Severity.CRITICAL,
                    is_active=True,
                )
            )
        if with_risk_history and risk_score is not None:
            session.add(
                IncidentHistory(
                    incident=incident,
                    from_state=IncidentState.UNDERSTOOD,
                    to_state=IncidentState.PRIORITISED,
                    action="risk_calculated",
                    actor="risk-engine",
                    details={
                        "risk_calculation": {
                            "risk_score": risk_score,
                            "severity": "CRITICAL",
                            "factors": {"asset_criticality": {"normalized_value": 100}},
                        }
                    },
                )
            )
        session.commit()
        return incident.id


def request_decision(core_api: CoreApi, incident_id: UUID):
    return core_api.client.post(
        f"/api/incidents/{incident_id}/decision",
        headers=core_api.headers,
    )


def test_decision_endpoint_requires_authentication(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = core_api.client.post(f"/api/incidents/{incident_id}/decision")

    assert response.status_code == 401


def test_decision_requires_completed_risk_calculation(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(
        core_api,
        state=IncidentState.UNDERSTOOD,
        risk_score=None,
        with_risk_history=False,
    )

    response = request_decision(core_api, incident_id)

    assert response.status_code == 409
    assert "risk calculation" in response.json()["detail"].lower()


def test_prioritised_incident_produces_persisted_decision(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = request_decision(core_api, incident_id)

    assert response.status_code == 201
    data = response.json()
    assert data["incidentId"] == str(incident_id)
    assert data["action"] == "ISOLATE_HOST"
    assert data["riskScore"] == 82.4
    with core_api.session_factory() as session:
        decision = session.get(Decision, UUID(data["id"]))
    assert decision is not None
    assert decision.action.name == "ISOLATE_HOST"
    assert decision.rationale == data["rationale"]


def test_action_selection_is_deterministic(core_api: CoreApi) -> None:
    first_id = seed_prioritised_incident(core_api)
    second_id = seed_prioritised_incident(core_api)

    first = request_decision(core_api, first_id)
    second = request_decision(core_api, second_id)

    assert first.status_code == second.status_code == 201
    assert first.json()["action"] == second.json()["action"] == "ISOLATE_HOST"
    assert first.json()["confidence"] == second.json()["confidence"] == 1.0


def test_confidence_uses_evidence_coverage_not_risk_magnitude(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(
        core_api,
        risk_score=82.4,
        event_count=1,
        with_threat=False,
        with_vulnerability=False,
    )

    response = request_decision(core_api, incident_id)

    assert response.status_code == 201
    assert response.json()["confidence"] == 0.55


def test_rationale_and_supporting_evidence_use_stored_context(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = request_decision(core_api, incident_id)

    assert response.status_code == 201
    rationale = response.json()["rationale"]
    recommendation = response.json()["recommendation"]
    assert "82.40" in rationale
    assert "CRITICAL" in rationale
    assert "2 linked events" in rationale
    assert "203.0.113.81" in rationale
    assert "CVE-2026-54321" in rationale
    assert "Phase 4 factor" in rationale
    assert "ISOLATE_HOST" in recommendation
    assert "does not execute containment" in recommendation


def test_duplicate_decision_returns_conflict(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    first = request_decision(core_api, incident_id)
    second = request_decision(core_api, incident_id)

    assert first.status_code == 201
    assert second.status_code == 409


def test_decision_does_not_execute_containment_or_change_lifecycle(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = request_decision(core_api, incident_id)

    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        containment_actions = list(incident.containment_actions)
    assert response.status_code == 201
    assert incident.state == IncidentState.PRIORITISED
    assert containment_actions == []


def test_decision_history_records_actor_and_supporting_evidence(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)

    response = request_decision(core_api, incident_id)

    with core_api.session_factory() as session:
        history = session.query(IncidentHistory).filter_by(
            incident_id=incident_id,
            action="decision_recommended",
        ).one()
    assert response.status_code == 201
    assert history.actor == "core-api-test@example.com"
    assert history.occurred_at is not None
    assert history.details["decision_id"] == response.json()["id"]
    assert history.details["action"] == response.json()["action"]


def test_phase_four_and_five_remain_unchanged_by_decision_generation(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(
        core_api,
        state=IncidentState.UNDERSTOOD,
        risk_score=None,
        with_risk_history=False,
    )
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        incident.events[0].anomaly_score = 0.64
        session.commit()

    risk_response = core_api.client.post(
        f"/api/incidents/{incident_id}/risk-score", headers=core_api.headers
    )
    queue_before_decision = core_api.client.get(
        "/api/incidents/prioritized", headers=core_api.headers
    )
    decision_response = request_decision(core_api, incident_id)
    queue_after_decision = core_api.client.get(
        "/api/incidents/prioritized", headers=core_api.headers
    )

    assert risk_response.status_code == 200
    assert decision_response.status_code == 201
    assert queue_before_decision.status_code == queue_after_decision.status_code == 200
    assert queue_before_decision.json() == queue_after_decision.json()
    assert decision_response.json()["riskScore"] == risk_response.json()["riskScore"]
