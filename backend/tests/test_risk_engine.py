from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

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
from app.models.incident import Incident, IncidentHistory
from app.models.threat_indicator import ThreatIndicator
from app.models.vulnerability import Vulnerability
from tests.conftest import CoreApi


def seed_risk_case(
    core_api: CoreApi,
    *,
    criticality: Criticality = Criticality.HIGH,
    cvss_scores: list[float] | None = None,
    anomaly_scores: list[float | None] | None = None,
    sources: list[DetectionSource] | None = None,
    event_types: list[str] | None = None,
    state: IncidentState = IncidentState.UNDERSTOOD,
    threat_match: tuple[float | None, Severity] | None = None,
) -> UUID:
    anomaly_scores = anomaly_scores if anomaly_scores is not None else [0.5]
    sources = sources if sources is not None else [DetectionSource.SURICATA] * len(anomaly_scores)
    event_types = event_types if event_types is not None else ["ssh_bruteforce"] * len(anomaly_scores)
    now = datetime.now(UTC)
    asset = Asset(
        asset_key=f"AST-{uuid4().hex[:8]}",
        name="Risk test asset",
        hostname="risk-host-01",
        ip_address="10.60.0.10",
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
            occurred_at=now + timedelta(minutes=index * 2),
            source=sources[index],
            event_type=event_types[index],
            signature=f"Risk test {event_types[index]} signature {index}",
            severity=Severity.HIGH,
            src_ip="198.51.100.77",
            dest_ip="10.60.0.10",
            dest_port=22,
            protocol="TCP",
            anomaly_score=anomaly_scores[index],
            asset=asset,
        )
        for index in range(len(anomaly_scores))
    ]
    incident = Incident(
        incident_key=f"INC-{uuid4().hex[:8]}",
        title="Risk engine test incident",
        description="Deterministic scoring test",
        severity=Severity.HIGH,
        risk_score=12.0,
        state=state,
        detection_source=sources[0],
        asset=asset,
        events=events,
    )
    with core_api.session_factory() as session:
        session.add(incident)
        for index, cvss_score in enumerate(cvss_scores or []):
            session.add(
                Vulnerability(
                    asset=asset,
                    cve_id=f"CVE-2026-{10000 + index}",
                    title=f"Risk test vulnerability {index}",
                    cvss_score=cvss_score,
                    severity=Severity.HIGH,
                    status=VulnerabilityStatus.OPEN,
                )
            )
        if threat_match is not None:
            confidence, threat_severity = threat_match
            session.add(
                ThreatIndicator(
                    value="198.51.100.77",
                    indicator_type=IndicatorType.IP,
                    source="risk-test-feed",
                    confidence=confidence,
                    severity=threat_severity,
                    is_active=True,
                )
            )
        session.commit()
        return incident.id


def calculate(core_api: CoreApi, incident_id: UUID):
    return core_api.client.post(
        f"/api/incidents/{incident_id}/risk-score",
        headers=core_api.headers,
    )


def test_low_risk_incident(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        criticality=Criticality.LOW,
        anomaly_scores=[0.1],
        sources=[DetectionSource.MANUAL],
    )

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["severity"] == "LOW"
    assert response.json()["riskScore"] == 15.75


def test_high_risk_incident(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        criticality=Criticality.HIGH,
        cvss_scores=[6.0],
        anomaly_scores=[0.5],
        sources=[DetectionSource.ML_ANOMALY],
    )

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["severity"] == "HIGH"
    assert response.json()["riskScore"] == 51.25
    detection = response.json()["factors"]["detection"]
    assert detection["normalizedValue"] == 70
    assert "probabilistic anomaly signal" in detection["evidence"][0]


def test_critical_risk_incident(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        criticality=Criticality.CRITICAL,
        cvss_scores=[10.0],
        anomaly_scores=[1.0, 1.0, 1.0],
        event_types=["port_scan", "ssh_bruteforce", "suspicious_outbound_connection"],
        threat_match=(1.0, Severity.CRITICAL),
    )

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["severity"] == "CRITICAL"
    assert response.json()["riskScore"] == 96.25


def test_cvss_is_normalized_to_a_0_to_100_factor(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[8.4, 6.2])

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["factors"]["vulnerability"]["normalizedValue"] == 84.0
    assert "CVE-2026-10000" in response.json()["factors"]["vulnerability"]["evidence"][0]


def test_critical_asset_contribution_is_explained(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, criticality=Criticality.CRITICAL)

    response = calculate(core_api, incident_id)

    factor = response.json()["factors"]["asset_criticality"]
    assert factor["normalizedValue"] == 100
    assert factor["weight"] == 0.25
    assert factor["contribution"] == 25.0
    assert "CRITICAL" in factor["evidence"][0]


def test_anomaly_score_is_normalized_to_0_to_100(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, anomaly_scores=[0.73])

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["factors"]["anomaly"]["normalizedValue"] == 73.0


def test_threat_intelligence_combines_confidence_and_severity(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, threat_match=(0.8, Severity.HIGH))

    response = calculate(core_api, incident_id)

    factor = response.json()["factors"]["threat_intelligence"]
    assert response.status_code == 200
    assert factor["normalizedValue"] == 78.5
    assert factor["weight"] == 0.1
    assert "risk-test-feed" in factor["evidence"][0]


def test_missing_vulnerability_contributes_zero_with_note(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api)

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["factors"]["vulnerability"]["normalizedValue"] == 0
    assert any("vulnerability" in note.lower() for note in response.json()["missingEvidence"])


def test_missing_anomaly_contributes_zero_with_note(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, anomaly_scores=[None])

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["factors"]["anomaly"]["normalizedValue"] == 0
    assert any("anomaly" in note.lower() for note in response.json()["missingEvidence"])


def test_missing_threat_intelligence_is_not_treated_as_benign(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api)

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert response.json()["factors"]["threat_intelligence"]["normalizedValue"] == 0
    assert any("not evidence" in note.lower() for note in response.json()["missingEvidence"])


def test_attack_context_uses_event_count_diversity_and_stages(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        criticality=Criticality.CRITICAL,
        anomaly_scores=[0.4, 0.5, 0.6],
        event_types=["port_scan", "ssh_bruteforce", "suspicious_outbound_connection"],
    )

    response = calculate(core_api, incident_id)

    factor = response.json()["factors"]["attack_context"]
    assert response.status_code == 200
    assert factor["normalizedValue"] == 85
    assert any("3 linked events" in item for item in factor["evidence"])


def test_final_risk_score_is_bounded_0_to_100(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        criticality=Criticality.CRITICAL,
        cvss_scores=[10.0],
        anomaly_scores=[1.0, 1.0, 1.0],
        event_types=["port_scan", "ssh_bruteforce", "suspicious_outbound_connection"],
        threat_match=(1.0, Severity.CRITICAL),
    )

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    assert 0 <= response.json()["riskScore"] <= 100


def test_factor_contributions_sum_to_final_score(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        cvss_scores=[7.1],
        threat_match=(0.72, Severity.MEDIUM),
    )

    response = calculate(core_api, incident_id)

    factors = response.json()["factors"].values()
    assert response.status_code == 200
    assert sum(factor["contribution"] for factor in factors) == pytest.approx(
        response.json()["riskScore"]
    )


def test_risk_explanation_is_persisted_in_history(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[5.5])

    response = calculate(core_api, incident_id)

    with core_api.session_factory() as session:
        history = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id,
                IncidentHistory.action == "risk_calculated",
            )
        ).one()
    assert response.status_code == 200
    explanation = history.details["risk_calculation"]
    assert explanation["risk_score"] == response.json()["riskScore"]
    assert set(explanation["factors"]) == {
        "asset_criticality",
        "vulnerability",
        "anomaly",
        "detection",
        "threat_intelligence",
        "attack_context",
    }
    assert history.from_state == IncidentState.UNDERSTOOD
    assert history.to_state == IncidentState.PRIORITISED
    assert history.actor == "core-api-test@example.com"
    assert history.occurred_at is not None


def test_incident_risk_score_is_updated(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api)

    response = calculate(core_api, incident_id)

    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
    assert response.status_code == 200
    assert incident.risk_score == response.json()["riskScore"]


def test_risk_calculation_transitions_understood_to_prioritised(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api)

    response = calculate(core_api, incident_id)

    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
    assert response.status_code == 200
    assert response.json()["stateTransition"] == {
        "fromState": "UNDERSTOOD",
        "toState": "PRIORITISED",
        "action": "risk_calculated",
    }
    assert incident.state == IncidentState.PRIORITISED


def test_risk_calculation_rejects_invalid_lifecycle_state(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, state=IncidentState.DETECTED)

    response = calculate(core_api, incident_id)

    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
    assert response.status_code == 409
    assert incident.state == IncidentState.DETECTED
    assert incident.risk_score == 12.0


def test_phase_one_to_three_flow_remains_usable(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(
        core_api,
        state=IncidentState.DETECTED,
        anomaly_scores=[0.5, 0.7],
        event_types=["port_scan", "ssh_bruteforce"],
    )
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        event = incident.events[0]
        related_event = SecurityEvent(
            event_uid=f"evt-{uuid4().hex}",
            occurred_at=event.occurred_at + timedelta(minutes=3),
            source=event.source,
            event_type="ssh_bruteforce",
            signature="Repeated SSH login failures",
            severity=Severity.HIGH,
            src_ip=event.src_ip,
            dest_ip=event.dest_ip,
            asset_id=incident.asset_id,
            anomaly_score=0.7,
        )
        session.add(related_event)
        session.commit()

    correlated = core_api.client.post(
        f"/api/incidents/{incident_id}/correlate", headers=core_api.headers
    )
    enriched = core_api.client.post(
        f"/api/incidents/{incident_id}/enrich", headers=core_api.headers
    )
    risk_response = calculate(core_api, incident_id)

    assert correlated.status_code == enriched.status_code == risk_response.status_code == 200
    assert len(enriched.json()["events"]) == 3
    assert risk_response.json()["stateTransition"]["toState"] == "PRIORITISED"