from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.models.asset import Asset
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.enums import (
    AssetEnvironment,
    AssetStatus,
    AssetType,
    AuthorizationStatus,
    ContainmentStatus,
    Criticality,
    DetectionSource,
    Effectiveness,
    Exposure,
    IncidentState,
    IndicatorType,
    ResponseAction,
    Severity,
    VulnerabilityStatus,
)
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentHistory
from app.models.threat_indicator import ThreatIndicator
from app.models.vulnerability import Vulnerability
from tests.conftest import CoreApi


def seed_core_records(core_api: CoreApi) -> dict[str, UUID]:
    now = datetime.now(UTC)
    asset = Asset(
        asset_key=f"AST-{uuid4().hex[:8]}",
        name="Critical database node",
        hostname="db-node-01",
        ip_address="10.20.0.10",
        asset_type=AssetType.DATABASE,
        environment=AssetEnvironment.PRODUCTION,
        criticality=Criticality.CRITICAL,
        exposure=Exposure.INTERNAL,
        owner="platform-team",
        status=AssetStatus.ACTIVE,
    )
    second_asset = Asset(
        asset_key=f"AST-{uuid4().hex[:8]}",
        name="Test workstation",
        hostname="workstation-02",
        ip_address="10.20.0.20",
        asset_type=AssetType.WORKSTATION,
        environment=AssetEnvironment.TEST,
        criticality=Criticality.LOW,
        exposure=Exposure.DMZ,
        owner="endpoint-team",
        status=AssetStatus.INACTIVE,
    )
    event = SecurityEvent(
        event_uid=f"evt-{uuid4().hex}",
        occurred_at=now,
        source=DetectionSource.SURICATA,
        event_type="ssh_auth_failure",
        signature="Repeated SSH authentication failures",
        severity=Severity.HIGH,
        src_ip="203.0.113.10",
        dest_ip="10.20.0.10",
        src_port=50000,
        dest_port=22,
        protocol="TCP",
        anomaly_score=0.82,
        asset=asset,
    )
    new_event = SecurityEvent(
        event_uid=f"evt-{uuid4().hex}",
        occurred_at=now - timedelta(minutes=10),
        source=DetectionSource.ML_ANOMALY,
        event_type="unusual_process",
        severity=Severity.CRITICAL,
        src_ip="203.0.113.20",
        dest_ip="10.20.0.20",
        protocol="TCP",
        anomaly_score=0.97,
        asset=second_asset,
    )
    incident = Incident(
        incident_key=f"INC-{uuid4().hex[:8]}",
        title="SSH brute force against database",
        description="Repeated login failures from a single source.",
        severity=Severity.HIGH,
        risk_score=76.5,
        state=IncidentState.DETECTED,
        detection_source=DetectionSource.SURICATA,
        recommended_action=ResponseAction.BLOCK_IP,
        asset=asset,
        events=[event],
        history=[
            IncidentHistory(
                from_state=None,
                to_state=IncidentState.DETECTED,
                action="Incident detected",
                actor="NETRA",
                occurred_at=now - timedelta(minutes=5),
                details={"source": "test"},
            )
        ],
    )
    closed_incident = Incident(
        incident_key=f"INC-{uuid4().hex[:8]}",
        title="Resolved endpoint alert",
        description="Previously learned incident.",
        severity=Severity.CRITICAL,
        risk_score=22,
        state=IncidentState.LEARNED,
        detection_source=DetectionSource.ML_ANOMALY,
        asset=second_asset,
    )
    decision = Decision(
        incident=incident,
        action=ResponseAction.BLOCK_IP,
        rationale="Stop repeated authentication attempts.",
        risk_score=76.5,
        confidence=0.91,
        recommendation="Block the source IP.",
    )
    authorization = Authorization(
        incident=incident,
        decision=decision,
        requested_action=ResponseAction.BLOCK_IP,
        status=AuthorizationStatus.PENDING,
        requested_by="analyst@example.test",
    )
    containment = ContainmentAction(
        incident=incident,
        authorization=authorization,
        action_type=ResponseAction.BLOCK_IP,
        target="203.0.113.10",
        status=ContainmentStatus.PENDING,
    )
    memory = CyberMemory(
        incident=incident,
        decision=decision,
        lesson="Rate-limit repeated SSH failures.",
        outcome="Source blocked after analyst review.",
        action_taken=ResponseAction.BLOCK_IP,
        effectiveness=Effectiveness.EFFECTIVE,
    )
    vulnerability = Vulnerability(
        asset=asset,
        cve_id="CVE-2026-12345",
        title="Test vulnerability",
        cvss_score=8.1,
        severity=Severity.HIGH,
        status=VulnerabilityStatus.OPEN,
    )
    indicator = ThreatIndicator(
        value="malicious.example",
        indicator_type=IndicatorType.DOMAIN,
        source="test-feed",
        confidence=0.94,
        severity=Severity.HIGH,
    )
    second_indicator = ThreatIndicator(
        value="203.0.113.200",
        indicator_type=IndicatorType.IP,
        source="secondary-feed",
        confidence=0.6,
        severity=Severity.MEDIUM,
    )
    with core_api.session_factory() as session:
        session.add_all(
            [
                asset,
                second_asset,
                event,
                new_event,
                incident,
                closed_incident,
                decision,
                authorization,
                containment,
                memory,
                vulnerability,
                indicator,
                second_indicator,
            ]
        )
        session.flush()
        identifiers = {
            "asset": asset.id,
            "second_asset": second_asset.id,
            "event": event.id,
            "new_event": new_event.id,
            "incident": incident.id,
            "closed_incident": closed_incident.id,
            "indicator": indicator.id,
        }
        session.commit()
    return identifiers


def test_dashboard_stats_empty_database(core_api: CoreApi) -> None:
    response = core_api.client.get("/api/dashboard/stats", headers=core_api.headers)

    assert response.status_code == 200
    assert response.json() == {
        "totalSecurityEvents": 0,
        "criticalEvents": 0,
        "highEvents": 0,
        "activeIncidents": 0,
        "criticalIncidents": 0,
        "averageRiskScore": None,
        "currentRiskScore": None,
        "assetCount": 0,
        "criticalAssetCount": 0,
        "threatIndicatorCount": 0,
        "recentEvents24h": 0,
        "recentIncidents24h": 0,
    }


def test_dashboard_requires_authentication(core_api: CoreApi) -> None:
    response = core_api.client.get("/api/dashboard/stats")

    assert response.status_code == 401


def test_empty_collection_endpoints_return_empty_pages(core_api: CoreApi) -> None:
    paths = (
        "/api/events",
        "/api/incidents",
        "/api/assets",
        "/api/threat-intelligence",
        "/api/cyber-memory",
    )

    for path in paths:
        response = core_api.client.get(path, headers=core_api.headers)
        assert response.status_code == 200
        assert response.json() == {"items": [], "total": 0, "page": 1, "pageSize": 25}


def test_openapi_documents_bearer_security_for_core_apis(core_api: CoreApi) -> None:
    document = core_api.client.get("/openapi.json").json()
    paths = (
        "/api/dashboard/stats",
        "/api/events",
        "/api/incidents",
        "/api/incidents/{incident_id}/timeline",
        "/api/assets",
        "/api/threat-intelligence",
        "/api/cyber-memory",
    )

    for path in paths:
        assert {"BearerAuth": []} in document["paths"][path]["get"]["security"]


def test_events_list_filters_pagination_detail_and_auth(core_api: CoreApi) -> None:
    ids = seed_core_records(core_api)
    headers = core_api.headers

    unauthenticated = core_api.client.get("/api/events")
    first_page = core_api.client.get("/api/events?page=1&pageSize=1", headers=headers)
    critical_new = core_api.client.get(
        "/api/events?severity=CRITICAL&status=NEW&source=ML_ANOMALY",
        headers=headers,
    )
    correlated = core_api.client.get("/api/events?status=CORRELATED", headers=headers)
    detail = core_api.client.get(f"/api/events/{ids['event']}", headers=headers)
    missing = core_api.client.get(f"/api/events/{uuid4()}", headers=headers)
    dashboard = core_api.client.get("/api/dashboard/stats", headers=headers)

    assert unauthenticated.status_code == 401
    assert first_page.status_code == 200
    assert first_page.json()["total"] == 2
    assert first_page.json()["pageSize"] == 1
    assert len(first_page.json()["items"]) == 1
    assert critical_new.json()["total"] == 1
    assert critical_new.json()["items"][0]["id"] == str(ids["new_event"])
    assert correlated.json()["items"][0]["status"] == "CORRELATED"
    assert detail.status_code == 200
    assert detail.json()["asset"]["name"] == "Critical database node"
    assert "password_hash" not in detail.text
    assert missing.status_code == 404
    assert dashboard.json()["totalSecurityEvents"] == 2
    assert dashboard.json()["activeIncidents"] == 1
    assert dashboard.json()["criticalAssetCount"] == 1


def test_incidents_filters_detail_and_timeline(core_api: CoreApi) -> None:
    ids = seed_core_records(core_api)
    headers = core_api.headers

    listing = core_api.client.get("/api/incidents?pageSize=1&sortBy=riskScore", headers=headers)
    filtered = core_api.client.get(
        "/api/incidents?severity=HIGH&state=DETECTED&active=true&search=brute",
        headers=headers,
    )
    inactive = core_api.client.get("/api/incidents?active=false", headers=headers)
    detail = core_api.client.get(f"/api/incidents/{ids['incident']}", headers=headers)
    timeline = core_api.client.get(f"/api/incidents/{ids['incident']}/timeline", headers=headers)
    missing = core_api.client.get(f"/api/incidents/{uuid4()}", headers=headers)

    assert listing.status_code == 200 and listing.json()["total"] == 2
    assert listing.json()["pageSize"] == 1
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["asset"]["assetKey"].startswith("AST-")
    assert inactive.json()["total"] == 1
    assert detail.status_code == 200
    detail_data = detail.json()
    assert detail_data["incident"]["eventCount"] == 1
    assert detail_data["asset"]["vulnerabilityCount"] == 1
    assert len(detail_data["events"]) == 1
    assert len(detail_data["decisions"]) == 1
    assert len(detail_data["authorizations"]) == 1
    assert len(detail_data["containmentActions"]) == 1
    assert len(detail_data["cyberMemories"]) == 1
    assert timeline.status_code == 200
    assert [row["source"] for row in timeline.json()] == ["history", "event"]
    assert missing.status_code == 404


def test_assets_list_filters_detail_and_missing(core_api: CoreApi) -> None:
    ids = seed_core_records(core_api)
    headers = core_api.headers

    listing = core_api.client.get("/api/assets?pageSize=1", headers=headers)
    filtered = core_api.client.get(
        "/api/assets?search=db-node&status=ACTIVE&criticality=CRITICAL&exposure=INTERNAL",
        headers=headers,
    )
    detail = core_api.client.get(f"/api/assets/{ids['asset']}", headers=headers)
    missing = core_api.client.get(f"/api/assets/{uuid4()}", headers=headers)

    assert listing.status_code == 200 and listing.json()["total"] == 2
    assert listing.json()["pageSize"] == 1
    assert filtered.json()["total"] == 1
    assert detail.status_code == 200
    assert detail.json()["vulnerabilityCount"] == 1
    assert detail.json()["ipAddress"] == "10.20.0.10"
    assert missing.status_code == 404


def test_threat_intelligence_list_filters_and_detail(core_api: CoreApi) -> None:
    ids = seed_core_records(core_api)
    headers = core_api.headers

    listing = core_api.client.get(
        "/api/threat-intelligence?indicatorType=DOMAIN&severity=HIGH&minConfidence=0.9&source=test",
        headers=headers,
    )
    all_indicators = core_api.client.get("/api/threat-intelligence", headers=headers)
    detail = core_api.client.get(f"/api/threat-intelligence/{ids['indicator']}", headers=headers)
    missing = core_api.client.get(f"/api/threat-intelligence/{uuid4()}", headers=headers)

    assert listing.status_code == 200 and listing.json()["total"] == 1
    assert listing.json()["items"][0]["indicatorType"] == "DOMAIN"
    assert all_indicators.json()["total"] == 2
    assert detail.status_code == 200
    assert detail.json()["value"] == "malicious.example"
    assert missing.status_code == 404


def test_cyber_memory_list_includes_related_records(core_api: CoreApi) -> None:
    ids = seed_core_records(core_api)

    response = core_api.client.get(
        f"/api/cyber-memory?incidentId={ids['incident']}&effectiveness=EFFECTIVE&search=rate-limit",
        headers=core_api.headers,
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    memory = response.json()["items"][0]
    assert memory["lesson"] == "Rate-limit repeated SSH failures."
    assert memory["incident"]["id"] == str(ids["incident"])
    assert memory["decision"]["action"] == "BLOCK_IP"
    assert len(memory["authorizations"]) == 1
    assert len(memory["containmentActions"]) == 1