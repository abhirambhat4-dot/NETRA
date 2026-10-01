from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select

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
from app.models.incident import Incident, IncidentEvent, IncidentHistory
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


def test_event_ingest_creates_event_with_raw_payload(core_api: CoreApi) -> None:
    asset = Asset(
        asset_key=f"AST-{uuid4().hex[:8]}",
        name="SSH gateway",
        hostname="gw-01",
        ip_address="10.10.10.10",
        asset_type=AssetType.SERVER,
        environment=AssetEnvironment.PRODUCTION,
        criticality=Criticality.HIGH,
        exposure=Exposure.INTERNET_FACING,
        owner="ops",
        status=AssetStatus.ACTIVE,
    )
    with core_api.session_factory() as session:
        session.add(asset)
        session.commit()

    payload = {
        "event_uid": "evt-ingest-001",
        "occurred_at": "2026-01-01T12:00:00Z",
        "source": "SURICATA",
        "event_type": "port_scan",
        "signature": "ET SCAN Potential External Scan",
        "severity": "HIGH",
        "src_ip": "198.51.100.9",
        "dest_ip": "10.10.10.10",
        "src_port": 54321,
        "dest_port": 22,
        "protocol": "TCP",
        "anomaly_score": 0.91,
        "asset_id": str(asset.id),
        "raw_data": {"alert": "port_scan", "sensor": "suricata"},
    }

    response = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)

    assert response.status_code == 201
    data = response.json()
    assert data["eventUid"] == "evt-ingest-001"
    assert data["detectionSource"] == "SURICATA"
    assert data["severity"] == "HIGH"
    assert data["assetId"] == str(asset.id)

    with core_api.session_factory() as session:
        event = session.get(SecurityEvent, UUID(data["id"]))
        assert event is not None
        assert event.raw_data == payload["raw_data"]


def test_event_ingest_rejects_invalid_and_duplicate_event_uids(core_api: CoreApi) -> None:
    invalid = {
        "occurred_at": "2026-01-01T12:00:00Z",
        "source": "SURICATA",
        "event_type": "ssh_login",
        "severity": "INVALID",
        "src_ip": "not-an-ip",
        "dest_ip": "10.0.0.5",
    }
    response = core_api.client.post("/api/events/ingest", json=invalid, headers=core_api.headers)
    assert response.status_code == 422

    payload = {
        "event_uid": "evt-ingest-duplicate",
        "occurred_at": "2026-01-01T12:00:00Z",
        "source": "SURICATA",
        "event_type": "ssh_bruteforce",
        "severity": "MEDIUM",
        "src_ip": "203.0.113.29",
        "dest_ip": "10.0.0.5",
    }
    first = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)
    second = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)

    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["detail"] == "Event UID already exists"


def test_incident_creation_and_link_event(core_api: CoreApi) -> None:
    payload = {
        "event_uid": "evt-incident-link",
        "occurred_at": "2026-01-01T10:00:00Z",
        "source": "SURICATA",
        "event_type": "ssh_bruteforce",
        "signature": "Repeated SSH authentication failures",
        "severity": "HIGH",
        "src_ip": "203.0.113.25",
        "dest_ip": "10.20.0.10",
        "src_port": 50000,
        "dest_port": 22,
        "protocol": "TCP",
        "anomaly_score": 0.84,
    }
    event_response = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)
    event_id = UUID(event_response.json()["id"])

    incident_response = core_api.client.post(
        "/api/incidents",
        json={
            "title": "SSH brute force against database",
            "description": "Repeated SSH auth failures",
            "detection_source": "SURICATA",
        },
        headers=core_api.headers,
    )
    assert incident_response.status_code == 201
    incident_id = UUID(incident_response.json()["id"])
    assert incident_response.json()["state"] == "DETECTED"

    link_response = core_api.client.post(
        f"/api/incidents/{incident_id}/events",
        json={"event_id": str(event_id)},
        headers=core_api.headers,
    )
    assert link_response.status_code == 201
    assert link_response.json()["incidentId"] == str(incident_id)
    assert link_response.json()["eventId"] == str(event_id)

    detail = core_api.client.get(f"/api/incidents/{incident_id}", headers=core_api.headers)
    assert detail.status_code == 200
    assert detail.json()["incident"]["eventCount"] == 1


def seed_enrichment_case(
    core_api: CoreApi,
    *,
    with_asset: bool = True,
    with_vulnerability: bool = False,
    raw_data: dict[str, object] | None = None,
) -> tuple[UUID, UUID | None]:
    asset = (
        Asset(
            asset_key=f"AST-{uuid4().hex[:8]}",
            name="Enrichment target",
            hostname="target-01",
            ip_address="10.30.0.10",
            asset_type=AssetType.SERVER,
            environment=AssetEnvironment.PRODUCTION,
            criticality=Criticality.HIGH,
            exposure=Exposure.INTERNET_FACING,
            owner="ops",
            status=AssetStatus.ACTIVE,
        )
        if with_asset
        else None
    )
    event = SecurityEvent(
        event_uid=f"evt-{uuid4().hex}",
        occurred_at=datetime.now(UTC),
        source=DetectionSource.SURICATA,
        event_type="ssh_bruteforce",
        signature="Repeated SSH authentication failures",
        severity=Severity.HIGH,
        src_ip="198.51.100.45",
        dest_ip="10.30.0.10",
        dest_port=22,
        protocol="TCP",
        anomaly_score=0.87,
        raw_data=raw_data,
        asset=asset,
    )
    incident = Incident(
        incident_key=f"INC-{uuid4().hex[:8]}",
        title="Context enrichment test incident",
        description="Test context bundle",
        severity=Severity.HIGH,
        risk_score=61.5,
        state=IncidentState.DETECTED,
        detection_source=DetectionSource.SURICATA,
        asset=asset,
        events=[event],
    )
    with core_api.session_factory() as session:
        session.add(incident)
        if with_vulnerability and asset is not None:
            session.add(
                Vulnerability(
                    asset=asset,
                    cve_id="CVE-2026-98765",
                    title="Enrichment test vulnerability",
                    cvss_score=7.4,
                    severity=Severity.HIGH,
                    status=VulnerabilityStatus.OPEN,
                )
            )
        session.commit()
        return incident.id, asset.id if asset is not None else None


def test_incident_enrichment_returns_asset_and_event_context(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)

    response = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert response.status_code == 200
    data = response.json()
    assert data["asset"]["criticality"] == "HIGH"
    assert data["asset"]["exposure"] == "INTERNET_FACING"
    assert data["asset"]["status"] == "ACTIVE"
    assert data["asset"]["assetType"] == "SERVER"
    assert data["asset"]["environment"] == "PRODUCTION"
    assert data["events"][0]["severity"] == "HIGH"
    assert data["events"][0]["anomalyScore"] == 0.87
    assert data["events"][0]["detectionSource"] == "SURICATA"
    assert data["events"][0]["sourceIp"] == "198.51.100.45"
    assert data["events"][0]["destinationIp"] == "10.30.0.10"
    assert any(row["title"] == "context_enriched" for row in core_api.client.get(
        f"/api/incidents/{incident_id}/timeline", headers=core_api.headers
    ).json())


def test_incident_enrichment_finds_asset_vulnerabilities(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api, with_vulnerability=True)

    response = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert response.status_code == 200
    vulnerability = response.json()["vulnerabilities"][0]
    assert vulnerability["cveId"] == "CVE-2026-98765"
    assert vulnerability["cvssScore"] == 7.4
    assert vulnerability["severity"] == "HIGH"
    assert vulnerability["status"] == "OPEN"


def test_incident_enrichment_matches_ip_domain_and_hash_indicators(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(
        core_api,
        raw_data={"domain": "Malicious.Example", "sha256": "aabbccdd00112233"},
    )
    with core_api.session_factory() as session:
        session.add_all(
            [
                ThreatIndicator(
                    value="198.51.100.45",
                    indicator_type=IndicatorType.IP,
                    source="ip-feed",
                    confidence=0.93,
                    severity=Severity.HIGH,
                ),
                ThreatIndicator(
                    value="malicious.example",
                    indicator_type=IndicatorType.DOMAIN,
                    source="domain-feed",
                    confidence=0.88,
                    severity=Severity.MEDIUM,
                ),
                ThreatIndicator(
                    value="AABBCCDD00112233",
                    indicator_type=IndicatorType.HASH,
                    source="hash-feed",
                    confidence=0.99,
                    severity=Severity.CRITICAL,
                ),
            ]
        )
        session.commit()

    response = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert response.status_code == 200
    matches = response.json()["threatIntelligenceMatches"]
    assert {match["indicatorType"] for match in matches} == {"IP", "DOMAIN", "HASH"}
    assert all(match["isActive"] for match in matches)
    assert all(match["matchedEventIds"] == [response.json()["events"][0]["id"]] for match in matches)


def test_incident_enrichment_ignores_inactive_and_nonmatching_indicators(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    with core_api.session_factory() as session:
        session.add_all(
            [
                ThreatIndicator(
                    value="198.51.100.45",
                    indicator_type=IndicatorType.IP,
                    source="inactive-feed",
                    confidence=0.9,
                    severity=Severity.HIGH,
                    is_active=False,
                ),
                ThreatIndicator(
                    value="203.0.113.200",
                    indicator_type=IndicatorType.IP,
                    source="unrelated-feed",
                    confidence=0.5,
                    severity=Severity.LOW,
                ),
            ]
        )
        session.commit()

    response = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert response.status_code == 200
    data = response.json()
    assert data["threatIntelligenceMatches"] == []
    ignored = [row for row in data["findings"] if row["category"] == "inactive_indicators_ignored"]
    assert len(ignored) == 1 and ignored[0]["count"] == 1


def test_incident_enrichment_succeeds_without_vulnerabilities(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)

    response = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert response.status_code == 200
    assert response.json()["vulnerabilities"] == []
    assert any(row["category"] == "vulnerability_context" for row in response.json()["findings"])


def test_incident_enrichment_succeeds_without_threat_match(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)

    response = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert response.status_code == 200
    assert response.json()["threatIntelligenceMatches"] == []
    assert any("No active threat-intelligence" in row["reason"] for row in response.json()["findings"])


def test_incident_enrichment_missing_invalid_and_unauthenticated(core_api: CoreApi) -> None:
    missing = core_api.client.post(f"/api/incidents/{uuid4()}/enrich", headers=core_api.headers)
    invalid = core_api.client.post("/api/incidents/not-a-uuid/enrich", headers=core_api.headers)
    unauthenticated = core_api.client.post(f"/api/incidents/{uuid4()}/enrich")

    assert missing.status_code == 404
    assert invalid.status_code == 422
    assert unauthenticated.status_code == 401


def test_incident_enrichment_does_not_calculate_or_overwrite_risk_score(core_api: CoreApi) -> None:
    ids = seed_core_records(core_api)
    with core_api.session_factory() as session:
        original_score = session.get(Incident, ids["incident"]).risk_score

    response = core_api.client.post(
        f"/api/incidents/{ids['incident']}/enrich", headers=core_api.headers
    )

    with core_api.session_factory() as session:
        updated_score = session.get(Incident, ids["incident"]).risk_score
    assert response.status_code == 200
    assert "riskScore" not in response.json()["incident"]
    assert updated_score == original_score == 76.5


def add_correlation_candidate(
    core_api: CoreApi,
    incident_id: UUID,
    *,
    offset_minutes: int = 5,
    asset_id: UUID | None = None,
    source: DetectionSource | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    event_type: str = "ssh_bruteforce",
    signature: str = "Repeated SSH authentication failures",
) -> UUID:
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        anchor = incident.events[0]
        candidate = SecurityEvent(
            event_uid=f"evt-{uuid4().hex}",
            occurred_at=anchor.occurred_at + timedelta(minutes=offset_minutes),
            source=source or anchor.source,
            event_type=event_type,
            signature=signature,
            severity=Severity.HIGH,
            src_ip=src_ip or anchor.src_ip,
            dest_ip=dest_ip or anchor.dest_ip,
            dest_port=22,
            protocol="TCP",
            anomaly_score=0.8,
            asset_id=asset_id if asset_id is not None else incident.asset_id,
        )
        session.add(candidate)
        session.commit()
        return candidate.id


def test_two_related_events_correlate_into_one_incident(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    candidate_id = add_correlation_candidate(
        core_api,
        incident_id,
        asset_id=asset_id,
        source=DetectionSource.ML_ANOMALY,
    )

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 200
    assert [row["id"] for row in response.json()["correlatedEvents"]] == [str(candidate_id)]
    assert response.json()["state"] == "UNDERSTOOD"
    assert any(row["type"] == "event_correlated" for row in response.json()["findings"])


def test_three_related_events_correlate_into_one_incident(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    first_candidate = add_correlation_candidate(core_api, incident_id, asset_id=asset_id)
    second_candidate = add_correlation_candidate(
        core_api,
        incident_id,
        offset_minutes=8,
        asset_id=asset_id,
        src_ip="10.30.0.10",
        dest_ip="192.0.2.88",
        event_type="suspicious_outbound_connection",
        signature="Unexpected outbound connection",
    )

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 200
    assert {row["id"] for row in response.json()["correlatedEvents"]} == {
        str(first_candidate),
        str(second_candidate),
    }
    with core_api.session_factory() as session:
        links = session.scalars(
            select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        ).all()
    assert len(links) == 3


def test_events_from_unrelated_assets_do_not_correlate(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    with core_api.session_factory() as session:
        other_asset = Asset(
            asset_key=f"AST-{uuid4().hex[:8]}",
            name="Unrelated host",
            hostname="other-01",
            ip_address="10.40.0.10",
            asset_type=AssetType.SERVER,
            environment=AssetEnvironment.PRODUCTION,
            criticality=Criticality.MEDIUM,
            exposure=Exposure.INTERNAL,
            owner="ops",
            status=AssetStatus.ACTIVE,
        )
        session.add(other_asset)
        session.commit()
        other_asset_id = other_asset.id
    add_correlation_candidate(core_api, incident_id, asset_id=other_asset_id)

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 200
    assert response.json()["correlatedEvents"] == []
    assert response.json()["state"] == "DETECTED"
    assert any("different_asset" in row.get("countsByReason", {}) for row in response.json()["findings"])


def test_events_outside_correlation_window_do_not_correlate(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, offset_minutes=31, asset_id=asset_id)

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 200
    assert response.json()["correlatedEvents"] == []
    assert response.json()["state"] == "DETECTED"


def test_duplicate_correlation_does_not_create_duplicate_links(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, asset_id=asset_id)

    first = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)
    second = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert first.status_code == second.status_code == 200
    assert len(first.json()["correlatedEvents"]) == 1
    assert second.json()["correlatedEvents"] == []
    with core_api.session_factory() as session:
        links = session.scalars(
            select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        ).all()
        transitions = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id,
                IncidentHistory.from_state == IncidentState.DETECTED,
                IncidentHistory.to_state == IncidentState.UNDERSTOOD,
            )
        ).all()
    assert len(links) == 2
    assert len(transitions) == 1


def test_successful_correlation_transitions_detected_to_understood(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, asset_id=asset_id)

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 200
    assert response.json()["stateTransition"] == {
        "fromState": "DETECTED",
        "toState": "UNDERSTOOD",
        "action": "events_correlated",
    }
    assert response.json()["state"] == "UNDERSTOOD"


def test_invalid_incident_state_transition_is_rejected(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, asset_id=asset_id)
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        incident.state = IncidentState.VERIFIED
        session.commit()

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 409
    assert "cannot be correlated" in response.json()["detail"]
    with core_api.session_factory() as session:
        links = session.scalars(
            select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        ).all()
    assert len(links) == 1


def test_correlation_transition_is_recorded_in_incident_history(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    candidate_id = add_correlation_candidate(core_api, incident_id, asset_id=asset_id)

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert response.status_code == 200
    with core_api.session_factory() as session:
        history = session.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id == incident_id,
                IncidentHistory.action == "events_correlated",
            )
        ).one()
    assert history.from_state == IncidentState.DETECTED
    assert history.to_state == IncidentState.UNDERSTOOD
    assert history.actor == "core-api-test@example.com"
    assert history.occurred_at is not None
    assert history.details["correlated_event_ids"] == [str(candidate_id)]


def test_incident_timeline_includes_correlation_transition(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, asset_id=asset_id)
    core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    response = core_api.client.get(f"/api/incidents/{incident_id}/timeline", headers=core_api.headers)

    assert response.status_code == 200
    transition = next(row for row in response.json() if row["title"] == "events_correlated")
    assert transition["source"] == "history"
    assert transition["stage"] == "UNDERSTOOD"
    assert "correlated_event_ids" in transition["description"]


def test_context_enrichment_remains_available_after_correlation(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, asset_id=asset_id)
    correlated = core_api.client.post(
        f"/api/incidents/{incident_id}/correlate", headers=core_api.headers
    )

    enriched = core_api.client.post(f"/api/incidents/{incident_id}/enrich", headers=core_api.headers)

    assert correlated.status_code == 200
    assert enriched.status_code == 200
    assert len(enriched.json()["events"]) == 2
    assert enriched.json()["incident"]["state"] == "UNDERSTOOD"