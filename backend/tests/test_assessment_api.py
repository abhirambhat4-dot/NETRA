"""Security Assessment API tests (PostgreSQL schema per test, always rolled back)."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    AssessmentFinding,
    Asset,
    Authorization,
    ContainmentAction,
    CyberMemory,
    Decision,
    Incident,
    IncidentEvent,
    IncidentHistory,
    SecurityAssessment,
    SecurityEvent,
    ThreatIndicator,
    Vulnerability,
)
from app.models.enums import (
    AssessmentGrade,
    AssetEnvironment,
    AssetType,
    Criticality,
    DetectionSource,
    Exposure,
    IncidentState,
    IndicatorType,
    ResponseAction,
    Severity,
    VulnerabilityStatus,
)
from app.services import assessment as assessment_service
from app.services.assessment import assessment_user_limiter
from tests.conftest import CoreApi

ASSESSMENTS = "/api/assessments"
WORKFLOW_MODELS = (
    SecurityEvent, Incident, IncidentEvent, IncidentHistory, Decision, Authorization, ContainmentAction, CyberMemory,
)


@pytest.fixture(autouse=True)
def clear_assessment_rate_limit() -> Any:
    assessment_user_limiter.clear()
    yield
    assessment_user_limiter.clear()


@dataclass
class Seeded:
    asset_id: UUID
    critical_vulnerability_id: UUID
    unscored_vulnerability_id: UUID
    incident_id: UUID
    event_id: UUID


def make_asset(**overrides: Any) -> Asset:
    fields: dict[str, Any] = {
        "asset_key": f"AST-{uuid4().hex[:8]}",
        "name": "Assessment API asset",
        "hostname": "assess-api-01",
        "ip_address": "10.90.0.10",
        "asset_type": AssetType.SERVER,
        "environment": AssetEnvironment.PRODUCTION,
        "criticality": Criticality.CRITICAL,
        "exposure": Exposure.INTERNET_FACING,
        "owner": "platform-team",
    }
    return Asset(**(fields | overrides))


def add_asset(api: CoreApi, **overrides: Any) -> UUID:
    with api.session_factory() as session:
        asset = make_asset(**overrides)
        session.add(asset)
        session.commit()
        return asset.id


def seed_full_case(api: CoreApi) -> Seeded:
    """An asset with vulnerabilities, an active incident with workflow records, a linked event and a matching indicator."""
    now = datetime.now(UTC)
    with api.session_factory() as session:
        asset = make_asset()
        critical = Vulnerability(asset=asset, cve_id="CVE-2026-0001", title="Critical flaw",
                                 cvss_score=Decimal("9.8"), severity=Severity.CRITICAL, status=VulnerabilityStatus.OPEN)
        unscored = Vulnerability(asset=asset, cve_id="CVE-2026-0002", title="Unscored flaw",
                                 cvss_score=None, severity=Severity.MEDIUM, status=VulnerabilityStatus.OPEN)
        event = SecurityEvent(
            event_uid=f"assess-{uuid4().hex}", occurred_at=now - timedelta(hours=2), source=DetectionSource.SURICATA,
            event_type="outbound_beacon", signature="Assessment test beacon", severity=Severity.CRITICAL,
            src_ip="10.90.0.10", dest_ip="203.0.113.66", protocol="TCP", asset=asset,
        )
        incident = Incident(
            incident_key=f"INC-{uuid4().hex[:8]}", title="Assessment test incident", severity=Severity.HIGH,
            risk_score=80.0, state=IncidentState.PRIORITISED, detection_source=DetectionSource.SURICATA,
            asset=asset, events=[event],
        )
        session.add_all([critical, unscored, incident])
        session.add(IncidentHistory(incident=incident, from_state=IncidentState.UNDERSTOOD,
                                    to_state=IncidentState.PRIORITISED, action="risk_calculated", actor="test"))
        session.add(Decision(incident=incident, action=ResponseAction.BLOCK_IP, rationale="test",
                             risk_score=80.0, confidence=0.8, recommendation="Block it"))
        session.add(ThreatIndicator(value="203.0.113.66", indicator_type=IndicatorType.IP, source="assess-feed",
                                    confidence=0.9, severity=Severity.HIGH, is_active=True))
        session.commit()
        return Seeded(asset.id, critical.id, unscored.id, incident.id, event.id)


def create(api: CoreApi, asset_id: UUID | str, headers: dict[str, str] | None = None) -> Any:
    return api.client.post(ASSESSMENTS, json={"assetId": str(asset_id)}, headers=api.headers if headers is None else headers)


def created(api: CoreApi, asset_id: UUID) -> dict[str, Any]:
    response = create(api, asset_id)
    assert response.status_code == 201, response.text
    return response.json()


def count(session: Session, model: type) -> int:
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


def by_key(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {finding["checkKey"]: finding for finding in body["findings"]}


# --- Authentication and validation --------------------------------------------------------------


def test_endpoints_require_authentication(core_api: CoreApi) -> None:
    asset_id = add_asset(core_api)
    for headers in ({}, {"Authorization": "Bearer not-a-token"}):
        assert create(core_api, asset_id, headers=headers).status_code == 401
        assert core_api.client.get(ASSESSMENTS, headers=headers).status_code == 401
        assert core_api.client.get(f"{ASSESSMENTS}/{uuid4()}", headers=headers).status_code == 401
        assert core_api.client.get(f"/api/assets/{asset_id}/vulnerabilities", headers=headers).status_code == 401
    with core_api.session_factory() as session:
        assert count(session, SecurityAssessment) == 0


@pytest.mark.parametrize(
    "body",
    [{}, {"assetId": "not-a-uuid"}, {"assetId": None}, {"assetId": str(uuid4()), "score": 100}, []],
)
def test_invalid_create_requests_are_rejected(core_api: CoreApi, body: Any) -> None:
    response = core_api.client.post(ASSESSMENTS, json=body, headers=core_api.headers)
    assert response.status_code == 422


def test_unknown_asset_returns_404_and_stores_nothing(core_api: CoreApi) -> None:
    response = create(core_api, uuid4())
    assert response.status_code == 404
    assert response.json() == {"detail": "Asset not found"}
    with core_api.session_factory() as session:
        assert count(session, SecurityAssessment) == 0


def test_unknown_or_malformed_assessment_id(core_api: CoreApi) -> None:
    missing = core_api.client.get(f"{ASSESSMENTS}/{uuid4()}", headers=core_api.headers)
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Assessment not found"}
    assert core_api.client.get(f"{ASSESSMENTS}/not-a-uuid", headers=core_api.headers).status_code == 422


# --- Create and detail --------------------------------------------------------------------------


def test_create_assesses_asset_from_database_evidence(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    body = created(core_api, seeded.asset_id)

    assert body["methodologyVersion"] == "assessment-v2"
    assert body["assetId"] == str(seeded.asset_id)
    assert body["asset"]["id"] == str(seeded.asset_id)
    assert body["requestedBy"] == "core-api-test@example.com"
    assert body["inputCounts"] == {"vulnerabilities": 2, "incidents": 1, "events": 1, "threatIndicators": 1}
    findings = by_key(body)
    assert len(findings) == 9
    assert [finding["position"] for finding in body["findings"]] == list(range(9))

    # assessment-v2: exposure HIGH 15, open vulnerability CRITICAL 25, incident HIGH 15 = 55. The
    # event is linked to that active incident, so checks 6 and 7 list it as INFO without deducting.
    assert body["score"] == 45
    assert body["grade"] == "F"
    assert (body["failed"], body["warnings"], body["informational"], body["passed"]) == (3, 0, 3, 3)
    recent = findings["recent_high_severity_events"]
    assert (recent["result"], recent["deduction"]) == ("INFO", 0)
    assert recent["evidence"][2] == "1 event is linked to an active incident and not deducted here:"
    assert recent["evidence"][3].endswith("(PRIORITISED).")

    vulnerabilities = findings["open_vulnerabilities"]
    assert (vulnerabilities["result"], vulnerabilities["severity"], vulnerabilities["deduction"]) == ("FAIL", "CRITICAL", 25)
    assert vulnerabilities["vulnerabilityIds"] == [str(seeded.critical_vulnerability_id), str(seeded.unscored_vulnerability_id)]
    assert "CVE-2026-0001: CVSS 9.8 (CRITICAL), recorded severity CRITICAL, status OPEN." in vulnerabilities["evidence"]
    assert findings["vulnerability_cvss_missing"]["vulnerabilityIds"] == [str(seeded.unscored_vulnerability_id)]
    assert findings["active_incidents"]["incidentIds"] == [str(seeded.incident_id)]
    assert findings["recent_high_severity_events"]["eventIds"] == [str(seeded.event_id)]
    threat = findings["threat_intel_matches"]
    assert threat["eventIds"] == [str(seeded.event_id)]
    assert (threat["result"], threat["deduction"]) == ("INFO", 0)
    assert "destination IP 203.0.113.66 matches active IP indicator from assess-feed" in threat["evidence"][3]
    assert findings["inventory_completeness"]["recommendation"] is None
    assert body["missingEvidence"] == ["CVSS is not recorded for 1 open vulnerability; recorded severity was used."]

    assert timedelta(0) <= datetime.now(UTC) - datetime.fromisoformat(body["asOf"]) < timedelta(minutes=1)


def test_detail_returns_the_stored_snapshot(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    body = created(core_api, seeded.asset_id)

    detail = core_api.client.get(f"{ASSESSMENTS}/{body['id']}", headers=core_api.headers)
    assert detail.status_code == 200
    assert detail.json() == body


def test_stored_records_preserve_version_and_evidence_references(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    body = created(core_api, seeded.asset_id)

    with core_api.session_factory() as session:
        assessment = session.get(SecurityAssessment, UUID(body["id"]))
        assert assessment.methodology_version == "assessment-v2"
        assert assessment.as_of == datetime.fromisoformat(body["asOf"])
        findings = {finding.check_key: finding for finding in assessment.findings}
        assert findings["open_vulnerabilities"].vulnerability_ids == [
            str(seeded.critical_vulnerability_id), str(seeded.unscored_vulnerability_id)
        ]
        assert findings["active_incidents"].incident_ids == [str(seeded.incident_id)]
        assert findings["threat_intel_matches"].event_ids == [str(seeded.event_id)]
        assert findings["open_vulnerabilities"].evidence == by_key(body)["open_vulnerabilities"]["evidence"]
        assert count(session, AssessmentFinding) == 9


def test_events_outside_the_window_are_not_loaded(core_api: CoreApi) -> None:
    now = datetime.now(UTC)
    with core_api.session_factory() as session:
        asset = make_asset(criticality=Criticality.LOW, exposure=Exposure.INTERNAL)
        session.add(asset)
        session.add(SecurityEvent(event_uid=f"old-{uuid4().hex}", occurred_at=now - timedelta(days=8),
                                  source=DetectionSource.MANUAL, event_type="old", severity=Severity.CRITICAL, asset=asset))
        session.commit()
        asset_id = asset.id

    body = created(core_api, asset_id)
    assert body["inputCounts"]["events"] == 0
    assert body["score"] == 100
    assert body["grade"] == "A"


# --- assessment-v2 event attribution through the database loader ----------------------------------


def test_events_of_a_contained_incident_are_not_deducted(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    with core_api.session_factory() as session:
        incident = session.get(Incident, seeded.incident_id)
        incident.state = IncidentState.CONTAINED
        incident_key = incident.incident_key
        session.commit()

    findings = by_key(body := created(core_api, seeded.asset_id))
    # Exposure HIGH 15 + open vulnerability CRITICAL 25; the contained incident and its event deduct nothing.
    assert (body["score"], body["grade"]) == (60, "D")
    assert findings["active_incidents"]["result"] == "PASS"
    recent = findings["recent_high_severity_events"]
    assert (recent["result"], recent["deduction"]) == ("INFO", 0)
    assert recent["evidence"][3].endswith(f"linked to {incident_key} (CONTAINED).")
    assert recent["recommendation"] == "Events linked only to contained or learned incidents need no further correlation."
    assert (findings["threat_intel_matches"]["result"], findings["threat_intel_matches"]["deduction"]) == ("INFO", 0)


def test_event_linked_to_an_incident_on_another_asset_is_attributed_to_it(core_api: CoreApi) -> None:
    now = datetime.now(UTC)
    with core_api.session_factory() as session:
        assessed = make_asset(criticality=Criticality.LOW, exposure=Exposure.INTERNAL)
        other = make_asset(asset_key=f"AST-{uuid4().hex[:8]}")
        event = SecurityEvent(event_uid=f"cross-{uuid4().hex}", occurred_at=now - timedelta(hours=1),
                              source=DetectionSource.SURICATA, event_type="scan", severity=Severity.HIGH, asset=assessed)
        session.add(Incident(incident_key=f"INC-{uuid4().hex[:8]}", title="Elsewhere", severity=Severity.HIGH,
                             risk_score=50.0, state=IncidentState.VERIFIED, detection_source=DetectionSource.SURICATA,
                             asset=other, events=[event]))
        session.commit()
        asset_id = assessed.id

    body = created(core_api, asset_id)
    recent = by_key(body)["recent_high_severity_events"]
    assert (body["score"], recent["result"]) == (100, "INFO")
    assert recent["evidence"][3].endswith("(VERIFIED).")


def test_historical_v1_snapshots_are_kept_as_stored(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    with core_api.session_factory() as session:
        historical = SecurityAssessment(
            asset_id=seeded.asset_id, asset_key="AST-HISTORICAL", methodology_version="assessment-v1",
            as_of=datetime.now(UTC) - timedelta(days=1), score=15, grade=AssessmentGrade.F,
            summary="Grade F (15/100) under assessment-v1: stored before v2.", passed=3, warnings=0, failed=5,
            informational=1, missing_evidence=[], input_counts={"events": 1}, requested_by="historian@example.com",
            findings=[],
        )
        session.add(historical)
        session.commit()
        historical_id = historical.id
    before = core_api.client.get(f"{ASSESSMENTS}/{historical_id}", headers=core_api.headers).json()

    current = created(core_api, seeded.asset_id)

    assert current["methodologyVersion"] == "assessment-v2"
    after = core_api.client.get(f"{ASSESSMENTS}/{historical_id}", headers=core_api.headers).json()
    assert after == before
    assert (after["methodologyVersion"], after["score"], after["grade"]) == ("assessment-v1", 15, "F")
    listed = core_api.client.get(ASSESSMENTS, params={"assetId": str(seeded.asset_id)}, headers=core_api.headers).json()
    assert [item["methodologyVersion"] for item in listed["items"]] == ["assessment-v2", "assessment-v1"]


# --- Safety: append-only, no workflow side effects, rollback -------------------------------------


def _row_snapshot(session: Session) -> dict[str, list[dict[str, Any]]]:
    snapshot = {}
    for model in (Asset, Vulnerability, ThreatIndicator, *WORKFLOW_MODELS):
        columns = model.__table__.columns
        rows = session.execute(select(*columns).order_by(*model.__table__.primary_key.columns)).mappings().all()
        snapshot[model.__tablename__] = [dict(row) for row in rows]
    return snapshot


def test_assessment_creates_no_workflow_records_and_changes_nothing(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    with core_api.session_factory() as session:
        before = _row_snapshot(session)
        assert all(count(session, model) > 0 for model in (SecurityEvent, Incident, IncidentEvent, IncidentHistory, Decision))

    created(core_api, seeded.asset_id)
    created(core_api, seeded.asset_id)

    with core_api.session_factory() as session:
        assert _row_snapshot(session) == before
        assert count(session, SecurityAssessment) == 2


def test_repeated_assessments_append_new_snapshots(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    first = created(core_api, seeded.asset_id)

    # Evidence changes between runs: the critical vulnerability is mitigated.
    with core_api.session_factory() as session:
        session.get(Vulnerability, seeded.critical_vulnerability_id).status = VulnerabilityStatus.MITIGATED
        session.commit()
    second = created(core_api, seeded.asset_id)

    assert second["id"] != first["id"]
    assert second["score"] > first["score"]
    assert core_api.client.get(f"{ASSESSMENTS}/{first['id']}", headers=core_api.headers).json() == first
    listed = core_api.client.get(ASSESSMENTS, params={"assetId": str(seeded.asset_id)}, headers=core_api.headers).json()
    assert [item["id"] for item in listed["items"]] == [second["id"], first["id"]]


def test_persistence_failure_rolls_back_the_whole_snapshot(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    asset_id = add_asset(core_api)
    real_assess = assessment_service.assess_asset

    def corrupt_last_finding(data: Any, **kwargs: Any) -> Any:
        result = real_assess(data, **kwargs)
        result.findings[-1].deduction = 500  # violates the finding deduction check constraint
        return result

    monkeypatch.setattr(assessment_service, "assess_asset", corrupt_last_finding)
    response = create(core_api, asset_id)

    assert response.status_code == 500
    assert response.json() == {"detail": "Assessment could not be stored"}
    with core_api.session_factory() as session:
        assert count(session, SecurityAssessment) == 0
        assert count(session, AssessmentFinding) == 0
    monkeypatch.setattr(assessment_service, "assess_asset", real_assess)
    assert create(core_api, asset_id).status_code == 201


# --- List, filters and pagination ---------------------------------------------------------------


def test_list_filters_and_paginates(core_api: CoreApi) -> None:
    clean_id = add_asset(core_api, criticality=Criticality.LOW, exposure=Exposure.INTERNAL)
    risky = seed_full_case(core_api)
    clean_runs = [created(core_api, clean_id) for _ in range(3)]
    risky_run = created(core_api, risky.asset_id)

    everything = core_api.client.get(ASSESSMENTS, headers=core_api.headers).json()
    assert everything["total"] == 4
    assert everything["items"][0]["id"] == risky_run["id"]
    assert "findings" not in everything["items"][0]

    by_asset = core_api.client.get(ASSESSMENTS, params={"assetId": str(clean_id)}, headers=core_api.headers).json()
    assert {item["id"] for item in by_asset["items"]} == {run["id"] for run in clean_runs}

    grade_f = core_api.client.get(ASSESSMENTS, params={"grade": "F"}, headers=core_api.headers).json()
    assert [item["id"] for item in grade_f["items"]] == [risky_run["id"]]
    grade_a = core_api.client.get(ASSESSMENTS, params={"grade": "A", "assetId": str(clean_id)}, headers=core_api.headers).json()
    assert grade_a["total"] == 3

    page_one = core_api.client.get(ASSESSMENTS, params={"pageSize": 2, "page": 1}, headers=core_api.headers).json()
    page_two = core_api.client.get(ASSESSMENTS, params={"pageSize": 2, "page": 2}, headers=core_api.headers).json()
    assert (page_one["total"], page_one["page"], page_one["pageSize"], len(page_one["items"])) == (4, 1, 2, 2)
    assert len(page_two["items"]) == 2
    assert not {item["id"] for item in page_one["items"]} & {item["id"] for item in page_two["items"]}


@pytest.mark.parametrize(
    "params",
    [{"grade": "E"}, {"grade": "a"}, {"assetId": "nope"}, {"page": 0}, {"pageSize": 0}, {"pageSize": 101}],
)
def test_list_rejects_invalid_parameters(core_api: CoreApi, params: dict[str, Any]) -> None:
    assert core_api.client.get(ASSESSMENTS, params=params, headers=core_api.headers).status_code == 422


# --- Rate limiting ------------------------------------------------------------------------------


def test_rate_limit_returns_429_without_storing(core_api: CoreApi) -> None:
    asset_id = add_asset(core_api)
    for _ in range(10):
        assert create(core_api, asset_id).status_code == 201
    limited = create(core_api, asset_id)

    assert limited.status_code == 429
    assert "rate limit" in limited.json()["detail"].lower()
    with core_api.session_factory() as session:
        assert count(session, SecurityAssessment) == 10
    # Reads are not rate limited.
    assert core_api.client.get(ASSESSMENTS, headers=core_api.headers).status_code == 200


# --- Asset vulnerabilities endpoint -------------------------------------------------------------


def test_asset_vulnerabilities_are_listed_highest_cvss_first(core_api: CoreApi) -> None:
    seeded = seed_full_case(core_api)
    with core_api.session_factory() as session:
        session.add(Vulnerability(asset_id=seeded.asset_id, cve_id="CVE-2026-0003", title="Medium flaw",
                                  description="Details", cvss_score=Decimal("5.3"), severity=Severity.MEDIUM,
                                  status=VulnerabilityStatus.MITIGATED))
        other = make_asset()
        session.add(Vulnerability(asset=other, cve_id="CVE-2026-0999", title="Other asset", cvss_score=Decimal("10.0"),
                                  severity=Severity.CRITICAL, status=VulnerabilityStatus.OPEN))
        session.commit()

    response = core_api.client.get(f"/api/assets/{seeded.asset_id}/vulnerabilities", headers=core_api.headers)
    assert response.status_code == 200
    items = response.json()
    assert [item["cveId"] for item in items] == ["CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0002"]
    assert items[0] == {
        "id": str(seeded.critical_vulnerability_id),
        "assetId": str(seeded.asset_id),
        "cveId": "CVE-2026-0001",
        "title": "Critical flaw",
        "description": None,
        "cvssScore": 9.8,
        "severity": "CRITICAL",
        "status": "OPEN",
        "createdAt": items[0]["createdAt"],
        "updatedAt": items[0]["updatedAt"],
    }
    assert items[1]["status"] == "MITIGATED"
    assert items[2]["cvssScore"] is None


def test_asset_vulnerabilities_empty_unknown_and_malformed(core_api: CoreApi) -> None:
    asset_id = add_asset(core_api)
    empty = core_api.client.get(f"/api/assets/{asset_id}/vulnerabilities", headers=core_api.headers)
    assert (empty.status_code, empty.json()) == (200, [])

    missing = core_api.client.get(f"/api/assets/{uuid4()}/vulnerabilities", headers=core_api.headers)
    assert (missing.status_code, missing.json()) == (404, {"detail": "Asset not found"})
    assert core_api.client.get("/api/assets/nope/vulnerabilities", headers=core_api.headers).status_code == 422
