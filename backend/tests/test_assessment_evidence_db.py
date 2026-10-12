"""Bounded evidence through the database loader (PostgreSQL schema per test, always rolled back).

The loader aggregates events in SQL and fetches only matchable indicators; these tests check it gives
exactly the result of loading every event and every active IP indicator into the engine.
"""

import random
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert, select
from sqlalchemy.orm import Session, selectinload

from app.models import Asset, Incident, IncidentEvent, SecurityAssessment, SecurityEvent, ThreatIndicator
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
)
from app.schemas.assessment import AssessmentInput
from app.services import assessment as assessment_service
from app.services.assessment import _event_input, _indicator_input, assessment_user_limiter, load_assessment_input
from app.services.assessment_engine import MAX_REFERENCE_IDS, METHODOLOGY_V1, METHODOLOGY_V2, SAMPLE_PER_CLASS, assess_asset
from tests.conftest import CoreApi

EVENT_COUNT = 5000
NOISE_INDICATORS = 5000
SEVERITIES = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
# (value, type, active, expected to be fetched by SQL, expected to match in the engine)
INDICATOR_FORMS = [
    ("  203.0.113.9\t", IndicatorType.IP, True, True, True),  # IPv4 with whitespace
    ("2001:0DB8:0000:0000:0000:0000:0000:0066", IndicatorType.IP, True, True, True),  # IPv6, expanded upper-case
    ("203.0.113.9/32", IndicatorType.IP, True, True, False),  # inet equal, but not an address for Python
    ("203.000.113.009", IndicatorType.IP, True, True, False),  # PostgreSQL accepts leading zeros, Python does not
    ("198.51.100.250", IndicatorType.IP, False, False, False),  # inactive, although events use it
    ("198.51.100.250", IndicatorType.DOMAIN, True, False, False),  # not an IP indicator
    ("not an address", IndicatorType.IP, True, False, False),  # never cast: pg_input_is_valid guards it
]


@pytest.fixture(autouse=True)
def clear_assessment_rate_limit() -> Any:
    assessment_user_limiter.clear()
    yield
    assessment_user_limiter.clear()


def seed_large_asset(api: CoreApi, *, seed: int = 5) -> tuple[UUID, datetime]:
    rng = random.Random(seed)
    as_of = datetime.now(UTC)
    with api.session_factory() as session:
        asset = Asset(asset_key=f"AST-{uuid4().hex[:8]}", name="Large evidence asset", hostname="large-01",
                      ip_address="10.40.0.1", asset_type=AssetType.SERVER, environment=AssetEnvironment.PRODUCTION,
                      criticality=Criticality.LOW, exposure=Exposure.INTERNAL, owner="platform-team",
                      status=AssetStatus.DECOMMISSIONED)
        session.add(asset)
        incidents = [
            Incident(incident_key=f"INC-{uuid4().hex[:8]}", title=f"Large {state.name}", severity=Severity.MEDIUM,
                     risk_score=40.0, state=state, detection_source=DetectionSource.SURICATA, asset=asset)
            for state in (IncidentState.DETECTED, IncidentState.VERIFIED, IncidentState.CONTAINED, IncidentState.LEARNED)
        ]
        session.add_all(incidents)
        session.flush()

        events, links = [], []
        for n in range(EVENT_COUNT):
            event_id = uuid4()
            events.append({
                "id": event_id, "event_uid": f"large-{n:05d}-{uuid4().hex[:6]}",
                "occurred_at": as_of - timedelta(seconds=rng.randint(60, 6 * 86400)),
                "source": DetectionSource.SURICATA, "event_type": "alert", "severity": rng.choice(SEVERITIES),
                "src_ip": rng.choice([f"10.40.{n % 40}.{n % 200}", "2001:db8::66"]),
                "dest_ip": rng.choice(["203.0.113.9", "198.51.100.250", "192.0.2.10", None]),
                "asset_id": asset.id,
            })
            for incident in rng.sample(incidents, rng.choice([0, 0, 1, 2])):
                links.append({"incident_id": incident.id, "event_id": event_id})
        # One event just outside the window must never be counted.
        events.append({"id": uuid4(), "event_uid": f"old-{uuid4().hex}", "occurred_at": as_of - timedelta(days=8),
                       "source": DetectionSource.SURICATA, "event_type": "alert", "severity": Severity.CRITICAL,
                       "src_ip": "2001:db8::66", "dest_ip": "203.0.113.9", "asset_id": asset.id})
        session.execute(insert(SecurityEvent), events)
        session.execute(insert(IncidentEvent), links)

        indicators = [
            {"value": f"100.64.{n // 250}.{n % 250}", "indicator_type": IndicatorType.IP, "source": "noise",
             "confidence": 0.5, "severity": Severity.LOW, "is_active": True}
            for n in range(NOISE_INDICATORS)
        ]
        indicators += [
            {"value": value, "indicator_type": kind, "source": f"form-{n}", "confidence": 0.9,
             "severity": Severity.HIGH if n else Severity.CRITICAL, "is_active": active}
            for n, (value, kind, active, _, _) in enumerate(INDICATOR_FORMS)
        ]
        session.execute(insert(ThreatIndicator), indicators)
        session.commit()
        return asset.id, as_of


def load_everything(session: Session, asset: Asset, as_of: datetime) -> AssessmentInput:
    """The Stage 5A approach: every in-window event and every active IP indicator, aggregated by the engine."""
    bounded = load_assessment_input(session, asset, as_of)
    events = session.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.asset_id == asset.id, SecurityEvent.occurred_at >= as_of - timedelta(days=7),
               SecurityEvent.occurred_at <= as_of)
        .options(selectinload(SecurityEvent.incidents))
    ).all()
    indicators = session.scalars(
        select(ThreatIndicator).where(ThreatIndicator.is_active.is_(True), ThreatIndicator.indicator_type == IndicatorType.IP)
    ).all()
    return bounded.model_copy(update={
        "event_evidence": None, "events": [_event_input(event) for event in events],
        "threat_indicators": [_indicator_input(item) for item in indicators], "active_ip_indicator_total": None,
    })


def test_sql_aggregation_matches_loading_everything(core_api: CoreApi) -> None:
    asset_id, as_of = seed_large_asset(core_api)
    with core_api.session_factory() as session:
        asset = session.get(Asset, asset_id)
        started = time.perf_counter()
        bounded = load_assessment_input(session, asset, as_of)
        bounded_seconds = time.perf_counter() - started
        started = time.perf_counter()
        everything = load_everything(session, asset, as_of)
        everything_seconds = time.perf_counter() - started - bounded_seconds  # load_everything reuses one bounded load

    evidence = bounded.event_evidence
    assert bounded.events == []
    assert sum(bucket.count for bucket in evidence.buckets) == EVENT_COUNT
    assert len(evidence.samples) <= 12 * SAMPLE_PER_CLASS
    assert len(everything.events) == EVENT_COUNT
    # Only indicators that can match were fetched; the total still counts every active IP indicator.
    expected_fetched = {value for value, _, _, fetched, _ in INDICATOR_FORMS if fetched}
    assert {item.value for item in bounded.threat_indicators} == expected_fetched
    assert bounded.active_ip_indicator_total == NOISE_INDICATORS + sum(
        1 for _, kind, active, _, _ in INDICATOR_FORMS if active and kind == IndicatorType.IP
    )
    assert len(everything.threat_indicators) == bounded.active_ip_indicator_total

    for methodology in (METHODOLOGY_V1, METHODOLOGY_V2):
        assert assess_asset(bounded, methodology=methodology) == assess_asset(everything, methodology=methodology)
    print(f"\n[evidence load] bounded {bounded_seconds:.3f}s; load-everything {everything_seconds:.3f}s; "
          f"samples {len(evidence.samples)}; buckets {len(evidence.buckets)}; "
          f"indicators fetched {len(bounded.threat_indicators)} of {bounded.active_ip_indicator_total}")


def test_ipv4_ipv6_and_non_ip_indicators(core_api: CoreApi) -> None:
    asset_id, as_of = seed_large_asset(core_api)
    with core_api.session_factory() as session:
        data = load_assessment_input(session, session.get(Asset, asset_id), as_of)
    threat = {f.check_key: f for f in assess_asset(data).findings}["threat_intel_matches"]
    matched_sources = {line.split(" from ", 1)[1].split(" ")[0] for line in threat.evidence if " matches active IP indicator from " in line}
    expected_sources = {f"form-{n}" for n, form in enumerate(INDICATOR_FORMS) if form[4]}
    assert matched_sources <= expected_sources
    assert "form-0" in matched_sources or "form-1" in matched_sources
    assert threat.event_total > 0


def test_loader_is_repeatable(core_api: CoreApi) -> None:
    asset_id, as_of = seed_large_asset(core_api)
    with core_api.session_factory() as session:
        asset = session.get(Asset, asset_id)
        first = assess_asset(load_assessment_input(session, asset, as_of)).model_dump(mode="json")
        second = assess_asset(load_assessment_input(session, asset, as_of)).model_dump(mode="json")
    assert first == second


def test_fallback_without_pg_input_is_valid_gives_the_same_result(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    asset_id, as_of = seed_large_asset(core_api)
    with core_api.session_factory() as session:
        asset = session.get(Asset, asset_id)
        modern = load_assessment_input(session, asset, as_of)
        monkeypatch.setattr(assessment_service, "PG_INPUT_IS_VALID_VERSION", (999,))
        fallback = load_assessment_input(session, asset, as_of)
    assert len(fallback.threat_indicators) == fallback.active_ip_indicator_total > len(modern.threat_indicators)
    assert assess_asset(fallback) == assess_asset(modern)


def test_api_persists_capped_references_with_totals(core_api: CoreApi) -> None:
    asset_id, _ = seed_large_asset(core_api)
    response = core_api.client.post("/api/assessments", json={"assetId": str(asset_id)}, headers=core_api.headers)
    assert response.status_code == 201, response.text
    body = response.json()
    findings = {f["checkKey"]: f for f in body["findings"]}

    assert body["inputCounts"]["events"] == EVENT_COUNT
    inactive = findings["inactive_asset_activity"]
    assert (len(inactive["eventIds"]), inactive["eventTotal"]) == (MAX_REFERENCE_IDS, EVENT_COUNT)
    for finding in body["findings"]:
        assert len(finding["eventIds"]) <= MAX_REFERENCE_IDS
        assert finding["eventTotal"] >= len(finding["eventIds"])
        assert finding["vulnerabilityTotal"] == len(finding["vulnerabilityIds"])
    assert findings["recent_high_severity_events"]["eventTotal"] > MAX_REFERENCE_IDS

    with core_api.session_factory() as session:
        stored = session.get(SecurityAssessment, UUID(body["id"]))
        stored_inactive = next(f for f in stored.findings if f.check_key == "inactive_asset_activity")
        assert (len(stored_inactive.event_ids), stored_inactive.event_total) == (MAX_REFERENCE_IDS, EVENT_COUNT)
    detail = core_api.client.get(f"/api/assessments/{body['id']}", headers=core_api.headers).json()
    assert detail == body
