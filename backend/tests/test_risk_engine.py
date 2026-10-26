import ast
import inspect
import json
import socket
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

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
from app.models.risk_evaluation import RiskEvaluation
from app.models.threat_indicator import ThreatIndicator
from app.models.vulnerability import Vulnerability
from app.schemas.enrichment import (
    AssetContext,
    EventContext,
    IncidentContext,
    IncidentContextBundle,
    ThreatMatchContext,
    VulnerabilityContext,
)
from app.services import risk_engine
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


# --- risk-v1 snapshot cases: pure contexts, no database --------------------------------------------
# The expected outputs in risk_engine_v1_snapshots.json were produced by the risk engine as it was before
# score_context existed (commit e005a93), from exactly these contexts. They pin risk-v1: any change to a
# score, level, factor value, weight, contribution, evidence line, reason or missing-evidence note fails.
# BEGIN RISK-V1 SNAPSHOT CASES
SNAPSHOT_TIME = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
SNAPSHOT_IP = "198.51.100.77"


def _snapshot_asset(criticality: str) -> AssetContext:
    return AssetContext(
        id=UUID(int=1),
        asset_key="AST-SNAPSHOT",
        name="Snapshot asset",
        hostname="snapshot-host-01",
        ip_address="10.60.0.10",
        criticality=criticality,
        exposure="INTERNET_FACING",
        status="ACTIVE",
        asset_type="SERVER",
        environment="PRODUCTION",
    )


def _snapshot_event(index: int, event_type: str, source: str, anomaly: float | None, signature: str | None = None) -> EventContext:
    return EventContext(
        id=UUID(int=100 + index),
        event_uid=f"evt-snapshot-{index}",
        occurred_at=SNAPSHOT_TIME + timedelta(minutes=2 * index),
        event_type=event_type,
        signature=signature,
        severity="HIGH",
        anomaly_score=anomaly,
        detection_source=source,
        source_ip=SNAPSHOT_IP,
        destination_ip="10.60.0.10",
        source_port=None,
        destination_port=22,
        protocol="TCP",
    )


def _snapshot_vulnerability(index: int, cvss: float | None) -> VulnerabilityContext:
    return VulnerabilityContext(
        id=UUID(int=200 + index),
        cve_id=f"CVE-2026-{20000 + index}",
        title=f"Snapshot vulnerability {index}",
        description=None,
        cvss_score=cvss,
        severity="HIGH",
        status="OPEN",
    )


def _snapshot_match(index: int, confidence: float | None, severity: str, source: str) -> ThreatMatchContext:
    return ThreatMatchContext(
        id=UUID(int=300 + index),
        value=SNAPSHOT_IP,
        indicator_type="IP",
        confidence=confidence,
        severity=severity,
        source=source,
        is_active=True,
        matched_event_ids=[UUID(int=100)],
    )


def _snapshot_bundle(
    asset: AssetContext | None,
    events: Sequence[EventContext] = (),
    vulnerabilities: Sequence[VulnerabilityContext] = (),
    matches: Sequence[ThreatMatchContext] = (),
) -> IncidentContextBundle:
    return IncidentContextBundle(
        incident=IncidentContext(
            id=UUID(int=9),
            incident_key="INC-SNAPSHOT",
            title="Snapshot incident",
            description=None,
            severity="HIGH",
            state="UNDERSTOOD",
            detection_source="SURICATA",
            asset_id=asset.id if asset else None,
        ),
        asset=asset,
        vulnerabilities=list(vulnerabilities),
        threat_intelligence_matches=list(matches),
        events=list(events),
        findings=[],
    )


SNAPSHOT_CASES: dict[str, Callable[[], IncidentContextBundle]] = {
    # Every factor without evidence: zero contributions and all six missing-evidence notes.
    "no_evidence": lambda: _snapshot_bundle(None),
    "low_manual_event": lambda: _snapshot_bundle(
        _snapshot_asset("LOW"), [_snapshot_event(0, "login_attempt", "MANUAL", 0.1)]
    ),
    # Vulnerability records without CVSS, no anomaly score, and a match with no confidence (severity only).
    "unscored_vulnerability_and_severity_only_match": lambda: _snapshot_bundle(
        _snapshot_asset("MEDIUM"),
        [_snapshot_event(0, "port_scan", "SURICATA", None, "ET SCAN Nmap")],
        [_snapshot_vulnerability(0, None)],
        [_snapshot_match(0, None, "MEDIUM", "snapshot-feed")],
    ),
    # Two sources report the same indicator: risk-v1 scores each match separately and takes the highest.
    "high_two_sources_same_indicator": lambda: _snapshot_bundle(
        _snapshot_asset("HIGH"),
        [
            _snapshot_event(0, "ssh_bruteforce", "ML_ANOMALY", 0.5, "SSH brute force A"),
            _snapshot_event(1, "ssh_bruteforce", "SURICATA", 0.73, "SSH brute force B"),
        ],
        [_snapshot_vulnerability(0, 6.0), _snapshot_vulnerability(1, 8.4)],
        [
            _snapshot_match(0, 0.8, "MEDIUM", "ThreatFox (abuse.ch)"),
            _snapshot_match(1, 0.6, "CRITICAL", "NETRA Demo Feed"),
        ],
    ),
    # All three attack-context stages, the score cap, and a detection source risk-v1 does not map (0 points).
    "critical_full_chain_with_unmapped_source": lambda: _snapshot_bundle(
        _snapshot_asset("CRITICAL"),
        [
            _snapshot_event(0, "port_scan", "THREAT_INTEL", 1.0, "Recon probe"),
            _snapshot_event(1, "ssh_bruteforce", "SURICATA", 1.0, "SSH password guessing"),
            _snapshot_event(2, "suspicious_outbound_connection", "ML_ANOMALY", 1.0, "Beacon"),
            _snapshot_event(3, "flow_record", "DATASET_IMPORT", None),
        ],
        [_snapshot_vulnerability(0, 10.0)],
        [_snapshot_match(0, 1.0, "CRITICAL", "snapshot-feed")],
    ),
    "dataset_import_only": lambda: _snapshot_bundle(
        _snapshot_asset("HIGH"), [_snapshot_event(0, "flow_record", "DATASET_IMPORT", None)]
    ),
}
SEVERITY_BOUNDARY_SCORES = (0.0, 24.99, 25.0, 49.99, 50.0, 74.99, 75.0, 100.0)
# END RISK-V1 SNAPSHOT CASES

# Cross-source cases: the same indicator reported by several sources, or by one source in several records.
# Their scores, levels and every factor except the threat-intelligence evidence text are pinned to the
# engine's output before evidence grouping (commit d88d659), stored in the snapshot as "groupingBaseline".
# BEGIN GROUPING CASES
def _grouping_match(index: int, value: str, indicator_type: str, confidence: float | None, severity: str, source: str) -> ThreatMatchContext:
    return ThreatMatchContext(
        id=UUID(int=400 + index),
        value=value,
        indicator_type=indicator_type,
        confidence=confidence,
        severity=severity,
        source=source,
        is_active=True,
        matched_event_ids=[UUID(int=100)],
    )


def _grouping_bundle(*matches: ThreatMatchContext) -> IncidentContextBundle:
    return _snapshot_bundle(
        _snapshot_asset("HIGH"),
        [_snapshot_event(0, "ssh_bruteforce", "SURICATA", 0.6, "SSH brute force")],
        [_snapshot_vulnerability(0, 7.5)],
        matches,
    )


GROUPING_CASES: dict[str, Callable[[], IncidentContextBundle]] = {
    # One indicator from three sources, one of them without a confidence value.
    "three_sources_one_ip": lambda: _grouping_bundle(
        _grouping_match(0, SNAPSHOT_IP, "IP", 0.6, "CRITICAL", "NETRA Demo Feed"),
        _grouping_match(1, SNAPSHOT_IP, "IP", None, "HIGH", "OSINT Feed"),
        _grouping_match(2, SNAPSHOT_IP, "IP", 0.8, "MEDIUM", "ThreatFox (abuse.ch)"),
    ),
    # Matching is case-insensitive but the unique key is not: one source can hold two rows for one domain.
    "duplicate_domain_records": lambda: _grouping_bundle(
        _grouping_match(0, "Evil.Example", "DOMAIN", 0.5, "LOW", "Feed A"),
        _grouping_match(1, "evil.example", "DOMAIN", 0.9, "HIGH", "Feed A"),
        _grouping_match(2, "evil.example", "DOMAIN", 0.4, "MEDIUM", "Feed B"),
    ),
    # Two spellings of one IPv6 address from one source.
    "non_canonical_ipv6_records": lambda: _grouping_bundle(
        _grouping_match(0, "2001:DB8::10", "IP", 0.7, "HIGH", "Feed A"),
        _grouping_match(1, "2001:db8:0::10", "IP", 0.7, "HIGH", "Feed A"),
    ),
    # A grouped indicator next to an indicator reported once: the single one keeps its existing line.
    "grouped_and_single_indicators": lambda: _grouping_bundle(
        _grouping_match(0, SNAPSHOT_IP, "IP", 0.9, "HIGH", "Feed A"),
        _grouping_match(1, SNAPSHOT_IP, "IP", 0.5, "LOW", "Feed B"),
        _grouping_match(2, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "HASH", 0.95, "CRITICAL", "Feed C"),
    ),
    # Different indicators, one source each: nothing to group, so the explanation is unchanged.
    "two_indicators_one_source_each": lambda: _grouping_bundle(
        _grouping_match(0, "198.51.100.77", "IP", 0.8, "HIGH", "Feed A"),
        _grouping_match(1, "203.0.113.9", "IP", 0.6, "MEDIUM", "Feed B"),
    ),
}
# END GROUPING CASES

SNAPSHOT_PATH = Path(__file__).with_name("risk_engine_v1_snapshots.json")
# Headline figures of the snapshot, captured from the pre-refactor engine (see risk_engine_v1_snapshots.json).
SNAPSHOT_HEADLINES = {
    "no_evidence": (0.0, "LOW"),
    "low_manual_event": (15.75, "LOW"),
    "unscored_vulnerability_and_severity_only_match": (30.25, "MEDIUM"),
    "high_two_sources_same_indicator": (72.1, "HIGH"),
    "critical_full_chain_with_unmapped_source": (97.75, "CRITICAL"),
    "dataset_import_only": (18.75, "LOW"),
}


def _snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def _id(n: int) -> str:
    return str(UUID(int=n))


# The only intended difference from the captured baselines: threat-intelligence evidence for an indicator
# held in several records is grouped into one entry naming every source and record. Every number is unchanged.
GROUPED_EVIDENCE = {
    "high_two_sources_same_indicator": [
        "IP 198.51.100.77 is reported by 2 sources (NETRA Demo Feed, ThreatFox (abuse.ch)) in 2 active records. "
        "This indicator is considered once, using its highest report (72/100); additional sources or records add no points.",
        f"IP 198.51.100.77 from NETRA Demo Feed: 70% confidence (60) + 30% severity (100) = 72/100 (indicator {_id(301)}).",
        f"IP 198.51.100.77 from ThreatFox (abuse.ch): 70% confidence (80) + 30% severity (50) = 71/100 (indicator {_id(300)}).",
    ],
    "three_sources_one_ip": [
        "IP 198.51.100.77 is reported by 3 sources (NETRA Demo Feed, OSINT Feed, ThreatFox (abuse.ch)) in 3 active records. "
        "This indicator is considered once, using its highest report (75/100); additional sources or records add no points.",
        f"IP 198.51.100.77 from OSINT Feed: severity only; confidence unavailable = 75/100 (indicator {_id(401)}).",
        f"IP 198.51.100.77 from NETRA Demo Feed: 70% confidence (60) + 30% severity (100) = 72/100 (indicator {_id(400)}).",
        f"IP 198.51.100.77 from ThreatFox (abuse.ch): 70% confidence (80) + 30% severity (50) = 71/100 (indicator {_id(402)}).",
    ],
    "duplicate_domain_records": [
        "DOMAIN evil.example is reported by 2 sources (Feed A, Feed B) in 3 active records. "
        "This indicator is considered once, using its highest report (85.5/100); additional sources or records add no points.",
        "DOMAIN evil.example from Feed A: 70% confidence (90) + 30% severity (75) = 85.5/100 "
        f"(2 records, indicators {_id(400)}, {_id(401)}; highest shown).",
        f"DOMAIN evil.example from Feed B: 70% confidence (40) + 30% severity (50) = 43/100 (indicator {_id(402)}).",
    ],
    "non_canonical_ipv6_records": [
        "IP 2001:db8::10 is reported by 1 source (Feed A) in 2 active records. "
        "This indicator is considered once, using its highest report (71.5/100); additional sources or records add no points.",
        "IP 2001:db8::10 from Feed A: 70% confidence (70) + 30% severity (75) = 71.5/100 "
        f"(2 records, indicators {_id(400)}, {_id(401)}; highest shown).",
    ],
    "grouped_and_single_indicators": [
        "IP 198.51.100.77 is reported by 2 sources (Feed A, Feed B) in 2 active records. "
        "This indicator is considered once, using its highest report (85.5/100); additional sources or records add no points.",
        f"IP 198.51.100.77 from Feed A: 70% confidence (90) + 30% severity (75) = 85.5/100 (indicator {_id(400)}).",
        f"IP 198.51.100.77 from Feed B: 70% confidence (50) + 30% severity (25) = 42.5/100 (indicator {_id(401)}).",
        # Reported once: exactly the existing single-line wording.
        "HASH e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 from Feed C: "
        "70% confidence (95) + 30% severity (100) = 96.5/100.",
    ],
}


def _with_grouped_evidence(name: str, baseline: dict) -> dict:
    expected = json.loads(json.dumps(baseline))
    if name in GROUPED_EVIDENCE:
        expected["factors"]["threat_intelligence"]["evidence"] = GROUPED_EVIDENCE[name]
    return expected


def _expected(name: str) -> dict:
    """The captured risk-v1 output for a snapshot case, with its threat-intelligence evidence grouped."""
    return _with_grouped_evidence(name, _snapshot()["cases"][name])


def _scored_view(scored: "risk_engine.ContextRiskScore") -> dict:
    """The shape the snapshot stores: the API's field names, factors in the order they are reported."""
    return {
        "riskScore": scored.risk_score,
        "severity": scored.severity,
        "factors": {name: factor.model_dump(mode="json", by_alias=True) for name, factor in scored.factors.items()},
        "reasons": scored.reasons,
        "missingEvidence": scored.missing_evidence,
    }


def test_the_snapshot_covers_every_case() -> None:
    assert set(_snapshot()["cases"]) == set(SNAPSHOT_CASES)


@pytest.mark.parametrize("name", sorted(SNAPSHOT_CASES))
def test_score_context_reproduces_the_risk_v1_snapshot(name: str) -> None:
    expected = _expected(name)
    actual = _scored_view(risk_engine.score_context(SNAPSHOT_CASES[name]()))
    assert actual == expected
    assert list(actual["factors"]) == list(expected["factors"])  # reporting order too


def test_snapshot_headline_scores_and_levels() -> None:
    # Readable copy of the snapshot's headline figures; the full comparison is the test above.
    assert {name: (case["riskScore"], case["severity"]) for name, case in _snapshot()["cases"].items()} == SNAPSHOT_HEADLINES


def test_risk_level_thresholds_are_unchanged() -> None:
    expected = _snapshot()["severityBoundaries"]
    assert {str(score): risk_engine._risk_severity(score) for score in SEVERITY_BOUNDARY_SCORES} == expected


def test_missing_evidence_is_reported_exactly_as_before() -> None:
    no_evidence = risk_engine.score_context(SNAPSHOT_CASES["no_evidence"]())
    assert no_evidence.risk_score == 0 and no_evidence.severity == "LOW"
    assert all(factor.contribution == 0 for factor in no_evidence.factors.values())
    assert no_evidence.missing_evidence == _snapshot()["cases"]["no_evidence"]["missingEvidence"]
    assert len(no_evidence.missing_evidence) == 6


def test_the_methodology_is_versioned() -> None:
    assert risk_engine.RISK_METHODOLOGY_VERSION == "risk-v1"
    assert risk_engine.score_context(SNAPSHOT_CASES["low_manual_event"]()).methodology_version == "risk-v1"


# Names whose use inside the scoring code would mean database, request, settings or clock access.
IMPURE_NAMES = frozenset(
    {
        "db", "session", "Session", "select", "commit", "flush", "execute", "scalars",
        "Incident", "IncidentHistory", "enrich_incident_context", "HTTPException",
        "get_settings", "Settings", "datetime", "date", "time", "now", "utcnow", "today", "random", "uuid4",
    }
)
PURE_FUNCTIONS = (
    "score_context", "_calculate_factors", "_factor", "_bounded", "_attack_context", "_attack_stages", "_risk_severity",
    "_threat_evidence", "_indicator_identity",
)


def test_score_context_uses_no_database_request_settings_or_clock_names() -> None:
    for name in PURE_FUNCTIONS:
        tree = ast.parse(inspect.getsource(getattr(risk_engine, name)))
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        used |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        assert not used & IMPURE_NAMES, (name, sorted(used & IMPURE_NAMES))
    assert list(inspect.signature(risk_engine.score_context).parameters) == ["context"]


def test_score_context_runs_with_database_and_network_access_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("score_context must not access the database or network")

    for method in ("execute", "scalars", "scalar", "get", "add", "commit", "flush"):
        monkeypatch.setattr(Session, method, forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    for name, build in SNAPSHOT_CASES.items():
        context = build()
        before = context.model_dump(mode="json")
        first, second = risk_engine.score_context(context), risk_engine.score_context(context)
        assert _scored_view(first) == _scored_view(second) == _expected(name)  # deterministic
        assert context.model_dump(mode="json") == before  # the input is not modified


def test_calculate_incident_risk_delegates_to_score_context_v2(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    # New calculations use the current methodology, risk-v2; risk-v1 (score_context) stays pinned above.
    incident_id = seed_risk_case(core_api, cvss_scores=[7.1], threat_match=(0.72, Severity.MEDIUM))
    seen: list[risk_engine.ContextRiskScore] = []
    original = risk_engine.score_context_v2

    def spy(context: IncidentContextBundle) -> risk_engine.ContextRiskScore:
        seen.append(original(context))
        return seen[-1]

    monkeypatch.setattr(risk_engine, "score_context_v2", spy)
    response = calculate(core_api, incident_id)

    assert response.status_code == 200 and len(seen) == 1
    body = response.json()
    scored = _scored_view(seen[0])
    assert {key: body[key] for key in scored} == scored
    # The API response keeps exactly its existing fields; the methodology version is not added to it.
    assert set(body) == {"incidentId", "riskScore", "severity", "factors", "reasons", "missingEvidence", "stateTransition"}


# --- cross-source threat evidence (explanation only) -----------------------------------------------


def _without_threat_evidence(view: dict) -> dict:
    stripped = json.loads(json.dumps(view))
    stripped["factors"]["threat_intelligence"].pop("evidence")
    return stripped


def test_the_grouping_baseline_covers_every_case() -> None:
    assert set(_snapshot()["groupingBaseline"]["cases"]) == set(GROUPING_CASES)


@pytest.mark.parametrize("name", sorted(GROUPING_CASES))
def test_grouping_changes_only_the_threat_intelligence_evidence(name: str) -> None:
    baseline = _snapshot()["groupingBaseline"]["cases"][name]
    actual = _scored_view(risk_engine.score_context(GROUPING_CASES[name]()))
    # Score, level, every factor value, weight and contribution, all reasons and missing evidence: unchanged.
    assert _without_threat_evidence(actual) == _without_threat_evidence(baseline)
    assert actual == _with_grouped_evidence(name, baseline)


@pytest.mark.parametrize(
    ("cases", "name"),
    [("snapshot", name) for name in sorted(SNAPSHOT_CASES)] + [("grouping", name) for name in sorted(GROUPING_CASES)],
)
def test_risk_scores_and_levels_are_identical_to_before_grouping(cases: str, name: str) -> None:
    builders = SNAPSHOT_CASES if cases == "snapshot" else GROUPING_CASES
    baseline = _snapshot()["cases"][name] if cases == "snapshot" else _snapshot()["groupingBaseline"]["cases"][name]
    scored = risk_engine.score_context(builders[name]())
    assert (scored.risk_score, scored.severity) == (baseline["riskScore"], baseline["severity"])
    assert {key: factor.contribution for key, factor in scored.factors.items()} == {
        key: factor["contribution"] for key, factor in baseline["factors"].items()
    }


def test_an_indicator_reported_by_one_source_keeps_the_existing_explanation() -> None:
    for name in ("two_indicators_one_source_each",):
        baseline = _snapshot()["groupingBaseline"]["cases"][name]["factors"]["threat_intelligence"]["evidence"]
        scored = risk_engine.score_context(GROUPING_CASES[name]())
        assert scored.factors["threat_intelligence"].evidence == baseline
    single = risk_engine.score_context(SNAPSHOT_CASES["critical_full_chain_with_unmapped_source"]())
    assert single.factors["threat_intelligence"].evidence == [
        "IP 198.51.100.77 from snapshot-feed: 70% confidence (100) + 30% severity (100) = 100/100."
    ]


@pytest.mark.parametrize("name", sorted(GROUPING_CASES))
def test_every_source_and_grouped_record_is_named(name: str) -> None:
    context = GROUPING_CASES[name]()
    evidence = "\n".join(risk_engine.score_context(context).factors["threat_intelligence"].evidence)
    for match in context.threat_intelligence_matches:
        assert match.source in evidence
        grouped = sum(
            risk_engine._indicator_identity(other) == risk_engine._indicator_identity(match)
            for other in context.threat_intelligence_matches
        ) > 1
        assert (str(match.id) in evidence) is grouped  # grouped records name their IDs; single lines are unchanged


def test_duplicate_records_of_one_source_are_listed_once() -> None:
    evidence = risk_engine.score_context(GROUPING_CASES["duplicate_domain_records"]()).factors["threat_intelligence"].evidence
    per_source = [line for line in evidence if " from " in line]
    assert [line.split(" from ")[1].split(":")[0] for line in per_source] == ["Feed A", "Feed B"]
    # Feed A's lower duplicate (42.5) is not presented as a separate report; its record ID is still listed.
    assert not any("42.5/100" in line for line in evidence)
    ipv6 = risk_engine.score_context(GROUPING_CASES["non_canonical_ipv6_records"]()).factors["threat_intelligence"].evidence
    assert len([line for line in ipv6 if " from Feed A:" in line]) == 1


def test_more_sources_for_one_indicator_add_no_points() -> None:
    reported_three_times = GROUPING_CASES["three_sources_one_ip"]()
    strongest_alone = reported_three_times.model_copy(
        update={"threat_intelligence_matches": [m for m in reported_three_times.threat_intelligence_matches if m.source == "OSINT Feed"]}
    )
    three, one = risk_engine.score_context(reported_three_times), risk_engine.score_context(strongest_alone)
    assert three.risk_score == one.risk_score
    assert three.factors["threat_intelligence"].normalized_value == one.factors["threat_intelligence"].normalized_value == 75


def _add_indicator(core_api: CoreApi, value: str, source: str, confidence: float, severity: Severity, *, active: bool) -> None:
    with core_api.session_factory() as session:
        session.add(
            ThreatIndicator(
                value=value,
                indicator_type=IndicatorType.IP,
                source=source,
                confidence=confidence,
                severity=severity,
                is_active=active,
            )
        )
        session.commit()


def test_inactive_indicators_stay_excluded_and_active_sources_are_grouped(core_api: CoreApi) -> None:
    # Active: risk-test-feed (0.8, HIGH = 78.5) and Second Feed (0.5, MEDIUM = 50). Inactive: Retired Feed,
    # whose 1.0/CRITICAL report (= 100) would raise the factor if it leaked into matching.
    incident_id = seed_risk_case(core_api, threat_match=(0.8, Severity.HIGH))
    _add_indicator(core_api, "198.51.100.77", "Second Feed", 0.5, Severity.MEDIUM, active=True)
    _add_indicator(core_api, "198.51.100.77", "Retired Feed", 1.0, Severity.CRITICAL, active=False)

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    factor = response.json()["factors"]["threat_intelligence"]
    assert factor["normalizedValue"] == 78.5 and factor["contribution"] == 7.85
    evidence = "\n".join(factor["evidence"])
    assert "Retired Feed" not in evidence
    assert factor["evidence"][0].startswith("IP 198.51.100.77 is reported by 2 sources (Second Feed, risk-test-feed) in 2 active records")
    assert len(factor["evidence"]) == 3


def test_grouping_leaves_the_api_score_and_workflow_unchanged(core_api: CoreApi) -> None:
    single = seed_risk_case(core_api, cvss_scores=[7.1], threat_match=(0.8, Severity.HIGH))
    # Same evidence; its events share the first incident's source IP, so risk-test-feed's indicator matches it too.
    reported_twice = seed_risk_case(core_api, cvss_scores=[7.1])
    single_before = calculate(core_api, single).json()
    _add_indicator(core_api, "198.51.100.77", "Second Feed", 0.5, Severity.MEDIUM, active=True)
    grouped = calculate(core_api, reported_twice).json()

    assert grouped["riskScore"] == single_before["riskScore"] and grouped["severity"] == single_before["severity"]
    assert set(grouped) == set(single_before)
    for name, factor in grouped["factors"].items():
        expected = single_before["factors"][name]
        assert (factor["normalizedValue"], factor["weight"], factor["contribution"], factor["reason"]) == (
            expected["normalizedValue"], expected["weight"], expected["contribution"], expected["reason"],
        )
    assert len(grouped["factors"]["threat_intelligence"]["evidence"]) == 3  # grouped: summary + one line per source
    assert len(single_before["factors"]["threat_intelligence"]["evidence"]) == 1
    assert grouped["missingEvidence"] == single_before["missingEvidence"]
    assert grouped["stateTransition"] == {"fromState": "UNDERSTOOD", "toState": "PRIORITISED", "action": "risk_calculated"}
    with core_api.session_factory() as session:
        incident = session.get(Incident, reported_twice)
        assert incident.state == IncidentState.PRIORITISED and incident.risk_score == grouped["riskScore"]


# --- initial risk evaluation history ---------------------------------------------------------------


def _evaluations(core_api: CoreApi, incident_id: UUID) -> list[RiskEvaluation]:
    with core_api.session_factory() as session:
        return list(
            session.scalars(
                select(RiskEvaluation).where(RiskEvaluation.incident_id == incident_id).order_by(RiskEvaluation.created_at)
            )
        )


def _risk_history(core_api: CoreApi, incident_id: UUID) -> list[IncidentHistory]:
    with core_api.session_factory() as session:
        return list(
            session.scalars(
                select(IncidentHistory).where(
                    IncidentHistory.incident_id == incident_id, IncidentHistory.action == "risk_calculated"
                )
            )
        )


def test_an_initial_calculation_records_exactly_one_evaluation_matching_the_result(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[7.1], threat_match=(0.8, Severity.HIGH))
    _add_indicator(core_api, "198.51.100.77", "Second Feed", 0.5, Severity.MEDIUM, active=True)
    _add_indicator(core_api, "198.51.100.77", "Retired Feed", 1.0, Severity.CRITICAL, active=False)

    response = calculate(core_api, incident_id)

    assert response.status_code == 200
    body = response.json()
    (evaluation,) = _evaluations(core_api, incident_id)
    assert evaluation.methodology_version == risk_engine.RISK_V2_METHODOLOGY_VERSION == "risk-v2"
    assert (evaluation.risk_score, evaluation.risk_level) == (body["riskScore"], body["severity"])
    assert evaluation.factors == body["factors"]  # the breakdown exactly as the API reported it, grouped evidence included
    assert evaluation.missing_evidence == body["missingEvidence"]
    assert evaluation.previous_risk_score == 12.0  # the incident's score before this calculation (seeded)
    assert (evaluation.trigger, evaluation.actor) == ("initial", "core-api-test@example.com")
    assert evaluation.created_at is not None

    with core_api.session_factory() as session:
        indicators = {row.source: row for row in session.scalars(select(ThreatIndicator))}
        event_ids = [str(event.id) for event in session.get(Incident, incident_id).events]
    # Active matches only, with their identifiers and attribution; the inactive Retired Feed record is absent.
    assert sorted(evaluation.matched_indicators, key=lambda item: item["source"]) == [
        {
            "id": str(indicators[source].id),
            "indicatorType": "IP",
            "value": "198.51.100.77",
            "source": source,
            "confidence": confidence,
            "severity": severity,
            "matchedEventIds": event_ids,
        }
        for source, confidence, severity in (("Second Feed", 0.5, "MEDIUM"), ("risk-test-feed", 0.8, "HIGH"))
    ]


def test_an_evaluation_leaves_the_incident_history_and_response_as_before(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[5.5])

    response = calculate(core_api, incident_id)

    body = response.json()
    assert set(body) == {"incidentId", "riskScore", "severity", "factors", "reasons", "missingEvidence", "stateTransition"}
    (history,) = _risk_history(core_api, incident_id)
    # The history entry keeps its existing content and format (snake_case model dump).
    assert history.details == {"risk_calculation": risk_engine.RiskScoreResult.model_validate(body).model_dump(mode="json")}
    assert (history.from_state, history.to_state, history.actor) == (
        IncidentState.UNDERSTOOD, IncidentState.PRIORITISED, "core-api-test@example.com",
    )
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        assert (incident.state, incident.risk_score) == (IncidentState.PRIORITISED, body["riskScore"])
    (evaluation,) = _evaluations(core_api, incident_id)
    assert evaluation.matched_indicators == []  # no threat-intelligence match in this case


def test_a_repeated_calculation_is_refused_and_records_no_second_evaluation(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api)
    assert calculate(core_api, incident_id).status_code == 200
    assert calculate(core_api, incident_id).status_code == 409
    assert len(_evaluations(core_api, incident_id)) == 1
    assert len(_risk_history(core_api, incident_id)) == 1


def test_a_refused_calculation_records_no_evaluation(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, state=IncidentState.DETECTED)
    assert calculate(core_api, incident_id).status_code == 409
    assert _evaluations(core_api, incident_id) == []


def test_a_failed_evaluation_insert_rolls_back_the_incident_and_history(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[7.1], threat_match=(0.8, Severity.HIGH))
    # An empty methodology version violates ck_risk_evaluations_methodology_version_present, so the
    # evaluation insert fails inside the calculation's single commit.
    monkeypatch.setattr(risk_engine, "RISK_V2_METHODOLOGY_VERSION", "")

    with pytest.raises(IntegrityError, match="ck_risk_evaluations_methodology_version_present"):
        calculate(core_api, incident_id)

    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        assert (incident.state, incident.risk_score) == (IncidentState.UNDERSTOOD, 12.0)
    assert _risk_history(core_api, incident_id) == []
    assert _evaluations(core_api, incident_id) == []

    # Nothing was left half-written: with the version restored, the same calculation succeeds once.
    monkeypatch.undo()
    assert calculate(core_api, incident_id).status_code == 200
    assert len(_evaluations(core_api, incident_id)) == len(_risk_history(core_api, incident_id)) == 1


# --- row lock on the incident read -------------------------------------------------------------------


def test_the_incident_read_compiles_to_for_no_key_update() -> None:
    statement = risk_engine._locked_incident(uuid4())
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert sql.rstrip().endswith("FOR NO KEY UPDATE")
    assert "FOR UPDATE" not in sql  # the lighter lock: inserts that only reference the incident are not blocked
    assert statement.get_execution_options()["populate_existing"] is True


def test_calculate_incident_risk_reads_the_incident_through_the_locked_query(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = seed_risk_case(core_api)
    requested: list[UUID] = []
    original = risk_engine._locked_incident

    def spy(requested_id: UUID):  # type: ignore[no-untyped-def]
        requested.append(requested_id)
        return original(requested_id)

    monkeypatch.setattr(risk_engine, "_locked_incident", spy)
    assert calculate(core_api, incident_id).status_code == 200
    assert requested == [incident_id]


def test_a_stale_incident_in_a_long_lived_session_is_refreshed_before_the_state_check(core_api: CoreApi) -> None:
    # seed_demo runs every step in one session: an incident loaded earlier must not hide a newer committed state.
    incident_id = seed_risk_case(core_api)
    with core_api.session_factory() as long_lived:
        assert long_lived.get(Incident, incident_id).state == IncidentState.UNDERSTOOD  # now held in its identity map
        with core_api.session_factory() as other:
            other.get(Incident, incident_id).state = IncidentState.PRIORITISED
            other.commit()

        with pytest.raises(HTTPException) as refused:
            risk_engine.calculate_incident_risk(long_lived, incident_id, actor="core-api-test@example.com")
        assert refused.value.status_code == 409
        long_lived.rollback()
    assert _evaluations(core_api, incident_id) == [] and _risk_history(core_api, incident_id) == []


def test_an_unknown_incident_is_still_not_found(core_api: CoreApi) -> None:
    missing = uuid4()
    response = calculate(core_api, missing)
    assert (response.status_code, response.json()) == (404, {"detail": "Incident not found"})
    assert _evaluations(core_api, missing) == []
