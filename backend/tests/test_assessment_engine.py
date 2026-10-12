"""Unit tests for the pure assessment engine under assessment-v1; no database, clock or network is used.

v1 stays callable for reference, so these tests pin it explicitly. assessment-v2 is covered by
test_assessment_engine_v2.py.
"""

import ast
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.schemas.assessment import (
    AssessmentAssetInput,
    AssessmentEventInput,
    AssessmentIncidentInput,
    AssessmentIndicatorInput,
    AssessmentInput,
    AssessmentVulnerabilityInput,
)
from app.services import assessment_engine
from app.services.assessment_engine import (
    CHECKS_V1 as CHECKS,
    EVENT_WINDOW,
    GRADE_BOUNDARIES,
    MAX_LISTED_EVENTS,
    METHODOLOGY_V1,
    SEVERITY_DEDUCTIONS,
    cvss_severity,
    grade_for_score,
)


def assess_asset(data: AssessmentInput):
    return assessment_engine.assess_asset(data, methodology=METHODOLOGY_V1)


AS_OF = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
ASSET_ID = UUID(int=1)


def asset(**overrides: Any) -> AssessmentAssetInput:
    fields: dict[str, Any] = {
        "id": ASSET_ID,
        "asset_key": "AST-TEST-01",
        "name": "Assessment test asset",
        "hostname": "assess-01",
        "ip_address": "10.70.0.10",
        "criticality": "MEDIUM",
        "exposure": "INTERNAL",
        "status": "ACTIVE",
        "owner": "platform-team",
    }
    return AssessmentAssetInput(**{**fields, **overrides})


def vulnerability(n: int, cvss: float | None, severity: str = "HIGH", status: str = "OPEN") -> AssessmentVulnerabilityInput:
    return AssessmentVulnerabilityInput(
        id=UUID(int=100 + n), cve_id=f"CVE-2026-{1000 + n}", title=f"Vulnerability {n}",
        cvss_score=cvss, severity=severity, status=status,
    )


def incident(n: int, severity: str, state: str) -> AssessmentIncidentInput:
    return AssessmentIncidentInput(id=UUID(int=200 + n), incident_key=f"INC-{n:04d}", severity=severity, state=state)


def event(n: int, severity: str, age: timedelta, src_ip: str | None = "198.51.100.20",
          dest_ip: str | None = "10.70.0.10") -> AssessmentEventInput:
    return AssessmentEventInput(
        id=UUID(int=300 + n), event_uid=f"evt-{n:04d}", occurred_at=AS_OF - age,
        severity=severity, src_ip=src_ip, dest_ip=dest_ip,
    )


def indicator(n: int, value: str, severity: str = "HIGH", indicator_type: str = "IP",
              is_active: bool = True, confidence: float | None = 0.9) -> AssessmentIndicatorInput:
    return AssessmentIndicatorInput(
        id=UUID(int=400 + n), value=value, indicator_type=indicator_type, source="test-feed",
        severity=severity, confidence=confidence, is_active=is_active,
    )


def build(**overrides: Any) -> AssessmentInput:
    fields: dict[str, Any] = {"asset": asset(), "as_of": AS_OF}
    return AssessmentInput(**{**fields, **overrides})


def finding(data: AssessmentInput, check_key: str):
    return next(item for item in assess_asset(data).findings if item.check_key == check_key)


# --- Methodology constants ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"), (69, "D"), (60, "D"), (59, "F"), (0, "F")],
)
def test_grade_boundaries(score: int, grade: str) -> None:
    assert grade_for_score(score) == grade


def test_methodology_tables_are_explicit() -> None:
    assert METHODOLOGY_V1 == "assessment-v1"
    assert SEVERITY_DEDUCTIONS == {"INFO": 0, "LOW": 3, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 25}
    assert GRADE_BOUNDARIES == (("A", 90), ("B", 80), ("C", 70), ("D", 60))
    assert EVENT_WINDOW == timedelta(days=7)


@pytest.mark.parametrize(
    ("cvss", "severity"),
    [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"), (6.9, "MEDIUM"),
     (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "INFO")],
)
def test_cvss_rating_scale(cvss: float, severity: str) -> None:
    assert cvss_severity(cvss) == severity


# --- Baseline, empty input and aggregation ------------------------------------------------------


def test_clean_asset_passes_every_check() -> None:
    result = assess_asset(build(events=[event(1, "LOW", timedelta(hours=1))], threat_indicators=[indicator(1, "203.0.113.5")]))

    assert result.score == 100
    assert result.grade == "A"
    assert [item.check_key for item in result.findings] == [check.__name__.removeprefix("check_") for check in CHECKS]
    assert all(item.result == "PASS" and item.deduction == 0 for item in result.findings)
    assert all(item.recommendation is None and item.evidence for item in result.findings)
    assert (result.passed, result.warnings, result.failed, result.informational) == (9, 0, 0, 0)
    assert result.missing_evidence == []
    assert result.methodology_version == "assessment-v1"
    assert result.asset_id == ASSET_ID


def test_empty_input_with_sparse_asset_still_assesses() -> None:
    result = assess_asset(build(asset=asset(hostname=None, ip_address=None, owner=None)))

    assert result.score == 97
    assert result.grade == "A"
    completeness = next(item for item in result.findings if item.check_key == "inventory_completeness")
    assert completeness.result == "WARN"
    assert completeness.evidence == ["No owner is recorded.", "Neither a hostname nor an IP address is recorded."]
    assert result.missing_evidence == [
        "No security events were recorded for the asset in the 7-day window.",
        "No active IP threat indicators were supplied, so no indicator match was possible.",
    ]
    events_finding = next(item for item in result.findings if item.check_key == "recent_high_severity_events")
    assert "Absence of events is not evidence that the asset is safe." in events_finding.evidence


def test_worked_example_score_and_summary() -> None:
    result = assess_asset(build(
        asset=asset(criticality="CRITICAL", exposure="INTERNET_FACING"),
        vulnerabilities=[vulnerability(1, 9.8)],
        incidents=[incident(1, "HIGH", "PRIORITISED")],
    ))

    # exposure HIGH 15 + open vulnerability CRITICAL 25 + active incident HIGH 15 = 55 deducted.
    assert [item.deduction for item in result.findings if item.deduction] == [15, 25, 15]
    assert result.score == 45
    assert result.grade == "F"
    assert result.summary == (
        "Grade F (45/100) under assessment-v1: 3 failed, 0 warnings, 0 informational and 6 passed checks."
    )


def test_score_is_clamped_at_zero() -> None:
    result = assess_asset(build(
        asset=asset(criticality="CRITICAL", exposure="INTERNET_FACING", status="DECOMMISSIONED", owner=None),
        vulnerabilities=[vulnerability(1, 9.8), vulnerability(2, 9.1, status="ACCEPTED")],
        incidents=[incident(1, "CRITICAL", "DETECTED")],
        events=[event(1, "CRITICAL", timedelta(hours=1), src_ip="203.0.113.9")],
        threat_indicators=[indicator(1, "203.0.113.9", severity="CRITICAL")],
    ))

    assert sum(item.deduction for item in result.findings) > 100
    assert result.score == 0
    assert result.grade == "F"


# --- Individual checks --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exposure", "criticality", "result", "severity"),
    [
        ("INTERNET_FACING", "CRITICAL", "FAIL", "HIGH"),
        ("INTERNET_FACING", "HIGH", "WARN", "MEDIUM"),
        ("DMZ", "CRITICAL", "WARN", "MEDIUM"),
        ("DMZ", "HIGH", "WARN", "LOW"),
        ("INTERNET_FACING", "MEDIUM", "PASS", None),
        ("INTERNAL", "CRITICAL", "PASS", None),
    ],
)
def test_exposure_criticality(exposure: str, criticality: str, result: str, severity: str | None) -> None:
    item = finding(build(asset=asset(exposure=exposure, criticality=criticality)), "exposure_criticality")
    assert (item.result, item.severity) == (result, severity)
    assert item.evidence[0] == f"Asset AST-TEST-01 exposure is {exposure} and criticality is {criticality}."
    assert (item.recommendation is None) == (severity is None)


@pytest.mark.parametrize(
    ("cvss", "recorded", "result", "severity", "deduction"),
    [
        (9.8, "LOW", "FAIL", "CRITICAL", 25),
        (7.5, "LOW", "FAIL", "HIGH", 15),
        (5.0, "CRITICAL", "WARN", "MEDIUM", 8),
        (2.0, "HIGH", "WARN", "LOW", 3),
        (0.0, "HIGH", "INFO", "INFO", 0),
        (None, "HIGH", "FAIL", "HIGH", 15),
    ],
)
def test_open_vulnerabilities_use_cvss_then_recorded_severity(
    cvss: float | None, recorded: str, result: str, severity: str, deduction: int
) -> None:
    item = finding(build(vulnerabilities=[vulnerability(1, cvss, severity=recorded)]), "open_vulnerabilities")
    assert (item.result, item.severity, item.deduction) == (result, severity, deduction)
    assert item.vulnerability_ids == [UUID(int=101)]
    assert "CVE-2026-1001" in item.recommendation


def test_open_vulnerabilities_ignore_resolved_records() -> None:
    data = build(vulnerabilities=[
        vulnerability(1, 9.8, status="MITIGATED"),
        vulnerability(2, 9.8, status="FALSE_POSITIVE"),
    ])
    item = finding(data, "open_vulnerabilities")
    assert item.result == "PASS"
    assert item.evidence == ["No open vulnerability records are linked to the asset."]


def test_open_vulnerabilities_report_highest_first_with_all_evidence() -> None:
    item = finding(
        build(vulnerabilities=[vulnerability(1, 5.0), vulnerability(2, 9.1), vulnerability(3, 9.8)]),
        "open_vulnerabilities",
    )
    assert item.evidence[0] == "3 open vulnerabilities; highest effective severity is CRITICAL."
    assert item.evidence[1].startswith("CVE-2026-1002: CVSS 9.1 (CRITICAL)")
    assert item.evidence[3] == "CVE-2026-1001: CVSS 5 (MEDIUM), recorded severity HIGH, status OPEN."
    assert "CVE-2026-1002, CVE-2026-1003" in item.recommendation


def test_missing_cvss_is_informational_and_recorded_as_missing_evidence() -> None:
    result = assess_asset(build(vulnerabilities=[vulnerability(1, None, severity="MEDIUM"), vulnerability(2, 6.0)]))
    item = next(entry for entry in result.findings if entry.check_key == "vulnerability_cvss_missing")

    assert (item.result, item.severity, item.deduction) == ("INFO", "INFO", 0)
    assert item.vulnerability_ids == [UUID(int=101)]
    assert "CVE-2026-1001: CVSS not recorded; recorded severity MEDIUM used; status OPEN." in item.evidence
    assert result.missing_evidence[0] == "CVSS is not recorded for 1 open vulnerabilities; recorded severity was used."


@pytest.mark.parametrize(
    ("exposure", "cvss", "result", "severity"),
    [
        ("INTERNET_FACING", 9.1, "WARN", "MEDIUM"),
        ("DMZ", 7.0, "WARN", "MEDIUM"),
        ("DMZ", 5.0, "WARN", "LOW"),
        ("INTERNAL", 9.8, "PASS", None),
    ],
)
def test_accepted_risk_exposure(exposure: str, cvss: float, result: str, severity: str | None) -> None:
    data = build(asset=asset(exposure=exposure), vulnerabilities=[vulnerability(1, cvss, status="ACCEPTED")])
    item = finding(data, "accepted_risk_exposure")
    assert (item.result, item.severity) == (result, severity)
    # Accepted records are not open, so they never also count as open vulnerabilities.
    assert finding(data, "open_vulnerabilities").result == "PASS"


@pytest.mark.parametrize(
    ("severity", "result", "deduction"),
    [("CRITICAL", "FAIL", 25), ("HIGH", "FAIL", 15), ("MEDIUM", "WARN", 8), ("LOW", "WARN", 3)],
)
def test_active_incidents_rate_by_highest_severity(severity: str, result: str, deduction: int) -> None:
    data = build(incidents=[incident(1, "LOW", "DETECTED"), incident(2, severity, "VERIFIED"), incident(3, "CRITICAL", "LEARNED")])
    item = finding(data, "active_incidents")
    assert (item.result, item.deduction) == (result, deduction)
    assert set(item.incident_ids) == {UUID(int=201), UUID(int=202)}


def test_contained_and_learned_incidents_are_not_active() -> None:
    item = finding(build(incidents=[incident(1, "CRITICAL", "CONTAINED"), incident(2, "HIGH", "LEARNED")]), "active_incidents")
    assert item.result == "PASS"
    assert item.evidence == ["No active incidents; 2 incidents are contained or learned."]


def test_recent_events_respect_the_seven_day_window() -> None:
    data = build(events=[
        event(1, "CRITICAL", EVENT_WINDOW),  # exactly at the window start: included
        event(2, "CRITICAL", EVENT_WINDOW + timedelta(seconds=1)),  # before the window
        event(3, "CRITICAL", -timedelta(seconds=1)),  # after as_of: outside the snapshot
    ])
    item = finding(data, "recent_high_severity_events")
    assert (item.result, item.severity) == ("FAIL", "HIGH")
    assert item.event_ids == [UUID(int=301)]


def test_high_events_are_rated_one_level_lower() -> None:
    item = finding(build(events=[event(1, "HIGH", timedelta(days=1)), event(2, "MEDIUM", timedelta(days=1))]),
                   "recent_high_severity_events")
    assert (item.result, item.severity, item.deduction) == ("WARN", "MEDIUM", 8)
    assert item.evidence[0].startswith("1 of 2 events from ")


def test_recent_event_listing_is_capped() -> None:
    events = [event(n, "HIGH", timedelta(minutes=n)) for n in range(MAX_LISTED_EVENTS + 3)]
    item = finding(build(events=events), "recent_high_severity_events")
    assert item.evidence[-1] == "3 more events are not listed."
    assert len(item.event_ids) == MAX_LISTED_EVENTS + 3
    # Most recent first.
    assert item.evidence[2].startswith("evt-0000:")


def test_threat_intel_match_on_event_ip() -> None:
    data = build(
        events=[event(1, "LOW", timedelta(hours=2), src_ip="203.0.113.9")],
        threat_indicators=[indicator(1, "203.0.113.9", severity="CRITICAL", confidence=0.85)],
    )
    item = finding(data, "threat_intel_matches")
    assert (item.result, item.severity) == ("FAIL", "CRITICAL")
    assert item.event_ids == [UUID(int=301)]
    assert item.evidence[1] == (
        "evt-0001: source IP 203.0.113.9 matches active IP indicator from test-feed (severity CRITICAL, confidence 0.85)."
    )


def test_threat_intel_normalizes_ipv6_and_matches_destination() -> None:
    data = build(
        events=[event(1, "INFO", timedelta(hours=2), src_ip=None, dest_ip="2001:0db8:0000:0000:0000:0000:0000:0001")],
        threat_indicators=[indicator(1, "2001:db8::1", severity="MEDIUM", confidence=None)],
    )
    item = finding(data, "threat_intel_matches")
    assert (item.result, item.severity) == ("WARN", "MEDIUM")
    assert "destination IP 2001:db8::1" in item.evidence[1]
    assert "confidence not recorded" in item.evidence[1]


def test_threat_intel_ignores_inactive_non_ip_and_out_of_window_matches() -> None:
    data = build(
        events=[
            event(1, "LOW", timedelta(hours=2), src_ip="203.0.113.9"),
            event(2, "LOW", timedelta(days=8), src_ip="203.0.113.10"),
        ],
        threat_indicators=[
            indicator(1, "203.0.113.9", is_active=False),
            indicator(2, "c2.example", indicator_type="DOMAIN"),
            indicator(3, "203.0.113.10"),
        ],
    )
    item = finding(data, "threat_intel_matches")
    assert item.result == "PASS"
    assert "1 active non-IP indicators were not compared; event records hold IP addresses only." in item.evidence


@pytest.mark.parametrize("owner", [None, "", "   "])
def test_missing_owner_is_an_inventory_gap(owner: str | None) -> None:
    item = finding(build(asset=asset(owner=owner)), "inventory_completeness")
    assert (item.result, item.severity, item.evidence) == ("WARN", "LOW", ["No owner is recorded."])


def test_hostname_or_ip_alone_is_enough_identity() -> None:
    assert finding(build(asset=asset(hostname=None)), "inventory_completeness").result == "PASS"
    assert finding(build(asset=asset(ip_address=None)), "inventory_completeness").result == "PASS"


@pytest.mark.parametrize("asset_status", ["INACTIVE", "DECOMMISSIONED"])
def test_activity_on_inactive_asset(asset_status: str) -> None:
    data = build(asset=asset(status=asset_status), events=[event(1, "INFO", timedelta(days=2))])
    item = finding(data, "inactive_asset_activity")
    assert (item.result, item.severity, item.deduction) == ("WARN", "MEDIUM", 8)
    assert item.event_ids == [UUID(int=301)]


def test_inactive_asset_without_recent_events_passes() -> None:
    data = build(asset=asset(status="DECOMMISSIONED"), events=[event(1, "HIGH", timedelta(days=30))])
    assert finding(data, "inactive_asset_activity").result == "PASS"


# --- Determinism, validation and purity ---------------------------------------------------------


def _rich_input(shuffle_seed: int | None = None) -> AssessmentInput:
    vulnerabilities = [vulnerability(n, cvss, status=status) for n, (cvss, status) in
                       enumerate([(9.8, "OPEN"), (None, "OPEN"), (7.2, "ACCEPTED"), (5.0, "OPEN"), (9.0, "MITIGATED")])]
    incidents = [incident(n, severity, state) for n, (severity, state) in
                 enumerate([("HIGH", "VERIFIED"), ("CRITICAL", "CONTAINED"), ("MEDIUM", "DETECTED")])]
    events = [event(n, severity, timedelta(hours=n), src_ip=f"203.0.113.{n}") for n, severity in
              enumerate(["CRITICAL", "HIGH", "LOW", "HIGH", "INFO", "CRITICAL"])]
    indicators = [indicator(1, "203.0.113.1"), indicator(2, "203.0.113.5", severity="CRITICAL"),
                  indicator(3, "bad.example", indicator_type="DOMAIN")]
    if shuffle_seed is not None:
        rng = random.Random(shuffle_seed)
        for items in (vulnerabilities, incidents, events, indicators):
            rng.shuffle(items)
    return build(asset=asset(exposure="DMZ", criticality="CRITICAL"), vulnerabilities=vulnerabilities,
                 incidents=incidents, events=events, threat_indicators=indicators)


def test_repeated_runs_are_identical() -> None:
    data = _rich_input()
    first = assess_asset(data).model_dump(mode="json")
    assert all(assess_asset(data).model_dump(mode="json") == first for _ in range(5))


def test_input_order_does_not_change_the_result() -> None:
    baseline = assess_asset(_rich_input()).model_dump(mode="json")
    for seed in range(10):
        assert assess_asset(_rich_input(seed)).model_dump(mode="json") == baseline


def test_assessment_does_not_mutate_input() -> None:
    data = _rich_input()
    before = data.model_dump(mode="json")
    assess_asset(data)
    assert data.model_dump(mode="json") == before


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        build(as_of=datetime(2026, 10, 1, 12, 0))
    with pytest.raises(ValidationError):
        AssessmentEventInput(id=UUID(int=1), event_uid="evt", occurred_at=datetime(2026, 10, 1),
                             severity="LOW", src_ip=None, dest_ip=None)


def test_unknown_enum_values_are_rejected() -> None:
    with pytest.raises(ValidationError):
        asset(criticality="EXTREME")


def test_engine_imports_no_database_or_network_modules() -> None:
    tree = ast.parse(Path(assessment_engine.__file__).read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = ("sqlalchemy", "app.db", "app.models", "httpx", "socket", "urllib", "requests")
    assert not [name for name in imported if name.startswith(forbidden)]
