"""Bounded event evidence in the pure engine: caps, totals and score independence from samples.

No database, clock or network is used.
"""

import random
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.schemas.assessment import (
    AssessmentAssetInput,
    AssessmentEventEvidence,
    AssessmentEventInput,
    AssessmentIncidentInput,
    AssessmentIndicatorInput,
    AssessmentInput,
    AssessmentLinkedIncidentInput,
    AssessmentVulnerabilityInput,
)
from app.services.assessment_engine import (
    MAX_REFERENCE_IDS,
    METHODOLOGY_V1,
    METHODOLOGY_V2,
    SAMPLE_PER_CLASS,
    assess_asset,
    event_order_key,
    summarize_events,
)

AS_OF = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
EVENT_COUNT = 5000
METHODOLOGIES = (METHODOLOGY_V1, METHODOLOGY_V2)


def asset(**overrides: Any) -> AssessmentAssetInput:
    fields: dict[str, Any] = {
        "id": UUID(int=1), "asset_key": "AST-EVIDENCE", "name": "evidence asset", "hostname": "evidence-host",
        "ip_address": "10.9.0.1", "criticality": "LOW", "exposure": "INTERNAL", "status": "DECOMMISSIONED",
        "owner": "platform-team",
    }
    return AssessmentAssetInput(**{**fields, **overrides})


def indicator(n: int, value: str, severity: str = "HIGH", indicator_type: str = "IP") -> AssessmentIndicatorInput:
    return AssessmentIndicatorInput(id=UUID(int=10_000_000 + n), value=value, indicator_type=indicator_type,
                                    source=f"feed-{n % 3}", severity=severity, confidence=0.5, is_active=True)


def large_case(seed: int = 7) -> AssessmentInput:
    """5,000 in-window events across every class, plus 20,000 indicators of which few can match."""
    rng = random.Random(seed)
    states = ["DETECTED", "VERIFIED", "CONTAINED", "LEARNED"]
    incidents = [AssessmentIncidentInput(id=UUID(int=500 + n), incident_key=f"INC-{n:03d}", severity="MEDIUM", state=state)
                 for n, state in enumerate(states)]
    events = []
    for n in range(EVENT_COUNT):
        links = [AssessmentLinkedIncidentInput(id=i.id, incident_key=i.incident_key, state=i.state)
                 for i in rng.sample(incidents, rng.choice([0, 0, 1, 2]))]
        dest = rng.choice(["203.0.113.9", "2001:db8::66", "198.51.100.200", "192.0.2.50", None])
        events.append(AssessmentEventInput(
            id=UUID(int=1_000_000 + n), event_uid=f"evt-{n:05d}",
            occurred_at=AS_OF - timedelta(seconds=rng.randint(0, 6 * 86400)),
            severity=rng.choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
            src_ip=f"10.9.{n % 50}.{n % 250}", dest_ip=dest, linked_incidents=links,
        ))
    indicators = [indicator(n, f"100.64.{n // 250}.{n % 250}", "LOW") for n in range(20_000)]  # never match
    indicators += [indicator(20_001, "203.0.113.9", "HIGH"), indicator(20_002, "2001:0DB8:0::66", "CRITICAL"),
                   indicator(20_003, "c2.example", "CRITICAL", indicator_type="DOMAIN")]
    return AssessmentInput(asset=asset(), incidents=incidents, events=events, threat_indicators=indicators, as_of=AS_OF)


@pytest.fixture(scope="module")
def case() -> AssessmentInput:
    return large_case()


@pytest.fixture(scope="module")
def evidence(case: AssessmentInput) -> AssessmentEventEvidence:
    return summarize_events(case)


def by_key(data: AssessmentInput, methodology: str) -> dict[str, Any]:
    return {item.check_key: item for item in assess_asset(data, methodology=methodology).findings}


# --- Caps and totals ----------------------------------------------------------------------------


@pytest.mark.parametrize("methodology", METHODOLOGIES)
def test_event_references_are_capped_with_exact_totals(case: AssessmentInput, methodology: str) -> None:
    findings = by_key(case, methodology)
    in_window = sorted(case.events, key=event_order_key, reverse=True)
    high = [e for e in in_window if e.severity in ("HIGH", "CRITICAL")]
    matched = [e for e in in_window if e.dest_ip in ("203.0.113.9", "2001:db8::66")]

    for key, expected in (
        ("recent_high_severity_events", high),
        ("threat_intel_matches", matched),
        ("inactive_asset_activity", in_window),
    ):
        finding = findings[key]
        assert finding.event_total == len(expected), key
        assert len(finding.event_ids) == MAX_REFERENCE_IDS, key
        # The kept IDs are the most recent matching events, in window order.
        assert finding.event_ids == [e.id for e in expected[:MAX_REFERENCE_IDS]], key

    assert findings["inactive_asset_activity"].event_total == EVENT_COUNT
    assert findings["inactive_asset_activity"].evidence[0].startswith(f"Asset status is DECOMMISSIONED, but {EVENT_COUNT} events")
    assert findings["inactive_asset_activity"].evidence[-1] == f"{EVENT_COUNT - 10} more events are not listed."
    assert findings["recent_high_severity_events"].evidence[0].startswith(f"{len(high)} of {EVENT_COUNT} events")


def test_match_totals_count_every_indicator_match(case: AssessmentInput) -> None:
    # Each matched event matches exactly one indicator (IPv4 or normalized IPv6); the DOMAIN indicator and
    # the 20,000 non-matching IPs never match.
    expected = sum(1 for e in case.events if e.dest_ip in ("203.0.113.9", "2001:db8::66"))
    threat = by_key(case, METHODOLOGY_V1)["threat_intel_matches"]
    assert threat.evidence[0] == f"{expected} indicator matches across events from {threat.evidence[0].split('from ', 1)[1]}"
    assert threat.evidence[-1] == f"{expected - 10} more matches are not listed."
    assert threat.severity == "CRITICAL"  # the IPv6 indicator written as 2001:0DB8:0::66


def test_vulnerability_and_incident_references_are_capped() -> None:
    vulns = [AssessmentVulnerabilityInput(id=UUID(int=2000 + n), cve_id=f"CVE-2099-{n:05d}", title=f"v{n}",
                                          cvss_score=5.0, severity="MEDIUM", status="OPEN") for n in range(150)]
    incidents = [AssessmentIncidentInput(id=UUID(int=3000 + n), incident_key=f"INC-{n:04d}", severity="LOW",
                                         state="DETECTED") for n in range(130)]
    data = AssessmentInput(asset=asset(status="ACTIVE"), vulnerabilities=vulns, incidents=incidents, as_of=AS_OF)
    findings = by_key(data, METHODOLOGY_V2)
    open_vulns, active = findings["open_vulnerabilities"], findings["active_incidents"]
    assert (len(open_vulns.vulnerability_ids), open_vulns.vulnerability_total) == (100, 150)
    assert open_vulns.vulnerability_ids == [v.id for v in vulns[:100]]  # CVE order
    assert (len(active.incident_ids), active.incident_total) == (100, 130)
    assert findings["exposure_criticality"].vulnerability_total == 0


def test_uncapped_lists_have_matching_totals() -> None:
    data = AssessmentInput(asset=asset(), events=large_case().events[:5], as_of=AS_OF)
    for finding in assess_asset(data).findings:
        assert finding.event_total >= len(finding.event_ids)
        assert finding.vulnerability_total == len(finding.vulnerability_ids)
        assert finding.incident_total == len(finding.incident_ids)


# --- Scores come from buckets, never from samples -----------------------------------------------


def test_samples_are_bounded_per_class(evidence: AssessmentEventEvidence) -> None:
    assert sum(b.count for b in evidence.buckets) == EVENT_COUNT
    assert len(evidence.samples) <= 12 * SAMPLE_PER_CLASS


@pytest.mark.parametrize("methodology", METHODOLOGIES)
def test_pre_aggregated_evidence_gives_the_identical_result(case, evidence, methodology: str) -> None:
    aggregated = case.model_copy(update={"events": [], "event_evidence": evidence})
    assert assess_asset(aggregated, methodology=methodology) == assess_asset(case, methodology=methodology)


@pytest.mark.parametrize("methodology", METHODOLOGIES)
@pytest.mark.parametrize("keep", ["none", "one", "random"])
def test_score_does_not_depend_on_which_events_are_sampled(case, evidence, methodology: str, keep: str) -> None:
    rng = random.Random(3)
    samples = {
        "none": [],
        "one": evidence.samples[:1],
        "random": rng.sample(evidence.samples, len(evidence.samples) // 3),
    }[keep]
    thinned = case.model_copy(update={"events": [], "event_evidence": evidence.model_copy(update={"samples": samples})})
    full, partial = assess_asset(case, methodology=methodology), assess_asset(thinned, methodology=methodology)

    assert (partial.score, partial.grade, partial.summary) == (full.score, full.grade, full.summary)
    for a, b in zip(full.findings, partial.findings, strict=True):
        assert (a.check_key, a.result, a.severity, a.deduction) == (b.check_key, b.result, b.severity, b.deduction)
        assert (a.event_total, a.vulnerability_total, a.incident_total) == (b.event_total, b.vulnerability_total, b.incident_total)
        # Count lines (the first evidence line) are exact even when fewer events are listed.
        assert a.evidence[0] == b.evidence[0]


def test_v2_attribution_holds_at_scale(case: AssessmentInput) -> None:
    v1, v2 = by_key(case, METHODOLOGY_V1), by_key(case, METHODOLOGY_V2)
    for key in ("recent_high_severity_events", "threat_intel_matches"):
        assert v2[key].deduction <= v1[key].deduction
    assert v2["recent_high_severity_events"].event_total == v1["recent_high_severity_events"].event_total
    assert assess_asset(case).score >= assess_asset(case, methodology=METHODOLOGY_V1).score


# --- Ordering, repeatability and validation -----------------------------------------------------


def test_large_case_is_repeatable_and_order_independent(case: AssessmentInput) -> None:
    baseline = assess_asset(case).model_dump(mode="json")
    rng = random.Random(11)
    shuffled = case.model_copy(update={
        "events": rng.sample(case.events, len(case.events)),
        "threat_indicators": rng.sample(case.threat_indicators, len(case.threat_indicators)),
    })
    assert assess_asset(case).model_dump(mode="json") == baseline
    assert assess_asset(shuffled).model_dump(mode="json") == baseline


def test_events_and_event_evidence_are_mutually_exclusive(case, evidence) -> None:
    with pytest.raises(ValidationError, match="either events or event_evidence"):
        AssessmentInput(asset=asset(), events=case.events[:1], event_evidence=evidence, as_of=AS_OF)


@pytest.mark.parametrize(
    ("value", "indicator_type", "matches"),
    [
        ("203.0.113.9", "IP", True),
        ("  203.0.113.9\t", "IP", True),
        (" 203.0.113.9　", "IP", True),  # non-ASCII whitespace, as str.strip() removes it
        ("2001:0DB8:0000:0000:0000:0000:0000:0066", "IP", True),
        ("2001:db8::66", "IP", True),
        ("203.0.113.9/32", "IP", False),  # a network, not an address
        ("203.000.113.009", "IP", False),  # leading zeros are rejected by Python's ipaddress
        ("not-an-ip", "IP", False),
        ("203.0.113.9", "DOMAIN", False),  # only IP indicators are compared
        ("203.0.113.9", "URL", False),
    ],
)
def test_indicator_normalization(value: str, indicator_type: str, matches: bool) -> None:
    events = [
        AssessmentEventInput(id=UUID(int=1), event_uid="evt-v4", occurred_at=AS_OF - timedelta(hours=1),
                             severity="LOW", src_ip=None, dest_ip="203.0.113.9"),
        AssessmentEventInput(id=UUID(int=2), event_uid="evt-v6", occurred_at=AS_OF - timedelta(hours=2),
                             severity="LOW", src_ip="2001:db8::66", dest_ip=None),
    ]
    data = AssessmentInput(asset=asset(status="ACTIVE"), events=events,
                           threat_indicators=[indicator(1, value, indicator_type=indicator_type)], as_of=AS_OF)
    threat = by_key(data, METHODOLOGY_V2)["threat_intel_matches"]
    assert (threat.result == "FAIL") is matches
    assert threat.event_total == (1 if matches else 0)
