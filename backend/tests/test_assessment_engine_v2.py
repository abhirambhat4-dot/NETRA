"""Unit tests for assessment-v2 event attribution; no database, clock or network is used.

Covers the Stage 4 review reproductions: one event must not be deducted by several checks, and events
linked only to contained or learned incidents are not treated as unresolved threats.
"""

import random
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from app.schemas.assessment import (
    AssessmentAssetInput,
    AssessmentEventInput,
    AssessmentIncidentInput,
    AssessmentIndicatorInput,
    AssessmentInput,
    AssessmentLinkedIncidentInput,
)
from app.services.assessment_engine import (
    CHECKS_V1,
    CHECKS_V2,
    LINK_ACTIVE,
    LINK_RESOLVED,
    LINK_UNLINKED,
    METHODOLOGY_V1,
    METHODOLOGY_V2,
    METHODOLOGY_VERSION,
    assess_asset,
    event_link_status,
)

AS_OF = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
WINDOW = "2026-09-24T12:00:00+00:00 to 2026-10-01T12:00:00+00:00"
EVENT_AT = "2026-10-01T11:00:00+00:00"
RULE_6 = (
    "assessment-v2 deducts each event once: events linked to an active incident are covered by that incident, "
    "events linked only to contained or learned incidents are not treated as unresolved, and unlinked events "
    "matching an active indicator are scored under threat-indicator matches."
)
RULE_7 = "assessment-v2 deducts each event once: only matches on unlinked events are scored here."
MATCH = (
    "evt-beacon: destination IP 203.0.113.9 matches active IP indicator from test-feed "
    "(severity HIGH, confidence 0.9)"
)


def asset(**overrides: Any) -> AssessmentAssetInput:
    # Low-criticality internal asset, so only event-driven checks can deduct.
    fields: dict[str, Any] = {
        "id": UUID(int=1), "asset_key": "AST-V2-01", "name": "v2 asset", "hostname": "v2-host",
        "ip_address": "10.0.0.1", "criticality": "LOW", "exposure": "INTERNAL", "status": "ACTIVE",
        "owner": "platform-team",
    }
    return AssessmentAssetInput(**{**fields, **overrides})


def incident(n: int, severity: str, state: str) -> AssessmentIncidentInput:
    return AssessmentIncidentInput(id=UUID(int=200 + n), incident_key=f"INC-{n:04d}", severity=severity, state=state)


def link(n: int, state: str) -> AssessmentLinkedIncidentInput:
    return AssessmentLinkedIncidentInput(id=UUID(int=200 + n), incident_key=f"INC-{n:04d}", state=state)


def event(uid: str = "evt-beacon", severity: str = "CRITICAL", links: list[AssessmentLinkedIncidentInput] | None = None,
          dest_ip: str = "203.0.113.9", n: int = 1, age: timedelta = timedelta(hours=1)) -> AssessmentEventInput:
    return AssessmentEventInput(
        id=UUID(int=300 + n), event_uid=uid, occurred_at=AS_OF - age, severity=severity,
        src_ip="10.0.0.1", dest_ip=dest_ip, linked_incidents=links or [],
    )


INDICATOR = AssessmentIndicatorInput(
    id=UUID(int=400), value="203.0.113.9", indicator_type="IP", source="test-feed", severity="HIGH",
    confidence=0.9, is_active=True,
)


def build(events: list[AssessmentEventInput], incidents: list[AssessmentIncidentInput] = (),
          indicators: list[AssessmentIndicatorInput] = (INDICATOR,), **asset_overrides: Any) -> AssessmentInput:
    return AssessmentInput(asset=asset(**asset_overrides), events=list(events), incidents=list(incidents),
                           threat_indicators=list(indicators), as_of=AS_OF)


def findings(data: AssessmentInput, methodology: str = METHODOLOGY_V2) -> dict[str, Any]:
    return {item.check_key: item for item in assess_asset(data, methodology=methodology).findings}


def deductions(data: AssessmentInput, methodology: str = METHODOLOGY_V2) -> dict[str, int]:
    return {key: item.deduction for key, item in findings(data, methodology).items() if item.deduction}


# --- Methodology versioning ---------------------------------------------------------------------


def test_v2_is_the_current_methodology_and_v1_stays_callable() -> None:
    assert METHODOLOGY_VERSION == METHODOLOGY_V2 == "assessment-v2"
    data = build([event()])
    assert assess_asset(data).methodology_version == "assessment-v2"
    assert assess_asset(data, methodology=METHODOLOGY_V1).methodology_version == "assessment-v1"


def test_unknown_methodology_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown assessment methodology"):
        assess_asset(build([]), methodology="assessment-v0")


def test_v2_keeps_v1_check_keys_and_order() -> None:
    data = build([])
    assert [item.check_key for item in assess_asset(data).findings] == [
        item.check_key for item in assess_asset(data, methodology=METHODOLOGY_V1).findings
    ]
    assert len(CHECKS_V2) == len(CHECKS_V1) == 9


def test_v2_evidence_names_its_own_methodology() -> None:
    exposure = findings(build([]))["exposure_criticality"]
    assert exposure.evidence[-1] == "This combination is not rated as elevated exposure in assessment-v2."
    summary = assess_asset(build([])).summary
    assert summary.endswith("under assessment-v2: 0 failed, 0 warnings, 0 informational and 9 passed checks.")


@pytest.mark.parametrize(
    ("states", "status"),
    [
        ([], LINK_UNLINKED),
        (["PRIORITISED"], LINK_ACTIVE),
        (["CONTAINED"], LINK_RESOLVED),
        (["LEARNED"], LINK_RESOLVED),
        (["CONTAINED", "LEARNED"], LINK_RESOLVED),
        (["CONTAINED", "VERIFIED"], LINK_ACTIVE),
        (["LEARNED", "DETECTED", "CONTAINED"], LINK_ACTIVE),
    ],
)
def test_event_link_status(states: list[str], status: str) -> None:
    assert event_link_status(event(links=[link(n, state) for n, state in enumerate(states)])) == status


# --- Stage 4 reproductions ----------------------------------------------------------------------


def test_a_event_linked_to_active_incident_is_deducted_once() -> None:
    data = build([event(links=[link(1, "PRIORITISED")])], [incident(1, "HIGH", "PRIORITISED")])
    result = assess_asset(data)
    found = findings(data)

    assert deductions(data) == {"active_incidents": 15}
    assert (result.score, result.grade) == (85, "B")
    assert (result.failed, result.warnings, result.informational, result.passed) == (1, 0, 2, 6)

    recent = found["recent_high_severity_events"]
    assert (recent.result, recent.severity, recent.deduction) == ("INFO", "INFO", 0)
    assert recent.evidence == [
        f"1 of 1 event from {WINDOW} is HIGH or CRITICAL.",
        RULE_6,
        "1 event is linked to an active incident and not deducted here:",
        f"evt-beacon: severity CRITICAL at {EVENT_AT}; linked to INC-0001 (PRIORITISED).",
    ]
    assert recent.recommendation == "Handle events already linked to active incidents through those incidents."
    assert recent.event_ids == [UUID(int=301)]

    threat = found["threat_intel_matches"]
    assert (threat.result, threat.severity, threat.deduction) == ("INFO", "INFO", 0)
    assert threat.evidence == [
        f"1 indicator match across events from {WINDOW}.",
        RULE_7,
        "1 match is on events linked to an active incident and not deducted here:",
        f"{MATCH}; event linked to INC-0001 (PRIORITISED).",
    ]
    assert threat.recommendation == "Matches on events linked to active incidents are handled through those incidents."
    assert threat.event_ids == [UUID(int=301)]

    active = found["active_incidents"]
    assert (active.result, active.severity, active.incident_ids) == ("FAIL", "HIGH", [UUID(int=201)])

    # v1 deducted the same event three times: 55/100, grade F.
    v1 = assess_asset(data, methodology=METHODOLOGY_V1)
    assert deductions(data, METHODOLOGY_V1) == {
        "active_incidents": 15, "recent_high_severity_events": 15, "threat_intel_matches": 15,
    }
    assert (v1.score, v1.grade) == (55, "F")


@pytest.mark.parametrize("state", ["CONTAINED", "LEARNED"])
def test_b_c_event_linked_only_to_resolved_incident_is_not_deducted(state: str) -> None:
    data = build([event(links=[link(1, state)])], [incident(1, "HIGH", state)])
    result = assess_asset(data)
    found = findings(data)

    assert deductions(data) == {}
    assert (result.score, result.grade) == (100, "A")
    assert (result.failed, result.warnings, result.informational, result.passed) == (0, 0, 2, 7)
    assert found["active_incidents"].evidence == ["No active incidents; 1 incident is contained or learned."]

    recent = found["recent_high_severity_events"]
    assert (recent.result, recent.deduction) == ("INFO", 0)
    assert recent.evidence[2:] == [
        "1 event is linked only to contained or learned incidents and not deducted:",
        f"evt-beacon: severity CRITICAL at {EVENT_AT}; linked to INC-0001 ({state}).",
    ]
    assert recent.recommendation == "Events linked only to contained or learned incidents need no further correlation."
    assert "correlate them into an incident" not in recent.recommendation

    threat = found["threat_intel_matches"]
    assert (threat.result, threat.deduction) == ("INFO", 0)
    assert threat.evidence[2:] == [
        "1 match is on events linked only to contained or learned incidents and not deducted:",
        f"{MATCH}; event linked to INC-0001 ({state}).",
    ]
    assert threat.recommendation == "Matches on events linked only to contained or learned incidents need no further action."

    # v1 still deducted checks 6 and 7 after containment: 70/100, grade C.
    v1 = assess_asset(data, methodology=METHODOLOGY_V1)
    assert (v1.score, v1.grade) == (70, "C")


def test_d_unlinked_event_matching_indicator_is_scored_by_threat_intel_only() -> None:
    data = build([event()])
    result = assess_asset(data)
    found = findings(data)

    assert deductions(data) == {"threat_intel_matches": 15}
    assert (result.score, result.grade) == (85, "B")

    recent = found["recent_high_severity_events"]
    assert (recent.result, recent.deduction) == ("INFO", 0)
    assert recent.evidence[2:] == [
        "1 unlinked event matches an active indicator and is scored under threat-indicator matches:",
        f"evt-beacon: severity CRITICAL at {EVENT_AT}.",
    ]
    assert recent.recommendation == (
        "Correlate the 1 unlinked event matching threat indicators into an incident; "
        "it is scored under threat-indicator matches."
    )

    threat = found["threat_intel_matches"]
    assert (threat.result, threat.severity, threat.deduction) == ("FAIL", "HIGH", 15)
    assert threat.evidence[2:] == ["1 match on unlinked events is scored here:", f"{MATCH}."]
    assert threat.recommendation.startswith("Investigate traffic between the asset and the matched indicator addresses")


def test_d_unlinked_event_without_indicator_is_scored_by_recent_events_only() -> None:
    data = build([event()], indicators=[])
    result = assess_asset(data)
    recent = findings(data)["recent_high_severity_events"]

    assert deductions(data) == {"recent_high_severity_events": 15}
    assert (result.score, result.grade) == (85, "B")
    assert (recent.result, recent.severity) == ("FAIL", "HIGH")
    assert recent.evidence[2:] == [
        "1 unlinked event is scored here, one level below the highest of its severity:",
        f"evt-beacon: severity CRITICAL at {EVENT_AT}.",
    ]
    assert recent.recommendation == (
        "Review the 1 unlinked high-severity event in Security Events and correlate it into an incident."
    )
    assert findings(data)["threat_intel_matches"].result == "PASS"


def test_e_event_linked_to_active_and_resolved_incidents_counts_as_active() -> None:
    # Links listed out of order: evidence sorts them by incident key.
    data = build(
        [event(links=[link(2, "VERIFIED"), link(1, "CONTAINED")])],
        [incident(1, "HIGH", "CONTAINED"), incident(2, "MEDIUM", "VERIFIED")],
    )
    result = assess_asset(data)
    found = findings(data)

    assert deductions(data) == {"active_incidents": 8}
    assert (result.score, result.grade) == (92, "A")
    assert found["active_incidents"].incident_ids == [UUID(int=202)]
    recent = found["recent_high_severity_events"]
    assert recent.evidence[2:] == [
        "1 event is linked to an active incident and not deducted here:",
        f"evt-beacon: severity CRITICAL at {EVENT_AT}; linked to INC-0001 (CONTAINED), INC-0002 (VERIFIED).",
    ]
    assert found["threat_intel_matches"].evidence[-1] == (
        f"{MATCH}; event linked to INC-0001 (CONTAINED), INC-0002 (VERIFIED)."
    )


def test_e_event_linked_to_several_resolved_incidents_is_resolved() -> None:
    data = build(
        [event(links=[link(1, "CONTAINED"), link(2, "LEARNED")])],
        [incident(1, "HIGH", "CONTAINED"), incident(2, "CRITICAL", "LEARNED")],
    )
    assert deductions(data) == {}
    assert assess_asset(data).score == 100
    assert findings(data)["recent_high_severity_events"].evidence[2] == (
        "1 event is linked only to contained or learned incidents and not deducted:"
    )


# --- Mixed batches and documented edge cases ----------------------------------------------------


def test_mixed_batch_attributes_each_event_once() -> None:
    events = [
        event("evt-active", "CRITICAL", [link(1, "PRIORITISED")], dest_ip="198.51.100.1", n=1),
        event("evt-resolved", "CRITICAL", [link(2, "LEARNED")], dest_ip="198.51.100.2", n=2),
        event("evt-unlinked", "HIGH", dest_ip="198.51.100.3", n=3),
        event("evt-ioc", "LOW", dest_ip="203.0.113.9", n=4),  # not HIGH: only check 7 sees it
    ]
    data = build(events, [incident(1, "HIGH", "PRIORITISED"), incident(2, "HIGH", "LEARNED")])
    found = findings(data)

    # Incident 15 + unlinked HIGH event (rated MEDIUM) 8 + unlinked indicator match HIGH 15.
    assert deductions(data) == {"active_incidents": 15, "recent_high_severity_events": 8, "threat_intel_matches": 15}
    assert assess_asset(data).score == 62
    recent = found["recent_high_severity_events"]
    assert recent.severity == "MEDIUM"
    assert set(recent.event_ids) == {UUID(int=301), UUID(int=302), UUID(int=303)}
    assert recent.recommendation == (
        "Review the 1 unlinked high-severity event in Security Events and correlate it into an incident. "
        "Handle events already linked to active incidents through those incidents. "
        "Events linked only to contained or learned incidents need no further correlation."
    )
    assert found["threat_intel_matches"].event_ids == [UUID(int=304)]


def test_event_linked_to_active_incident_on_another_asset_is_covered_by_that_incident() -> None:
    # Documented v2 behaviour: the incident is not on this asset, so check 5 does not deduct it either.
    data = build([event(links=[link(9, "UNDERSTOOD")])], incidents=[])
    assert deductions(data) == {}
    assert findings(data)["active_incidents"].result == "PASS"
    assert findings(data)["recent_high_severity_events"].evidence[-1].endswith("linked to INC-0009 (UNDERSTOOD).")


def test_inactive_asset_activity_rule_is_unchanged_in_v2() -> None:
    data = build([event(links=[link(1, "CONTAINED")])], [incident(1, "HIGH", "CONTAINED")], status="DECOMMISSIONED")
    v1, v2 = findings(data, METHODOLOGY_V1)["inactive_asset_activity"], findings(data)["inactive_asset_activity"]
    assert (v2.result, v2.severity, v2.deduction, v2.event_ids, v2.event_total) == (
        v1.result, v1.severity, v1.deduction, v1.event_ids, v1.event_total
    )
    # Only the wording differs: v2 agrees with the count, v1 keeps its original text.
    assert v1.evidence[0].startswith("Asset status is DECOMMISSIONED, but 1 events were recorded from ")
    assert v2.evidence[0].startswith("Asset status is DECOMMISSIONED, but 1 event was recorded from ")


# --- Evidence wording ---------------------------------------------------------------------------


def _wording_case(count: int) -> AssessmentInput:
    from app.schemas.assessment import AssessmentVulnerabilityInput

    vulns = [AssessmentVulnerabilityInput(id=UUID(int=900 + n), cve_id=f"CVE-2099-{n:04d}", title=f"v{n}",
                                          cvss_score=None, severity="MEDIUM", status=status)
             for n in range(count) for status in ("OPEN", "ACCEPTED")]
    events = [event(f"evt-{n}", "HIGH", dest_ip="192.0.2.77", n=n) for n in range(count)]
    data = build(events, [incident(n, "LOW", "CONTAINED") for n in range(count)], indicators=[],
                 exposure="DMZ", status="INACTIVE")
    return data.model_copy(update={"vulnerabilities": vulns})


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (1, [
            "1 open vulnerability; highest effective severity is MEDIUM.",
            "1 open vulnerability has no CVSS score; its recorded severity was used instead.",
            "1 accepted-risk vulnerability on a DMZ asset; highest effective severity is MEDIUM.",
            "No active incidents; 1 incident is contained or learned.",
            f"1 of 1 event from {WINDOW} is HIGH or CRITICAL.",
            "1 unlinked event is scored here, one level below the highest of its severity:",
            "Asset status is INACTIVE, but 1 event was recorded from",
            "CVSS is not recorded for 1 open vulnerability; recorded severity was used.",
        ]),
        (2, [
            "2 open vulnerabilities; highest effective severity is MEDIUM.",
            "2 open vulnerabilities have no CVSS score; their recorded severity was used instead.",
            "2 accepted-risk vulnerabilities on a DMZ asset; highest effective severity is MEDIUM.",
            "No active incidents; 2 incidents are contained or learned.",
            f"2 of 2 events from {WINDOW} are HIGH or CRITICAL.",
            "2 unlinked events are scored here, one level below the highest of their severities:",
            "Asset status is INACTIVE, but 2 events were recorded from",
            "CVSS is not recorded for 2 open vulnerabilities; recorded severity was used.",
        ]),
    ],
)
def test_v2_wording_agrees_with_counts(count: int, expected: list[str]) -> None:
    result = assess_asset(_wording_case(count))
    text = [line for finding in result.findings for line in finding.evidence] + result.missing_evidence
    for phrase in expected:
        assert any(line.startswith(phrase) for line in text), phrase
    recent = findings(_wording_case(count))["recent_high_severity_events"]
    assert recent.recommendation == (
        f"Review the {count} unlinked high-severity {'event' if count == 1 else 'events'} in Security Events and "
        f"correlate {'it' if count == 1 else 'them'} into an incident."
    )


def test_v1_keeps_its_original_wording() -> None:
    result = assess_asset(_wording_case(1), methodology=METHODOLOGY_V1)
    text = [line for finding in result.findings for line in finding.evidence] + result.missing_evidence
    for phrase in (
        "1 open vulnerabilities; highest effective severity is MEDIUM.",
        "1 open vulnerabilities have no CVSS score; their recorded severity was used instead.",
        "No active incidents; 1 incidents are contained or learned.",
        f"1 of 1 events from {WINDOW} are HIGH or CRITICAL.",
        "CVSS is not recorded for 1 open vulnerabilities; recorded severity was used.",
    ):
        assert any(line.startswith(phrase) for line in text), phrase


def test_v2_summary_wording() -> None:
    # Exposure DMZ + LOW criticality is not rated; one accepted MEDIUM vulnerability on a DMZ asset is the
    # only warning, and the asset is active with no events, so 8 checks pass.
    base = _wording_case(1)
    accepted = [item for item in base.vulnerabilities if item.status == "ACCEPTED"]
    data = base.model_copy(update={
        "events": [], "incidents": [], "vulnerabilities": accepted,
        "asset": base.asset.model_copy(update={"status": "ACTIVE"}),
    })
    assert assess_asset(data).summary.endswith(": 0 failed, 1 warning, 0 informational and 8 passed checks.")
    assert assess_asset(data, methodology=METHODOLOGY_V1).summary.endswith(
        ": 0 failed, 1 warnings, 0 informational and 8 passed checks."
    )


def test_more_than_ten_events_per_group_are_capped_in_evidence_not_ids() -> None:
    events = [event(f"evt-{n:02d}", "HIGH", [link(1, "PRIORITISED")], n=n, age=timedelta(minutes=n)) for n in range(12)]
    recent = findings(build(events, [incident(1, "HIGH", "PRIORITISED")]))["recent_high_severity_events"]
    assert recent.evidence[-1] == "2 more events are not listed."
    assert len(recent.event_ids) == 12


# --- Determinism and invariants -----------------------------------------------------------------


def _random_case(seed: int) -> AssessmentInput:
    rng = random.Random(seed)
    states = ["DETECTED", "UNDERSTOOD", "PRIORITISED", "VERIFIED", "AUTHORIZED", "CONTAINED", "LEARNED"]
    incidents = [incident(n, rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]), rng.choice(states)) for n in range(4)]
    events = []
    for n in range(rng.randint(0, 8)):
        links = [link(i.id.int - 200, i.state) for i in rng.sample(incidents, rng.randint(0, 2))]
        ip = rng.choice(["203.0.113.9", "198.51.100.7", "192.0.2.1"])
        events.append(event(f"evt-{n}", rng.choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]), links,
                            dest_ip=ip, n=n, age=timedelta(hours=rng.randint(0, 200))))
    indicators = [INDICATOR, AssessmentIndicatorInput(id=UUID(int=401), value="198.51.100.7", indicator_type="IP",
                                                      source="feed-2", severity="CRITICAL", confidence=None, is_active=True)]
    return build(events, incidents, indicators)


@pytest.mark.parametrize("seed", range(40))
def test_v2_never_deducts_more_than_v1_for_events(seed: int) -> None:
    data = _random_case(seed)
    v1, v2 = deductions(data, METHODOLOGY_V1), deductions(data)
    for key in ("recent_high_severity_events", "threat_intel_matches"):
        assert v2.get(key, 0) <= v1.get(key, 0)
    for key in set(v1) - {"recent_high_severity_events", "threat_intel_matches"}:
        assert v2.get(key) == v1[key]
    assert assess_asset(data).score >= assess_asset(data, methodology=METHODOLOGY_V1).score


@pytest.mark.parametrize("seed", range(10))
def test_v2_is_deterministic_and_order_independent(seed: int) -> None:
    data = _random_case(seed)
    baseline = assess_asset(data).model_dump(mode="json")
    assert assess_asset(data).model_dump(mode="json") == baseline
    rng = random.Random(seed + 1000)
    events = [item.model_copy(update={"linked_incidents": rng.sample(item.linked_incidents, len(item.linked_incidents))})
              for item in data.events]
    rng.shuffle(events)
    incidents = rng.sample(data.incidents, len(data.incidents))
    indicators = rng.sample(data.threat_indicators, len(data.threat_indicators))
    shuffled = data.model_copy(update={"events": events, "incidents": incidents, "threat_indicators": indicators})
    assert assess_asset(shuffled).model_dump(mode="json") == baseline
