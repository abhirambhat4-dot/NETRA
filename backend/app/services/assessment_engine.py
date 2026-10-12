"""Security Assessment engine: methodologies assessment-v1 and assessment-v2.

Pure and deterministic: callers pass an AssessmentInput snapshot (including the evidence cut-off
``as_of``); the engine never queries the database, reads the clock or makes network calls. Findings
cite only the supplied records and use no MITRE mapping. Assessment never creates events or incidents.

assessment-v2 is current. It keeps every v1 check and deduction except how events are attributed in
checks 6 (recent high-severity events) and 7 (threat-indicator matches), so one event is never
deducted more than once:

* An event linked to at least one active incident (not CONTAINED or LEARNED) is covered by that
  incident: check 5 scores incidents on this asset, and checks 6 and 7 list the event without
  deducting for it. Any active link wins, so an event linked to both active and resolved incidents
  counts as active.
* An event linked only to CONTAINED or LEARNED incidents is resolved: it is listed, never treated as
  an unresolved threat and never deducted.
* An unlinked event that matches an active indicator is deducted once, by check 7 only.
* Any other unlinked HIGH or CRITICAL event is deducted once, by check 6 only.
* Only unlinked events get the advice to correlate them into an incident.

A check whose matched events are all attributed elsewhere reports INFO with no deduction, so what
matched stays visible. assessment-v1 remains callable for reference; stored snapshots keep the
methodology they were produced with and are never recalculated.

Evidence wording: v2 agrees with its counts ("1 open vulnerability", "1 event was recorded"); v1 keeps
its original always-plural text so recomputed v1 output still matches stored v1 snapshots. Wording
never affects scoring.

Event evidence is bounded. Events are reduced to exact bucket counts (severity, incident-link status
and matched indicator addresses) plus the most recent SAMPLE_PER_CLASS events of each class.
Severities, deductions and totals come from the buckets only; samples supply listed evidence and
referenced IDs, so which events are sampled never changes a score. Callers either pass raw events
(aggregated here) or pre-aggregated ``event_evidence`` built the same way, for example in SQL.
Each finding keeps at most MAX_REFERENCE_IDS IDs per reference list, most relevant first, together
with the total number of matching records.
"""

import ipaddress
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from uuid import UUID

from app.schemas.assessment import (
    AssessmentAssetInput,
    AssessmentEventBucket,
    AssessmentEventEvidence,
    AssessmentEventInput,
    AssessmentFinding,
    AssessmentGrade,
    AssessmentIncidentInput,
    AssessmentIndicatorInput,
    AssessmentInput,
    AssessmentResult,
    AssessmentResultName,
    AssessmentVulnerabilityInput,
    SeverityName,
)

METHODOLOGY_V1 = "assessment-v1"
METHODOLOGY_V2 = "assessment-v2"
# Methodology used for new assessments.
METHODOLOGY_VERSION = METHODOLOGY_V2
MAX_SCORE = 100
EVENT_WINDOW = timedelta(days=7)
MAX_LISTED_EVENTS = 10
# Referenced IDs kept per list in each finding; the finding also records the full total.
MAX_REFERENCE_IDS = 100
# Most recent events kept per (link status, HIGH/CRITICAL, indicator-matched) class. Every finding's
# ID list and listed evidence is a most-recent-first prefix of a union of classes, so this many per
# class always supplies the first MAX_REFERENCE_IDS of it.
SAMPLE_PER_CLASS = MAX_REFERENCE_IDS

SEVERITY_RANK: dict[SeverityName, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# The deduction depends only on the finding severity; every check uses this one table.
SEVERITY_DEDUCTIONS: dict[SeverityName, int] = {"INFO": 0, "LOW": 3, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 25}
# Inclusive lower bound of each grade, highest first; scores below the last bound grade F.
GRADE_BOUNDARIES: tuple[tuple[AssessmentGrade, int], ...] = (("A", 90), ("B", 80), ("C", 70), ("D", 60))

# Internet-facing or DMZ placement of an important asset widens its attack surface; this is
# exposure, not evidence of compromise, so the ratings stay at HIGH or below.
EXPOSURE_SEVERITY: dict[tuple[str, str], SeverityName] = {
    ("INTERNET_FACING", "CRITICAL"): "HIGH",
    ("INTERNET_FACING", "HIGH"): "MEDIUM",
    ("DMZ", "CRITICAL"): "MEDIUM",
    ("DMZ", "HIGH"): "LOW",
}
RESOLVED_INCIDENT_STATES = frozenset({"CONTAINED", "LEARNED"})
INACTIVE_ASSET_STATUSES = frozenset({"INACTIVE", "DECOMMISSIONED"})
HIGH_EVENT_SEVERITIES = frozenset({"HIGH", "CRITICAL"})

LINK_ACTIVE = "active"
LINK_RESOLVED = "resolved"
LINK_UNLINKED = "unlinked"


@dataclass(frozen=True)
class Wording:
    """Count wording for evidence text.

    assessment-v1 keeps its original, always-plural text ("1 open vulnerabilities") so recomputed v1
    output matches stored v1 snapshots; assessment-v2 agrees with the count ("1 open vulnerability").
    """

    agrees: bool

    def word(self, count: int, singular: str, plural: str) -> str:
        return singular if self.agrees and count == 1 else plural

    def count(self, count: int, singular: str, plural: str) -> str:
        return f"{count} {self.word(count, singular, plural)}"


LEGACY_WORDING = Wording(agrees=False)
AGREEING_WORDING = Wording(agrees=True)


def deduction_for(severity: SeverityName | None) -> int:
    return SEVERITY_DEDUCTIONS[severity] if severity is not None else 0


def grade_for_score(score: int) -> AssessmentGrade:
    for grade, lower_bound in GRADE_BOUNDARIES:
        if score >= lower_bound:
            return grade
    return "F"


def cvss_severity(cvss_score: float) -> SeverityName:
    """CVSS v3 qualitative rating scale; a 0.0 base score (rating None) maps to INFO."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    if cvss_score > 0.0:
        return "LOW"
    return "INFO"


def _result_for(severity: SeverityName | None) -> AssessmentResultName:
    if severity is None:
        return "PASS"
    if severity == "INFO":
        return "INFO"
    return "FAIL" if SEVERITY_RANK[severity] >= SEVERITY_RANK["HIGH"] else "WARN"


def _highest(severities: Iterable[SeverityName]) -> SeverityName:
    return max(severities, key=SEVERITY_RANK.__getitem__)


def _capped(ids: Iterable[UUID]) -> tuple[list[UUID], int]:
    items = list(ids)
    return items[:MAX_REFERENCE_IDS], len(items)


def _finding(
    check_key: str,
    category: str,
    title: str,
    severity: SeverityName | None,
    evidence: list[str],
    recommendation: str,
    *,
    vulnerability_ids: Iterable[UUID] = (),
    incident_ids: Iterable[UUID] = (),
    event_ids: Iterable[UUID] = (),
    event_total: int | None = None,
) -> AssessmentFinding:
    """``event_ids`` may be a most-recent-first sample; ``event_total`` then counts every matching event."""
    vulnerabilities, vulnerability_total = _capped(vulnerability_ids)
    incidents, incident_total = _capped(incident_ids)
    events, event_count = _capped(event_ids)
    return AssessmentFinding(
        check_key=check_key,
        category=category,
        title=title,
        result=_result_for(severity),
        severity=severity,
        deduction=deduction_for(severity),
        evidence=evidence,
        # A passing check needs no action.
        recommendation=recommendation if severity is not None else None,
        vulnerability_ids=vulnerabilities,
        incident_ids=incidents,
        event_ids=events,
        vulnerability_total=vulnerability_total,
        incident_total=incident_total,
        event_total=event_count if event_total is None else event_total,
    )


def _vulnerability_label(vulnerability: AssessmentVulnerabilityInput) -> str:
    return vulnerability.cve_id or vulnerability.title


def _effective_severity(vulnerability: AssessmentVulnerabilityInput) -> SeverityName:
    """CVSS rating when a score is recorded, otherwise the recorded severity."""
    if vulnerability.cvss_score is None:
        return vulnerability.severity
    return cvss_severity(vulnerability.cvss_score)


def _vulnerability_order(vulnerability: AssessmentVulnerabilityInput) -> tuple[int, str, str]:
    return (-SEVERITY_RANK[_effective_severity(vulnerability)], _vulnerability_label(vulnerability), str(vulnerability.id))


def _vulnerability_evidence(vulnerability: AssessmentVulnerabilityInput) -> str:
    label = _vulnerability_label(vulnerability)
    if vulnerability.cvss_score is None:
        return (
            f"{label}: CVSS not recorded; recorded severity {vulnerability.severity} used; "
            f"status {vulnerability.status}."
        )
    return (
        f"{label}: CVSS {vulnerability.cvss_score:g} ({cvss_severity(vulnerability.cvss_score)}), "
        f"recorded severity {vulnerability.severity}, status {vulnerability.status}."
    )


def _vulnerabilities_with_status(data: AssessmentInput, status: str) -> list[AssessmentVulnerabilityInput]:
    return sorted((item for item in data.vulnerabilities if item.status == status), key=_vulnerability_order)


def event_order_key(event: AssessmentEventInput) -> tuple:
    """Window order is this key, descending: most recent first, then event_uid and id."""
    return (event.occurred_at, event.event_uid, str(event.id))


def _window_events(data: AssessmentInput) -> list[AssessmentEventInput]:
    """Raw events inside [as_of - 7 days, as_of], most recent first; later events are outside the snapshot."""
    start = data.as_of - EVENT_WINDOW
    events = [event for event in data.events if start <= event.occurred_at <= data.as_of]
    return sorted(events, key=event_order_key, reverse=True)


def _window_text(data: AssessmentInput) -> str:
    return f"{(data.as_of - EVENT_WINDOW).isoformat()} to {data.as_of.isoformat()}"


def _listed_events(
    events: list[AssessmentEventInput], describe: Callable[[AssessmentEventInput], str], total: int,
    w: Wording = LEGACY_WORDING,
) -> list[str]:
    """The first listed events of a most-recent-first sample, plus how many of ``total`` are not listed."""
    lines = [describe(event) for event in events[:MAX_LISTED_EVENTS]]
    if total > MAX_LISTED_EVENTS:
        more = total - MAX_LISTED_EVENTS
        lines.append(f"{w.count(more, 'more event', 'more events')} {w.word(more, 'is', 'are')} not listed.")
    return lines


def _normalized_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _asset_text(asset: AssessmentAssetInput) -> str:
    return f"Asset {asset.asset_key}"


def event_link_status(event: AssessmentEventInput) -> str:
    """active if any linked incident is unresolved, resolved if all are CONTAINED/LEARNED, else unlinked."""
    if not event.linked_incidents:
        return LINK_UNLINKED
    if any(item.state not in RESOLVED_INCIDENT_STATES for item in event.linked_incidents):
        return LINK_ACTIVE
    return LINK_RESOLVED


# --- Event evidence: exact buckets plus bounded samples -----------------------------------------


def indicator_address_index(
    indicators: Iterable[AssessmentIndicatorInput],
) -> tuple[dict[str, list[AssessmentIndicatorInput]], int]:
    """(normalized address -> active IP indicators, count of active indicators that are not usable IPs).

    Indicators per address are ordered by value, source and id, which is the order matches are listed in.
    """
    active = [item for item in indicators if item.is_active]
    index: dict[str, list[AssessmentIndicatorInput]] = {}
    for indicator in sorted(active, key=lambda item: (item.value, item.source, str(item.id))):
        address = _normalized_ip(indicator.value) if indicator.indicator_type == "IP" else None
        if address is not None:
            index.setdefault(address, []).append(indicator)
    return index, len(active) - sum(len(items) for items in index.values())


def _matched_address(value: str | None, index: dict[str, list[AssessmentIndicatorInput]]) -> str | None:
    address = _normalized_ip(value)
    return address if address is not None and address in index else None


def summarize_events(data: AssessmentInput) -> AssessmentEventEvidence:
    """Aggregate raw in-window events into buckets and per-class samples (or return pre-aggregated evidence)."""
    if data.event_evidence is not None:
        return data.event_evidence
    index, _ = indicator_address_index(data.threat_indicators)
    counts: Counter[tuple[str, str, str | None, str | None]] = Counter()
    per_class: Counter[tuple[str, bool, bool]] = Counter()
    samples = []
    for event in _window_events(data):
        src, dest = _matched_address(event.src_ip, index), _matched_address(event.dest_ip, index)
        link = event_link_status(event)
        counts[(event.severity, link, src, dest)] += 1
        sample_class = (link, event.severity in HIGH_EVENT_SEVERITIES, src is not None or dest is not None)
        if per_class[sample_class] < SAMPLE_PER_CLASS:
            per_class[sample_class] += 1
            samples.append(event)
    buckets = [
        AssessmentEventBucket(severity=severity, link_status=link, src_ip=src, dest_ip=dest, count=count)
        for (severity, link, src, dest), count in counts.items()
    ]
    buckets.sort(key=lambda b: (-SEVERITY_RANK[b.severity], b.link_status, b.src_ip or "", b.dest_ip or ""))
    return AssessmentEventEvidence(buckets=buckets, samples=samples)


@dataclass(frozen=True)
class _EventView:
    total: int
    buckets: list[AssessmentEventBucket]
    samples: list[AssessmentEventInput]  # most recent first
    index: dict[str, list[AssessmentIndicatorInput]]
    unchecked_indicators: int

    def match_count(self, bucket: AssessmentEventBucket) -> int:
        """Indicator matches per event in the bucket: source-address plus destination-address indicators."""
        return sum(len(self.index.get(address, [])) for address in (bucket.src_ip, bucket.dest_ip) if address)

    def matched_severities(self, bucket: AssessmentEventBucket) -> list[SeverityName]:
        return [item.severity for address in (bucket.src_ip, bucket.dest_ip) if address for item in self.index.get(address, [])]

    def is_matched(self, event: AssessmentEventInput) -> bool:
        return any(_matched_address(value, self.index) for value in (event.src_ip, event.dest_ip))


def _event_view(data: AssessmentInput) -> _EventView:
    evidence = summarize_events(data)
    index, unchecked = indicator_address_index(data.threat_indicators)
    return _EventView(
        total=sum(bucket.count for bucket in evidence.buckets),
        buckets=evidence.buckets,
        samples=sorted(evidence.samples, key=event_order_key, reverse=True),
        index=index,
        unchecked_indicators=unchecked,
    )


def _bucket_total(buckets: Iterable[AssessmentEventBucket]) -> int:
    return sum(bucket.count for bucket in buckets)


def _is_matched_bucket(bucket: AssessmentEventBucket) -> bool:
    return bucket.src_ip is not None or bucket.dest_ip is not None


IndicatorMatch = tuple[AssessmentEventInput, str, str, AssessmentIndicatorInput]
THREAT_INTEL_TITLE = "Events matching active threat indicators"


def _sample_matches(view: _EventView, events: Iterable[AssessmentEventInput]) -> list[IndicatorMatch]:
    """Matches of sampled events: event order, then source before destination IP, then indicator order."""
    matches: list[IndicatorMatch] = []
    for event in events:
        for field, value in (("source IP", event.src_ip), ("destination IP", event.dest_ip)):
            address = _matched_address(value, view.index)
            for indicator in view.index.get(address, []) if address is not None else []:
                matches.append((event, field, address, indicator))
    return matches


# --- Checks -------------------------------------------------------------------------------------


def check_exposure_criticality(data: AssessmentInput) -> AssessmentFinding:
    asset = data.asset
    severity = EXPOSURE_SEVERITY.get((asset.exposure, asset.criticality))
    evidence = [f"{_asset_text(asset)} exposure is {asset.exposure} and criticality is {asset.criticality}."]
    if severity is None:
        evidence.append("This combination is not rated as elevated exposure in assessment-v1.")
    return _finding(
        "exposure_criticality",
        "exposure",
        "Exposure of a business-critical asset",
        severity,
        evidence,
        "Confirm the exposure is required, restrict inbound access to the services the asset must offer "
        "(for example with firewall rules, a reverse proxy or VPN), and prioritise it when patching.",
    )


def check_open_vulnerabilities(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    open_items = _vulnerabilities_with_status(data, "OPEN")
    if not open_items:
        return _finding(
            "open_vulnerabilities",
            "vulnerability",
            "Open vulnerabilities",
            None,
            ["No open vulnerability records are linked to the asset."],
            "",
        )
    severity = _highest(_effective_severity(item) for item in open_items)
    top_labels = [_vulnerability_label(item) for item in open_items if _effective_severity(item) == severity]
    evidence = [
        f"{w.count(len(open_items), 'open vulnerability', 'open vulnerabilities')}; highest effective severity is {severity}.",
        *(_vulnerability_evidence(item) for item in open_items),
    ]
    return _finding(
        "open_vulnerabilities",
        "vulnerability",
        "Open vulnerabilities",
        severity,
        evidence,
        f"Patch or mitigate the open vulnerabilities, starting with {', '.join(top_labels)}, and update "
        "each record's status once remediation is verified.",
        vulnerability_ids=(item.id for item in open_items),
    )


def check_vulnerability_cvss_missing(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    unscored = [item for item in _vulnerabilities_with_status(data, "OPEN") if item.cvss_score is None]
    if not unscored:
        return _finding(
            "vulnerability_cvss_missing",
            "data_quality",
            "Open vulnerabilities without CVSS scores",
            None,
            ["Every open vulnerability has a recorded CVSS score, or none are open."],
            "",
        )
    return _finding(
        "vulnerability_cvss_missing",
        "data_quality",
        "Open vulnerabilities without CVSS scores",
        "INFO",
        [
            f"{w.count(len(unscored), 'open vulnerability', 'open vulnerabilities')} "
            f"{w.word(len(unscored), 'has', 'have')} no CVSS score; {w.word(len(unscored), 'its', 'their')} "
            "recorded severity was used instead.",
            *(_vulnerability_evidence(item) for item in unscored),
        ],
        "Record the CVSS base score from the vendor or NVD advisory so vulnerability severity is compared "
        "on a consistent scale.",
        vulnerability_ids=(item.id for item in unscored),
    )


def check_accepted_risk_exposure(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    accepted = _vulnerabilities_with_status(data, "ACCEPTED")
    exposure = data.asset.exposure
    title = "Accepted-risk vulnerabilities on an exposed asset"
    if not accepted:
        return _finding(
            "accepted_risk_exposure", "vulnerability", title, None,
            ["No vulnerabilities are recorded as accepted risk."], "",
        )
    if exposure == "INTERNAL":
        return _finding(
            "accepted_risk_exposure", "vulnerability", title, None,
            [
                f"{w.count(len(accepted), 'accepted-risk vulnerability', 'accepted-risk vulnerabilities')} "
                f"{w.word(len(accepted), 'is', 'are')} on an INTERNAL asset."
            ], "",
            vulnerability_ids=(item.id for item in accepted),
        )
    highest = _highest(_effective_severity(item) for item in accepted)
    severity: SeverityName = "MEDIUM" if SEVERITY_RANK[highest] >= SEVERITY_RANK["HIGH"] else "LOW"
    return _finding(
        "accepted_risk_exposure",
        "vulnerability",
        title,
        severity,
        [
            f"{w.count(len(accepted), 'accepted-risk vulnerability', 'accepted-risk vulnerabilities')} on a "
            f"{exposure} asset; highest effective severity is {highest}.",
            *(_vulnerability_evidence(item) for item in accepted),
        ],
        f"Re-review the risk acceptance given the asset's {exposure} exposure: record compensating controls "
        "and a review date, or schedule remediation.",
        vulnerability_ids=(item.id for item in accepted),
    )


def _incident_order(incident: AssessmentIncidentInput) -> tuple[int, str, str]:
    return (-SEVERITY_RANK[incident.severity], incident.incident_key, str(incident.id))


def check_active_incidents(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    active = sorted(
        (item for item in data.incidents if item.state not in RESOLVED_INCIDENT_STATES), key=_incident_order
    )
    resolved_count = len(data.incidents) - len(active)
    if not active:
        return _finding(
            "active_incidents",
            "incident",
            "Active incidents on the asset",
            None,
            [
                f"No active incidents; {w.count(resolved_count, 'incident', 'incidents')} "
                f"{w.word(resolved_count, 'is', 'are')} contained or learned."
            ],
            "",
        )
    severity = _highest(item.severity for item in active)
    return _finding(
        "active_incidents",
        "incident",
        "Active incidents on the asset",
        severity,
        [
            f"{w.count(len(active), 'active incident', 'active incidents')} (not contained or learned); "
            f"highest severity is {severity}.",
            *(f"{item.incident_key}: severity {item.severity}, state {item.state}." for item in active),
        ],
        f"Progress the active incidents through verification and containment in the Incidents workflow, "
        f"starting with {active[0].incident_key}.",
        incident_ids=(item.id for item in active),
    )


def _severity_line(event: AssessmentEventInput) -> str:
    return f"{event.event_uid}: severity {event.severity} at {event.occurred_at.isoformat()}."


def _no_high_events_finding(data: AssessmentInput, view: _EventView, w: Wording) -> AssessmentFinding:
    evidence = [
        f"{w.count(view.total, 'event', 'events')} from {_window_text(data)}; "
        f"none {w.word(view.total, 'is', 'are')} HIGH or CRITICAL."
    ]
    if not view.total:
        evidence.append("Absence of events is not evidence that the asset is safe.")
    return _finding("recent_high_severity_events", "detection", "Recent high-severity security events", None, evidence, "")


def _high_share_line(data: AssessmentInput, high_total: int, total: int, w: Wording) -> str:
    return (
        f"{high_total} of {w.count(total, 'event', 'events')} from {_window_text(data)} "
        f"{w.word(high_total, 'is', 'are')} HIGH or CRITICAL."
    )


def check_recent_high_severity_events(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    view = _event_view(data)
    high_buckets = [bucket for bucket in view.buckets if bucket.severity in HIGH_EVENT_SEVERITIES]
    high_total = _bucket_total(high_buckets)
    if not high_total:
        return _no_high_events_finding(data, view, w)
    high = [event for event in view.samples if event.severity in HIGH_EVENT_SEVERITIES]
    # Event severity is a detector signal, not confirmed compromise, so the rating is one level lower.
    severity: SeverityName = "HIGH" if any(bucket.severity == "CRITICAL" for bucket in high_buckets) else "MEDIUM"
    return _finding(
        "recent_high_severity_events",
        "detection",
        "Recent high-severity security events",
        severity,
        [
            _high_share_line(data, high_total, view.total, w),
            "Event severity is a detector signal, not confirmed compromise; the finding is rated one level "
            "below the highest event severity.",
            *_listed_events(high, _severity_line, high_total, w),
        ],
        "Review these events in Security Events and correlate them into an incident if they are not "
        "already linked to one.",
        event_ids=(event.id for event in high),
        event_total=high_total,
    )


def _no_indicator_match_finding(data: AssessmentInput, view: _EventView, w: Wording) -> AssessmentFinding:
    if data.active_ip_indicator_total is None:
        indicators = f"{w.count(len(view.index), 'active IP indicator', 'active IP indicators')} supplied"
    else:
        indicators = f"{w.count(data.active_ip_indicator_total, 'active IP indicator', 'active IP indicators')} checked"
    evidence = [
        f"No source or destination IP of the {w.count(view.total, 'event', 'events')} from {_window_text(data)} "
        f"matches an active IP indicator ({indicators})."
    ]
    if view.unchecked_indicators:
        unchecked = view.unchecked_indicators
        evidence.append(
            f"{w.count(unchecked, 'active non-IP indicator', 'active non-IP indicators')} "
            f"{w.word(unchecked, 'was', 'were')} not compared; event records hold IP addresses only."
        )
    return _finding("threat_intel_matches", "threat_intelligence", THREAT_INTEL_TITLE, None, evidence, "")


def _match_line(match: IndicatorMatch) -> str:
    event, field, address, indicator = match
    confidence = f"{indicator.confidence:g}" if indicator.confidence is not None else "not recorded"
    return (
        f"{event.event_uid}: {field} {address} matches active IP indicator from {indicator.source} "
        f"(severity {indicator.severity}, confidence {confidence})."
    )


def _listed_matches(
    matches: list[IndicatorMatch], total: int, describe: Callable[[IndicatorMatch], str], w: Wording
) -> list[str]:
    lines = [describe(match) for match in matches[:MAX_LISTED_EVENTS]]
    if total > MAX_LISTED_EVENTS:
        more = total - MAX_LISTED_EVENTS
        lines.append(f"{w.count(more, 'more match', 'more matches')} {w.word(more, 'is', 'are')} not listed.")
    return lines


def _match_total_line(data: AssessmentInput, match_total: int, w: Wording) -> str:
    return f"{w.count(match_total, 'indicator match', 'indicator matches')} across events from {_window_text(data)}."


def check_threat_intel_matches(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    view = _event_view(data)
    matched_buckets = [bucket for bucket in view.buckets if _is_matched_bucket(bucket)]
    match_total = sum(bucket.count * view.match_count(bucket) for bucket in matched_buckets)
    if not match_total:
        return _no_indicator_match_finding(data, view, w)

    severity = _highest(severity for bucket in matched_buckets for severity in view.matched_severities(bucket))
    matched_events = [event for event in view.samples if view.is_matched(event)]
    evidence = [
        _match_total_line(data, match_total, w),
        *_listed_matches(_sample_matches(view, matched_events), match_total, _match_line, w),
    ]
    return _finding(
        "threat_intel_matches",
        "threat_intelligence",
        THREAT_INTEL_TITLE,
        severity,
        evidence,
        "Investigate traffic between the asset and the matched indicator addresses, confirm whether it is "
        "expected, and use the authorized containment workflow if blocking is needed.",
        event_ids=(event.id for event in matched_events),
        event_total=_bucket_total(matched_buckets),
    )


def check_inventory_completeness(data: AssessmentInput) -> AssessmentFinding:
    asset = data.asset
    gaps = []
    if not (asset.owner and asset.owner.strip()):
        gaps.append("No owner is recorded.")
    if not (asset.hostname and asset.hostname.strip()) and not asset.ip_address:
        gaps.append("Neither a hostname nor an IP address is recorded.")
    title = "Inventory completeness"
    if not gaps:
        return _finding(
            "inventory_completeness", "inventory", title, None,
            [f"{_asset_text(asset)} has a recorded owner and at least one network identifier."], "",
        )
    return _finding(
        "inventory_completeness",
        "inventory",
        title,
        "LOW",
        gaps,
        "Record an accountable owner and at least one network identifier so findings and incidents can be "
        "routed and matched to the asset.",
    )


def check_inactive_asset_activity(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> AssessmentFinding:
    asset = data.asset
    title = "Activity on an inactive or decommissioned asset"
    if asset.status not in INACTIVE_ASSET_STATUSES:
        return _finding(
            "inactive_asset_activity", "inventory", title, None, [f"Asset status is {asset.status}."], ""
        )
    view = _event_view(data)
    if not view.total:
        return _finding(
            "inactive_asset_activity", "inventory", title, None,
            [f"Asset status is {asset.status} and no events were recorded from {_window_text(data)}."], "",
        )
    return _finding(
        "inactive_asset_activity",
        "inventory",
        title,
        "MEDIUM",
        [
            f"Asset status is {asset.status}, but {w.count(view.total, 'event', 'events')} "
            f"{w.word(view.total, 'was', 'were')} recorded from {_window_text(data)}.",
            *_listed_events(view.samples, _severity_line, view.total, w),
        ],
        "Confirm whether the asset is still running: correct its status if it is, otherwise investigate the "
        "source of the activity attributed to it.",
        event_ids=(event.id for event in view.samples),
        event_total=view.total,
    )


# --- assessment-v2 event attribution ------------------------------------------------------------


def _linked_incident_text(event: AssessmentEventInput) -> str:
    links = sorted(event.linked_incidents, key=lambda item: (item.incident_key, str(item.id)))
    return ", ".join(f"{item.incident_key} ({item.state})" for item in links)


def _event_line(event: AssessmentEventInput) -> str:
    line = f"{event.event_uid}: severity {event.severity} at {event.occurred_at.isoformat()}"
    return f"{line}; linked to {_linked_incident_text(event)}." if event.linked_incidents else f"{line}."


def _event_group(events: list[AssessmentEventInput], total: int, heading: str, w: Wording) -> list[str]:
    return [heading, *_listed_events(events, _event_line, total, w)] if total else []


def check_recent_high_severity_events_v2(data: AssessmentInput, w: Wording = AGREEING_WORDING) -> AssessmentFinding:
    view = _event_view(data)
    high_buckets = [bucket for bucket in view.buckets if bucket.severity in HIGH_EVENT_SEVERITIES]
    high_total = _bucket_total(high_buckets)
    if not high_total:
        return _no_high_events_finding(data, view, w)

    def group(link: str, matched: bool | None = None) -> tuple[list[AssessmentEventBucket], list[AssessmentEventInput]]:
        buckets = [
            bucket for bucket in high_buckets
            if bucket.link_status == link and (matched is None or _is_matched_bucket(bucket) == matched)
        ]
        events = [
            event for event in view.samples
            if event.severity in HIGH_EVENT_SEVERITIES and event_link_status(event) == link
            and (matched is None or view.is_matched(event) == matched)
        ]
        return buckets, events

    scored_buckets, scored = group(LINK_UNLINKED, matched=False)
    to_threat_intel_buckets, to_threat_intel = group(LINK_UNLINKED, matched=True)
    covered_buckets, covered = group(LINK_ACTIVE)
    resolved_buckets, resolved = group(LINK_RESOLVED)
    scored_total, to_threat_intel_total = _bucket_total(scored_buckets), _bucket_total(to_threat_intel_buckets)
    covered_total, resolved_total = _bucket_total(covered_buckets), _bucket_total(resolved_buckets)

    if scored_total:
        # Event severity is a detector signal, not confirmed compromise, so the rating is one level lower.
        severity: SeverityName = "HIGH" if any(bucket.severity == "CRITICAL" for bucket in scored_buckets) else "MEDIUM"
    else:
        severity = "INFO"
    evidence = [
        _high_share_line(data, high_total, view.total, w),
        "assessment-v2 deducts each event once: events linked to an active incident are covered by that "
        "incident, events linked only to contained or learned incidents are not treated as unresolved, and "
        "unlinked events matching an active indicator are scored under threat-indicator matches.",
        *_event_group(
            scored, scored_total,
            f"{w.count(scored_total, 'unlinked event', 'unlinked events')} {w.word(scored_total, 'is', 'are')} "
            f"scored here, one level below the highest of {w.word(scored_total, 'its', 'their')} "
            f"{w.word(scored_total, 'severity', 'severities')}:",
            w,
        ),
        *_event_group(
            covered, covered_total,
            f"{w.count(covered_total, 'event', 'events')} {w.word(covered_total, 'is', 'are')} linked to an active "
            "incident and not deducted here:",
            w,
        ),
        *_event_group(
            resolved, resolved_total,
            f"{w.count(resolved_total, 'event', 'events')} {w.word(resolved_total, 'is', 'are')} linked only to "
            "contained or learned incidents and not deducted:",
            w,
        ),
        *_event_group(
            to_threat_intel, to_threat_intel_total,
            f"{w.count(to_threat_intel_total, 'unlinked event', 'unlinked events')} "
            f"{w.word(to_threat_intel_total, 'matches', 'match')} an active indicator and "
            f"{w.word(to_threat_intel_total, 'is', 'are')} scored under threat-indicator matches:",
            w,
        ),
    ]
    actions = []
    if scored_total:
        actions.append(
            f"Review the {w.count(scored_total, 'unlinked high-severity event', 'unlinked high-severity events')} "
            f"in Security Events and correlate {w.word(scored_total, 'it', 'them')} into an incident."
        )
    if covered_total:
        actions.append("Handle events already linked to active incidents through those incidents.")
    if resolved_total:
        actions.append("Events linked only to contained or learned incidents need no further correlation.")
    if to_threat_intel_total:
        actions.append(
            f"Correlate the {w.count(to_threat_intel_total, 'unlinked event', 'unlinked events')} matching threat "
            f"indicators into an incident; {w.word(to_threat_intel_total, 'it is', 'they are')} scored under "
            "threat-indicator matches."
        )
    high = [event for event in view.samples if event.severity in HIGH_EVENT_SEVERITIES]
    return _finding(
        "recent_high_severity_events",
        "detection",
        "Recent high-severity security events",
        severity,
        evidence,
        " ".join(actions),
        event_ids=(event.id for event in high),
        event_total=high_total,
    )


def check_threat_intel_matches_v2(data: AssessmentInput, w: Wording = AGREEING_WORDING) -> AssessmentFinding:
    view = _event_view(data)
    matched_buckets = [bucket for bucket in view.buckets if _is_matched_bucket(bucket)]
    match_totals = {
        link: sum(bucket.count * view.match_count(bucket) for bucket in matched_buckets if bucket.link_status == link)
        for link in (LINK_UNLINKED, LINK_ACTIVE, LINK_RESOLVED)
    }
    match_total = sum(match_totals.values())
    if not match_total:
        return _no_indicator_match_finding(data, view, w)

    scored_severities = [
        severity
        for bucket in matched_buckets if bucket.link_status == LINK_UNLINKED
        for severity in view.matched_severities(bucket)
    ]
    severity: SeverityName = _highest(scored_severities) if scored_severities else "INFO"
    matched_events = [event for event in view.samples if view.is_matched(event)]

    evidence = [
        _match_total_line(data, match_total, w),
        "assessment-v2 deducts each event once: only matches on unlinked events are scored here.",
    ]
    for link, heading, linked in (
        (LINK_UNLINKED, "on unlinked events {} scored here:", False),
        (LINK_ACTIVE, "{} on events linked to an active incident and not deducted here:", True),
        (LINK_RESOLVED, "{} on events linked only to contained or learned incidents and not deducted:", True),
    ):
        total = match_totals[link]
        if not total:
            continue
        evidence.append(f"{w.count(total, 'match', 'matches')} {heading.format(w.word(total, 'is', 'are'))}")
        matches = _sample_matches(view, (event for event in matched_events if event_link_status(event) == link))
        evidence.extend(_listed_matches(
            matches,
            total,
            (lambda match: f"{_match_line(match)[:-1]}; event linked to {_linked_incident_text(match[0])}.")
            if linked else _match_line,
            w,
        ))

    actions = []
    if match_totals[LINK_UNLINKED]:
        actions.append(
            "Investigate traffic between the asset and the matched indicator addresses on unlinked events, confirm "
            "whether it is expected, and use the authorized containment workflow if blocking is needed."
        )
    if match_totals[LINK_ACTIVE]:
        actions.append("Matches on events linked to active incidents are handled through those incidents.")
    if match_totals[LINK_RESOLVED]:
        actions.append("Matches on events linked only to contained or learned incidents need no further action.")
    return _finding(
        "threat_intel_matches",
        "threat_intelligence",
        THREAT_INTEL_TITLE,
        severity,
        evidence,
        " ".join(actions),
        event_ids=(event.id for event in matched_events),
        event_total=_bucket_total(matched_buckets),
    )


def check_exposure_criticality_v2(data: AssessmentInput) -> AssessmentFinding:
    """Same rule as v1; only the methodology named in the evidence differs."""
    finding = check_exposure_criticality(data)
    evidence = [line.replace("in assessment-v1.", "in assessment-v2.") for line in finding.evidence]
    return finding.model_copy(update={"evidence": evidence})


Check = Callable[[AssessmentInput], AssessmentFinding]

# Order is part of each methodology: findings are always reported in this sequence.
CHECKS_V1: tuple[Check, ...] = (
    check_exposure_criticality,
    check_open_vulnerabilities,
    check_vulnerability_cvss_missing,
    check_accepted_risk_exposure,
    check_active_incidents,
    check_recent_high_severity_events,
    check_threat_intel_matches,
    check_inventory_completeness,
    check_inactive_asset_activity,
)
# Same checks, keys and order as v1; event attribution in checks 6 and 7 differs, and evidence wording
# agrees with its counts.
CHECKS_V2: tuple[Check, ...] = (
    check_exposure_criticality_v2,
    partial(check_open_vulnerabilities, w=AGREEING_WORDING),
    partial(check_vulnerability_cvss_missing, w=AGREEING_WORDING),
    partial(check_accepted_risk_exposure, w=AGREEING_WORDING),
    partial(check_active_incidents, w=AGREEING_WORDING),
    check_recent_high_severity_events_v2,
    check_threat_intel_matches_v2,
    check_inventory_completeness,
    partial(check_inactive_asset_activity, w=AGREEING_WORDING),
)
METHODOLOGIES: dict[str, tuple[Check, ...]] = {METHODOLOGY_V1: CHECKS_V1, METHODOLOGY_V2: CHECKS_V2}
WORDING: dict[str, Wording] = {METHODOLOGY_V1: LEGACY_WORDING, METHODOLOGY_V2: AGREEING_WORDING}


def _missing_evidence(data: AssessmentInput, w: Wording = LEGACY_WORDING) -> list[str]:
    missing = []
    unscored = sum(1 for item in data.vulnerabilities if item.status == "OPEN" and item.cvss_score is None)
    if unscored:
        missing.append(
            f"CVSS is not recorded for {w.count(unscored, 'open vulnerability', 'open vulnerabilities')}; "
            "recorded severity was used."
        )
    if not _bucket_total(summarize_events(data).buckets):
        missing.append("No security events were recorded for the asset in the 7-day window.")
    if data.active_ip_indicator_total is None:
        no_indicators = not any(item.is_active and item.indicator_type == "IP" for item in data.threat_indicators)
    else:
        no_indicators = data.active_ip_indicator_total == 0
    if no_indicators:
        missing.append("No active IP threat indicators were supplied, so no indicator match was possible.")
    return missing


def assess_asset(data: AssessmentInput, methodology: str = METHODOLOGY_VERSION) -> AssessmentResult:
    checks = METHODOLOGIES.get(methodology)
    if checks is None:
        raise ValueError(f"Unknown assessment methodology: {methodology}")
    # Aggregate raw events once; every check then reads the same buckets and samples.
    if data.event_evidence is None:
        data = data.model_copy(update={"events": [], "event_evidence": summarize_events(data)})
    findings = [check(data) for check in checks]
    score = max(0, MAX_SCORE - sum(finding.deduction for finding in findings))
    grade = grade_for_score(score)
    counts = {result: sum(1 for finding in findings if finding.result == result) for result in ("PASS", "WARN", "FAIL", "INFO")}
    w = WORDING[methodology]
    summary = (
        f"Grade {grade} ({score}/100) under {methodology}: {counts['FAIL']} failed, "
        f"{w.count(counts['WARN'], 'warning', 'warnings')}, {counts['INFO']} informational and "
        f"{counts['PASS']} passed {w.word(counts['PASS'], 'check', 'checks')}."
    )
    return AssessmentResult(
        methodology_version=methodology,
        asset_id=data.asset.id,
        asset_key=data.asset.asset_key,
        as_of=data.as_of,
        score=score,
        grade=grade,
        summary=summary,
        passed=counts["PASS"],
        warnings=counts["WARN"],
        failed=counts["FAIL"],
        informational=counts["INFO"],
        findings=findings,
        missing_evidence=_missing_evidence(data, w),
    )
