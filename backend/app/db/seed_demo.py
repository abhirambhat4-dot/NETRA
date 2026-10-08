"""NETRA demonstration dataset: small, fictional, deterministic and idempotent.

Dry run (read-only, the default):  python -m app.db.seed_demo
Write missing demo data:           python -m app.db.seed_demo --apply

Every record is marked as NETRA DEMO data and uses reserved documentation networks
(203.0.113.0/24, 198.51.100.0/24), private 10.250.0.0/16 addresses and *.netra-demo.example
hostnames. Existing records are reused, never updated or deleted; conflicting records are
reported and stop the run before anything is written. Incidents are advanced only through
the existing workflow services, and only forward towards each scenario's target.
"""

import argparse
import ipaddress
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Literal

from fastapi import HTTPException
from sqlalchemy import inspect, select, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.enums import (
    AssetEnvironment,
    AssetType,
    AuthorizationStatus,
    ContainmentStatus,
    Criticality,
    DetectionSource,
    Exposure,
    IncidentState,
    IndicatorType,
    ResponseAction,
    Severity,
)
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent, IncidentHistory
from app.models.threat_indicator import ThreatIndicator
from app.models.vulnerability import Vulnerability
from app.services.context_enrichment import enrich_incident_context
from app.services.controlled_response import (
    create_incident_cyber_memory,
    simulate_authorized_containment,
    verify_containment,
)
from app.services.decision_workflow import (
    approve_decision_authorization,
    recommend_incident_decision,
    request_decision_authorization,
    verify_incident,
)
from app.services.event_correlation import correlate_incident_events
from app.services.intake import create_event, link_event_to_incident
from app.services.risk_engine import calculate_incident_risk

DATASET = "netra-demo-v1"
DEMO_MARKER: dict[str, Any] = {"netra_demo": True, "dataset": DATASET}
EVENT_UID_PREFIX = "netra-demo-"
TITLE_PREFIX = "[NETRA DEMO]"
INDICATOR_SOURCE = "NETRA Demo Feed"
OWNER = "NETRA Demo Team"
ACTOR = "netra-demo-seed"

REQUIRED_TABLES = (
    "assets",
    "vulnerabilities",
    "threat_indicators",
    "security_events",
    "incidents",
    "incident_events",
    "incident_history",
    "decisions",
    "authorizations",
    "containment_actions",
    "cyber_memories",
)
LOCAL_HOSTS = {"", "localhost", "127.0.0.1", "::1"}

EXIT_OK = 0
EXIT_WORKFLOW_ERROR = 1
EXIT_BLOCKED = 2


# ---------------------------------------------------------------------------
# Dataset


@dataclass(frozen=True)
class AssetSpec:
    key: str
    name: str
    hostname: str
    ip_address: str
    asset_type: AssetType
    criticality: Criticality
    exposure: Exposure
    environment: AssetEnvironment = AssetEnvironment.PRODUCTION


@dataclass(frozen=True)
class VulnerabilitySpec:
    asset_key: str
    cve_id: str
    title: str
    description: str
    cvss_score: Decimal
    severity: Severity


@dataclass(frozen=True)
class IndicatorSpec:
    indicator_type: IndicatorType
    value: str
    confidence: float
    severity: Severity


@dataclass(frozen=True)
class EventSpec:
    uid: str
    offset_minutes: int
    event_type: str
    signature: str
    severity: Severity
    src_ip: str
    dest_ip: str
    src_port: int | None
    dest_port: int | None
    protocol: str = "TCP"
    extra_raw: dict[str, Any] = field(default_factory=dict)


Target = Literal["learned", "authorization_pending", "decision"]


@dataclass(frozen=True)
class ScenarioSpec:
    incident_key: str
    title: str
    description: str
    asset_key: str
    severity: Severity
    source: DetectionSource
    minutes_before_now: int
    events: tuple[EventSpec, ...]
    target: Target
    expected_action: ResponseAction


ASSETS = (
    AssetSpec("DEMO-DB-01", "Customer DB", "db-01.netra-demo.example", "10.250.20.20",
              AssetType.DATABASE, Criticality.CRITICAL, Exposure.INTERNAL),
    AssetSpec("DEMO-WEB-01", "Public portal", "portal.netra-demo.example", "10.250.10.10",
              AssetType.APPLICATION, Criticality.HIGH, Exposure.INTERNET_FACING),
    AssetSpec("DEMO-WS-07", "Analyst workstation", "ws-07.netra-demo.example", "10.250.30.7",
              AssetType.WORKSTATION, Criticality.MEDIUM, Exposure.INTERNAL),
)

VULNERABILITIES = (
    VulnerabilitySpec("DEMO-DB-01", "DEMO-CVE-2026-0001",
                      f"{TITLE_PREFIX} Pre-auth code execution in database admin console",
                      "Fictional vulnerability for the NETRA demonstration dataset.",
                      Decimal("9.8"), Severity.CRITICAL),
    VulnerabilitySpec("DEMO-WEB-01", "DEMO-CVE-2026-0002",
                      f"{TITLE_PREFIX} Authentication bypass in portal admin plugin",
                      "Fictional vulnerability for the NETRA demonstration dataset.",
                      Decimal("7.5"), Severity.HIGH),
    VulnerabilitySpec("DEMO-WS-07", "DEMO-CVE-2026-0003",
                      f"{TITLE_PREFIX} Outdated browser extension sandbox weakness",
                      "Fictional vulnerability for the NETRA demonstration dataset.",
                      Decimal("5.4"), Severity.MEDIUM),
)

INDICATORS = (
    IndicatorSpec(IndicatorType.IP, "203.0.113.45", 0.95, Severity.HIGH),
    IndicatorSpec(IndicatorType.IP, "198.51.100.77", 0.85, Severity.HIGH),
    IndicatorSpec(IndicatorType.DOMAIN, "c2.netra-demo.example", 0.90, Severity.CRITICAL),
)

SCENARIOS = (
    # Full lifecycle: correlation pulls in events A2-A4, risk lands above 75 -> ISOLATE_HOST.
    ScenarioSpec(
        incident_key="INC-DEMO-0001",
        title=f"{TITLE_PREFIX} Intrusion chain against customer database",
        description="Fictional NETRA demonstration incident: scan, SSH brute force and outbound beacon on DEMO-DB-01.",
        asset_key="DEMO-DB-01",
        severity=Severity.HIGH,
        source=DetectionSource.THREAT_INTEL,
        minutes_before_now=120,
        target="learned",
        expected_action=ResponseAction.ISOLATE_HOST,
        events=(
            EventSpec("netra-demo-a1-port-scan", 0, "port_scan",
                      "NETRA DEMO TCP port scan from listed address", Severity.MEDIUM,
                      "203.0.113.45", "10.250.20.20", 44321, None),
            EventSpec("netra-demo-a2-ssh-brute-force", 6, "ssh_brute_force",
                      "NETRA DEMO repeated SSH authentication failures", Severity.HIGH,
                      "203.0.113.45", "10.250.20.20", 44388, 22),
            EventSpec("netra-demo-a3-ssh-brute-force", 11, "ssh_brute_force",
                      "NETRA DEMO SSH brute force threshold exceeded", Severity.HIGH,
                      "203.0.113.45", "10.250.20.20", 44410, 22),
            EventSpec("netra-demo-a4-outbound-beacon", 18, "outbound_beacon",
                      "NETRA DEMO outbound beacon to listed command-and-control domain", Severity.CRITICAL,
                      "10.250.20.20", "203.0.113.45", 49822, 443,
                      extra_raw={"dns_query": "c2.netra-demo.example"}),
        ),
    ),
    # Live UI demo: seeded to VERIFIED with a PENDING authorization for BLOCK_IP.
    ScenarioSpec(
        incident_key="INC-DEMO-0002",
        title=f"{TITLE_PREFIX} Credential attack on public portal",
        description="Fictional NETRA demonstration incident: scan and admin login attacks on DEMO-WEB-01.",
        asset_key="DEMO-WEB-01",
        severity=Severity.HIGH,
        source=DetectionSource.THREAT_INTEL,
        minutes_before_now=80,
        target="authorization_pending",
        expected_action=ResponseAction.BLOCK_IP,
        events=(
            EventSpec("netra-demo-b1-web-scan", 0, "web_scan",
                      "NETRA DEMO web vulnerability scan against public portal", Severity.MEDIUM,
                      "198.51.100.77", "10.250.10.10", 51022, 443),
            EventSpec("netra-demo-b2-admin-login", 5, "admin_login_failure",
                      "NETRA DEMO repeated admin login failures", Severity.HIGH,
                      "198.51.100.77", "10.250.10.10", 51088, 443),
            EventSpec("netra-demo-b3-admin-login", 9, "admin_login_failure",
                      "NETRA DEMO credential stuffing pattern on admin login", Severity.HIGH,
                      "198.51.100.77", "10.250.10.10", 51140, 443),
        ),
    ),
    # Contrast: operator reports with no threat-intelligence match stay at PRIORITISED -> INVESTIGATE.
    ScenarioSpec(
        incident_key="INC-DEMO-0003",
        title=f"{TITLE_PREFIX} User-reported suspicious login prompt",
        description="Fictional NETRA demonstration incident: two manual reports from DEMO-WS-07.",
        asset_key="DEMO-WS-07",
        severity=Severity.LOW,
        source=DetectionSource.MANUAL,
        minutes_before_now=50,
        target="decision",
        expected_action=ResponseAction.INVESTIGATE,
        events=(
            EventSpec("netra-demo-c1-login-prompt", 0, "suspicious_login",
                      "NETRA DEMO analyst reported unexpected login prompt", Severity.LOW,
                      "10.250.30.7", "10.250.40.40", 50211, 443),
            EventSpec("netra-demo-c2-login-prompt", 8, "suspicious_login",
                      "NETRA DEMO second report of unexpected login prompt", Severity.LOW,
                      "10.250.30.7", "10.250.40.40", 50234, 443),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Reporting


@dataclass
class Report:
    out: Callable[[str], None]
    created: Counter[str] = field(default_factory=Counter)
    reused: Counter[str] = field(default_factory=Counter)
    planned: Counter[str] = field(default_factory=Counter)
    transitions: int = 0
    conflicts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def line(self, message: str) -> None:
        self.out(message)

    def conflict(self, message: str) -> None:
        self.conflicts.append(message)
        self.out(f"  CONFLICT  {message}")

    def error(self, message: str) -> None:
        self.errors.append(message)
        self.out(f"  ERROR     {message}")


def describe_target(url: URL) -> str:
    """Local or remote classification only: never includes credentials, host or database name."""
    if url.get_backend_name() != "postgresql":
        return f"{url.get_backend_name()} database"
    host = (url.host or "").lower()
    if host in LOCAL_HOSTS:
        return "local PostgreSQL"
    if host.endswith(".neon.tech"):
        return "remote PostgreSQL (*.neon.tech)"
    return "remote PostgreSQL (non-local host)"


# ---------------------------------------------------------------------------
# Comparison helpers


def _normalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, float):
        return round(value, 4)
    return value


def _ip(value: Any) -> str | None:
    return None if value is None else str(ipaddress.ip_address(str(value)))


def _differences(record: Any, expected: dict[str, Any], ip_fields: tuple[str, ...] = ()) -> list[str]:
    differences = []
    for name, value in expected.items():
        actual = getattr(record, name)
        if name in ip_fields:
            actual, value = _ip(actual), _ip(value)
        if _normalize(actual) != _normalize(value):
            differences.append(name)
    return differences


def _has_demo_marker(event: SecurityEvent) -> bool:
    raw = event.raw_data or {}
    return event.event_uid.startswith(EVENT_UID_PREFIX) and all(raw.get(k) == v for k, v in DEMO_MARKER.items())


# ---------------------------------------------------------------------------
# Lookups


def _asset(session: Session, key: str) -> Asset | None:
    return session.scalar(select(Asset).where(Asset.asset_key == key))


def _vulnerability(session: Session, asset: Asset, cve_id: str) -> Vulnerability | None:
    return session.scalar(
        select(Vulnerability).where(Vulnerability.asset_id == asset.id, Vulnerability.cve_id == cve_id)
    )


def _indicator(session: Session, spec: IndicatorSpec) -> ThreatIndicator | None:
    return session.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.indicator_type == spec.indicator_type,
            ThreatIndicator.value == spec.value,
            ThreatIndicator.source == INDICATOR_SOURCE,
        )
    )


def _event(session: Session, uid: str) -> SecurityEvent | None:
    return session.scalar(select(SecurityEvent).where(SecurityEvent.event_uid == uid))


def _incident(session: Session, key: str) -> Incident | None:
    return session.scalar(select(Incident).where(Incident.incident_key == key))


def _asset_fields(spec: AssetSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "hostname": spec.hostname,
        "ip_address": spec.ip_address,
        "asset_type": spec.asset_type,
        "environment": spec.environment,
        "criticality": spec.criticality,
        "exposure": spec.exposure,
        "owner": OWNER,
    }


def _vulnerability_fields(spec: VulnerabilitySpec) -> dict[str, Any]:
    return {"title": spec.title, "cvss_score": spec.cvss_score, "severity": spec.severity}


def _indicator_fields(spec: IndicatorSpec) -> dict[str, Any]:
    return {"confidence": spec.confidence, "severity": spec.severity, "is_active": True}


def _event_fields(spec: EventSpec, scenario: ScenarioSpec, asset: Asset | None) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "source": scenario.source,
        "event_type": spec.event_type,
        "src_ip": spec.src_ip,
        "dest_ip": spec.dest_ip,
    }
    if asset is not None:
        fields["asset_id"] = asset.id
    return fields


# ---------------------------------------------------------------------------
# Plan (read-only)


def missing_tables(session: Session) -> list[str]:
    connection = session.connection()
    schema = (connection.get_execution_options().get("schema_translate_map") or {}).get(None)
    existing = set(inspect(connection).get_table_names(schema=schema))
    return [table for table in REQUIRED_TABLES if table not in existing]


def _plan(session: Session, report: Report) -> None:
    """Classify every demo record as reused, planned or conflicting without writing anything."""
    report.line("Base records")
    assets: dict[str, Asset | None] = {}
    for spec in ASSETS:
        asset = assets[spec.key] = _asset(session, spec.key)
        _classify(report, "asset", spec.key, asset, _asset_fields(spec), ("ip_address",))
        if asset is not None:
            foreign = session.scalar(
                select(SecurityEvent.id).where(
                    SecurityEvent.asset_id == asset.id, SecurityEvent.event_uid.not_like(f"{EVENT_UID_PREFIX}%")
                ).limit(1)
            )
            if foreign is not None:
                report.conflict(f"asset {spec.key}: has non-demo events attached; correlation could include them")

    for spec in VULNERABILITIES:
        asset = assets[spec.asset_key]
        record = _vulnerability(session, asset, spec.cve_id) if asset is not None else None
        _classify(report, "vulnerability", spec.cve_id, record, _vulnerability_fields(spec))

    for spec in INDICATORS:
        _classify(report, "threat indicator", spec.value, _indicator(session, spec), _indicator_fields(spec))

    report.line("Events and incidents")
    for scenario in SCENARIOS:
        asset = assets[scenario.asset_key]
        for spec in scenario.events:
            event = _event(session, spec.uid)
            _classify(report, "event", spec.uid, event, _event_fields(spec, scenario, asset), ("src_ip", "dest_ip"))
            if event is not None and not _has_demo_marker(event):
                report.conflict(f"event {spec.uid}: raw_data lacks the NETRA demo marker")

        incident = _incident(session, scenario.incident_key)
        expected = {"title": scenario.title}
        if asset is not None:
            expected["asset_id"] = asset.id
        _classify(report, "incident", scenario.incident_key, incident, expected)
        if incident is not None:
            linked = session.scalars(
                select(SecurityEvent.event_uid)
                .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
                .where(IncidentEvent.incident_id == incident.id)
            ).all()
            if any(not uid.startswith(EVENT_UID_PREFIX) for uid in linked):
                report.conflict(f"incident {scenario.incident_key}: non-demo events are linked")


def _classify(
    report: Report,
    kind: str,
    label: str,
    record: Any,
    expected: dict[str, Any],
    ip_fields: tuple[str, ...] = (),
) -> None:
    if record is None:
        report.planned[kind] += 1
        report.line(f"  create    {kind} {label}")
        return
    differences = _differences(record, expected, ip_fields)
    if differences:
        report.conflict(f"{kind} {label}: existing values differ ({', '.join(differences)}); left unchanged")
    else:
        report.reused[kind] += 1
        report.line(f"  reuse     {kind} {label}")


# ---------------------------------------------------------------------------
# Apply: base records


def _create_base_records(session: Session, report: Report) -> dict[str, Asset]:
    assets: dict[str, Asset] = {}
    for spec in ASSETS:
        asset = _asset(session, spec.key)
        if asset is None:
            asset = Asset(asset_key=spec.key, **_asset_fields(spec))
            session.add(asset)
            report.created["asset"] += 1
        assets[spec.key] = asset
    session.flush()

    for spec in VULNERABILITIES:
        asset = assets[spec.asset_key]
        if _vulnerability(session, asset, spec.cve_id) is None:
            session.add(Vulnerability(asset_id=asset.id, cve_id=spec.cve_id, description=spec.description,
                                      **_vulnerability_fields(spec)))
            report.created["vulnerability"] += 1

    for spec in INDICATORS:
        if _indicator(session, spec) is None:
            session.add(ThreatIndicator(indicator_type=spec.indicator_type, value=spec.value,
                                        source=INDICATOR_SOURCE, **_indicator_fields(spec)))
            report.created["threat indicator"] += 1
    session.commit()
    return assets


def _ensure_events(session: Session, scenario: ScenarioSpec, asset: Asset, report: Report) -> list[SecurityEvent]:
    existing = {spec.uid: _event(session, spec.uid) for spec in scenario.events}
    # Keep a partially created scenario on one timeline so correlation windows still hold.
    anchor = next(
        (
            event.occurred_at - timedelta(minutes=spec.offset_minutes)
            for spec in scenario.events
            if (event := existing[spec.uid]) is not None
        ),
        datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=scenario.minutes_before_now),
    )
    events = []
    for spec in scenario.events:
        event = existing[spec.uid]
        if event is None:
            # The same intake service that backs POST /api/events/ingest.
            event = create_event(
                session,
                {
                    "event_uid": spec.uid,
                    "occurred_at": anchor + timedelta(minutes=spec.offset_minutes),
                    "source": scenario.source.name,
                    "event_type": spec.event_type,
                    "signature": spec.signature,
                    "severity": spec.severity.name,
                    "src_ip": spec.src_ip,
                    "dest_ip": spec.dest_ip,
                    "src_port": spec.src_port,
                    "dest_port": spec.dest_port,
                    "protocol": spec.protocol,
                    "asset_id": asset.id,
                    "raw_data": {**DEMO_MARKER, "scenario": scenario.incident_key, **spec.extra_raw},
                },
            )
            report.created["event"] += 1
        events.append(event)
    return events


def _ensure_incident(
    session: Session, scenario: ScenarioSpec, asset: Asset, first_event: SecurityEvent, report: Report
) -> Incident:
    incident = _incident(session, scenario.incident_key)
    if incident is not None:
        return incident
    # Mirrors app.services.intake.create_incident, which only generates random keys.
    incident = Incident(
        incident_key=scenario.incident_key,
        title=scenario.title,
        description=scenario.description,
        severity=scenario.severity,
        risk_score=None,
        state=IncidentState.DETECTED,
        detection_source=scenario.source,
        recommended_action=None,
        asset_id=asset.id,
    )
    session.add(incident)
    session.flush()
    session.add(
        IncidentHistory(
            incident_id=incident.id,
            from_state=None,
            to_state=IncidentState.DETECTED,
            action="incident_created",
            actor=ACTOR,
            details={"title": scenario.title, "dataset": DATASET},
        )
    )
    # Only the first event is linked; correlation must discover the rest.
    link_event_to_incident(session, incident.id, first_event.id, commit=False)
    session.commit()
    report.created["incident"] += 1
    return incident


# ---------------------------------------------------------------------------
# Apply: workflow


@dataclass
class Snapshot:
    state: IncidentState
    enriched: bool
    decision: Decision | None
    authorization: Authorization | None
    containment: ContainmentAction | None
    memory: CyberMemory | None


def _snapshot(session: Session, incident_id: Any) -> Snapshot:
    session.expire_all()
    incident = session.get(Incident, incident_id)
    assert incident is not None
    enriched = session.scalar(
        select(IncidentHistory.id).where(
            IncidentHistory.incident_id == incident_id, IncidentHistory.action == "context_enriched"
        ).limit(1)
    ) is not None
    decision = session.scalars(
        select(Decision).where(Decision.incident_id == incident_id).order_by(Decision.created_at.desc(), Decision.id.desc())
    ).first()
    authorization = None
    if decision is not None:
        authorization = session.scalars(
            select(Authorization)
            .where(Authorization.decision_id == decision.id)
            .order_by(Authorization.requested_at.desc(), Authorization.id.desc())
        ).first()
    containment = None
    if authorization is not None:
        containment = session.scalars(
            select(ContainmentAction)
            .where(ContainmentAction.authorization_id == authorization.id)
            .order_by(ContainmentAction.created_at.desc(), ContainmentAction.id.desc())
        ).first()
    memory = session.scalars(select(CyberMemory).where(CyberMemory.incident_id == incident_id)).first()
    return Snapshot(incident.state, enriched, decision, authorization, containment, memory)


Step = tuple[str, Callable[[], object]]
DONE = "done"
BEYOND = "beyond"


def _next_step(session: Session, scenario: ScenarioSpec, incident_id: Any, snap: Snapshot) -> Step | str:
    """Return the next workflow step, DONE, BEYOND (already past the target) or an error message."""
    target, state = scenario.target, snap.state
    if snap.decision is not None and snap.decision.action != scenario.expected_action:
        return (
            f"decision policy produced {snap.decision.action.name}, expected {scenario.expected_action.name}; "
            "stopping without further steps"
        )

    if state in (IncidentState.DETECTED, IncidentState.UNDERSTOOD) and not snap.enriched:
        return "enrich context", lambda: enrich_incident_context(session, incident_id, actor=ACTOR)
    if state == IncidentState.DETECTED:
        return "correlate events", lambda: correlate_incident_events(session, incident_id, actor=ACTOR)
    if state == IncidentState.UNDERSTOOD:
        return "calculate risk", lambda: calculate_incident_risk(session, incident_id, actor=ACTOR)
    if state == IncidentState.PRIORITISED:
        if snap.decision is None:
            return "recommend decision", lambda: recommend_incident_decision(session, incident_id, actor=ACTOR)
        if target == "decision":
            return DONE
        return "verify incident", lambda: verify_incident(session, incident_id, actor=ACTOR)
    if state == IncidentState.VERIFIED:
        if target == "decision":
            return BEYOND
        if snap.authorization is None:
            decision_id = snap.decision.id  # a VERIFIED incident always has its decision first
            return "request authorization", lambda: request_decision_authorization(session, decision_id, actor=ACTOR)
        if snap.authorization.status == AuthorizationStatus.PENDING:
            if target == "authorization_pending":
                return DONE
            authorization_id = snap.authorization.id
            return "approve authorization", lambda: approve_decision_authorization(
                session, authorization_id, actor=ACTOR
            )
        if target == "authorization_pending":
            return BEYOND
        return f"authorization is {snap.authorization.status.name}; the seed will not request another"
    if state == IncidentState.AUTHORIZED:
        if target != "learned":
            return BEYOND
        if snap.containment is None:
            authorization_id = snap.authorization.id
            return "simulate containment", lambda: simulate_authorized_containment(
                session, authorization_id, actor=ACTOR
            )
        if snap.containment.status == ContainmentStatus.SUCCEEDED:
            containment_id = snap.containment.id
            return "verify containment", lambda: verify_containment(session, containment_id, actor=ACTOR)
        return f"containment is {snap.containment.status.name}; the seed will not retry it"
    if state == IncidentState.CONTAINED:
        if target != "learned":
            return BEYOND
        return "create Cyber Memory", lambda: create_incident_cyber_memory(session, incident_id, actor=ACTOR)
    if state == IncidentState.LEARNED:
        return DONE if target == "learned" else BEYOND
    return f"unexpected state {state.name}"


def _describe(snap: Snapshot) -> str:
    parts = [snap.state.name]
    if snap.decision is not None:
        parts.append(f"decision {snap.decision.action.name}")
    if snap.authorization is not None:
        parts.append(f"authorization {snap.authorization.status.name}")
    if snap.containment is not None:
        parts.append(f"containment {snap.containment.status.name}")
    if snap.memory is not None:
        parts.append("Cyber Memory recorded")
    return ", ".join(parts)


def _advance(session: Session, scenario: ScenarioSpec, incident: Incident, report: Report) -> None:
    incident_id = incident.id
    for _ in range(20):
        snap = _snapshot(session, incident_id)
        step = _next_step(session, scenario, incident_id, snap)
        if step == DONE:
            report.line(f"  {scenario.incident_key}: at target ({_describe(snap)})")
            return
        if step == BEYOND:
            report.line(f"  {scenario.incident_key}: already past the seed target ({_describe(snap)}); left as is")
            return
        if isinstance(step, str):
            report.error(f"{scenario.incident_key}: {step}")
            return
        label, run = step
        try:
            run()
        except HTTPException as error:
            session.rollback()
            report.error(f"{scenario.incident_key}: {label} failed ({error.status_code}): {error.detail}")
            return
        report.transitions += 1
        after = _snapshot(session, incident_id)
        if label == "correlate events" and after.state == IncidentState.DETECTED:
            report.error(f"{scenario.incident_key}: correlation found no related demo events; stopping")
            return
        report.line(f"  {scenario.incident_key}: {label} -> {_describe(after)}")
    report.error(f"{scenario.incident_key}: workflow did not settle")


def _verify_links(session: Session, report: Report) -> None:
    for scenario in SCENARIOS:
        incident = _incident(session, scenario.incident_key)
        if incident is None:
            continue
        linked = session.scalars(
            select(SecurityEvent)
            .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
            .where(IncidentEvent.incident_id == incident.id)
        ).all()
        foreign = [event.event_uid for event in linked if not _has_demo_marker(event)]
        if foreign:
            report.error(f"{scenario.incident_key}: non-demo events linked: {', '.join(sorted(foreign))}")
        risk = "n/a" if incident.risk_score is None else f"{incident.risk_score:g}"
        report.line(f"  {scenario.incident_key}: {len(linked)} linked demo events, risk {risk}")


# ---------------------------------------------------------------------------
# Entry points


def run_seed(session: Session, *, apply: bool, out: Callable[[str], None] = print) -> int:
    """Plan the demo dataset and, with ``apply``, create missing records and advance incidents."""
    report = Report(out)
    missing = missing_tables(session)
    if missing:
        report.line(f"Required tables are missing: {', '.join(missing)}. Create the schema first; nothing was written.")
        return EXIT_BLOCKED

    _plan(session, report)
    if report.conflicts:
        report.line(f"{len(report.conflicts)} conflict(s) found; nothing was written. Resolve them manually.")
        return EXIT_BLOCKED

    if not apply:
        for scenario in SCENARIOS:
            incident = _incident(session, scenario.incident_key)
            if incident is None:
                report.line(f"  {scenario.incident_key}: would be created and advanced to target '{scenario.target}'")
                continue
            snap = _snapshot(session, incident.id)
            step = _next_step(session, scenario, incident.id, snap)
            status = step[0] if isinstance(step, tuple) else step
            report.line(f"  {scenario.incident_key}: {_describe(snap)}; next: {status}")
        report.line(f"Dry run complete: {sum(report.planned.values())} record(s) would be created. Nothing was written.")
        return EXIT_OK

    report.line("Applying")
    assets = _create_base_records(session, report)
    for scenario in SCENARIOS:
        asset = assets[scenario.asset_key]
        events = _ensure_events(session, scenario, asset, report)
        incident = _ensure_incident(session, scenario, asset, events[0], report)
        _advance(session, scenario, incident, report)

    report.line("Verification")
    _verify_links(session, report)
    created = ", ".join(f"{count} {kind}" for kind, count in sorted(report.created.items())) or "0 records"
    report.line(f"Created: {created}; workflow steps run: {report.transitions}; errors: {len(report.errors)}")
    return EXIT_WORKFLOW_ERROR if report.errors else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the fictional NETRA demonstration dataset.")
    parser.add_argument("--apply", action="store_true", help="write missing demo data (default: dry run)")
    args = parser.parse_args(argv)

    from app.db.session import SessionLocal, engine

    print(f"NETRA demo seed ({DATASET}) - target: {describe_target(engine.url)}")
    print("Mode: APPLY (writes missing demo records)" if args.apply else "Mode: DRY RUN (read-only)")
    try:
        with SessionLocal() as session:
            if not args.apply and engine.dialect.name == "postgresql":
                # Any accidental write in a dry run fails instead of committing.
                session.execute(text("SET TRANSACTION READ ONLY"))
            code = run_seed(session, apply=args.apply)
            if not args.apply:
                session.rollback()
    finally:
        engine.dispose()
    return code


if __name__ == "__main__":
    sys.exit(main())
