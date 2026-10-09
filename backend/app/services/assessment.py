"""Security Assessment: load database evidence for one asset, score it with the pure engine and
persist the result as an append-only snapshot.

Assessment only reads assets, vulnerabilities, incidents, events and threat indicators; it never
creates or changes events, incidents, decisions, authorizations, containment or Cyber Memory.
"""

import ipaddress
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement, case, cast, exists, func, null, or_, select, union
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload, selectinload

from app.api.core_serializers import enum_text
from app.models.assessment import AssessmentFinding, SecurityAssessment
from app.models.asset import Asset
from app.models.enums import AssessmentGrade, FindingResult, IncidentState, IndicatorType, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent
from app.models.threat_indicator import ThreatIndicator
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.assessment import (
    AssessmentAssetInput,
    AssessmentEventBucket,
    AssessmentEventEvidence,
    AssessmentEventInput,
    AssessmentIncidentInput,
    AssessmentIndicatorInput,
    AssessmentInput,
    AssessmentLinkedIncidentInput,
    AssessmentResult,
    AssessmentVulnerabilityInput,
)
from app.services.assessment_engine import (
    EVENT_WINDOW,
    LINK_ACTIVE,
    LINK_RESOLVED,
    LINK_UNLINKED,
    METHODOLOGY_VERSION,
    SAMPLE_PER_CLASS,
    assess_asset,
    indicator_address_index,
)
from app.services.rate_limit import SlidingWindowRateLimiter

# PostgreSQL 16 added pg_input_is_valid, which lets SQL test free-text indicator values as inet.
PG_INPUT_IS_VALID_VERSION = (16,)
# Every character Python's str.strip() removes (chr(c).isspace()), so SQL trims indicator values exactly
# as the engine does.
STRIPPED_CHARACTERS = (
    "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0          "
    "      　"
)
RESOLVED_STATES = (IncidentState.CONTAINED, IncidentState.LEARNED)

# Each run reads several tables, so runs are limited to 10 per user per minute.
assessment_user_limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)


def consume_rate_limit(user: User) -> None:
    if not assessment_user_limiter.allow(str(user.id)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Assessment rate limit exceeded. Try again in a minute.",
        )


def _text(value: object) -> str | None:
    return str(value) if value is not None else None


def _event_input(event: SecurityEvent) -> AssessmentEventInput:
    return AssessmentEventInput(
        id=event.id,
        event_uid=event.event_uid,
        occurred_at=event.occurred_at,
        severity=enum_text(event.severity),
        src_ip=_text(event.src_ip),
        dest_ip=_text(event.dest_ip),
        # Incident links (on any asset) and their states decide how assessment-v2 attributes the event.
        linked_incidents=[
            AssessmentLinkedIncidentInput(id=incident.id, incident_key=incident.incident_key, state=enum_text(incident.state))
            for incident in event.incidents
        ],
    )


def _indicator_input(indicator: ThreatIndicator) -> AssessmentIndicatorInput:
    return AssessmentIndicatorInput(
        id=indicator.id,
        value=indicator.value,
        indicator_type=enum_text(indicator.indicator_type),
        source=indicator.source,
        severity=enum_text(indicator.severity),
        confidence=indicator.confidence,
        is_active=indicator.is_active,
    )


def _candidate_indicators(db: Session, window: list[ColumnElement[bool]]) -> list[ThreatIndicator]:
    """Active IP indicators that can match an in-window event address.

    The SQL filter is a superset of what the engine matches: the engine still applies its own IP
    normalization to these rows. PostgreSQL 16+ tests each trimmed value as inet with
    pg_input_is_valid, so free-text values never raise a cast error; older servers load every active
    IP indicator, as before.
    """
    active_ip = (ThreatIndicator.is_active.is_(True), ThreatIndicator.indicator_type == IndicatorType.IP)
    if (db.connection().dialect.server_version_info or (0,)) < PG_INPUT_IS_VALID_VERSION:
        return list(db.scalars(select(ThreatIndicator).where(*active_ip)).all())
    trimmed = func.btrim(ThreatIndicator.value, STRIPPED_CHARACTERS)
    as_inet = case((func.pg_input_is_valid(trimmed, "inet"), cast(trimmed, INET)), else_=null())
    event_addresses = union(
        select(SecurityEvent.src_ip.label("address")).where(*window, SecurityEvent.src_ip.is_not(None)),
        select(SecurityEvent.dest_ip.label("address")).where(*window, SecurityEvent.dest_ip.is_not(None)),
    ).subquery()
    return list(db.scalars(select(ThreatIndicator).where(*active_ip, as_inet.in_(select(event_addresses.c.address)))).all())


def _event_evidence(
    db: Session, window: list[ColumnElement[bool]], matched_addresses: list[str]
) -> AssessmentEventEvidence:
    """Exact bucket counts and the most recent SAMPLE_PER_CLASS events per class, aggregated in SQL."""
    addresses = [ipaddress.ip_address(address) for address in matched_addresses]
    active_link = exists(
        select(IncidentEvent.event_id)
        .join(Incident, Incident.id == IncidentEvent.incident_id)
        .where(IncidentEvent.event_id == SecurityEvent.id, Incident.state.not_in(list(RESOLVED_STATES)))
    )
    any_link = exists(select(IncidentEvent.event_id).where(IncidentEvent.event_id == SecurityEvent.id))
    src_matched = SecurityEvent.src_ip.in_(addresses)
    dest_matched = SecurityEvent.dest_ip.in_(addresses)
    classified = (
        select(
            SecurityEvent.id,
            SecurityEvent.severity,
            case((active_link, LINK_ACTIVE), (any_link, LINK_RESOLVED), else_=LINK_UNLINKED).label("link_status"),
            case((src_matched, SecurityEvent.src_ip), else_=null()).label("src_match"),
            case((dest_matched, SecurityEvent.dest_ip), else_=null()).label("dest_match"),
            SecurityEvent.severity.in_([Severity.HIGH, Severity.CRITICAL]).label("is_high"),
            # IN on a NULL address yields NULL; coalesce so each event lands in exactly one sample class.
            func.coalesce(or_(src_matched, dest_matched), False).label("is_matched"),
            SecurityEvent.occurred_at,
            SecurityEvent.event_uid,
        )
        .where(*window)
        .subquery()
    )
    c = classified.c
    bucket_rows = db.execute(
        select(c.severity, c.link_status, c.src_match, c.dest_match, func.count())
        .group_by(c.severity, c.link_status, c.src_match, c.dest_match)
    ).all()
    buckets = [
        AssessmentEventBucket(
            severity=enum_text(severity), link_status=link, src_ip=_text(src), dest_ip=_text(dest), count=count
        )
        for severity, link, src, dest, count in bucket_rows
    ]

    ranked = (
        select(
            c.id,
            # Same order as the engine's window order: occurred_at, then event_uid in byte order
            # (Python string order), then id; each class keeps its most recent SAMPLE_PER_CLASS events.
            func.row_number()
            .over(
                partition_by=(c.link_status, c.is_high, c.is_matched),
                order_by=(c.occurred_at.desc(), c.event_uid.collate("C").desc(), c.id.desc()),
            )
            .label("class_rank"),
        )
        .subquery()
    )
    sample_ids = select(ranked.c.id).where(ranked.c.class_rank <= SAMPLE_PER_CLASS)
    samples = db.scalars(
        select(SecurityEvent).where(SecurityEvent.id.in_(sample_ids)).options(selectinload(SecurityEvent.incidents))
    ).all()
    return AssessmentEventEvidence(buckets=buckets, samples=[_event_input(event) for event in samples])


def load_assessment_input(db: Session, asset: Asset, as_of: datetime) -> AssessmentInput:
    """Load bounded evidence for one asset: exact event counts plus samples, and only matchable indicators."""
    vulnerabilities = db.scalars(select(Vulnerability).where(Vulnerability.asset_id == asset.id)).all()
    incidents = db.scalars(select(Incident).where(Incident.asset_id == asset.id)).all()
    window = [
        SecurityEvent.asset_id == asset.id,
        SecurityEvent.occurred_at >= as_of - EVENT_WINDOW,
        SecurityEvent.occurred_at <= as_of,
    ]
    active_ip_total = int(
        db.scalar(
            select(func.count()).select_from(ThreatIndicator).where(
                ThreatIndicator.is_active.is_(True), ThreatIndicator.indicator_type == IndicatorType.IP
            )
        ) or 0
    )
    indicators = [_indicator_input(item) for item in _candidate_indicators(db, window)]
    # The engine's own normalization decides which addresses match; SQL only groups by them.
    matched_addresses, _ = indicator_address_index(indicators)
    return AssessmentInput(
        asset=AssessmentAssetInput(
            id=asset.id,
            asset_key=asset.asset_key,
            name=asset.name,
            hostname=asset.hostname,
            ip_address=_text(asset.ip_address),
            criticality=enum_text(asset.criticality),
            exposure=enum_text(asset.exposure),
            status=enum_text(asset.status),
            owner=asset.owner,
        ),
        vulnerabilities=[
            AssessmentVulnerabilityInput(
                id=item.id,
                cve_id=item.cve_id,
                title=item.title,
                cvss_score=float(item.cvss_score) if item.cvss_score is not None else None,
                severity=enum_text(item.severity),
                status=enum_text(item.status),
            )
            for item in vulnerabilities
        ],
        incidents=[
            AssessmentIncidentInput(
                id=item.id, incident_key=item.incident_key, severity=enum_text(item.severity), state=enum_text(item.state)
            )
            for item in incidents
        ],
        event_evidence=_event_evidence(db, window, list(matched_addresses)),
        threat_indicators=indicators,
        active_ip_indicator_total=active_ip_total,
        as_of=as_of,
    )


def _input_counts(data: AssessmentInput) -> dict[str, int]:
    events = data.event_evidence.buckets if data.event_evidence is not None else None
    return {
        "vulnerabilities": len(data.vulnerabilities),
        "incidents": len(data.incidents),
        "events": sum(bucket.count for bucket in events) if events is not None else len(data.events),
        "threatIndicators": (
            data.active_ip_indicator_total if data.active_ip_indicator_total is not None else len(data.threat_indicators)
        ),
    }


def _snapshot(data: AssessmentInput, result: AssessmentResult, user: User) -> SecurityAssessment:
    return SecurityAssessment(
        asset_id=result.asset_id,
        asset_key=result.asset_key,
        methodology_version=result.methodology_version,
        as_of=result.as_of,
        score=result.score,
        grade=AssessmentGrade[result.grade],
        summary=result.summary,
        passed=result.passed,
        warnings=result.warnings,
        failed=result.failed,
        informational=result.informational,
        missing_evidence=result.missing_evidence,
        input_counts=_input_counts(data),
        requested_by=user.email,
        requested_by_id=user.id,
        findings=[
            AssessmentFinding(
                position=position,
                check_key=finding.check_key,
                category=finding.category,
                title=finding.title,
                result=FindingResult[finding.result],
                severity=Severity[finding.severity] if finding.severity is not None else None,
                deduction=finding.deduction,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                vulnerability_ids=[str(item) for item in finding.vulnerability_ids],
                incident_ids=[str(item) for item in finding.incident_ids],
                event_ids=[str(item) for item in finding.event_ids],
                vulnerability_total=finding.vulnerability_total,
                incident_total=finding.incident_total,
                event_total=finding.event_total,
            )
            for position, finding in enumerate(result.findings)
        ],
    )


def get_assessment(db: Session, assessment_id: UUID) -> SecurityAssessment | None:
    return db.scalars(
        select(SecurityAssessment)
        .where(SecurityAssessment.id == assessment_id)
        .options(joinedload(SecurityAssessment.asset), selectinload(SecurityAssessment.findings))
    ).one_or_none()


def run_assessment(db: Session, user: User, asset_id: UUID) -> SecurityAssessment:
    """Assess one asset and store a new snapshot; earlier snapshots are never modified."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # One timestamp bounds both the evidence query and the engine, so the snapshot is reproducible.
    as_of = datetime.now(UTC)
    data = load_assessment_input(db, asset, as_of)
    # New snapshots always use the current methodology; stored snapshots keep theirs.
    result = assess_asset(data, methodology=METHODOLOGY_VERSION)
    snapshot = _snapshot(data, result, user)
    try:
        db.add(snapshot)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Assessment could not be stored"
        ) from None
    # Reload from the database so the response matches what GET /assessments/{id} returns.
    db.expunge(snapshot)
    stored = get_assessment(db, snapshot.id)
    assert stored is not None
    return stored
