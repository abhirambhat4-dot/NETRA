"""Read-only aggregation of source-supplied ATT&CK technique observations.

Counts only persisted ``event_attack_techniques`` rows with ``evidence_kind = 'source_supplied'``: technique IDs
that a detection source explicitly reported for an event. Nothing is inferred from raw payloads, signatures,
tags or dataset labels, and nothing is written.

Every figure comes from one filtered set of (technique, event) rows: the time window (``as_of - days <=
occurred_at <= as_of``, both ends inclusive, one ``as_of`` per request) and the optional source, origin and
technique filters are applied once, there, so event counts, first/last seen, severity, the source and origin
breakdowns and the linked incidents always describe the same events. A fixed number of queries is used
(count, page, then three breakdowns for the page's techniques), with grouping, ordering and paging in SQL.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import case, distinct, func, select
from sqlalchemy.orm import Session

from app.models.attack_technique import EventAttackTechnique
from app.models.enums import DetectionSource, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent
from app.services.prioritization import ACTIVE_STATES

INCIDENT_ID_CAP = 100
SortBy = Literal["eventCount", "lastSeen", "techniqueId"]
SortOrder = Literal["asc", "desc"]
# Severity rank from the enum's declared order (INFO < LOW < MEDIUM < HIGH < CRITICAL), as the event APIs order it.
_SEVERITY_NAMES = {rank: severity.name for rank, severity in enumerate(Severity)}


@dataclass(frozen=True)
class ObservationQuery:
    as_of: datetime
    days: int
    source: DetectionSource | None = None
    origin: str | None = None
    technique_id: str | None = None
    page: int = 1
    page_size: int = 25
    sort_by: SortBy = "eventCount"
    sort_order: SortOrder = "desc"


@dataclass(frozen=True)
class Observation:
    technique_id: str
    event_count: int
    incident_count: int
    active_incident_count: int
    incident_ids: list[UUID]
    highest_severity: str
    first_seen: datetime
    last_seen: datetime
    sources: dict[str, int]
    origins: dict[str, int]


def _matching(query: ObservationQuery):  # type: ignore[no-untyped-def]
    """The filtered (technique, event) rows every figure is computed from."""
    conditions = [
        EventAttackTechnique.evidence_kind == "source_supplied",
        SecurityEvent.occurred_at >= query.as_of - timedelta(days=query.days),
        SecurityEvent.occurred_at <= query.as_of,
    ]
    if query.source is not None:
        conditions.append(SecurityEvent.source == query.source)
    if query.origin is not None:
        conditions.append(EventAttackTechnique.evidence_origin == query.origin)
    if query.technique_id is not None:
        conditions.append(EventAttackTechnique.technique_id == query.technique_id)
    return (
        select(
            EventAttackTechnique.technique_id.label("technique_id"),
            EventAttackTechnique.event_id.label("event_id"),
            EventAttackTechnique.evidence_origin.label("origin"),
            SecurityEvent.source.label("source"),
            SecurityEvent.severity.label("severity"),
            SecurityEvent.occurred_at.label("occurred_at"),
        )
        .join(SecurityEvent, SecurityEvent.id == EventAttackTechnique.event_id)
        .where(*conditions)
        .subquery("matching")
    )


def observed_techniques(db: Session, query: ObservationQuery) -> tuple[list[Observation], int]:
    """(this page's observations, total techniques). Read-only."""
    matching = _matching(query)
    rank = case(*((matching.c.severity == severity, position) for position, severity in enumerate(Severity)))
    grouped = (
        select(
            matching.c.technique_id,
            func.count(distinct(matching.c.event_id)).label("event_count"),
            func.min(matching.c.occurred_at).label("first_seen"),
            func.max(matching.c.occurred_at).label("last_seen"),
            func.max(rank).label("severity_rank"),
        )
        .group_by(matching.c.technique_id)
        .subquery("grouped")
    )
    total = db.scalar(select(func.count()).select_from(grouped)) or 0

    primary = {"eventCount": grouped.c.event_count, "lastSeen": grouped.c.last_seen, "techniqueId": grouped.c.technique_id}[query.sort_by]
    order = [primary.asc() if query.sort_order == "asc" else primary.desc()]
    if query.sort_by != "techniqueId":
        order.append(grouped.c.technique_id.asc())  # stable tie-breaker
    rows = db.execute(
        select(grouped).order_by(*order).offset((query.page - 1) * query.page_size).limit(query.page_size)
    ).all()
    if not rows:
        return [], total
    page_ids = [row.technique_id for row in rows]
    on_page = matching.c.technique_id.in_(page_ids)

    sources: dict[str, dict[str, int]] = {technique: {} for technique in page_ids}
    for technique, source, count in db.execute(
        select(matching.c.technique_id, matching.c.source, func.count(distinct(matching.c.event_id)))
        .where(on_page)
        .group_by(matching.c.technique_id, matching.c.source)
    ):
        sources[technique][source.name] = count
    origins: dict[str, dict[str, int]] = {technique: {} for technique in page_ids}
    for technique, origin, count in db.execute(
        select(matching.c.technique_id, matching.c.origin, func.count(distinct(matching.c.event_id)))
        .where(on_page)
        .group_by(matching.c.technique_id, matching.c.origin)
    ):
        origins[technique][origin] = count

    # Distinct (technique, incident) pairs reached only through the matching events.
    pairs = (
        select(matching.c.technique_id, IncidentEvent.incident_id, Incident.state)
        .join(IncidentEvent, IncidentEvent.event_id == matching.c.event_id)
        .join(Incident, Incident.id == IncidentEvent.incident_id)
        .where(on_page)
        .distinct()
        .subquery("pairs")
    )
    incident_counts = {
        technique: (count, active)
        for technique, count, active in db.execute(
            select(pairs.c.technique_id, func.count(), func.count().filter(pairs.c.state.in_(ACTIVE_STATES)))
            .group_by(pairs.c.technique_id)
        )
    }
    ranked = select(
        pairs.c.technique_id,
        pairs.c.incident_id,
        func.row_number().over(partition_by=pairs.c.technique_id, order_by=pairs.c.incident_id).label("position"),
    ).subquery("ranked")
    incident_ids: dict[str, list[UUID]] = {technique: [] for technique in page_ids}
    for technique, incident_id in db.execute(
        select(ranked.c.technique_id, ranked.c.incident_id)
        .where(ranked.c.position <= INCIDENT_ID_CAP)
        .order_by(ranked.c.technique_id, ranked.c.position)
    ):
        incident_ids[technique].append(incident_id)

    return [
        Observation(
            technique_id=row.technique_id,
            event_count=row.event_count,
            incident_count=incident_counts.get(row.technique_id, (0, 0))[0],
            active_incident_count=incident_counts.get(row.technique_id, (0, 0))[1],
            incident_ids=incident_ids[row.technique_id],
            highest_severity=_SEVERITY_NAMES[row.severity_rank],
            # In UTC like asOf (PostgreSQL returns timestamps in the session's time zone).
            first_seen=row.first_seen.astimezone(UTC),
            last_seen=row.last_seen.astimezone(UTC),
            sources=dict(sorted(sources[row.technique_id].items())),
            origins=dict(sorted(origins[row.technique_id].items())),
        )
        for row in rows
    ], total
