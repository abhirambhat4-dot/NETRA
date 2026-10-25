"""Dashboard risk trend: incident risk and event volume per time bucket, reconstructed from stored history.

Read-only. Each bucket reports, at its end (the last bucket at "now"):

* ``risk_score``: the same figure as the dashboard's average active incident risk
  (``DashboardStats.average_risk_score``): the mean risk score of incidents that were active
  (not CONTAINED or LEARNED) then, ignoring unscored ones; ``None`` when none was scored;
* ``active_incidents``: incidents created by then and not yet resolved;
* ``events``: security events that occurred inside the bucket, by detection source.

An incident's state at a time is the ``to_state`` of its latest ``incident_history`` entry by then (before its
first entry: that entry's ``from_state``). Its score at a time is the latest stored score by then, from
``risk_evaluations`` rows and ``risk_calculated`` history entries. Two fallbacks keep older or seeded data
usable, and are documented as estimates: an incident with no history keeps its current state throughout, and
one whose current ``risk_score`` has no recorded time is treated as scored since it was created. Nothing is
recalculated or written.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import DetectionSource, IncidentState
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentHistory
from app.models.risk_evaluation import RiskEvaluation

TrendRange = Literal["24h", "7d"]
#: (bucket width, number of buckets); matches the dashboard panel (hourly for 24h, 6-hour buckets for 7d).
TREND_RANGES: dict[str, tuple[timedelta, int]] = {"24h": (timedelta(hours=1), 24), "7d": (timedelta(hours=6), 28)}
RESOLVED_STATES = frozenset({IncidentState.CONTAINED, IncidentState.LEARNED})
EVENT_SOURCE_KEYS = tuple(source.name for source in DetectionSource)


@dataclass
class IncidentTimeline:
    created_at: datetime
    current_state: IncidentState
    current_score: float | None
    #: (when, state entered), oldest first.
    states: list[tuple[datetime, IncidentState]] = field(default_factory=list)
    #: State before the first history entry (its from_state), when known.
    initial_state: IncidentState | None = None
    #: (when, score), oldest first: risk_evaluations rows and risk_calculated history entries.
    scores: list[tuple[datetime, float]] = field(default_factory=list)

    def state_at(self, moment: datetime) -> IncidentState:
        if not self.states:
            return self.current_state  # no history: estimate with the current state
        state = self.initial_state or self.states[0][1]
        for when, entered in self.states:
            if when > moment:
                break
            state = entered
        return state

    def score_at(self, moment: datetime) -> float | None:
        if not self.scores:
            return self.current_score  # a score without a recorded time: known since creation (estimate)
        score = None
        for when, value in self.scores:
            if when > moment:
                break
            score = value
        return score


@dataclass(frozen=True)
class TrendPoint:
    timestamp: datetime
    risk_score: float | None
    active_incidents: int
    scored_incidents: int
    events: dict[str, int]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def trend_buckets(trend_range: str, now: datetime) -> list[datetime]:
    """Bucket start times, oldest first; the last bucket contains ``now``. Aligned to whole UTC buckets."""
    width, count = TREND_RANGES[trend_range]
    seconds = int(width.total_seconds())
    current_start = datetime.fromtimestamp(int(_aware(now).timestamp()) // seconds * seconds, tz=UTC)
    return [current_start - width * (count - 1 - index) for index in range(count)]


def build_trend(
    trend_range: str,
    now: datetime,
    incidents: Iterable[IncidentTimeline],
    event_counts: dict[tuple[int, str], int],
) -> list[TrendPoint]:
    """Pure: the trend from incident timelines and per-(bucket index, source name) event counts."""
    width, _ = TREND_RANGES[trend_range]
    timelines = list(incidents)
    points: list[TrendPoint] = []
    starts = trend_buckets(trend_range, now)
    for index, start in enumerate(starts):
        moment = min(start + width, _aware(now))  # the last bucket is measured now
        active = [t for t in timelines if t.created_at <= moment and t.state_at(moment) not in RESOLVED_STATES]
        scores = [score for t in active if (score := t.score_at(moment)) is not None]
        points.append(
            TrendPoint(
                timestamp=start,
                risk_score=round(sum(scores) / len(scores), 2) if scores else None,
                active_incidents=len(active),
                scored_incidents=len(scores),
                events={key: event_counts.get((index, key), 0) for key in EVENT_SOURCE_KEYS},
            )
        )
    return points


def _history_score(details: dict | None) -> float | None:
    calculation = (details or {}).get("risk_calculation")
    value = calculation.get("risk_score") if isinstance(calculation, dict) else None
    return float(value) if isinstance(value, int | float) else None


def load_risk_trend(db: Session, trend_range: str, *, now: datetime | None = None) -> list[TrendPoint]:
    now = _aware(now or datetime.now(UTC))
    width, count = TREND_RANGES[trend_range]
    starts = trend_buckets(trend_range, now)
    window_start, window_end = starts[0], starts[-1] + width

    rows = db.execute(
        select(Incident.id, Incident.created_at, Incident.state, Incident.risk_score).where(Incident.created_at <= now)
    ).all()
    timelines: dict[UUID, IncidentTimeline] = {
        incident_id: IncidentTimeline(
            created_at=_aware(created_at),
            current_state=state,
            current_score=float(score) if score is not None else None,
        )
        for incident_id, created_at, state, score in rows
    }
    if timelines:
        history = db.execute(
            select(
                IncidentHistory.incident_id,
                IncidentHistory.occurred_at,
                IncidentHistory.from_state,
                IncidentHistory.to_state,
                IncidentHistory.action,
                IncidentHistory.details,
            )
            .where(IncidentHistory.incident_id.in_(timelines))
            .order_by(IncidentHistory.occurred_at, IncidentHistory.id)
        ).all()
        scores: dict[UUID, list[tuple[datetime, float]]] = defaultdict(list)
        for incident_id, occurred_at, from_state, to_state, action, details in history:
            timeline = timelines[incident_id]
            if not timeline.states:
                timeline.initial_state = from_state
            timeline.states.append((_aware(occurred_at), to_state))
            if action == "risk_calculated" and (score := _history_score(details)) is not None:
                scores[incident_id].append((_aware(occurred_at), score))
        for incident_id, created_at, score in db.execute(
            select(RiskEvaluation.incident_id, RiskEvaluation.created_at, RiskEvaluation.risk_score).where(
                RiskEvaluation.incident_id.in_(timelines)
            )
        ).all():
            scores[incident_id].append((_aware(created_at), float(score)))
        for incident_id, entries in scores.items():
            timelines[incident_id].scores = sorted(entries, key=lambda entry: entry[0])

    seconds = width.total_seconds()
    bucket = func.floor((func.extract("epoch", SecurityEvent.occurred_at) - window_start.timestamp()) / seconds)
    event_counts = {
        (int(index), source.name): int(total)
        for index, source, total in db.execute(
            select(bucket, SecurityEvent.source, func.count())
            .where(SecurityEvent.occurred_at >= window_start, SecurityEvent.occurred_at < window_end)
            .group_by(bucket, SecurityEvent.source)
        ).all()
        if 0 <= int(index) < count
    }
    return build_trend(trend_range, now, timelines.values(), event_counts)
