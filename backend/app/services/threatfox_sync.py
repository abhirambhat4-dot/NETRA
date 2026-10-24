"""Store mapped ThreatFox indicators in ``threat_indicators`` (the table correlation, risk scoring and
Security Assessment already read), and reconcile which ones are active.

- Scope: only rows whose ``source`` is ``THREATFOX_SOURCE``. Seed, demo and other indicators are never read
  for update, changed, expired, reactivated or deleted.
- Idempotent: a row is found by (type, normalised value, source), the table's unique key. Missing rows are
  created; existing rows only widen first/last seen and take a newer confidence.
- Never deletes. Severity: ThreatFox reports none, so new rows get ``THREATFOX_SEVERITY`` (a NETRA-assigned
  value, stated as such); an existing row's severity is never changed.

Expiry (``expiry_days``, default 90) is symmetric: on every sync, every ThreatFox row's ``is_active`` is set to
exactly "its ``last_seen`` is trustworthy and within the window", where

- ``last_seen`` is the latest date ThreatFox reported (its last_seen, or first_seen when it gave none), after
  this sync's report is merged in;
- trustworthy means present and at most ``MAX_FUTURE_SKEW`` in the future (a missing or future date is
  never treated as fresh);
- the window is inclusive: ``now - expiry_days <= last_seen``.

So the active state depends only on the stored date, the window and the clock, never on past settings or on
whether ThreatFox reported the indicator again: lowering the window expires rows, raising it reactivates them,
and a repeated report reactivates an indicator only if it brings its ``last_seen`` back inside the window.
``is_active`` on ThreatFox rows is therefore derived, not an analyst setting. Correlation and Security
Assessment match active indicators only; inactive ones stay stored, with their provenance, for history.

The caller owns the transaction; with ``apply=False`` the same counts are computed and nothing is changed.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.enums import IndicatorType, Severity
from app.models.threat_indicator import ThreatIndicator
from app.services.threatfox import MAX_FUTURE_SKEW, THREATFOX_SOURCE, IndicatorCandidate

#: NETRA-assigned: ThreatFox does not grade severity. Confidence carries ThreatFox's own confidence_level.
THREATFOX_SEVERITY = Severity.MEDIUM
DEFAULT_EXPIRY_DAYS = 90
#: ThreatFox itself stops serving indicators older than six months; NETRA never keeps them active longer.
MAX_EXPIRY_DAYS = 180
LOOKUP_CHUNK = 500


@dataclass
class SyncSummary:
    created: int = 0
    #: Of ``created``: stored inactive because their latest date was already outside the window.
    created_expired: int = 0
    updated: int = 0
    unchanged: int = 0
    #: Existing ThreatFox rows made active (a fresh report, or a window that now covers their date).
    reactivated: int = 0
    #: Existing ThreatFox rows made inactive (their date left the window, or is missing or untrustworthy).
    expired: int = 0


@dataclass(frozen=True)
class Window:
    cutoff: datetime
    latest_trusted: datetime

    def fresh(self, last_seen: datetime | None) -> bool:
        """Inclusive at the cutoff; a missing or future date is never fresh."""
        if last_seen is None:
            return False
        moment = _aware(last_seen)
        return self.cutoff <= moment <= self.latest_trusted


def window_for(now: datetime, expiry_days: int) -> Window:
    if not 1 <= expiry_days <= MAX_EXPIRY_DAYS:
        raise ValueError(f"expiry_days must be from 1 to {MAX_EXPIRY_DAYS}")
    return Window(cutoff=now - timedelta(days=expiry_days), latest_trusted=now + MAX_FUTURE_SKEW)


def sync_indicators(
    session: Session,
    candidates: list[IndicatorCandidate],
    *,
    apply: bool,
    now: datetime | None = None,
    expiry_days: int = DEFAULT_EXPIRY_DAYS,
) -> SyncSummary:
    window = window_for(now or datetime.now(UTC), expiry_days)
    summary = SyncSummary()
    existing = _existing(session, candidates)
    for candidate in candidates:
        row = existing.get((candidate.indicator_type, candidate.value))
        if row is None:
            fresh = window.fresh(candidate.last_seen)
            summary.created += 1
            summary.created_expired += 0 if fresh else 1
            if apply:
                session.add(
                    ThreatIndicator(
                        value=candidate.value,
                        indicator_type=candidate.indicator_type,
                        source=THREATFOX_SOURCE,
                        confidence=candidate.confidence,
                        severity=THREATFOX_SEVERITY,
                        first_seen=candidate.first_seen,
                        last_seen=candidate.last_seen,
                        is_active=fresh,
                    )
                )
            continue
        changes = _changes(row, candidate, window)
        if changes.get("is_active") is True:
            summary.reactivated += 1
        elif changes.get("is_active") is False:
            summary.expired += 1
        if not changes:
            summary.unchanged += 1
            continue
        summary.updated += 1
        if apply:
            for name, value in changes.items():
                setattr(row, name, value)
    expired, reactivated = _reconcile_untouched(session, candidates, window, apply=apply)
    summary.expired += expired
    summary.reactivated += reactivated
    if apply:
        session.flush()
    return summary


def _existing(session: Session, candidates: list[IndicatorCandidate]) -> dict[tuple[IndicatorType, str], ThreatIndicator]:
    by_type: dict[IndicatorType, list[str]] = {}
    for candidate in candidates:
        by_type.setdefault(candidate.indicator_type, []).append(candidate.value)
    rows: dict[tuple[IndicatorType, str], ThreatIndicator] = {}
    for indicator_type, values in by_type.items():
        for start in range(0, len(values), LOOKUP_CHUNK):
            chunk = values[start : start + LOOKUP_CHUNK]
            for row in session.scalars(
                select(ThreatIndicator).where(
                    ThreatIndicator.source == THREATFOX_SOURCE,
                    ThreatIndicator.indicator_type == indicator_type,
                    ThreatIndicator.value.in_(chunk),
                )
            ):
                rows[(row.indicator_type, row.value)] = row
    return rows


def _changes(row: ThreatIndicator, candidate: IndicatorCandidate, window: Window) -> dict[str, object]:
    changes: dict[str, object] = {}
    first_seen = _aware(row.first_seen) if row.first_seen is not None else None
    last_seen = _aware(row.last_seen) if row.last_seen is not None else None
    if first_seen is None or candidate.first_seen < first_seen:
        changes["first_seen"] = candidate.first_seen
    if last_seen is None or candidate.last_seen > last_seen:
        changes["last_seen"] = candidate.last_seen
    if candidate.confidence is not None and candidate.confidence != row.confidence:
        changes["confidence"] = candidate.confidence
    merged_last_seen = candidate.last_seen if last_seen is None else max(last_seen, candidate.last_seen)
    active = window.fresh(merged_last_seen)
    if active != row.is_active:
        changes["is_active"] = active
    return changes


def _reconcile_untouched(
    session: Session, candidates: list[IndicatorCandidate], window: Window, *, apply: bool
) -> tuple[int, int]:
    """(expired, reactivated): ThreatFox rows not in this response whose active state disagrees with the window."""
    handled = {(candidate.indicator_type, candidate.value) for candidate in candidates}
    stale_or_untrusted = or_(
        ThreatIndicator.last_seen.is_(None),
        ThreatIndicator.last_seen < window.cutoff,
        ThreatIndicator.last_seen > window.latest_trusted,
    )
    in_window = and_(ThreatIndicator.last_seen >= window.cutoff, ThreatIndicator.last_seen <= window.latest_trusted)
    mismatched = session.scalars(
        select(ThreatIndicator).where(
            ThreatIndicator.source == THREATFOX_SOURCE,
            or_(
                and_(ThreatIndicator.is_active.is_(True), stale_or_untrusted),
                and_(ThreatIndicator.is_active.is_(False), in_window),
            ),
        )
    ).all()
    expired = reactivated = 0
    for row in mismatched:
        if (row.indicator_type, row.value) in handled:
            continue
        active = window.fresh(row.last_seen)
        if active == row.is_active:
            continue
        if active:
            reactivated += 1
        else:
            expired += 1
        if apply:
            row.is_active = active
    return expired, reactivated


def _aware(value: datetime) -> datetime:
    """Stored timestamps are compared as UTC; a naive value is read as UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
