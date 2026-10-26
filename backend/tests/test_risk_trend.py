"""GET /api/dashboard/risk-trend and the pure trend reconstruction in app/services/risk_trend.py.

Pure tests use a fixed clock; API tests run on the core_api fixture's throwaway schema (rolled back).
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.models.enums import DetectionSource, IncidentState, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentHistory
from app.models.risk_evaluation import RiskEvaluation
from app.services import risk_trend
from app.services.risk_trend import EVENT_SOURCE_KEYS, IncidentTimeline, build_trend, trend_buckets
from tests.conftest import CoreApi

NOW = datetime(2026, 10, 25, 10, 37, tzinfo=UTC)
S = IncidentState


def test_buckets_are_whole_utc_buckets_ending_with_the_current_one() -> None:
    hourly = trend_buckets("24h", NOW)
    assert len(hourly) == 24 and hourly[-1] == datetime(2026, 10, 25, 10, tzinfo=UTC)
    assert all(later - earlier == timedelta(hours=1) for earlier, later in zip(hourly, hourly[1:]))
    six_hourly = trend_buckets("7d", NOW)
    assert len(six_hourly) == 28 and six_hourly[-1] == datetime(2026, 10, 25, 6, tzinfo=UTC)
    assert six_hourly[0] == datetime(2026, 10, 18, 12, tzinfo=UTC)


def _timeline(created_hours_ago: float, states, scores, *, current_state=S.PRIORITISED, current_score=None, initial=S.DETECTED):  # type: ignore[no-untyped-def]
    return IncidentTimeline(
        created_at=NOW - timedelta(hours=created_hours_ago),
        current_state=current_state,
        current_score=current_score,
        states=[(NOW - timedelta(hours=hours), state) for hours, state in states],
        initial_state=initial if states else None,
        scores=[(NOW - timedelta(hours=hours), score) for hours, score in scores],
    )


def test_state_and_score_are_reconstructed_at_each_bucket_end() -> None:
    # Created 5.5 h ago; scored 60 at 3.5 h ago; contained 1.5 h ago.
    contained = _timeline(5.5, [(4.5, S.UNDERSTOOD), (3.5, S.PRIORITISED), (1.5, S.CONTAINED)], [(3.5, 60.0)], current_state=S.CONTAINED, current_score=60.0)
    # Created 2.5 h ago; scored 30, then 50 (a later evaluation); still active.
    rescored = _timeline(2.5, [(2.2, S.UNDERSTOOD), (2.0, S.PRIORITISED)], [(2.0, 30.0), (0.2, 50.0)], current_score=50.0)
    points = build_trend("24h", NOW, [contained, rescored], {})
    by_end = {point.timestamp + timedelta(hours=1): point for point in points}

    def at(hour: int):  # type: ignore[no-untyped-def]
        return by_end[datetime(2026, 10, 25, hour, tzinfo=UTC)]

    assert (at(5).active_incidents, at(5).risk_score) == (0, None)  # nothing created yet
    assert (at(6).active_incidents, at(6).scored_incidents, at(6).risk_score) == (1, 0, None)  # created, not scored
    assert (at(8).active_incidents, at(8).risk_score) == (1, 60.0)  # scored at 07:07; the second is created at 08:07
    assert (at(9).active_incidents, at(9).risk_score) == (2, 45.0)  # 60 and 30 (scored at 08:37)
    assert (at(10).active_incidents, at(10).risk_score) == (1, 30.0)  # the first was contained at 09:07
    current = points[-1]  # measured now (10:37): the second incident's latest score is 50
    assert (current.timestamp, current.active_incidents, current.risk_score) == (datetime(2026, 10, 25, 10, tzinfo=UTC), 1, 50.0)


def test_an_incident_without_history_keeps_its_current_state_and_score() -> None:
    seeded = _timeline(3, [], [], current_state=S.VERIFIED, current_score=72.5)
    resolved = _timeline(3, [], [], current_state=S.LEARNED, current_score=90.0)
    current = build_trend("24h", NOW, [seeded, resolved], {})[-1]
    assert (current.active_incidents, current.scored_incidents, current.risk_score) == (1, 1, 72.5)


def test_event_counts_cover_every_detection_source() -> None:
    points = build_trend("24h", NOW, [], {(23, "SURICATA"): 3, (23, "DATASET_IMPORT"): 2, (0, "MANUAL"): 1})
    assert set(points[-1].events) == set(EVENT_SOURCE_KEYS) == {source.name for source in DetectionSource}
    assert (points[-1].events["SURICATA"], points[-1].events["DATASET_IMPORT"], points[0].events["MANUAL"]) == (3, 2, 1)
    assert all(point.risk_score is None and point.active_incidents == 0 for point in points)


# --- API ---------------------------------------------------------------------------------------


def test_the_risk_trend_requires_authentication_and_a_known_range(core_api: CoreApi) -> None:
    assert core_api.client.get("/api/dashboard/risk-trend").status_code == 401
    assert core_api.client.get("/api/dashboard/risk-trend?range=30d", headers=core_api.headers).status_code == 422


def test_an_empty_database_gives_empty_buckets_not_an_empty_list(core_api: CoreApi) -> None:
    for trend_range, count in (("24h", 24), ("7d", 28)):
        response = core_api.client.get(f"/api/dashboard/risk-trend?range={trend_range}", headers=core_api.headers)
        assert response.status_code == 200
        points = response.json()
        assert len(points) == count
        assert all(p["riskScore"] is None and p["activeIncidents"] == 0 and sum(p["events"].values()) == 0 for p in points)
        assert set(points[0]) == {"timestamp", "riskScore", "activeIncidents", "scoredIncidents", "events"}


def test_the_trend_is_reconstructed_from_stored_records_and_ends_at_the_live_average(
    core_api: CoreApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One fixed clock for the test and the endpoint, at half past the hour: no bucket boundary can fall between
    # seeding and the request, and every seeded time sits mid-bucket.
    now = datetime.now(UTC).replace(minute=30, second=0, microsecond=0)

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[no-untyped-def, override]
            return now if tz is None else now.astimezone(tz)

    monkeypatch.setattr(risk_trend, "datetime", FixedClock)
    with core_api.session_factory() as session:
        def incident(created: datetime, state: IncidentState, score: float | None) -> Incident:
            row = Incident(
                incident_key=f"INC-{uuid4().hex[:8]}", title="Trend test", severity=Severity.HIGH,
                detection_source=DetectionSource.SURICATA, state=state, risk_score=score, created_at=created,
            )
            session.add(row)
            session.flush()
            return row

        scored = incident(now - timedelta(hours=5), S.PRIORITISED, 64.0)
        session.add_all([
            IncidentHistory(incident_id=scored.id, from_state=S.DETECTED, to_state=S.UNDERSTOOD, action="events_correlated",
                            actor="trend-test", occurred_at=now - timedelta(hours=4, minutes=30)),
            IncidentHistory(incident_id=scored.id, from_state=S.UNDERSTOOD, to_state=S.PRIORITISED, action="risk_calculated",
                            actor="trend-test", occurred_at=now - timedelta(hours=4),
                            details={"risk_calculation": {"risk_score": 64.0}}),
        ])
        session.add(RiskEvaluation(
            incident_id=scored.id, methodology_version="risk-v1", risk_score=64.0, risk_level="HIGH",
            previous_risk_score=None, factors={}, missing_evidence=[], matched_indicators=[], trigger="initial",
            actor="trend-test", created_at=now - timedelta(hours=4),
        ))
        resolved = incident(now - timedelta(hours=6), S.CONTAINED, 90.0)
        session.add_all([
            IncidentHistory(incident_id=resolved.id, from_state=S.DETECTED, to_state=S.PRIORITISED, action="risk_calculated",
                            actor="trend-test", occurred_at=now - timedelta(hours=5, minutes=30),
                            details={"risk_calculation": {"risk_score": 90.0}}),
            IncidentHistory(incident_id=resolved.id, from_state=S.AUTHORIZED, to_state=S.CONTAINED, action="containment_succeeded",
                            actor="trend-test", occurred_at=now - timedelta(hours=2)),
        ])
        incident(now - timedelta(hours=1), S.DETECTED, None)  # active, unscored
        session.add_all([
            SecurityEvent(event_uid=f"evt-trend-{uuid4().hex}", occurred_at=now - timedelta(hours=3), source=source,
                          event_type="trend_test", severity=Severity.MEDIUM)
            for source in (DetectionSource.SURICATA, DetectionSource.SURICATA, DetectionSource.ML_ANOMALY, DetectionSource.DATASET_IMPORT)
        ])
        session.add(SecurityEvent(event_uid=f"evt-trend-{uuid4().hex}", occurred_at=now - timedelta(days=3), source=DetectionSource.SURICATA,
                                  event_type="trend_test", severity=Severity.LOW))  # outside 24h, inside 7d
        session.commit()

    points = core_api.client.get("/api/dashboard/risk-trend?range=24h", headers=core_api.headers).json()
    stats = core_api.client.get("/api/dashboard/stats", headers=core_api.headers).json()
    current = points[-1]
    # The endpoint used the pinned clock: its current bucket starts at the pinned hour.
    assert datetime.fromisoformat(current["timestamp"]) == now.replace(minute=0)
    # The current bucket uses the dashboard's own definition: average risk of active incidents, unscored ignored.
    assert (current["riskScore"], current["activeIncidents"], current["scoredIncidents"]) == (64.0, 2, 1)
    assert current["riskScore"] == stats["averageRiskScore"] and current["activeIncidents"] == stats["activeIncidents"]

    # Events land in the bucket containing them, by source.
    moment = now - timedelta(hours=3)
    bucket = next(p for p in points if datetime.fromisoformat(p["timestamp"]) <= moment < datetime.fromisoformat(p["timestamp"]) + timedelta(hours=1))
    assert (bucket["events"]["SURICATA"], bucket["events"]["ML_ANOMALY"], bucket["events"]["DATASET_IMPORT"]) == (2, 1, 1)
    assert sum(sum(p["events"].values()) for p in points) == 4

    # Before the containment (2 h ago) both scored incidents were active: (64 + 90) / 2.
    before = next(p for p in points if datetime.fromisoformat(p["timestamp"]) + timedelta(hours=1) <= now - timedelta(hours=2, minutes=1)
                  and datetime.fromisoformat(p["timestamp"]) + timedelta(hours=1) > now - timedelta(hours=3, minutes=59))
    assert (before["riskScore"], before["activeIncidents"]) == (77.0, 2)

    weekly = core_api.client.get("/api/dashboard/risk-trend?range=7d", headers=core_api.headers).json()
    assert sum(sum(p["events"].values()) for p in weekly) == 5
    assert weekly[-1]["riskScore"] == 64.0
