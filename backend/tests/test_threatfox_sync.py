"""ThreatFox sync into threat_indicators (including the expiry policy), and the guarded manual command.

Throwaway PostgreSQL schemas inside transactions that are always rolled back (run only through
scripts/netra_e2e_pytest.py). ThreatFox is never called: records are synthetic and the fetch is stubbed.
A fixed clock (NOW) keeps the expiry boundaries exact.
"""

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import engine
from app.models import ThreatIndicator
from app.models.enums import IndicatorType, Severity
from app.services.threatfox import THREATFOX_SOURCE, IndicatorCandidate, map_iocs
from app.services.threatfox_sync import DEFAULT_EXPIRY_DAYS, THREATFOX_SEVERITY, SyncSummary, sync_indicators, window_for
from scripts import netra_threatfox_sync as command

LOCAL = make_url("postgresql+psycopg://user:secret@localhost:5432/netra_e2e")
REMOTE = make_url("postgresql+psycopg://user:secret@db.example.com:5432/netra")
DUMMY_KEY = "dummy-threatfox-key-for-tests"
NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
T0 = datetime(2026, 10, 23, 10, tzinfo=UTC)
CUTOFF = NOW - timedelta(days=DEFAULT_EXPIRY_DAYS)


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    schema = f"netra_threatfox_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            isolated = connection.execution_options(schema_translate_map={None: schema})
            Base.metadata.create_all(isolated)
            yield sessionmaker(bind=isolated, autoflush=False, expire_on_commit=False, join_transaction_mode="create_savepoint")
        finally:
            transaction.rollback()


def candidate(value: str = "8.8.4.4", *, kind: IndicatorType = IndicatorType.IP, confidence: float | None = 0.5, first: datetime = T0, last: datetime | None = None) -> IndicatorCandidate:
    return IndicatorCandidate(kind, value, confidence, first, last or first)


def rows(factory: sessionmaker[Session]) -> list[ThreatIndicator]:
    with factory() as session:
        return list(session.scalars(select(ThreatIndicator).order_by(ThreatIndicator.source, ThreatIndicator.value)))


def by_value(factory: sessionmaker[Session], source: str = THREATFOX_SOURCE) -> dict[str, ThreatIndicator]:
    return {r.value: r for r in rows(factory) if r.source == source}


def sync(factory: sessionmaker[Session], candidates: list[IndicatorCandidate], *, apply: bool = True, now: datetime = NOW, days: int = DEFAULT_EXPIRY_DAYS) -> SyncSummary:
    with factory() as session:
        summary = sync_indicators(session, candidates, apply=apply, now=now, expiry_days=days)
        session.commit()
        return summary


def add(factory: sessionmaker[Session], value: str, *, source: str = THREATFOX_SOURCE, last: datetime = T0, active: bool = True) -> None:
    with factory() as session:
        session.add(ThreatIndicator(value=value, indicator_type=IndicatorType.IP, source=source, confidence=0.6, severity=Severity.MEDIUM, is_active=active, first_seen=last, last_seen=last))
        session.commit()


# --- sync -----------------------------------------------------------------------------------------


def test_new_indicators_are_created_with_threatfox_attribution(factory: sessionmaker[Session]) -> None:
    summary = sync(factory, [candidate("8.8.4.4"), candidate("evil.example", kind=IndicatorType.DOMAIN, confidence=None)])
    assert (summary.created, summary.updated, summary.unchanged, summary.created_expired) == (2, 0, 0, 0)
    # Ordered by source, then value.
    assert [(r.indicator_type, r.value, r.source, r.severity, r.is_active, r.confidence) for r in rows(factory)] == [
        (IndicatorType.IP, "8.8.4.4", THREATFOX_SOURCE, THREATFOX_SEVERITY, True, 0.5),
        (IndicatorType.DOMAIN, "evil.example", THREATFOX_SOURCE, THREATFOX_SEVERITY, True, None),
    ]


def test_resync_is_idempotent(factory: sessionmaker[Session]) -> None:
    sync(factory, [candidate()])
    again = sync(factory, [candidate()])
    assert (again.created, again.updated, again.unchanged, again.expired, again.reactivated) == (0, 0, 1, 0, 0)
    assert len(rows(factory)) == 1


def test_existing_rows_only_widen_seen_dates_take_new_confidence_and_keep_severity(factory: sessionmaker[Session]) -> None:
    sync(factory, [candidate(confidence=0.5)])
    with factory() as session:
        row = session.scalar(select(ThreatIndicator))
        row.severity = Severity.HIGH  # e.g. an analyst's own grading
        session.commit()
    later = datetime(2026, 10, 24, 9, tzinfo=UTC)
    summary = sync(factory, [candidate(confidence=0.9, first=datetime(2026, 10, 22, tzinfo=UTC), last=later)])
    assert summary.updated == 1
    [row] = rows(factory)
    assert (row.confidence, row.severity, row.is_active) == (0.9, Severity.HIGH, True)
    assert row.first_seen.astimezone(UTC) == datetime(2026, 10, 22, tzinfo=UTC)
    assert row.last_seen.astimezone(UTC) == later
    # An older report never moves last_seen backwards, and an unknown confidence keeps the stored one.
    sync(factory, [candidate(confidence=None, last=T0)])
    [row] = rows(factory)
    assert (row.confidence, row.last_seen.astimezone(UTC)) == (0.9, later)


def test_dry_run_counts_match_apply_and_write_nothing(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=CUTOFF - timedelta(days=1))  # would expire
    add(factory, "2.2.2.2", last=NOW - timedelta(days=5), active=False)  # would be reactivated by the window
    batch = [candidate("8.8.4.4"), candidate("9.9.9.9", first=CUTOFF - timedelta(days=3))]
    dry = sync(factory, batch, apply=False)
    stored = by_value(factory)
    assert set(stored) == {"1.1.1.1", "2.2.2.2"}
    assert (stored["1.1.1.1"].is_active, stored["2.2.2.2"].is_active) == (True, False)  # dry run changed nothing
    applied = sync(factory, batch, apply=True)
    assert dry == applied == SyncSummary(created=2, created_expired=1, updated=0, unchanged=0, reactivated=1, expired=1)
    stored = by_value(factory)
    assert (stored["1.1.1.1"].is_active, stored["2.2.2.2"].is_active) == (False, True)


# --- expiry policy --------------------------------------------------------------------------------


def test_expiry_boundary_is_inclusive_of_the_cutoff(factory: sessionmaker[Session]) -> None:
    summary = sync(factory, [candidate("8.8.4.4", first=CUTOFF), candidate("9.9.9.9", first=CUTOFF - timedelta(seconds=1))])
    assert (summary.created, summary.created_expired) == (2, 1)
    stored = by_value(factory)
    assert stored["8.8.4.4"].is_active is True  # exactly 90 days old: still active
    assert stored["9.9.9.9"].is_active is False  # one second older: stored, but inactive


def test_stale_active_threatfox_rows_expire_without_deletion(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=CUTOFF - timedelta(days=10))
    add(factory, "2.2.2.2", last=CUTOFF + timedelta(days=1))
    summary = sync(factory, [candidate("8.8.4.4")])
    assert summary.expired == 1
    stored = by_value(factory)
    assert (stored["1.1.1.1"].is_active, stored["2.2.2.2"].is_active, stored["8.8.4.4"].is_active) == (False, True, True)
    assert len(rows(factory)) == 3  # nothing deleted


def test_expiry_never_touches_other_sources(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", source="NETRA Demo Feed", last=CUTOFF - timedelta(days=400))  # stale but active
    add(factory, "2.2.2.2", source="NETRA Demo Feed", last=NOW - timedelta(days=1), active=False)  # fresh but inactive
    add(factory, "1.1.1.1", source=THREATFOX_SOURCE, last=CUTOFF - timedelta(days=1))
    add(factory, "2.2.2.2", source=THREATFOX_SOURCE, last=NOW - timedelta(days=1), active=False)
    summary = sync(factory, [])
    assert (summary.expired, summary.reactivated) == (1, 1)  # ThreatFox rows only
    demo = by_value(factory, "NETRA Demo Feed")
    assert (demo["1.1.1.1"].is_active, demo["2.2.2.2"].is_active) == (True, False)
    threatfox = by_value(factory)
    assert (threatfox["1.1.1.1"].is_active, threatfox["2.2.2.2"].is_active) == (False, True)


def test_expired_indicators_reappearing_with_a_fresh_date_are_reactivated(factory: sessionmaker[Session]) -> None:
    add(factory, "8.8.4.4", last=CUTOFF - timedelta(days=30), active=False)
    summary = sync(factory, [candidate("8.8.4.4", first=NOW - timedelta(hours=2))])
    assert (summary.reactivated, summary.updated, summary.expired) == (1, 1, 0)
    row = by_value(factory)["8.8.4.4"]
    assert row.is_active is True and row.last_seen.astimezone(UTC) == NOW - timedelta(hours=2)


def test_reappearing_with_only_a_stale_date_does_not_revive(factory: sessionmaker[Session]) -> None:
    add(factory, "8.8.4.4", last=CUTOFF - timedelta(days=30), active=False)
    summary = sync(factory, [candidate("8.8.4.4", first=CUTOFF - timedelta(days=5))])
    assert (summary.reactivated, summary.expired) == (0, 0)
    assert by_value(factory)["8.8.4.4"].is_active is False


def test_an_active_row_reported_with_a_stale_date_expires_once(factory: sessionmaker[Session]) -> None:
    add(factory, "8.8.4.4", last=CUTOFF - timedelta(days=2), active=True)
    summary = sync(factory, [candidate("8.8.4.4", first=CUTOFF - timedelta(days=4))])
    assert (summary.expired, summary.updated) == (1, 1)  # counted once, not again by the sweep
    assert by_value(factory)["8.8.4.4"].is_active is False


def test_expiry_window_is_configurable_within_bounds(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=NOW - timedelta(days=40))
    assert sync(factory, [], days=60).expired == 0
    assert sync(factory, [], days=30).expired == 1
    for invalid in (0, 181):
        with pytest.raises(ValueError):
            sync(factory, [], days=invalid)


def test_lowering_then_raising_the_window_reconciles_without_new_reports(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=NOW - timedelta(days=40))
    add(factory, "2.2.2.2", last=NOW - timedelta(days=10))
    lowered = sync(factory, [], days=30)
    assert (lowered.expired, lowered.reactivated) == (1, 0)
    assert {v: r.is_active for v, r in by_value(factory).items()} == {"1.1.1.1": False, "2.2.2.2": True}
    raised = sync(factory, [], days=60)
    assert (raised.expired, raised.reactivated) == (0, 1)  # no fresh report needed
    assert {v: r.is_active for v, r in by_value(factory).items()} == {"1.1.1.1": True, "2.2.2.2": True}
    # Running again changes nothing: the state depends only on the date, the window and the clock.
    again = sync(factory, [], days=60)
    assert (again.expired, again.reactivated) == (0, 0)


def test_reconciliation_boundary_is_inclusive_for_rows_not_in_the_response(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=CUTOFF, active=False)
    add(factory, "2.2.2.2", last=CUTOFF - timedelta(seconds=1), active=True)
    summary = sync(factory, [])
    assert (summary.reactivated, summary.expired) == (1, 1)
    stored = by_value(factory)
    assert (stored["1.1.1.1"].is_active, stored["2.2.2.2"].is_active) == (True, False)


def test_untrustworthy_future_dates_are_never_treated_as_fresh(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=NOW + timedelta(days=3), active=True)
    add(factory, "2.2.2.2", last=NOW + timedelta(days=3), active=False)
    add(factory, "3.3.3.3", last=NOW + timedelta(hours=23), active=False)  # within the 24-hour skew: trusted
    summary = sync(factory, [])
    stored = by_value(factory)
    assert (stored["1.1.1.1"].is_active, stored["2.2.2.2"].is_active, stored["3.3.3.3"].is_active) == (False, False, True)
    assert (summary.expired, summary.reactivated) == (1, 1)


def test_missing_dates_are_never_fresh() -> None:
    window = window_for(NOW, DEFAULT_EXPIRY_DAYS)
    assert window.fresh(None) is False
    assert window.fresh(CUTOFF) is True and window.fresh(CUTOFF - timedelta(microseconds=1)) is False
    assert window.fresh(NOW.replace(tzinfo=None)) is True  # a naive stored value is read as UTC


# --- source isolation -----------------------------------------------------------------------------


def test_other_sources_are_never_touched_and_nothing_is_deleted(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        session.add(ThreatIndicator(value="8.8.4.4", indicator_type=IndicatorType.IP, source="NETRA Demo Feed", confidence=0.95, severity=Severity.CRITICAL, is_active=True))
        session.commit()
    add(factory, "1.1.1.1", last=T0)
    summary = sync(factory, [candidate("8.8.4.4")])
    assert summary.created == 1  # same value, different source: a separate, attributed row
    demo = by_value(factory, "NETRA Demo Feed")["8.8.4.4"]
    assert (demo.confidence, demo.severity, demo.is_active) == (0.95, Severity.CRITICAL, True)
    # Absent from this response but still within the window: kept and active.
    assert by_value(factory)["1.1.1.1"].is_active is True
    assert len(rows(factory)) == 3


# --- manual command --------------------------------------------------------------------------------


def run_command(factory: sessionmaker[Session], argv: list[str], *, url=LOCAL, records: list[Any] | None = None, environ: dict[str, str] | None = None) -> tuple[int, list[str], list[tuple[str | None, int]]]:  # type: ignore[no-untyped-def]
    lines: list[str] = []
    calls: list[tuple[str | None, int]] = []

    def fetch(key: str | None, days: int) -> list[Any]:
        calls.append((key, days))
        return records if records is not None else []

    code = command.main(argv, database=(url, factory), api_key=DUMMY_KEY, fetch=fetch, environ=environ or {}, out=lines.append, now=NOW)
    return code, lines, calls


def threatfox_records() -> list[dict[str, Any]]:
    base = {"confidence_level": 80, "first_seen": "2026-10-23 10:00:00 UTC", "last_seen": None, "is_compromised": False}
    return [
        {**base, "ioc_type": "ip:port", "ioc": "8.8.4.4:443"},
        {**base, "ioc_type": "ip:port", "ioc": "8.8.4.4:8443"},
        {**base, "ioc_type": "domain", "ioc": "evil.example"},
        {**base, "ioc_type": "domain", "ioc": "hijacked.example", "is_compromised": True},
        {**base, "ioc_type": "ip:port", "ioc": "10.0.0.5:80"},
        {**base, "ioc_type": "cve", "ioc": "CVE-2024-0001"},
    ]


def test_command_dry_run_writes_nothing_and_prints_aggregates_only(factory: sessionmaker[Session]) -> None:
    code, lines, calls = run_command(factory, [], records=threatfox_records())
    assert code == 0
    assert calls == [(DUMMY_KEY, 1)]
    output = "\n".join(lines)
    assert "target: localhost:5432/netra_e2e" in output
    assert "6 received, 2 mappable" in output
    assert "received by ThreatFox type: ip:port 3, domain 2, cve 1" in output
    assert "mappable by NETRA type: ip 1, domain 1" in output
    assert "is_compromised: true 1, false 5, missing 0" in output
    for reason in ("skipped compromised_asset: 1", "skipped non_public_ip: 1", "skipped unsupported_type: 1"):
        assert reason in output
    assert "Dry run (nothing written): 2 new" in output
    assert "expiry (90 days): 0 expired, 0 reactivated, 0 new already outside the window" in output
    for secret in (DUMMY_KEY, "secret", "8.8.4.4", "evil.example", "hijacked.example"):
        assert secret not in output
    assert rows(factory) == []


def test_command_apply_writes_to_a_confirmed_local_target(factory: sessionmaker[Session]) -> None:
    code, lines, _ = run_command(factory, ["--apply", "--confirm-target", "localhost:5432/netra_e2e"], records=threatfox_records())
    assert code == 0 and "Applied: 2 new" in "\n".join(lines)
    assert sorted(r.value for r in rows(factory)) == ["8.8.4.4", "evil.example"]


def test_command_expiry_days_override(factory: sessionmaker[Session]) -> None:
    add(factory, "1.1.1.1", last=NOW - timedelta(days=40))
    lines: list[str] = []
    code = command.main([], database=(LOCAL, factory), api_key=DUMMY_KEY, fetch=lambda key, days: [], environ={}, out=lines.append, now=NOW, expiry_days=30)
    assert code == 0 and "expiry (30 days): 1 expired" in "\n".join(lines)
    assert by_value(factory)["1.1.1.1"].is_active is True  # dry run: nothing written


@pytest.mark.parametrize(
    ("url", "argv", "environ", "reason"),
    [
        (LOCAL, ["--apply"], {}, "--confirm-target must equal localhost:5432/netra_e2e"),
        (LOCAL, ["--apply", "--confirm-target", "localhost:5432/netra"], {}, "--confirm-target must equal"),
        (REMOTE, ["--apply", "--confirm-target", "db.example.com:5432/netra"], {}, "runs only against the local netra_e2e database"),
        (LOCAL, ["--apply", "--confirm-target", "localhost:5432/netra_e2e"], {"PGHOST": "elsewhere"}, "unset PGHOST"),
        (make_url("postgresql+psycopg://u:p@localhost:5432/netra_e2e?host=elsewhere"), ["--apply", "--confirm-target", "localhost:5432/netra_e2e"], {}, "can redirect it (host)"),
    ],
)
def test_command_refuses_unsafe_writes_before_fetching(factory: sessionmaker[Session], url, argv, environ, reason) -> None:  # type: ignore[no-untyped-def]
    code, lines, calls = run_command(factory, argv, url=url, records=threatfox_records(), environ=environ)
    assert code == 1 and reason in "\n".join(lines)
    assert calls == []  # refused before ThreatFox is called
    assert rows(factory) == []


def test_command_reports_threatfox_failures_without_the_key(factory: sessionmaker[Session]) -> None:
    from app.services.threatfox import ThreatFoxError

    lines: list[str] = []

    def failing(key: str | None, days: int) -> list[Any]:
        raise ThreatFoxError("auth", "ThreatFox rejected the API key (HTTP 401)")

    code = command.main([], database=(LOCAL, factory), api_key=DUMMY_KEY, fetch=failing, environ={}, out=lines.append, now=NOW)
    output = "\n".join(lines)
    assert code == 1 and "[auth]" in output and "nothing was written" in output and DUMMY_KEY not in output


def test_command_reads_a_saved_fixture_without_calling_threatfox(factory: sessionmaker[Session], tmp_path: Path) -> None:
    saved = tmp_path / "get_iocs.json"
    saved.write_text(json.dumps({"query_status": "ok", "data": threatfox_records()}), encoding="utf-8")
    code, lines, calls = run_command(factory, ["--fixture", str(saved)])
    assert code == 0 and calls == [] and "saved fixture" in "\n".join(lines)


def test_command_days_outside_1_to_7_are_refused(factory: sessionmaker[Session]) -> None:
    code, lines, calls = run_command(factory, ["--days", "8"])
    assert code == 1 and calls == [] and "--days must be from 1 to 7" in "\n".join(lines)


def test_mapping_and_sync_compose(factory: sessionmaker[Session]) -> None:
    mapped = map_iocs(threatfox_records(), now=NOW)
    summary = sync(factory, mapped.indicators)
    assert summary.created == 2
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ThreatIndicator).where(ThreatIndicator.source == THREATFOX_SOURCE)) == 2


# --- local-only target guard (both modes) ----------------------------------------------------------

NEON = make_url("postgresql+psycopg://owner:secret@ep-example-123.eu-central-1.aws.neon.tech:5432/neondb")


class NoConnection:
    """A session factory that fails the test if the command ever tries to open a database session."""

    def __init__(self) -> None:
        self.opened = 0

    def __call__(self):  # type: ignore[no-untyped-def]
        self.opened += 1
        raise AssertionError("a refused run must not open a database session")


class FakeSession:
    """Answers the post-connect identity query with a chosen server identity; records everything else."""

    def __init__(self, database: str, address: str | None) -> None:
        self.identity = (database, address)
        self.statements: list[str] = []
        self.committed = False

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, statement):  # type: ignore[no-untyped-def]
        self.statements.append(str(statement))
        identity = self.identity
        return type("Result", (), {"one": staticmethod(lambda: identity)})()

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        pass


def guarded_run(argv: list[str], url, factory, environ: dict[str, str] | None = None) -> tuple[int, str, list[int]]:  # type: ignore[no-untyped-def]
    lines: list[str] = []
    calls: list[int] = []

    def fetch(key: str | None, days: int) -> list[Any]:
        calls.append(days)
        return []

    code = command.main(argv, database=(url, factory), api_key=DUMMY_KEY, fetch=fetch, environ=environ or {}, out=lines.append, now=NOW)
    return code, "\n".join(lines), calls


@pytest.mark.parametrize(
    "url",
    [
        NEON,
        REMOTE,
        make_url("postgresql+psycopg://user:secret@10.0.0.5:5432/netra_e2e"),
        make_url("postgresql+psycopg://user:secret@localhost:5432/netra"),  # the developer database
        make_url("postgresql+psycopg://user:secret@localhost:5432/neondb"),
        make_url("postgresql+psycopg://user:secret@/netra_e2e"),  # no host: a Unix socket or libpq default
        make_url("sqlite:///netra_e2e"),
    ],
)
@pytest.mark.parametrize("argv", [[], ["--apply", "--confirm-target", "localhost:5432/netra_e2e"]])
def test_non_local_or_wrong_targets_are_refused_before_any_connection_or_request(url, argv) -> None:  # type: ignore[no-untyped-def]
    factory = NoConnection()
    code, output, calls = guarded_run(argv, url, factory)
    assert code == 1
    assert "runs only against the local netra_e2e database" in output and "nothing was fetched or written" in output
    assert calls == [] and factory.opened == 0
    assert "secret" not in output and "owner" not in output


@pytest.mark.parametrize(
    ("url", "environ", "reason"),
    [
        (make_url("postgresql+psycopg://u:p@localhost:5432/netra_e2e?host=ep-example-123.neon.tech"), {}, "can redirect it (host)"),
        (make_url("postgresql+psycopg://u:p@localhost:5432/netra_e2e?hostaddr=10.0.0.5"), {}, "can redirect it (hostaddr)"),
        (make_url("postgresql+psycopg://u:p@localhost:5432/netra_e2e?dbname=neondb"), {}, "can redirect it (dbname)"),
        (make_url("postgresql+psycopg://u:p@localhost:5432/netra_e2e?service=prod"), {}, "can redirect it (service)"),
        (LOCAL, {"PGHOST": "ep-example-123.neon.tech"}, "unset PGHOST"),
        (LOCAL, {"PGDATABASE": "neondb"}, "unset PGDATABASE"),
        (LOCAL, {"PGSERVICE": "prod"}, "unset PGSERVICE"),
    ],
)
def test_dry_run_refuses_redirected_or_conflicting_configuration(url, environ, reason) -> None:  # type: ignore[no-untyped-def]
    factory = NoConnection()
    code, output, calls = guarded_run([], url, factory, environ)
    assert code == 1 and reason in output
    assert calls == [] and factory.opened == 0


def test_settings_resolving_to_neon_are_refused_before_an_engine_is_created(monkeypatch: pytest.MonkeyPatch) -> None:
    engines: list[object] = []
    calls: list[int] = []
    monkeypatch.setattr(command, "load_settings", lambda: (NEON, DUMMY_KEY, DEFAULT_EXPIRY_DAYS))
    monkeypatch.setattr(command, "create_engine", lambda *args, **kwargs: engines.append(args) or pytest.fail("no engine may be created"))
    lines: list[str] = []
    code = command.main([], fetch=lambda key, days: calls.append(days) or [], environ={}, out=lines.append, now=NOW)
    output = "\n".join(lines)
    assert code == 1 and "runs only against the local netra_e2e database" in output
    assert "ep-example-123.eu-central-1.aws.neon.tech:5432/neondb" in output and "secret" not in output
    assert engines == [] and calls == []


def test_a_valid_local_target_passes_the_guard() -> None:
    for url in (
        LOCAL,
        make_url("postgresql+psycopg://user:secret@127.0.0.1:5432/netra_e2e"),
        make_url("postgresql+psycopg://user:secret@[::1]:5432/netra_e2e"),
    ):
        assert command.target_refusal(url, {}) is None, url
    assert command.write_refusal(LOCAL, "localhost:5432/netra_e2e", {}) is None
    assert command.write_refusal(LOCAL, "LOCALHOST:5432/netra_e2e", {}) is None  # host is case-insensitive


def test_apply_still_needs_its_confirmation_and_it_cannot_authorise_a_remote_target() -> None:
    assert command.write_refusal(LOCAL, None, {}) == "--confirm-target must equal localhost:5432/netra_e2e"
    assert command.write_refusal(LOCAL, "localhost:5432/netra", {}) == "--confirm-target must equal localhost:5432/netra_e2e"
    # A confirmation matching a remote target exactly still refuses: the target checks come first.
    assert "runs only against the local netra_e2e database" in (command.write_refusal(NEON, "ep-example-123.eu-central-1.aws.neon.tech:5432/neondb", {}) or "")


@pytest.mark.parametrize(
    ("identity", "reason"),
    [
        (("neondb", "::1"), "the connected database is not netra_e2e"),
        (("netra_e2e", "10.20.30.40"), "did not answer on a loopback address"),
        (("netra_e2e", None), "did not answer on a loopback address"),  # e.g. a Unix-socket connection
    ],
)
@pytest.mark.parametrize("argv", [[], ["--apply", "--confirm-target", "localhost:5432/netra_e2e"]])
def test_a_server_that_is_not_the_local_netra_e2e_is_refused_before_any_request(identity, reason, argv) -> None:  # type: ignore[no-untyped-def]
    session = FakeSession(*identity)
    code, output, calls = guarded_run(argv, LOCAL, lambda: session)
    assert code == 1 and reason in output and "nothing was fetched or written" in output
    assert calls == [] and session.committed is False
    # Only the read-only setting (dry run) and the identity query ran: nothing was read or written.
    assert all("threat_indicators" not in statement for statement in session.statements)


def test_the_real_local_test_database_passes_the_identity_check(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        assert command.connected_refusal(session) is None
