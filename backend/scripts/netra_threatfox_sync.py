"""Manual ThreatFox (abuse.ch) sync into NETRA's threat_indicators.

Run from backend/ with the project virtual environment:

    .\\.venv\\Scripts\\python.exe scripts\\netra_threatfox_sync.py                      # dry run: fetch, map, count; writes nothing
    .\\.venv\\Scripts\\python.exe scripts\\netra_threatfox_sync.py --fixture saved.json # dry run from a saved response; no network
    .\\.venv\\Scripts\\python.exe scripts\\netra_threatfox_sync.py --apply --confirm-target localhost:5432/netra_e2e

ThreatFox ``get_iocs`` returns indicators reported in the last ``--days`` (1-7, default 1). This is a
recent-history import run on demand, not real-time monitoring. Indicators are attributed to
"ThreatFox (abuse.ch)" and are reference data for matching events, never observed NETRA security events.

Only records whose is_compromised is exactly false are imported; true, missing and unrecognized flags are
skipped and counted. Every sync sets each ThreatFox indicator active exactly when its latest ThreatFox date is
within THREATFOX_EXPIRY_DAYS (default 90); inactive indicators stop matching and are never deleted. See
docs/THREAT_INTEL_THREATFOX.md.

The key comes only from THREATFOX_AUTH_KEY (environment or backend/.env); it is sent as the Auth-Key
header and is never printed, logged or stored. Output is counts only, never indicator values.

The target database is resolved exactly as the application resolves it (a shell DATABASE_URL, then
.env in the current directory) and printed as host:port/database only. In BOTH modes the command runs
only against the local netra_e2e database and fails closed otherwise:

1. before any connection or ThreatFox request, the URL must be PostgreSQL on localhost/127.0.0.1/::1 with
   database netra_e2e, carry no URL options that could redirect the connection, and no libpq redirect
   variable (PGHOST, PGHOSTADDR, PGPORT, PGDATABASE, PGSERVICE, PGSERVICEFILE) may be set;
2. after connecting, and still before any ThreatFox request, the server must report current_database()
   netra_e2e on a loopback address (this catches a port forward or tunnel on localhost).

--apply additionally needs --confirm-target equal to the printed target; it never authorizes a target the
checks above refuse. The dry run uses a read-only transaction that is rolled back. Launch through
scripts/netra_e2e.py's load()/run_child() so .env.e2e supplies the settings.
"""

import argparse
import os
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import URL, make_url  # noqa: E402
from sqlalchemy.exc import SQLAlchemyError  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from app.services.threatfox import (  # noqa: E402
    MAX_DAYS,
    MAX_RESPONSE_BYTES,
    MIN_DAYS,
    THREATFOX_SOURCE,
    ThreatFoxError,
    fetch_recent_iocs,
    map_iocs,
    parse_response_body,
)
from app.services.threatfox_sync import DEFAULT_EXPIRY_DAYS, THREATFOX_SEVERITY, sync_indicators  # noqa: E402

DEFAULT_PORT = 5432
#: The only database this command reads or writes.
E2E_DATABASE = "netra_e2e"
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1"})
REDIRECTING_QUERY_KEYS = frozenset({"host", "hostaddr", "port", "dbname", "service", "servicefile"})
REDIRECTING_ENV_VARS = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE")
Fetch = Callable[[str | None, int], list[Any]]


class CommandError(Exception):
    pass


def describe(url: URL) -> str:
    """host:port/database only: never the username, password or query options."""
    return f"{url.host or '?'}:{url.port or DEFAULT_PORT}/{url.database or '?'}"


def target_refusal(url: URL, environ: Mapping[str, str]) -> str | None:
    """Why ``url`` may not be used at all (dry run or apply), or None. Never connects."""
    if url.get_backend_name() != "postgresql" or (url.host or "").lower() not in LOCAL_HOSTS or url.database != E2E_DATABASE:
        return f"the ThreatFox sync runs only against the local {E2E_DATABASE} database, not {describe(url)}"
    redirecting = sorted(key for key in url.query if key.lower() in REDIRECTING_QUERY_KEYS)
    if redirecting:
        return f"DATABASE_URL carries connection options that can redirect it ({', '.join(redirecting)})"
    set_vars = [name for name in REDIRECTING_ENV_VARS if environ.get(name)]
    if set_vars:
        return f"unset {', '.join(set_vars)} first: they can redirect the connection"
    return None


def write_refusal(url: URL, confirmation: str | None, environ: Mapping[str, str]) -> str | None:
    """Why a write to ``url`` is refused, or None: the target checks, then the explicit confirmation. Never connects."""
    if refusal := target_refusal(url, environ):
        return refusal
    if confirmation is None or confirmation.strip().lower() != describe(url).lower():
        return f"--confirm-target must equal {describe(url)}"
    return None


def connected_refusal(session: Session) -> str | None:
    """After connecting: why the server is not the local netra_e2e database, or None (fails closed)."""
    database, address = session.execute(text("SELECT current_database(), host(inet_server_addr())")).one()
    if database != E2E_DATABASE:
        return f"the connected database is not {E2E_DATABASE}"
    if address not in LOOPBACK_ADDRESSES:
        return "the server did not answer on a loopback address (a port forward or tunnel?)"
    return None


def load_settings() -> tuple[URL, str | None, int]:
    """(target URL, ThreatFox key or None, expiry days). Fresh settings, resolved as the application resolves them."""
    from app.core.config import Settings

    try:
        settings = Settings()
    except ValidationError as error:
        # Field names only: validation messages can echo rejected (secret) values.
        fields = sorted({".".join(str(part) for part in issue["loc"]) for issue in error.errors()})
        raise CommandError(f"settings could not be loaded (check: {', '.join(fields)})") from None
    try:
        url = make_url(settings.database_url.get_secret_value())
    except Exception:
        raise CommandError("DATABASE_URL is not a valid database URL") from None
    key = settings.threatfox_auth_key.get_secret_value() if settings.threatfox_auth_key else None
    return url, key, settings.threatfox_expiry_days


def read_fixture(path: str) -> list[Any]:
    file = Path(path)
    if not file.is_file():
        raise CommandError("fixture file not found")
    if file.stat().st_size > MAX_RESPONSE_BYTES:
        raise CommandError(f"fixture exceeds {MAX_RESPONSE_BYTES} bytes")
    return parse_response_body(file.read_bytes())


def _counts(counter: Counter[str]) -> str:
    return ", ".join(f"{name} {count}" for name, count in counter.most_common()) or "none"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manual ThreatFox sync into threat_indicators (dry run by default).")
    parser.add_argument("--apply", action="store_true", help="write the indicators (default: dry run)")
    parser.add_argument("--confirm-target", metavar="HOST:PORT/DATABASE", help="required with --apply")
    parser.add_argument("--days", type=int, default=1, help=f"ThreatFox look-back window, {MIN_DAYS}-{MAX_DAYS} (default 1)")
    parser.add_argument("--fixture", metavar="PATH", help="read a saved get_iocs JSON response instead of calling ThreatFox")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    database: tuple[URL, sessionmaker[Session]] | None = None,
    api_key: str | None = None,
    fetch: Fetch = lambda key, days: fetch_recent_iocs(key, days),
    environ: Mapping[str, str] = os.environ,
    out: Callable[[str], None] = print,
    now: datetime | None = None,
    expiry_days: int | None = None,
) -> int:
    """``database`` (target URL, session factory), ``api_key``, ``fetch``, ``now`` and ``expiry_days`` let tests
    run fully offline and deterministically."""
    options = build_parser().parse_args(argv)
    engine = None
    try:
        if not MIN_DAYS <= options.days <= MAX_DAYS:
            raise CommandError(f"--days must be from {MIN_DAYS} to {MAX_DAYS}")
        if database:
            url, key, days_setting = database[0], api_key, DEFAULT_EXPIRY_DAYS
        else:
            url, settings_key, days_setting = load_settings()
            key = api_key if api_key is not None else settings_key
        expiry = expiry_days if expiry_days is not None else days_setting
        out(f"target: {describe(url)}")
        # Both modes, before any connection or ThreatFox request.
        refusal = write_refusal(url, options.confirm_target, environ) if options.apply else target_refusal(url, environ)
        if refusal:
            raise CommandError(f"{refusal}; nothing was fetched or written")

        if database:
            factory = database[1]
        else:
            engine = create_engine(url, poolclass=NullPool)
            factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        with factory() as session:
            if not options.apply:
                # Any accidental write in a dry run fails instead of committing.
                session.execute(text("SET TRANSACTION READ ONLY"))
            # Still before any ThreatFox request: prove the server is the local netra_e2e database.
            if problem := connected_refusal(session):
                raise CommandError(f"{problem}; nothing was fetched or written")

            records = read_fixture(options.fixture) if options.fixture else fetch(key, options.days)
            mapped = map_iocs(records, now=now)
            window = "saved fixture" if options.fixture else f"get_iocs days={options.days}"
            out(f"ThreatFox ({window}): {mapped.received} received, {len(mapped.indicators)} mappable indicator(s)")
            out(f"  received by ThreatFox type: {_counts(mapped.received_types)}")
            out(f"  mappable by NETRA type: {_counts(mapped.mapped_types())}")
            flags = mapped.compromised  # a Counter: absent flags read as 0
            out(f"  is_compromised: true {flags['true']}, false {flags['false']}, missing {flags['missing']}"
                + (f", unrecognized {flags['unrecognized']}" if flags["unrecognized"] else ""))
            for reason, count in sorted(mapped.skipped.items()):
                out(f"  skipped {reason}: {count}")

            summary = sync_indicators(session, mapped.indicators, apply=options.apply, now=now, expiry_days=expiry)
            if options.apply:
                session.commit()
            else:
                session.rollback()
        verb = "Applied" if options.apply else "Dry run (nothing written)"
        out(
            f"{verb}: {summary.created} new, {summary.updated} updated, {summary.unchanged} unchanged "
            f"[source {THREATFOX_SOURCE!r}; new rows get NETRA-assigned severity {THREATFOX_SEVERITY.value!r}]"
        )
        out(
            f"  expiry ({expiry} days): {summary.expired} expired, {summary.reactivated} reactivated, "
            f"{summary.created_expired} new already outside the window (stored inactive)"
        )
    except ThreatFoxError as error:
        out(f"REFUSED: {error} [{error.kind}]; nothing was written")
        return 1
    except CommandError as error:
        out(f"REFUSED: {error}")
        return 1
    except ValueError as error:
        # e.g. an expiry window outside 1-180 days; nothing was committed.
        out(f"REFUSED: {error}; nothing was written")
        return 1
    except SQLAlchemyError as error:
        # Error type only: driver messages can echo connection details.
        out(f"REFUSED: database error ({type(error).__name__}); nothing was written")
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
