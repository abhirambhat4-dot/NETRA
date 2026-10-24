"""Guard for online Alembic runs (migrations/env.py); checked before any engine or connection exists.

Alembic resolves its database exactly as the application does: a shell DATABASE_URL first, then .env in
the current directory. A local PostgreSQL target (localhost, 127.0.0.1 or ::1) is allowed as before, which
covers developer databases and scripts/netra_e2e.py (stamp/status, run with .env.e2e). Any other host,
including Neon, is refused unless NETRA_MIGRATION_CONFIRM_TARGET names that exact host:port/database,
so a shell DATABASE_URL left pointing at production can never be migrated by accident. URL options and
libpq variables that could redirect the connection are always refused. Offline (--sql) runs never connect
and are not checked.
"""

from collections.abc import Mapping

from sqlalchemy.engine import URL

CONFIRM_ENV = "NETRA_MIGRATION_CONFIRM_TARGET"
DEFAULT_PORT = 5432
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
REDIRECTING_QUERY_KEYS = frozenset({"host", "hostaddr", "port", "dbname", "service", "servicefile"})
REDIRECTING_ENV_VARS = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE")


def describe(url: URL) -> str:
    """host:port/database only: never the username, password or query options."""
    return f"{url.host or '?'}:{url.port or DEFAULT_PORT}/{url.database or '?'}"


def migration_refusal(url: URL, environ: Mapping[str, str]) -> str | None:
    """Why an online migration against ``url`` is refused, or None. Never connects."""
    if url.get_backend_name() != "postgresql" or not url.host or not url.database:
        return "the target must be a PostgreSQL URL naming its host and database"
    redirecting = sorted(key for key in url.query if key.lower() in REDIRECTING_QUERY_KEYS)
    if redirecting:
        return f"DATABASE_URL carries connection options that can redirect it ({', '.join(redirecting)})"
    set_vars = [name for name in REDIRECTING_ENV_VARS if environ.get(name)]
    if set_vars:
        return f"unset {', '.join(set_vars)} first: they can redirect the connection"
    if url.host.lower() in LOCAL_HOSTS:
        return None
    if environ.get(CONFIRM_ENV, "").strip().lower() != describe(url).lower():
        return f"{describe(url)} is not a local database; set {CONFIRM_ENV}={describe(url)} to confirm this exact target"
    return None
