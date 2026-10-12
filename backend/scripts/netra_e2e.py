"""Guarded commands for NETRA's isolated end-to-end database, ``netra_e2e``.

Run from backend/ with the project virtual environment:

    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py check         # validate .env.e2e; no connection
    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py create-db     # createdb netra_e2e (via the postgres maintenance DB)
    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py init-schema   # app.db.init_db into the EMPTY netra_e2e
    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py stamp         # alembic stamp head (records the version only)
    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py status        # current_database(), table count, alembic current
    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py serve         # uvicorn on 127.0.0.1:8001
    .\\.venv\\Scripts\\python.exe scripts\\netra_e2e.py drop-db --confirm netra_e2e

Every command reads only backend/.env.e2e and refuses to run unless it targets ``netra_e2e`` on
localhost. Commands that start a child process re-check the resolved settings inside that child;
commands that touch the database also check ``current_database()`` after connecting. Passwords and
secrets are never printed. Nothing here reads data from, or connects to, any other database.
"""

import argparse
import os
import socket
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError

BACKEND = Path(__file__).resolve().parents[1]
E2E_ENV_FILE = BACKEND / ".env.e2e"
MAIN_ENV_FILE = BACKEND / ".env"
E2E_DATABASE = "netra_e2e"
ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1"})
REQUIRED_DRIVER = "postgresql+psycopg"
MAINTENANCE_DATABASE = "postgres"
PASSWORD_PLACEHOLDER = "__REPLACE_WITH_URL_ENCODED_PASSWORD__"
API_HOST = "127.0.0.1"
API_PORT = 8001
DEFAULT_PG_BIN = Path(r"C:\Program Files\PostgreSQL\18\bin")
# Inherited libpq variables could redirect createdb/dropdb; they are always replaced or removed.
LIBPQ_VARIABLES = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE")


class GuardError(Exception):
    pass


def validate_config(e2e: dict[str, str | None], main: dict[str, str | None]) -> URL:
    """Static checks on the e2e settings; no connection. Returns the parsed database URL."""
    raw_url = e2e.get("DATABASE_URL") or ""
    if not raw_url:
        raise GuardError("DATABASE_URL is missing from .env.e2e")
    if PASSWORD_PLACEHOLDER in raw_url:
        raise GuardError("replace the password placeholder in .env.e2e first")
    try:
        url = make_url(raw_url)
    except Exception:
        raise GuardError("DATABASE_URL in .env.e2e is not a valid database URL") from None
    if url.drivername != REQUIRED_DRIVER:
        raise GuardError(f"DATABASE_URL must use {REQUIRED_DRIVER}")
    if url.host not in ALLOWED_HOSTS:
        raise GuardError("DATABASE_URL host must be localhost or 127.0.0.1")
    if url.database != E2E_DATABASE:
        raise GuardError(f"DATABASE_URL must name the {E2E_DATABASE} database")
    if not url.username or not url.password:
        raise GuardError("DATABASE_URL must include a username and password")
    if url.query:
        raise GuardError("DATABASE_URL must not carry query options (they could redirect the connection)")

    main_url = main.get("DATABASE_URL")
    if main_url and make_url(main_url).database == E2E_DATABASE:
        raise GuardError("backend/.env also names netra_e2e; refusing an ambiguous setup")

    secret = e2e.get("JWT_SECRET_KEY") or ""
    if len(secret) < 32:
        raise GuardError("JWT_SECRET_KEY in .env.e2e must be at least 32 characters")
    if secret == main.get("JWT_SECRET_KEY"):
        raise GuardError("JWT_SECRET_KEY in .env.e2e must differ from backend/.env")

    # Settings fall back to backend/.env for any key .env.e2e leaves out, so every key must be defined here.
    missing = sorted(key for key in main if key not in e2e)
    if missing:
        raise GuardError(f".env.e2e must define every key in backend/.env (missing: {', '.join(missing)})")
    return url


def load() -> tuple[dict[str, str | None], URL]:
    if not E2E_ENV_FILE.is_file():
        raise GuardError(f"{E2E_ENV_FILE.name} not found in backend/")
    e2e = dotenv_values(E2E_ENV_FILE)
    main = dotenv_values(MAIN_ENV_FILE) if MAIN_ENV_FILE.is_file() else {}
    return e2e, validate_config(e2e, main)


def describe(url: URL) -> str:
    return f"{url.username}@{url.host}:{url.port or 5432}/{url.database}"


def child_env(e2e: dict[str, str | None]) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in LIBPQ_VARIABLES}
    env.update({key: value or "" for key, value in e2e.items()})
    return env


def run_child(args: list[str], e2e: dict[str, str | None]) -> None:
    # Re-resolve the settings inside a child with the same environment, without connecting.
    probe = (
        "from sqlalchemy.engine import make_url; from app.core.config import get_settings; "
        "u = make_url(get_settings().database_url.get_secret_value()); print(u.host, u.database)"
    )
    resolved = subprocess.run(
        [sys.executable, "-c", probe], cwd=BACKEND, env=child_env(e2e), capture_output=True, text=True, check=False
    )
    host, _, database = resolved.stdout.strip().partition(" ")
    if resolved.returncode != 0 or host not in ALLOWED_HOSTS or database != E2E_DATABASE:
        raise GuardError("the child process did not resolve to localhost/netra_e2e; refusing to run")
    completed = subprocess.run(args, cwd=BACKEND, env=child_env(e2e), check=False)
    if completed.returncode != 0:
        raise GuardError(f"command failed with exit code {completed.returncode}")


def connected_database(url: URL) -> tuple[str, int]:
    """Connect to netra_e2e only; returns current_database() and the number of public tables."""
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            name = connection.scalar(text("SELECT current_database()"))
            tables = connection.scalar(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
            )
    except SQLAlchemyError as error:
        # Error type only: driver messages can echo connection details.
        raise GuardError(f"could not connect to {E2E_DATABASE} ({type(error).__name__}); was create-db run?") from None
    finally:
        engine.dispose()
    if name != E2E_DATABASE:
        raise GuardError("connected database is not netra_e2e; refusing to continue")
    return name, int(tables or 0)


def pg_tool(name: str, url: URL, extra: list[str], pg_bin: Path) -> None:
    executable = pg_bin / f"{name}.exe" if os.name == "nt" else pg_bin / name
    if not executable.is_file():
        raise GuardError(f"{name} not found in {pg_bin} (pass --pg-bin)")
    env = {key: value for key, value in os.environ.items() if key not in LIBPQ_VARIABLES}
    env["PGPASSWORD"] = url.password or ""  # passed to the child only; never printed
    args = [
        str(executable),
        "--host", url.host or "localhost",
        "--port", str(url.port or 5432),
        "--username", url.username or "",
        f"--maintenance-db={MAINTENANCE_DATABASE}",
        "--no-password",
        *extra,
        E2E_DATABASE,  # a constant, never taken from configuration
    ]
    completed = subprocess.run(args, env=env, check=False)
    if completed.returncode != 0:
        raise GuardError(f"{name} failed with exit code {completed.returncode}")


def port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((host, port)) != 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guarded commands for the isolated netra_e2e database.")
    parser.add_argument(
        "command", choices=["check", "create-db", "init-schema", "stamp", "status", "serve", "drop-db"]
    )
    parser.add_argument("--confirm", help="drop-db only: must be exactly netra_e2e")
    parser.add_argument("--pg-bin", type=Path, default=Path(os.environ.get("NETRA_PG_BIN", DEFAULT_PG_BIN)))
    options = parser.parse_args(argv)

    try:
        e2e, url = load()
        print(f"target ok: {describe(url)}")
        command = options.command
        if command == "check":
            print("static checks passed; no database connection was made")
        elif command == "create-db":
            pg_tool("createdb", url, [], options.pg_bin)
            print(f"created {E2E_DATABASE}")
        elif command == "init-schema":
            _, tables = connected_database(url)
            if tables:
                raise GuardError(f"{E2E_DATABASE} is not empty ({tables} tables); init-schema expects a new database")
            run_child([sys.executable, "-m", "app.db.init_db"], e2e)
        elif command == "stamp":
            _, tables = connected_database(url)
            if tables == 0:
                raise GuardError("run init-schema before stamp")
            run_child([sys.executable, "-m", "alembic", "stamp", "head"], e2e)
        elif command == "status":
            name, tables = connected_database(url)
            print(f"current_database={name} public_tables={tables}")
            run_child([sys.executable, "-m", "alembic", "current"], e2e)
        elif command == "serve":
            connected_database(url)
            if not port_is_free(API_HOST, API_PORT):
                raise GuardError(f"port {API_PORT} is already in use")
            print(f"frontend: $env:VITE_API_BASE_URL = 'http://{API_HOST}:{API_PORT}'; npm run dev")
            run_child([sys.executable, "-m", "uvicorn", "app.main:app", "--host", API_HOST, "--port", str(API_PORT)], e2e)
        elif command == "drop-db":
            if options.confirm != E2E_DATABASE:
                raise GuardError(f"drop-db requires --confirm {E2E_DATABASE}")
            pg_tool("dropdb", url, ["--if-exists"], options.pg_bin)
            print(f"dropped {E2E_DATABASE}")
    except GuardError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
