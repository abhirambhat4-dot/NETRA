"""Guarded pytest launcher for NETRA's isolated ``netra_e2e`` database.

Paths are derived from this file's location (backend/scripts/). The child's working directory is a
dedicated folder under the system temporary directory, never inside the repository, and nothing is
written to the repository. Run it from backend/ with the project virtual environment, always with
``-I -B``:

    .\\.venv\\Scripts\\python.exe -I -B scripts\\netra_e2e_pytest.py selftest   # synthetic inputs only; reads no credential file
    .\\.venv\\Scripts\\python.exe -I -B scripts\\netra_e2e_pytest.py check      # validates backend/.env.e2e; offline
    .\\.venv\\Scripts\\python.exe -I -B scripts\\netra_e2e_pytest.py run [--path P] [-x] [-q] [-v] [-k EXPR]

Prerequisite: backend/.env.e2e and the local netra_e2e database, prepared with scripts/netra_e2e.py
(check, create-db, init-schema, stamp).

Modes
-----
selftest  Exercises every guard against synthetic configurations. Runs under the offline guard, and
          the repo guard's file loaders are replaced so no real .env file can be read.
check     Runs backend/scripts/netra_e2e.py's ``load()``/``validate_config()`` plus the extra checks
          below, builds the child environment and simulates the child's settings resolution. Runs
          under the offline guard: Python sockets, DNS lookups, subprocesses and psycopg connections
          raise, and ``app.db.session`` is never imported. Locality cannot be proven offline, so check
          reports it as unproven instead of passing it.
run       Everything ``check`` does, then proves the target is local (see "Port forwarding"), then
          starts pytest in a child process that re-validates everything before importing pytest.

Configuration-loading order (run)
---------------------------------
1. The parent reads backend/.env.e2e (and backend/.env, for comparison only) via the repo guard.
2. The child environment is the parent's environment with every ``PG*`` variable, PYTEST_ADDOPTS,
   PYTEST_PLUGINS, PYTHONPATH/HOME/STARTUP/USERBASE, and every inherited NETRA settings key that
   .env.e2e does not define removed; then *every* .env.e2e key is applied on top.
3. The child runs with ``python -I -B`` (PYTHON* variables, user site and the script directory are
   ignored) in a dedicated empty directory, so pydantic-settings' ``env_file=".env"`` finds nothing:
   backend/.env is never read by the child, and settings come only from the environment built in 2.
4. Before pytest is imported the child re-runs the repo guard, checks its own environment matches
   .env.e2e exactly, resolves ``get_settings()`` and ``app.db.session.engine`` and compares both to the
   validated URL, then performs the single locality probe described below.
5. pytest is started with an empty ``-c`` ini, ``--rootdir``/``--confcutdir`` pinned to backend/ and
   the cache plugin disabled, so no stray ini, conftest or addopts can redirect it.

Port forwarding
---------------
A URL naming localhost:5432 cannot, on its own, distinguish a local PostgreSQL server from an SSH
tunnel, WSL/Docker relay or other forward listening on that port. ``run`` therefore fails closed
unless both of these hold:
* (parent and child, from the OS tables, no connection) every listener on the target port is a
  local process named ``postgres.exe`` (the postmaster, possibly sharing its listen sockets with
  postgres.exe children), and at least one listener is bound to loopback or the wildcard address; and
* (child, one connection through the exact engine the tests use) ``current_database()`` is
  netra_e2e, ``inet_server_addr()`` is loopback, ``inet_server_port()`` is the target port, and
  ``pg_backend_pid()`` is a local ``postgres.exe`` process whose parent is one of those listeners.
Processes are identified through Win32_Process, whose name and parent PID are readable without
administrator rights. The PostgreSQL service runs under another account, so Windows usually hides
its executable path from a standard user; whenever the path *is* visible it must also equal
``postgres.exe`` in the configured bin directory. A tunnel, relay or remote server fails at least
one of these. A PostgreSQL server running in Docker or WSL is refused too; that is deliberate.
"""

import argparse
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
GUARD_SCRIPT = BACKEND / "scripts" / "netra_e2e.py"
VENV = BACKEND / ".venv"
TESTS = BACKEND / "tests"
# The child's working directory: outside the repository, so no project .env can ever be in reach.
RUN_DIR = Path(tempfile.gettempdir()).resolve() / "netra_e2e_pytest_run"
RUN_INI_NAME = "pytest.ini"
RUN_INI_TEXT = "[pytest]\n"
ALLOWED_PORTS = frozenset({5432})
DEFAULT_PORT = 5432
LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1"})
WILDCARD_ADDRESSES = frozenset({"0.0.0.0", "::"})
CHILD_MARKER = "NETRA_E2E_PYTEST_CHILD"
# sys.modules name of the in-process proof that tests/_launch_guard.py requires; must match it.
PROOF_MODULE = "netra_e2e_launch_proof"
# Removed from the child environment in addition to the repo guard's LIBPQ_VARIABLES and every PG* key.
STRIPPED_KEYS = frozenset(
    {"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", CHILD_MARKER}
)
# .env.e2e may not define these: they would re-inject libpq, pytest or interpreter settings.
FORBIDDEN_E2E_PREFIXES = ("PG", "PYTEST", "PYTHON", CHILD_MARKER)
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


class LaunchError(Exception):
    pass


class OfflineViolation(LaunchError):
    pass


_guard: ModuleType | None = None


def load_guard() -> ModuleType:
    """Import backend/scripts/netra_e2e.py by path (read-only) so its guards are reused, not copied."""
    global _guard
    if _guard is None:
        spec = importlib.util.spec_from_file_location("netra_e2e_guard", GUARD_SCRIPT)
        if spec is None or spec.loader is None:
            raise LaunchError(f"cannot load {GUARD_SCRIPT}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if Path(module.BACKEND).resolve() != BACKEND.resolve():
            raise LaunchError("the repo guard resolves a different backend directory")
        _guard = module
    return _guard


def refusal_types() -> tuple[type[BaseException], ...]:
    return (LaunchError, load_guard().GuardError) if _guard is not None else (LaunchError,)


def require_venv() -> None:
    if Path(sys.prefix).resolve() != VENV.resolve():
        raise LaunchError(f"run this with {VENV / 'Scripts' / 'python.exe'}")
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise LaunchError("run this with python -I -B")


def backend_on_path() -> None:
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))


def settings_class() -> type:
    backend_on_path()
    from app.core.config import Settings  # pydantic only; nothing connects

    return Settings


def settings_fields(settings: type) -> frozenset[str]:
    return frozenset(name.upper() for name in settings.model_fields)


# --- Static checks ---------------------------------------------------------------------------------


def extra_checks(e2e: Mapping[str, str | None], url: Any) -> None:
    """Checks on top of the repo guard's validate_config(), which has already passed for ``url``."""
    forbidden = sorted(key for key in e2e if key.upper().startswith(FORBIDDEN_E2E_PREFIXES))
    if forbidden:
        raise LaunchError(f".env.e2e must not define {', '.join(forbidden)}")
    if (url.port or DEFAULT_PORT) not in ALLOWED_PORTS:
        allowed = ", ".join(str(port) for port in sorted(ALLOWED_PORTS))
        raise LaunchError(f"DATABASE_URL port must be one of: {allowed}")


def validated_target() -> tuple[dict[str, str | None], Any]:
    guard = load_guard()
    e2e, url = guard.load()  # reads backend/.env.e2e and backend/.env; runs validate_config()
    extra_checks(e2e, url)
    return e2e, url


def child_environment(e2e: Mapping[str, str | None], fields: frozenset[str]) -> tuple[dict[str, str], list[str]]:
    """The child's complete environment, and the names of the inherited keys that were removed."""
    inherited = set(os.environ)
    env = load_guard().child_env(dict(e2e))  # drops LIBPQ_VARIABLES, then applies every .env.e2e key
    e2e_upper = {key.upper() for key in e2e}
    removed = sorted(key for key in inherited if key not in env)
    for key in list(env):
        upper = key.upper()
        if key in e2e:
            continue
        if upper.startswith("PG") or upper in STRIPPED_KEYS or upper in e2e_upper or upper in fields:
            del env[key]
            removed.append(key)
    env[CHILD_MARKER] = "1"
    return env, sorted(set(removed))


def assert_child_env(env: Mapping[str, str], e2e: Mapping[str, str | None]) -> None:
    mismatched = sorted(key for key, value in e2e.items() if env.get(key) != (value or ""))
    if mismatched:
        raise LaunchError(f"child environment does not carry .env.e2e exactly (keys: {', '.join(mismatched)})")
    leaked = sorted(key for key in env if key.upper().startswith("PG") or (key.upper() in STRIPPED_KEYS and key != CHILD_MARKER))
    if leaked:
        raise LaunchError(f"child environment still carries {', '.join(leaked)}")
    uppers = [key.upper() for key in env]
    duplicated = sorted({key for key in uppers if uppers.count(key) > 1})
    if duplicated:
        raise LaunchError(f"child environment has case-duplicated keys: {', '.join(duplicated)}")


def resolved_settings_url(env: Mapping[str, str], settings: type) -> Any:
    """What the child's get_settings() resolves when no .env file is in reach (its working directory)."""
    from sqlalchemy.engine import make_url

    with mock.patch.dict(os.environ, env, clear=True):
        resolved = settings(_env_file=None)
    return make_url(resolved.database_url.get_secret_value())


def check_run_dir(run_dir: Path) -> str:
    """The child's working directory may hold only the launcher's empty pytest.ini, never a .env."""
    if run_dir.resolve().is_relative_to(REPOSITORY.resolve()):
        raise LaunchError(f"{run_dir} is inside the repository; the run directory must be outside it")
    if not run_dir.exists():
        return "absent"
    if not run_dir.is_dir():
        raise LaunchError(f"{run_dir} is not a directory")
    entries = sorted(entry.name for entry in run_dir.iterdir())
    if entries not in ([], [RUN_INI_NAME]):
        raise LaunchError(f"{run_dir} must contain only {RUN_INI_NAME} (found: {', '.join(entries)})")
    ini = run_dir / RUN_INI_NAME
    if ini.exists() and ini.read_text(encoding="utf-8") != RUN_INI_TEXT:
        raise LaunchError(f"{ini} has unexpected content")
    return "clean"


def prepare_run_dir(run_dir: Path) -> None:
    check_run_dir(run_dir)
    run_dir.mkdir(exist_ok=True)
    ini = run_dir / RUN_INI_NAME
    if not ini.exists():
        ini.write_text(RUN_INI_TEXT, encoding="utf-8")
    check_run_dir(run_dir)


def build_pytest_args(
    run_dir: Path, paths: list[str], *, exitfirst: bool = False, quiet: bool = False, verbose: bool = False,
    keyword: str | None = None,
) -> list[str]:
    targets = []
    for raw in paths:
        file_part, separator, node = raw.partition("::")
        candidate = Path(file_part)
        resolved = Path(os.path.abspath(candidate if candidate.is_absolute() else BACKEND / candidate))
        if not resolved.is_relative_to(TESTS):
            raise LaunchError(f"--path must be inside {TESTS}: {raw}")
        targets.append(f"{resolved}{separator}{node}")
    if keyword is not None and (not keyword.strip() or keyword.lstrip().startswith("-")):
        raise LaunchError("-k needs an expression that does not start with '-'")
    args = [
        "-c", str(run_dir / RUN_INI_NAME),
        "--rootdir", str(BACKEND),
        "--confcutdir", str(BACKEND),
        "-p", "no:cacheprovider",
    ]
    args += [flag for flag, on in (("-x", exitfirst), ("-q", quiet), ("-v", verbose)) if on]
    if keyword is not None:
        args += ["-k", keyword]
    return args + (targets or [str(TESTS)])


# --- Locality (run mode only) ----------------------------------------------------------------------


def expected_postgres(pg_bin: Path) -> str:
    return os.path.normcase(os.path.abspath(pg_bin / "postgres.exe"))


def is_local_postgres(process: Mapping[str, Any], pg_bin: Path) -> bool:
    """Named postgres.exe; and, when Windows exposes the executable path, it is the configured one."""
    if str(process.get("name") or "").lower() != "postgres.exe":
        return False
    path = str(process.get("path") or "")
    return not path or os.path.normcase(os.path.abspath(path)) == expected_postgres(pg_bin)


def verify_listeners(records: list[dict[str, Any]], port: int, pg_bin: Path) -> frozenset[int]:
    """Every listener on ``port`` is a local postgres.exe, one reachable on loopback; returns their PIDs.

    Usually that is the postmaster alone; PostgreSQL on Windows may also hand its listen sockets to
    child processes, which are postgres.exe as well.
    """
    if not records:
        raise LaunchError(f"nothing is listening on port {port}; is the local PostgreSQL service running?")
    for record in records:
        if not is_local_postgres(record, pg_bin):
            raise LaunchError(
                f"port {port} has a listener that is not the local postgres.exe "
                f"(pid {record.get('pid')}: {record.get('name') or 'unidentified'}); refusing, since it could be a port forward"
            )
    pids = frozenset(int(record.get("pid") or 0) for record in records)
    if 0 in pids:
        raise LaunchError(f"a listener on port {port} has no owning process; refusing")
    if not any(record.get("address") in LOOPBACK_ADDRESSES | WILDCARD_ADDRESSES for record in records):
        raise LaunchError(f"no postgres.exe listener on port {port} is bound to loopback")
    return pids


def verify_backend(
    database: str, address: str | None, server_port: int | None, backend: Mapping[str, Any], *, port: int,
    pg_bin: Path, listener_pids: frozenset[int],
) -> None:
    guard = load_guard()
    if database != guard.E2E_DATABASE:
        raise LaunchError("connected database is not netra_e2e")
    if address not in LOOPBACK_ADDRESSES:
        raise LaunchError("the server did not accept the connection on a loopback address")
    if server_port != port:
        raise LaunchError("the server reports a different port; refusing, since it could be a port forward")
    if not is_local_postgres(backend, pg_bin):
        raise LaunchError("the connection's backend PID is not a local postgres.exe process")
    if int(backend.get("parent") or 0) not in listener_pids:
        raise LaunchError("the connection's backend process is not a child of the postmaster listening on the port")


def powershell(script: str) -> str:
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if completed.returncode != 0:
        raise LaunchError(f"local process inspection failed (exit code {completed.returncode})")
    return completed.stdout.strip()


def parse_json_rows(output: str) -> list[dict[str, Any]]:
    try:
        rows = json.loads(output or "[]")
    except json.JSONDecodeError:
        raise LaunchError("could not read the local process tables") from None
    rows = rows if isinstance(rows, list) else [rows]
    if not all(isinstance(row, dict) for row in rows):
        raise LaunchError("could not read the local process tables")
    return rows


def query_listeners(port: int) -> list[dict[str, Any]]:
    """Reads the OS listener and process tables; opens no socket."""
    script = (
        "$ErrorActionPreference = 'Stop'; "
        f"$rows = @(Get-NetTCPConnection -State Listen -LocalPort {int(port)} -ErrorAction SilentlyContinue | "
        "ForEach-Object { $p = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$_.OwningProcess); "
        "[pscustomobject]@{ address = [string]$_.LocalAddress; pid = [int]$_.OwningProcess; "
        "name = [string]$p.Name; path = [string]$p.ExecutablePath } }); "
        "ConvertTo-Json -InputObject $rows -Compress"
    )
    return parse_json_rows(powershell(script))


def query_process(pid: int) -> dict[str, Any]:
    script = (
        "$ErrorActionPreference = 'Stop'; "
        f"$rows = @(Get-CimInstance Win32_Process -Filter 'ProcessId = {int(pid)}' | ForEach-Object {{ "
        "[pscustomobject]@{ pid = [int]$_.ProcessId; parent = [int]$_.ParentProcessId; "
        "name = [string]$_.Name; path = [string]$_.ExecutablePath } }); "
        "ConvertTo-Json -InputObject $rows -Compress"
    )
    rows = parse_json_rows(powershell(script))
    return rows[0] if len(rows) == 1 else {}


# --- Offline guard ---------------------------------------------------------------------------------


@contextmanager
def offline_guard() -> Iterator[list[str]]:
    """Make any network, subprocess or PostgreSQL connection attempt raise, and record it."""
    import psycopg

    attempts: list[str] = []

    def blocker(name: str) -> Callable[..., Any]:
        def blocked(*_args: Any, **_kwargs: Any) -> Any:
            attempts.append(name)
            raise OfflineViolation(f"{name} is blocked in offline mode")

        return blocked

    targets: list[tuple[Any, str, bool]] = [
        (socket, "socket", False), (socket, "create_connection", False), (socket, "getaddrinfo", False),
        (socket, "socketpair", False), (subprocess, "Popen", False), (os, "system", False),
        (psycopg, "connect", False), (psycopg.Connection, "connect", True), (psycopg.AsyncConnection, "connect", True),
    ]
    saved = []
    for owner, name, on_class in targets:
        present = name in vars(owner)
        saved.append((owner, name, present, vars(owner).get(name)))
        replacement = blocker(f"{getattr(owner, '__name__', owner)}.{name}")
        setattr(owner, name, staticmethod(replacement) if on_class else replacement)
    try:
        yield attempts
    finally:
        for owner, name, present, original in reversed(saved):
            if present:
                setattr(owner, name, original)
            else:
                delattr(owner, name)


# --- Modes -----------------------------------------------------------------------------------------


def default_pg_bin() -> Path:
    """Same default and NETRA_PG_BIN override as backend/scripts/netra_e2e.py's --pg-bin."""
    return Path(os.environ.get("NETRA_PG_BIN", load_guard().DEFAULT_PG_BIN))


def check_main(pg_bin: Path | None) -> int:
    require_venv()
    with offline_guard() as attempts:
        guard = load_guard()
        pg_bin = pg_bin or default_pg_bin()
        e2e, url = validated_target()
        print(f"target ok: {guard.describe(url)}")
        print("static guards passed: driver, host, database name, credentials, no query options, port, "
              "every backend/.env key defined, JWT separation, no PG*/PYTEST*/PYTHON* keys in .env.e2e")
        settings = settings_class()
        env, removed = child_environment(e2e, settings_fields(settings))
        assert_child_env(env, e2e)
        print(f"child environment: {len(e2e)} .env.e2e keys applied; removed inherited keys: {', '.join(removed) or 'none'}")
        if resolved_settings_url(env, settings) != url:
            raise LaunchError("the child's settings would not resolve to the validated target")
        print("settings resolution: the child resolves exactly the .env.e2e DATABASE_URL with no .env file in reach")
        print(f"run directory {RUN_DIR}: {check_run_dir(RUN_DIR)}")
        print(f"pytest arguments: {' '.join(build_pytest_args(RUN_DIR, []))}")
        postgres = Path(expected_postgres(pg_bin))
        print(f"postgres.exe: {'found' if postgres.is_file() else 'NOT FOUND (run would refuse)'} at {postgres}")
        print("locality: NOT PROVEN offline. A localhost port may be a forward; run proves it from the OS "
              "listener table and the backend process before any test, or refuses.")
    if attempts:
        raise LaunchError(f"offline guard recorded attempts: {', '.join(attempts)}")
    print("offline: no socket, DNS lookup, subprocess or database connection was attempted")
    return 0


def run_main(options: argparse.Namespace) -> int:
    require_venv()
    guard = load_guard()
    e2e, url = validated_target()
    print(f"target ok: {guard.describe(url)}")
    port = url.port or DEFAULT_PORT
    if not Path(expected_postgres(options.pg_bin)).is_file():
        raise LaunchError(f"postgres.exe not found in {options.pg_bin} (pass --pg-bin)")
    listener_pids = verify_listeners(query_listeners(port), port, options.pg_bin)
    print(f"listeners on port {port}: local postgres.exe only (pids {', '.join(map(str, sorted(listener_pids)))})")
    settings = settings_class()
    env, _ = child_environment(e2e, settings_fields(settings))
    assert_child_env(env, e2e)
    if resolved_settings_url(env, settings) != url:
        raise LaunchError("the child's settings would not resolve to the validated target")
    prepare_run_dir(RUN_DIR)
    build_pytest_args(RUN_DIR, options.path, exitfirst=options.x, quiet=options.q, verbose=options.v, keyword=options.k)
    child = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_child", "--pg-bin", str(options.pg_bin)]
    child += [f"--path={path}" for path in options.path]
    child += [flag for flag, on in (("-x", options.x), ("-q", options.q), ("-v", options.v)) if on]
    if options.k is not None:
        child.append(f"-k={options.k}")
    return subprocess.run(child, cwd=RUN_DIR, env=env, check=False).returncode


def child_main(options: argparse.Namespace) -> int:
    require_venv()
    if os.environ.get(CHILD_MARKER) != "1":
        raise LaunchError("_child is started only by run")
    if Path.cwd().resolve() != RUN_DIR.resolve() or check_run_dir(RUN_DIR) != "clean" or Path(".env").exists():
        raise LaunchError("the child must run in the clean launcher directory, with no .env in reach")
    e2e, url = validated_target()
    assert_child_env(os.environ, e2e)
    port = url.port or DEFAULT_PORT
    args = build_pytest_args(RUN_DIR, options.path, exitfirst=options.x, quiet=options.q, verbose=options.v, keyword=options.k)

    backend_on_path()
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import SQLAlchemyError

    from app.core.config import get_settings

    if make_url(get_settings().database_url.get_secret_value()) != url:
        raise LaunchError("get_settings() did not resolve to the validated target")
    from app.db.session import engine  # create_engine() is lazy; this does not connect

    if engine.url != url:
        raise LaunchError("app.db.session.engine does not target the validated URL")
    listener_pids = verify_listeners(query_listeners(port), port, options.pg_bin)  # re-checked from the child
    try:
        with engine.connect() as connection:
            database, address, server_port, pid = connection.execute(
                text("SELECT current_database(), host(inet_server_addr()), inet_server_port(), pg_backend_pid()")
            ).one()
            backend = query_process(pid)  # while the backend process is certainly alive
            connection.rollback()
    except SQLAlchemyError as error:
        raise LaunchError(f"could not connect to netra_e2e ({type(error).__name__})") from None
    verify_backend(database, address, server_port, backend, port=port, pg_bin=options.pg_bin, listener_pids=listener_pids)
    print("locality proven: netra_e2e on loopback, served by the local postgres.exe")

    # In-process proof for tests/_launch_guard.py, which refuses to run tests without it. It exists only in
    # this interpreter, after every check above passed; an environment variable cannot stand in for it.
    proof = ModuleType(PROOF_MODULE)
    proof.url = url
    proof.pid = os.getpid()
    proof.locality_proven = True
    sys.modules[PROOF_MODULE] = proof

    import pytest

    return pytest.main(args)


# --- Self-test (synthetic inputs only) -------------------------------------------------------------


def _refuses(action: Callable[[], Any], refused_types: tuple[type[BaseException], ...]) -> bool:
    try:
        action()
    except refused_types:
        return True
    return False


def selftest_main() -> int:
    require_venv()
    from sqlalchemy.engine import make_url

    results: list[tuple[str, bool]] = []
    with offline_guard() as attempts:
        guard = load_guard()
        refused_types = refusal_types()

        # The offline guard itself must block before anything else is trusted.
        for name, attempt in (
            ("blocks socket.socket", lambda: socket.socket()),
            ("blocks socket.getaddrinfo", lambda: socket.getaddrinfo("localhost", 5432)),
            ("blocks subprocess", lambda: subprocess.run(["cmd", "/c", "exit"])),
            ("blocks psycopg.connect", lambda: __import__("psycopg").connect("dbname=x")),
        ):
            try:
                attempt()
                results.append((f"offline guard {name}", False))
            except OfflineViolation:
                results.append((f"offline guard {name}", True))
        attempts.clear()

        def file_read_refused(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("selftest must not read real configuration files")

        with mock.patch.object(guard, "load", file_read_refused), mock.patch.object(guard, "dotenv_values", file_read_refused):
            settings = settings_class()
            fields = settings_fields(settings)
            main_secret, e2e_secret = "m" * 40, "e" * 40  # synthetic, not real secrets
            good_url = "postgresql+psycopg://netra:synthetic-pw@127.0.0.1:5432/netra_e2e"
            main = {
                "DATABASE_URL": "postgresql+psycopg://app:synthetic-pw@ep-example.neon.tech/neondb",
                "JWT_SECRET_KEY": main_secret,
                "CORS_ORIGINS": '["http://localhost:5173"]',
            }

            def e2e(**overrides: str | None) -> dict[str, str | None]:
                values: dict[str, str | None] = {"DATABASE_URL": good_url, "JWT_SECRET_KEY": e2e_secret, "CORS_ORIGINS": main["CORS_ORIGINS"]}
                values.update(overrides)
                return values

            def validate(values: dict[str, str | None], against: dict[str, str | None] = main) -> Any:
                url = guard.validate_config(values, against)
                extra_checks(values, url)
                return url

            def accepted(name: str, action: Callable[[], Any]) -> None:
                try:
                    action()
                    results.append((name, True))
                except Exception as error:  # noqa: BLE001
                    results.append((f"{name} [{type(error).__name__}: {error}]", False))

            def refused(name: str, action: Callable[[], Any]) -> None:
                try:
                    action()
                    results.append((f"{name} [was accepted]", False))
                except refused_types:
                    results.append((name, True))
                except Exception as error:  # noqa: BLE001
                    results.append((f"{name} [{type(error).__name__}: {error}]", False))

            accepted("accepts 127.0.0.1:5432/netra_e2e", lambda: validate(e2e()))
            accepted("accepts localhost without a port (libpq default 5432)",
                     lambda: validate(e2e(DATABASE_URL="postgresql+psycopg://netra:synthetic-pw@localhost/netra_e2e")))
            for name, url in {
                "Neon host": "postgresql+psycopg://netra:pw@ep-example.neon.tech/netra_e2e",
                "remote IP": "postgresql+psycopg://netra:pw@10.0.0.5:5432/netra_e2e",
                "IPv6 loopback literal (not allowlisted)": "postgresql+psycopg://netra:pw@[::1]:5432/netra_e2e",
                "multi-host list": "postgresql+psycopg://netra:pw@localhost,evil.example/netra_e2e",
                "database netra": "postgresql+psycopg://netra:pw@127.0.0.1:5432/netra",
                "database neondb": "postgresql+psycopg://netra:pw@127.0.0.1:5432/neondb",
                "driver psycopg2": "postgresql+psycopg2://netra:pw@127.0.0.1:5432/netra_e2e",
                "bare postgresql driver": "postgresql://netra:pw@127.0.0.1:5432/netra_e2e",
                "query ?host= redirect": "postgresql+psycopg://netra:pw@127.0.0.1:5432/netra_e2e?host=evil.example",
                "query ?hostaddr= redirect": "postgresql+psycopg://netra:pw@127.0.0.1:5432/netra_e2e?hostaddr=203.0.113.9",
                "port 5433": "postgresql+psycopg://netra:pw@127.0.0.1:5433/netra_e2e",
                "port 15432 (typical tunnel)": "postgresql+psycopg://netra:pw@localhost:15432/netra_e2e",
                "non-numeric port": "postgresql+psycopg://netra:pw@127.0.0.1:abc/netra_e2e",
                "missing password": "postgresql+psycopg://netra@127.0.0.1:5432/netra_e2e",
                "password placeholder": f"postgresql+psycopg://netra:{guard.PASSWORD_PLACEHOLDER}@127.0.0.1/netra_e2e",
                "empty URL": "",
            }.items():
                refused(f"refuses {name}", lambda url=url: validate(e2e(DATABASE_URL=url)))
            refused("refuses .env.e2e missing a backend/.env key",
                    lambda: validate({k: v for k, v in e2e().items() if k != "CORS_ORIGINS"}))
            refused("refuses a JWT secret shared with backend/.env", lambda: validate(e2e(JWT_SECRET_KEY=main_secret)))
            refused("refuses backend/.env also naming netra_e2e", lambda: validate(e2e(), {**main, "DATABASE_URL": good_url}))
            for key in ("PGHOST", "PGHOSTADDR", "PGOPTIONS", "pgport", "PYTEST_ADDOPTS", "PYTHONPATH", CHILD_MARKER):
                refused(f"refuses .env.e2e defining {key}", lambda key=key: validate({**e2e(), key: "x"}))

            # Child environment: complete .env.e2e on top of a hostile parent environment.
            hostile = {
                "PATH": os.environ.get("PATH", ""), "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
                "DATABASE_URL": main["DATABASE_URL"], "JWT_SECRET_KEY": main_secret, "PGHOST": "evil.example",
                "PGHOSTADDR": "203.0.113.9", "PGOPTIONS": "-c search_path=public", "PGSSLMODE": "disable",
                "PGPASSWORD": "synthetic", "PYTEST_ADDOPTS": "--rootdir=C:\\", "PYTEST_PLUGINS": "evil",
                "PYTHONPATH": "C:\\evil", "EMAIL_HOST": "smtp.evil.example", CHILD_MARKER: "0",
            }
            values = e2e()
            with mock.patch.dict(os.environ, hostile, clear=True):
                env, removed = child_environment(values, fields)
            upper_env = {key.upper(): value for key, value in env.items()}
            accepted("child env carries .env.e2e exactly", lambda: assert_child_env(env, values))
            results.append(("child env DATABASE_URL comes from .env.e2e", upper_env.get("DATABASE_URL") == good_url))
            results.append(("child env JWT_SECRET_KEY comes from .env.e2e", upper_env.get("JWT_SECRET_KEY") == e2e_secret))
            results.append(("child env has no PG* keys", not any(key.startswith("PG") for key in upper_env)))
            results.append(("child env drops PYTEST_ADDOPTS/PYTEST_PLUGINS/PYTHONPATH",
                            not {"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"} & set(upper_env)))
            results.append(("child env drops inherited settings not in .env.e2e (EMAIL_HOST)", "EMAIL_HOST" not in upper_env))
            results.append(("child env sets its own marker", upper_env.get(CHILD_MARKER) == "1"))
            results.append(("child env keeps PATH", "PATH" in upper_env))
            results.append(("removed-key report lists PGPASSWORD and EMAIL_HOST",
                            {"PGPASSWORD", "EMAIL_HOST"} <= {key.upper() for key in removed}))
            mixed = {**values, "Email_Host": "smtp.e2e.example"}
            with mock.patch.dict(os.environ, hostile, clear=True):
                mixed_env, _ = child_environment(mixed, fields)
            results.append(("child env keeps only the .env.e2e spelling of a case-variant key",
                            [key for key in mixed_env if key.upper() == "EMAIL_HOST"] == ["Email_Host"]))
            refused("assert_child_env refuses a leaked PGHOST", lambda: assert_child_env({**env, "PGHOST": "x"}, values))
            refused("assert_child_env refuses a changed DATABASE_URL",
                    lambda: assert_child_env({**env, "DATABASE_URL": main["DATABASE_URL"]}, values))

            # Settings precedence: environment beats a decoy .env in the working directory.
            with tempfile.TemporaryDirectory() as temp:
                decoy = Path(temp)
                (decoy / ".env").write_text(f"DATABASE_URL={main['DATABASE_URL']}\nJWT_SECRET_KEY={main_secret}\n", encoding="utf-8")
                previous = Path.cwd()
                os.chdir(decoy)
                try:
                    with mock.patch.dict(os.environ, env, clear=True):
                        from_decoy_cwd = settings()
                finally:
                    os.chdir(previous)
                results.append(("environment wins over a decoy .env (DATABASE_URL)",
                                from_decoy_cwd.database_url.get_secret_value() == good_url))
                results.append(("environment wins over a decoy .env (JWT_SECRET_KEY)",
                                from_decoy_cwd.jwt_secret_key.get_secret_value() == e2e_secret))
                results.append(("simulated child resolution equals the validated URL",
                                resolved_settings_url(env, settings) == make_url(good_url)))
                refused("refuses a run directory containing .env", lambda: check_run_dir(decoy))

            with tempfile.TemporaryDirectory() as temp:
                run_dir = Path(temp)
                results.append(("accepts an empty run directory", check_run_dir(run_dir) == "clean"))
                (run_dir / RUN_INI_NAME).write_text(RUN_INI_TEXT, encoding="utf-8")
                results.append(("accepts a run directory with only the launcher ini", check_run_dir(run_dir) == "clean"))
                (run_dir / RUN_INI_NAME).write_text("[pytest]\naddopts = --rootdir=C:\\\n", encoding="utf-8")
                refused("refuses a modified launcher ini", lambda: check_run_dir(run_dir))
                results.append(("reports a missing run directory as absent", check_run_dir(run_dir / "missing") == "absent"))
            refused("refuses a run directory inside the repository", lambda: check_run_dir(BACKEND / "tests"))
            results.append(("the run directory is outside the repository",
                            not RUN_DIR.resolve().is_relative_to(REPOSITORY.resolve())))

            # pytest arguments.
            default_args = build_pytest_args(RUN_DIR, [])
            results.append(("pytest args pin -c/--rootdir/--confcutdir and disable the cache",
                            default_args[:8] == ["-c", str(RUN_DIR / RUN_INI_NAME), "--rootdir", str(BACKEND),
                                                 "--confcutdir", str(BACKEND), "-p", "no:cacheprovider"]))
            results.append(("pytest args default to the whole backend/tests suite", default_args[-1] == str(TESTS)))
            results.append(("--path accepts the new workflow-permission tests",
                            build_pytest_args(RUN_DIR, ["tests/test_workflow_permissions.py"])[-1]
                            == str(TESTS / "test_workflow_permissions.py")))
            results.append(("--path keeps a ::node suffix",
                            build_pytest_args(RUN_DIR, ["tests/test_health_db.py::test_database_health_check"])[-1]
                            == f"{TESTS / 'test_health_db.py'}::test_database_health_check"))
            for raw in ("app", "tests/../app", "tests/../.env.e2e", r"C:\Windows", "../backend/scripts"):
                refused(f"--path refuses {raw}", lambda raw=raw: build_pytest_args(RUN_DIR, [raw]))
            refused("-k refuses an option-like expression", lambda: build_pytest_args(RUN_DIR, [], keyword="--rootdir=C:\\"))

            # Locality decisions (pure functions; synthetic listener and backend data).
            pg_bin = Path(guard.DEFAULT_PG_BIN)
            postgres = str(pg_bin / "postgres.exe")

            def listener(address: str, pid: int = 10, name: str = "postgres.exe", path: str = postgres) -> dict[str, Any]:
                return {"address": address, "pid": pid, "name": name, "path": path}

            results.append(("listeners: postgres.exe on 0.0.0.0 and :: returns the postmaster pid",
                            verify_listeners([listener("0.0.0.0"), listener("::")], 5432, pg_bin) == {10}))
            results.append(("listeners: listen sockets shared with postgres.exe children return every pid",
                            verify_listeners([listener("0.0.0.0", 10), listener("0.0.0.0", 11, path="")], 5432, pg_bin) == {10, 11}))
            accepted("listeners: postgres.exe on 127.0.0.1 (path case differs)",
                     lambda: verify_listeners([listener("127.0.0.1", path=postgres.upper())], 5432, pg_bin))
            accepted("listeners: service postgres.exe whose path Windows hides",
                     lambda: verify_listeners([listener("0.0.0.0", path="")], 5432, pg_bin))
            for name, records in {
                "an SSH forward beside postgres": [listener("0.0.0.0"), listener("127.0.0.1", 20, "ssh.exe", r"C:\Windows\System32\OpenSSH\ssh.exe")],
                "an SSH forward with a hidden path": [listener("127.0.0.1", 20, "ssh.exe", "")],
                "a WSL relay": [listener("127.0.0.1", 30, "wslrelay.exe", r"C:\Windows\System32\wslrelay.exe")],
                "a Docker proxy": [listener("0.0.0.0", 31, "com.docker.backend.exe", "")],
                "postgres.exe from another directory": [listener("127.0.0.1", 40, path=r"C:\Temp\postgres.exe")],
                "an unidentified process": [listener("127.0.0.1", 4, "", "")],
                "a postgres.exe-named forward among real listeners": [listener("0.0.0.0"), listener("127.0.0.1", 12, path=r"C:\Tools\postgres.exe")],
                "a listener with no pid": [listener("127.0.0.1", 0)],
                "no listener": [],
                "postgres only on a LAN address": [listener("192.168.1.5")],
            }.items():
                refused(f"listeners: refuses {name}", lambda records=records: verify_listeners(records, 5432, pg_bin))

            def process(name: str = "postgres.exe", parent: int = 10, path: str = postgres) -> dict[str, Any]:
                return {"pid": 99, "parent": parent, "name": name, "path": path}

            listeners = frozenset({10})
            accepted("backend: netra_e2e via 127.0.0.1, child of the postmaster",
                     lambda: verify_backend("netra_e2e", "127.0.0.1", 5432, process(), port=5432, pg_bin=pg_bin, listener_pids=listeners))
            accepted("backend: netra_e2e via ::1 with the path hidden",
                     lambda: verify_backend("netra_e2e", "::1", 5432, process(path=""), port=5432, pg_bin=pg_bin, listener_pids=listeners))
            for name, row in {
                "another database": ("netra", "127.0.0.1", 5432, process()),
                "a non-loopback server address": ("netra_e2e", "10.0.0.5", 5432, process()),
                "a missing server address": ("netra_e2e", None, 5432, process()),
                "a different server port": ("netra_e2e", "127.0.0.1", 6543, process()),
                "a backend pid that is not postgres.exe": ("netra_e2e", "127.0.0.1", 5432, process("svchost.exe", path="")),
                "postgres.exe from another directory": ("netra_e2e", "127.0.0.1", 5432, process(path=r"C:\Temp\postgres.exe")),
                "a postgres.exe of another postmaster": ("netra_e2e", "127.0.0.1", 5432, process(parent=77)),
                "a backend pid with no local process": ("netra_e2e", "127.0.0.1", 5432, {}),
            }.items():
                refused(f"backend: refuses {name}",
                        lambda row=row: verify_backend(*row, port=5432, pg_bin=pg_bin, listener_pids=listeners))
            results.append(("process-table parser refuses non-JSON output",
                            _refuses(lambda: parse_json_rows("not json"), refused_types)))
            results.append(("process-table parser refuses non-object rows",
                            _refuses(lambda: parse_json_rows("[1, 2]"), refused_types)))
            results.append(("process-table parser wraps a single object", parse_json_rows('{"pid": 1}') == [{"pid": 1}]))

    results.append(("no network, subprocess or connection attempt after the guard probes", not attempts))
    failed = [name for name, ok in results if not ok]
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guarded pytest launcher for the isolated netra_e2e database.")
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("selftest", help="synthetic checks only; offline")
    modes.add_parser("check", help="validate backend/.env.e2e; offline").add_argument("--pg-bin", type=Path)
    for name in ("run", "_child"):
        mode = modes.add_parser(name, help="prove locality, then run pytest" if name == "run" else argparse.SUPPRESS)
        mode.add_argument("--pg-bin", type=Path)
        mode.add_argument("--path", action="append", default=[], help="test file or node, relative to backend/")
        mode.add_argument("-x", action="store_true")
        mode.add_argument("-q", action="store_true")
        mode.add_argument("-v", action="store_true")
        mode.add_argument("-k")
    options = parser.parse_args(argv)
    try:
        require_venv()
        if options.mode in ("run", "_child") and options.pg_bin is None:
            options.pg_bin = default_pg_bin()
        if options.mode == "selftest":
            return selftest_main()
        if options.mode == "check":
            return check_main(options.pg_bin)
        if options.mode == "run":
            return run_main(options)
        return child_main(options)
    except refusal_types() as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
