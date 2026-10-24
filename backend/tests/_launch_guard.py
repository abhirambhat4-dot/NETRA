"""Fail-closed guard for the backend test suite: tests run only inside scripts/netra_e2e_pytest.py ``run``.

It is enforced from tests/__init__.py, which Python executes before it imports tests.conftest or any
tests.test_* module (also with ``--noconftest``), so no test code that creates or uses a database engine
runs until it passes. conftest.py imports the package first as well.

The environment marker alone is not trusted. All of these must hold:

1. NETRA_E2E_PYTEST_CHILD == "1" (set only in the launcher's child environment);
2. an in-process proof object, registered by the launcher's child in *this* interpreter (same PID) only
   after it validated .env.e2e, resolved settings and engine to that URL, and proved with one connection
   that the server is the local netra_e2e on loopback. A shell variable cannot create it;
3. the proof's target is postgresql+psycopg on localhost/127.0.0.1, database netra_e2e, no URL options;
4. the settings, resolved again here independently, give exactly that URL (so neither a shell
   DATABASE_URL nor any .env file can have redirected them);
5. if app.db.session is already imported, its engine targets that URL;
6. no libpq PG* variable is set (they could redirect a connection away from the URL).

Checks 1-2 run before anything from ``app`` is imported; nothing here ever opens a connection.
"""

import os
import sys
from collections.abc import Mapping
from typing import Any

CHILD_MARKER = "NETRA_E2E_PYTEST_CHILD"
#: Name of the module object the launcher's child registers in sys.modules; must match the launcher.
PROOF_MODULE = "netra_e2e_launch_proof"
E2E_DATABASE = "netra_e2e"
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
REQUIRED_DRIVER = "postgresql+psycopg"
LAUNCH_HINT = r".\.venv\Scripts\python.exe -I -B scripts\netra_e2e_pytest.py run"


def launcher_refusal(environ: Mapping[str, str], proof: Any, pid: int) -> str | None:
    """Checks 1-3; needs nothing from ``app``."""
    if environ.get(CHILD_MARKER) != "1":
        return "not started by the guarded launcher"
    if proof is None:
        return "no validated-target proof from the launcher in this process"
    if getattr(proof, "pid", None) != pid:
        return "the launcher's proof belongs to another process"
    if getattr(proof, "locality_proven", False) is not True:
        return "the launcher did not prove the database is local"
    target = getattr(proof, "url", None)
    if (
        target is None
        or getattr(target, "drivername", None) != REQUIRED_DRIVER
        or getattr(target, "host", None) not in LOCAL_HOSTS
        or getattr(target, "database", None) != E2E_DATABASE
        or getattr(target, "query", None)
    ):
        return "the launcher's target is not the local netra_e2e database"
    return None


def target_refusal(environ: Mapping[str, str], proof: Any, resolved_url: Any, engine_url: Any | None) -> str | None:
    """Checks 4-6, against the settings resolved independently by the caller."""
    if resolved_url != proof.url:
        return "settings resolve to a different database than the launcher validated"
    if engine_url is not None and engine_url != proof.url:
        return "app.db.session.engine targets a different database than the launcher validated"
    leaked = sorted(key for key in environ if key.upper().startswith("PG"))
    if leaked:
        return f"libpq variables are set ({', '.join(leaked)}); they could redirect a connection"
    return None


def refuse(reason: str) -> None:
    message = (
        f"REFUSED: backend tests run only through the guarded launcher ({reason}). "
        f"No database connection was made. Use: {LAUNCH_HINT}"
    )
    if "pytest" in sys.modules:
        import pytest

        pytest.exit(message, returncode=2)
    raise RuntimeError(message)


def enforce() -> None:
    proof = sys.modules.get(PROOF_MODULE)
    reason = launcher_refusal(os.environ, proof, os.getpid())
    if reason is None:
        # Only now import from app: resolving settings and URLs never connects.
        from sqlalchemy.engine import make_url

        from app.core.config import Settings

        resolved = make_url(Settings().database_url.get_secret_value())
        session = sys.modules.get("app.db.session")
        reason = target_refusal(os.environ, proof, resolved, getattr(getattr(session, "engine", None), "url", None))
    if reason is not None:
        refuse(reason)
