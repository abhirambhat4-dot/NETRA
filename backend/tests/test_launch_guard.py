"""The test-suite launcher guard and the Alembic migration guard: synthetic inputs only, no connections."""

import re
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy.engine import make_url

from app.db.migration_guard import CONFIRM_ENV, migration_refusal
from tests._launch_guard import CHILD_MARKER, PROOF_MODULE, launcher_refusal, target_refusal

BACKEND = Path(__file__).resolve().parents[1]
E2E = make_url("postgresql+psycopg://e2e:secret@localhost:5432/netra_e2e")
NEON = make_url("postgresql+psycopg://owner:secret@ep-example-123.eu-central-1.aws.neon.tech:5432/neondb")
MARKED = {CHILD_MARKER: "1"}


def proof(url=E2E, pid: int = 4242, locality_proven: bool = True) -> SimpleNamespace:  # type: ignore[no-untyped-def]
    return SimpleNamespace(url=url, pid=pid, locality_proven=locality_proven)


# --- launcher guard -------------------------------------------------------------------------------


def test_a_validated_launch_passes() -> None:
    assert launcher_refusal(MARKED, proof(), 4242) is None
    assert target_refusal(MARKED, proof(), E2E, E2E) is None
    assert target_refusal(MARKED, proof(), E2E, None) is None


def test_the_environment_marker_alone_is_not_enough() -> None:
    assert launcher_refusal({}, proof(), 4242) == "not started by the guarded launcher"
    assert launcher_refusal({CHILD_MARKER: "0"}, proof(), 4242) == "not started by the guarded launcher"
    assert launcher_refusal(MARKED, None, 4242) == "no validated-target proof from the launcher in this process"
    assert launcher_refusal(MARKED, proof(pid=1), 4242) == "the launcher's proof belongs to another process"
    assert launcher_refusal(MARKED, proof(locality_proven=False), 4242) == "the launcher did not prove the database is local"


def test_only_the_local_netra_e2e_target_is_accepted() -> None:
    for url in (
        NEON,
        make_url("postgresql+psycopg://e2e:secret@localhost:5432/netra"),
        make_url("postgresql+psycopg://e2e:secret@10.0.0.5:5432/netra_e2e"),
        make_url("postgresql://e2e:secret@localhost:5432/netra_e2e"),
        make_url("postgresql+psycopg://e2e:secret@localhost:5432/netra_e2e?host=elsewhere"),
    ):
        assert launcher_refusal(MARKED, proof(url=url), 4242) == "the launcher's target is not the local netra_e2e database", url


def test_a_shell_database_url_or_env_file_cannot_redirect_the_tests() -> None:
    # The settings are resolved again in the test process; any difference from the validated URL refuses.
    assert target_refusal(MARKED, proof(), NEON, None) == "settings resolve to a different database than the launcher validated"
    assert target_refusal(MARKED, proof(), E2E, NEON) == "app.db.session.engine targets a different database than the launcher validated"
    assert "libpq variables" in (target_refusal({**MARKED, "PGHOST": "elsewhere"}, proof(), E2E, E2E) or "")


def test_the_guard_runs_before_any_test_code_and_matches_the_launcher() -> None:
    init = (BACKEND / "tests" / "__init__.py").read_text(encoding="utf-8")
    assert re.search(r"^from tests\._launch_guard import enforce\n\nenforce\(\)$", init, re.M)
    conftest = (BACKEND / "tests" / "conftest.py").read_text(encoding="utf-8")
    first_import = next(line for line in conftest.splitlines() if line.startswith(("import ", "from ")))
    assert first_import.startswith("import tests")
    assert conftest.index("import tests") < conftest.index("from app.db.session import engine")
    launcher = (BACKEND / "scripts" / "netra_e2e_pytest.py").read_text(encoding="utf-8")
    assert f'PROOF_MODULE = "{PROOF_MODULE}"' in launcher
    # The proof is registered only after locality is proven, and before pytest starts.
    assert launcher.index('print("locality proven') < launcher.index("sys.modules[PROOF_MODULE] = proof") < launcher.index("return pytest.main(args)")
    guard = (BACKEND / "tests" / "_launch_guard.py").read_text(encoding="utf-8")
    module_imports = [line for line in guard.splitlines() if line.startswith(("import ", "from "))]
    assert not [line for line in module_imports if "app" in line.split()[1] or "sqlalchemy" in line]


# --- Alembic guard --------------------------------------------------------------------------------


def test_local_migrations_are_allowed_as_before() -> None:
    for host in ("localhost", "127.0.0.1", "LOCALHOST"):
        assert migration_refusal(make_url(f"postgresql+psycopg://u:p@{host}:5432/netra"), {}) is None
    assert migration_refusal(E2E, {}) is None


def test_remote_migrations_need_the_exact_target_confirmed() -> None:
    refusal = migration_refusal(NEON, {}) or ""
    assert "is not a local database" in refusal and CONFIRM_ENV in refusal and "secret" not in refusal and "owner" not in refusal
    assert migration_refusal(NEON, {CONFIRM_ENV: "ep-example-123.eu-central-1.aws.neon.tech:5432/other"}) is not None
    assert migration_refusal(NEON, {CONFIRM_ENV: "ep-example-123.eu-central-1.aws.neon.tech:5432/neondb"}) is None


def test_redirecting_options_and_variables_are_always_refused() -> None:
    assert "can redirect it (host)" in (migration_refusal(make_url("postgresql+psycopg://u:p@localhost:5432/netra?host=elsewhere"), {}) or "")
    assert "unset PGHOST" in (migration_refusal(E2E, {"PGHOST": "elsewhere"}) or "")
    assert migration_refusal(make_url("sqlite:///netra.db"), {}) is not None


def test_alembic_checks_the_guard_before_creating_an_engine() -> None:
    env = (BACKEND / "migrations" / "env.py").read_text(encoding="utf-8")
    online = env[env.index("def run_migrations_online"):]
    assert online.index("migration_refusal(url, os.environ)") < online.index("sys.exit(") < online.index("engine_from_config(")
