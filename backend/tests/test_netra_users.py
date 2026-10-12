"""backend/scripts/netra_users.py against SQLite only: the in-memory user store, or a throwaway file under
pytest's tmp_path.

``create_engine`` is replaced in every test (refusing, or recording the URL and serving the SQLite file),
so no command can open a connection to a real database.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker

from app.core.permissions import Role
from app.models.user import User
from app.services.auth import create_access_token, hash_password, verify_password
from scripts import netra_users

# A stand-in target: describes and confirms like a real one, but every session comes from SQLite.
DB = "netra_cli_test"
TARGET = URL.create(
    "postgresql+psycopg", username="cli_user", password="cli-target-secret", host="db.internal", port=5432, database=DB
)
CONFIRM = "db.internal:5432/netra_cli_test"  # the printed target line, as an operator would copy it
EMAIL = "ana.admin@example.com"
PASSWORD = "cli-password-123"


@pytest.fixture(autouse=True)
def no_real_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> None:
        raise AssertionError("netra_users tried to create a real database engine")

    monkeypatch.setattr(netra_users, "create_engine", refuse)


def prompts(*answers: str) -> Any:
    remaining: Iterator[str] = iter(answers)
    asked: list[str] = []

    def prompt(label: str) -> str:
        asked.append(label)
        return next(remaining)

    prompt.asked = asked  # type: ignore[attr-defined]
    return prompt


def run(auth_db: sessionmaker[Session], *argv: str, prompt: Any = None) -> int:
    # An empty environment: no PG* variable on the test host can change the outcome.
    return netra_users.main(list(argv), database=(TARGET, auth_db), prompt=prompt or prompts(), environ={})


def stored(auth_db: sessionmaker[Session], email: str = EMAIL) -> User | None:
    with auth_db() as session:
        return session.scalar(select(User).where(User.email == email))


def add_user(auth_db: sessionmaker[Session], *, role: str = "operator", active: bool = True) -> User:
    with auth_db() as session:
        user = User(email=EMAIL, full_name="Ana Admin", password_hash=hash_password(PASSWORD), role=role, is_active=active)
        session.add(user)
        session.commit()
        return user


def assert_no_secrets(output: str) -> None:
    for secret in (PASSWORD, "cli-target-secret", "cli_user", "$argon2"):
        assert secret not in output


def test_describe_shows_only_host_port_and_database() -> None:
    assert netra_users.describe(TARGET) == "db.internal:5432/netra_cli_test"


def test_create_makes_an_active_account_with_a_hashed_password(
    auth_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    prompt = prompts(PASSWORD, PASSWORD)

    code = run(auth_db, "create", "--email", " Ana.Admin@Example.com ", "--name", "Ana Admin", "--role", "admin",
               "--confirm-target", CONFIRM, prompt=prompt)

    user = stored(auth_db)
    out = capsys.readouterr()
    assert code == 0
    assert user is not None and user.role == "admin" and user.is_active
    assert user.password_hash != PASSWORD and verify_password(PASSWORD, user.password_hash)
    assert prompt.asked == ["Password (hidden): ", "Repeat password: "]
    assert "target: db.internal:5432/netra_cli_test" in out.out
    assert_no_secrets(out.out + out.err)


@pytest.mark.parametrize("role", [role.value for role in Role])
def test_create_accepts_every_canonical_role(auth_db: sessionmaker[Session], role: str) -> None:
    code = run(auth_db, "create", "--email", EMAIL, "--name", "Ana", "--role", role, "--confirm-target", CONFIRM,
               prompt=prompts(PASSWORD, PASSWORD))

    assert code == 0
    assert stored(auth_db).role == role


@pytest.mark.parametrize("role", ["viewer", "Admin", "superuser", ""])
def test_unknown_roles_are_rejected(auth_db: sessionmaker[Session], role: str) -> None:
    add_user(auth_db)
    with pytest.raises(SystemExit) as create_exit:
        run(auth_db, "create", "--email", "x@example.com", "--name", "X", "--role", role, "--confirm-target", CONFIRM)
    with pytest.raises(SystemExit) as set_role_exit:
        run(auth_db, "set-role", "--email", EMAIL, "--role", role, "--confirm-target", CONFIRM)

    assert create_exit.value.code == set_role_exit.value.code == 2
    assert stored(auth_db, "x@example.com") is None
    assert stored(auth_db).role == "operator"


def test_password_is_never_an_argument(auth_db: sessionmaker[Session]) -> None:
    with pytest.raises(SystemExit):
        run(auth_db, "create", "--email", EMAIL, "--name", "Ana", "--role", "admin", "--confirm-target", CONFIRM,
            "--password", PASSWORD)

    assert stored(auth_db) is None


@pytest.mark.parametrize(
    ("answers", "reason"),
    [((PASSWORD, "different-password-1"), "do not match"), (("short", "short"), "password")],
)
def test_create_refuses_mismatched_or_weak_passwords(
    auth_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str], answers: tuple[str, str], reason: str
) -> None:
    code = run(auth_db, "create", "--email", EMAIL, "--name", "Ana", "--role", "admin", "--confirm-target", CONFIRM,
               prompt=prompts(*answers))

    err = capsys.readouterr().err
    assert code == 1
    assert reason in err
    assert all(answer not in err for answer in answers)
    assert stored(auth_db) is None


def test_create_refuses_a_duplicate_email(auth_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]) -> None:
    add_user(auth_db)

    code = run(auth_db, "create", "--email", EMAIL.upper(), "--name", "Copy", "--role", "admin",
               "--confirm-target", CONFIRM, prompt=prompts(PASSWORD, PASSWORD))

    assert code == 1
    assert "already exists" in capsys.readouterr().err
    assert stored(auth_db).role == "operator"


@pytest.mark.parametrize(
    "argv",
    [
        ["create", "--email", EMAIL, "--name", "Ana", "--role", "admin"],
        ["set-role", "--email", EMAIL, "--role", "admin"],
        ["activate", "--email", EMAIL],
        ["deactivate", "--email", EMAIL],
    ],
)
@pytest.mark.parametrize(
    "confirm",
    [
        "other.internal:5432/netra_cli_test",  # same database name on a different host
        "localhost:5432/netra_cli_test",
        "db.internal:5433/netra_cli_test",  # same host and name, different port
        "db.internal:5432/netra",
        "db.internal:5432/NETRA_CLI_TEST",  # database names are case-sensitive
        "db.internal/netra_cli_test",  # port missing
        "netra_cli_test",  # the database name alone is no longer enough
        "db.internal:5432/",
        "",
    ],
)
def test_writes_need_the_exact_target_and_touch_nothing_otherwise(
    capsys: pytest.CaptureFixture[str], argv: list[str], confirm: str
) -> None:
    def unused_factory() -> Session:
        raise AssertionError("a session was opened without a matching --confirm-target")

    prompt = prompts()
    code = netra_users.main(
        [*argv, "--confirm-target", confirm], database=(TARGET, unused_factory), prompt=prompt, environ={}
    )

    assert code == 1
    assert "--confirm-target does not match the target host:port/database" in capsys.readouterr().err
    assert prompt.asked == []


@pytest.mark.parametrize("confirm", [CONFIRM, "DB.Internal:5432/netra_cli_test", f"  {CONFIRM} "])
def test_the_matching_target_is_accepted_with_a_case_insensitive_host(
    auth_db: sessionmaker[Session], confirm: str
) -> None:
    add_user(auth_db)

    assert run(auth_db, "set-role", "--email", EMAIL, "--role", "approver", "--confirm-target", confirm) == 0
    assert stored(auth_db).role == "approver"


def test_the_old_name_only_flag_is_no_longer_accepted(auth_db: sessionmaker[Session]) -> None:
    add_user(auth_db)
    with pytest.raises(SystemExit) as exit_info:
        run(auth_db, "set-role", "--email", EMAIL, "--role", "admin", "--confirm-database", DB)

    assert exit_info.value.code == 2
    assert stored(auth_db).role == "operator"


def test_writes_without_confirm_target_are_a_usage_error(auth_db: sessionmaker[Session]) -> None:
    add_user(auth_db)
    with pytest.raises(SystemExit) as exit_info:
        run(auth_db, "set-role", "--email", EMAIL, "--role", "admin")

    assert exit_info.value.code == 2
    assert stored(auth_db).role == "operator"


@pytest.mark.parametrize(
    "url",
    [
        TARGET.set(query={"host": "elsewhere.internal"}),
        TARGET.set(query={"hostaddr": "203.0.113.7"}),
        TARGET.set(query={"port": "6543"}),
        TARGET.set(query={"dbname": "other"}),
        TARGET.set(query={"service": "prod"}),
        TARGET.set(query={"HOST": "elsewhere.internal"}),
    ],
)
def test_url_options_that_could_redirect_the_connection_are_refused(
    capsys: pytest.CaptureFixture[str], url: URL
) -> None:
    def unused_factory() -> Session:
        raise AssertionError("a session was opened for an ambiguous target")

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", CONFIRM], database=(url, unused_factory), environ={}
    )

    err = capsys.readouterr().err
    assert code == 1
    assert "connection options that can redirect it" in err
    assert "elsewhere" not in err and "203.0.113.7" not in err


def test_harmless_url_options_such_as_sslmode_are_allowed(auth_db: sessionmaker[Session]) -> None:
    add_user(auth_db)
    url = TARGET.set(query={"sslmode": "require", "channel_binding": "require"})

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", CONFIRM], database=(url, auth_db), environ={}
    )

    assert code == 0
    assert stored(auth_db).is_active is False


@pytest.mark.parametrize("name", netra_users.REDIRECTING_ENV_VARS)
def test_pg_connection_variables_are_refused(capsys: pytest.CaptureFixture[str], name: str) -> None:
    def unused_factory() -> Session:
        raise AssertionError("a session was opened while a PG* variable could redirect it")

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", CONFIRM],
        database=(TARGET, unused_factory),
        environ={name: "elsewhere.internal"},
    )

    err = capsys.readouterr().err
    assert code == 1
    assert f"unset {name} first" in err
    assert "elsewhere" not in err


def test_a_target_without_an_explicit_host_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    def unused_factory() -> Session:
        raise AssertionError("a session was opened for a target without a host")

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", f"localhost:5432/{DB}"],
        # URL.set(host=None) would keep the host, so build the host-less URL directly.
        database=(URL.create("postgresql+psycopg", username="cli_user", database=DB), unused_factory),
        environ={},
    )

    assert code == 1
    assert "must name its host and database" in capsys.readouterr().err


def test_the_configured_target_is_refused_before_any_connection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(netra_users, "settings_url", lambda: TARGET)

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", "other.internal:5432/netra_cli_test"], environ={}
    )

    out = capsys.readouterr()
    assert code == 1
    assert "target: db.internal:5432/netra_cli_test" in out.out
    assert_no_secrets(out.out + out.err)


# The effective DATABASE_URL: a shell-set variable overrides .env, exactly as the application resolves it.

SHELL_TARGET = TARGET.set(host="shell.internal", database="netra")
DOTENV_TARGET = TARGET.set(host="dotenv.internal", database="netra")


@pytest.fixture
def dotenv_dir(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A temporary working directory whose .env names DOTENV_TARGET (placeholder credentials only)."""
    (tmp_path / ".env").write_text(
        f"DATABASE_URL={DOTENV_TARGET.render_as_string(hide_password=False)}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return tmp_path


@pytest.fixture
def file_db(tmp_path: Any) -> sessionmaker[Session]:
    """A throwaway SQLite file under pytest's tmp_path; it survives the script disposing its engine."""
    engine = create_engine(f"sqlite:///{tmp_path / 'netra_users_cli.db'}")
    User.__table__.create(engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def engine_calls(monkeypatch: pytest.MonkeyPatch, file_db: sessionmaker[Session]) -> list[URL]:
    """Record the URL any engine is created for, and serve it from the throwaway SQLite file instead."""
    calls: list[URL] = []

    def record(url: URL, **_: Any) -> Any:
        calls.append(url)
        return file_db.kw["bind"]

    monkeypatch.setattr(netra_users, "create_engine", record)
    return calls


def test_dotenv_supplies_the_target_when_no_shell_variable_is_set(dotenv_dir: Any) -> None:
    assert netra_users.settings_url().host == "dotenv.internal"


def test_a_shell_database_url_overrides_dotenv(dotenv_dir: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", SHELL_TARGET.render_as_string(hide_password=False))

    assert netra_users.settings_url().host == "shell.internal"


def test_confirming_the_dotenv_target_is_refused_when_the_shell_overrides_it(
    dotenv_dir: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], engine_calls: list[URL]
) -> None:
    monkeypatch.setenv("DATABASE_URL", SHELL_TARGET.render_as_string(hide_password=False))

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", "dotenv.internal:5432/netra"], environ={}
    )

    out = capsys.readouterr()
    assert code == 1
    assert "target: shell.internal:5432/netra" in out.out
    assert engine_calls == []  # refused before any engine was created
    assert_no_secrets(out.out + out.err)


def test_confirming_the_effective_shell_target_proceeds_against_it(
    dotenv_dir: Any,
    monkeypatch: pytest.MonkeyPatch,
    file_db: sessionmaker[Session],
    engine_calls: list[URL],
) -> None:
    add_user(file_db)
    monkeypatch.setenv("DATABASE_URL", SHELL_TARGET.render_as_string(hide_password=False))

    code = netra_users.main(
        ["deactivate", "--email", EMAIL, "--confirm-target", "shell.internal:5432/netra"], environ={}
    )

    assert code == 0
    assert [(url.host, url.database) for url in engine_calls] == [("shell.internal", "netra")]
    assert stored(file_db).is_active is False


def test_set_role_applies_to_an_existing_token(auth_db: sessionmaker[Session], auth_client: TestClient) -> None:
    token = create_access_token(add_user(auth_db))

    code = run(auth_db, "set-role", "--email", EMAIL, "--role", "approver", "--confirm-target", CONFIRM)

    me = auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert code == 0
    assert me.json()["role"] == "approver"


def test_deactivate_blocks_login_and_existing_tokens_and_activate_restores_them(
    auth_db: sessionmaker[Session], auth_client: TestClient
) -> None:
    token = create_access_token(add_user(auth_db))
    headers = {"Authorization": f"Bearer {token}"}
    credentials = {"email": EMAIL, "password": PASSWORD}

    assert run(auth_db, "deactivate", "--email", EMAIL, "--confirm-target", CONFIRM) == 0
    assert auth_client.get("/api/auth/me", headers=headers).status_code == 401
    assert auth_client.post("/api/auth/login", json=credentials).status_code == 401

    assert run(auth_db, "activate", "--email", EMAIL, "--confirm-target", CONFIRM) == 0
    assert auth_client.get("/api/auth/me", headers=headers).status_code == 200
    assert auth_client.post("/api/auth/login", json=credentials).status_code == 200


def test_repeated_changes_are_reported_as_no_ops(
    auth_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    add_user(auth_db, role="approver")

    assert run(auth_db, "set-role", "--email", EMAIL, "--role", "approver", "--confirm-target", CONFIRM) == 0
    assert run(auth_db, "activate", "--email", EMAIL, "--confirm-target", CONFIRM) == 0

    out = capsys.readouterr().out
    assert "already approver; nothing changed" in out
    assert "already active; nothing changed" in out


@pytest.mark.parametrize("command", [["set-role", "--role", "admin"], ["activate"], ["deactivate"]])
def test_unknown_email_is_refused(
    auth_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    code = run(auth_db, command[0], "--email", "nobody@example.com", *command[1:], "--confirm-target", CONFIRM)

    assert code == 1
    assert "no account with this email" in capsys.readouterr().err


def test_list_is_read_only_and_never_prints_hashes(
    auth_db: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    add_user(auth_db, role="viewer", active=False)

    code = run(auth_db, "list")

    out = capsys.readouterr().out
    assert code == 0
    assert "1 account(s)" in out
    assert f"{EMAIL}  role=viewer (unrecognised: no permissions)  inactive" in out
    assert_no_secrets(out)
    assert stored(auth_db).role == "viewer"
