"""Guarded administrator commands for NETRA user accounts.

Run from backend/ with the project virtual environment:

    .\\.venv\\Scripts\\python.exe scripts\\netra_users.py list
    .\\.venv\\Scripts\\python.exe scripts\\netra_users.py create --email ana@example.com --name "Ana Admin" --role admin --confirm-target <host:port/database>
    .\\.venv\\Scripts\\python.exe scripts\\netra_users.py set-role --email ana@example.com --role approver --confirm-target <host:port/database>
    .\\.venv\\Scripts\\python.exe scripts\\netra_users.py deactivate --email ana@example.com --confirm-target <host:port/database>
    .\\.venv\\Scripts\\python.exe scripts\\netra_users.py activate --email ana@example.com --confirm-target <host:port/database>

The target is the effective database setting, resolved as the application resolves it: the
DATABASE_URL environment variable (for example one set in the current shell) wins over DATABASE_URL in
.env in the current directory. Every command first prints only `target: host:port/database`; the
connection string, user name, passwords and password hashes are never printed. Run `list` (read-only)
to see the target, then pass that exact host:port/database to --confirm-target for a write.

Before any connection is opened, a write is refused unless --confirm-target matches the target's host,
port and database, and unless that target is unambiguous: the URL must name its host, may not carry
connection options that redirect it (host, hostaddr, port, dbname, service, servicefile), and the PG*
connection variables (PGHOST, PGHOSTADDR, PGPORT, PGDATABASE, PGSERVICE, PGSERVICEFILE) must be unset.

`create` reads the password from a hidden prompt, entered twice; it is never accepted as an argument.
Roles are limited to the canonical list in app.core.permissions.
"""

import argparse
import getpass
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.engine import URL, make_url  # noqa: E402
from sqlalchemy.exc import IntegrityError, SQLAlchemyError  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from app.core.permissions import Role  # noqa: E402
from app.models.user import User  # noqa: E402
from app.schemas.auth import RegisterRequest  # noqa: E402
from app.services.auth import hash_password  # noqa: E402

ROLES = tuple(role.value for role in Role)
WRITE_COMMANDS = frozenset({"create", "set-role", "activate", "deactivate"})
DEFAULT_PORT = 5432
# libpq connection parameters that, in the URL query, override the host, port or database it names.
REDIRECTING_QUERY_KEYS = frozenset({"host", "hostaddr", "port", "dbname", "service", "servicefile"})
# libpq environment variables that can supply or redirect the host, port or database.
REDIRECTING_ENV_VARS = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE")
Prompt = Callable[[str], str]


class CommandError(Exception):
    pass


def describe(url: URL) -> str:
    """host:port/database only: never the username, password or query options."""
    return f"{url.host or 'localhost'}:{url.port or DEFAULT_PORT}/{url.database or '?'}"


def target_key(url: URL) -> tuple[str, int, str]:
    return ((url.host or "").lower(), url.port or DEFAULT_PORT, url.database or "")


def parse_confirmation(value: str) -> tuple[str, int, str] | None:
    """``host:port/database`` (host case-insensitive) as a comparable key, or None when malformed."""
    host_port, slash, database = value.strip().rpartition("/")
    host, colon, port = host_port.rpartition(":")
    if not slash or not colon or not host or not database or not port.isdigit():
        return None
    return (host.lower(), int(port), database)


def check_write_target(url: URL, confirmation: str, environ: Mapping[str, str]) -> None:
    """Refuse a write unless the target is unambiguous and ``confirmation`` names it. Never connects."""
    if not url.host or not url.database:
        raise CommandError("the target must name its host and database explicitly; nothing was changed")
    redirecting = sorted(key for key in url.query if key.lower() in REDIRECTING_QUERY_KEYS)
    if redirecting:
        raise CommandError(
            f"DATABASE_URL carries connection options that can redirect it ({', '.join(redirecting)}); nothing was changed"
        )
    set_vars = [name for name in REDIRECTING_ENV_VARS if environ.get(name)]
    if set_vars:
        raise CommandError(f"unset {', '.join(set_vars)} first: they can redirect the connection; nothing was changed")
    if parse_confirmation(confirmation) != target_key(url):
        raise CommandError(
            "--confirm-target does not match the target host:port/database printed above; nothing was changed"
        )


def settings_url() -> URL:
    # Fresh, not the cached app settings: environment variables (including a shell-set DATABASE_URL)
    # first, then .env in the current directory, exactly as the application resolves them.
    from app.core.config import Settings

    try:
        raw = Settings().database_url.get_secret_value()
    except ValidationError as error:
        # Field names only: validation messages can echo the rejected (secret) values.
        fields = sorted({".".join(str(part) for part in issue["loc"]) for issue in error.errors()})
        raise CommandError(f"settings could not be loaded (check: {', '.join(fields)})") from None
    try:
        return make_url(raw)
    except Exception:
        raise CommandError("DATABASE_URL is not a valid database URL") from None


def normalize_email(email: str) -> str:
    return email.strip().lower()


def find_user(session: Session, email: str) -> User:
    user = session.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None:
        raise CommandError("no account with this email")
    return user


def create(session: Session, options: argparse.Namespace, prompt: Prompt) -> str:
    password = prompt("Password (hidden): ")
    if prompt("Repeat password: ") != password:
        raise CommandError("the passwords do not match")
    try:
        # The same email, name and password rules as self-registration.
        request = RegisterRequest(email=options.email, full_name=options.name, password=password)
    except ValidationError as error:
        problems = "; ".join(f"{'.'.join(str(p) for p in issue['loc'])}: {issue['msg']}" for issue in error.errors())
        raise CommandError(problems) from None
    if session.scalar(select(User).where(User.email == request.email)) is not None:
        raise CommandError("an account with this email already exists")
    session.add(
        User(
            email=str(request.email),
            full_name=request.full_name,
            password_hash=hash_password(password),
            role=options.role,
            is_active=True,
        )
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise CommandError("an account with this email already exists") from None
    return f"created {request.email} (role {options.role}, active)"


def set_role(session: Session, options: argparse.Namespace) -> str:
    user = find_user(session, options.email)
    previous = user.role
    if previous == options.role:
        return f"{user.email}: role is already {previous}; nothing changed"
    user.role = options.role
    session.commit()
    return f"{user.email}: role {previous} -> {options.role} (applies to existing sessions immediately)"


def set_active(session: Session, options: argparse.Namespace, active: bool) -> str:
    user = find_user(session, options.email)
    state = "active" if active else "inactive"
    if user.is_active == active:
        return f"{user.email}: already {state}; nothing changed"
    user.is_active = active
    session.commit()
    effect = "can sign in again" if active else "can no longer sign in; existing tokens stop working"
    return f"{user.email}: now {state} ({effect})"


def list_users(session: Session) -> list[str]:
    users = session.scalars(select(User).order_by(User.email)).all()
    lines = [f"{len(users)} account(s)"]
    for user in users:
        role = user.role if user.role in ROLES else f"{user.role} (unrecognised: no permissions)"
        created = user.created_at.date().isoformat() if user.created_at else "-"
        lines.append(f"  {user.email}  role={role}  {'active' if user.is_active else 'inactive'}  created={created}")
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guarded administrator commands for NETRA user accounts.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list accounts: email, role, status (read-only)")

    def write_command(name: str, help_text: str) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--email", required=True)
        command.add_argument(
            "--confirm-target",
            required=True,
            metavar="HOST:PORT/DATABASE",
            help="must equal the 'target:' line this script prints (run 'list' to see it)",
        )
        return command

    create_command = write_command("create", "create an active account; the password is prompted for (hidden)")
    create_command.add_argument("--name", required=True, help="full name")
    create_command.add_argument("--role", required=True, choices=ROLES)
    write_command("set-role", "change an account's role").add_argument("--role", required=True, choices=ROLES)
    write_command("activate", "allow an account to sign in")
    write_command("deactivate", "block sign-in and invalidate the account's existing tokens")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    database: tuple[URL, sessionmaker[Session]] | None = None,
    prompt: Prompt = getpass.getpass,
    environ: Mapping[str, str] = os.environ,
) -> int:
    """``database`` (target URL, session factory) lets tests supply an isolated database."""
    options = build_parser().parse_args(argv)
    engine = None
    try:
        url = database[0] if database else settings_url()
        print(f"target: {describe(url)}")
        if options.command in WRITE_COMMANDS:
            # Before any engine or connection exists.
            check_write_target(url, options.confirm_target, environ)
        if database:
            factory = database[1]
        else:
            engine = create_engine(url, poolclass=NullPool)
            factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

        with factory() as session:
            if options.command == "list":
                print("\n".join(list_users(session)))
            elif options.command == "create":
                print(create(session, options, prompt))
            elif options.command == "set-role":
                print(set_role(session, options))
            else:
                print(set_active(session, options, active=options.command == "activate"))
    except CommandError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    except SQLAlchemyError as error:
        # Error type only: driver messages can echo connection details.
        print(f"REFUSED: database error ({type(error).__name__}); nothing was changed", file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
