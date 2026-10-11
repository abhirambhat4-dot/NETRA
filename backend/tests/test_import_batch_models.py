"""Import batch model and migration 0004 tests.

Each test works inside a throwaway PostgreSQL schema within a transaction that is always rolled
back, so no real NETRA tables or data are touched.
"""

import hashlib
import importlib.util
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, delete, inspect, literal_column, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import engine
from app.models import ImportBatch, User
from app.models.enums import ImportBatchStatus

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND / "migrations" / "versions" / "0004_add_import_batches.py"
NEW_TABLES = {"import_batches"}


@pytest.fixture
def db_session() -> Iterator[Session]:
    schema = f"netra_import_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            translated = connection.execution_options(schema_translate_map={None: schema})
            Base.metadata.create_all(translated)
            with Session(bind=translated, join_transaction_mode="create_savepoint") as session:
                yield session
        finally:
            transaction.rollback()


def make_batch(**overrides: Any) -> ImportBatch:
    fields: dict[str, Any] = {
        "dataset_profile": "generic-csv",
        "profile_version": "1",
        "original_filename": "flows.csv",
        "file_sha256": hashlib.sha256(b"flows").hexdigest(),
        "file_size_bytes": 5,
        "status": ImportBatchStatus.VALIDATED,
        "total_rows": 3,
        "accepted_rows": 2,
        "rejected_rows": 1,
        "error_total": 1,
        "error_sample": [{"rule": "row.column_count", "message": "m", "row": 3, "column": None, "columnIndex": None}],
        "completed_at": datetime(2026, 10, 11, 12, 0, tzinfo=UTC),
    }
    return ImportBatch(**(fields | overrides))


def test_batch_persists_and_survives_uploader_deletion(db_session: Session) -> None:
    user = User(email="importer@example.com", full_name="Importer", password_hash="unused")
    db_session.add(user)
    db_session.flush()
    db_session.add(make_batch(uploaded_by_id=user.id))
    db_session.commit()
    db_session.expunge_all()

    stored = db_session.scalars(select(ImportBatch)).one()
    assert stored.uploaded_by.email == "importer@example.com"
    assert stored.created_at is not None
    assert stored.error_sample[0]["rule"] == "row.column_count"

    db_session.execute(delete(User))
    db_session.expunge_all()
    assert db_session.scalars(select(ImportBatch)).one().uploaded_by_id is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"file_sha256": "not-a-hash"},
        {"file_sha256": hashlib.sha256(b"x").hexdigest().upper()},
        {"file_size_bytes": -1},
        {"total_rows": 4},  # accepted + rejected must equal total
        {"rejected_rows": -1, "accepted_rows": 4},
        {"error_total": -1},
    ],
)
def test_batch_constraints_are_enforced(db_session: Session, overrides: dict[str, Any]) -> None:
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(make_batch(**overrides))
        db_session.flush()


def test_status_column_rejects_unknown_values(db_session: Session) -> None:
    db_session.add(make_batch())
    db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.execute(update(ImportBatch).values(status=literal_column("'imported'")))


def test_only_validated_batches_reserve_a_file_hash(db_session: Session) -> None:
    db_session.add_all(
        [
            make_batch(status=ImportBatchStatus.REJECTED),
            make_batch(status=ImportBatchStatus.REJECTED),
            make_batch(),
            make_batch(profile_version="2"),
            make_batch(dataset_profile="other-profile"),
        ]
    )
    db_session.flush()
    with pytest.raises(IntegrityError, match="uq_import_batches_validated_file"), db_session.begin_nested():
        db_session.add(make_batch(original_filename="renamed.csv"))
        db_session.flush()


# --- Alembic migration 0004 --------------------------------------------------------------------


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0004", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_extends_the_chain_from_0003() -> None:
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0004_add_import_batches"]
    assert scripts.get_revision("0004_add_import_batches").down_revision == "0003_add_security_assessments"


@pytest.fixture
def migration_connection() -> Iterator[Connection]:
    """A connection whose search_path is a throwaway schema holding only the tables 0004 depends on."""
    schema = f"netra_migration_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            Base.metadata.create_all(connection, tables=[Base.metadata.tables["users"]])
            yield connection
        finally:
            transaction.rollback()


def _new_tables_only(_obj: Any, name: str | None, type_: str, _reflected: bool, _compare_to: Any) -> bool:
    return type_ != "table" or name in NEW_TABLES


def test_migration_matches_model_and_is_guarded(migration_connection: Connection) -> None:
    migration = _migration()
    context = MigrationContext.configure(
        migration_connection, opts={"compare_type": True, "include_object": _new_tables_only}
    )
    with Operations.context(context):
        migration.upgrade()
        # Second run is a no-op: the existence guard skips a table that already exists.
        migration.upgrade()

    inspector = inspect(migration_connection)
    assert NEW_TABLES <= set(inspector.get_table_names())
    assert compare_metadata(context, Base.metadata) == []

    model_table = Base.metadata.tables["import_batches"]
    model_checks = {constraint.name for constraint in model_table.constraints if constraint.__class__.__name__ == "CheckConstraint"}
    assert {item["name"] for item in inspector.get_check_constraints("import_batches")} == model_checks

    indexes = {index["name"]: index for index in inspector.get_indexes("import_batches")}
    assert set(indexes) == {index.name for index in model_table.indexes}
    unique_file = indexes["uq_import_batches_validated_file"]
    assert unique_file["unique"] is True
    assert unique_file["column_names"] == ["dataset_profile", "profile_version", "file_sha256"]
    assert "validated" in unique_file["dialect_options"]["postgresql_where"]


def test_migration_skips_table_created_by_init_db(migration_connection: Connection) -> None:
    Base.metadata.create_all(migration_connection, tables=[Base.metadata.tables["import_batches"]])
    with Operations.context(MigrationContext.configure(migration_connection)):
        _migration().upgrade()
    assert NEW_TABLES <= set(inspect(migration_connection).get_table_names())


def test_migration_downgrade_removes_only_the_new_table(migration_connection: Connection) -> None:
    migration = _migration()
    with Operations.context(MigrationContext.configure(migration_connection)):
        migration.upgrade()
        migration.downgrade()
    assert set(inspect(migration_connection).get_table_names()) == {"users"}
