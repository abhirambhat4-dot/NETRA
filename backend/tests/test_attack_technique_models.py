"""EventAttackTechnique model and migration 0007 tests.

Each database test works inside a throwaway PostgreSQL schema within a transaction that is always rolled
back, so no real NETRA tables or data are touched. The offline test renders SQL without any connection.
"""

import importlib.util
import io
import re
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
from sqlalchemy import Connection, delete, func, insert, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateSchema

import app.models
from app.db.base import Base
from app.db.session import engine
from app.models import EventAttackTechnique
from app.models.attack_technique import ATTACK_EVIDENCE_KINDS, ATTACK_EVIDENCE_ORIGINS, TECHNIQUE_ID_PATTERN

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND / "migrations" / "versions" / "0007_event_attack_techniques.py"
REVISION = "0007_event_attack_techniques"
TABLE = "event_attack_techniques"
INDEX = "ix_event_attack_techniques_technique_id"
UNIQUE = "uq_event_attack_techniques_event_id_technique_id_evidence_kind"
# The tables 0007 depends on: security_events (created by app.db.init_db) and the tables it references.
PREREQUISITES = ("users", "assets", "import_batches", "security_events")


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0007", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scripts() -> ScriptDirectory:
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "migrations"))
    return ScriptDirectory.from_config(config)


@pytest.fixture
def empty_schema() -> Iterator[Connection]:
    """A connection whose search_path is a new, empty throwaway schema; everything is rolled back."""
    schema = f"netra_migration_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            assert connection.scalar(text("SELECT current_schema()")) == schema
            yield connection
        finally:
            transaction.rollback()


@pytest.fixture
def migration_connection(empty_schema: Connection) -> Connection:
    """The throwaway schema holding only the tables 0007 depends on."""
    Base.metadata.create_all(empty_schema, tables=[Base.metadata.tables[name] for name in PREREQUISITES])
    return empty_schema


def _new_table_only(_obj: Any, name: str | None, type_: str, _reflected: bool, _compare_to: Any) -> bool:
    return type_ != "table" or name == TABLE


def _upgraded(connection: Connection) -> Connection:
    with Operations.context(MigrationContext.configure(connection)):
        _migration().upgrade()
    return connection


def _add_event(connection: Connection) -> uuid.UUID:
    event_id = uuid.uuid4()
    connection.execute(
        insert(Base.metadata.tables["security_events"]).values(
            id=event_id,
            event_uid=f"evt-attack-{event_id.hex[:12]}",
            occurred_at=datetime(2026, 10, 25, 9, tzinfo=UTC),
            source="suricata",
            event_type="alert",
            severity="high",
        )
    )
    return event_id


def _technique(event_id: uuid.UUID, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "event_id": event_id,
        "technique_id": "T1110",
        "evidence_kind": "source_supplied",
        "evidence_origin": "ingest_field",
    }
    return values | overrides


def _count(connection: Connection) -> int:
    return connection.scalar(select(func.count()).select_from(Base.metadata.tables[TABLE]))


# --- chain and model -------------------------------------------------------------------------------


def test_0007_is_the_single_head_after_0006() -> None:
    scripts = _scripts()
    assert scripts.get_heads() == [REVISION]
    assert scripts.get_revision(REVISION).down_revision == "0006_add_risk_evaluations"
    assert len(REVISION) <= 32  # alembic_version.version_num is VARCHAR(32)


def test_earlier_migrations_are_unchanged_in_the_chain() -> None:
    scripts = _scripts()
    chain = [script.revision for script in scripts.walk_revisions("base", REVISION)]
    assert list(reversed(chain)) == [
        "0001_add_users_table",
        "0002_add_password_reset_tokens",
        "0003_add_security_assessments",
        "0004_add_import_batches",
        "0005_dataset_event_provenance",
        "0006_add_risk_evaluations",
        REVISION,
    ]


def test_the_model_is_registered_with_only_source_supplied_evidence() -> None:
    assert TABLE in Base.metadata.tables
    assert app.models.EventAttackTechnique is EventAttackTechnique and "EventAttackTechnique" in app.models.__all__
    assert ATTACK_EVIDENCE_KINDS == ("source_supplied",)
    assert ATTACK_EVIDENCE_ORIGINS == ("ingest_field", "collector_field")
    assert TECHNIQUE_ID_PATTERN == r"^T[0-9]{4}(\.[0-9]{3})?$"
    table = Base.metadata.tables[TABLE]
    (foreign_key,) = table.foreign_keys
    assert (foreign_key.column.table.name, foreign_key.ondelete) == ("security_events", "CASCADE")
    assert {index.name for index in table.indexes} == {INDEX}
    assert all(len(constraint.name) <= 63 for constraint in table.constraints if constraint.name)  # PostgreSQL limit


def test_offline_sql_creates_only_the_new_table_and_index() -> None:
    """--sql mode: rendered without any database connection."""
    buffer = io.StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buffer})
    with Operations.context(context):
        _migration().upgrade()
    sql = buffer.getvalue()
    assert sql.count("CREATE TABLE") == 1 and f"CREATE TABLE {TABLE}" in sql
    assert sql.count("CREATE INDEX") == 1 and f"CREATE INDEX {INDEX}" in sql
    # No other statement (ON DELETE CASCADE inside the CREATE TABLE is a clause, not a statement).
    assert re.findall(r"^\s*(ALTER|DROP|INSERT|UPDATE|DELETE|TRUNCATE)\b", sql, re.M) == []
    assert "REFERENCES security_events (id) ON DELETE CASCADE" in sql


# --- migration on a throwaway schema ----------------------------------------------------------------


def test_upgrade_creates_the_table_matching_the_model_and_repeating_it_is_safe(migration_connection: Connection) -> None:
    migration = _migration()
    context = MigrationContext.configure(migration_connection, opts={"compare_type": True, "include_object": _new_table_only})
    with Operations.context(context):
        migration.upgrade()
        migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_technique(_add_event(migration_connection))))
        migration.upgrade()  # existence guard: a no-op that keeps the row

    inspector = inspect(migration_connection)
    assert set(inspector.get_table_names()) == {*PREREQUISITES, TABLE}
    assert compare_metadata(context, Base.metadata) == []
    assert _count(migration_connection) == 1
    model_checks = {c.name for c in Base.metadata.tables[TABLE].constraints if c.__class__.__name__ == "CheckConstraint"}
    assert {item["name"] for item in inspector.get_check_constraints(TABLE)} == model_checks == {
        "ck_event_attack_techniques_technique_id_format",
        "ck_event_attack_techniques_evidence_kind_values",
        "ck_event_attack_techniques_evidence_origin_values",
    }
    assert [(u["name"], u["column_names"]) for u in inspector.get_unique_constraints(TABLE)] == [
        (UNIQUE, ["event_id", "technique_id", "evidence_kind"])
    ]
    assert {i["name"]: i["column_names"] for i in inspector.get_indexes(TABLE) if not i.get("duplicates_constraint")} == {
        INDEX: ["technique_id"]
    }
    (foreign_key,) = inspector.get_foreign_keys(TABLE)
    assert (foreign_key["referred_table"], foreign_key["options"].get("ondelete")) == ("security_events", "CASCADE")


def test_upgrade_leaves_a_table_created_by_init_db_as_it_is(migration_connection: Connection) -> None:
    Base.metadata.create_all(migration_connection, tables=[Base.metadata.tables[TABLE]])
    migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_technique(_add_event(migration_connection))))
    _upgraded(migration_connection)
    assert _count(migration_connection) == 1


def test_upgrade_fails_clearly_without_security_events(empty_schema: Connection) -> None:
    with pytest.raises(RuntimeError, match="the security_events table does not exist .* nothing was changed"):
        _upgraded(empty_schema)
    assert inspect(empty_schema).get_table_names() == []


def test_downgrade_removes_only_the_new_table(migration_connection: Connection) -> None:
    event_id = _add_event(migration_connection)
    with Operations.context(MigrationContext.configure(migration_connection)):
        migration = _migration()
        migration.upgrade()
        migration.downgrade()
    assert set(inspect(migration_connection).get_table_names()) == set(PREREQUISITES)
    events = Base.metadata.tables["security_events"]
    assert migration_connection.scalar(select(func.count()).select_from(events).where(events.c.id == event_id)) == 1


# --- constraints on the migrated table ----------------------------------------------------------------


def test_well_formed_technique_and_sub_technique_ids_and_both_origins_are_accepted(migration_connection: Connection) -> None:
    event_id = _add_event(_upgraded(migration_connection))
    rows = [
        _technique(event_id, technique_id="T1110"),
        _technique(event_id, technique_id="T1110.001", evidence_origin="collector_field"),
        _technique(event_id, technique_id="T9999"),  # well-formed but unknown to any catalogue: still evidence
    ]
    migration_connection.execute(insert(Base.metadata.tables[TABLE]), rows)
    assert _count(migration_connection) == 3
    created = migration_connection.execute(select(Base.metadata.tables[TABLE].c.created_at)).scalars().all()
    assert all(value is not None and value.tzinfo is not None for value in created)  # generated by the database


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"technique_id": "T111"}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "T11100"}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "t1110"}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "T1110.01"}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "T1110.0001"}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "TA0006"}, "ck_event_attack_techniques_technique_id_format"),  # a tactic, not a technique
        ({"technique_id": " T1110"}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "T1110 "}, "ck_event_attack_techniques_technique_id_format"),
        ({"technique_id": "T1110\n"}, "ck_event_attack_techniques_technique_id_format"),
        ({"evidence_kind": "mapped"}, "ck_event_attack_techniques_evidence_kind_values"),
        ({"evidence_kind": "inferred"}, "ck_event_attack_techniques_evidence_kind_values"),
        ({"evidence_origin": "raw_data"}, "ck_event_attack_techniques_evidence_origin_values"),
        ({"evidence_origin": ""}, "ck_event_attack_techniques_evidence_origin_values"),
    ],
)
def test_malformed_ids_and_unknown_kinds_or_origins_are_refused(
    migration_connection: Connection, overrides: dict[str, object], constraint: str
) -> None:
    event_id = _add_event(_upgraded(migration_connection))
    with pytest.raises(IntegrityError, match=constraint), migration_connection.begin_nested():
        migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_technique(event_id, **overrides)))


def test_the_same_technique_is_recorded_once_per_event(migration_connection: Connection) -> None:
    event_id = _add_event(_upgraded(migration_connection))
    table = Base.metadata.tables[TABLE]
    migration_connection.execute(insert(table).values(**_technique(event_id)))
    with pytest.raises(IntegrityError, match=UNIQUE), migration_connection.begin_nested():
        migration_connection.execute(insert(table).values(**_technique(event_id, evidence_origin="collector_field")))
    # Another event may report the same technique.
    migration_connection.execute(insert(table).values(**_technique(_add_event(migration_connection))))
    assert _count(migration_connection) == 2


def test_evidence_needs_an_existing_event_and_is_removed_with_it(migration_connection: Connection) -> None:
    _upgraded(migration_connection)
    table = Base.metadata.tables[TABLE]
    with pytest.raises(IntegrityError, match="fk_event_attack_techniques_event_id_security_events"), migration_connection.begin_nested():
        migration_connection.execute(insert(table).values(**_technique(uuid.uuid4())))
    event_id = _add_event(migration_connection)
    migration_connection.execute(insert(table), [_technique(event_id), _technique(event_id, technique_id="T1046")])
    events = Base.metadata.tables["security_events"]
    migration_connection.execute(delete(events).where(events.c.id == event_id))
    assert _count(migration_connection) == 0


# --- an existing table is accepted only when its structure matches ------------------------------------


def _structure(connection: Connection) -> dict[str, object]:
    """A comparable snapshot of the table's columns, constraints and indexes."""
    inspector = inspect(connection)
    return {
        "columns": sorted((c["name"], str(c["type"]), c["nullable"], c.get("default")) for c in inspector.get_columns(TABLE)),
        "checks": sorted((c["name"], c["sqltext"]) for c in inspector.get_check_constraints(TABLE)),
        "uniques": sorted((u["name"], tuple(u["column_names"])) for u in inspector.get_unique_constraints(TABLE)),
        "foreign_keys": sorted((f["name"], f["referred_table"], str(f.get("options"))) for f in inspector.get_foreign_keys(TABLE)),
        "indexes": sorted((i["name"], tuple(i["column_names"])) for i in inspector.get_indexes(TABLE)),
    }


@pytest.fixture
def matching_table(migration_connection: Connection) -> Connection:
    """The table as app.db.init_db would create it from the model."""
    Base.metadata.create_all(migration_connection, tables=[Base.metadata.tables[TABLE]])
    return migration_connection


@pytest.mark.parametrize(
    ("ddl", "problem"),
    [
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT ck_event_attack_techniques_technique_id_format"],
         "missing CHECK constraint ck_event_attack_techniques_technique_id_format"),
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT ck_event_attack_techniques_evidence_kind_values",
          "ALTER TABLE event_attack_techniques ADD CONSTRAINT ck_event_attack_techniques_evidence_kind_values "
          "CHECK (evidence_kind IN ('source_supplied', 'mapped'))"],
         "ck_event_attack_techniques_evidence_kind_values accepts 'mapped'"),
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT ck_event_attack_techniques_technique_id_format",
          "ALTER TABLE event_attack_techniques ADD CONSTRAINT ck_event_attack_techniques_technique_id_format "
          r"CHECK (technique_id ~* '^T[0-9]{4}(\.[0-9]{3})?$')"],  # case-insensitive: would admit t1110
         "ck_event_attack_techniques_technique_id_format accepts 't1110'"),
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT ck_event_attack_techniques_technique_id_format",
          "ALTER TABLE event_attack_techniques ADD CONSTRAINT ck_event_attack_techniques_technique_id_format "
          "CHECK (technique_id ~ '^T[0-9]{4}' AND evidence_kind <> '')"],  # refers to another column
         "ck_event_attack_techniques_technique_id_format could not be evaluated against technique_id alone"),
        (["ALTER TABLE event_attack_techniques ADD CONSTRAINT ck_event_attack_techniques_extra CHECK (technique_id <> 'T0000')"],
         "unexpected CHECK constraint ck_event_attack_techniques_extra"),
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT uq_event_attack_techniques_event_id_technique_id_evidence_kind"],
         "missing unique constraint uq_event_attack_techniques_event_id_technique_id_evidence_kind"),
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT uq_event_attack_techniques_event_id_technique_id_evidence_kind",
          "ALTER TABLE event_attack_techniques ADD CONSTRAINT uq_event_attack_techniques_event_id_technique_id_evidence_kind "
          "UNIQUE (event_id, technique_id)"],
         "unique constraint uq_event_attack_techniques_event_id_technique_id_evidence_kind is on"),
        (["ALTER TABLE event_attack_techniques DROP CONSTRAINT fk_event_attack_techniques_event_id_security_events",
          "ALTER TABLE event_attack_techniques ADD CONSTRAINT fk_event_attack_techniques_event_id_security_events "
          "FOREIGN KEY (event_id) REFERENCES security_events (id)"],
         "expected event_id -> security_events(id) ON DELETE CASCADE"),
        (["DROP INDEX ix_event_attack_techniques_technique_id"], "missing index ix_event_attack_techniques_technique_id"),
        (["DROP INDEX ix_event_attack_techniques_technique_id",
          "CREATE INDEX ix_event_attack_techniques_technique_id ON event_attack_techniques (evidence_kind)"],
         "index ix_event_attack_techniques_technique_id is not a plain index on exactly (technique_id)"),
        (["CREATE INDEX ix_unrelated ON event_attack_techniques (evidence_origin)"], "unexpected index ix_unrelated"),
        (["ALTER TABLE event_attack_techniques ADD COLUMN note text"], "unexpected column note"),
        (["ALTER TABLE event_attack_techniques ALTER COLUMN technique_id TYPE varchar(64)"],
         "column technique_id is VARCHAR(64) NOT NULL, expected VARCHAR(16) NOT NULL"),
        (["ALTER TABLE event_attack_techniques ALTER COLUMN evidence_origin DROP NOT NULL"],
         "column evidence_origin is VARCHAR(32) NULL, expected VARCHAR(32) NOT NULL"),
        (["ALTER TABLE event_attack_techniques ALTER COLUMN created_at DROP DEFAULT"], "column created_at default is None"),
    ],
)
def test_an_incompatible_existing_table_is_refused_without_any_change(
    matching_table: Connection, ddl: list[str], problem: str
) -> None:
    for statement in ddl:
        matching_table.execute(text(statement))
    before = _structure(matching_table)
    with pytest.raises(RuntimeError, match=re.escape(problem)) as refused:
        _upgraded(matching_table)
    assert str(refused.value).startswith(f"{REVISION}: {TABLE} already exists but does not match this migration (")
    assert str(refused.value).endswith("nothing was changed")
    assert _structure(matching_table) == before  # refused before any DDL: nothing dropped, created or repaired


def test_a_matching_existing_table_is_accepted_and_kept(matching_table: Connection) -> None:
    matching_table.execute(insert(Base.metadata.tables[TABLE]).values(**_technique(_add_event(matching_table))))
    before = _structure(matching_table)
    _upgraded(matching_table)
    assert _structure(matching_table) == before and _count(matching_table) == 1


@pytest.mark.parametrize(
    "ddl",
    [
        # Same meaning, different PostgreSQL text: OR instead of IN, and an explicit = ANY array.
        ["ALTER TABLE event_attack_techniques DROP CONSTRAINT ck_event_attack_techniques_evidence_origin_values",
         "ALTER TABLE event_attack_techniques ADD CONSTRAINT ck_event_attack_techniques_evidence_origin_values "
         "CHECK (evidence_origin = 'ingest_field' OR evidence_origin = 'collector_field')"],
        ["ALTER TABLE event_attack_techniques DROP CONSTRAINT ck_event_attack_techniques_evidence_kind_values",
         "ALTER TABLE event_attack_techniques ADD CONSTRAINT ck_event_attack_techniques_evidence_kind_values "
         "CHECK (evidence_kind = ANY (ARRAY['source_supplied']))"],
    ],
)
def test_equivalent_check_expressions_written_differently_are_accepted(matching_table: Connection, ddl: list[str]) -> None:
    for statement in ddl:
        matching_table.execute(text(statement))
    _upgraded(matching_table)  # no error: behaviour, not text, is compared
