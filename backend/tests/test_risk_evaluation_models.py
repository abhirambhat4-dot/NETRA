"""RiskEvaluation model and migration 0006 tests.

Each test works inside a throwaway PostgreSQL schema within a transaction that is always rolled back,
so no real NETRA tables or data are touched.
"""

import importlib.util
import uuid
from collections.abc import Iterator
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
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema

import app.models
from app.db.base import Base
from app.db.session import engine
from app.models import RiskEvaluation
from app.models.risk_evaluation import RISK_EVALUATION_TRIGGERS, RISK_LEVELS, AppendOnlyError
from app.services.risk_engine import RISK_METHODOLOGY_VERSION

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND / "migrations" / "versions" / "0006_add_risk_evaluations.py"
REVISION = "0006_add_risk_evaluations"
TABLE = "risk_evaluations"
# The tables 0006 depends on: incidents (created by app.db.init_db) and assets, which incidents references.
PREREQUISITES = ("assets", "incidents")


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0006", MIGRATION)
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
            # Prove the throwaway schema is the only place unqualified names resolve to.
            assert connection.scalar(text("SELECT current_schema()")) == schema
            yield connection
        finally:
            transaction.rollback()


@pytest.fixture
def migration_connection(empty_schema: Connection) -> Connection:
    """The throwaway schema holding only the tables 0006 depends on."""
    Base.metadata.create_all(empty_schema, tables=[Base.metadata.tables[name] for name in PREREQUISITES])
    return empty_schema


def _new_table_only(_obj: Any, name: str | None, type_: str, _reflected: bool, _compare_to: Any) -> bool:
    return type_ != "table" or name == TABLE


def _add_incident(connection: Connection) -> uuid.UUID:
    incident_id = uuid.uuid4()
    connection.execute(
        insert(Base.metadata.tables["incidents"]).values(
            id=incident_id,
            incident_key=f"INC-{incident_id.hex[:8]}",
            title="Migration test incident",
            severity="high",
            state="prioritised",
            detection_source="manual",
        )
    )
    return incident_id


def _evaluation(incident_id: uuid.UUID, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "incident_id": incident_id,
        "methodology_version": RISK_METHODOLOGY_VERSION,
        "risk_score": 51.25,
        "risk_level": "HIGH",
        "previous_risk_score": None,
        "factors": {"asset_criticality": {"normalizedValue": 75.0, "weight": 0.25, "contribution": 18.75}},
        "missing_evidence": ["Vulnerability CVSS evidence is unavailable."],
        "matched_indicators": [{"id": str(uuid.uuid4()), "source": "ThreatFox (abuse.ch)", "indicatorType": "IP"}],
        "trigger": "initial",
        "actor": "migration-test@example.com",
    }
    return values | overrides


def _upgraded(connection: Connection) -> Connection:
    with Operations.context(MigrationContext.configure(connection)):
        _migration().upgrade()
    return connection


# --- chain -----------------------------------------------------------------------------------------


def test_0006_follows_0005() -> None:
    scripts = _scripts()
    # 0007_event_attack_techniques is now the single head (tests/test_attack_technique_models.py).
    assert scripts.get_heads() == ["0007_event_attack_techniques"]
    assert scripts.get_revision(REVISION).down_revision == "0005_dataset_event_provenance"
    assert len(REVISION) <= 32  # alembic_version.version_num is VARCHAR(32)


def test_the_model_is_registered() -> None:
    assert TABLE in Base.metadata.tables
    assert app.models.RiskEvaluation is RiskEvaluation and "RiskEvaluation" in app.models.__all__


# --- migration -------------------------------------------------------------------------------------


def test_upgrade_creates_the_table_matching_the_model_and_repeating_it_is_safe(migration_connection: Connection) -> None:
    migration = _migration()
    context = MigrationContext.configure(
        migration_connection, opts={"compare_type": True, "include_object": _new_table_only}
    )
    with Operations.context(context):
        migration.upgrade()
        migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_evaluation(_add_incident(migration_connection))))
        # Second run is a no-op: the existence guard skips the table and keeps its rows.
        migration.upgrade()

    inspector = inspect(migration_connection)
    assert set(inspector.get_table_names()) == {*PREREQUISITES, TABLE}
    assert compare_metadata(context, Base.metadata) == []
    assert migration_connection.scalar(select(func.count()).select_from(Base.metadata.tables[TABLE])) == 1

    model_table = Base.metadata.tables[TABLE]
    model_checks = {constraint.name for constraint in model_table.constraints if constraint.__class__.__name__ == "CheckConstraint"}
    assert {item["name"] for item in inspector.get_check_constraints(TABLE)} == model_checks == {
        "ck_risk_evaluations_risk_score_range",
        "ck_risk_evaluations_previous_risk_score_range",
        "ck_risk_evaluations_risk_level_values",
        "ck_risk_evaluations_trigger_values",
        "ck_risk_evaluations_methodology_version_present",
    }
    assert {index["name"]: index["column_names"] for index in inspector.get_indexes(TABLE)} == {
        "ix_risk_evaluations_incident_id_created_at": ["incident_id", "created_at"]
    }
    (foreign_key,) = inspector.get_foreign_keys(TABLE)
    assert (foreign_key["referred_table"], foreign_key["options"].get("ondelete")) == ("incidents", "CASCADE")
    created_at = next(column for column in inspector.get_columns(TABLE) if column["name"] == "created_at")
    assert created_at["nullable"] is False and "now()" in str(created_at["default"])


def test_upgrade_leaves_a_table_created_by_init_db_as_it_is(migration_connection: Connection) -> None:
    Base.metadata.create_all(migration_connection, tables=[Base.metadata.tables[TABLE]])
    migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_evaluation(_add_incident(migration_connection))))
    _upgraded(migration_connection)
    assert migration_connection.scalar(select(func.count()).select_from(Base.metadata.tables[TABLE])) == 1


def test_upgrade_fails_clearly_without_the_incidents_table(empty_schema: Connection) -> None:
    with pytest.raises(RuntimeError, match="the incidents table does not exist .* nothing was changed"):
        _upgraded(empty_schema)
    assert inspect(empty_schema).get_table_names() == []


def test_downgrade_removes_only_the_new_table(migration_connection: Connection) -> None:
    incident_id = _add_incident(migration_connection)
    with Operations.context(MigrationContext.configure(migration_connection)):
        migration = _migration()
        migration.upgrade()
        migration.downgrade()
    assert set(inspect(migration_connection).get_table_names()) == set(PREREQUISITES)
    incidents = Base.metadata.tables["incidents"]
    assert migration_connection.scalar(select(func.count()).select_from(incidents).where(incidents.c.id == incident_id)) == 1


# --- constraints (on the migrated table) -----------------------------------------------------------


def test_valid_evaluations_are_accepted_at_the_boundaries(migration_connection: Connection) -> None:
    incident_id = _add_incident(_upgraded(migration_connection))
    table = Base.metadata.tables[TABLE]
    rows = [
        _evaluation(incident_id, risk_score=0.0, risk_level="LOW", previous_risk_score=None),
        _evaluation(incident_id, risk_score=100.0, risk_level="CRITICAL", previous_risk_score=0.0, trigger="reevaluation"),
        _evaluation(incident_id, risk_score=30.25, risk_level="MEDIUM", previous_risk_score=100.0, trigger="reevaluation"),
    ]
    migration_connection.execute(insert(table), rows)
    assert migration_connection.scalar(select(func.count()).select_from(table)) == 3
    stored = migration_connection.execute(select(table.c.created_at)).scalars().all()
    assert all(value is not None and value.tzinfo is not None for value in stored)  # generated by the database
    assert set(RISK_LEVELS) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(RISK_EVALUATION_TRIGGERS) == {"initial", "reevaluation"}


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"risk_score": 100.01}, "ck_risk_evaluations_risk_score_range"),
        ({"risk_score": -0.01}, "ck_risk_evaluations_risk_score_range"),
        ({"previous_risk_score": 150.0}, "ck_risk_evaluations_previous_risk_score_range"),
        ({"previous_risk_score": -1.0}, "ck_risk_evaluations_previous_risk_score_range"),
        ({"risk_level": "SEVERE"}, "ck_risk_evaluations_risk_level_values"),
        ({"risk_level": "high"}, "ck_risk_evaluations_risk_level_values"),  # the lower-case Severity value
        ({"trigger": "manual"}, "ck_risk_evaluations_trigger_values"),
        ({"methodology_version": ""}, "ck_risk_evaluations_methodology_version_present"),
    ],
)
def test_out_of_range_or_unknown_values_are_refused(migration_connection: Connection, overrides: dict[str, object], constraint: str) -> None:
    incident_id = _add_incident(_upgraded(migration_connection))
    with pytest.raises(IntegrityError, match=constraint), migration_connection.begin_nested():
        migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_evaluation(incident_id, **overrides)))


def test_an_evaluation_needs_an_existing_incident(migration_connection: Connection) -> None:
    _upgraded(migration_connection)
    with pytest.raises(IntegrityError, match="fk_risk_evaluations_incident_id_incidents"), migration_connection.begin_nested():
        migration_connection.execute(insert(Base.metadata.tables[TABLE]).values(**_evaluation(uuid.uuid4())))


def test_evaluations_are_removed_with_their_incident_like_incident_history(migration_connection: Connection) -> None:
    incident_id = _add_incident(_upgraded(migration_connection))
    table = Base.metadata.tables[TABLE]
    migration_connection.execute(insert(table), [_evaluation(incident_id), _evaluation(incident_id, trigger="reevaluation")])
    incidents = Base.metadata.tables["incidents"]
    migration_connection.execute(delete(incidents).where(incidents.c.id == incident_id))
    assert migration_connection.scalar(select(func.count()).select_from(table)) == 0


# --- append-only through the ORM -------------------------------------------------------------------


def _stored_evaluation(connection: Connection, session: Session) -> RiskEvaluation:
    evaluation = RiskEvaluation(**_evaluation(_add_incident(connection)))
    session.add(evaluation)
    session.flush()
    return evaluation


def test_the_orm_refuses_to_change_an_evaluation(migration_connection: Connection) -> None:
    _upgraded(migration_connection)
    with Session(bind=migration_connection, join_transaction_mode="create_savepoint") as session:
        evaluation = _stored_evaluation(migration_connection, session)
        evaluation.risk_score = 99.0
        with pytest.raises(AppendOnlyError, match="append-only and cannot be changed"):
            session.flush()


def test_the_orm_refuses_to_delete_an_evaluation(migration_connection: Connection) -> None:
    _upgraded(migration_connection)
    with Session(bind=migration_connection, join_transaction_mode="create_savepoint") as session:
        evaluation = _stored_evaluation(migration_connection, session)
        session.delete(evaluation)
        with pytest.raises(AppendOnlyError, match="removed only with its incident"):
            session.flush()
