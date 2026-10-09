"""Security Assessment model and migration tests.

Each test works inside a throwaway PostgreSQL schema within a transaction that is always rolled
back, so no real NETRA tables or data are touched.
"""

import importlib.util
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import Connection, delete, inspect, literal_column, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import engine
from app.models import AssessmentFinding, Asset, SecurityAssessment, User
from app.models.enums import AssessmentGrade, AssetEnvironment, AssetType, Criticality, Exposure, FindingResult, Severity

NEW_TABLES = {"security_assessments", "assessment_findings"}
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0003_add_security_assessments.py"


@pytest.fixture
def db_session() -> Iterator[Session]:
    schema = f"netra_assess_test_{uuid.uuid4().hex[:12]}"
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


def make_asset() -> Asset:
    return Asset(
        asset_key=f"AST-{uuid.uuid4().hex[:8]}",
        name="Assessment model asset",
        hostname="assess-model-01",
        ip_address="10.80.0.10",
        asset_type=AssetType.SERVER,
        environment=AssetEnvironment.TEST,
        criticality=Criticality.HIGH,
        exposure=Exposure.DMZ,
        owner="test-team",
    )


def make_finding(index: int, **overrides: Any) -> AssessmentFinding:
    fields: dict[str, Any] = {
        "position": index,
        "check_key": f"check_{index}",
        "category": "test",
        "title": f"Check {index}",
        "result": FindingResult.WARN,
        "severity": Severity.LOW,
        "deduction": 3,
        "evidence": [f"Evidence {index}."],
        "recommendation": "Do the thing.",
        "vulnerability_ids": [str(uuid.UUID(int=index))],
        "incident_ids": [],
        "event_ids": [],
        "vulnerability_total": 1,
        "incident_total": 0,
        "event_total": 0,
    }
    return AssessmentFinding(**(fields | overrides))


def make_assessment(asset: Asset | None, findings: list[AssessmentFinding] | None = None, **overrides: Any) -> SecurityAssessment:
    fields: dict[str, Any] = {
        "asset": asset,
        "asset_key": asset.asset_key if asset is not None else "AST-GONE",
        "methodology_version": "assessment-v1",
        "as_of": datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        "score": 94,
        "grade": AssessmentGrade.A,
        "summary": "Test summary.",
        "passed": 7,
        "warnings": 2,
        "failed": 0,
        "informational": 0,
        "missing_evidence": ["Nothing."],
        "input_counts": {"vulnerabilities": 1, "incidents": 0, "events": 0, "threatIndicators": 0},
        "requested_by": "assessor@example.com",
        "findings": findings if findings is not None else [make_finding(1), make_finding(0)],
    }
    return SecurityAssessment(**(fields | overrides))


def test_assessment_and_findings_persist_with_relationships(db_session: Session) -> None:
    user = User(email="assessor@example.com", full_name="Assessor", password_hash="unused")
    asset = make_asset()
    db_session.add_all([user, asset])
    db_session.flush()
    asset_key = asset.asset_key
    db_session.add(make_assessment(asset, requested_by_id=user.id))
    db_session.commit()
    db_session.expunge_all()

    stored = db_session.scalars(select(SecurityAssessment)).one()
    assert stored.asset.asset_key == asset_key
    assert stored.requested_by_user.email == "assessor@example.com"
    assert stored.grade == AssessmentGrade.A
    assert stored.methodology_version == "assessment-v1"
    assert stored.created_at is not None
    assert [finding.position for finding in stored.findings] == [0, 1]
    assert stored.findings[1].vulnerability_ids == [str(uuid.UUID(int=1))]
    assert stored.findings[0].assessment is stored
    assert stored.input_counts["vulnerabilities"] == 1


def test_snapshot_survives_asset_and_user_deletion(db_session: Session) -> None:
    user = User(email="assessor@example.com", full_name="Assessor", password_hash="unused")
    asset = make_asset()
    db_session.add_all([user, asset])
    db_session.flush()
    db_session.add(make_assessment(asset, requested_by_id=user.id))
    db_session.flush()
    db_session.execute(delete(Asset))
    db_session.execute(delete(User))
    db_session.expunge_all()

    stored = db_session.scalars(select(SecurityAssessment)).one()
    assert stored.asset_id is None
    assert stored.requested_by_id is None
    assert stored.asset_key == asset.asset_key
    assert stored.requested_by == "assessor@example.com"
    assert len(stored.findings) == 2


def test_findings_are_deleted_with_their_assessment(db_session: Session) -> None:
    db_session.add(make_assessment(make_asset()))
    db_session.flush()
    db_session.execute(delete(SecurityAssessment))
    assert db_session.scalar(select(AssessmentFinding.id).limit(1)) is None


@pytest.mark.parametrize(
    "assessment_overrides",
    [{"score": 101}, {"score": -1}, {"failed": -1}],
)
def test_assessment_constraints_are_enforced(db_session: Session, assessment_overrides: dict[str, Any]) -> None:
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(make_assessment(make_asset(), **assessment_overrides))
        db_session.flush()


@pytest.mark.parametrize(
    "finding_overrides",
    [
        [{"deduction": 101}],
        [{"position": -1}],
        [{}, {"check_key": "check_0"}],  # duplicate check in one assessment
        [{}, {"position": 0}],  # duplicate position in one assessment
    ],
)
def test_finding_constraints_are_enforced(db_session: Session, finding_overrides: list[dict[str, Any]]) -> None:
    findings = [make_finding(index, **overrides) for index, overrides in enumerate(finding_overrides)]
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(make_assessment(make_asset(), findings=findings))
        db_session.flush()


def test_grade_column_rejects_unknown_values(db_session: Session) -> None:
    db_session.add(make_assessment(make_asset()))
    db_session.flush()
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.execute(update(SecurityAssessment).values(grade=literal_column("'e'")))


def test_orm_updates_to_snapshots_are_rejected(db_session: Session) -> None:
    db_session.add(make_assessment(make_asset()))
    db_session.commit()

    stored = db_session.scalars(select(SecurityAssessment)).one()
    stored.score = 10
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()

    finding = db_session.scalars(select(AssessmentFinding)).first()
    finding.evidence = ["rewritten"]
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()
    assert db_session.scalars(select(SecurityAssessment.score)).one() == 94


# --- Alembic migration 0003 --------------------------------------------------------------------


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0003", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def migration_connection() -> Iterator[Connection]:
    """A connection whose search_path is a throwaway schema holding only the tables 0003 depends on."""
    schema = f"netra_migration_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            Base.metadata.create_all(
                connection, tables=[Base.metadata.tables["users"], Base.metadata.tables["assets"]]
            )
            yield connection
        finally:
            transaction.rollback()


def _new_tables_only(_obj: Any, name: str | None, type_: str, _reflected: bool, _compare_to: Any) -> bool:
    return type_ != "table" or name in NEW_TABLES


def test_migration_matches_models_and_is_guarded(migration_connection: Connection) -> None:
    migration = _migration()
    context = MigrationContext.configure(
        migration_connection, opts={"compare_type": True, "include_object": _new_tables_only}
    )
    with Operations.context(context):
        migration.upgrade()
        # Second run is a no-op: the existence guards skip tables that already exist.
        migration.upgrade()

    inspector = inspect(migration_connection)
    assert NEW_TABLES <= set(inspector.get_table_names())
    assert compare_metadata(context, Base.metadata) == []

    model_checks = {
        table: {constraint.name for constraint in Base.metadata.tables[table].constraints if constraint.__class__.__name__ == "CheckConstraint"}
        for table in NEW_TABLES
    }
    for table in NEW_TABLES:
        assert {item["name"] for item in inspector.get_check_constraints(table)} == model_checks[table]


def test_migration_skips_tables_created_by_init_db(migration_connection: Connection) -> None:
    Base.metadata.create_all(
        migration_connection, tables=[Base.metadata.tables[name] for name in ("security_assessments", "assessment_findings")]
    )
    migration = _migration()
    with Operations.context(MigrationContext.configure(migration_connection)):
        migration.upgrade()
    assert NEW_TABLES <= set(inspect(migration_connection).get_table_names())


def test_migration_downgrade_removes_only_new_tables(migration_connection: Connection) -> None:
    migration = _migration()
    with Operations.context(MigrationContext.configure(migration_connection)):
        migration.upgrade()
        migration.downgrade()
    assert set(inspect(migration_connection).get_table_names()) == {"users", "assets"}
