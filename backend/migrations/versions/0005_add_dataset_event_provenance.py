"""Dataset normalisation: event provenance columns, batch outcome counts and the dataset_import source.

Additive apart from the two detectionsource CHECK constraints, which are replaced by ones that also
allow 'dataset_import' (existing rows already satisfy both versions). No existing row is changed.
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

# At most 32 characters: alembic_version.version_num is VARCHAR(32).
revision: str = "0005_dataset_event_provenance"
down_revision: str | None = "0004_add_import_batches"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_SOURCES = ("suricata", "ml_anomaly", "threat_intel", "vulnerability_scan", "manual")
NEW_SOURCES = (*OLD_SOURCES, "dataset_import")
# (table, column) pairs typed DetectionSource; both CHECK constraints are named ck_<table>_detectionsource.
SOURCE_COLUMNS = (("security_events", "source"), ("incidents", "detection_source"))


def _online() -> bool:
    return not op.get_context().as_sql


def _columns(table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)} if _online() else set()


def _checks(table: str) -> set[str]:
    return {item["name"] for item in sa.inspect(op.get_bind()).get_check_constraints(table)} if _online() else set()


def _indexes(table: str) -> set[str]:
    return {item["name"] for item in sa.inspect(op.get_bind()).get_indexes(table)} if _online() else set()


def _replace_source_checks(sources: tuple[str, ...]) -> None:
    allowed = ", ".join(f"'{value}'" for value in sources)
    for table, column in SOURCE_COLUMNS:
        name = f"ck_{table}_detectionsource"
        op.execute(f'ALTER TABLE {table} DROP CONSTRAINT IF EXISTS "{name}"')
        op.create_check_constraint(op.f(name), table, f"{column} IN ({allowed})")


def upgrade() -> None:
    # app.db.init_db creates tables from the models, so on a fresh database these may already exist.
    event_columns = _columns("security_events")
    if "import_batch_id" not in event_columns:
        op.add_column("security_events", sa.Column("import_batch_id", sa.Uuid(), nullable=True))
        op.create_foreign_key(
            op.f("fk_security_events_import_batch_id_import_batches"),
            "security_events",
            "import_batches",
            ["import_batch_id"],
            ["id"],
        )
    if "source_row" not in event_columns:
        op.add_column("security_events", sa.Column("source_row", sa.Integer(), nullable=True))

    event_checks = _checks("security_events")
    if "ck_security_events_import_provenance" not in event_checks:
        op.create_check_constraint(
            op.f("ck_security_events_import_provenance"),
            "security_events",
            "(import_batch_id IS NULL) = (source_row IS NULL)",
        )
    if "ck_security_events_source_row_range" not in event_checks:
        op.create_check_constraint(op.f("ck_security_events_source_row_range"), "security_events", "source_row >= 2")

    event_indexes = _indexes("security_events")
    if "ix_security_events_import_batch_id" not in event_indexes:
        op.create_index(op.f("ix_security_events_import_batch_id"), "security_events", ["import_batch_id"])
    if "uq_security_events_import_batch_id_source_row" not in event_indexes:
        op.create_index(
            "uq_security_events_import_batch_id_source_row",
            "security_events",
            ["import_batch_id", "source_row"],
            unique=True,
            postgresql_where=sa.text("import_batch_id IS NOT NULL"),
        )

    batch_columns = _columns("import_batches")
    if "events_created" not in batch_columns:
        op.add_column(
            "import_batches", sa.Column("events_created", sa.Integer(), server_default=sa.text("0"), nullable=False)
        )
    if "duplicate_rows" not in batch_columns:
        op.add_column(
            "import_batches", sa.Column("duplicate_rows", sa.Integer(), server_default=sa.text("0"), nullable=False)
        )
    if "ck_import_batches_normalised_counts" not in _checks("import_batches"):
        op.create_check_constraint(
            op.f("ck_import_batches_normalised_counts"),
            "import_batches",
            "events_created >= 0 AND duplicate_rows >= 0 AND events_created + duplicate_rows <= accepted_rows",
        )

    _replace_source_checks(NEW_SOURCES)


def downgrade() -> None:
    if _online():
        bind = op.get_bind()
        imported = bind.execute(
            sa.text(
                "SELECT (SELECT count(*) FROM security_events WHERE import_batch_id IS NOT NULL "
                "OR source = 'dataset_import') + (SELECT count(*) FROM incidents WHERE detection_source = 'dataset_import')"
            )
        ).scalar()
        if imported:
            raise RuntimeError(
                f"{imported} rows come from dataset imports; downgrading would drop their provenance. Nothing was changed."
            )
    _replace_source_checks(OLD_SOURCES)
    op.drop_constraint(op.f("ck_import_batches_normalised_counts"), "import_batches", type_="check")
    op.drop_column("import_batches", "duplicate_rows")
    op.drop_column("import_batches", "events_created")
    op.drop_index("uq_security_events_import_batch_id_source_row", table_name="security_events")
    op.drop_index(op.f("ix_security_events_import_batch_id"), table_name="security_events")
    op.drop_constraint(op.f("ck_security_events_source_row_range"), "security_events", type_="check")
    op.drop_constraint(op.f("ck_security_events_import_provenance"), "security_events", type_="check")
    op.drop_constraint(
        op.f("fk_security_events_import_batch_id_import_batches"), "security_events", type_="foreignkey"
    )
    op.drop_column("security_events", "source_row")
    op.drop_column("security_events", "import_batch_id")
