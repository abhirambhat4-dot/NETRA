"""Risk evaluation history: the risk_evaluations table (append-only; one row per risk scoring run).

Additive only: creates one table and its index; no existing table or row is changed. incidents is created
by app.db.init_db, not by a migration, so it must already exist; risk_evaluations itself may already exist
for the same reason, and is then left as it is.
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# At most 32 characters: alembic_version.version_num is VARCHAR(32).
revision: str = "0006_add_risk_evaluations"
down_revision: str | None = "0005_dataset_event_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "risk_evaluations"


def _table_exists(name: str) -> bool:
    return not op.get_context().as_sql and sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not op.get_context().as_sql and not _table_exists("incidents"):
        raise RuntimeError(
            f"{revision}: the incidents table does not exist (it is created by app.db.init_db), so "
            f"{TABLE} cannot reference it; nothing was changed"
        )
    if _table_exists(TABLE):
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("methodology_version", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("previous_risk_score", sa.Float(), nullable=True),
        sa.Column("factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("missing_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("matched_indicators", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name=op.f("ck_risk_evaluations_risk_score_range")),
        sa.CheckConstraint(
            "previous_risk_score IS NULL OR previous_risk_score BETWEEN 0 AND 100",
            name=op.f("ck_risk_evaluations_previous_risk_score_range"),
        ),
        sa.CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name=op.f("ck_risk_evaluations_risk_level_values")
        ),
        sa.CheckConstraint(
            "trigger IN ('initial', 'reevaluation')", name=op.f("ck_risk_evaluations_trigger_values")
        ),
        sa.CheckConstraint(
            "methodology_version <> ''", name=op.f("ck_risk_evaluations_methodology_version_present")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_risk_evaluations_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_evaluations")),
    )
    op.create_index("ix_risk_evaluations_incident_id_created_at", TABLE, ["incident_id", "created_at"])


def downgrade() -> None:
    # Drops every stored evaluation; incidents and their incident_history are untouched.
    op.drop_index("ix_risk_evaluations_incident_id_created_at", table_name=TABLE)
    op.drop_table(TABLE)
