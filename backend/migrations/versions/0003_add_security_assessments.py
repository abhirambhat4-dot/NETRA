from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_add_security_assessments"
down_revision: str | None = "0002_add_password_reset_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITIES = "'info', 'low', 'medium', 'high', 'critical'"


def _table_exists(name: str) -> bool:
    # app.db.init_db creates missing tables from the models, so the table may already exist.
    return not op.get_context().as_sql and sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if not _table_exists("security_assessments"):
        op.create_table(
            "security_assessments",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("asset_id", sa.Uuid(), nullable=True),
            sa.Column("asset_key", sa.String(length=64), nullable=False),
            sa.Column("methodology_version", sa.String(length=32), nullable=False),
            sa.Column("as_of", sa.DateTime(timezone=True), nullable=False),
            sa.Column("score", sa.Integer(), nullable=False),
            sa.Column("grade", sa.String(length=32), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("passed", sa.Integer(), nullable=False),
            sa.Column("warnings", sa.Integer(), nullable=False),
            sa.Column("failed", sa.Integer(), nullable=False),
            sa.Column("informational", sa.Integer(), nullable=False),
            sa.Column("missing_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("input_counts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("requested_by", sa.String(length=320), nullable=False),
            sa.Column("requested_by_id", sa.Uuid(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.CheckConstraint("score BETWEEN 0 AND 100", name=op.f("ck_security_assessments_score_range")),
            sa.CheckConstraint(
                "passed >= 0 AND warnings >= 0 AND failed >= 0 AND informational >= 0",
                name=op.f("ck_security_assessments_result_counts"),
            ),
            sa.CheckConstraint(
                "grade IN ('a', 'b', 'c', 'd', 'f')", name=op.f("ck_security_assessments_assessmentgrade")
            ),
            sa.ForeignKeyConstraint(
                ["asset_id"],
                ["assets.id"],
                name=op.f("fk_security_assessments_asset_id_assets"),
                ondelete="SET NULL",
            ),
            sa.ForeignKeyConstraint(
                ["requested_by_id"],
                ["users.id"],
                name=op.f("fk_security_assessments_requested_by_id_users"),
                ondelete="SET NULL",
            ),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_security_assessments")),
        )
        op.create_index("ix_security_assessments_asset_id_as_of", "security_assessments", ["asset_id", "as_of"])
        op.create_index(op.f("ix_security_assessments_grade"), "security_assessments", ["grade"])
        op.create_index(
            op.f("ix_security_assessments_methodology_version"), "security_assessments", ["methodology_version"]
        )
        op.create_index(op.f("ix_security_assessments_requested_by_id"), "security_assessments", ["requested_by_id"])

    if not _table_exists("assessment_findings"):
        op.create_table(
            "assessment_findings",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column("assessment_id", sa.Uuid(), nullable=False),
            sa.Column("position", sa.Integer(), nullable=False),
            sa.Column("check_key", sa.String(length=64), nullable=False),
            sa.Column("category", sa.String(length=64), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("result", sa.String(length=32), nullable=False),
            sa.Column("severity", sa.String(length=32), nullable=True),
            sa.Column("deduction", sa.Integer(), nullable=False),
            sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("recommendation", sa.Text(), nullable=True),
            sa.Column("vulnerability_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("incident_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("vulnerability_total", sa.Integer(), nullable=False),
            sa.Column("incident_total", sa.Integer(), nullable=False),
            sa.Column("event_total", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.CheckConstraint("deduction BETWEEN 0 AND 100", name=op.f("ck_assessment_findings_deduction_range")),
            sa.CheckConstraint("position >= 0", name=op.f("ck_assessment_findings_position_range")),
            sa.CheckConstraint(
                "vulnerability_total >= 0 AND incident_total >= 0 AND event_total >= 0",
                name=op.f("ck_assessment_findings_reference_totals"),
            ),
            sa.CheckConstraint(
                "result IN ('pass', 'warn', 'fail', 'info')", name=op.f("ck_assessment_findings_findingresult")
            ),
            sa.CheckConstraint(f"severity IN ({SEVERITIES})", name=op.f("ck_assessment_findings_severity")),
            sa.ForeignKeyConstraint(
                ["assessment_id"],
                ["security_assessments.id"],
                name=op.f("fk_assessment_findings_assessment_id_security_assessments"),
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_assessment_findings")),
            sa.UniqueConstraint(
                "assessment_id", "check_key", name=op.f("uq_assessment_findings_assessment_id_check_key")
            ),
            sa.UniqueConstraint(
                "assessment_id", "position", name=op.f("uq_assessment_findings_assessment_id_position")
            ),
        )
        op.create_index(op.f("ix_assessment_findings_assessment_id"), "assessment_findings", ["assessment_id"])
        op.create_index(op.f("ix_assessment_findings_result"), "assessment_findings", ["result"])


def downgrade() -> None:
    op.drop_index(op.f("ix_assessment_findings_result"), table_name="assessment_findings")
    op.drop_index(op.f("ix_assessment_findings_assessment_id"), table_name="assessment_findings")
    op.drop_table("assessment_findings")
    op.drop_index(op.f("ix_security_assessments_requested_by_id"), table_name="security_assessments")
    op.drop_index(op.f("ix_security_assessments_methodology_version"), table_name="security_assessments")
    op.drop_index(op.f("ix_security_assessments_grade"), table_name="security_assessments")
    op.drop_index("ix_security_assessments_asset_id_as_of", table_name="security_assessments")
    op.drop_table("security_assessments")
