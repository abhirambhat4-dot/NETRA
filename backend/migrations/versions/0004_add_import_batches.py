from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_add_import_batches"
down_revision: str | None = "0003_add_security_assessments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _table_exists(name: str) -> bool:
    # app.db.init_db creates missing tables from the models, so the table may already exist.
    return not op.get_context().as_sql and sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    if _table_exists("import_batches"):
        return
    op.create_table(
        "import_batches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("dataset_profile", sa.String(length=64), nullable=False),
        sa.Column("profile_version", sa.String(length=32), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("file_sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("uploaded_by_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("total_rows", sa.Integer(), nullable=False),
        sa.Column("accepted_rows", sa.Integer(), nullable=False),
        sa.Column("rejected_rows", sa.Integer(), nullable=False),
        sa.Column("error_total", sa.Integer(), nullable=False),
        sa.Column("error_sample", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("file_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_import_batches_file_sha256_format")),
        sa.CheckConstraint("file_size_bytes >= 0", name=op.f("ck_import_batches_file_size_range")),
        sa.CheckConstraint(
            "total_rows >= 0 AND accepted_rows >= 0 AND rejected_rows >= 0 "
            "AND accepted_rows + rejected_rows = total_rows",
            name=op.f("ck_import_batches_row_counts"),
        ),
        sa.CheckConstraint("error_total >= 0", name=op.f("ck_import_batches_error_total_range")),
        sa.CheckConstraint(
            "status IN ('validated', 'rejected')", name=op.f("ck_import_batches_importbatchstatus")
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_id"],
            ["users.id"],
            name=op.f("fk_import_batches_uploaded_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_import_batches")),
    )
    op.create_index(op.f("ix_import_batches_status"), "import_batches", ["status"])
    op.create_index(
        "ix_import_batches_uploaded_by_id_created_at", "import_batches", ["uploaded_by_id", "created_at"]
    )
    op.create_index(
        "uq_import_batches_validated_file",
        "import_batches",
        ["dataset_profile", "profile_version", "file_sha256"],
        unique=True,
        postgresql_where=sa.text("status = 'validated'"),
    )


def downgrade() -> None:
    op.drop_index("uq_import_batches_validated_file", table_name="import_batches")
    op.drop_index("ix_import_batches_uploaded_by_id_created_at", table_name="import_batches")
    op.drop_index(op.f("ix_import_batches_status"), table_name="import_batches")
    op.drop_table("import_batches")
