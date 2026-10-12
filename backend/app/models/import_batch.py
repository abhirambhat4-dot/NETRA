import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import ImportBatchStatus

if TYPE_CHECKING:
    from app.models.user import User


class ImportBatch(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One uploaded dataset file and its validation report.

    For a profile that defines a normalisation, the accepted rows of a VALIDATED batch are stored as
    security events in the same transaction (security_events.import_batch_id/source_row point back here).
    """

    __tablename__ = "import_batches"
    __table_args__ = (
        CheckConstraint("file_sha256 ~ '^[0-9a-f]{64}$'", name="file_sha256_format"),
        CheckConstraint("file_size_bytes >= 0", name="file_size_range"),
        CheckConstraint(
            "total_rows >= 0 AND accepted_rows >= 0 AND rejected_rows >= 0 "
            "AND accepted_rows + rejected_rows = total_rows",
            name="row_counts",
        ),
        CheckConstraint("error_total >= 0", name="error_total_range"),
        # Every accepted row is either stored as a new event or counted as a duplicate of an existing one.
        CheckConstraint(
            "events_created >= 0 AND duplicate_rows >= 0 AND events_created + duplicate_rows <= accepted_rows",
            name="normalised_counts",
        ),
        # A file is recorded as validated at most once per profile version. Rejected batches do not
        # reserve the hash, so a corrected or retried upload is never blocked by an earlier failure.
        Index(
            "uq_import_batches_validated_file",
            "dataset_profile",
            "profile_version",
            "file_sha256",
            unique=True,
            postgresql_where=text("status = 'validated'"),
        ),
        Index("ix_import_batches_uploaded_by_id_created_at", "uploaded_by_id", "created_at"),
    )

    dataset_profile: Mapped[str] = mapped_column(String(64))
    profile_version: Mapped[str] = mapped_column(String(32))
    # Base name only, control characters removed and truncated; never a server path.
    original_filename: Mapped[str] = mapped_column(String(255))
    file_sha256: Mapped[str] = mapped_column(String(64))
    file_size_bytes: Mapped[int] = mapped_column(BigInteger)
    # Indexed by the composite (uploaded_by_id, created_at) index above.
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[ImportBatchStatus] = mapped_column(enum_type(ImportBatchStatus), index=True)
    total_rows: Mapped[int] = mapped_column(Integer)
    accepted_rows: Mapped[int] = mapped_column(Integer)
    rejected_rows: Mapped[int] = mapped_column(Integer)
    # Every issue found; error_sample keeps only the first few, so error_total above its length means it was capped.
    error_total: Mapped[int] = mapped_column(Integer)
    # Issues name a row, a column and a rule only, never cell contents.
    error_sample: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    completed_at: Mapped[datetime | None]
    # Normalisation outcome; both stay 0 for validation-only profiles and for rejected batches.
    events_created: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    # Accepted rows whose content already exists as an event (from this file or an earlier batch).
    duplicate_rows: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))

    uploaded_by: Mapped["User | None"] = relationship()
