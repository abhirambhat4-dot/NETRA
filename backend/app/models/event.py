import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import DetectionSource, Severity

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.attack_technique import EventAttackTechnique
    from app.models.incident import Incident


class SecurityEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("src_port BETWEEN 0 AND 65535", name="src_port_range"),
        CheckConstraint("dest_port BETWEEN 0 AND 65535", name="dest_port_range"),
        CheckConstraint("anomaly_score BETWEEN 0 AND 1", name="anomaly_score_range"),
        # Dataset provenance: an imported event names both its batch and its row, any other event neither.
        CheckConstraint("(import_batch_id IS NULL) = (source_row IS NULL)", name="import_provenance"),
        CheckConstraint("source_row >= 2", name="source_row_range"),
        Index(
            "uq_security_events_import_batch_id_source_row",
            "import_batch_id",
            "source_row",
            unique=True,
            postgresql_where=text("import_batch_id IS NOT NULL"),
        ),
    )

    event_uid: Mapped[str] = mapped_column(String(128), unique=True)
    occurred_at: Mapped[datetime] = mapped_column(index=True)
    source: Mapped[DetectionSource] = mapped_column(enum_type(DetectionSource), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    signature: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), index=True)
    src_ip: Mapped[str | None] = mapped_column(INET, index=True)
    dest_ip: Mapped[str | None] = mapped_column(INET, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    anomaly_score: Mapped[float | None]
    # Original detector payload (e.g. Suricata EVE JSON); the columns above hold the queryable fields.
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )

    # Set only for events normalised from a dataset upload: the batch and the file row (header = row 1).
    import_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("import_batches.id"), index=True)
    source_row: Mapped[int | None] = mapped_column(Integer)

    asset: Mapped["Asset | None"] = relationship(back_populates="events")
    incidents: Mapped[list["Incident"]] = relationship(
        secondary="incident_events", back_populates="events", passive_deletes=True
    )
    # Source-supplied ATT&CK technique IDs (event_attack_techniques). Read-only here: rows are written only by
    # intake.create_event, and removed by the database together with the event.
    attack_techniques: Mapped[list["EventAttackTechnique"]] = relationship(
        viewonly=True, order_by="EventAttackTechnique.technique_id"
    )
