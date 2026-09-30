import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import DetectionSource, Severity

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.incident import Incident


class SecurityEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("src_port BETWEEN 0 AND 65535", name="src_port_range"),
        CheckConstraint("dest_port BETWEEN 0 AND 65535", name="dest_port_range"),
        CheckConstraint("anomaly_score BETWEEN 0 AND 1", name="anomaly_score_range"),
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

    asset: Mapped["Asset | None"] = relationship(back_populates="events")
    incidents: Mapped[list["Incident"]] = relationship(
        secondary="incident_events", back_populates="events", passive_deletes=True
    )
