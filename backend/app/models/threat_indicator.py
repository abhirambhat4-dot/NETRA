from datetime import datetime

from sqlalchemy import CheckConstraint, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import IndicatorType, Severity


class ThreatIndicator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value", "source"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
    )

    value: Mapped[str] = mapped_column(String(2048), index=True)
    indicator_type: Mapped[IndicatorType] = mapped_column(enum_type(IndicatorType))
    source: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[float | None]
    severity: Mapped[Severity] = mapped_column(enum_type(Severity))
    first_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    is_active: Mapped[bool] = mapped_column(default=True, index=True)
