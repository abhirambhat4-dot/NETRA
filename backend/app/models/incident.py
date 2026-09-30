import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import DetectionSource, IncidentState, ResponseAction, Severity

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.authorization import Authorization
    from app.models.containment import ContainmentAction
    from app.models.cyber_memory import CyberMemory
    from app.models.decision import Decision
    from app.models.event import SecurityEvent


class Incident(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),)

    incident_key: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), index=True)
    risk_score: Mapped[float | None] = mapped_column(index=True)
    state: Mapped[IncidentState] = mapped_column(
        enum_type(IncidentState), default=IncidentState.DETECTED, index=True
    )
    detection_source: Mapped[DetectionSource] = mapped_column(enum_type(DetectionSource))
    recommended_action: Mapped[ResponseAction | None] = mapped_column(enum_type(ResponseAction))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )

    asset: Mapped["Asset | None"] = relationship(back_populates="incidents")
    events: Mapped[list["SecurityEvent"]] = relationship(
        secondary="incident_events", back_populates="incidents", passive_deletes=True
    )
    history: Mapped[list["IncidentHistory"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IncidentHistory.occurred_at",
    )
    decisions: Mapped[list["Decision"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    authorizations: Mapped[list["Authorization"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    containment_actions: Mapped[list["ContainmentAction"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    memories: Mapped[list["CyberMemory"]] = relationship(back_populates="incident", passive_deletes=True)


class IncidentEvent(Base):
    """Association between an incident and the security events correlated into it."""

    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    linked_at: Mapped[datetime] = mapped_column(server_default=func.now())


class IncidentHistory(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "incident_history"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    from_state: Mapped[IncidentState | None] = mapped_column(enum_type(IncidentState, "from_state"))
    to_state: Mapped[IncidentState] = mapped_column(enum_type(IncidentState, "to_state"))
    action: Mapped[str] = mapped_column(String(255))
    actor: Mapped[str] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    incident: Mapped["Incident"] = relationship(back_populates="history")
