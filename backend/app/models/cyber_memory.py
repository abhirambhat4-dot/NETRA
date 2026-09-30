import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import Effectiveness, ResponseAction

if TYPE_CHECKING:
    from app.models.decision import Decision
    from app.models.incident import Incident


class CyberMemory(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A lesson learned from a handled incident; kept even if the incident is deleted."""

    __tablename__ = "cyber_memories"

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    decision_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("decisions.id", ondelete="SET NULL"))
    lesson: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(Text)
    action_taken: Mapped[ResponseAction | None] = mapped_column(enum_type(ResponseAction))
    effectiveness: Mapped[Effectiveness] = mapped_column(
        enum_type(Effectiveness), default=Effectiveness.UNKNOWN
    )

    incident: Mapped["Incident | None"] = relationship(back_populates="memories")
    decision: Mapped["Decision | None"] = relationship()
