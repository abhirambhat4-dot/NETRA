import uuid
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import ResponseAction

if TYPE_CHECKING:
    from app.models.authorization import Authorization
    from app.models.incident import Incident


class Decision(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "decisions"
    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[ResponseAction] = mapped_column(enum_type(ResponseAction))
    rationale: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[float]
    confidence: Mapped[float]
    recommendation: Mapped[str | None] = mapped_column(Text)

    incident: Mapped["Incident"] = relationship(back_populates="decisions")
    authorizations: Mapped[list["Authorization"]] = relationship(back_populates="decision")
