import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import AuthorizationStatus, ResponseAction

if TYPE_CHECKING:
    from app.models.containment import ContainmentAction
    from app.models.decision import Decision
    from app.models.incident import Incident


class Authorization(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "authorizations"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    decision_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("decisions.id", ondelete="SET NULL"), index=True
    )
    requested_action: Mapped[ResponseAction] = mapped_column(enum_type(ResponseAction))
    status: Mapped[AuthorizationStatus] = mapped_column(
        enum_type(AuthorizationStatus), default=AuthorizationStatus.PENDING, index=True
    )
    requested_by: Mapped[str] = mapped_column(String(255))
    # Records whoever resolved the request, whether it was approved or rejected.
    approved_by: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(server_default=func.now())
    approved_at: Mapped[datetime | None]

    incident: Mapped["Incident"] = relationship(back_populates="authorizations")
    decision: Mapped["Decision | None"] = relationship(back_populates="authorizations")
    containment_actions: Mapped[list["ContainmentAction"]] = relationship(back_populates="authorization")
