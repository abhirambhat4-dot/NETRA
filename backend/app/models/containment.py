import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import ContainmentStatus, ResponseAction

if TYPE_CHECKING:
    from app.models.authorization import Authorization
    from app.models.incident import Incident


class ContainmentAction(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "containment_actions"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    # Every containment action must be backed by an authorization record.
    authorization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("authorizations.id"), index=True)
    action_type: Mapped[ResponseAction] = mapped_column(enum_type(ResponseAction))
    target: Mapped[str] = mapped_column(String(255))
    status: Mapped[ContainmentStatus] = mapped_column(
        enum_type(ContainmentStatus), default=ContainmentStatus.PENDING, index=True
    )
    executed_at: Mapped[datetime | None]
    verified_at: Mapped[datetime | None]
    result: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    incident: Mapped["Incident"] = relationship(back_populates="containment_actions")
    authorization: Mapped["Authorization"] = relationship(back_populates="containment_actions")
