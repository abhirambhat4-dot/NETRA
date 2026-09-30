from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import AssetEnvironment, AssetStatus, AssetType, Criticality, Exposure

if TYPE_CHECKING:
    from app.models.event import SecurityEvent
    from app.models.incident import Incident
    from app.models.vulnerability import Vulnerability


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    asset_key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(INET, index=True)
    asset_type: Mapped[AssetType] = mapped_column(enum_type(AssetType))
    environment: Mapped[AssetEnvironment] = mapped_column(enum_type(AssetEnvironment))
    criticality: Mapped[Criticality] = mapped_column(enum_type(Criticality), index=True)
    exposure: Mapped[Exposure] = mapped_column(enum_type(Exposure))
    owner: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[AssetStatus] = mapped_column(
        enum_type(AssetStatus), default=AssetStatus.ACTIVE, index=True
    )

    events: Mapped[list["SecurityEvent"]] = relationship(back_populates="asset", passive_deletes=True)
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", passive_deletes=True
    )
    incidents: Mapped[list["Incident"]] = relationship(back_populates="asset", passive_deletes=True)
