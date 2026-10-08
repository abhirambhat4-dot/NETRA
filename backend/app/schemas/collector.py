from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel

from app.schemas.core import CoreResponse, EventResponse

# Mirrors the security_events column limits so oversized input is rejected before the database.
EVENT_TYPE_MAX_LENGTH = 100
SIGNATURE_MAX_LENGTH = 512
PROTOCOL_MAX_LENGTH = 16
IDEMPOTENCY_KEY_MAX_LENGTH = 128
SEVERITY_NAMES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class CollectorEventIn(CoreResponse):
    """One submitted event. Source and collector attribution are assigned by the server."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")

    idempotency_key: str = Field(
        min_length=1, max_length=IDEMPOTENCY_KEY_MAX_LENGTH, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    occurred_at: datetime
    event_type: str = Field(min_length=1, max_length=EVENT_TYPE_MAX_LENGTH)
    severity: str
    signature: str | None = Field(default=None, max_length=SIGNATURE_MAX_LENGTH)
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=PROTOCOL_MAX_LENGTH)
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    asset_id: UUID | None = None
    raw_data: dict[str, Any] | None = None

    @field_validator("event_type", "signature", "protocol", mode="before")
    @classmethod
    def strip_text(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("severity")
    @classmethod
    def known_severity(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in SEVERITY_NAMES:
            raise ValueError(f"must be one of {', '.join(SEVERITY_NAMES)}")
        return normalized

    @field_validator("occurred_at")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("must include a timezone offset")
        return value


class CollectorEventResult(CoreResponse):
    index: int
    idempotency_key: str | None
    status: Literal["created", "duplicate", "rejected"]
    event_id: UUID | None = None
    event_uid: str | None = None
    reason: str | None = None


class CollectorSubmitResponse(CoreResponse):
    created: int
    duplicates: int
    rejected: int
    results: list[CollectorEventResult]


class CollectorStatusResponse(CoreResponse):
    collector: str
    status: Literal["receiving", "idle"]
    total_events: int
    events_last_24h: int = Field(alias="eventsLast24h")
    last_received_at: datetime | None
    recent_events: list[EventResponse]
