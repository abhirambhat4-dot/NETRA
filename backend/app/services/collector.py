"""NETRA Web Collector: authenticated, stateless event submission built on the intake service.

Submitted events are claimed data. They are stored with source MANUAL, server-assigned
attribution and a deterministic UID; nothing here creates incidents, fetches URLs or logs payloads.
"""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.enums import DetectionSource
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.collector import CollectorEventIn, CollectorEventResult
from app.services.intake import create_event
from app.services.rate_limit import SlidingWindowRateLimiter

COLLECTOR_NAME = "netra-web"
EVENT_UID_PREFIX = "collector-web-"
RESERVED_RAW_DATA_KEY = "collector"
MAX_BATCH_EVENTS = 20
MAX_RAW_DATA_BYTES = 16 * 1024
MAX_RAW_DATA_DEPTH = 20
# Matches CollectorEventIn.idempotency_key, so keys are echoed only when well formed.
IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_EVENT_AGE = timedelta(days=30)
RECEIVING_WINDOW = timedelta(minutes=5)
RECENT_EVENT_LIMIT = 10

# Each submitted event counts towards the per-user budget of 60 events per minute.
collector_user_limiter = SlidingWindowRateLimiter(limit=60, window_seconds=60)


def collector_event_uid(user_id: UUID, idempotency_key: str) -> str:
    """Deterministic per user and key; the digest does not reveal who submitted the event."""
    digest = hashlib.sha256(f"netra-web-collector\x00{user_id}\x00{idempotency_key}".encode()).hexdigest()
    return f"{EVENT_UID_PREFIX}{digest}"  # 14 + 64 = 78 characters, within the 128 column limit


def consume_rate_limit(user: User, event_count: int) -> None:
    key = str(user.id)
    for _ in range(event_count):
        if not collector_user_limiter.allow(key):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Collector rate limit exceeded. Try again in a minute.",
            )


def _validation_reason(error: ValidationError) -> str:
    """Field names and rule messages only; submitted values are never echoed."""
    reasons = []
    for item in error.errors(include_input=False, include_url=False, include_context=False):
        location = ".".join(str(part) for part in item["loc"]) or "event"
        message = "is assigned by the server" if item["type"] == "extra_forbidden" else item["msg"]
        reasons.append(f"{location}: {message}")
    return "; ".join(reasons)


def _raw_data_problem(raw_data: dict[str, Any] | None) -> str | None:
    if raw_data is None:
        return None
    if RESERVED_RAW_DATA_KEY in raw_data:
        return "rawData.collector is reserved for server attribution"
    size = len(json.dumps(raw_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    if size > MAX_RAW_DATA_BYTES:
        return f"rawData exceeds {MAX_RAW_DATA_BYTES // 1024} KB"
    return None


def _exceeds_depth(value: Any, limit: int) -> bool:
    """Iterative nesting check (objects and arrays; the outer value is level 1) that cannot recurse."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def _time_problem(occurred_at: datetime, now: datetime) -> str | None:
    if occurred_at > now + MAX_FUTURE_SKEW:
        return "occurredAt is more than 5 minutes in the future"
    if occurred_at < now - MAX_EVENT_AGE:
        return "occurredAt is older than 30 days"
    return None


def _existing_event(db: Session, event_uid: str) -> SecurityEvent | None:
    return db.scalar(select(SecurityEvent).where(SecurityEvent.event_uid == event_uid))


def _result(index: int, key: str | None, outcome: str, event: SecurityEvent | None = None,
            reason: str | None = None) -> CollectorEventResult:
    return CollectorEventResult(
        index=index,
        idempotency_key=key,
        status=outcome,
        event_id=event.id if event is not None else None,
        event_uid=event.event_uid if event is not None else None,
        reason=reason,
    )


def submit_event(db: Session, user: User, index: int, raw: Any) -> CollectorEventResult:
    if not isinstance(raw, dict):
        return _result(index, None, "rejected", reason="event must be a JSON object")
    raw_key = raw.get("idempotencyKey", raw.get("idempotency_key"))
    # Checked before validation: recursive steps (validation, size check, intake) cannot handle deep nesting.
    if any(_exceeds_depth(raw.get(name), MAX_RAW_DATA_DEPTH) for name in ("rawData", "raw_data")):
        safe_key = raw_key if isinstance(raw_key, str) and IDEMPOTENCY_KEY_PATTERN.fullmatch(raw_key) else None
        reason = f"rawData is nested too deeply (maximum {MAX_RAW_DATA_DEPTH} levels)"
        return _result(index, safe_key, "rejected", reason=reason)
    try:
        event = CollectorEventIn.model_validate(raw)
    except ValidationError as error:
        # Echo the key only when it passed validation, so arbitrary input is never reflected.
        key_invalid = any(item["loc"][:1] in (("idempotencyKey",), ("idempotency_key",)) for item in error.errors())
        safe_key = raw_key if isinstance(raw_key, str) and not key_invalid else None
        return _result(index, safe_key, "rejected", reason=_validation_reason(error))

    key = event.idempotency_key
    now = datetime.now(UTC)
    problem = _time_problem(event.occurred_at, now) or _raw_data_problem(event.raw_data)
    if problem is not None:
        return _result(index, key, "rejected", reason=problem)

    event_uid = collector_event_uid(user.id, key)
    existing = _existing_event(db, event_uid)
    if existing is not None:
        return _result(index, key, "duplicate", existing)

    payload: dict[str, Any] = {
        "event_uid": event_uid,
        "occurred_at": event.occurred_at,
        "source": DetectionSource.MANUAL.name,  # never taken from the client
        "event_type": event.event_type,
        "signature": event.signature,
        "severity": event.severity,
        "src_ip": event.src_ip,
        "dest_ip": event.dest_ip,
        "src_port": event.src_port,
        "dest_port": event.dest_port,
        "protocol": event.protocol,
        "anomaly_score": event.anomaly_score,
        "asset_id": event.asset_id,
        "raw_data": {
            **(event.raw_data or {}),
            RESERVED_RAW_DATA_KEY: {
                "name": COLLECTOR_NAME,
                "submitted_by": str(user.id),
                "received_at": now.isoformat(),
            },
        },
    }
    try:
        stored = create_event(db, {name: value for name, value in payload.items() if value is not None})
    except HTTPException as error:
        db.rollback()
        if error.status_code == status.HTTP_409_CONFLICT:
            return _result(index, key, "duplicate", _existing_event(db, event_uid))
        if error.status_code == status.HTTP_404_NOT_FOUND:
            return _result(index, key, "rejected", reason="assetId does not match a registered asset")
        return _result(index, key, "rejected", reason=_safe_intake_reason(error))
    except IntegrityError:
        # A concurrent submission stored the same UID first: the unique constraint is the final guard.
        db.rollback()
        return _result(index, key, "duplicate", _existing_event(db, event_uid))
    except SQLAlchemyError:
        db.rollback()
        return _result(index, key, "rejected", reason="event could not be stored")
    return _result(index, key, "created", stored)


def _safe_intake_reason(error: HTTPException) -> str:
    detail = str(error.detail)
    for field in ("src_ip", "dest_ip"):
        if detail == f"Invalid {field}":
            camel = "srcIp" if field == "src_ip" else "destIp"
            return f"{camel}: must be a valid IPv4 or IPv6 address"
    return "event failed validation"


def collector_status(db: Session) -> dict[str, Any]:
    is_collector_event = (
        SecurityEvent.event_uid.startswith(EVENT_UID_PREFIX, autoescape=True),
        SecurityEvent.raw_data[RESERVED_RAW_DATA_KEY]["name"].astext == COLLECTOR_NAME,
    )
    now = datetime.now(UTC)
    total = int(db.scalar(select(func.count()).select_from(SecurityEvent).where(*is_collector_event)) or 0)
    last_24h = int(
        db.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(*is_collector_event, SecurityEvent.created_at >= now - timedelta(hours=24))
        )
        or 0
    )
    last_received_at = db.scalar(select(func.max(SecurityEvent.created_at)).where(*is_collector_event))
    recent = db.scalars(
        select(SecurityEvent)
        .where(*is_collector_event)
        .options(joinedload(SecurityEvent.asset), selectinload(SecurityEvent.incidents))
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(RECENT_EVENT_LIMIT)
    ).unique().all()
    receiving = last_received_at is not None and now - last_received_at <= RECEIVING_WINDOW
    return {
        "collector": COLLECTOR_NAME,
        "status": "receiving" if receiving else "idle",
        "total_events": total,
        "events_last_24h": last_24h,
        "last_received_at": last_received_at,
        "recent_events": list(recent),
    }
