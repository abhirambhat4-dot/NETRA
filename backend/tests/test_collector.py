"""NETRA Web Collector API tests (PostgreSQL schema per test, always rolled back)."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.models.asset import Asset
from app.models.enums import AssetEnvironment, AssetType, Criticality, DetectionSource, Exposure
from app.models.event import SecurityEvent
from app.models.user import User
from app.services import collector as collector_service
from app.services.auth import create_access_token
from app.services.collector import (
    COLLECTOR_NAME,
    EVENT_UID_PREFIX,
    MAX_RAW_DATA_BYTES,
    collector_event_uid,
    collector_user_limiter,
)
from tests.conftest import CoreApi

SUBMIT = "/api/collector/events"
STATUS = "/api/collector/status"


@pytest.fixture(autouse=True)
def clear_collector_rate_limit() -> Any:
    collector_user_limiter.clear()
    yield
    collector_user_limiter.clear()


def event(key: str | None = None, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "idempotencyKey": key or f"key-{uuid4().hex}",
        "occurredAt": datetime.now(UTC).isoformat(),
        "eventType": "suspicious_login",
        "severity": "medium",
        "signature": "Operator reported an unexpected login prompt",
        "srcIp": "198.51.100.20",
        "destIp": "10.250.30.7",
        "srcPort": 51515,
        "destPort": 443,
        "protocol": "TCP",
        "rawData": {"note": "submitted from the collector test"},
    }
    payload.update(overrides)
    return {name: value for name, value in payload.items() if value is not None}


def submit(api: CoreApi, *events: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
    return api.client.post(SUBMIT, json={"events": list(events)}, headers=api.headers if headers is None else headers)


def single(api: CoreApi, payload: dict[str, Any]) -> dict[str, Any]:
    response = submit(api, payload)
    assert response.status_code == 200, response.text
    [result] = response.json()["results"]
    return result


def stored(api: CoreApi, event_uid: str) -> SecurityEvent:
    with api.session_factory() as session:
        record = session.scalar(select(SecurityEvent).where(SecurityEvent.event_uid == event_uid))
        assert record is not None
        return record


def test_endpoints_require_authentication(core_api: CoreApi) -> None:
    assert core_api.client.post(SUBMIT, json={"events": [event()]}).status_code == 401
    assert core_api.client.get(STATUS).status_code == 401
    assert core_api.client.post(SUBMIT, json={"events": [event()]}, headers={"Authorization": "Bearer bad"}).status_code == 401


def test_valid_single_event_is_created_as_manual_with_attribution(core_api: CoreApi) -> None:
    result = single(core_api, event("single-1"))

    assert result["status"] == "created"
    assert result["idempotencyKey"] == "single-1"
    record = stored(core_api, result["eventUid"])
    assert record.source == DetectionSource.MANUAL
    attribution = record.raw_data["collector"]
    assert attribution["name"] == COLLECTOR_NAME
    with core_api.session_factory() as session:
        user = session.scalar(select(User).where(User.email == "core-api-test@example.com"))
    assert attribution["submitted_by"] == str(user.id)
    assert datetime.fromisoformat(attribution["received_at"]) <= datetime.now(UTC)
    assert record.raw_data["note"] == "submitted from the collector test"


def test_valid_batch_is_created(core_api: CoreApi) -> None:
    response = submit(core_api, *(event(f"batch-{index}") for index in range(5)))

    body = response.json()
    assert response.status_code == 200
    assert (body["created"], body["duplicates"], body["rejected"]) == (5, 0, 0)
    assert [result["index"] for result in body["results"]] == list(range(5))


def test_client_cannot_override_source_or_attribution(core_api: CoreApi) -> None:
    with_source = single(core_api, event("override-1", source="SURICATA"))
    with_attribution = single(core_api, event("override-2", rawData={"collector": {"name": "spoofed"}}))
    with_detection_source = single(core_api, event("override-3", detectionSource="THREAT_INTEL"))

    assert with_source["status"] == "rejected"
    assert "source: is assigned by the server" in with_source["reason"]
    assert with_attribution["status"] == "rejected"
    assert "rawData.collector is reserved" in with_attribution["reason"]
    assert with_detection_source["status"] == "rejected"
    with core_api.session_factory() as session:
        assert session.scalar(select(SecurityEvent).where(SecurityEvent.event_uid.startswith(EVENT_UID_PREFIX))) is None


def test_duplicate_key_is_reported_and_scoped_per_user(core_api: CoreApi) -> None:
    first = single(core_api, event("repeat-1"))
    again = single(core_api, event("repeat-1"))
    with core_api.session_factory() as session:
        other = User(email="second-user@example.com", full_name="Second", password_hash="unused")
        session.add(other)
        session.commit()
        other_headers = {"Authorization": f"Bearer {create_access_token(other)}"}
    other_user = submit(core_api, event("repeat-1"), headers=other_headers).json()["results"][0]

    assert first["status"] == "created"
    assert again["status"] == "duplicate"
    assert again["eventId"] == first["eventId"]
    assert other_user["status"] == "created"
    assert other_user["eventUid"] != first["eventUid"]


def test_duplicate_within_one_batch(core_api: CoreApi) -> None:
    body = submit(core_api, event("same-batch"), event("same-batch")).json()

    assert [result["status"] for result in body["results"]] == ["created", "duplicate"]


def test_race_is_resolved_as_duplicate(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    created = single(core_api, event("race-1"))
    real_lookup = collector_service._existing_event
    real_create = collector_service.create_event
    lookups: list[str] = []

    def stale_first_lookup(db: Any, event_uid: str) -> Any:
        # The concurrent request committed after this request's pre-check.
        lookups.append(event_uid)
        return None if len(lookups) == 1 else real_lookup(db, event_uid)

    monkeypatch.setattr(collector_service, "_existing_event", stale_first_lookup)
    caught_by_intake = single(core_api, event("race-1"))

    def concurrent_winner(db: Any, payload: dict[str, Any]) -> None:
        # Another request inserts the same UID first; this request then hits the unique constraint.
        real_create(db, payload)
        raise IntegrityError("INSERT INTO security_events", {}, Exception("unique violation"))

    lookups.clear()
    monkeypatch.setattr(collector_service, "create_event", concurrent_winner)
    caught_by_constraint = single(core_api, event("race-2"))

    assert caught_by_intake["status"] == "duplicate"
    assert caught_by_intake["eventId"] == created["eventId"]
    assert caught_by_constraint["status"] == "duplicate"
    assert caught_by_constraint["eventId"] is not None
    with core_api.session_factory() as session:
        uids = session.scalars(select(SecurityEvent.event_uid)).all()
    assert len(uids) == len(set(uids)) == 2


def test_event_uid_is_opaque_and_within_column_limit(core_api: CoreApi) -> None:
    long_key = "k" * 128
    result = single(core_api, event(long_key))

    assert result["status"] == "created"
    assert len(result["eventUid"]) <= 128
    assert result["eventUid"].startswith(EVENT_UID_PREFIX)
    assert "core-api-test" not in result["eventUid"]
    with core_api.session_factory() as session:
        user_id = session.scalar(select(User.id).where(User.email == "core-api-test@example.com"))
    assert str(user_id) not in result["eventUid"]
    assert result["eventUid"] == collector_event_uid(user_id, long_key)
    assert single(core_api, event("k" * 129))["status"] == "rejected"


@pytest.mark.parametrize(
    ("field", "limit"),
    [("eventType", 100), ("signature", 512), ("protocol", 16)],
)
def test_text_length_boundaries(core_api: CoreApi, field: str, limit: int) -> None:
    at_limit = single(core_api, event(**{field: "x" * limit}))
    over_limit = single(core_api, event(**{field: "x" * (limit + 1)}))

    assert at_limit["status"] == "created"
    assert over_limit["status"] == "rejected"
    assert field in over_limit["reason"]
    assert "x" * (limit + 1) not in over_limit["reason"]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"srcIp": "999.1.1.1"}, "srcIp: must be a valid IPv4 or IPv6 address"),
        ({"destIp": "not-an-ip"}, "destIp: must be a valid IPv4 or IPv6 address"),
        ({"srcPort": 70000}, "srcPort"),
        ({"destPort": -1}, "destPort"),
        ({"anomalyScore": 1.5}, "anomalyScore"),
        ({"anomalyScore": -0.1}, "anomalyScore"),
        ({"severity": "urgent"}, "severity"),
        ({"occurredAt": "2026-10-08T10:00:00"}, "timezone"),
    ],
)
def test_invalid_fields_are_rejected_safely(core_api: CoreApi, overrides: dict[str, Any], reason: str) -> None:
    result = single(core_api, event(**overrides))

    assert result["status"] == "rejected"
    assert reason in result["reason"]
    for value in overrides.values():
        if isinstance(value, str) and value not in ("2026-10-08T10:00:00",):
            assert value not in result["reason"]


def test_nonexistent_asset_is_rejected_and_existing_asset_links(core_api: CoreApi) -> None:
    missing = single(core_api, event(assetId=str(uuid4())))
    with core_api.session_factory() as session:
        asset = Asset(asset_key=f"COLLECT-{uuid4().hex[:6]}", name="Collector test asset",
                      hostname="collector-test.netra-demo.example", ip_address="10.250.30.7",
                      asset_type=AssetType.WORKSTATION, environment=AssetEnvironment.TEST,
                      criticality=Criticality.MEDIUM, exposure=Exposure.INTERNAL)
        session.add(asset)
        session.commit()
        asset_id = asset.id
    linked = single(core_api, event(assetId=str(asset_id)))

    assert missing["status"] == "rejected"
    assert missing["reason"] == "assetId does not match a registered asset"
    assert linked["status"] == "created"
    assert stored(core_api, linked["eventUid"]).asset_id == asset_id


def test_timestamp_window(core_api: CoreApi) -> None:
    now = datetime.now(UTC)
    future = single(core_api, event(occurredAt=(now + timedelta(minutes=6)).isoformat()))
    near_future = single(core_api, event(occurredAt=(now + timedelta(minutes=4)).isoformat()))
    old = single(core_api, event(occurredAt=(now - timedelta(days=31)).isoformat()))
    recent = single(core_api, event(occurredAt=(now - timedelta(days=29)).isoformat()))

    assert future["status"] == "rejected" and "future" in future["reason"]
    assert old["status"] == "rejected" and "30 days" in old["reason"]
    assert near_future["status"] == "created"
    assert recent["status"] == "created"


def test_raw_data_limits(core_api: CoreApi) -> None:
    secret = "do-not-echo-this-value"
    oversized = single(core_api, event(rawData={"blob": secret + "x" * MAX_RAW_DATA_BYTES}))
    not_object = single(core_api, event(rawData=["not", "an", "object"]))
    within = single(core_api, event(rawData={"blob": "x" * (MAX_RAW_DATA_BYTES - 100)}))

    assert oversized["status"] == "rejected"
    assert "16 KB" in oversized["reason"]
    assert secret not in json.dumps(oversized)
    assert not_object["status"] == "rejected"
    assert within["status"] == "created"


def test_batch_limits_and_malformed_bodies(core_api: CoreApi) -> None:
    secret = "secret-payload-value"
    too_many = submit(core_api, *(event(rawData={"note": secret}) for _ in range(21)))
    empty = submit(core_api)
    not_json = core_api.client.post(SUBMIT, content=b"{not json", headers={**core_api.headers, "Content-Type": "application/json"})
    nan = core_api.client.post(SUBMIT, content=b'{"events":[{"anomalyScore": NaN}]}', headers={**core_api.headers, "Content-Type": "application/json"})
    oversized = core_api.client.post(SUBMIT, content=b"{" + b" " * (600 * 1024) + b"}", headers={**core_api.headers, "Content-Type": "application/json"})

    assert too_many.status_code == 422
    assert too_many.json() == {"detail": "A batch may contain at most 20 events"}
    assert secret not in too_many.text
    assert empty.status_code == 422
    assert not_json.status_code == 422
    assert nan.status_code == 422
    assert oversized.status_code == 413
    with core_api.session_factory() as session:
        assert session.scalar(select(SecurityEvent)) is None


def test_rate_limit_returns_429(core_api: CoreApi) -> None:
    for batch in range(3):
        response = submit(core_api, *(event(f"rate-{batch}-{index}") for index in range(20)))
        assert response.status_code == 200

    limited = submit(core_api, event("rate-over"))

    assert limited.status_code == 429
    assert "rate limit" in limited.json()["detail"].lower()


def test_status_idle_with_no_events(core_api: CoreApi) -> None:
    response = core_api.client.get(STATUS, headers=core_api.headers)

    assert response.status_code == 200
    assert response.json() == {
        "collector": COLLECTOR_NAME,
        "status": "idle",
        "totalEvents": 0,
        "eventsLast24h": 0,
        "lastReceivedAt": None,
        "recentEvents": [],
    }


def test_status_receiving_after_event_then_idle_when_stale(core_api: CoreApi) -> None:
    created = single(core_api, event("status-1"))
    receiving = core_api.client.get(STATUS, headers=core_api.headers).json()

    assert receiving["status"] == "receiving"
    assert receiving["totalEvents"] == 1
    assert receiving["eventsLast24h"] == 1
    assert receiving["lastReceivedAt"] is not None
    assert [item["eventUid"] for item in receiving["recentEvents"]] == [created["eventUid"]]
    assert receiving["recentEvents"][0]["detectionSource"] == "MANUAL"
    assert "rawData" not in receiving["recentEvents"][0]

    with core_api.session_factory() as session:
        session.execute(
            update(SecurityEvent)
            .where(SecurityEvent.event_uid == created["eventUid"])
            .values(created_at=datetime.now(UTC) - timedelta(hours=2))
        )
        session.commit()
    idle = core_api.client.get(STATUS, headers=core_api.headers).json()

    assert idle["status"] == "idle"
    assert idle["eventsLast24h"] == 1


def test_status_lists_at_most_ten_and_ignores_other_events(core_api: CoreApi) -> None:
    submit(core_api, *(event(f"many-{index}") for index in range(12)))
    ingest = core_api.client.post(
        "/api/events/ingest",
        json={"eventUid": f"{EVENT_UID_PREFIX}spoofed", "occurredAt": datetime.now(UTC).isoformat(),
              "source": "MANUAL", "eventType": "spoof", "severity": "LOW"},
        headers=core_api.headers,
    )

    body = core_api.client.get(STATUS, headers=core_api.headers).json()

    assert ingest.status_code == 201  # existing ingest behaviour is unchanged
    assert body["totalEvents"] == 12  # the prefix alone, without server attribution, is not counted
    assert len(body["recentEvents"]) == 10


def test_existing_ingest_endpoint_is_unchanged(core_api: CoreApi) -> None:
    payload = {"eventUid": f"ingest-{uuid4().hex}", "occurredAt": datetime.now(UTC).isoformat(),
               "source": "SURICATA", "eventType": "alert", "severity": "HIGH", "srcIp": "203.0.113.9"}

    first = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)
    second = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)

    assert first.status_code == 201
    assert first.json()["detectionSource"] == "SURICATA"
    assert second.status_code == 409


def test_intake_rejection_details_are_mapped_safely() -> None:
    assert collector_service._safe_intake_reason(HTTPException(422, "Invalid src_ip")) == (
        "srcIp: must be a valid IPv4 or IPv6 address"
    )
    assert collector_service._safe_intake_reason(HTTPException(422, "Invalid severity: <script>")) == (
        "event failed validation"
    )


DEEP_MARKER = "deep-nesting-secret-value"


def nested_json(depth: int, leaf: str = f'"{DEEP_MARKER}"') -> str:
    """A JSON object nested ``depth`` levels deep, built as text so the test never recurses."""
    return '{"level":' * depth + leaf + "}" * depth


def deep_body(depth: int, key: str) -> bytes:
    fields = {name: value for name, value in event(key).items() if name != "rawData"}
    encoded = json.dumps(fields)  # a flat object; rawData is spliced in as text below
    return ('{"events":[' + encoded[:-1] + ',"rawData":' + nested_json(depth) + "}]}").encode()


def post_raw(api: CoreApi, body: bytes) -> Any:
    return api.client.post(SUBMIT, content=body, headers={**api.headers, "Content-Type": "application/json"})


def collector_event_count(api: CoreApi) -> int:
    with api.session_factory() as session:
        return len(session.scalars(select(SecurityEvent).where(SecurityEvent.event_uid.startswith(EVENT_UID_PREFIX))).all())


def test_raw_data_depth_limit_boundary(core_api: CoreApi) -> None:
    at_limit = single(core_api, event("depth-20", rawData=json.loads(nested_json(20))))
    over_limit = single(core_api, event("depth-21", rawData=json.loads(nested_json(21))))
    in_list = single(core_api, event("depth-list", rawData={"items": [[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]}))

    assert at_limit["status"] == "created"
    assert over_limit == {**over_limit, "status": "rejected", "idempotencyKey": "depth-21",
                          "reason": "rawData is nested too deeply (maximum 20 levels)"}
    assert in_list["status"] == "rejected"  # arrays count as levels too
    assert collector_event_count(core_api) == 1


def test_deep_raw_data_is_rejected_per_event_not_500(core_api: CoreApi) -> None:
    response = post_raw(core_api, deep_body(1500, "depth-1500"))

    assert response.status_code == 200
    [result] = response.json()["results"]
    assert result["status"] == "rejected"
    assert result["reason"] == "rawData is nested too deeply (maximum 20 levels)"
    assert DEEP_MARKER not in response.text
    assert collector_event_count(core_api) == 0


def test_body_too_deep_to_parse_is_422_not_500(core_api: CoreApi) -> None:
    response = post_raw(core_api, deep_body(5000, "depth-5000"))

    assert response.status_code == 422
    assert response.json() == {"detail": "Request body is nested too deeply"}
    assert DEEP_MARKER not in response.text
    assert collector_event_count(core_api) == 0


def test_deep_body_still_requires_authentication(core_api: CoreApi) -> None:
    response = core_api.client.post(SUBMIT, content=deep_body(5000, "unauthenticated"),
                                    headers={"Content-Type": "application/json"})

    assert response.status_code == 401
