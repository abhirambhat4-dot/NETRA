"""Source-supplied ATT&CK technique ingestion (POST /api/events/ingest and POST /api/collector/events).

Pure tests cover normalisation; API tests run on the core_api fixture's throwaway schema (rolled back), whose
tables come from the models, so migration 0007 is never executed.
"""

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models.attack_technique import (
    MAX_ATTACK_TECHNIQUES_PER_EVENT,
    TECHNIQUE_ID_PATTERN,
    EventAttackTechnique,
    normalize_attack_technique_ids,
)
from app.models.event import SecurityEvent
from app.services import intake
from tests.conftest import CoreApi

INGEST = "/api/events/ingest"
COLLECTOR = "/api/collector/events"


# --- normalisation (pure) ----------------------------------------------------------------------------


def test_base_and_sub_technique_ids_are_accepted() -> None:
    assert normalize_attack_technique_ids(["T1110", "T1110.001", "T0001", "T9999.999"]) == ["T1110", "T1110.001", "T0001", "T9999.999"]


def test_ids_are_trimmed_upper_cased_and_de_duplicated_keeping_first_order() -> None:
    assert normalize_attack_technique_ids([" t1110 ", "T1110", "t1110.001\n", "\tT1059 ", "T1059"]) == ["T1110", "T1110.001", "T1059"]


def test_omitted_and_empty_lists_give_no_ids() -> None:
    assert normalize_attack_technique_ids(None) == [] and normalize_attack_technique_ids([]) == []


def test_at_most_twenty_distinct_ids() -> None:
    twenty = [f"T{1000 + n}" for n in range(MAX_ATTACK_TECHNIQUES_PER_EVENT)]
    assert normalize_attack_technique_ids(twenty) == twenty
    assert len(normalize_attack_technique_ids(twenty + [i.lower() for i in twenty])) == 20  # duplicates do not count
    with pytest.raises(ValueError, match="at most 20 distinct technique IDs per event"):
        normalize_attack_technique_ids([*twenty, "T2000"])
    with pytest.raises(ValueError, match="at most 100 items"):
        normalize_attack_technique_ids(["T1110"] * 101)


@pytest.mark.parametrize(
    "bad",
    ["T111", "T11100", "TA0006", "T1110.01", "T1110.0001", "T 1110", "T1110x", "T1110.", "", "   ", "\n",
     "T１１１０", "T١١١٠", "T1110\nT1059", "X1110", "1110"],
)
def test_malformed_ids_tactic_ids_and_whitespace_cases_are_refused(bad: str) -> None:
    with pytest.raises(ValueError) as refused:
        normalize_attack_technique_ids(["T1110", bad])
    # A fixed message with the position only: the submitted value can never be echoed.
    assert str(refused.value) == "item 1 must be an ATT&CK technique ID such as T1110 or T1110.001"


def test_non_string_items_are_refused() -> None:
    with pytest.raises(ValueError, match="item 0 must be a string"):
        normalize_attack_technique_ids([1110])


def test_every_normalised_id_satisfies_the_database_check() -> None:
    database = re.compile(TECHNIQUE_ID_PATTERN)
    for value in normalize_attack_technique_ids([" t1110 ", "T1110.001", "t0001", "T9999.999"]):
        assert database.fullmatch(value)


# --- helpers ------------------------------------------------------------------------------------------


def _ingest_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_uid": f"evt-attack-{uuid4().hex}",
        "occurred_at": "2026-10-25T09:00:00Z",
        "source": "SURICATA",
        "event_type": "alert",
        "signature": "ET SCAN Possible brute force",
        "severity": "HIGH",
        "src_ip": "198.51.100.30",
        "dest_ip": "10.20.0.30",
    }
    return payload | overrides


def _collector_event(key: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "idempotencyKey": key,
        "occurredAt": datetime.now(UTC).isoformat(),
        "eventType": "suspicious_login",
        "severity": "medium",
        "srcIp": "198.51.100.31",
        "destIp": "10.20.0.31",
    }
    return payload | overrides


def _rows(core_api: CoreApi, event_id: str | UUID | None = None) -> list[tuple[str, str, str]]:
    with core_api.session_factory() as session:
        query = select(EventAttackTechnique.technique_id, EventAttackTechnique.evidence_kind, EventAttackTechnique.evidence_origin)
        if event_id is not None:
            query = query.where(EventAttackTechnique.event_id == UUID(str(event_id)))
        return [tuple(row) for row in session.execute(query.order_by(EventAttackTechnique.technique_id)).all()]


def _event_count(core_api: CoreApi, event_uid: str) -> int:
    with core_api.session_factory() as session:
        return session.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.event_uid == event_uid))


# --- POST /api/events/ingest -------------------------------------------------------------------------


def test_ingest_stores_source_supplied_ids_with_their_origin_and_returns_them(core_api: CoreApi) -> None:
    response = core_api.client.post(
        INGEST, json=_ingest_payload(attack_technique_ids=[" t1110.001 ", "T1046", "T1110.001"]), headers=core_api.headers
    )
    assert response.status_code == 201, response.text
    event = response.json()
    assert event["attackTechniqueIds"] == ["T1046", "T1110.001"]  # normalised, de-duplicated, sorted
    assert _rows(core_api, event["id"]) == [("T1046", "source_supplied", "ingest_field"), ("T1110.001", "source_supplied", "ingest_field")]
    detail = core_api.client.get(f"/api/events/{event['id']}", headers=core_api.headers).json()
    listed = core_api.client.get("/api/events", headers=core_api.headers).json()["items"]
    assert detail["attackTechniqueIds"] == ["T1046", "T1110.001"]
    assert next(item for item in listed if item["id"] == event["id"])["attackTechniqueIds"] == ["T1046", "T1110.001"]


def test_ingest_accepts_the_camel_case_field_name(core_api: CoreApi) -> None:
    payload = _ingest_payload()
    payload["attackTechniqueIds"] = ["T1059"]
    response = core_api.client.post(INGEST, json=payload, headers=core_api.headers)
    assert response.status_code == 201 and response.json()["attackTechniqueIds"] == ["T1059"]


@pytest.mark.parametrize("ids", [None, []], ids=["omitted", "empty"])
def test_ingest_without_ids_is_unchanged_and_stores_no_technique_rows(core_api: CoreApi, ids: list[str] | None) -> None:
    payload = _ingest_payload() if ids is None else _ingest_payload(attack_technique_ids=ids)
    response = core_api.client.post(INGEST, json=payload, headers=core_api.headers)
    assert response.status_code == 201, response.text
    event = response.json()
    assert event["attackTechniqueIds"] == []
    assert (event["eventUid"], event["detectionSource"], event["severity"], event["signature"]) == (
        payload["event_uid"], "SURICATA", "HIGH", "ET SCAN Possible brute force",
    )
    assert _rows(core_api) == []


@pytest.mark.parametrize(
    "ids",
    [["T1110", "TA0006"], ["T1110.01"], ["T 1110"], [f"T{1000 + n}" for n in range(21)], ["T1110", 1110]],
    ids=["tactic", "short-sub", "inner-space", "21-distinct", "non-string"],
)
def test_ingest_rejects_malformed_ids_without_storing_anything(core_api: CoreApi, ids: list[Any]) -> None:
    payload = _ingest_payload(attack_technique_ids=ids)
    response = core_api.client.post(INGEST, json=payload, headers=core_api.headers)
    assert response.status_code == 422
    assert _event_count(core_api, payload["event_uid"]) == 0 and _rows(core_api) == []


def test_ids_only_in_raw_data_or_the_signature_create_no_technique_records(core_api: CoreApi) -> None:
    raw = {"alert": {"metadata": {"mitre_technique_id": ["T1110"], "mitre_tactic_id": ["TA0006"]}}, "technique": "T1046"}
    response = core_api.client.post(
        INGEST, json=_ingest_payload(signature="ATT&CK T1110 brute force", raw_data=raw), headers=core_api.headers
    )
    assert response.status_code == 201
    assert response.json()["attackTechniqueIds"] == [] and _rows(core_api) == []


def test_a_failing_technique_insert_leaves_no_event_behind(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    # Bypass validation so the database CHECK fails at commit: the event and its technique rows share one
    # transaction, so neither may remain.
    monkeypatch.setattr(intake, "normalize_attack_technique_ids", lambda values: ["NOT-AN-ID"] if values else [])
    payload = _ingest_payload(attack_technique_ids=["T1110"])
    with pytest.raises(IntegrityError, match="ck_event_attack_techniques_technique_id_format"):
        core_api.client.post(INGEST, json=payload, headers=core_api.headers)
    assert _event_count(core_api, payload["event_uid"]) == 0 and _rows(core_api) == []


def test_intake_revalidates_and_refuses_unknown_origins(core_api: CoreApi) -> None:
    with core_api.session_factory() as session:
        with pytest.raises(Exception, match="attack_technique_ids: item 0 must be an ATT&CK technique ID"):
            intake.create_event(session, {**_ingest_payload(), "attack_technique_ids": ["TA0001"]})
        with pytest.raises(ValueError, match="unknown ATT&CK evidence origin"):
            intake.create_event(session, _ingest_payload(), attack_technique_origin="raw_data")
    assert _rows(core_api) == []


# --- POST /api/collector/events ----------------------------------------------------------------------


def test_collector_stores_ids_with_collector_origin_and_rejects_only_the_bad_row(core_api: CoreApi) -> None:
    response = core_api.client.post(
        COLLECTOR,
        json={"events": [
            _collector_event("attack-good", attackTechniqueIds=["t1078", "T1078", "T1021.001 "]),
            _collector_event("attack-bad", attackTechniqueIds=["T1078", "TA0001"]),
            _collector_event("attack-none"),
        ]},
        headers=core_api.headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["created"], body["rejected"], body["duplicates"]) == (2, 1, 0)
    good, bad, none = body["results"]
    assert (good["status"], bad["status"], none["status"]) == ("created", "rejected", "created")
    assert "attackTechniqueIds" in bad["reason"] and "item 1 must be an ATT&CK technique ID" in bad["reason"]
    assert "TA0001" not in bad["reason"]  # submitted values are never echoed
    assert bad["eventId"] is None
    assert _rows(core_api, good["eventId"]) == [("T1021.001", "source_supplied", "collector_field"), ("T1078", "source_supplied", "collector_field")]
    assert _rows(core_api, none["eventId"]) == []
    listed = {item["id"]: item for item in core_api.client.get("/api/events", headers=core_api.headers).json()["items"]}
    assert listed[good["eventId"]]["attackTechniqueIds"] == ["T1021.001", "T1078"]
    assert listed[none["eventId"]]["attackTechniqueIds"] == []


def test_collector_rows_with_too_many_ids_are_rejected_individually(core_api: CoreApi) -> None:
    too_many = [f"T{1000 + n}" for n in range(21)]
    body = core_api.client.post(
        COLLECTOR,
        json={"events": [_collector_event("attack-21", attackTechniqueIds=too_many), _collector_event("attack-ok", attackTechniqueIds=["T1110"])]},
        headers=core_api.headers,
    ).json()
    assert [result["status"] for result in body["results"]] == ["rejected", "created"]
    assert "at most 20 distinct technique IDs per event" in body["results"][0]["reason"]
    assert _rows(core_api) == [("T1110", "source_supplied", "collector_field")]


def test_collector_ids_only_in_raw_data_create_no_technique_records(core_api: CoreApi) -> None:
    body = core_api.client.post(
        COLLECTOR,
        json={"events": [_collector_event("attack-raw", rawData={"mitre_technique_id": "T1110", "tags": ["T1046"]})]},
        headers=core_api.headers,
    ).json()
    assert body["results"][0]["status"] == "created" and _rows(core_api) == []


# --- boundaries on both paths, read-only relationship, collector atomicity ----------------------------

TWENTY = [f"T{1000 + n}" for n in range(20)]
# 100 raw items that normalise to the same 20 distinct IDs (mixed case and padding).
HUNDRED_RAW = [variant for technique in TWENTY for variant in (technique, technique.lower(), f" {technique} ", f"{technique.lower()}\t", technique)]


def test_the_event_relationship_is_read_only_with_no_orm_cascade() -> None:
    relationship = SecurityEvent.attack_techniques.property
    assert relationship.viewonly is True
    assert not relationship.cascade.delete and not relationship.cascade.save_update and not relationship.cascade.delete_orphan


def test_exactly_one_hundred_raw_items_are_accepted() -> None:
    assert len(HUNDRED_RAW) == 100
    assert normalize_attack_technique_ids(HUNDRED_RAW) == TWENTY


@pytest.mark.parametrize(
    ("ids", "status", "stored"),
    [
        (TWENTY, 201, 20),
        (HUNDRED_RAW, 201, 20),
        ([*TWENTY, "T2000"], 422, 0),
        ([*HUNDRED_RAW, "T1000"], 422, 0),  # 101 raw items, even though still 20 distinct
    ],
    ids=["20-distinct", "100-raw", "21-distinct", "101-raw"],
)
def test_ingest_boundaries(core_api: CoreApi, ids: list[str], status: int, stored: int) -> None:
    payload = _ingest_payload(attack_technique_ids=ids)
    response = core_api.client.post(INGEST, json=payload, headers=core_api.headers)
    assert response.status_code == status, response.text
    assert _event_count(core_api, payload["event_uid"]) == (1 if status == 201 else 0)
    assert len(_rows(core_api)) == stored
    if status == 201:
        assert response.json()["attackTechniqueIds"] == sorted(TWENTY)


def test_collector_boundaries_are_applied_per_row(core_api: CoreApi) -> None:
    body = core_api.client.post(
        COLLECTOR,
        json={"events": [
            _collector_event("b-20", attackTechniqueIds=TWENTY),
            _collector_event("b-100", attackTechniqueIds=HUNDRED_RAW),
            _collector_event("b-21", attackTechniqueIds=[*TWENTY, "T2000"]),
            _collector_event("b-101", attackTechniqueIds=[*HUNDRED_RAW, "T1000"]),
            _collector_event("b-empty", attackTechniqueIds=[]),
        ]},
        headers=core_api.headers,
    ).json()
    statuses = {result["idempotencyKey"]: result for result in body["results"]}
    assert [statuses[k]["status"] for k in ("b-20", "b-100", "b-21", "b-101", "b-empty")] == [
        "created", "created", "rejected", "rejected", "created",
    ]
    assert "at most 20 distinct technique IDs per event" in statuses["b-21"]["reason"]
    assert "at most 100 items may be submitted" in statuses["b-101"]["reason"]
    assert len(_rows(core_api, statuses["b-20"]["eventId"])) == len(_rows(core_api, statuses["b-100"]["eventId"])) == 20
    assert _rows(core_api, statuses["b-empty"]["eventId"]) == []
    assert statuses["b-21"]["eventId"] is None and statuses["b-101"]["eventId"] is None
    assert len(_rows(core_api)) == 40


def test_a_failing_technique_insert_on_the_collector_path_stores_nothing(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intake, "normalize_attack_technique_ids", lambda values: ["NOT-AN-ID"] if values else [])
    body = core_api.client.post(
        COLLECTOR,
        json={"events": [_collector_event("atomic-fail", attackTechniqueIds=["T1110"]), _collector_event("atomic-ok")]},
        headers=core_api.headers,
    ).json()
    failed, ok = body["results"]
    assert failed["status"] != "created" and failed["eventId"] is None  # the event was rolled back with its rows
    assert ok["status"] == "created"  # the next row in the batch is unaffected
    assert _rows(core_api) == []
    with core_api.session_factory() as session:
        uids = session.scalars(select(SecurityEvent.event_uid)).all()
    assert uids == [ok["eventUid"]]  # the throwaway schema starts empty: only the unaffected row's event exists
