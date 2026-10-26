"""GET /api/threat-intelligence/techniques/observed: read-only, source-supplied ATT&CK observations.

Runs on the core_api fixture's throwaway schema (rolled back); tables come from the models, so migration 0007
is never executed. The request clock is pinned so window boundaries are exact.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import func, select

from app.api import threat_intelligence
from app.db.base import Base
from app.db.session import engine
from app.models.attack_technique import EventAttackTechnique
from app.models.enums import DetectionSource, IncidentState, Severity
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent
from app.services.attack_observations import ObservationQuery, _matching
from tests.conftest import CoreApi

URL = "/api/threat-intelligence/techniques/observed"
AS_OF = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
UNKNOWN = {"status": "unknown", "name": None, "tactics": [], "url": None}


@pytest.fixture(autouse=True)
def pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_intelligence, "_utc_now", lambda: AS_OF)


class Seed:
    def __init__(self, core_api: CoreApi) -> None:
        self.api = core_api

    def event(self, techniques: list[str], *, at: datetime = AS_OF - timedelta(hours=1), source: DetectionSource = DetectionSource.SURICATA,
              severity: Severity = Severity.MEDIUM, origin: str = "ingest_field", raw_data: dict | None = None) -> UUID:
        with self.api.session_factory() as session:
            row = SecurityEvent(event_uid=f"evt-obs-{uuid4().hex}", occurred_at=at, source=source, event_type="alert",
                                severity=severity, raw_data=raw_data)
            session.add(row)
            session.flush()
            session.add_all(EventAttackTechnique(event_id=row.id, technique_id=technique, evidence_kind="source_supplied",
                                                 evidence_origin=origin) for technique in techniques)
            session.commit()
            return row.id

    def incident(self, events: list[UUID], state: IncidentState = IncidentState.PRIORITISED) -> UUID:
        with self.api.session_factory() as session:
            row = Incident(incident_key=f"INC-{uuid4().hex[:8]}", title="Observation test", severity=Severity.HIGH,
                           detection_source=DetectionSource.SURICATA, state=state)
            session.add(row)
            session.flush()
            session.add_all(IncidentEvent(incident_id=row.id, event_id=event_id) for event_id in events)
            session.commit()
            return row.id


@pytest.fixture
def seed(core_api: CoreApi) -> Seed:
    return Seed(core_api)


def get(core_api: CoreApi, **params: Any) -> Any:
    return core_api.client.get(URL, params=params, headers=core_api.headers)


def items(core_api: CoreApi, **params: Any) -> list[dict[str, Any]]:
    response = get(core_api, **params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


@contextmanager
def recorded_statements() -> Iterator[list[str]]:
    statements: list[str] = []

    def record(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        statements.append(statement)

    sa_event.listen(engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        sa_event.remove(engine, "before_cursor_execute", record)


# --- authentication and validation -------------------------------------------------------------------


def test_authentication_is_required(core_api: CoreApi) -> None:
    assert core_api.client.get(URL).status_code == 401


@pytest.mark.parametrize(
    "params",
    [{"days": 0}, {"days": 91}, {"days": "x"}, {"pageSize": 0}, {"pageSize": 101}, {"page": 0}, {"sortBy": "severity"},
     {"sortOrder": "up"}, {"source": "suricata"}, {"source": "HYBRID"}, {"origin": "raw_data"}, {"techniqueId": "TA0006"},
     {"techniqueId": "T1110.01"}, {"techniqueId": "T 1110"}, {"techniqueId": ""}, {"techniqueId": "T" * 40}],
)
def test_invalid_parameters_are_refused(core_api: CoreApi, params: dict[str, Any]) -> None:
    assert get(core_api, **params).status_code == 422


def test_the_technique_filter_uses_the_ingestion_rule(core_api: CoreApi, seed: Seed) -> None:
    seed.event(["T1110"])
    assert [i["techniqueId"] for i in items(core_api, techniqueId=" t1110 ")] == ["T1110"]


# --- empty results, window and asOf --------------------------------------------------------------------


def test_no_evidence_gives_an_honest_empty_page(core_api: CoreApi) -> None:
    body = get(core_api).json()
    assert body == {"items": [], "total": 0, "page": 1, "pageSize": 25, "asOf": "2026-10-25T12:00:00Z", "windowDays": 7, "catalogue": None}


def test_window_boundaries_are_inclusive_at_both_ends(core_api: CoreApi, seed: Seed) -> None:
    cutoff = AS_OF - timedelta(days=7)
    seed.event(["T1001"], at=cutoff)  # exactly at the cutoff: included
    seed.event(["T1002"], at=cutoff - timedelta(microseconds=1))  # just before: excluded
    seed.event(["T1003"], at=AS_OF)  # exactly asOf: included
    seed.event(["T1004"], at=AS_OF + timedelta(microseconds=1))  # after asOf: excluded
    body = get(core_api, sortBy="techniqueId", sortOrder="asc").json()
    assert [i["techniqueId"] for i in body["items"]] == ["T1001", "T1003"]
    assert body["asOf"] == "2026-10-25T12:00:00Z" and body["windowDays"] == 7
    assert [i["techniqueId"] for i in items(core_api, days=1)] == ["T1003"]  # the cutoff moves with days, asOf does not


# --- filters and their interaction ---------------------------------------------------------------------


@pytest.fixture
def mixed(seed: Seed) -> dict[str, UUID]:
    suricata = seed.event(["T1110", "T1046"], source=DetectionSource.SURICATA, severity=Severity.HIGH)
    manual = seed.event(["T1110"], source=DetectionSource.MANUAL, origin="collector_field", severity=Severity.CRITICAL)
    return {
        "suricata": suricata,
        "manual": manual,
        "suricata_incident": seed.incident([suricata], IncidentState.PRIORITISED),
        "manual_incident": seed.incident([manual], IncidentState.CONTAINED),
    }


def test_unfiltered_rows_combine_both_sources(core_api: CoreApi, mixed: dict[str, UUID]) -> None:
    t1110 = next(i for i in items(core_api) if i["techniqueId"] == "T1110")
    assert (t1110["eventCount"], t1110["incidentCount"], t1110["activeIncidentCount"]) == (2, 2, 1)
    assert t1110["sources"] == {"MANUAL": 1, "SURICATA": 1} and t1110["origins"] == {"collector_field": 1, "ingest_field": 1}
    assert t1110["highestSeverity"] == "CRITICAL"


def test_a_source_filter_excludes_incidents_reached_only_through_other_sources(core_api: CoreApi, mixed: dict[str, UUID]) -> None:
    t1110 = next(i for i in items(core_api, source="SURICATA") if i["techniqueId"] == "T1110")
    assert (t1110["eventCount"], t1110["incidentCount"], t1110["activeIncidentCount"]) == (1, 1, 1)
    assert t1110["incidentIds"] == [str(mixed["suricata_incident"])]  # never the MANUAL-only incident
    assert t1110["sources"] == {"SURICATA": 1} and t1110["origins"] == {"ingest_field": 1}
    assert t1110["highestSeverity"] == "HIGH"  # the CRITICAL MANUAL event is filtered out everywhere


def test_origin_and_technique_filters_apply_to_every_figure(core_api: CoreApi, mixed: dict[str, UUID]) -> None:
    (row,) = items(core_api, origin="collector_field")
    assert (row["techniqueId"], row["eventCount"], row["incidentIds"], row["activeIncidentCount"]) == (
        "T1110", 1, [str(mixed["manual_incident"])], 0,
    )
    assert row["sources"] == {"MANUAL": 1}
    assert [i["techniqueId"] for i in items(core_api, techniqueId="T1046")] == ["T1046"]
    assert items(core_api, source="SURICATA", origin="collector_field") == []  # no event matches both
    assert items(core_api, source="MANUAL", techniqueId="T1046") == []


# --- aggregation -----------------------------------------------------------------------------------------


def test_counts_times_severity_and_distinct_incidents(core_api: CoreApi, seed: Seed) -> None:
    first = seed.event(["T1059"], at=AS_OF - timedelta(days=3), severity=Severity.LOW)
    second = seed.event(["T1059"], at=AS_OF - timedelta(days=1), severity=Severity.HIGH)
    third = seed.event(["T1059"], at=AS_OF - timedelta(hours=2), severity=Severity.MEDIUM)
    shared = seed.incident([first, second], IncidentState.VERIFIED)  # two matching events, one incident
    seed.incident([third], IncidentState.LEARNED)
    (row,) = items(core_api)
    assert row["eventCount"] == 3
    assert (row["firstSeen"], row["lastSeen"]) == ((AS_OF - timedelta(days=3)).isoformat().replace("+00:00", "Z"),
                                                  (AS_OF - timedelta(hours=2)).isoformat().replace("+00:00", "Z"))
    assert row["highestSeverity"] == "HIGH"
    assert (row["incidentCount"], row["activeIncidentCount"]) == (2, 1)
    assert str(shared) in row["incidentIds"]


def test_incident_ids_are_capped_without_undercounting(core_api: CoreApi, seed: Seed) -> None:
    events = [seed.event(["T1078"]) for _ in range(105)]
    incidents = [seed.incident([event_id]) for event_id in events]
    (row,) = items(core_api)
    assert (row["eventCount"], row["incidentCount"], row["activeIncidentCount"]) == (105, 105, 105)
    assert row["incidentIds"] == sorted(str(i) for i in incidents)[:100]


# --- pagination and ordering ---------------------------------------------------------------------------


def test_pagination_sorting_and_tie_breaking(core_api: CoreApi, seed: Seed) -> None:
    for technique, count, hours_ago in (("T1003", 3, 5), ("T1001", 2, 1), ("T1002", 2, 2), ("T1004", 1, 3)):
        for _ in range(count):
            seed.event([technique], at=AS_OF - timedelta(hours=hours_ago))
    order = lambda **p: [i["techniqueId"] for i in items(core_api, **p)]  # noqa: E731
    assert order() == ["T1003", "T1001", "T1002", "T1004"]  # eventCount desc, ties by techniqueId asc
    assert order(sortOrder="asc") == ["T1004", "T1001", "T1002", "T1003"]
    assert order(sortBy="techniqueId", sortOrder="desc") == ["T1004", "T1003", "T1002", "T1001"]
    assert order(sortBy="lastSeen") == ["T1001", "T1002", "T1004", "T1003"]
    first, second = get(core_api, pageSize=2).json(), get(core_api, pageSize=2, page=2).json()
    assert [i["techniqueId"] for i in first["items"]] == ["T1003", "T1001"] and first["total"] == 4
    assert [i["techniqueId"] for i in second["items"]] == ["T1002", "T1004"] and second["total"] == 4
    assert get(core_api, page=3, pageSize=2).json()["items"] == []


# --- evidence boundaries, catalogue, read-only and query count ------------------------------------------


def test_raw_data_only_ids_and_other_evidence_are_never_counted(core_api: CoreApi, seed: Seed) -> None:
    seed.event([], raw_data={"alert": {"metadata": {"mitre_technique_id": ["T1110"]}}, "tags": ["T1046"]})
    assert items(core_api) == []
    sql = str(_matching(ObservationQuery(as_of=AS_OF, days=7)).compile(compile_kwargs={"literal_binds": True}))
    assert "event_attack_techniques.evidence_kind = 'source_supplied'" in sql


def test_catalogue_metadata_is_unknown_and_never_invented(core_api: CoreApi, seed: Seed) -> None:
    seed.event(["T1110", "T9999"])
    body = get(core_api).json()
    assert body["catalogue"] is None
    assert all(item["catalogue"] == UNKNOWN for item in body["items"])
    assert {item["evidenceKind"] for item in body["items"]} == {"source_supplied"}


def test_the_endpoint_is_read_only(core_api: CoreApi, mixed: dict[str, UUID]) -> None:
    def counts() -> dict[str, int]:
        with core_api.session_factory() as session:
            return {name: session.scalar(select(func.count()).select_from(table)) for name, table in Base.metadata.tables.items()}

    before = counts()
    with recorded_statements() as statements:
        assert get(core_api).status_code == 200
    assert counts() == before
    writes = [s for s in statements if s.lstrip().split(None, 1)[0].upper() in {"INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE"}]
    assert writes == []


def test_the_query_count_does_not_grow_with_the_page(core_api: CoreApi, seed: Seed) -> None:
    seed.incident([seed.event(["T1001"])])

    def selects() -> int:
        with recorded_statements() as statements:
            assert get(core_api).status_code == 200
        return len([s for s in statements if s.lstrip().upper().startswith("SELECT")])

    one = selects()
    for n in range(2, 12):
        seed.incident([seed.event([f"T{1000 + n}"]), seed.event([f"T{1000 + n}"])])
    assert selects() == one  # a fixed number of queries for 1 or 11 techniques (no N+1)
