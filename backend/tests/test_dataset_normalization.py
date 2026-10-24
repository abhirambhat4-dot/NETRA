"""Dataset normalisation tests: validated CIC-IDS2017 rows become provenance-tagged security events,
and those events reach Security Assessment findings only through implemented evidence rules.

All rows are synthetic (documentation addresses). PostgreSQL schema per test, always rolled back.
"""

import importlib.util
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, func, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import engine
from app.models import Asset, ImportBatch, SecurityEvent, ThreatIndicator
from app.models.enums import (
    AssetEnvironment,
    AssetType,
    Criticality,
    DetectionSource,
    Exposure,
    IndicatorType,
    Severity,
)
from app.services import dataset_normalization
from app.services.assessment import assessment_user_limiter
from app.services.dataset_import import import_user_limiter
from app.services.dataset_profiles import CicIds2017Profile, cic_ids2017_occurred_at
from tests.conftest import CoreApi
from tests.test_cic_ids2017_profile import csv_bytes, row

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = BACKEND / "migrations" / "versions" / "0005_add_dataset_event_provenance.py"
PROFILE = CicIds2017Profile()
# row() defaults: 192.0.2.10:51515 -> 198.51.100.20:443/tcp at "7/7/2017 3:30".
SRC, DEST = "192.0.2.10", "198.51.100.20"
DDOS = row(label="DDoS", source_port="40000", flow_id=f"{SRC}-{DEST}-40000-443-6")
BAD_IP = row(source_ip="not-an-ip")


@pytest.fixture(autouse=True)
def clear_rate_limits() -> Iterator[None]:
    import_user_limiter.clear()
    assessment_user_limiter.clear()
    yield
    import_user_limiter.clear()
    assessment_user_limiter.clear()


def upload(api: CoreApi, content: bytes, filename: str = "flows.csv") -> Any:
    return api.client.post(
        "/api/imports",
        files={"file": (filename, content, "text/csv")},
        data={"profile": "cic-ids2017"},
        headers=api.headers,
    )


def add_asset(api: CoreApi, key: str, ip: str | None) -> UUID:
    with api.session_factory() as session:
        asset = Asset(
            asset_key=key,
            name=key,
            ip_address=ip,
            asset_type=AssetType.SERVER,
            environment=AssetEnvironment.TEST,
            criticality=Criticality.HIGH,
            exposure=Exposure.INTERNET_FACING,
        )
        session.add(asset)
        session.commit()
        return asset.id


def imported_events(api: CoreApi) -> list[SecurityEvent]:
    with api.session_factory() as session:
        return list(session.scalars(select(SecurityEvent).order_by(SecurityEvent.import_batch_id, SecurityEvent.source_row)))


# --- Profile mapping --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("7/7/2017 3:30", "2017-07-07T15:30:00-03:00"),
        ("03/07/2017 08:55:58", "2017-07-03T08:55:58-03:00"),
        ("5/7/2017 12:05", "2017-07-05T12:05:00-03:00"),
        ("6/7/2017 1:00", "2017-07-06T13:00:00-03:00"),
        ("4/7/2017 11:59", "2017-07-04T11:59:00-03:00"),
    ],
)
def test_timestamp_interpretation_is_the_documented_assumption(written: str, expected: str) -> None:
    assert cic_ids2017_occurred_at(written).isoformat() == expected


def test_label_is_kept_as_ground_truth_and_rows_hash_by_content() -> None:
    benign = PROFILE.normalize_row(dict(zip(PROFILE.keys, row(), strict=True)))
    ddos = PROFILE.normalize_row(dict(zip(PROFILE.keys, DDOS, strict=True)))
    again = PROFILE.normalize_row(dict(zip(PROFILE.keys, row(), strict=True)))

    assert (ddos.event_type, ddos.protocol, ddos.src_ip, ddos.dest_ip, ddos.src_port, ddos.dest_port) == (
        "network_flow", "tcp", SRC, DEST, 40000, 443,
    )  # fmt: skip
    assert ddos.raw_data["groundTruthLabel"] == "DDoS"
    assert "assumption" in ddos.raw_data["occurredAtInterpretation"]
    assert len(ddos.raw_data["sourceFields"]) == 85
    assert ddos.raw_data["sourceFields"]["fwd_header_length_2"] == "32"
    assert benign.content_sha256 == again.content_sha256 != ddos.content_sha256


# --- Upload -> events ----------------------------------------------------------------------------------------


def test_validated_upload_stores_accepted_rows_with_provenance(core_api: CoreApi) -> None:
    response = upload(core_api, csv_bytes(row(), DDOS, BAD_IP))

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["status"], body["totalRows"], body["acceptedRows"], body["rejectedRows"]) == ("VALIDATED", 3, 2, 1)
    assert (body["eventsCreated"], body["duplicateRows"]) == (2, 0)
    assert {issue["row"] for issue in body["errorSample"]} == {4}

    events = imported_events(core_api)
    assert [(str(event.import_batch_id), event.source_row) for event in events] == [(body["id"], 2), (body["id"], 3)]
    for event in events:
        assert event.source == DetectionSource.DATASET_IMPORT
        # The DDoS label does not make the flow a detection: every imported row is INFO.
        assert event.severity == Severity.INFO
        assert event.event_type == "network_flow"
        assert event.occurred_at == datetime(2017, 7, 7, 18, 30, tzinfo=UTC)
        assert event.raw_data["importBatchId"] == body["id"]
        assert event.raw_data["sourceRow"] == event.source_row
        assert event.raw_data["fileSha256"] == body["fileSha256"]
        assert event.raw_data["assetLink"]["result"] == "no asset has the source or destination IP"
        assert event.asset_id is None
    assert [event.raw_data["groundTruthLabel"] for event in events] == ["BENIGN", "DDoS"]

    detail = core_api.client.get(f"/api/imports/{body['id']}", headers=core_api.headers).json()
    assert (detail["eventsCreated"], detail["duplicateRows"]) == (2, 0)


def test_events_api_exposes_provenance_and_filters_by_batch(core_api: CoreApi) -> None:
    first = upload(core_api, csv_bytes(row()), "a.csv").json()
    upload(core_api, csv_bytes(DDOS), "b.csv")

    listing = core_api.client.get(
        "/api/events", params={"importBatchId": first["id"]}, headers=core_api.headers
    ).json()
    assert listing["total"] == 1
    item = listing["items"][0]
    assert (item["importBatchId"], item["sourceRow"], item["detectionSource"], item["severity"]) == (
        first["id"], 2, "DATASET_IMPORT", "INFO",
    )  # fmt: skip
    by_source = core_api.client.get("/api/events", params={"source": "DATASET_IMPORT"}, headers=core_api.headers)
    assert by_source.json()["total"] == 2


def test_duplicate_rows_are_counted_not_stored(core_api: CoreApi) -> None:
    within = upload(core_api, csv_bytes(row(), row(), DDOS), "within.csv").json()
    assert (within["acceptedRows"], within["eventsCreated"], within["duplicateRows"]) == (3, 2, 1)

    # A different file (another hash) that repeats a stored row plus one new row.
    across = upload(core_api, csv_bytes(DDOS, row(flow_bytes_s="99.5")), "across.csv").json()
    assert (across["acceptedRows"], across["eventsCreated"], across["duplicateRows"]) == (2, 1, 1)

    events = imported_events(core_api)
    assert len(events) == 3
    # The repeated rows keep the provenance of their first occurrence.
    assert {(str(event.import_batch_id), event.source_row) for event in events} == {
        (within["id"], 2), (within["id"], 4), (across["id"], 3),
    }  # fmt: skip


def test_reupload_of_validated_file_is_refused_without_new_events(core_api: CoreApi) -> None:
    content = csv_bytes(row(), DDOS)
    assert upload(core_api, content).status_code == 201
    assert upload(core_api, content, "copy.csv").status_code == 409
    assert len(imported_events(core_api)) == 2


def test_rejected_file_stores_no_events(core_api: CoreApi) -> None:
    body = upload(core_api, csv_bytes(row(), header="Not, The, Header")).json()
    assert (body["status"], body["eventsCreated"]) == ("REJECTED", 0)
    assert imported_events(core_api) == []


def test_failed_normalisation_keeps_neither_batch_nor_events(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    original = dataset_normalization._insert_chunk

    def insert_then_fail(db: Any, rows: list[dict[str, Any]]) -> int:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise SQLAlchemyError("simulated failure after the first chunk was written")
        return original(db, rows)

    monkeypatch.setattr(dataset_normalization, "NORMALIZE_CHUNK_ROWS", 1)
    monkeypatch.setattr(dataset_normalization, "_insert_chunk", insert_then_fail)
    with pytest.raises(SQLAlchemyError):
        upload(core_api, csv_bytes(row(), DDOS))

    with core_api.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(ImportBatch)) == 0
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 0


def test_assets_are_linked_only_by_one_exact_ip_match(core_api: CoreApi) -> None:
    target = add_asset(core_api, "DEST-HOST", DEST)
    add_asset(core_api, "UNRELATED", "203.0.113.200")
    upload(core_api, csv_bytes(row()), "one.csv")

    (event,) = imported_events(core_api)
    assert event.asset_id == target
    assert event.raw_data["assetLink"] == {
        "rule": "exact-ip-match-v1", "result": "linked", "assetId": str(target), "matchedOn": ["destination IP"],
    }  # fmt: skip

    # With a second asset on the source address the match is ambiguous: no link, both candidates recorded.
    source_asset = add_asset(core_api, "SRC-HOST", SRC)
    second = upload(core_api, csv_bytes(DDOS), "two.csv").json()
    (ambiguous,) = [event for event in imported_events(core_api) if str(event.import_batch_id) == second["id"]]
    assert ambiguous.asset_id is None
    assert ambiguous.raw_data["assetLink"]["result"] == "not linked: 2 assets match"
    assert set(ambiguous.raw_data["assetLink"]["candidates"]) == {str(target), str(source_asset)}


def test_manual_ingest_cannot_claim_the_dataset_import_source(core_api: CoreApi) -> None:
    payload = {
        "event_uid": "evt-fake-import",
        "occurred_at": "2026-01-01T12:00:00Z",
        "source": "DATASET_IMPORT",
        "event_type": "network_flow",
        "severity": "INFO",
    }
    response = core_api.client.post("/api/events/ingest", json=payload, headers=core_api.headers)
    assert response.status_code == 422
    assert "dataset imports" in response.json()["detail"]


# --- Events -> Security Assessment -----------------------------------------------------------------------------


def test_imported_rows_trace_into_assessment_findings(core_api: CoreApi) -> None:
    asset_id = add_asset(core_api, "DATASET-WEB", DEST)
    with core_api.session_factory() as session:
        session.add(
            ThreatIndicator(value=SRC, indicator_type=IndicatorType.IP, source="test-feed", severity=Severity.HIGH, is_active=True)
        )
        session.commit()
    batch = upload(core_api, csv_bytes(row(), DDOS, BAD_IP)).json()
    assert batch["eventsCreated"] == 2

    # Assessed now, the 2017 flows are outside the 7-day window: nothing is attributed to them.
    now = core_api.client.post("/api/assessments", json={"assetId": str(asset_id)}, headers=core_api.headers).json()
    assert now["inputCounts"]["events"] == 0

    response = core_api.client.post(
        "/api/assessments",
        json={"assetId": str(asset_id), "asOf": "2017-07-08T00:00:00Z"},
        headers=core_api.headers,
    )
    assert response.status_code == 201, response.text
    assessment = response.json()
    assert datetime.fromisoformat(assessment["asOf"]) == datetime(2017, 7, 8, tzinfo=UTC)
    assert assessment["inputCounts"]["events"] == 2

    findings = {finding["checkKey"]: finding for finding in assessment["findings"]}
    matched = findings["threat_intel_matches"]
    assert matched["eventTotal"] == 2
    cited = set(matched["eventIds"])

    # Every cited event traces back to this batch and a row that passed validation.
    with core_api.session_factory() as session:
        traced = session.scalars(select(SecurityEvent).where(SecurityEvent.id.in_([UUID(item) for item in cited]))).all()
    assert {(str(event.import_batch_id), event.source_row) for event in traced} == {(batch["id"], 2), (batch["id"], 3)}

    # The stored snapshot returns the same evidence after a refresh.
    stored = core_api.client.get(f"/api/assessments/{assessment['id']}", headers=core_api.headers).json()
    stored_matched = {finding["checkKey"]: finding for finding in stored["findings"]}["threat_intel_matches"]
    assert set(stored_matched["eventIds"]) == cited


@pytest.mark.parametrize(
    "as_of",
    [(datetime.now(UTC) + timedelta(days=1)).isoformat(), "2017-07-08T00:00:00"],
    ids=["future", "no-offset"],
)
def test_assessment_as_of_must_be_past_and_zoned(core_api: CoreApi, as_of: str) -> None:
    asset_id = add_asset(core_api, "ANY", None)
    response = core_api.client.post(
        "/api/assessments", json={"assetId": str(asset_id), "asOf": as_of}, headers=core_api.headers
    )
    assert response.status_code == 422


# --- Alembic migration 0005 --------------------------------------------------------------------------------------

TABLES = ("users", "assets", "import_batches", "security_events", "incidents")


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0005", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_0005_follows_0004() -> None:
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    # 0006_add_risk_evaluations is now the head (tests/test_risk_evaluation_models.py).
    assert scripts.get_heads() == ["0006_add_risk_evaluations"]
    assert scripts.get_revision("0006_add_risk_evaluations").down_revision == "0005_dataset_event_provenance"
    assert scripts.get_revision("0005_dataset_event_provenance").down_revision == "0004_add_import_batches"


def test_every_revision_id_fits_the_alembic_version_column() -> None:
    # alembic_version.version_num is VARCHAR(32); a longer id fails only when the upgrade records it,
    # after the migration's DDL has run (and been rolled back).
    config = Config(str(BACKEND / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND / "migrations"))
    too_long = {
        script.revision: len(script.revision)
        for script in ScriptDirectory.from_config(config).walk_revisions()
        if len(script.revision) > 32
    }
    assert too_long == {}


@pytest.fixture
def migration_connection() -> Iterator[Connection]:
    """A throwaway schema holding the current model's tables that 0005 alters (and their dependencies)."""
    schema = f"netra_migration_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
            Base.metadata.create_all(connection, tables=[Base.metadata.tables[name] for name in TABLES])
            yield connection
        finally:
            transaction.rollback()


def _these_tables(_obj: Any, name: str | None, type_: str, _reflected: bool, _compare_to: Any) -> bool:
    return type_ != "table" or name in TABLES


def _checks(connection: Connection, table: str) -> dict[str, str]:
    return {item["name"]: item["sqltext"] for item in inspect(connection).get_check_constraints(table)}


def test_migration_0005_round_trip_matches_the_model(migration_connection: Connection) -> None:
    migration = _migration()
    context = MigrationContext.configure(
        migration_connection, opts={"compare_type": True, "include_object": _these_tables}
    )
    with Operations.context(context):
        # Tables created by init_db already match: upgrade is a no-op apart from re-creating the source checks.
        migration.upgrade()
        assert compare_metadata(context, Base.metadata) == []
        migration.downgrade()

        columns = {column["name"] for column in inspect(migration_connection).get_columns("security_events")}
        assert {"import_batch_id", "source_row"}.isdisjoint(columns)
        assert "dataset_import" not in _checks(migration_connection, "security_events")["ck_security_events_detectionsource"]

        migration.upgrade()

    assert compare_metadata(context, Base.metadata) == []
    for table in ("security_events", "import_batches", "incidents"):
        model_checks = {
            constraint.name
            for constraint in Base.metadata.tables[table].constraints
            if constraint.__class__.__name__ == "CheckConstraint"
        }
        assert set(_checks(migration_connection, table)) == model_checks
    for table in ("security_events", "incidents"):
        assert "dataset_import" in _checks(migration_connection, table)[f"ck_{table}_detectionsource"]
    indexes = {index["name"]: index for index in inspect(migration_connection).get_indexes("security_events")}
    assert indexes["uq_security_events_import_batch_id_source_row"]["unique"] is True


def test_migration_0005_downgrade_refuses_while_imported_events_exist(migration_connection: Connection) -> None:
    migration_connection.execute(
        text(
            "INSERT INTO security_events (id, event_uid, occurred_at, source, event_type, severity) "
            "VALUES (:id, 'dataset:x', now(), 'dataset_import', 'network_flow', 'info')"
        ),
        {"id": uuid.uuid4()},
    )
    with Operations.context(MigrationContext.configure(migration_connection)):
        with pytest.raises(RuntimeError, match="come from dataset imports"):
            _migration().downgrade()
    columns = {column["name"] for column in inspect(migration_connection).get_columns("security_events")}
    assert {"import_batch_id", "source_row"} <= columns
