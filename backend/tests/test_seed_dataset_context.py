"""Dataset demonstration context tests: the guarded asset + indicator seed, and the path it enables from
imported CIC-IDS2017 rows into Security Assessment findings.

Throwaway PostgreSQL schemas inside transactions that are always rolled back. Rows are synthetic.
"""

import uuid
from collections.abc import Iterator
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db.base import Base
from app.db.seed_dataset_context import (
    ASSET_FIELDS,
    ASSET_KEY,
    EXIT_BLOCKED,
    EXIT_OK,
    INDICATOR_SOURCE,
    INDICATOR_VALUE,
    run,
    write_refusal,
)
from app.db.session import engine
from app.models import Asset, SecurityEvent, ThreatIndicator
from app.models.enums import AssetEnvironment, AssetType, Criticality, Exposure
from app.services.assessment import assessment_user_limiter
from app.services.dataset_import import import_user_limiter
from tests.conftest import CoreApi
from tests.test_cic_ids2017_profile import csv_bytes, row

SERVER, INDICATED, INTERNAL = "192.168.10.50", INDICATOR_VALUE, "192.168.10.16"


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    schema = f"netra_ctx_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            isolated = connection.execution_options(schema_translate_map={None: schema})
            Base.metadata.create_all(isolated)
            yield sessionmaker(bind=isolated, autoflush=False, expire_on_commit=False, join_transaction_mode="create_savepoint")
        finally:
            transaction.rollback()


@pytest.fixture(autouse=True)
def clear_rate_limits() -> Iterator[None]:
    import_user_limiter.clear()
    assessment_user_limiter.clear()
    yield
    import_user_limiter.clear()
    assessment_user_limiter.clear()


def seed(factory: sessionmaker[Session], *, apply: bool) -> tuple[int, list[str]]:
    lines: list[str] = []
    with factory() as session:
        code = run(session, apply=apply, out=lines.append)
    return code, lines


def counts(factory: sessionmaker[Session]) -> tuple[int, int, int]:
    with factory() as session:
        return tuple(
            int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (Asset, ThreatIndicator, SecurityEvent)
        )  # type: ignore[return-value]


def test_dry_run_writes_nothing(factory: sessionmaker[Session]) -> None:
    code, lines = seed(factory, apply=False)
    assert code == EXIT_OK
    assert "would create asset CIC-DEMO-WEB-50; IP indicator 172.16.0.1" in lines[-1]
    assert counts(factory) == (0, 0, 0)


def test_apply_creates_only_the_labelled_asset_and_indicator_and_is_idempotent(factory: sessionmaker[Session]) -> None:
    assert seed(factory, apply=True)[0] == EXIT_OK
    assert counts(factory) == (1, 1, 0)
    with factory() as session:
        asset = session.scalars(select(Asset)).one()
        indicator = session.scalars(select(ThreatIndicator)).one()
    assert (asset.asset_key, str(asset.ip_address), asset.environment) == (ASSET_KEY, SERVER, AssetEnvironment.TEST)
    assert asset.name.startswith("[DATASET DEMO]")
    assert (indicator.value, indicator.source, indicator.is_active, indicator.confidence) == (
        INDICATOR_VALUE, INDICATOR_SOURCE, True, None,
    )  # fmt: skip
    assert "not a threat feed" in indicator.source

    code, lines = seed(factory, apply=True)
    assert code == EXIT_OK and "nothing to write" in lines[-1]
    assert counts(factory) == (1, 1, 0)


@pytest.mark.parametrize(
    ("key", "ip"),
    [(ASSET_KEY, "192.168.10.51"), ("SOMEONE-ELSE", SERVER)],
    ids=["same-key-different-ip", "other-asset-owns-the-ip"],
)
def test_conflicts_block_every_write(factory: sessionmaker[Session], key: str, ip: str) -> None:
    with factory() as session:
        session.add(
            Asset(asset_key=key, name="existing", ip_address=ip, asset_type=AssetType.SERVER,
                  environment=AssetEnvironment.TEST, criticality=Criticality.LOW, exposure=Exposure.INTERNAL)
        )
        session.commit()

    code, lines = seed(factory, apply=True)
    assert code == EXIT_BLOCKED
    assert any(line.startswith("CONFLICT") for line in lines) and lines[-1] == "Nothing was written."
    assert counts(factory) == (1, 0, 0)


@pytest.mark.parametrize(
    ("url", "confirmation", "environ", "refused"),
    [
        ("postgresql+psycopg://u:p@localhost:5432/netra", "localhost:5432/netra", {}, None),
        ("postgresql+psycopg://u:p@LOCALHOST:5432/netra", "localhost:5432/netra", {}, None),
        ("postgresql+psycopg://u:p@db.example.neon.tech:5432/netra", "db.example.neon.tech:5432/netra", {}, "local"),
        ("postgresql+psycopg://u:p@localhost:5432/netra", "localhost:5432/netra_e2e", {}, "--confirm-target"),
        ("postgresql+psycopg://u:p@localhost:5432/netra", None, {}, "--confirm-target"),
        ("postgresql+psycopg://u:p@localhost:5432/netra", "localhost:5432/netra", {"PGHOST": "elsewhere"}, "PGHOST"),
        ("postgresql+psycopg://u:p@localhost:5432/netra?host=elsewhere", "localhost:5432/netra", {}, "query"),
    ],
)
def test_writes_are_refused_unless_local_and_confirmed(
    url: str, confirmation: str | None, environ: dict[str, str], refused: str | None
) -> None:
    reason = write_refusal(make_url(url), confirmation, environ)
    if refused is None:
        assert reason is None
    else:
        assert reason is not None and refused in reason


def flow(src: str, dest: str, label: str, src_port: str) -> list[str]:
    return row(
        source_ip=src, destination_ip=dest, source_port=src_port, destination_port="80",
        flow_id=f"{src}-{dest}-{src_port}-80-6", label=label,
    )  # fmt: skip


def test_imported_rows_reach_findings_through_the_indicator_not_the_label(core_api: CoreApi) -> None:
    with core_api.session_factory() as session:
        assert run(session, apply=True, out=lambda _line: None) == EXIT_OK
        asset_id = session.scalar(select(Asset.id).where(Asset.asset_key == ASSET_KEY))

    content = csv_bytes(
        flow(INDICATED, SERVER, "DDoS", "40001"),
        flow(INDICATED, SERVER, "BENIGN", "40002"),
        flow(INTERNAL, SERVER, "BENIGN", "40003"),
    )
    batch = core_api.client.post(
        "/api/imports",
        files={"file": ("cic-extract.csv", content, "text/csv")},
        data={"profile": "cic-ids2017"},
        headers=core_api.headers,
    ).json()
    assert (batch["status"], batch["eventsCreated"]) == ("VALIDATED", 3)

    with core_api.session_factory() as session:
        events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.source_row)).all()
    # All three are linked by the exact-IP rule on the destination address, whatever their label.
    assert [event.asset_id for event in events] == [asset_id] * 3
    assert all(event.raw_data["assetLink"]["matchedOn"] == ["destination IP"] for event in events)
    by_row = {event.source_row: str(event.id) for event in events}

    response = core_api.client.post(
        "/api/assessments", json={"assetId": str(asset_id), "asOf": "2017-07-08T00:00:00Z"}, headers=core_api.headers
    )
    assert response.status_code == 201, response.text
    assessment = response.json()
    assert assessment["inputCounts"]["events"] == 3
    findings = {finding["checkKey"]: finding for finding in assessment["findings"]}
    # The indicator matches rows 2 and 3 (source 172.16.0.1), labelled DDoS and BENIGN alike; row 4 has no match.
    assert set(findings["threat_intel_matches"]["eventIds"]) == {by_row[2], by_row[3]}
    # Imported rows are INFO, so none of them counts as a high-severity event.
    assert findings["recent_high_severity_events"]["eventIds"] == []

    stored = core_api.client.get(f"/api/assessments/{assessment['id']}", headers=core_api.headers).json()
    stored_findings = {finding["checkKey"]: finding for finding in stored["findings"]}
    assert set(stored_findings["threat_intel_matches"]["eventIds"]) == {by_row[2], by_row[3]}
    with core_api.session_factory() as session:
        cited = session.scalars(
            select(SecurityEvent).where(SecurityEvent.id.in_([UUID(item) for item in stored_findings["threat_intel_matches"]["eventIds"]]))
        ).all()
    assert {(str(event.import_batch_id), event.source_row) for event in cited} == {(batch["id"], 2), (batch["id"], 3)}


def test_asset_fields_are_the_documented_demo_values() -> None:
    assert ASSET_FIELDS["ip_address"] == SERVER
    assert ASSET_FIELDS["environment"] == AssetEnvironment.TEST
