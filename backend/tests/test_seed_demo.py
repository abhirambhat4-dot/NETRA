"""Demo seed tests.

Each test builds the schema in a throwaway PostgreSQL schema inside a transaction that is
always rolled back (INET/JSONB need PostgreSQL), so no real NETRA data is read or changed.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db import seed_demo
from app.db.base import Base
from app.db.seed_demo import (
    DEMO_MARKER,
    EVENT_UID_PREFIX,
    EXIT_BLOCKED,
    EXIT_OK,
    EXIT_WORKFLOW_ERROR,
    INDICATOR_SOURCE,
    OWNER,
    TITLE_PREFIX,
    describe_target,
    run_seed,
)
from app.db.session import engine
from app.models import (
    Asset,
    Authorization,
    ContainmentAction,
    CyberMemory,
    Decision,
    Incident,
    IncidentEvent,
    IncidentHistory,
    SecurityEvent,
    ThreatIndicator,
    Vulnerability,
)
from app.models.enums import (
    AssetEnvironment,
    AssetType,
    AuthorizationStatus,
    ContainmentStatus,
    Criticality,
    DetectionSource,
    Exposure,
    IncidentState,
    ResponseAction,
    Severity,
)
from app.services.decision_workflow import approve_decision_authorization

COUNTED_MODELS = (
    Asset,
    Vulnerability,
    ThreatIndicator,
    SecurityEvent,
    Incident,
    IncidentEvent,
    IncidentHistory,
    Decision,
    Authorization,
    ContainmentAction,
    CyberMemory,
)


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    schema = f"netra_seed_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            isolated = connection.execution_options(schema_translate_map={None: schema})
            Base.metadata.create_all(isolated)
            # Same session options as the API, so workflow services behave identically.
            yield sessionmaker(
                bind=isolated,
                autoflush=False,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            )
        finally:
            transaction.rollback()


def seed(factory: sessionmaker[Session], *, apply: bool = True) -> tuple[int, list[str]]:
    lines: list[str] = []
    with factory() as session:
        code = run_seed(session, apply=apply, out=lines.append)
    return code, lines


def counts(factory: sessionmaker[Session]) -> dict[str, int]:
    with factory() as session:
        return {
            model.__tablename__: session.scalar(select(func.count()).select_from(model)) or 0
            for model in COUNTED_MODELS
        }


def incident(session: Session, key: str) -> Incident:
    record = session.scalar(select(Incident).where(Incident.incident_key == key))
    assert record is not None
    return record


def latest(session: Session, model: Any, **filters: Any) -> Any:
    statement = select(model).filter_by(**filters)
    return session.scalars(statement).all()


def test_dry_run_writes_nothing(factory: sessionmaker[Session]) -> None:
    before = counts(factory)

    code, lines = seed(factory, apply=False)

    assert code == EXIT_OK
    assert counts(factory) == before
    assert any("would be created" in line for line in lines)
    assert lines[-1].startswith("Dry run complete")


def test_apply_creates_marked_records(factory: sessionmaker[Session]) -> None:
    code, lines = seed(factory)

    assert code == EXIT_OK, lines
    with factory() as session:
        assets = session.scalars(select(Asset)).all()
        assert sorted(a.asset_key for a in assets) == ["DEMO-DB-01", "DEMO-WEB-01", "DEMO-WS-07"]
        assert {a.owner for a in assets} == {OWNER}
        assert all(a.hostname.endswith(".netra-demo.example") for a in assets)
        assert all(str(a.ip_address).startswith("10.250.") for a in assets)

        vulnerabilities = session.scalars(select(Vulnerability)).all()
        assert sorted(v.cve_id for v in vulnerabilities) == [f"DEMO-CVE-2026-000{i}" for i in (1, 2, 3)]

        indicators = session.scalars(select(ThreatIndicator)).all()
        assert {i.source for i in indicators} == {INDICATOR_SOURCE}
        assert {i.value for i in indicators} == {"203.0.113.45", "198.51.100.77", "c2.netra-demo.example"}

        events = session.scalars(select(SecurityEvent)).all()
        assert len(events) == 9
        for event in events:
            assert event.event_uid.startswith(EVENT_UID_PREFIX)
            assert event.raw_data is not None and DEMO_MARKER.items() <= event.raw_data.items()
            assert event.source in (DetectionSource.THREAT_INTEL, DetectionSource.MANUAL)

        incidents = session.scalars(select(Incident)).all()
        assert sorted(i.incident_key for i in incidents) == ["INC-DEMO-0001", "INC-DEMO-0002", "INC-DEMO-0003"]
        assert all(i.title.startswith(TITLE_PREFIX) for i in incidents)


def test_scenario_a_completes_lifecycle_with_isolation(factory: sessionmaker[Session]) -> None:
    seed(factory)

    with factory() as session:
        record = incident(session, "INC-DEMO-0001")
        assert record.state == IncidentState.LEARNED
        assert record.risk_score is not None and record.risk_score >= 75
        assert len(record.events) == 4  # one linked at creation, three found by correlation
        [decision] = latest(session, Decision, incident_id=record.id)
        assert decision.action == ResponseAction.ISOLATE_HOST
        [authorization] = latest(session, Authorization, incident_id=record.id)
        assert authorization.status == AuthorizationStatus.APPROVED
        [containment] = latest(session, ContainmentAction, incident_id=record.id)
        assert containment.status == ContainmentStatus.VERIFIED
        assert containment.target == "db-01.netra-demo.example"
        assert len(latest(session, CyberMemory, incident_id=record.id)) == 1
        actions = [entry.action for entry in record.history]
        for step in ("context_enriched", "events_correlated", "risk_calculated", "decision_recommended",
                     "incident_verified", "authorization_requested", "authorization_approved",
                     "containment_executed", "cyber_memory_created"):
            assert step in actions


def test_scenario_b_waits_for_presenter_approval(factory: sessionmaker[Session]) -> None:
    seed(factory)

    with factory() as session:
        record = incident(session, "INC-DEMO-0002")
        assert record.state == IncidentState.VERIFIED
        assert record.risk_score is not None and 55 <= record.risk_score < 75
        assert len(record.events) == 3
        [decision] = latest(session, Decision, incident_id=record.id)
        assert decision.action == ResponseAction.BLOCK_IP
        [authorization] = latest(session, Authorization, incident_id=record.id)
        assert authorization.status == AuthorizationStatus.PENDING
        assert latest(session, ContainmentAction, incident_id=record.id) == []


def test_scenario_c_is_prioritised_for_investigation(factory: sessionmaker[Session]) -> None:
    seed(factory)

    with factory() as session:
        record = incident(session, "INC-DEMO-0003")
        assert record.state == IncidentState.PRIORITISED
        assert record.risk_score is not None and record.risk_score < 50
        [decision] = latest(session, Decision, incident_id=record.id)
        assert decision.action == ResponseAction.INVESTIGATE
        assert latest(session, Authorization, incident_id=record.id) == []


def test_second_run_creates_nothing_and_changes_nothing(factory: sessionmaker[Session]) -> None:
    seed(factory)
    before = counts(factory)
    with factory() as session:
        states = {i.incident_key: i.state for i in session.scalars(select(Incident))}

    code, lines = seed(factory)

    assert code == EXIT_OK, lines
    assert counts(factory) == before
    assert lines[-1].startswith("Created: 0 records; workflow steps run: 0; errors: 0")
    with factory() as session:
        assert {i.incident_key: i.state for i in session.scalars(select(Incident))} == states


def test_only_demo_events_are_linked_and_non_demo_rows_are_untouched(factory: sessionmaker[Session]) -> None:
    # A real-looking record set sharing an IP and time window with Scenario A, on its own asset.
    with factory() as session:
        asset = Asset(asset_key="PROD-APP-01", name="Production app", hostname="app-01.internal",
                      ip_address="10.0.0.5", asset_type=AssetType.SERVER, environment=AssetEnvironment.PRODUCTION,
                      criticality=Criticality.HIGH, exposure=Exposure.INTERNET_FACING, owner="ops")
        session.add(asset)
        session.flush()
        event = SecurityEvent(event_uid="prod-event-1", occurred_at=datetime.now(UTC) - timedelta(minutes=115),
                              source=DetectionSource.THREAT_INTEL, event_type="port_scan", signature="scan",
                              severity=Severity.MEDIUM, src_ip="203.0.113.45", dest_ip="10.0.0.5",
                              raw_data={"origin": "production"}, asset_id=asset.id)
        other = Incident(incident_key="INC-PROD-0001", title="Production incident", severity=Severity.HIGH,
                         detection_source=DetectionSource.THREAT_INTEL, asset_id=asset.id)
        session.add_all([event, other])
        session.commit()
        snapshot = (asset.id, event.id, other.id, other.state, other.updated_at)

    code, lines = seed(factory)

    assert code == EXIT_OK, lines
    with factory() as session:
        for record in session.scalars(select(Incident).where(Incident.incident_key.like("INC-DEMO-%"))):
            for linked in record.events:
                assert linked.event_uid.startswith(EVENT_UID_PREFIX)
                assert DEMO_MARKER.items() <= (linked.raw_data or {}).items()
        asset_id, event_id, other_id, other_state, other_updated = snapshot
        assert session.get(Asset, asset_id).asset_key == "PROD-APP-01"
        prod_event = session.get(SecurityEvent, event_id)
        assert prod_event.raw_data == {"origin": "production"}
        assert prod_event.incidents == []
        prod_incident = session.get(Incident, other_id)
        assert (prod_incident.state, prod_incident.updated_at) == (other_state, other_updated)
        assert prod_incident.history == []


def test_conflicting_record_is_reported_and_nothing_is_written(factory: sessionmaker[Session]) -> None:
    with factory() as session:
        session.add(Asset(asset_key="DEMO-DB-01", name="Customer DB", hostname="db-01.netra-demo.example",
                          ip_address="10.250.20.20", asset_type=AssetType.DATABASE,
                          environment=AssetEnvironment.PRODUCTION, criticality=Criticality.LOW,
                          exposure=Exposure.INTERNAL, owner=OWNER))
        session.commit()
    before = counts(factory)

    code, lines = seed(factory)

    assert code == EXIT_BLOCKED
    assert any("CONFLICT" in line and "DEMO-DB-01" in line and "criticality" in line for line in lines)
    assert counts(factory) == before
    with factory() as session:
        assert session.scalar(select(Asset.criticality).where(Asset.asset_key == "DEMO-DB-01")) == Criticality.LOW


def test_interrupted_run_resumes_without_duplicates(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(*_: object, **__: object) -> None:
        raise HTTPException(status_code=503, detail="simulated interruption")

    monkeypatch.setattr(seed_demo, "approve_decision_authorization", interrupted)
    code, lines = seed(factory)
    assert code == EXIT_WORKFLOW_ERROR
    assert any("approve authorization failed" in line for line in lines)
    with factory() as session:
        assert incident(session, "INC-DEMO-0001").state == IncidentState.VERIFIED

    monkeypatch.undo()
    code, lines = seed(factory)

    assert code == EXIT_OK, lines
    with factory() as session:
        record = incident(session, "INC-DEMO-0001")
        assert record.state == IncidentState.LEARNED
        assert len(latest(session, Decision, incident_id=record.id)) == 1
        assert len(latest(session, Authorization, incident_id=record.id)) == 1
    assert counts(factory)["security_events"] == 9


def test_incident_past_its_target_is_not_moved_back(factory: sessionmaker[Session]) -> None:
    seed(factory)
    with factory() as session:
        record = incident(session, "INC-DEMO-0002")
        [authorization] = latest(session, Authorization, incident_id=record.id)
        approve_decision_authorization(session, authorization.id, actor="presenter@example.com")

    code, lines = seed(factory)

    assert code == EXIT_OK, lines
    assert any("INC-DEMO-0002: already past the seed target" in line for line in lines)
    with factory() as session:
        record = incident(session, "INC-DEMO-0002")
        assert record.state == IncidentState.AUTHORIZED
        assert len(latest(session, Authorization, incident_id=record.id)) == 1


def test_target_description_never_reveals_connection_details() -> None:
    secret = "s3cr3t-pa55"
    cases = {
        f"postgresql+psycopg://user:{secret}@localhost:5432/netra": "local PostgreSQL",
        f"postgresql+psycopg://user:{secret}@ep-demo-123.eu-central-1.aws.neon.tech/neondb": "remote PostgreSQL (*.neon.tech)",
        f"postgresql+psycopg://user:{secret}@db.internal.example:5432/netra": "remote PostgreSQL (non-local host)",
    }
    for raw, expected in cases.items():
        described = describe_target(make_url(raw))
        assert described == expected
        assert secret not in described and "user" not in described and "netra" not in described.lower()


def test_missing_tables_block_the_seed() -> None:
    schema = f"netra_seed_empty_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            isolated = connection.execution_options(schema_translate_map={None: schema})
            with Session(bind=isolated, join_transaction_mode="create_savepoint") as session:
                lines: list[str] = []
                code = run_seed(session, apply=True, out=lines.append)
            assert code == EXIT_BLOCKED
            assert "Required tables are missing" in lines[0]
        finally:
            transaction.rollback()
