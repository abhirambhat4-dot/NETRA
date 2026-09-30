"""Schema and model tests.

Each test builds the full schema inside a throwaway PostgreSQL schema within a single
transaction that is always rolled back, so no real NETRA tables or data are touched.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import Connection, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import engine
from app.models import (
    Asset,
    Authorization,
    ContainmentAction,
    CyberMemory,
    Decision,
    Incident,
    IncidentHistory,
    SecurityEvent,
    ThreatIndicator,
    Vulnerability,
)
from app.models.enums import (
    AssetEnvironment,
    AssetType,
    AuthorizationStatus,
    Criticality,
    DetectionSource,
    Effectiveness,
    Exposure,
    IncidentState,
    IndicatorType,
    ResponseAction,
    Severity,
)

EXPECTED_TABLES = {
    "assets",
    "security_events",
    "incidents",
    "incident_events",
    "incident_history",
    "vulnerabilities",
    "threat_indicators",
    "decisions",
    "authorizations",
    "containment_actions",
    "cyber_memories",
    "users",
}


@dataclass
class IsolatedDb:
    connection: Connection
    schema: str


@pytest.fixture
def isolated_db() -> Iterator[IsolatedDb]:
    """Create all tables in a temporary schema; roll everything back afterwards."""
    schema = f"netra_test_{uuid.uuid4().hex[:12]}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(CreateSchema(schema))
            translated = connection.execution_options(schema_translate_map={None: schema})
            Base.metadata.create_all(translated)
            yield IsolatedDb(connection=translated, schema=schema)
        finally:
            transaction.rollback()


@pytest.fixture
def db_session(isolated_db: IsolatedDb) -> Iterator[Session]:
    with Session(bind=isolated_db.connection, join_transaction_mode="create_savepoint") as session:
        yield session


def make_asset(**overrides: object) -> Asset:
    fields: dict[str, object] = {
        "asset_key": f"TEST-{uuid.uuid4().hex[:8]}",
        "name": "Test web server",
        "hostname": "web-01.test.local",
        "ip_address": "10.0.0.10",
        "asset_type": AssetType.SERVER,
        "environment": AssetEnvironment.TEST,
        "criticality": Criticality.HIGH,
        "exposure": Exposure.INTERNET_FACING,
        "owner": "test-team",
    }
    return Asset(**(fields | overrides))


def make_event(asset: Asset | None = None, **overrides: object) -> SecurityEvent:
    fields: dict[str, object] = {
        "event_uid": f"test-{uuid.uuid4().hex}",
        "occurred_at": datetime.now(UTC),
        "source": DetectionSource.SURICATA,
        "event_type": "alert",
        "signature": "TEST signature",
        "severity": Severity.HIGH,
        "src_ip": "203.0.113.5",
        "dest_ip": "10.0.0.10",
        "src_port": 51515,
        "dest_port": 443,
        "protocol": "TCP",
        "raw_data": {"test": True},
        "asset": asset,
    }
    return SecurityEvent(**(fields | overrides))


def make_incident(asset: Asset | None = None, **overrides: object) -> Incident:
    fields: dict[str, object] = {
        "incident_key": f"INC-TEST-{uuid.uuid4().hex[:8]}",
        "title": "Test incident",
        "severity": Severity.HIGH,
        "risk_score": 72.5,
        "detection_source": DetectionSource.SURICATA,
        "recommended_action": ResponseAction.BLOCK_IP,
    }
    if asset is not None:
        fields["asset"] = asset
    return Incident(**(fields | overrides))


def test_metadata_contains_expected_tables() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_tables_can_be_created(isolated_db: IsolatedDb) -> None:
    created = set(inspect(isolated_db.connection).get_table_names(schema=isolated_db.schema))
    assert created == EXPECTED_TABLES


def test_foreign_keys_reference_expected_tables(isolated_db: IsolatedDb) -> None:
    inspector = inspect(isolated_db.connection)
    fks = {
        (table, fk["constrained_columns"][0], fk["referred_table"])
        for table in EXPECTED_TABLES
        for fk in inspector.get_foreign_keys(table, schema=isolated_db.schema)
    }
    assert fks == {
        ("security_events", "asset_id", "assets"),
        ("incidents", "asset_id", "assets"),
        ("vulnerabilities", "asset_id", "assets"),
        ("incident_events", "incident_id", "incidents"),
        ("incident_events", "event_id", "security_events"),
        ("incident_history", "incident_id", "incidents"),
        ("decisions", "incident_id", "incidents"),
        ("authorizations", "incident_id", "incidents"),
        ("authorizations", "decision_id", "decisions"),
        ("containment_actions", "incident_id", "incidents"),
        ("containment_actions", "authorization_id", "authorizations"),
        ("cyber_memories", "incident_id", "incidents"),
        ("cyber_memories", "decision_id", "decisions"),
    }


def test_foreign_key_is_enforced(db_session: Session) -> None:
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(make_incident(asset_id=uuid.uuid4()))
        db_session.flush()


def test_check_constraint_is_enforced(db_session: Session) -> None:
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(make_incident(risk_score=150))
        db_session.flush()


def test_insert_and_query_asset_event_incident(db_session: Session) -> None:
    asset = make_asset()
    event = make_event(asset)
    incident = make_incident(asset)
    db_session.add_all([asset, event, incident])
    db_session.flush()
    db_session.expire_all()

    stored_asset = db_session.scalars(select(Asset).where(Asset.asset_key == asset.asset_key)).one()
    stored_event = db_session.scalars(select(SecurityEvent).where(SecurityEvent.id == event.id)).one()
    stored_incident = db_session.get_one(Incident, incident.id)

    assert stored_asset.criticality is Criticality.HIGH
    assert str(stored_asset.ip_address) == "10.0.0.10"
    assert stored_asset.created_at.tzinfo is not None
    assert stored_event.dest_port == 443
    assert stored_event.raw_data == {"test": True}
    assert stored_incident.state is IncidentState.DETECTED
    assert stored_incident.risk_score == 72.5


def test_asset_relationships(db_session: Session) -> None:
    asset = make_asset()
    asset.vulnerabilities.append(
        Vulnerability(
            cve_id="CVE-2024-0001",
            title="Test vulnerability",
            cvss_score=Decimal("9.8"),
            severity=Severity.CRITICAL,
        )
    )
    db_session.add_all([asset, make_event(asset), make_incident(asset)])
    db_session.flush()
    db_session.expire_all()

    stored = db_session.get_one(Asset, asset.id)
    assert len(stored.events) == 1
    assert len(stored.incidents) == 1
    assert stored.vulnerabilities[0].cvss_score == Decimal("9.8")


def test_incident_lifecycle_relationships(db_session: Session) -> None:
    asset = make_asset()
    incident = make_incident(asset)
    incident.events.extend([make_event(asset), make_event(asset)])
    incident.history.append(
        IncidentHistory(
            from_state=None,
            to_state=IncidentState.DETECTED,
            action="incident_created",
            actor="test",
            details={"test": True},
        )
    )
    decision = Decision(
        action=ResponseAction.BLOCK_IP,
        rationale="Test rationale",
        risk_score=72.5,
        confidence=0.9,
    )
    authorization = Authorization(
        decision=decision,
        requested_action=ResponseAction.BLOCK_IP,
        requested_by="test-analyst",
        status=AuthorizationStatus.APPROVED,
    )
    incident.decisions.append(decision)
    incident.authorizations.append(authorization)
    incident.containment_actions.append(
        ContainmentAction(
            authorization=authorization,
            action_type=ResponseAction.BLOCK_IP,
            target="203.0.113.5",
        )
    )
    incident.memories.append(
        CyberMemory(
            decision=decision,
            lesson="Test lesson",
            action_taken=ResponseAction.BLOCK_IP,
            effectiveness=Effectiveness.EFFECTIVE,
        )
    )
    db_session.add(incident)
    db_session.flush()
    db_session.expire_all()

    stored = db_session.get_one(Incident, incident.id)
    assert stored.asset is not None and stored.asset.id == asset.id
    assert len(stored.events) == 2
    assert all(stored in event.incidents for event in stored.events)
    assert stored.history[0].to_state is IncidentState.DETECTED
    assert stored.decisions[0].authorizations[0].id == authorization.id
    assert stored.containment_actions[0].authorization.decision_id == decision.id
    assert stored.memories[0].decision_id == decision.id


def test_deleting_incident_cascades_but_keeps_events_and_memory(db_session: Session) -> None:
    event = make_event()
    incident = make_incident()
    incident.events.append(event)
    incident.history.append(
        IncidentHistory(to_state=IncidentState.DETECTED, action="incident_created", actor="test")
    )
    memory = CyberMemory(lesson="Keep me")
    incident.memories.append(memory)
    db_session.add(incident)
    db_session.flush()

    db_session.delete(incident)
    db_session.flush()
    db_session.expire_all()

    assert db_session.scalars(select(IncidentHistory)).all() == []
    assert db_session.get(SecurityEvent, event.id) is not None
    kept_memory = db_session.get_one(CyberMemory, memory.id)
    assert kept_memory.incident_id is None


def test_threat_indicator_uniqueness(db_session: Session) -> None:
    def indicator() -> ThreatIndicator:
        return ThreatIndicator(
            value="203.0.113.5",
            indicator_type=IndicatorType.IP,
            source="test-feed",
            confidence=0.8,
            severity=Severity.HIGH,
        )

    db_session.add(indicator())
    db_session.flush()

    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(indicator())
        db_session.flush()
