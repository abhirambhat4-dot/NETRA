from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.core import CoreResponse


class IncidentContext(CoreResponse):
    id: UUID
    incident_key: str
    title: str
    description: str | None
    severity: str
    state: str
    detection_source: str
    asset_id: UUID | None


class AssetContext(CoreResponse):
    id: UUID
    asset_key: str
    name: str
    hostname: str | None
    ip_address: str | None
    criticality: str
    exposure: str
    status: str
    asset_type: str
    environment: str


class VulnerabilityContext(CoreResponse):
    id: UUID
    cve_id: str | None
    title: str
    description: str | None
    cvss_score: float | None
    severity: str
    status: str


class ThreatMatchContext(CoreResponse):
    id: UUID
    value: str
    indicator_type: str
    confidence: float | None
    severity: str
    source: str
    is_active: bool
    matched_event_ids: list[UUID]


class EventContext(CoreResponse):
    id: UUID
    event_uid: str
    occurred_at: datetime
    event_type: str
    signature: str | None
    severity: str
    anomaly_score: float | None
    detection_source: str
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None


class EnrichmentFinding(CoreResponse):
    category: str
    reason: str
    count: int | None = None


class IncidentContextBundle(CoreResponse):
    incident: IncidentContext
    asset: AssetContext | None
    vulnerabilities: list[VulnerabilityContext]
    threat_intelligence_matches: list[ThreatMatchContext]
    events: list[EventContext]
    findings: list[EnrichmentFinding]