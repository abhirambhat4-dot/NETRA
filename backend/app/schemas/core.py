from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

T = TypeVar("T")


class CoreResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PageResponse(CoreResponse, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class AssetReference(CoreResponse):
    id: UUID
    asset_key: str
    name: str
    hostname: str | None
    ip_address: str | None
    criticality: str
    status: str


class AssetResponse(AssetReference):
    asset_type: str
    environment: str
    exposure: str
    owner: str | None
    vulnerability_count: int
    created_at: datetime
    updated_at: datetime


class EventResponse(CoreResponse):
    id: UUID
    event_uid: str
    occurred_at: datetime
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    event_type: str
    signature: str | None
    severity: str
    detection_source: str
    status: str = Field(description="Derived as NEW or CORRELATED from incident links; no dismissed state is stored.")
    anomaly_score: float | None
    incident_ids: list[UUID]
    asset_id: UUID | None
    asset: AssetReference | None


class EventIngestRequest(CoreResponse):
    event_uid: str
    occurred_at: datetime
    source: str
    event_type: str
    signature: str | None = None
    severity: str
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    asset_id: UUID | None = None
    raw_data: dict[str, Any] | None = None


class IncidentCreateRequest(CoreResponse):
    title: str
    description: str | None = None
    severity: str | None = None
    detection_source: str | None = None
    asset_id: UUID | None = None
    event_ids: list[UUID] | None = None


class IncidentEventLinkRequest(CoreResponse):
    event_id: UUID


class IncidentEventLinkResponse(CoreResponse):
    incident_id: UUID
    event_id: UUID
    linked_at: datetime
    status: str = "linked"


class IncidentResponse(CoreResponse):
    id: UUID
    incident_key: str
    title: str
    description: str | None
    severity: str
    risk_score: float | None
    state: str
    detection_source: str
    recommended_action: str | None
    asset_id: UUID | None
    asset: AssetReference | None
    event_count: int
    created_at: datetime
    updated_at: datetime
    latest_decision: "DecisionResponse | None" = None


class DecisionResponse(CoreResponse):
    id: UUID
    incident_id: UUID
    action: str
    rationale: str
    risk_score: float
    confidence: float
    recommendation: str | None
    created_at: datetime


class AuthorizationResponse(CoreResponse):
    id: UUID
    incident_id: UUID
    decision_id: UUID | None
    requested_action: str
    status: str
    requested_by: str
    approved_by: str | None
    reason: str | None
    requested_at: datetime
    approved_at: datetime | None


class ContainmentResponse(CoreResponse):
    id: UUID
    incident_id: UUID
    authorization_id: UUID
    action_type: str
    target: str
    status: str
    executed_at: datetime | None
    verified_at: datetime | None
    result: str | None
    error_message: str | None
    created_at: datetime


class TimelineEntryResponse(CoreResponse):
    id: UUID
    timestamp: datetime
    source: str
    stage: str | None
    title: str
    description: str
    actor: str | None
    event_id: UUID | None = None


class IncidentDetailResponse(CoreResponse):
    incident: IncidentResponse
    asset: AssetResponse | None
    events: list[EventResponse]
    timeline: list[TimelineEntryResponse]
    decisions: list[DecisionResponse]
    authorizations: list[AuthorizationResponse]
    containment_actions: list[ContainmentResponse]
    cyber_memories: list["CyberMemoryReference"]


class CyberMemoryReference(CoreResponse):
    id: UUID
    lesson: str
    outcome: str | None


class ThreatIndicatorResponse(CoreResponse):
    id: UUID
    value: str
    indicator_type: str
    source: str
    confidence: float | None
    severity: str
    first_seen: datetime
    last_seen: datetime
    is_active: bool


class IncidentReference(CoreResponse):
    id: UUID
    incident_key: str
    title: str
    state: str
    severity: str
    risk_score: float | None


class CyberMemoryResponse(CoreResponse):
    id: UUID
    incident_id: UUID | None
    decision_id: UUID | None
    lesson: str
    outcome: str | None
    action_taken: str | None
    effectiveness: str
    created_at: datetime
    incident: IncidentReference | None
    decision: DecisionResponse | None
    authorizations: list[AuthorizationResponse]
    containment_actions: list[ContainmentResponse]


class DashboardStats(CoreResponse):
    total_security_events: int
    critical_events: int
    high_events: int
    active_incidents: int
    critical_incidents: int
    average_risk_score: float | None
    current_risk_score: float | None = Field(
        description="System-level current risk is not persisted; null until a risk assessment model exists."
    )
    asset_count: int
    critical_asset_count: int
    threat_indicator_count: int
    recent_events_24h: int = Field(alias="recentEvents24h")
    recent_incidents_24h: int = Field(alias="recentIncidents24h")