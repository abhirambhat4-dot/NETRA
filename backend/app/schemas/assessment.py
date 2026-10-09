from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

from app.schemas.core import AssetReference, CoreResponse

SeverityName = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CriticalityName = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ExposureName = Literal["INTERNAL", "DMZ", "INTERNET_FACING"]
AssetStatusName = Literal["ACTIVE", "INACTIVE", "DECOMMISSIONED"]
VulnerabilityStatusName = Literal["OPEN", "MITIGATED", "ACCEPTED", "FALSE_POSITIVE"]
IncidentStateName = Literal[
    "DETECTED", "UNDERSTOOD", "PRIORITISED", "VERIFIED", "AUTHORIZED", "CONTAINED", "LEARNED"
]
IndicatorTypeName = Literal["IP", "DOMAIN", "URL", "HASH"]
AssessmentResultName = Literal["PASS", "WARN", "FAIL", "INFO"]
AssessmentGrade = Literal["A", "B", "C", "D", "F"]


# Evidence snapshots: plain values loaded from the database, so the engine itself never queries.
class AssessmentAssetInput(CoreResponse):
    id: UUID
    asset_key: str
    name: str
    hostname: str | None
    ip_address: str | None
    criticality: CriticalityName
    exposure: ExposureName
    status: AssetStatusName
    owner: str | None


class AssessmentVulnerabilityInput(CoreResponse):
    id: UUID
    cve_id: str | None
    title: str
    cvss_score: float | None
    severity: SeverityName
    status: VulnerabilityStatusName


class AssessmentIncidentInput(CoreResponse):
    id: UUID
    incident_key: str
    severity: SeverityName
    state: IncidentStateName


class AssessmentLinkedIncidentInput(CoreResponse):
    """An incident an event is linked to, on any asset; its state decides how v2 attributes the event."""

    id: UUID
    incident_key: str
    state: IncidentStateName


class AssessmentEventInput(CoreResponse):
    id: UUID
    event_uid: str
    occurred_at: datetime
    severity: SeverityName
    src_ip: str | None
    dest_ip: str | None
    # Used by assessment-v2 only; assessment-v1 ignores incident links.
    linked_incidents: list[AssessmentLinkedIncidentInput] = []

    @field_validator("occurred_at")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("must include a timezone offset")
        return value


LinkStatusName = Literal["active", "resolved", "unlinked"]


class AssessmentEventBucket(CoreResponse):
    """How many in-window events share a severity, incident-link status and matched addresses.

    ``src_ip`` / ``dest_ip`` hold the normalized address only when it matches a supplied active IP
    indicator; otherwise they are null. Scores are computed from buckets, never from samples.
    """

    severity: SeverityName
    link_status: LinkStatusName
    src_ip: str | None
    dest_ip: str | None
    count: int = Field(ge=1)


class AssessmentEventEvidence(CoreResponse):
    """Aggregated in-window events: exact bucket counts plus a bounded sample of event rows.

    ``samples`` must hold the most recent events (by occurred_at, event_uid, id) of every
    (link status, HIGH/CRITICAL or not, indicator-matched or not) class, up to the engine's
    sample limit per class, with their linked incidents. Samples only supply listed evidence and
    referenced IDs, so which events they hold never changes a score.
    """

    buckets: list[AssessmentEventBucket] = []
    samples: list[AssessmentEventInput] = []


class AssessmentIndicatorInput(CoreResponse):
    id: UUID
    value: str
    indicator_type: IndicatorTypeName
    source: str
    severity: SeverityName
    confidence: float | None
    is_active: bool


class AssessmentInput(CoreResponse):
    asset: AssessmentAssetInput
    vulnerabilities: list[AssessmentVulnerabilityInput] = []
    incidents: list[AssessmentIncidentInput] = []
    # Either raw events (the engine aggregates them) or pre-aggregated ``event_evidence``, not both.
    events: list[AssessmentEventInput] = []
    event_evidence: AssessmentEventEvidence | None = None
    # With event_evidence, only indicators that can match the events need to be supplied; this then
    # records how many active IP indicators exist in total.
    threat_indicators: list[AssessmentIndicatorInput] = []
    active_ip_indicator_total: int | None = Field(default=None, ge=0)
    # Evidence cut-off; passed in rather than read from the clock so a snapshot can be reproduced.
    as_of: datetime

    @field_validator("as_of")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("must include a timezone offset")
        return value

    @model_validator(mode="after")
    def one_event_source(self) -> "AssessmentInput":
        if self.events and self.event_evidence is not None:
            raise ValueError("supply either events or event_evidence, not both")
        return self


class AssessmentFinding(CoreResponse):
    check_key: str
    category: str
    title: str
    result: AssessmentResultName
    severity: SeverityName | None
    deduction: int
    evidence: list[str]
    recommendation: str | None
    # Referenced IDs are capped (engine MAX_REFERENCE_IDS, most relevant first); the totals count every
    # matching record, so a total above the list length means the list was capped.
    vulnerability_ids: list[UUID] = []
    incident_ids: list[UUID] = []
    event_ids: list[UUID] = []
    vulnerability_total: int = 0
    incident_total: int = 0
    event_total: int = 0


class AssessmentResult(CoreResponse):
    methodology_version: str
    asset_id: UUID
    asset_key: str
    as_of: datetime
    score: int
    grade: AssessmentGrade
    summary: str
    passed: int
    warnings: int
    failed: int
    informational: int
    findings: list[AssessmentFinding]
    missing_evidence: list[str]


# --- API -----------------------------------------------------------------------------------------


class AssessmentCreateRequest(CoreResponse):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")

    asset_id: UUID


class AssessmentFindingResponse(CoreResponse):
    id: UUID
    position: int
    check_key: str
    category: str
    title: str
    result: AssessmentResultName
    severity: SeverityName | None
    deduction: int
    evidence: list[str]
    recommendation: str | None
    vulnerability_ids: list[UUID]
    incident_ids: list[UUID]
    event_ids: list[UUID]
    # Every matching record, including any beyond the capped ID lists above.
    vulnerability_total: int
    incident_total: int
    event_total: int


class AssessmentSummaryResponse(CoreResponse):
    id: UUID
    asset_id: UUID | None
    asset_key: str
    asset: AssetReference | None
    methodology_version: str
    as_of: datetime
    score: int
    grade: AssessmentGrade
    summary: str
    passed: int
    warnings: int
    failed: int
    informational: int
    requested_by: str
    created_at: datetime


class AssessmentDetailResponse(AssessmentSummaryResponse):
    missing_evidence: list[str]
    input_counts: dict[str, int]
    findings: list[AssessmentFindingResponse]
