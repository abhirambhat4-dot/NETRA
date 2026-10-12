from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from pydantic.alias_generators import to_camel

from app.schemas.core import CoreResponse
from app.services.security_csv import (
    DEFAULT_EVENT_TYPE_PATTERN,
    EVENT_TYPE_MAX_LENGTH,
    MAPPED_COLUMN_MAX_LENGTH,
    RECORD_TYPES,
    UTC_OFFSET_PATTERN,
)

CanonicalFieldName = Literal[
    "occurred_at", "event_type", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "severity", "message",
    "outcome", "label",
]  # fmt: skip
MappedColumn = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAPPED_COLUMN_MAX_LENGTH)]


class FieldMapping(BaseModel):
    """How a ``security-csv`` upload is read: sent as the JSON ``mapping`` form field of POST /api/imports.

    ``fields`` maps canonical field names (snake_case, as listed by the preview) to header names in the
    file; matching ignores case and surrounding spaces. Errors never echo submitted values.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid", frozen=True)

    record_type: Literal["security_event", "network_flow"]
    fields: dict[CanonicalFieldName, MappedColumn]
    timestamp_format: Literal["iso8601", "dmy", "mdy", "rfc2822", "epoch_seconds", "epoch_millis"]
    utc_offset: str = Field(default="+00:00", pattern=UTC_OFFSET_PATTERN)
    encoding: Literal["utf-8", "utf-16", "cp1252", "iso-8859-1"] = "utf-8"
    delimiter: Literal[",", ";", "\t", "|"] = ","
    # Event type for every row when no column holds one.
    default_event_type: str | None = Field(
        default=None, min_length=1, max_length=EVENT_TYPE_MAX_LENGTH, pattern=DEFAULT_EVENT_TYPE_PATTERN
    )

    @model_validator(mode="after")
    def complete_and_unambiguous(self) -> "FieldMapping":
        if self.default_event_type is not None and "event_type" in self.fields:
            raise ValueError("defaultEventType applies only when no column is mapped to event_type")
        required = RECORD_TYPES[self.record_type].required
        missing = [
            name
            for name in required
            if name not in self.fields and not (name == "event_type" and self.default_event_type)
        ]
        if missing:
            raise ValueError(f"required fields are not mapped: {', '.join(missing)}")
        columns = [column.casefold() for column in self.fields.values()]
        if len(set(columns)) != len(columns):
            raise ValueError("each column can be mapped to only one field")
        return self


class ImportIssueResponse(CoreResponse):
    """One validation issue. Never carries cell contents."""

    rule: str
    message: str
    row: int | None = Field(description="Record number counting the header as row 1.")
    column: str | None = Field(description="Column name defined by the dataset profile (security-csv: the canonical field).")
    column_index: int | None = Field(description="1-based column position in the uploaded file.")


class ImportBatchSummaryResponse(CoreResponse):
    id: UUID
    dataset_profile: str
    profile_version: str
    original_filename: str
    file_sha256: str
    file_size_bytes: int
    status: str = Field(description="VALIDATED or REJECTED. Only a VALIDATED batch of a normalising profile stores rows.")
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    error_total: int
    events_created: int = Field(description="Accepted rows stored as security events (0 for validation-only profiles).")
    duplicate_rows: int = Field(description="Accepted rows skipped because an identical row already exists as an event.")
    created_at: datetime
    completed_at: datetime | None


class EventCoverageResponse(CoreResponse):
    """What the batch's stored events can support. Security Assessment reads only asset-linked events."""

    events: int
    linked_to_asset: int
    address_without_asset: int = Field(description="Events with an IP address that no single registered asset matches.")
    without_address: int = Field(description="Events with no IP address; they cannot be linked to an asset.")


class ImportBatchDetailResponse(ImportBatchSummaryResponse):
    error_sample: list[ImportIssueResponse]
    error_sample_truncated: bool = Field(description="True when errorTotal exceeds the stored sample.")
    normalization: dict[str, Any] | None = Field(
        default=None,
        description="How rows were interpreted (profile, and for security-csv the record type, field mapping and "
        "timestamp reading), as recorded on the batch's events; null when the batch stored no events.",
    )
    event_coverage: EventCoverageResponse | None = None


class PreviewColumnResponse(CoreResponse):
    index: int = Field(description="1-based column position.")
    name: str
    mappable: bool = Field(description="False for blank or repeated names, which cannot be mapped by name.")
    inferred_kind: str
    non_empty: int = Field(description="Sampled rows with a value in this column.")


class FieldSuggestionResponse(CoreResponse):
    field: str
    column: str | None
    column_index: int | None
    confidence: Literal["high", "low", "ambiguous", "none"] = Field(
        description="Only 'high' (column name and sampled values agree) should be preselected."
    )
    reason: str
    candidates: list[str]


class CanonicalFieldResponse(CoreResponse):
    name: str
    label: str
    kind: str
    description: str


class RecordTypeResponse(CoreResponse):
    name: str
    title: str
    description: str
    required: list[str]


class NamedOptionResponse(CoreResponse):
    name: str
    label: str


class DelimiterOptionResponse(CoreResponse):
    value: str
    label: str


class ImportPreviewResponse(CoreResponse):
    """Read-only: nothing is recorded. Sample cells are truncated and formula-like cells neutralised."""

    original_filename: str
    file_size_bytes: int
    file_sha256: str
    encoding: str
    encoding_confident: bool
    delimiter: str
    delimiter_confident: bool
    columns: list[PreviewColumnResponse]
    rows: list[list[str]]
    sampled_rows: int
    more_rows: bool
    suggested_record_type: str
    suggestions: list[FieldSuggestionResponse]
    suggested_timestamp_format: str | None
    timestamp_format_candidates: list[str]
    timestamp_has_zone: bool | None
    recognized_profile: str | None
    warnings: list[str]
    needs_review: bool
    already_imported_batch_id: UUID | None = Field(
        default=None, description="Set when the caller already imported these exact bytes with security-csv."
    )
    already_imported: bool = False
    fields: list[CanonicalFieldResponse]
    record_types: list[RecordTypeResponse]
    timestamp_formats: list[NamedOptionResponse]
    encodings: list[str]
    delimiters: list[DelimiterOptionResponse]

