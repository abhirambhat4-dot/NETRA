from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.schemas.core import CoreResponse


class TechniqueCatalogueEntry(CoreResponse):
    """Catalogue metadata for a technique ID. Lookup data only: it never changes what was observed.

    No ATT&CK catalogue is bundled yet, so every entry is ``unknown`` with no name, tactics or URL.
    """

    status: Literal["known", "deprecated", "revoked", "unknown"] = "unknown"
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None


class TechniqueCatalogueInfo(CoreResponse):
    name: str
    version: str
    attribution: str


class ObservedTechniqueResponse(CoreResponse):
    """One technique ID as reported by detection sources (source-supplied evidence only; never inferred)."""

    technique_id: str
    evidence_kind: Literal["source_supplied"] = "source_supplied"
    event_count: int = Field(description="Distinct matching events that reported this technique.")
    incident_count: int = Field(description="Distinct incidents linked to those matching events.")
    active_incident_count: int = Field(description="Of incidentCount, incidents not CONTAINED or LEARNED.")
    incident_ids: list[UUID] = Field(description="Up to 100 of those incidents, ordered by id; incidentCount is the full count.")
    highest_severity: str
    first_seen: datetime
    last_seen: datetime
    sources: dict[str, int] = Field(description="Matching events by detection source.")
    origins: dict[str, int] = Field(description="Matching events by evidence origin (ingest_field, collector_field).")
    catalogue: TechniqueCatalogueEntry


class ObservedTechniquePage(CoreResponse):
    items: list[ObservedTechniqueResponse]
    total: int
    page: int
    page_size: int
    as_of: datetime = Field(description="The single UTC instant this response was computed for.")
    window_days: int = Field(description="Events with asOf - windowDays <= occurredAt <= asOf (both ends inclusive).")
    catalogue: TechniqueCatalogueInfo | None = Field(
        default=None, description="The bundled ATT&CK catalogue's name, version and attribution; null until one is approved."
    )
