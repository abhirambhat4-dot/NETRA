from datetime import datetime
from uuid import UUID

from pydantic import Field

from app.schemas.core import CoreResponse


class ImportIssueResponse(CoreResponse):
    """One validation issue. Never carries cell contents."""

    rule: str
    message: str
    row: int | None = Field(description="Record number counting the header as row 1.")
    column: str | None = Field(description="Column name defined by the dataset profile.")
    column_index: int | None = Field(description="1-based column position in the uploaded file.")


class ImportBatchSummaryResponse(CoreResponse):
    id: UUID
    dataset_profile: str
    profile_version: str
    original_filename: str
    file_sha256: str
    file_size_bytes: int
    status: str = Field(description="VALIDATED or REJECTED. Uploads are validation-only: no rows are stored.")
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    error_total: int
    created_at: datetime
    completed_at: datetime | None


class ImportBatchDetailResponse(ImportBatchSummaryResponse):
    error_sample: list[ImportIssueResponse]
    error_sample_truncated: bool = Field(description="True when errorTotal exceeds the stored sample.")
