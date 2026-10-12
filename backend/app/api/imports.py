from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
# Starlette's parser yields its own UploadFile; fastapi.UploadFile is a subclass that would never match.
from starlette.datastructures import FormData, UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from app.api.auth import get_current_user, require_permission
from app.api.core_serializers import enum_text
from app.core.permissions import Permission
from app.db.dependencies import get_db
from app.models.import_batch import ImportBatch
from app.models.user import User
from app.schemas.core import PageResponse
from app.schemas.imports import ImportBatchDetailResponse, ImportBatchSummaryResponse, ImportIssueResponse
from app.services.dataset_import import (
    DuplicateImport,
    RowLimitExceeded,
    UploadTooLarge,
    consume_rate_limit,
    digest_upload,
    find_validated_batch,
    get_batch,
    import_limits,
    list_batches,
    record_batch,
    safe_filename,
    validate_upload,
)
from app.services.dataset_profiles import DatasetProfile, get_profile

router = APIRouter(prefix="/imports", tags=["imports"])

# Room for the multipart boundaries, part headers and the profile field around the file itself.
MULTIPART_OVERHEAD_BYTES = 64 * 1024
MAX_FIELD_BYTES = 1024
FORM_FIELDS = {"file", "profile"}
# Browsers label .csv files inconsistently (Windows commonly sends application/vnd.ms-excel).
CSV_CONTENT_TYPES = frozenset(
    {"text/csv", "application/csv", "text/plain", "application/vnd.ms-excel", "application/octet-stream"}
)
FORM_SHAPE = "Body must be multipart form data with one 'file' part and one 'profile' field"


@dataclass(frozen=True)
class ImportUpload:
    file: UploadFile
    filename: str
    profile: DatasetProfile


def _too_large(max_bytes: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        detail=f"File exceeds the upload limit of {max_bytes} bytes",
    )


async def _capped_stream(request: Request, limit: int) -> AsyncIterator[bytes]:
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            # The parser closes (and so deletes) any temporary file it has opened.
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Request body is too large")
        yield chunk


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail)


def _upload_from_form(form: FormData) -> ImportUpload:
    if set(form.keys()) - FORM_FIELDS:
        raise _unprocessable(FORM_SHAPE)
    file = form.get("file")
    if not isinstance(file, UploadFile):
        raise _unprocessable("file is required and must be sent as a file part")

    raw_profile = form.get("profile")
    if not isinstance(raw_profile, str) or not raw_profile.strip():
        raise _unprocessable("profile is required")
    profile = get_profile(raw_profile.strip())
    if profile is None:
        raise _unprocessable("profile is not a known dataset profile")

    filename = safe_filename(file.filename)
    part_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if not filename.casefold().endswith(".csv") or (part_type and part_type not in CSV_CONTENT_TYPES):
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only CSV files (.csv) are accepted")
    return ImportUpload(file=file, filename=filename, profile=profile)


async def read_import_upload(
    request: Request,
    # Authentication and the rate limit resolve first, so no body is read for rejected callers.
    current_user: Annotated[User, Depends(require_permission(Permission.OPERATE_WORKFLOW))],
    db: Annotated[Session, Depends(get_db)],
) -> AsyncIterator[ImportUpload]:
    """Parse the multipart body through a byte cap; the file spools to a temporary file, never fully to memory."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "multipart/form-data":
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=FORM_SHAPE)
    limits = import_limits()
    request_limit = limits.max_upload_bytes + MULTIPART_OVERHEAD_BYTES
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > request_limit:
        raise _too_large(limits.max_upload_bytes)
    consume_rate_limit(current_user)
    # Authentication read from the database; end that transaction so no connection idles while the body streams.
    await run_in_threadpool(db.commit)

    parser = MultiPartParser(
        request.headers,
        _capped_stream(request, request_limit),
        max_files=1,
        max_fields=1,
        max_part_size=MAX_FIELD_BYTES,
    )
    try:
        form = await parser.parse()
    except MultiPartException:
        raise _unprocessable(FORM_SHAPE) from None
    try:
        yield _upload_from_form(form)
    finally:
        await form.close()


def _summary_fields(batch: ImportBatch) -> dict[str, object]:
    return {
        "id": batch.id,
        "dataset_profile": batch.dataset_profile,
        "profile_version": batch.profile_version,
        "original_filename": batch.original_filename,
        "file_sha256": batch.file_sha256,
        "file_size_bytes": batch.file_size_bytes,
        "status": enum_text(batch.status),
        "total_rows": batch.total_rows,
        "accepted_rows": batch.accepted_rows,
        "rejected_rows": batch.rejected_rows,
        "error_total": batch.error_total,
        "events_created": batch.events_created,
        "duplicate_rows": batch.duplicate_rows,
        "created_at": batch.created_at,
        "completed_at": batch.completed_at,
    }


def import_batch_detail_response(batch: ImportBatch) -> ImportBatchDetailResponse:
    return ImportBatchDetailResponse(
        **_summary_fields(batch),
        error_sample=[ImportIssueResponse.model_validate(issue) for issue in batch.error_sample],
        error_sample_truncated=batch.error_total > len(batch.error_sample),
    )


def _duplicate(existing: ImportBatch | None, user: User) -> HTTPException:
    detail = "This file has already been validated with this dataset profile"
    # Batch IDs are shown only to their uploader.
    if existing is not None and existing.uploaded_by_id == user.id:
        detail = f"{detail} (import batch {existing.id})"
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


@router.post(
    "",
    response_model=ImportBatchDetailResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_409_CONFLICT: {"description": "File already validated with this profile"},
        status.HTTP_413_CONTENT_TOO_LARGE: {"description": "Upload byte or row limit exceeded"},
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"description": "Not a multipart CSV upload"},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Import rate limit exceeded"},
    },
)
def create_import(
    upload: Annotated[ImportUpload, Depends(read_import_upload)],
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission(Permission.OPERATE_WORKFLOW))],
) -> ImportBatchDetailResponse:
    """Validate a CSV against a dataset profile and record the batch.

    For a normalising profile, the accepted rows of a validated batch are stored as security events in
    the same transaction; other profiles store no rows.
    """
    limits = import_limits()
    try:
        digest = digest_upload(upload.file.file, limits.max_upload_bytes)
    except UploadTooLarge:
        raise _too_large(limits.max_upload_bytes) from None
    existing = find_validated_batch(db, upload.profile, digest.sha256)
    if existing is not None:
        raise _duplicate(existing, current_user)
    try:
        report = validate_upload(upload.file.file, upload.profile, digest, limits.max_rows)
    except RowLimitExceeded:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File has more than {limits.max_rows} data rows",
        ) from None
    try:
        batch = record_batch(
            db,
            current_user,
            profile=upload.profile,
            filename=upload.filename,
            digest=digest,
            report=report,
            file=upload.file.file,
        )
    except DuplicateImport as duplicate:
        raise _duplicate(duplicate.existing, current_user) from None
    return import_batch_detail_response(batch)


@router.get("", response_model=PageResponse[ImportBatchSummaryResponse])
def list_imports(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
) -> PageResponse[ImportBatchSummaryResponse]:
    total, batches = list_batches(db, current_user, page, page_size)
    return PageResponse[ImportBatchSummaryResponse](
        items=[ImportBatchSummaryResponse(**_summary_fields(batch)) for batch in batches],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{batch_id}",
    response_model=ImportBatchDetailResponse,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Import batch not found"}},
)
def get_import(
    batch_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> ImportBatchDetailResponse:
    batch = get_batch(db, current_user, batch_id)
    if batch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Import batch not found")
    return import_batch_detail_response(batch)
