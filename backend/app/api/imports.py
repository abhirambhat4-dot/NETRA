import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError
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
from app.schemas.imports import (
    EventCoverageResponse,
    FieldMapping,
    FieldSuggestionResponse,
    ImportBatchDetailResponse,
    ImportBatchSummaryResponse,
    ImportIssueResponse,
    ImportPreviewResponse,
)
from app.services.csv_preview import PreviewError, build_preview, catalog
from app.services.dataset_import import (
    DuplicateImport,
    RowLimitExceeded,
    UploadTooLarge,
    batch_normalization,
    consume_preview_rate_limit,
    consume_rate_limit,
    digest_upload,
    event_coverage,
    find_validated_batch,
    find_validated_file,
    get_batch,
    import_limits,
    list_batches,
    record_batch,
    safe_filename,
    validate_upload,
)
from app.services.dataset_profiles import DatasetProfile, get_profile
from app.services.security_csv import DELIMITERS, ENCODINGS, SECURITY_CSV_PROFILE, SecurityCsvProfile

router = APIRouter(prefix="/imports", tags=["imports"])

# Room for the multipart boundaries, part headers and the form fields around the file itself.
MULTIPART_OVERHEAD_BYTES = 64 * 1024
# Largest non-file form field: a security-csv mapping is a small JSON object.
MAX_FIELD_BYTES = 16 * 1024
MAX_FORM_FIELDS = 2
FORM_FIELDS = {"file", "profile", "mapping"}
PREVIEW_FORM_FIELDS = {"file", "encoding", "delimiter"}
# Browsers label .csv files inconsistently (Windows commonly sends application/vnd.ms-excel).
CSV_CONTENT_TYPES = frozenset(
    {"text/csv", "application/csv", "text/plain", "application/vnd.ms-excel", "application/octet-stream"}
)
FORM_SHAPE = (
    "Body must be multipart form data with one 'file' part, one 'profile' field and, for security-csv, "
    "one 'mapping' field"
)
PREVIEW_FORM_SHAPE = "Body must be multipart form data with one 'file' part and optional 'encoding' and 'delimiter' fields"


@dataclass(frozen=True)
class ImportUpload:
    file: UploadFile
    filename: str
    profile: DatasetProfile


@dataclass(frozen=True)
class PreviewUpload:
    file: UploadFile
    filename: str
    encoding: str | None
    delimiter: str | None


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


def _csv_file(form: FormData, allowed: set[str], shape: str) -> tuple[UploadFile, str]:
    """The single CSV file part, after checking the form has only ``allowed`` fields, each at most once."""
    keys = [key for key, _ in form.multi_items()]
    if set(keys) - allowed or len(keys) != len(set(keys)):
        raise _unprocessable(shape)
    file = form.get("file")
    if not isinstance(file, UploadFile):
        raise _unprocessable("file is required and must be sent as a file part")
    filename = safe_filename(file.filename)
    part_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if not filename.casefold().endswith(".csv") or (part_type and part_type not in CSV_CONTENT_TYPES):
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only CSV files (.csv) are accepted")
    return file, filename


def _text_field(form: FormData, name: str) -> str | None:
    value = form.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _unprocessable(f"{name} must be a text field")
    return value


def parse_mapping(raw: str) -> FieldMapping:
    """The mapping field as a FieldMapping; errors name the field and rule, never the submitted value."""
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise _unprocessable("mapping must be a JSON object") from None
    if not isinstance(data, dict):
        raise _unprocessable("mapping must be a JSON object")
    try:
        return FieldMapping.model_validate(data)
    except ValidationError as error:
        reasons = []
        for item in error.errors(include_input=False, include_url=False, include_context=False):
            location = ".".join(str(part) for part in item["loc"])
            message = item["msg"].removeprefix("Value error, ")
            reasons.append(f"{location}: {message}" if location else message)
        raise _unprocessable("mapping is invalid: " + "; ".join(reasons)) from None


def _upload_from_form(form: FormData) -> ImportUpload:
    file, filename = _csv_file(form, FORM_FIELDS, FORM_SHAPE)
    raw_profile = _text_field(form, "profile")
    if raw_profile is None or not raw_profile.strip():
        raise _unprocessable("profile is required")
    raw_mapping = _text_field(form, "mapping")
    profile: DatasetProfile | None
    if raw_profile.strip() == SECURITY_CSV_PROFILE:
        if raw_mapping is None or not raw_mapping.strip():
            raise _unprocessable("mapping is required for the security-csv profile")
        profile = SecurityCsvProfile(parse_mapping(raw_mapping))
    else:
        profile = get_profile(raw_profile.strip())
        if profile is None:
            raise _unprocessable("profile is not a known dataset profile")
        if raw_mapping is not None:
            raise _unprocessable("mapping applies only to the security-csv profile")
    return ImportUpload(file=file, filename=filename, profile=profile)


def _preview_from_form(form: FormData) -> PreviewUpload:
    file, filename = _csv_file(form, PREVIEW_FORM_FIELDS, PREVIEW_FORM_SHAPE)
    encoding = _text_field(form, "encoding") or None
    delimiter = _text_field(form, "delimiter") or None
    if encoding is not None and encoding not in ENCODINGS:
        raise _unprocessable(f"encoding must be one of {', '.join(ENCODINGS)}")
    if delimiter is not None and delimiter not in DELIMITERS:
        raise _unprocessable("delimiter must be a comma, semicolon, tab or pipe")
    return PreviewUpload(file=file, filename=filename, encoding=encoding, delimiter=delimiter)


@asynccontextmanager
async def _multipart_form(
    request: Request, user: User, db: Session, rate_limit: Callable[[User], None], shape: str
) -> AsyncIterator[FormData]:
    """Parse the multipart body through a byte cap; the file spools to a temporary file, never fully to memory."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "multipart/form-data":
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=shape)
    limits = import_limits()
    request_limit = limits.max_upload_bytes + MULTIPART_OVERHEAD_BYTES
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > request_limit:
        raise _too_large(limits.max_upload_bytes)
    rate_limit(user)
    # Authentication read from the database; end that transaction so no connection idles while the body streams.
    await run_in_threadpool(db.commit)

    parser = MultiPartParser(
        request.headers,
        _capped_stream(request, request_limit),
        max_files=1,
        max_fields=MAX_FORM_FIELDS,
        max_part_size=MAX_FIELD_BYTES,
    )
    try:
        form = await parser.parse()
    except MultiPartException:
        raise _unprocessable(shape) from None
    try:
        yield form
    finally:
        await form.close()


async def read_import_upload(
    request: Request,
    # Authentication and the rate limit resolve first, so no body is read for rejected callers.
    current_user: Annotated[User, Depends(require_permission(Permission.OPERATE_WORKFLOW))],
    db: Annotated[Session, Depends(get_db)],
) -> AsyncIterator[ImportUpload]:
    async with _multipart_form(request, current_user, db, consume_rate_limit, FORM_SHAPE) as form:
        yield _upload_from_form(form)


async def read_preview_upload(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(Permission.OPERATE_WORKFLOW))],
    db: Annotated[Session, Depends(get_db)],
) -> AsyncIterator[PreviewUpload]:
    async with _multipart_form(request, current_user, db, consume_preview_rate_limit, PREVIEW_FORM_SHAPE) as form:
        yield _preview_from_form(form)


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


def import_batch_detail_response(db: Session, batch: ImportBatch) -> ImportBatchDetailResponse:
    stored = batch.events_created > 0
    return ImportBatchDetailResponse(
        **_summary_fields(batch),
        error_sample=[ImportIssueResponse.model_validate(issue) for issue in batch.error_sample],
        error_sample_truncated=batch.error_total > len(batch.error_sample),
        normalization=batch_normalization(db, batch) if stored else None,
        event_coverage=EventCoverageResponse(**event_coverage(db, batch)) if stored else None,
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
    the same transaction; other profiles store no rows. The security-csv profile also needs a
    ``mapping`` field (a JSON FieldMapping), normally confirmed from POST /api/imports/preview.
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
    return import_batch_detail_response(db, batch)


@router.post(
    "/preview",
    response_model=ImportPreviewResponse,
    responses={
        status.HTTP_413_CONTENT_TOO_LARGE: {"description": "Upload byte limit exceeded"},
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"description": "Not a multipart CSV upload"},
        status.HTTP_422_UNPROCESSABLE_CONTENT: {"description": "The file cannot be read as CSV text"},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Preview rate limit exceeded"},
    },
)
def preview_import(
    upload: Annotated[PreviewUpload, Depends(read_preview_upload)],
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission(Permission.OPERATE_WORKFLOW))],
) -> ImportPreviewResponse:
    """Detect the encoding, delimiter and likely field mappings of a CSV without recording anything.

    Suggestions are advice for the user to confirm or correct: POST /api/imports with the security-csv
    profile requires the confirmed mapping explicitly.
    """
    limits = import_limits()
    try:
        digest = digest_upload(upload.file.file, limits.max_upload_bytes)
    except UploadTooLarge:
        raise _too_large(limits.max_upload_bytes) from None
    try:
        preview = build_preview(upload.file.file, encoding=upload.encoding, delimiter=upload.delimiter)
    except PreviewError as error:
        raise _unprocessable(str(error)) from None
    existing = find_validated_file(db, SECURITY_CSV_PROFILE, SecurityCsvProfile.version, digest.sha256)
    return ImportPreviewResponse(
        original_filename=upload.filename,
        file_size_bytes=digest.size_bytes,
        file_sha256=digest.sha256,
        encoding=preview.encoding,
        encoding_confident=preview.encoding_confident,
        delimiter=preview.delimiter,
        delimiter_confident=preview.delimiter_confident,
        columns=preview.columns,
        rows=preview.rows,
        sampled_rows=preview.sampled_rows,
        more_rows=preview.more_rows,
        suggested_record_type=preview.suggested_record_type,
        suggestions=[
            FieldSuggestionResponse(
                field=item.field,
                column=item.column,
                column_index=item.column_index,
                confidence=item.confidence,
                reason=item.reason,
                candidates=list(item.candidates),
            )
            for item in preview.suggestions
        ],
        suggested_timestamp_format=preview.suggested_timestamp_format,
        timestamp_format_candidates=preview.timestamp_format_candidates,
        timestamp_has_zone=preview.timestamp_has_zone,
        recognized_profile=preview.recognized_profile,
        warnings=preview.warnings,
        needs_review=preview.needs_review,
        already_imported=existing is not None,
        # Batch IDs are shown only to their uploader.
        already_imported_batch_id=existing.id if existing is not None and existing.uploaded_by_id == current_user.id else None,
        **catalog(),
    )


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
    return import_batch_detail_response(db, batch)
