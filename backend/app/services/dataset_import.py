"""Validation-only dataset imports: hash an uploaded CSV, validate it against a profile and record
the outcome as an import batch.

Dataset rows are never stored. Nothing here writes to security_events, incidents, assets or the
Security Assessment tables, and issues never carry cell contents.

Duplicate policy: a file (by SHA-256) is recorded as VALIDATED at most once per profile identifier
and version. A pre-check answers quickly; the partial unique index uq_import_batches_validated_file
is the final guard when two uploads of the same file race. REJECTED batches do not reserve the hash.
"""

import csv
import hashlib
import io
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, BinaryIO
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.enums import ImportBatchStatus
from app.models.import_batch import ImportBatch
from app.models.user import User
from app.services.dataset_profiles import DatasetProfile, ValidationIssue
from app.services.rate_limit import SlidingWindowRateLimiter

HASH_CHUNK_BYTES = 1024 * 1024
# Longest physical line read into memory; bounds per-row memory independently of the file cap.
MAX_LINE_CHARACTERS = 1024 * 1024
MAX_ERROR_SAMPLE = 100
MAX_FILENAME_LENGTH = 255
VALIDATED_FILE_INDEX = "uq_import_batches_validated_file"

# Each upload is parsed and hashed in full, so uploads are limited per user.
import_user_limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)


@dataclass(frozen=True)
class ImportLimits:
    max_upload_bytes: int
    max_rows: int


@dataclass(frozen=True)
class FileDigest:
    sha256: str
    size_bytes: int
    contains_nul: bool


@dataclass
class ValidationReport:
    total_rows: int = 0
    accepted_rows: int = 0
    rejected_rows: int = 0
    error_total: int = 0
    error_sample: list[dict[str, Any]] = field(default_factory=list)
    file_rejected: bool = False

    def add(self, issue: ValidationIssue) -> None:
        self.error_total += 1
        if len(self.error_sample) < MAX_ERROR_SAMPLE:
            self.error_sample.append(issue.as_dict())

    def reject_file(self, issue: ValidationIssue) -> None:
        self.add(issue)
        self.file_rejected = True


class UploadTooLarge(Exception):
    pass


class RowLimitExceeded(Exception):
    pass


class LineTooLong(Exception):
    pass


class DuplicateImport(Exception):
    def __init__(self, existing: ImportBatch | None) -> None:
        super().__init__("file already validated")
        self.existing = existing


def import_limits() -> ImportLimits:
    settings = get_settings()
    return ImportLimits(max_upload_bytes=settings.import_max_upload_bytes, max_rows=settings.import_max_rows)


def consume_rate_limit(user: User) -> None:
    if not import_user_limiter.allow(str(user.id)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Import rate limit exceeded. Try again in a minute.",
        )


def safe_filename(raw: str | None) -> str:
    """Base name only, without control or format characters, truncated to the column length.

    Truncation shortens the stem so a short extension such as ``.csv`` survives.
    """
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(character for character in name if unicodedata.category(character)[0] != "C").strip()
    if len(name) <= MAX_FILENAME_LENGTH:
        return name
    stem, dot, extension = name.rpartition(".")
    if dot and stem and len(extension) <= 16:
        return f"{stem[: MAX_FILENAME_LENGTH - len(extension) - 1]}.{extension}"
    return name[:MAX_FILENAME_LENGTH]


def digest_upload(file: BinaryIO, max_bytes: int) -> FileDigest:
    """SHA-256 and size, read in fixed chunks; raises UploadTooLarge past ``max_bytes``."""
    file.seek(0)
    digest = hashlib.sha256()
    size = 0
    contains_nul = False
    while chunk := file.read(HASH_CHUNK_BYTES):
        size += len(chunk)
        if size > max_bytes:
            raise UploadTooLarge
        digest.update(chunk)
        contains_nul = contains_nul or b"\x00" in chunk
    file.seek(0)
    return FileDigest(sha256=digest.hexdigest(), size_bytes=size, contains_nul=contains_nul)


def _bounded_lines(text: io.TextIOBase) -> Iterator[str]:
    while line := text.readline(MAX_LINE_CHARACTERS + 1):
        if len(line) > MAX_LINE_CHARACTERS:
            raise LineTooLong
        yield line


READ_ERRORS = (UnicodeDecodeError, LineTooLong, csv.Error)


def read_issue(error: Exception, profile: DatasetProfile, row: int) -> ValidationIssue:
    """File-level issue for one of READ_ERRORS."""
    if isinstance(error, UnicodeDecodeError):
        # Decoding runs ahead of parsing, so no row number is given rather than a misleading one.
        return ValidationIssue("file.encoding", f"file is not valid {profile.encoding} text")
    if isinstance(error, LineTooLong):
        return ValidationIssue("file.line_too_long", f"line is longer than {MAX_LINE_CHARACTERS} characters", row=row)
    # csv.Error messages are not echoed: the report states the rule only.
    return ValidationIssue("file.malformed", "row is not valid CSV", row=row)


@contextmanager
def open_csv(file: BinaryIO, profile: DatasetProfile) -> Iterator[Iterator[list[str]]]:
    """CSV records decoded with the profile's encoding (strict), with line length bounded.

    Reading may raise any of READ_ERRORS. The binary file is left open for its owner to close.
    """
    file.seek(0)
    text = io.TextIOWrapper(file, encoding=profile.encoding, errors="strict", newline="")
    try:
        yield csv.reader(_bounded_lines(text), strict=True)
    finally:
        text.detach()


def check_record(
    profile: DatasetProfile, header: list[str], positions: dict[str, int], record: list[str], row: int
) -> list[ValidationIssue]:
    """Issues for one non-blank record: the field count, then the profile's row rules."""
    if len(record) != len(header):
        return [ValidationIssue("row.column_count", f"row has {len(record)} fields; the header has {len(header)}", row=row)]
    values = {name: record[index] for name, index in positions.items()}
    return [replace(issue, row=row) for issue in profile.check_row(values)]


def validate_upload(file: BinaryIO, profile: DatasetProfile, digest: FileDigest, max_rows: int) -> ValidationReport:
    """Stream the file through the profile. Raises RowLimitExceeded past ``max_rows`` data rows."""
    report = ValidationReport()
    if digest.contains_nul:
        report.reject_file(ValidationIssue("file.not_text", "file contains binary data, not CSV text"))
        return report

    with open_csv(file, profile) as reader:
        try:
            header = next(reader, None)
        except READ_ERRORS as error:
            report.reject_file(read_issue(error, profile, row=1))
            return report
        if not header:
            report.reject_file(ValidationIssue("header.missing", "file has no header row", row=1))
            return report
        header_issues = profile.check_header(header)
        if header_issues:
            for issue in header_issues:
                report.add(issue)
            report.file_rejected = True
            return report

        positions = profile.column_positions(header)
        row_number = 1
        while True:
            try:
                record = next(reader, None)
            except READ_ERRORS as error:
                report.reject_file(read_issue(error, profile, row=row_number + 1))
                break
            if record is None:
                break
            row_number += 1
            if not record:
                continue  # blank line: keeps its row number, is not counted as data
            if report.total_rows >= max_rows:
                raise RowLimitExceeded
            report.total_rows += 1

            issues = check_record(profile, header, positions, record, row_number)
            if issues:
                report.rejected_rows += 1
                for issue in issues:
                    report.add(issue)
            else:
                report.accepted_rows += 1

        if not report.file_rejected and report.total_rows == 0:
            report.reject_file(ValidationIssue("file.no_rows", "file has a header but no data rows"))
        return report


def find_validated_batch(db: Session, profile: DatasetProfile, sha256: str) -> ImportBatch | None:
    return db.scalar(
        select(ImportBatch).where(
            ImportBatch.dataset_profile == profile.identifier,
            ImportBatch.profile_version == profile.version,
            ImportBatch.file_sha256 == sha256,
            ImportBatch.status == ImportBatchStatus.VALIDATED,
        )
    )


def _violates_validated_file_index(error: IntegrityError) -> bool:
    diag = getattr(error.orig, "diag", None)
    return getattr(diag, "constraint_name", None) == VALIDATED_FILE_INDEX


def record_batch(
    db: Session,
    user: User,
    *,
    profile: DatasetProfile,
    filename: str,
    digest: FileDigest,
    report: ValidationReport,
) -> ImportBatch:
    batch = ImportBatch(
        dataset_profile=profile.identifier,
        profile_version=profile.version,
        original_filename=filename,
        file_sha256=digest.sha256,
        file_size_bytes=digest.size_bytes,
        uploaded_by_id=user.id,
        status=ImportBatchStatus.REJECTED if report.file_rejected else ImportBatchStatus.VALIDATED,
        total_rows=report.total_rows,
        accepted_rows=report.accepted_rows,
        rejected_rows=report.rejected_rows,
        error_total=report.error_total,
        error_sample=report.error_sample,
        completed_at=datetime.now(UTC),
    )
    db.add(batch)
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        if _violates_validated_file_index(error):
            # A concurrent upload of the same file was recorded first.
            raise DuplicateImport(find_validated_batch(db, profile, digest.sha256)) from None
        raise
    db.refresh(batch)
    return batch


def list_batches(db: Session, user: User, page: int, page_size: int) -> tuple[int, list[ImportBatch]]:
    """Batches uploaded by ``user``, newest first. There is no role model, so nobody sees others' batches."""
    own = ImportBatch.uploaded_by_id == user.id
    total = int(db.scalar(select(func.count()).select_from(ImportBatch).where(own)) or 0)
    batches = db.scalars(
        select(ImportBatch)
        .where(own)
        # created_at is the transaction time; completed_at is assigned per upload by the application.
        .order_by(ImportBatch.created_at.desc(), ImportBatch.completed_at.desc(), ImportBatch.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return total, list(batches)


def get_batch(db: Session, user: User, batch_id: UUID) -> ImportBatch | None:
    return db.scalar(select(ImportBatch).where(ImportBatch.id == batch_id, ImportBatch.uploaded_by_id == user.id))
