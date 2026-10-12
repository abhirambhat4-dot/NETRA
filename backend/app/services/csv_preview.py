"""Read-only preview of an uploaded CSV: encoding, delimiter, sample rows and suggested field mappings.

Nothing is stored. Only the first ``SAMPLE_BYTES`` of the file are read, so problems later in the file
are found by the import itself. Suggestions are advice: the import requires an explicit mapping, and
only a suggestion whose column name AND sampled values agree is marked ``high`` confidence. Anything
weaker (``low``, ``ambiguous``) is shown to the user to decide, never applied silently.

Sample cells are returned to the uploader so they can check the mapping; each is truncated and
formula-like cells are neutralised (``formula_safe``) so copying them into a spreadsheet is inert.
"""

import codecs
import csv
import io
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, BinaryIO

from app.services.dataset_profiles import CIC_IDS2017_COLUMNS, MAX_COLUMNS, column_key
from app.services.security_csv import (
    DELIMITERS,
    ENCODINGS,
    FIELDS,
    RECORD_TYPES,
    TIMESTAMP_FORMATS,
    TimestampError,
    formula_safe,
    is_formula_like,
    parse_port,
    parse_protocol,
    parse_timestamp,
    valid_ip,
)

SAMPLE_BYTES = 1024 * 1024
SAMPLE_ROWS = 200
PREVIEW_ROWS = 20
PREVIEW_CELL_CHARACTERS = 200
DELIMITER_PROBE_RECORDS = 50
# Share of a column's sampled non-empty values that must fit a field's kind for a confident match.
VALUE_AGREEMENT = 0.9
# Formats tried when detecting timestamps, in order of preference.
DETECTABLE_FORMATS = ("iso8601", "rfc2822", "dmy", "mdy", "epoch_seconds", "epoch_millis")


class PreviewError(ValueError):
    """The file cannot be previewed at all; the message is fixed text, never file content."""


@dataclass
class ColumnSample:
    index: int  # 1-based
    name: str
    values: list[str] = field(default_factory=list)  # non-empty, stripped

    @property
    def key(self) -> str:
        return column_key(self.name)


@dataclass(frozen=True)
class Suggestion:
    field: str
    column: str | None
    column_index: int | None
    confidence: str  # high | low | ambiguous | none
    reason: str
    candidates: tuple[str, ...] = ()


def detect_encoding(head: bytes) -> tuple[str, bool]:
    """(encoding name, confident). UTF-16 needs a byte order mark; otherwise UTF-8, then Windows-1252."""
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16", True
    try:
        codecs.getincrementaldecoder("utf-8")(errors="strict").decode(head, final=False)
        return "utf-8", True
    except UnicodeDecodeError:
        pass
    try:
        head.decode("cp1252")
        return "cp1252", False
    except UnicodeDecodeError:
        return "iso-8859-1", False


def _records(text: str, delimiter: str, limit: int) -> tuple[list[list[str]], bool]:
    """Up to ``limit`` records (blank ones dropped) and whether parsing stopped on malformed CSV."""
    records: list[list[str]] = []
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
    try:
        for record in reader:
            if record and any(cell.strip() for cell in record):
                records.append(record)
                if len(records) >= limit:
                    break
    except csv.Error:
        return records, True
    return records, False


def detect_delimiter(text: str) -> tuple[str, bool]:
    """(delimiter, confident): the candidate giving every probed record the header's field count (> 1)."""
    consistent: list[tuple[int, str]] = []
    widest: tuple[int, str] = (1, ",")
    for delimiter in DELIMITERS:
        records, _ = _records(text, delimiter, DELIMITER_PROBE_RECORDS)
        if not records:
            continue
        width = len(records[0])
        widest = max(widest, (width, delimiter), key=lambda item: item[0])
        if width > 1 and all(len(record) == width for record in records):
            consistent.append((width, delimiter))
    if not consistent:
        return widest[1], False
    # Prefer the candidate that splits into the most columns; ties keep candidate order (comma first).
    best = max(consistent, key=lambda item: item[0])
    return best[1], len(consistent) == 1 or sum(width == best[0] for width, _ in consistent) == 1


def _share(values: Sequence[str], test: Any) -> float:
    return sum(1 for value in values if test(value)) / len(values) if values else 0.0


def timestamp_formats(values: Sequence[str], now: datetime) -> list[str]:
    """Formats that parse every sampled value (empty when there are no values)."""
    if not values:
        return []
    found = []
    for fmt in DETECTABLE_FORMATS:
        try:
            for value in values:
                parse_timestamp(value, fmt, UTC, now)
        except TimestampError:
            continue
        found.append(fmt)
    return found


def _values_fit(kind: str, column: ColumnSample, now: datetime, *, named: bool) -> bool:
    values = column.values
    if not values:
        return False
    if kind == "ip":
        return _share(values, valid_ip) >= VALUE_AGREEMENT
    if kind == "port":
        return _share(values, lambda value: parse_port(value) is not None) >= VALUE_AGREEMENT
    if kind == "protocol":
        return _share(values, lambda value: parse_protocol(value) is not None) >= VALUE_AGREEMENT
    if kind == "timestamp":
        formats = timestamp_formats(values, now)
        # Any small integer is a valid Unix time, so epoch formats count only for a column named as a time.
        return bool(formats if named else [fmt for fmt in formats if not fmt.startswith("epoch")])
    return True


def inferred_kind(column: ColumnSample, now: datetime) -> str:
    values = column.values
    if not values:
        return "empty"
    if _share(values, valid_ip) >= VALUE_AGREEMENT:
        return "ip address"
    if [fmt for fmt in timestamp_formats(values, now) if not fmt.startswith("epoch")]:
        return "timestamp"
    if _share(values, lambda value: parse_port(value) is not None) >= VALUE_AGREEMENT:
        return "integer"
    return "text"


def suggest_fields(columns: Sequence[ColumnSample], now: datetime) -> list[Suggestion]:
    """One suggestion per canonical field. Only a name match whose values also fit is ``high``."""
    usable = [column for column in columns if column.name.strip()]
    names = Counter(column.key for column in usable)
    high: dict[str, list[ColumnSample]] = {}
    low: dict[str, tuple[ColumnSample, str]] = {}
    for canonical in FIELDS:
        for column in usable:
            if names[column.key] > 1:
                continue  # repeated names cannot be mapped unambiguously
            name_match = column.key in canonical.synonyms
            fits = _values_fit(canonical.kind, column, now, named=name_match)
            if name_match and fits:
                high.setdefault(canonical.name, []).append(column)
            elif name_match and canonical.name not in low:
                reason = (
                    "column name matches, but the column is empty in the sample"
                    if not column.values
                    else f"column name matches, but sampled values do not look like a {canonical.label.lower()}"
                )
                low[canonical.name] = (column, reason)
            elif fits and canonical.kind in ("timestamp", "ip") and canonical.name not in low:
                low[canonical.name] = (column, f"values look like a {canonical.label.lower()}, but the name does not say so")

    suggestions: list[Suggestion] = []
    taken: set[str] = set()
    for canonical in FIELDS:
        matches = [column for column in high.get(canonical.name, []) if column.key not in taken]
        if len(matches) == 1:
            column = matches[0]
            taken.add(column.key)
            suggestions.append(
                Suggestion(canonical.name, column.name.strip(), column.index, "high", "column name and sampled values agree")
            )
        elif len(matches) > 1:
            suggestions.append(
                Suggestion(
                    canonical.name, None, None, "ambiguous", "several columns match; choose one",
                    tuple(column.name.strip() for column in matches),
                )
            )  # fmt: skip
        elif canonical.name in low and low[canonical.name][0].key not in taken:
            column, reason = low[canonical.name]
            suggestions.append(Suggestion(canonical.name, column.name.strip(), column.index, "low", reason))
        else:
            suggestions.append(Suggestion(canonical.name, None, None, "none", "no matching column found"))
    return suggestions


@dataclass
class Preview:
    encoding: str
    encoding_confident: bool
    delimiter: str
    delimiter_confident: bool
    columns: list[dict[str, Any]]
    rows: list[list[str]]
    sampled_rows: int
    more_rows: bool
    suggested_record_type: str
    suggestions: list[Suggestion]
    suggested_timestamp_format: str | None
    timestamp_format_candidates: list[str]
    timestamp_has_zone: bool | None
    recognized_profile: str | None
    warnings: list[str]
    needs_review: bool


def _preview_cell(value: str) -> str:
    cell = formula_safe(value)
    return cell if len(cell) <= PREVIEW_CELL_CHARACTERS else f"{cell[: PREVIEW_CELL_CHARACTERS - 1]}…"


def build_preview(
    file: BinaryIO,
    *,
    encoding: str | None = None,
    delimiter: str | None = None,
    now: datetime | None = None,
) -> Preview:
    """Profile the start of ``file``. ``encoding``/``delimiter`` override detection when given."""
    now = now or datetime.now(UTC)
    file.seek(0)
    head = file.read(SAMPLE_BYTES + 1)
    file.seek(0)
    truncated = len(head) > SAMPLE_BYTES
    head = head[:SAMPLE_BYTES]
    if not head.strip():
        raise PreviewError("The file is empty.")

    encoding_confident = True
    if encoding is None:
        encoding, encoding_confident = detect_encoding(head)
    if encoding != "utf-16" and b"\x00" in head:
        raise PreviewError("The file contains binary data, not CSV text.")
    try:
        text = codecs.getincrementaldecoder(ENCODINGS[encoding])(errors="strict").decode(head, final=not truncated)
    except UnicodeDecodeError:
        raise PreviewError(f"The file is not valid {encoding} text. Choose another encoding.") from None
    if "\x00" in text:
        raise PreviewError("The file contains binary data, not CSV text.")
    if truncated:
        # Drop the partial last line of the sample.
        text = text[: text.rfind("\n") + 1] or text

    delimiter_confident = True
    if delimiter is None:
        delimiter, delimiter_confident = detect_delimiter(text)

    records, malformed = _records(text, delimiter, SAMPLE_ROWS + 1)
    if not records:
        raise PreviewError("The file has no header row.")
    header, data = records[0], records[1:]
    if len(header) > MAX_COLUMNS:
        raise PreviewError(f"The header has more than {MAX_COLUMNS} columns.")
    more_rows = truncated or len(data) >= SAMPLE_ROWS or malformed
    data = data[: SAMPLE_ROWS]

    columns = [ColumnSample(index=position, name=name) for position, name in enumerate(header, start=1)]
    mismatched = 0
    for record in data:
        if len(record) != len(header):
            mismatched += 1
            continue
        for column, cell in zip(columns, record, strict=True):
            if cell.strip():
                column.values.append(cell.strip())

    suggestions = suggest_fields(columns, now)
    by_field = {suggestion.field: suggestion for suggestion in suggestions}
    confident = {name for name, suggestion in by_field.items() if suggestion.confidence == "high"}
    record_type = "network_flow" if {"src_ip", "dest_ip"} <= confident else "security_event"

    warnings: list[str] = []
    timestamp_column = by_field["occurred_at"]
    candidates: list[str] = []
    suggested_format: str | None = None
    has_zone: bool | None = None
    if timestamp_column.column_index is not None:
        values = columns[timestamp_column.column_index - 1].values
        candidates = timestamp_formats(values, now)
        if "iso8601" in candidates:
            suggested_format = "iso8601"
        elif "rfc2822" in candidates:
            suggested_format = "rfc2822"
        elif "dmy" in candidates and "mdy" in candidates:
            warnings.append(
                "Every sampled date could be day/month/year or month/day/year. Choose the timestamp format."
            )
        elif candidates:
            suggested_format = candidates[0]
        else:
            warnings.append("No supported timestamp format matches every sampled value of the timestamp column.")
        if suggested_format is not None and values:
            zones = [parse_timestamp(value, suggested_format, UTC, now).had_zone for value in values]
            has_zone = all(zones)
            if not has_zone:
                warnings.append(
                    "Some timestamps carry no time zone. They will be read in the UTC offset you choose (default +00:00)."
                )

    if not encoding_confident:
        warnings.append(f"The file is not valid UTF-8; it was read as {encoding}. Check that characters look right.")
    if not delimiter_confident:
        warnings.append("The delimiter could not be detected with confidence. Check that columns split correctly.")
    if len(header) == 1:
        warnings.append("Only one column was found. Check the delimiter.")
    if mismatched:
        warnings.append(f"{mismatched} sampled row(s) have a different number of fields than the header; the import will reject them.")
    if malformed:
        warnings.append("Part of the sample is not valid CSV (for example an unclosed quote); the import may reject the file.")
    blank_or_repeated = [column.index for column in columns if not column.name.strip()]
    counts = Counter(column.key for column in columns if column.name.strip())
    blank_or_repeated += [column.index for column in columns if column.name.strip() and counts[column.key] > 1]
    if blank_or_repeated:
        warnings.append(
            "Columns "
            + ", ".join(str(index) for index in sorted(blank_or_repeated))
            + " have blank or repeated names; they are kept with each event but cannot be mapped."
        )
    preview_rows = data[:PREVIEW_ROWS]
    formula_cells = sum(1 for record in preview_rows for cell in record if is_formula_like(cell))
    if formula_cells:
        warnings.append(
            f"{formula_cells} previewed cell(s) start with =, +, -, @ or a tab and are shown with a leading apostrophe "
            "so spreadsheets treat them as text."
        )

    recognized = "cic-ids2017" if tuple(name.strip() for name in header) == CIC_IDS2017_COLUMNS else None
    if recognized:
        warnings.append("The header matches CIC-IDS2017 labelled flows. The CIC-IDS2017 profile validates these files fully.")

    required = RECORD_TYPES[record_type].required
    needs_review = (
        not encoding_confident
        or not delimiter_confident
        or suggested_format is None
        or any(by_field[name].confidence != "high" for name in required)
        or any(suggestion.confidence == "ambiguous" for suggestion in suggestions)
    )
    return Preview(
        encoding=encoding,
        encoding_confident=encoding_confident,
        delimiter=delimiter,
        delimiter_confident=delimiter_confident,
        columns=[
            {
                "index": column.index,
                "name": column.name.strip(),
                "mappable": bool(column.name.strip()) and counts[column.key] == 1,
                "inferred_kind": inferred_kind(column, now),
                "non_empty": len(column.values),
            }
            for column in columns
        ],
        rows=[[_preview_cell(cell) for cell in record] for record in preview_rows],
        sampled_rows=len(data),
        more_rows=more_rows,
        suggested_record_type=record_type,
        suggestions=suggestions,
        suggested_timestamp_format=suggested_format,
        timestamp_format_candidates=candidates,
        timestamp_has_zone=has_zone,
        recognized_profile=recognized,
        warnings=warnings,
        needs_review=needs_review,
    )


def catalog() -> dict[str, Any]:
    """Field, record-type and format definitions the client needs to render the mapping form."""
    return {
        "fields": [
            {"name": item.name, "label": item.label, "kind": item.kind, "description": item.description} for item in FIELDS
        ],
        "record_types": [
            {"name": item.name, "title": item.title, "description": item.description, "required": list(item.required)}
            for item in RECORD_TYPES.values()
        ],
        "timestamp_formats": [{"name": name, "label": label} for name, label in TIMESTAMP_FORMATS.items()],
        "encodings": list(ENCODINGS),
        "delimiters": [{"value": value, "label": label} for value, label in DELIMITERS.items()],
    }
