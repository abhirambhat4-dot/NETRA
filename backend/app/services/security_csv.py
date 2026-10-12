"""Security CSV (profile ``security-csv``): field-mapped import of security CSVs from any source.

Unlike the fixed dataset profiles, this profile has no built-in header. Each upload carries a
``FieldMapping`` the user confirmed (normally after ``POST /api/imports/preview`` suggested one): which
source column holds each canonical event field, the record type, the timestamp format and the file's
encoding and delimiter. The server never guesses a mapping at import time.

Rules (each failure names a canonical field and a rule, never cell contents):
- Required fields depend on the record type (``RECORD_TYPES``); every other field is optional.
- A mapped value that is present must be valid (an optional IP that is malformed rejects the row
  rather than being dropped). A blank optional value is simply absent.
- A record whose cells are all empty is skipped like a blank line; it is not counted as data.
- Timestamps must parse under the chosen format and fall between 1970-01-01 and one day from now.
  A value without a zone is read in the mapping's ``utc_offset``; that reading is recorded per event.

What is trusted: nothing in the file is a NETRA finding. Severity is stored as INFO; the source's
severity, label, message and outcome are kept in ``raw_data`` only, and ``signature`` stays empty so
free text never feeds correlation keyword matching.
"""

import hashlib
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

from app.services.dataset_profiles import MAX_COLUMNS, DatasetProfile, NormalizedEvent, ValidationIssue

if TYPE_CHECKING:
    from app.schemas.imports import FieldMapping

SECURITY_CSV_PROFILE = "security-csv"


@dataclass(frozen=True)
class CanonicalField:
    name: str
    label: str
    # timestamp | ip | port | protocol | text
    kind: str
    description: str
    # Header names (after dataset_profiles.column_key) that suggest this field.
    synonyms: frozenset[str]


FIELDS: tuple[CanonicalField, ...] = (
    CanonicalField(
        "occurred_at", "Timestamp", "timestamp", "When the event happened.",
        frozenset({
            "timestamp", "time_stamp", "time", "datetime", "date_time", "date", "event_time", "eventtime",
            "event_timestamp", "ts", "created_at", "createdat", "time_generated", "timegenerated", "time_created",
            "timecreated", "log_time", "logtime", "start_time", "starttime", "stime", "received_at", "receivedat",
            "utc_time", "utctime", "generated_at", "occurred_at", "occurredat",
        }),
    ),
    CanonicalField(
        "event_type", "Event type", "text", "What the row records, such as a failed login or a blocked connection.",
        frozenset({
            "event_type", "eventtype", "event_name", "eventname", "event", "type", "category", "event_category",
            "eventcategory", "activity", "activity_name", "alert_type", "log_type", "logtype", "event_id", "eventid",
        }),
    ),
    CanonicalField(
        "src_ip", "Source IP", "ip", "Address the activity came from.",
        frozenset({
            "source_ip", "src_ip", "srcip", "sourceip", "src", "source", "source_address", "sourceaddress",
            "src_addr", "srcaddr", "src_ip_addr", "client_ip", "clientip", "client_address", "ip_src", "saddr",
            "id_orig_h", "orig_h", "source_ip_address", "remote_ip", "remote_addr", "ip_address", "ip",
        }),
    ),
    CanonicalField(
        "dest_ip", "Destination IP", "ip", "Address the activity was aimed at.",
        frozenset({
            "destination_ip", "dst_ip", "dest_ip", "dstip", "destip", "destinationip", "dst", "dest",
            "destination", "destination_address", "dst_addr", "dstaddr", "server_ip", "serverip", "ip_dst",
            "daddr", "id_resp_h", "resp_h", "target_ip", "host_ip",
        }),
    ),
    CanonicalField(
        "src_port", "Source port", "port", "Port the activity came from (0-65535).",
        frozenset({
            "source_port", "src_port", "srcport", "sourceport", "sport", "spt", "s_port", "id_orig_p", "orig_p",
            "client_port",
        }),
    ),
    CanonicalField(
        "dest_port", "Destination port", "port", "Port the activity was aimed at (0-65535).",
        frozenset({
            "destination_port", "dst_port", "dest_port", "dstport", "destport", "destinationport", "dport", "dpt",
            "d_port", "id_resp_p", "resp_p", "server_port", "port",
        }),
    ),
    CanonicalField(
        "protocol", "Protocol", "protocol", "Network protocol, by name (tcp) or IANA number (6).",
        frozenset({"protocol", "proto", "ip_protocol", "protocol_name", "transport", "l4_protocol"}),
    ),
    CanonicalField(
        "severity", "Reported severity", "text",
        "The source's own severity. Kept for reference only; NETRA stores imported events as INFO.",
        frozenset({
            "severity", "sev", "level", "log_level", "loglevel", "priority", "risk", "risk_level", "alert_severity",
            "severity_level",
        }),
    ),
    CanonicalField(
        "message", "Message", "text", "Free-text description. Kept with the event; never used as a detection signature.",
        frozenset({
            "message", "msg", "description", "details", "detail", "summary", "text", "log", "log_message",
            "signature", "alert", "alert_message", "rule_name", "rule", "reason",
        }),
    ),
    CanonicalField(
        "outcome", "Outcome", "text", "What happened, such as success, failure, allowed or blocked.",
        frozenset({"outcome", "result", "status", "action", "disposition", "event_outcome"}),
    ),
    CanonicalField(
        "label", "Dataset label", "text",
        "Ground-truth label of a labelled dataset. Kept for evaluation; never treated as a confirmed threat.",
        frozenset({
            "label", "labels", "class", "ground_truth", "groundtruth", "attack", "attack_cat", "attack_type",
            "attacktype", "is_attack", "malicious",
        }),
    ),
)  # fmt: skip
FIELDS_BY_NAME: dict[str, CanonicalField] = {item.name: item for item in FIELDS}
FIELD_NAMES: tuple[str, ...] = tuple(FIELDS_BY_NAME)


@dataclass(frozen=True)
class RecordType:
    name: str
    title: str
    description: str
    required: tuple[str, ...]


RECORD_TYPES: dict[str, RecordType] = {
    "security_event": RecordType(
        "security_event",
        "Security event",
        "Any timestamped security record: authentication, alert, audit, endpoint or application log rows. "
        "Network fields are optional.",
        ("occurred_at", "event_type"),
    ),
    "network_flow": RecordType(
        "network_flow",
        "Network flow",
        "Connection or flow records with source and destination addresses. Stored with event type "
        "network_flow unless an event type column is mapped.",
        ("occurred_at", "src_ip", "dest_ip"),
    ),
}

TIMESTAMP_FORMATS: dict[str, str] = {
    "iso8601": "ISO 8601 · 2024-05-01T13:45:00Z, 2024-05-01 13:45:00, 2024/05/01 13:45",
    "dmy": "Day/month/year · 01/05/2024 13:45:00",
    "mdy": "Month/day/year · 05/01/2024 1:45:00 PM",
    "rfc2822": "RFC 2822 · Wed, 01 May 2024 13:45:00 +0000",
    "epoch_seconds": "Unix seconds · 1714571100",
    "epoch_millis": "Unix milliseconds · 1714571100000",
}
# Names offered to users mapped to Python codecs. utf-8 also accepts (and drops) a byte order mark.
ENCODINGS: dict[str, str] = {"utf-8": "utf-8-sig", "utf-16": "utf-16", "cp1252": "cp1252", "iso-8859-1": "iso-8859-1"}
DELIMITERS: dict[str, str] = {",": "Comma", ";": "Semicolon", "\t": "Tab", "|": "Pipe"}
UTC_OFFSET_PATTERN = r"^[+-](?:0\d|1[0-4]):[0-5]\d$"
DEFAULT_EVENT_TYPE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 _.:/-]*$"
MAPPED_COLUMN_MAX_LENGTH = 256

EVENT_TYPE_MAX_LENGTH = 100  # security_events.event_type
SEVERITY_MAX_LENGTH = 64
SHORT_TEXT_MAX_LENGTH = 256  # outcome, label
MESSAGE_MAX_LENGTH = 4096
EARLIEST_TIMESTAMP = datetime(1970, 1, 1, tzinfo=UTC)
MAX_FUTURE = timedelta(days=1)

# Normalised spellings of the source's severity; anything else is kept as written with normalized = None.
SEVERITY_WORDS: dict[str, str] = {
    **dict.fromkeys(("critical", "crit", "fatal", "emergency", "emerg", "alert", "severe"), "critical"),
    **dict.fromkeys(("high", "error", "err", "major"), "high"),
    **dict.fromkeys(("medium", "moderate", "warning", "warn", "med"), "medium"),
    **dict.fromkeys(("low", "minor", "notice"), "low"),
    **dict.fromkeys(("info", "informational", "information", "debug", "none", "trace"), "info"),
}
PROTOCOL_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "ipv6-icmp", "132": "sctp"}
_PROTOCOL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,15}")
_PORT = re.compile(r"(\d{1,5})(?:\.0+)?")
_PROTOCOL_NUMBER = re.compile(r"\d{1,3}")

# --- Formula injection -----------------------------------------------------------------------------

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_PLAIN_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")


def is_formula_like(value: str) -> bool:
    """True when a spreadsheet would treat the cell as a formula (OWASP CSV injection prefixes).

    Plain signed numbers such as ``-5`` or ``+1.5`` are not formulas.
    """
    return value.startswith(_FORMULA_PREFIXES) and not _PLAIN_NUMBER.fullmatch(value)


def formula_safe(value: str) -> str:
    """Prefix a formula-like value with an apostrophe so spreadsheets show it as text."""
    return f"'{value}" if is_formula_like(value) else value


# --- Timestamps ------------------------------------------------------------------------------------

_ZONE = r"(Z|z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)"
_ISO = re.compile(
    r"(\d{4})([-/])(\d{1,2})\2(\d{1,2})"
    r"(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?"
    rf"\s*{_ZONE}?"
)
_DAY_MONTH = re.compile(
    r"(\d{1,2})([/.-])(\d{1,2})\2(\d{4})"
    r"(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*([AaPp][Mm])?)?"
    rf"\s*{_ZONE}?"
)
# Wide enough that a millisecond value read as seconds fails the range check, which says so, not the format.
_EPOCH_SECONDS = re.compile(r"\d{1,14}(?:\.\d{1,9})?")
_EPOCH_MILLIS = re.compile(r"\d{1,14}")


class TimestampError(ValueError):
    def __init__(self, rule: str, message: str) -> None:
        super().__init__(message)
        self.rule = rule
        self.message = message


@dataclass(frozen=True)
class ParsedTimestamp:
    value: datetime
    # False when the value carried no zone and the mapping's offset was applied.
    had_zone: bool


def parse_utc_offset(text: str) -> timezone:
    if not re.fullmatch(UTC_OFFSET_PATTERN, text):
        raise ValueError("UTC offset must look like +05:30 or -03:00")
    sign = 1 if text[0] == "+" else -1
    return timezone(sign * timedelta(hours=int(text[1:3]), minutes=int(text[4:6])))


def _zone(text: str | None) -> timezone | None:
    if not text:
        return None
    if text.upper() in ("Z", "UTC", "GMT"):
        return UTC
    digits = text[1:].replace(":", "")
    hours, minutes = int(digits[:2]), int(digits[2:] or 0)
    if hours > 14 or minutes > 59:
        raise TimestampError("row.invalid_timestamp", "has an invalid time zone offset")
    sign = 1 if text[0] == "+" else -1
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _microseconds(fraction: str | None) -> int:
    return int((fraction or "0")[:6].ljust(6, "0"))


def _build(
    year: int, month: int, day: int, hour: int, minute: int, second: int, micro: int, zone: timezone | None,
    default_zone: timezone,
) -> ParsedTimestamp:
    try:
        value = datetime(year, month, day, hour, minute, second, micro, tzinfo=zone or default_zone)
    except ValueError:
        raise TimestampError("row.invalid_timestamp", "is not a valid calendar date and time") from None
    return ParsedTimestamp(value, zone is not None)


def _parse_iso(value: str, default_zone: timezone) -> ParsedTimestamp:
    match = _ISO.fullmatch(value)
    if match is None:
        raise TimestampError("row.invalid_timestamp", "does not match the chosen format (ISO 8601)")
    year, _, month, day, hour, minute, second, fraction, zone = match.groups()
    return _build(
        int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0),
        _microseconds(fraction), _zone(zone), default_zone,
    )  # fmt: skip


def _parse_day_month(value: str, default_zone: timezone, *, day_first: bool) -> ParsedTimestamp:
    match = _DAY_MONTH.fullmatch(value)
    if match is None:
        label = "day/month/year" if day_first else "month/day/year"
        raise TimestampError("row.invalid_timestamp", f"does not match the chosen format ({label})")
    first, _, second_part, year, hour, minute, second, fraction, meridiem, zone = match.groups()
    day, month = (first, second_part) if day_first else (second_part, first)
    hour_value = int(hour or 0)
    if meridiem:
        if not 1 <= hour_value <= 12:
            raise TimestampError("row.invalid_timestamp", "has an hour outside 1-12 with AM/PM")
        hour_value = hour_value % 12 + (12 if meridiem.lower() == "pm" else 0)
    return _build(
        int(year), int(month), int(day), hour_value, int(minute or 0), int(second or 0),
        _microseconds(fraction), _zone(zone), default_zone,
    )  # fmt: skip


def _parse_epoch(value: str, *, millis: bool) -> ParsedTimestamp:
    pattern = _EPOCH_MILLIS if millis else _EPOCH_SECONDS
    if not pattern.fullmatch(value):
        unit = "milliseconds" if millis else "seconds"
        raise TimestampError("row.invalid_timestamp", f"must be a whole number of Unix {unit}")
    seconds = int(value) / 1000 if millis else float(value)
    try:
        return ParsedTimestamp(datetime.fromtimestamp(seconds, UTC), True)
    except (OverflowError, OSError, ValueError):
        raise TimestampError("row.timestamp_out_of_range", "is outside the supported date range") from None


def _parse_rfc2822(value: str) -> ParsedTimestamp:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        raise TimestampError("row.invalid_timestamp", "does not match the chosen format (RFC 2822)") from None
    if parsed.tzinfo is None:
        # RFC 2822 requires a zone; "-0000" means "unknown" and parses naive.
        raise TimestampError("row.invalid_timestamp", "has no time zone (RFC 2822 requires one)")
    return ParsedTimestamp(parsed, True)


def parse_timestamp(value: str, fmt: str, default_zone: timezone, now: datetime | None = None) -> ParsedTimestamp:
    """Parse ``value`` (already stripped) under ``fmt``; raise TimestampError naming the rule that failed."""
    if fmt == "iso8601":
        parsed = _parse_iso(value, default_zone)
    elif fmt in ("dmy", "mdy"):
        parsed = _parse_day_month(value, default_zone, day_first=fmt == "dmy")
    elif fmt == "rfc2822":
        parsed = _parse_rfc2822(value)
    elif fmt in ("epoch_seconds", "epoch_millis"):
        parsed = _parse_epoch(value, millis=fmt == "epoch_millis")
    else:
        raise ValueError(f"unknown timestamp format {fmt!r}")
    latest = (now or datetime.now(UTC)) + MAX_FUTURE
    if not EARLIEST_TIMESTAMP <= parsed.value <= latest:
        raise TimestampError("row.timestamp_out_of_range", "must be between 1970-01-01 and one day from now")
    return parsed


# --- Values ----------------------------------------------------------------------------------------


def valid_ip(value: str) -> bool:
    # Zone indices (fe80::1%eth0) parse in Python but are not valid PostgreSQL INET values.
    if "%" in value:
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def parse_port(value: str) -> int | None:
    """0-65535 written as an integer; ``443.0`` (common in pandas exports) is accepted as 443."""
    match = _PORT.fullmatch(value)
    if match is None or int(match.group(1)) > 65535:
        return None
    return int(match.group(1))


def parse_protocol(value: str) -> str | None:
    if _PROTOCOL_NUMBER.fullmatch(value):
        return PROTOCOL_NUMBERS.get(str(int(value)), str(int(value))) if int(value) <= 255 else None
    if _PROTOCOL_NAME.fullmatch(value):
        return value.lower()
    return None


def _has_control(value: str, allowed: str = "") -> bool:
    return any(unicodedata.category(character) == "Cc" and character not in allowed for character in value)


def source_keys(header: Sequence[str]) -> list[str]:
    """Header names as written (trimmed), made unique: blank names become ``column N``, repeats get `` (2)``."""
    keys: list[str] = []
    seen: set[str] = set()
    for position, name in enumerate(header, start=1):
        base = name.strip() or f"column {position}"
        key, count = base, 1
        while key in seen:
            count += 1
            key = f"{base} ({count})"
        seen.add(key)
        keys.append(key)
    return keys


@dataclass
class _Interpretation:
    occurred_at: datetime | None = None
    had_zone: bool = True
    event_type: str | None = None
    event_type_from_default: bool = False
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    text: dict[str, str] = field(default_factory=dict)
    neutralized: list[str] = field(default_factory=list)


class SecurityCsvProfile(DatasetProfile):
    """A CSV whose columns are mapped to canonical event fields by a user-confirmed ``FieldMapping``.

    One instance per upload: the header seen by ``column_positions`` decides where each field is read.
    """

    identifier = SECURITY_CSV_PROFILE
    version = "1"
    title = "Security CSV (mapped fields)"
    normalizes = True
    skip_blank_records = True

    def __init__(self, mapping: "FieldMapping") -> None:
        self.mapping = mapping
        self.encoding = ENCODINGS[mapping.encoding]
        self.delimiter = mapping.delimiter
        # UTF-16 text is full of NUL bytes; decoded NUL characters are rejected per row instead.
        self.rejects_nul_bytes = mapping.encoding != "utf-16"
        self.record_type = RECORD_TYPES[mapping.record_type]
        self.default_zone = parse_utc_offset(mapping.utc_offset)
        self._keys: tuple[str, ...] = ()
        # canonical field -> (source key, 1-based column position)
        self._fields: dict[str, tuple[str, int]] = {}

    def check_header(self, header: Sequence[str]) -> list[ValidationIssue]:
        if len(header) > MAX_COLUMNS:
            return [ValidationIssue("header.too_many_columns", f"header has more than {MAX_COLUMNS} columns", row=1)]
        names = [self.normalize_column(name) for name in header]
        counts = Counter(names)
        issues: list[ValidationIssue] = []
        for name, column in self.mapping.fields.items():
            wanted = self.normalize_column(column)
            if counts[wanted] == 0:
                issues.append(
                    ValidationIssue("header.missing_column", "mapped column is not in the header", row=1, column=name)
                )
            elif counts[wanted] > 1:
                issues.append(
                    ValidationIssue(
                        "header.ambiguous_column",
                        "mapped column name appears more than once in the header",
                        row=1,
                        column=name,
                        column_index=names.index(wanted) + 1,
                    )
                )
        return issues

    def column_positions(self, header: Sequence[str]) -> dict[str, int]:
        keys = source_keys(header)
        names = [self.normalize_column(name) for name in header]
        self._keys = tuple(keys)
        self._fields = {}
        for name, column in self.mapping.fields.items():
            index = names.index(self.normalize_column(column))
            self._fields[name] = (keys[index], index + 1)
        return {key: index for index, key in enumerate(keys)}

    def _value(self, values: Mapping[str, str], name: str) -> str:
        located = self._fields.get(name)
        return values[located[0]].strip() if located else ""

    def _issue(self, name: str, rule: str, message: str) -> ValidationIssue:
        located = self._fields.get(name)
        return ValidationIssue(rule, message, column=name, column_index=located[1] if located else None)

    def _interpret(self, values: Mapping[str, str]) -> tuple[_Interpretation, list[ValidationIssue]]:
        result = _Interpretation()
        issues: list[ValidationIssue] = []
        if any("\x00" in cell for cell in values.values()):
            return result, [ValidationIssue("row.binary_content", "record contains NUL characters")]

        required = set(self.record_type.required)
        if "event_type" in required and "event_type" not in self.mapping.fields:
            required.discard("event_type")  # satisfied by default_event_type (checked by the mapping schema)
        for name in self.record_type.required:
            if name in required and not self._value(values, name):
                issues.append(self._issue(name, "row.missing_value", "required value is missing"))

        written = self._value(values, "occurred_at")
        if written:
            try:
                parsed = parse_timestamp(written, self.mapping.timestamp_format, self.default_zone)
            except TimestampError as error:
                issues.append(self._issue("occurred_at", error.rule, error.message))
            else:
                result.occurred_at, result.had_zone = parsed.value, parsed.had_zone

        event_type = self._value(values, "event_type")
        if event_type:
            if _has_control(event_type):
                issues.append(self._issue("event_type", "row.invalid_text", "contains control characters"))
            elif len(event_type) > EVENT_TYPE_MAX_LENGTH:
                issues.append(
                    self._issue("event_type", "row.value_too_long", f"is longer than {EVENT_TYPE_MAX_LENGTH} characters")
                )
            elif is_formula_like(event_type):
                # Stored as text a spreadsheet will not evaluate; the original stays in sourceFields.
                result.event_type = formula_safe(event_type)[:EVENT_TYPE_MAX_LENGTH]
                result.neutralized.append("event_type")
            else:
                result.event_type = event_type
        elif "event_type" not in self.mapping.fields:
            result.event_type = self.mapping.default_event_type or self.record_type.name
            result.event_type_from_default = True
        elif self.record_type.name == "network_flow":
            result.event_type = "network_flow"
            result.event_type_from_default = True

        for name in ("src_ip", "dest_ip"):
            address = self._value(values, name)
            if address:
                if valid_ip(address):
                    setattr(result, name, address)
                else:
                    issues.append(self._issue(name, "row.invalid_ip", "must be an IPv4 or IPv6 address"))
        for name in ("src_port", "dest_port"):
            port = self._value(values, name)
            if port:
                number = parse_port(port)
                if number is None:
                    issues.append(self._issue(name, "row.invalid_port", "must be an integer from 0 to 65535"))
                else:
                    setattr(result, name, number)
        protocol = self._value(values, "protocol")
        if protocol:
            result.protocol = parse_protocol(protocol)
            if result.protocol is None:
                issues.append(
                    self._issue("protocol", "row.invalid_protocol", "must be a protocol number (0-255) or a short name")
                )

        limits = {
            "severity": SEVERITY_MAX_LENGTH,
            "outcome": SHORT_TEXT_MAX_LENGTH,
            "label": SHORT_TEXT_MAX_LENGTH,
            "message": MESSAGE_MAX_LENGTH,
        }
        for name, limit in limits.items():
            text = self._value(values, name)
            if not text:
                continue
            if _has_control(text, allowed="\t\n\r" if name == "message" else ""):
                issues.append(self._issue(name, "row.invalid_text", "contains control characters"))
            elif len(text) > limit:
                issues.append(self._issue(name, "row.value_too_long", f"is longer than {limit} characters"))
            else:
                result.text[name] = text
        return result, issues

    def check_row(self, values: Mapping[str, str]) -> list[ValidationIssue]:
        return self._interpret(values)[1]

    def normalize_row(self, values: Mapping[str, str]) -> NormalizedEvent:
        result, issues = self._interpret(values)
        if issues or result.occurred_at is None or result.event_type is None:
            raise ValueError("row was not validated")
        mapping = self.mapping
        source_fields = {key: values[key] for key in self._keys}
        mapped_keys = {key for key, _ in self._fields.values()}
        # Order-independent: the same cells under the same column names hash alike in any column order.
        content = json.dumps(sorted(source_fields.items()), ensure_ascii=False, separators=(",", ":"))
        zone_reading = (
            "zone as written"
            if result.had_zone
            else f"no zone in the value; read as UTC{mapping.utc_offset}, the offset chosen at import"
        )
        raw: dict[str, Any] = {
            "dataset": {
                "profile": self.identifier,
                "profileVersion": self.version,
                "recordType": mapping.record_type,
                "fieldMapping": dict(mapping.fields),
                "timestampFormat": mapping.timestamp_format,
                "utcOffset": mapping.utc_offset,
                "encoding": mapping.encoding,
                "delimiter": mapping.delimiter,
                **({"defaultEventType": mapping.default_event_type} if mapping.default_event_type else {}),
            },
            "timestampAsWritten": self._value(values, "occurred_at"),
            "occurredAtInterpretation": f"{mapping.timestamp_format}; {zone_reading}",
            "eventTypeSource": "default" if result.event_type_from_default else "column",
            # Every column as written, keyed by its header name (blank or repeated names made unique).
            "sourceFields": source_fields,
            "unmappedColumns": [key for key in self._keys if key not in mapped_keys],
        }
        text = result.text
        if "message" in text:
            raw["message"] = text["message"]
        if "outcome" in text:
            raw["outcome"] = text["outcome"]
        if "label" in text:
            # The dataset's own label: ground truth for evaluation, never a NETRA detection.
            raw["groundTruthLabel"] = text["label"]
        if "severity" in text:
            # The source's claim; NETRA's severity for the event stays INFO.
            raw["reportedSeverity"] = {
                "asWritten": text["severity"],
                "normalized": SEVERITY_WORDS.get(text["severity"].casefold()),
            }
        if result.protocol is not None:
            raw["protocolAsWritten"] = self._value(values, "protocol")
        if result.neutralized:
            raw["formulaNeutralized"] = result.neutralized
        return NormalizedEvent(
            occurred_at=result.occurred_at,
            event_type=result.event_type,
            src_ip=result.src_ip,
            dest_ip=result.dest_ip,
            src_port=result.src_port,
            dest_port=result.dest_port,
            protocol=result.protocol,
            content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            raw_data=raw,
        )
