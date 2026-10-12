"""Dataset profiles: the header contract and row rules an uploaded CSV is validated against.

Issues name a row, a column and the rule that failed, never cell contents: uploads are untrusted
and may hold sensitive data. A column is named only when the name comes from the profile itself;
columns found in the file are identified by position.

Name-based profiles (``DatasetProfile``) look columns up by name and reject repeated names.
Positional profiles (``PositionalProfile``) require an exact header, column by column, and give
every position its own key, so a repeated name is kept twice rather than merged or dropped.
"""

import hashlib
import re
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any, ClassVar

PROFILE_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
MAX_COLUMNS = 512


@dataclass(frozen=True)
class ValidationIssue:
    rule: str
    message: str
    # Record number with the header counted as row 1, so data starts at row 2 (as in a spreadsheet).
    row: int | None = None
    # A column name defined by the profile, never text read from the file.
    column: str | None = None
    # 1-based position of the column in the uploaded file.
    column_index: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "message": self.message,
            "row": self.row,
            "column": self.column,
            "columnIndex": self.column_index,
        }


class DatasetProfile:
    """Base profile: structural header checks plus the profile's required columns.

    Subclasses set the class attributes and may override ``check_row``. Bump ``version`` whenever
    the rules change, so a file validated under older rules can be validated again.
    """

    identifier: ClassVar[str]
    version: ClassVar[str]
    title: ClassVar[str]
    encoding: ClassVar[str] = "utf-8-sig"
    required_columns: ClassVar[tuple[str, ...]] = ()
    # True when normalize_row maps accepted rows to events; otherwise uploads are validation-only.
    normalizes: ClassVar[bool] = False

    @staticmethod
    def normalize_column(name: str) -> str:
        return name.strip().casefold()

    def check_header(self, header: Sequence[str]) -> list[ValidationIssue]:
        """Return header issues; any issue rejects the whole file before rows are read."""
        if len(header) > MAX_COLUMNS:
            return [ValidationIssue("header.too_many_columns", f"header has more than {MAX_COLUMNS} columns", row=1)]
        issues: list[ValidationIssue] = []
        seen: set[str] = set()
        for position, name in enumerate(header, start=1):
            normalized = self.normalize_column(name)
            if not normalized:
                issues.append(ValidationIssue("header.empty_column", "column has no name", row=1, column_index=position))
            elif normalized in seen:
                issues.append(
                    ValidationIssue("header.duplicate_column", "column name is repeated", row=1, column_index=position)
                )
            seen.add(normalized)
        for required in self.required_columns:
            if self.normalize_column(required) not in seen:
                issues.append(
                    ValidationIssue("header.missing_column", "required column is missing", row=1, column=required)
                )
        return issues

    def column_positions(self, header: Sequence[str]) -> dict[str, int]:
        """Where each value passed to ``check_row`` is read from, keyed as ``check_row`` expects.

        Called only after ``check_header`` found no issues.
        """
        positions = {self.normalize_column(name): index for index, name in enumerate(header)}
        return {name: positions[self.normalize_column(name)] for name in self.required_columns}

    def check_row(self, values: Mapping[str, str]) -> list[ValidationIssue]:
        """Validate one row. ``values`` holds the columns from ``column_positions``.

        Returned issues omit the row number; the caller adds it.
        """
        return []

    def describe_record(self, values: Mapping[str, str]) -> Iterator[tuple[str, str]]:
        """(fact, value) pairs the local profiler tallies, for checking a profile's assumptions."""
        return iter(())

    def normalize_row(self, values: Mapping[str, str]) -> "NormalizedEvent | None":
        """Event fields for one row that passed ``check_row``; None keeps the profile validation-only."""
        return None


@dataclass(frozen=True)
class NormalizedEvent:
    """A dataset row mapped to NETRA's canonical event fields. Severity is not derived from the row."""

    occurred_at: datetime
    event_type: str
    src_ip: str | None
    dest_ip: str | None
    src_port: int | None
    dest_port: int | None
    protocol: str | None
    # Hash of the row's cells as written: identical rows (in one file or across uploads) share it.
    content_sha256: str
    # Source fields as written, the dataset's own label (ground truth, not a NETRA finding) and how
    # each derived field was interpreted.
    raw_data: dict[str, Any]


class GenericCsvProfile(DatasetProfile):
    """Structure only: a usable header and a consistent number of fields. No dataset semantics."""

    identifier = "generic-csv"
    version = "1"
    title = "Generic CSV (structure only)"


def column_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")


class PositionalProfile(DatasetProfile):
    """The header must equal ``columns`` exactly, position by position, after trimming whitespace.

    A name may repeat only where ``columns`` repeats it. Each position gets its own key (a repeat
    gets a ``_2`` suffix), so every column reaches ``check_row`` and none is merged or dropped.
    """

    columns: ClassVar[tuple[str, ...]]

    def __init__(self) -> None:
        keys: list[str] = []
        seen: Counter[str] = Counter()
        for name in self.columns:
            base = column_key(name)
            seen[base] += 1
            keys.append(base if seen[base] == 1 else f"{base}_{seen[base]}")
        self.keys: tuple[str, ...] = tuple(keys)

    def check_header(self, header: Sequence[str]) -> list[ValidationIssue]:
        if len(header) > MAX_COLUMNS:
            return [ValidationIssue("header.too_many_columns", f"header has more than {MAX_COLUMNS} columns", row=1)]
        if len(header) != len(self.columns):
            return [
                ValidationIssue(
                    "header.column_count",
                    f"header has {len(header)} columns; the profile expects {len(self.columns)}",
                    row=1,
                )
            ]
        return [
            ValidationIssue(
                "header.unexpected_column",
                "column does not match the profile at this position",
                row=1,
                column=expected,
                column_index=position,
            )
            for position, (name, expected) in enumerate(zip(header, self.columns), start=1)
            if name.strip() != expected
        ]

    def column_positions(self, header: Sequence[str]) -> dict[str, int]:
        return {key: index for index, key in enumerate(self.keys)}


# --- CIC-IDS2017 (GeneratedLabelledFlows / TrafficLabelling CSVs) ----------------------------------

CIC_IDS2017_COLUMNS: tuple[str, ...] = (
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label",
)  # fmt: skip

# 0-based positions. "Fwd Header Length" appears at 40 and 61 (columns 41 and 62).
FLOW_ID, SOURCE_IP, SOURCE_PORT, DESTINATION_IP, DESTINATION_PORT, PROTOCOL, TIMESTAMP = range(7)
FWD_HEADER_LENGTH, FWD_HEADER_LENGTH_2, LABEL = 40, 61, 84
NUMERIC_POSITIONS = range(7, 84)

_EN_DASH = "–"  # byte 0x96 in Windows-1252
# Labels seen in the audit's sampled rows.
CIC_IDS2017_OBSERVED_LABELS = frozenset({
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "PortScan", "SSH-Patator", f"Web Attack {_EN_DASH} Brute Force",
})  # fmt: skip
# Labels named in public CIC-IDS2017 documentation but not seen in the audit's samples; their exact
# spelling in these files is an assumption until the local profiler reports it.
CIC_IDS2017_DOCUMENTED_LABELS = frozenset({
    "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration",
    f"Web Attack {_EN_DASH} Sql Injection", f"Web Attack {_EN_DASH} XSS",
})  # fmt: skip
CIC_IDS2017_LABELS = CIC_IDS2017_OBSERVED_LABELS | CIC_IDS2017_DOCUMENTED_LABELS

# Two shapes were seen: "7/7/2017 3:30" and (Monday) "03/07/2017 08:55:58". Dates read as
# day/month/year match each file's weekday name for 3-7 July 2017.
_TIMESTAMP = re.compile(r"(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?")
CAPTURE_FIRST_DAY = date(2017, 7, 3)
CAPTURE_LAST_DAY = date(2017, 7, 7)
# The files appear to use a 12-hour clock without AM/PM: morning files show 8-12, afternoon files 1-5.
# Any other hour would contradict that reading, so it is rejected rather than interpreted.
# Validation never converts timestamps; the time zone is not recorded in the files.
CIC_IDS2017_ACCEPTED_HOURS = frozenset({1, 2, 3, 4, 5, 8, 9, 10, 11, 12})
# Normalisation only: occurred_at needs a 24-hour, zoned instant, which the files do not state.
# Both readings below are ASSUMPTIONS (see docs/DATASET_IMPORTS.md), recorded on every imported
# event so a later correction can find and re-derive them:
# - 12-hour clock without AM/PM: hours 8-11 are morning, 12 is noon, 1-5 are afternoon (13-17).
# - Capture-local time is UTC-03:00 (Atlantic Daylight Time; the capture is publicly described as
#   taking place in New Brunswick, Canada). Not verified against the files.
CIC_IDS2017_ASSUMED_UTC_OFFSET = timezone(timedelta(hours=-3))
CIC_IDS2017_TIME_INTERPRETATION = (
    "cic-ids2017 timestamp read as day/month/year on a 12-hour clock without AM/PM (8-11 morning, 12 noon, "
    "1-5 afternoon) in assumed capture-local time UTC-03:00; both readings are unverified assumptions"
)
CIC_IDS2017_PROTOCOLS = {"6": "tcp", "17": "udp"}
_NUMBER = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
# Recorded by the dataset's flow meter; kept as written, never converted to zero or dropped.
NON_FINITE_VALUES = frozenset({"Infinity", "-Infinity", "NaN"})
_DIGITS = re.compile(r"\d{1,5}")


class CicIds2017Profile(PositionalProfile):
    """CIC-IDS2017 labelled flow CSVs (85 columns). Accepted rows of a validated upload are normalised
    to ``network_flow`` events (``normalize_row``); the Label is kept as ground truth, never as a finding.

    Flow ID and the Source/Destination columns are checked for consistency only. Flow ID lists the
    endpoints in either order, so neither it nor the column names establish connection direction,
    and Flow ID is not unique: rows are identified by their row number.
    """

    identifier = "cic-ids2017"
    version = "1"
    title = "CIC-IDS2017 labelled flows"
    # ASCII apart from byte 0x96 (en dash) in web-attack labels. Bytes undefined in Windows-1252
    # still fail decoding, so the file is rejected rather than guessed at.
    encoding = "cp1252"
    columns = CIC_IDS2017_COLUMNS
    normalizes = True

    def _issue(self, position: int, rule: str, message: str) -> ValidationIssue:
        return ValidationIssue(rule, message, column=self.columns[position], column_index=position + 1)

    def _cells(self, values: Mapping[str, str]) -> list[str]:
        return [values[key] for key in self.keys]

    def check_row(self, values: Mapping[str, str]) -> list[ValidationIssue]:
        cells = self._cells(values)
        if not any(cell.strip() for cell in cells):
            return [ValidationIssue("row.empty_record", "record has no values")]

        issues: list[ValidationIssue] = []
        present = [bool(cell.strip()) for cell in cells]
        for position, has_value in enumerate(present):
            if not has_value:
                issues.append(self._issue(position, "row.missing_value", "value is missing"))

        for position in (SOURCE_IP, DESTINATION_IP):
            if present[position] and not _is_ip(cells[position]):
                issues.append(self._issue(position, "row.invalid_ip", "must be an IPv4 or IPv6 address"))
        for position in (SOURCE_PORT, DESTINATION_PORT):
            if present[position] and not _in_range(cells[position], 65535):
                issues.append(self._issue(position, "row.invalid_port", "must be an integer from 0 to 65535"))
        if present[PROTOCOL] and not _in_range(cells[PROTOCOL], 255):
            issues.append(self._issue(PROTOCOL, "row.invalid_protocol", "must be an integer from 0 to 255"))
        if present[TIMESTAMP]:
            problem = _timestamp_problem(cells[TIMESTAMP])
            if problem is not None:
                issues.append(self._issue(TIMESTAMP, *problem))
        if present[LABEL] and cells[LABEL] not in CIC_IDS2017_LABELS:
            issues.append(self._issue(LABEL, "row.unknown_label", "is not a known CIC-IDS2017 label"))
        for position in NUMERIC_POSITIONS:
            cell = cells[position]
            if present[position] and cell not in NON_FINITE_VALUES and not _NUMBER.fullmatch(cell):
                issues.append(self._issue(position, "row.invalid_number", "must be a number, Infinity, -Infinity or NaN"))
        if present[FWD_HEADER_LENGTH] and present[FWD_HEADER_LENGTH_2] and cells[FWD_HEADER_LENGTH] != cells[FWD_HEADER_LENGTH_2]:
            issues.append(
                self._issue(FWD_HEADER_LENGTH_2, "row.duplicate_column_mismatch", "differs from Fwd Header Length (column 41)")
            )
        if present[FLOW_ID]:
            problem = _flow_id_problem(cells)
            if problem is not None:
                issues.append(self._issue(FLOW_ID, *problem))
        return issues

    def describe_record(self, values: Mapping[str, str]) -> Iterator[tuple[str, str]]:
        cells = self._cells(values)
        if not any(cell.strip() for cell in cells):
            return
        label = cells[LABEL]
        yield ("label", label if label in CIC_IDS2017_LABELS else f"[unknown] {label}")
        timestamp = cells[TIMESTAMP]
        yield ("timestamp shape", re.sub(r"\d", "9", timestamp))
        match = _TIMESTAMP.fullmatch(timestamp)
        if match:
            day, month, year, hour = (int(part) for part in match.group(1, 2, 3, 4))
            yield ("timestamp hour (as written)", f"{hour:02d}")
            try:
                yield ("timestamp date (day/month/year)", date(year, month, day).isoformat())
            except ValueError:
                yield ("timestamp date (day/month/year)", "[invalid date]")
        yield ("protocol", cells[PROTOCOL])
        yield ("flow id order", _flow_id_order(cells))
        yield (
            "fwd header length columns",
            "equal" if cells[FWD_HEADER_LENGTH] == cells[FWD_HEADER_LENGTH_2] else "differ",
        )
        for position in NUMERIC_POSITIONS:
            cell = cells[position]
            if cell in NON_FINITE_VALUES:
                yield ("non-finite values", f"{self.columns[position]} = {cell}")
            elif cell.startswith("-") and _NUMBER.fullmatch(cell) and float(cell) != 0:
                yield ("negative values", self.columns[position])

    def normalize_row(self, values: Mapping[str, str]) -> NormalizedEvent:
        """One flow as a ``network_flow`` event. The Label is kept as ground truth and never sets severity."""
        cells = self._cells(values)
        protocol = cells[PROTOCOL]
        return NormalizedEvent(
            occurred_at=cic_ids2017_occurred_at(cells[TIMESTAMP]),
            event_type="network_flow",
            src_ip=cells[SOURCE_IP],
            dest_ip=cells[DESTINATION_IP],
            src_port=int(cells[SOURCE_PORT]),
            dest_port=int(cells[DESTINATION_PORT]),
            protocol=CIC_IDS2017_PROTOCOLS.get(protocol, protocol),
            content_sha256=hashlib.sha256("\x1f".join(cells).encode("utf-8")).hexdigest(),
            raw_data={
                "dataset": {"profile": self.identifier, "profileVersion": self.version},
                # The dataset's own label: evaluation ground truth, not a detection made by NETRA.
                "groundTruthLabel": cells[LABEL],
                "timestampAsWritten": cells[TIMESTAMP],
                "occurredAtInterpretation": CIC_IDS2017_TIME_INTERPRETATION,
                "protocolAsWritten": protocol,
                # Every column as written, keyed by profile key (the repeated column is fwd_header_length_2).
                "sourceFields": dict(zip(self.keys, cells, strict=True)),
            },
        )


def cic_ids2017_occurred_at(value: str) -> datetime:
    """A validated CIC-IDS2017 timestamp as an aware datetime under the assumptions documented above."""
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("timestamp was not validated")
    day, month, year, hour, minute = (int(part) for part in match.group(1, 2, 3, 4, 5))
    second = int(match.group(6) or 0)
    if hour not in CIC_IDS2017_ACCEPTED_HOURS:
        raise ValueError("timestamp was not validated")
    hour_24 = hour + 12 if hour <= 5 else hour
    return datetime(year, month, day, hour_24, minute, second, tzinfo=CIC_IDS2017_ASSUMED_UTC_OFFSET)


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _in_range(value: str, maximum: int) -> bool:
    return bool(_DIGITS.fullmatch(value)) and int(value) <= maximum


def _timestamp_problem(value: str) -> tuple[str, str] | None:
    match = _TIMESTAMP.fullmatch(value)
    if not match:
        return ("row.invalid_timestamp", "must be D/M/YYYY H:MM or DD/MM/YYYY HH:MM:SS")
    day, month, year, hour, minute = (int(part) for part in match.group(1, 2, 3, 4, 5))
    second = int(match.group(6) or 0)
    try:
        written = date(year, month, day)
    except ValueError:
        return ("row.invalid_timestamp", "is not a valid day/month/year date")
    if minute > 59 or second > 59:
        return ("row.invalid_timestamp", "has an invalid minute or second")
    if not CAPTURE_FIRST_DAY <= written <= CAPTURE_LAST_DAY:
        return ("row.timestamp_out_of_range", "date is outside 3-7 July 2017 (read as day/month/year)")
    if hour not in CIC_IDS2017_ACCEPTED_HOURS:
        return ("row.timestamp_hour_unverified", "hour is outside the 12-hour reading the profile relies on (1-5, 8-12)")
    return None


def _flow_id_order(cells: Sequence[str]) -> str:
    parts = tuple(cells[FLOW_ID].split("-"))
    source = cells[SOURCE_IP], cells[DESTINATION_IP], cells[SOURCE_PORT], cells[DESTINATION_PORT], cells[PROTOCOL]
    reverse = cells[DESTINATION_IP], cells[SOURCE_IP], cells[DESTINATION_PORT], cells[SOURCE_PORT], cells[PROTOCOL]
    if parts == source:
        return "source columns first"
    if parts == reverse:
        return "destination columns first"
    return "matches neither order"


def _flow_id_problem(cells: Sequence[str]) -> tuple[str, str] | None:
    if len(cells[FLOW_ID].split("-")) != 5:
        return ("row.invalid_flow_id", "must have five parts: two addresses, two ports and a protocol")
    if _flow_id_order(cells) == "matches neither order":
        return ("row.flow_id_mismatch", "does not match this row's addresses, ports and protocol in either order")
    return None


PROFILES: dict[str, DatasetProfile] = {
    profile.identifier: profile for profile in (GenericCsvProfile(), CicIds2017Profile())
}


def get_profile(identifier: str) -> DatasetProfile | None:
    return PROFILES.get(identifier)
