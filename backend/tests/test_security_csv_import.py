"""Security CSV (profile ``security-csv``): preview, field mapping, validation and normalisation.

Unit tests need no database. API tests use a PostgreSQL schema per test, always rolled back. All
rows are synthetic and use documentation addresses (RFC 5737 / RFC 3849).
"""

import hashlib
import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.core.config import get_settings
from app.models import ImportBatch, Incident, SecurityAssessment, SecurityEvent
from app.models.enums import DetectionSource, Severity
from app.schemas.imports import FieldMapping
from app.services.csv_preview import PreviewError, build_preview, detect_delimiter, detect_encoding
from app.services.dataset_import import FileDigest, import_user_limiter, preview_user_limiter, validate_upload
from app.services.dataset_normalization import accepted_rows
from app.services.security_csv import (
    SecurityCsvProfile,
    TimestampError,
    formula_safe,
    is_formula_like,
    parse_timestamp,
)
from tests.conftest import CoreApi
from tests.test_cic_ids2017_profile import csv_bytes, row
from tests.test_dataset_normalization import add_asset

IMPORTS = "/api/imports"
PREVIEW = "/api/imports/preview"
SECRET = "SECRET-CELL-5c1d"
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)

AUTH_CSV = (
    "Event Time,User,Source IP,Action,Severity,Event Type,Message,Label\n"
    "2024-05-01T10:00:00Z,alice,203.0.113.5,failure,High,login_failure,bad password,brute-force\n"
    "2024-05-01T10:00:00Z,alice,203.0.113.5,failure,High,login_failure,bad password,brute-force\n"
    "2024-05-01T10:02:00Z,bob,198.51.100.7,success,info,login_success,ok,benign\n"
).encode()
AUTH_MAPPING: dict[str, Any] = {
    "recordType": "security_event",
    "timestampFormat": "iso8601",
    "fields": {
        "occurred_at": "Event Time",
        "src_ip": "Source IP",
        "outcome": "Action",
        "severity": "Severity",
        "event_type": "Event Type",
        "message": "Message",
        "label": "Label",
    },
}
FLOW_CSV = (
    "ts;src;dst;sport;dst_port;proto\n"
    "1714557600;192.0.2.10;198.51.100.20;51515;443;6\n"
    "1714557601;192.0.2.10;198.51.100.21;51516;53;17\n"
).encode()
FLOW_MAPPING: dict[str, Any] = {
    "recordType": "network_flow",
    "timestampFormat": "epoch_seconds",
    "delimiter": ";",
    "fields": {
        "occurred_at": "ts",
        "src_ip": "src",
        "dest_ip": "dst",
        "src_port": "sport",
        "dest_port": "dst_port",
        "protocol": "proto",
    },
}


@pytest.fixture(autouse=True)
def clear_rate_limits() -> Iterator[None]:
    import_user_limiter.clear()
    preview_user_limiter.clear()
    yield
    import_user_limiter.clear()
    preview_user_limiter.clear()


def mapping(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    return {**base, **changes}


def profile_for(spec: dict[str, Any]) -> SecurityCsvProfile:
    return SecurityCsvProfile(FieldMapping.model_validate(spec))


def validate(content: bytes, spec: dict[str, Any]) -> Any:
    digest = FileDigest(sha256="0" * 64, size_bytes=len(content), contains_nul=b"\x00" in content)
    return validate_upload(io.BytesIO(content), profile_for(spec), digest, max_rows=1000)


def events_for(content: bytes, spec: dict[str, Any]) -> list[Any]:
    profile = profile_for(spec)
    return [profile.normalize_row(values) for _, values in accepted_rows(io.BytesIO(content), profile)]


def preview(content: bytes, **kwargs: Any) -> Any:
    return build_preview(io.BytesIO(content), now=NOW, **kwargs)


def by_field(result: Any) -> dict[str, Any]:
    return {item.field: item for item in result.suggestions}


# --- Timestamps --------------------------------------------------------------------------------------

UTC0 = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))


@pytest.mark.parametrize(
    ("value", "fmt", "expected", "had_zone"),
    [
        ("2024-05-01T10:00:00Z", "iso8601", "2024-05-01T10:00:00+00:00", True),
        ("2024-05-01T10:00:00.250+02:00", "iso8601", "2024-05-01T10:00:00.250000+02:00", True),
        ("2024-05-01 10:00", "iso8601", "2024-05-01T10:00:00+05:30", False),
        ("2024/05/01 10:00:07", "iso8601", "2024-05-01T10:00:07+05:30", False),
        ("2024-05-01", "iso8601", "2024-05-01T00:00:00+05:30", False),
        ("03/07/2017 08:55:58", "dmy", "2017-07-03T08:55:58+05:30", False),
        ("07/03/2017 8:55:58 PM", "mdy", "2017-07-03T20:55:58+05:30", False),
        ("12/31/2023 12:00 AM", "mdy", "2023-12-31T00:00:00+05:30", False),
        ("Wed, 01 May 2024 10:00:00 +0000", "rfc2822", "2024-05-01T10:00:00+00:00", True),
        ("1714557600", "epoch_seconds", "2024-05-01T10:00:00+00:00", True),
        ("1714557600.5", "epoch_seconds", "2024-05-01T10:00:00.500000+00:00", True),
        ("1714557600000", "epoch_millis", "2024-05-01T10:00:00+00:00", True),
    ],
)
def test_supported_timestamp_formats(value: str, fmt: str, expected: str, had_zone: bool) -> None:
    parsed = parse_timestamp(value, fmt, IST, NOW)
    assert parsed.value.isoformat() == expected
    assert parsed.had_zone is had_zone


@pytest.mark.parametrize(
    ("value", "fmt", "rule"),
    [
        ("yesterday", "iso8601", "row.invalid_timestamp"),
        ("2024-02-30T10:00:00Z", "iso8601", "row.invalid_timestamp"),
        ("2024-05-01T25:00:00Z", "iso8601", "row.invalid_timestamp"),
        ("13/13/2024 10:00", "dmy", "row.invalid_timestamp"),
        ("01/05/2024 13:00 PM", "mdy", "row.invalid_timestamp"),
        ("Wed, 01 May 2024 10:00:00 -0000", "rfc2822", "row.invalid_timestamp"),
        ("1714557600000", "epoch_seconds", "row.timestamp_out_of_range"),
        ("1969-12-31T23:59:59Z", "iso8601", "row.timestamp_out_of_range"),
        ("2026-10-14T00:00:00Z", "iso8601", "row.timestamp_out_of_range"),
        ("-5", "epoch_seconds", "row.invalid_timestamp"),
    ],
)
def test_invalid_or_out_of_range_timestamps_name_their_rule(value: str, fmt: str, rule: str) -> None:
    with pytest.raises(TimestampError) as error:
        parse_timestamp(value, fmt, UTC0, NOW)
    assert error.value.rule == rule
    assert value not in error.value.message


# --- Detection ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_delimiter_is_detected(delimiter: str) -> None:
    text = delimiter.join(["time", "src", "dst", "msg"]) + "\n"
    text += delimiter.join(["2024-05-01T10:00:00Z", "192.0.2.1", "192.0.2.2", '"a, b; c | d"']) + "\n"
    assert detect_delimiter(text) == (delimiter, True)


def test_encoding_detection_prefers_utf8_and_flags_fallbacks() -> None:
    assert detect_encoding("time,msg\n2024,café\n".encode()) == ("utf-8", True)
    assert detect_encoding(b"\xef\xbb\xbftime,msg\n") == ("utf-8", True)
    assert detect_encoding("time,msg\n".encode("utf-16")) == ("utf-16", True)
    assert detect_encoding("time,msg\nWeb Attack – XSS\n".encode("cp1252")) == ("cp1252", False)


@pytest.mark.parametrize(
    "header",
    [
        "Event Time,Source IP,Destination IP,Destination Port,Protocol",
        "protocol,dst_port,dst_ip,src_ip,timestamp",
        "@timestamp,id.orig_h,id.resp_h,id.resp_p,proto",
    ],
)
def test_different_names_and_orders_suggest_the_same_mapping(header: str) -> None:
    columns = header.split(",")
    values = {
        "occurred_at": "2024-05-01T10:00:00Z",
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "dest_port": "443",
        "protocol": "tcp",
    }
    canonical = ["occurred_at", "src_ip", "dest_ip", "dest_port", "protocol"]
    order = {
        "Event Time": "occurred_at", "timestamp": "occurred_at", "@timestamp": "occurred_at",
        "Source IP": "src_ip", "src_ip": "src_ip", "id.orig_h": "src_ip",
        "Destination IP": "dest_ip", "dst_ip": "dest_ip", "id.resp_h": "dest_ip",
        "Destination Port": "dest_port", "dst_port": "dest_port", "id.resp_p": "dest_port",
        "Protocol": "protocol", "protocol": "protocol", "proto": "protocol",
    }  # fmt: skip
    line = ",".join(values[order[name]] for name in columns)
    result = by_field(preview(f"{header}\n{line}\n{line}\n".encode()))
    for name in canonical:
        assert result[name].confidence == "high", name
        assert order[result[name].column] == name


def test_network_columns_suggest_a_network_flow_record_type() -> None:
    result = preview(FLOW_CSV)
    assert result.delimiter == ";"
    assert result.suggested_record_type == "network_flow"
    assert result.suggested_timestamp_format == "epoch_seconds"
    assert result.needs_review is False


def test_unknown_columns_are_not_guessed() -> None:
    result = preview(b"alpha,beta,gamma\nfoo,1,x\nbar,2,y\n")
    assert all(item.confidence == "none" for item in result.suggestions)
    assert result.suggested_record_type == "security_event"
    assert result.needs_review is True


def test_two_matching_columns_are_ambiguous_not_chosen() -> None:
    result = by_field(preview(b"time,Source IP,src_ip,event\n2024-05-01T10:00:00Z,192.0.2.1,192.0.2.2,x\n"))
    assert result["src_ip"].confidence == "ambiguous"
    assert result["src_ip"].column is None
    assert set(result["src_ip"].candidates) == {"Source IP", "src_ip"}


def test_name_match_with_wrong_values_is_low_confidence() -> None:
    result = by_field(preview(b"timestamp,src_ip,event\n2024-05-01T10:00:00Z,web-01,x\n2024-05-01T10:00:01Z,web-02,y\n"))
    assert result["src_ip"].confidence == "low"
    assert result["occurred_at"].confidence == "high"
    assert result["event_type"].confidence == "high"


def test_day_month_ambiguity_requires_a_user_choice() -> None:
    result = preview(b"date,event\n03/07/2017 08:55,login\n04/07/2017 09:00,logout\n")
    assert result.suggested_timestamp_format is None
    assert set(result.timestamp_format_candidates) >= {"dmy", "mdy"}
    assert result.needs_review is True
    assert any("day/month" in warning for warning in result.warnings)


def test_unambiguous_day_first_dates_are_detected() -> None:
    result = preview(b"date,event\n25/07/2017 08:55,login\n04/07/2017 09:00,logout\n")
    assert result.suggested_timestamp_format == "dmy"


def test_naive_timestamps_are_flagged() -> None:
    result = preview(b"timestamp,event\n2024-05-01 10:00:00,login\n")
    assert result.timestamp_has_zone is False
    assert any("time zone" in warning for warning in result.warnings)


def test_cic_ids2017_header_is_recognised() -> None:
    assert preview(csv_bytes(row())).recognized_profile == "cic-ids2017"
    assert preview(AUTH_CSV).recognized_profile is None


def test_preview_neutralises_formula_cells_and_truncates() -> None:
    content = b"timestamp,event,msg\n2024-05-01T10:00:00Z,=cmd|' /C calc'!A0,-5\n2024-05-01T10:00:00Z,@SUM(1),\"" + b"x" * 500 + b"\"\n"
    result = preview(content)
    assert result.rows[0][1] == "'=cmd|' /C calc'!A0"
    assert result.rows[0][2] == "-5"
    assert result.rows[1][1] == "'@SUM(1)"
    assert len(result.rows[1][2]) == 200 and result.rows[1][2].endswith("…")
    assert any("apostrophe" in warning for warning in result.warnings)


@pytest.mark.parametrize(
    ("content", "message"),
    [(b"", "empty"), (b"  \n\n", "empty"), (b"time,msg\x00\n", "binary")],
)
def test_unusable_files_cannot_be_previewed(content: bytes, message: str) -> None:
    with pytest.raises(PreviewError, match=message):
        preview(content)


def test_blank_and_repeated_header_names_are_not_mappable() -> None:
    result = preview(b"time,,time\n2024-05-01T10:00:00Z,a,b\n")
    assert [column["mappable"] for column in result.columns] == [False, False, False]
    assert any("blank or repeated" in warning for warning in result.warnings)


@pytest.mark.parametrize(
    ("value", "safe"),
    [("=1+1", "'=1+1"), ("+cmd", "'+cmd"), ("@SUM(A1)", "'@SUM(A1)"), ("\t=x", "'\t=x"), ("-5", "-5"), ("+1.5e3", "+1.5e3"), ("login", "login")],
)
def test_formula_neutralisation(value: str, safe: str) -> None:
    assert formula_safe(value) == safe
    assert is_formula_like(value) is (value != safe)


# --- Mapping schema ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"fields": {"occurred_at": "Event Time"}}, "required fields are not mapped: event_type"),
        ({"recordType": "network_flow"}, "required fields are not mapped: dest_ip"),
        ({"fields": {**AUTH_MAPPING["fields"], "outcome": "event time"}}, "only one field"),
        ({"defaultEventType": "auth"}, "defaultEventType applies only"),
        ({"utcOffset": "+25:00"}, "String should match pattern"),
        ({"timestampFormat": "excel"}, "Input should be"),
        ({"fields": {**AUTH_MAPPING["fields"], "username": "User"}}, "Input should be"),
        ({"extra": 1}, "Extra inputs are not permitted"),
    ],
)
def test_incomplete_or_ambiguous_mappings_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        FieldMapping.model_validate(mapping(AUTH_MAPPING, **changes))


def test_default_event_type_satisfies_the_event_type_requirement() -> None:
    fields = {key: value for key, value in AUTH_MAPPING["fields"].items() if key != "event_type"}
    spec = mapping(AUTH_MAPPING, fields=fields, defaultEventType="authentication")
    assert [event.event_type for event in events_for(AUTH_CSV, spec)] == ["authentication"] * 3


# --- Validation and normalisation (no database) ------------------------------------------------------


def test_reordered_columns_normalise_identically() -> None:
    reordered = (
        "proto|dst_port|dst|src|ts|sport\n"
        "6|443|198.51.100.20|192.0.2.10|1714557600|51515\n"
    ).encode()
    spec = mapping(FLOW_MAPPING, delimiter="|")
    first, second = events_for(FLOW_CSV, FLOW_MAPPING)[0], events_for(reordered, spec)[0]
    for name in ("occurred_at", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "event_type"):
        assert getattr(first, name) == getattr(second, name)
    # The same cells under the same column names hash alike, so a reordered copy is a duplicate.
    assert first.content_sha256 == second.content_sha256
    assert (first.protocol, first.event_type) == ("tcp", "network_flow")


def test_normalised_event_keeps_provenance_and_never_trusts_labels() -> None:
    event = events_for(AUTH_CSV, AUTH_MAPPING)[0]
    raw = event.raw_data
    assert event.event_type == "login_failure"
    assert raw["groundTruthLabel"] == "brute-force"
    assert raw["reportedSeverity"] == {"asWritten": "High", "normalized": "high"}
    assert raw["message"] == "bad password" and raw["outcome"] == "failure"
    assert raw["sourceFields"]["User"] == "alice"
    assert raw["unmappedColumns"] == ["User"]
    assert raw["dataset"]["fieldMapping"]["occurred_at"] == "Event Time"
    assert raw["dataset"]["recordType"] == "security_event"
    assert raw["timestampAsWritten"] == "2024-05-01T10:00:00Z"


def test_missing_optional_fields_are_absent_and_missing_required_reject_the_row() -> None:
    content = (
        "Event Time,User,Source IP,Action,Severity,Event Type,Message,Label\n"
        "2024-05-01T10:00:00Z,alice,,,,login_failure,,\n"
        ",alice,203.0.113.5,failure,High,login_failure,x,y\n"
        "2024-05-01T10:00:00Z,alice,203.0.113.5,failure,High,,x,y\n"
    ).encode()
    report = validate(content, AUTH_MAPPING)
    assert (report.total_rows, report.accepted_rows, report.rejected_rows) == (3, 1, 2)
    assert [(issue["row"], issue["column"], issue["rule"]) for issue in report.error_sample] == [
        (3, "occurred_at", "row.missing_value"),
        (4, "event_type", "row.missing_value"),
    ]
    (event,) = events_for(content, AUTH_MAPPING)
    assert event.src_ip is None and "groundTruthLabel" not in event.raw_data and "reportedSeverity" not in event.raw_data


def test_malformed_values_reject_rows_without_echoing_cells() -> None:
    content = (
        "ts;src;dst;sport;dst_port;proto\n"
        f"{SECRET};192.0.2.10;198.51.100.20;1;2;6\n"
        f"1714557600;{SECRET};198.51.100.20;1;2;6\n"
        "1714557600;192.0.2.10;fe80::1%eth0;1;2;6\n"
        "1714557600;192.0.2.10;198.51.100.20;70000;2;6\n"
        f"1714557600;192.0.2.10;198.51.100.20;1;2;{SECRET}!\n"
        "1714557600;192.0.2.10;198.51.100.20;1;2\n"
        "1714557600;192.0.2.10;198.51.100.20;443.0;80;256\n"
        ";;;;;\n"
        "1714557600;192.0.2.10;198.51.100.20;443.0;80;tcp\n"
    ).encode()
    report = validate(content, FLOW_MAPPING)
    rules = [(issue["row"], issue["rule"]) for issue in report.error_sample]
    assert rules == [
        (2, "row.invalid_timestamp"),
        (3, "row.invalid_ip"),
        (4, "row.invalid_ip"),
        (5, "row.invalid_port"),
        (6, "row.invalid_protocol"),
        (7, "row.column_count"),
        (8, "row.invalid_protocol"),
    ]
    # The all-empty record (row 9) is skipped like a blank line; row 10 is accepted.
    assert (report.total_rows, report.accepted_rows, report.rejected_rows) == (8, 1, 7)
    assert SECRET not in json.dumps(report.error_sample)
    (event,) = events_for(content, FLOW_MAPPING)
    assert event.src_port == 443


def test_overlong_and_control_character_values_are_rejected() -> None:
    content = (
        "Event Time,User,Source IP,Action,Severity,Event Type,Message,Label\n"
        f"2024-05-01T10:00:00Z,a,,,,{'x' * 101},,\n"
        "2024-05-01T10:00:00Z,a,,,,\"bad\x07type\",,\n"
        "2024-05-01T10:00:00Z,a,,,,ok,\"line one\nline two\",\n"
    ).encode()
    report = validate(content, AUTH_MAPPING)
    assert [(issue["row"], issue["rule"]) for issue in report.error_sample] == [
        (2, "row.value_too_long"),
        (3, "row.invalid_text"),
    ]
    assert report.accepted_rows == 1


def test_formula_event_type_is_neutralised_but_kept_as_written_in_source_fields() -> None:
    content = (
        "Event Time,User,Source IP,Action,Severity,Event Type,Message,Label\n"
        "2024-05-01T10:00:00Z,a,,,,=HYPERLINK(\"http://x\"),<script>alert(1)</script>,\n"
    ).encode()
    (event,) = events_for(content, AUTH_MAPPING)
    assert event.event_type == "'=HYPERLINK(\"http://x\")"
    assert event.raw_data["formulaNeutralized"] == ["event_type"]
    assert event.raw_data["sourceFields"]["Event Type"] == "=HYPERLINK(\"http://x\")"
    # Markup is data: stored verbatim, never interpreted (the UI renders it as text).
    assert event.raw_data["message"] == "<script>alert(1)</script>"


def test_naive_timestamps_use_the_chosen_offset_and_record_it() -> None:
    content = b"time,event\n2024-05-01 10:00:00,login\n"
    spec = {"recordType": "security_event", "timestampFormat": "iso8601", "utcOffset": "+05:30",
            "fields": {"occurred_at": "time", "event_type": "event"}}  # fmt: skip
    (event,) = events_for(content, spec)
    assert event.occurred_at == datetime(2024, 5, 1, 4, 30, tzinfo=UTC)
    assert "UTC+05:30" in event.raw_data["occurredAtInterpretation"]


def test_missing_and_repeated_mapped_columns_reject_the_file() -> None:
    missing = validate(AUTH_CSV, mapping(AUTH_MAPPING, fields={**AUTH_MAPPING["fields"], "dest_ip": "Target"}))
    assert missing.file_rejected
    assert [(issue["rule"], issue["column"]) for issue in missing.error_sample] == [("header.missing_column", "dest_ip")]
    repeated = validate(b"time,event,EVENT\n2024-05-01T10:00:00Z,a,b\n", {
        "recordType": "security_event", "timestampFormat": "iso8601", "fields": {"occurred_at": "time", "event_type": "event"},
    })  # fmt: skip
    assert repeated.file_rejected
    assert repeated.error_sample[0]["rule"] == "header.ambiguous_column"


def test_column_names_match_ignoring_case_and_spaces() -> None:
    spec = mapping(AUTH_MAPPING, fields={name: f"  {column.upper()} " for name, column in AUTH_MAPPING["fields"].items()})
    assert validate(AUTH_CSV, spec).accepted_rows == 3


@pytest.mark.parametrize(("encoding", "python_codec"), [("utf-8", "utf-8-sig"), ("utf-16", "utf-16"), ("cp1252", "cp1252")])
def test_encodings(encoding: str, python_codec: str) -> None:
    text = "time,event,msg\n2024-05-01T10:00:00Z,login,Web Attack – café\n"
    content = text.encode(python_codec)
    spec = {"recordType": "security_event", "timestampFormat": "iso8601", "encoding": encoding,
            "fields": {"occurred_at": "time", "event_type": "event", "message": "msg"}}  # fmt: skip
    report = validate(content, spec)
    assert (report.file_rejected, report.accepted_rows) == (False, 1)
    assert events_for(content, spec)[0].raw_data["message"] == "Web Attack – café"


def test_wrong_encoding_rejects_the_file() -> None:
    content = "time,event\n2024-05-01T10:00:00Z,Web Attack – XSS\n".encode("cp1252")
    report = validate(content, {"recordType": "security_event", "timestampFormat": "iso8601",
                                "fields": {"occurred_at": "time", "event_type": "event"}})  # fmt: skip
    assert report.file_rejected and report.error_sample[0]["rule"] == "file.encoding"


def test_nul_characters_are_rejected() -> None:
    utf8 = validate(b"time,event\n2024-05-01T10:00:00Z,a\x00b\n", {
        "recordType": "security_event", "timestampFormat": "iso8601", "fields": {"occurred_at": "time", "event_type": "event"},
    })  # fmt: skip
    assert utf8.file_rejected and utf8.error_sample[0]["rule"] == "file.not_text"
    utf16 = validate("time,event\n2024-05-01T10:00:00Z,a\x00b\n".encode("utf-16"), {
        "recordType": "security_event", "timestampFormat": "iso8601", "encoding": "utf-16",
        "fields": {"occurred_at": "time", "event_type": "event"},
    })  # fmt: skip
    assert (utf16.file_rejected, utf16.rejected_rows) == (False, 1)
    assert utf16.error_sample[0]["rule"] == "row.binary_content"


# --- API ---------------------------------------------------------------------------------------------


def post_preview(api: CoreApi, content: bytes, *, filename: str = "events.csv", data: dict[str, str] | None = None,
                 headers: dict[str, str] | None = None) -> Any:  # fmt: skip
    return api.client.post(
        PREVIEW,
        files={"file": (filename, content, "text/csv")},
        data=data or {},
        headers=api.headers if headers is None else headers,
    )


def post_import(api: CoreApi, content: bytes, spec: dict[str, Any] | str | None, *, profile: str = "security-csv",
                filename: str = "events.csv") -> Any:  # fmt: skip
    data = {"profile": profile}
    if spec is not None:
        data["mapping"] = spec if isinstance(spec, str) else json.dumps(spec)
    return api.client.post(IMPORTS, files={"file": (filename, content, "text/csv")}, data=data, headers=api.headers)


def counts(api: CoreApi) -> tuple[int, int]:
    with api.session_factory() as session:
        return (
            int(session.scalar(select(func.count()).select_from(ImportBatch)) or 0),
            int(session.scalar(select(func.count()).select_from(SecurityEvent)) or 0),
        )


def mapping_from_preview(body: dict[str, Any]) -> dict[str, Any]:
    """What the UI does: keep only high-confidence suggestions, then the user confirms the rest."""
    fields = {item["field"]: item["column"] for item in body["suggestions"] if item["confidence"] == "high"}
    return {
        "recordType": body["suggestedRecordType"],
        "timestampFormat": body["suggestedTimestampFormat"],
        "encoding": body["encoding"],
        "delimiter": body["delimiter"],
        "fields": fields,
    }


def test_preview_requires_authentication(core_api: CoreApi) -> None:
    assert post_preview(core_api, AUTH_CSV, headers={}).status_code == 401
    assert post_preview(core_api, AUTH_CSV, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_preview_suggests_without_recording_anything(core_api: CoreApi) -> None:
    response = post_preview(core_api, AUTH_CSV)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["encoding"] == "utf-8" and body["delimiter"] == ","
    assert body["suggestedRecordType"] == "security_event"
    assert body["suggestedTimestampFormat"] == "iso8601"
    assert body["fileSha256"] == hashlib.sha256(AUTH_CSV).hexdigest()
    assert body["alreadyImported"] is False
    assert {item["name"] for item in body["recordTypes"]} == {"security_event", "network_flow"}
    assert [field["name"] for field in body["fields"]][:2] == ["occurred_at", "event_type"]
    assert len(body["rows"]) == 3 and body["rows"][0][1] == "alice"
    assert counts(core_api) == (0, 0)


@pytest.mark.parametrize(
    ("content", "filename", "data", "code"),
    [
        (b"", "e.csv", {}, 422),
        (b"time,msg\x00\n", "e.csv", {}, 422),
        (AUTH_CSV, "e.xlsx", {}, 415),
        (AUTH_CSV, "e.csv", {"encoding": "ebcdic"}, 422),
        (AUTH_CSV, "e.csv", {"delimiter": "x"}, 422),
        (AUTH_CSV, "e.csv", {"profile": "generic-csv"}, 422),
        ("café,x\n".encode("cp1252"), "e.csv", {"encoding": "utf-8"}, 422),
    ],
)
def test_preview_refuses_unusable_requests(
    core_api: CoreApi, content: bytes, filename: str, data: dict[str, str], code: int
) -> None:
    response = post_preview(core_api, content, filename=filename, data=data)
    assert response.status_code == code, response.text
    assert counts(core_api) == (0, 0)


def test_preview_and_import_respect_the_byte_limit(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "import_max_upload_bytes", 64)
    assert post_preview(core_api, AUTH_CSV).status_code == 413
    assert post_import(core_api, AUTH_CSV, AUTH_MAPPING).status_code == 413
    assert counts(core_api) == (0, 0)


def test_import_respects_the_row_limit(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "import_max_rows", 2)
    response = post_import(core_api, AUTH_CSV, AUTH_MAPPING)
    assert response.status_code == 413
    assert counts(core_api) == (0, 0)


@pytest.mark.parametrize(
    ("spec", "profile", "fragment"),
    [
        (None, "security-csv", "mapping is required"),
        ("not json", "security-csv", "mapping must be a JSON object"),
        ("[1, 2]", "security-csv", "mapping must be a JSON object"),
        (json.dumps({"recordType": "network_flow", "timestampFormat": "iso8601", "fields": {"occurred_at": SECRET}}),
         "security-csv", "required fields are not mapped"),
        (AUTH_MAPPING, "generic-csv", "mapping applies only to the security-csv profile"),
        (AUTH_MAPPING, "cic-ids2017", "mapping applies only to the security-csv profile"),
    ],
)  # fmt: skip
def test_import_requires_a_valid_explicit_mapping(core_api: CoreApi, spec: Any, profile: str, fragment: str) -> None:
    response = post_import(core_api, AUTH_CSV, spec, profile=profile)
    assert response.status_code == 422
    assert fragment in response.json()["detail"]
    assert SECRET not in response.text
    assert counts(core_api) == (0, 0)


def test_oversized_mapping_field_is_refused(core_api: CoreApi) -> None:
    spec = mapping(AUTH_MAPPING, fields={**AUTH_MAPPING["fields"], "message": "m" * 20_000})
    assert post_import(core_api, AUTH_CSV, spec).status_code == 422


def test_end_to_end_unfamiliar_csv_is_previewed_mapped_imported_and_visible(core_api: CoreApi) -> None:
    asset_id = add_asset(core_api, "AUTH-GW", "203.0.113.5")
    preview_body = post_preview(core_api, AUTH_CSV).json()
    spec = mapping_from_preview(preview_body)
    # Every field this file has was detected with high confidence, so no user correction is needed here.
    assert set(spec["fields"]) == {"occurred_at", "src_ip", "outcome", "severity", "event_type", "message", "label"}

    response = post_import(core_api, AUTH_CSV, spec)
    assert response.status_code == 201, response.text
    batch = response.json()
    assert batch["datasetProfile"] == "security-csv" and batch["status"] == "VALIDATED"
    assert (batch["totalRows"], batch["acceptedRows"], batch["rejectedRows"]) == (3, 3, 0)
    assert (batch["eventsCreated"], batch["duplicateRows"]) == (2, 1)  # rows 2 and 3 are identical
    assert batch["normalization"]["fieldMapping"]["occurred_at"] == "Event Time"
    # Row 4's address matches no asset, so an assessment of AUTH-GW can use only row 2's event.
    assert batch["eventCoverage"] == {"events": 2, "linkedToAsset": 1, "addressWithoutAsset": 1, "withoutAddress": 0}
    assert post_import(core_api, AUTH_CSV, spec).status_code == 409

    with core_api.session_factory() as session:
        events = list(session.scalars(select(SecurityEvent).order_by(SecurityEvent.source_row)))
        assert [event.source_row for event in events] == [2, 4]
        for event in events:
            assert event.source == DetectionSource.DATASET_IMPORT
            assert event.severity == Severity.INFO  # the file's "High" is kept only as reportedSeverity
            assert event.signature is None
            assert str(event.import_batch_id) == batch["id"]
            assert event.event_uid.startswith("dataset:security-csv:")
        assert [event.asset_id for event in events] == [asset_id, None]
        assert events[0].raw_data["groundTruthLabel"] == "brute-force"
        for model in (Incident, SecurityAssessment):
            assert session.scalar(select(func.count()).select_from(model)) == 0

    listed = core_api.client.get("/api/events", params={"importBatchId": batch["id"]}, headers=core_api.headers).json()
    assert listed["total"] == 2
    assert {item["eventType"] for item in listed["items"]} == {"login_failure", "login_success"}
    assert all(item["severity"] == "INFO" and item["sourceRow"] in (2, 4) for item in listed["items"])

    status = core_api.client.get("/api/collector/status", headers=core_api.headers).json()
    assert status["importedEventsTotal"] == 2
    assert [item["sourceRow"] for item in status["recentImportedEvents"]] == [2, 4]
    assert status["totalEvents"] == 0  # imports are not collector submissions

    detail = core_api.client.get(f"{IMPORTS}/{batch['id']}", headers=core_api.headers).json()
    assert detail["eventCoverage"]["linkedToAsset"] == 1
    assert detail["normalization"]["recordType"] == "security_event"
    again = post_preview(core_api, AUTH_CSV).json()
    assert again["alreadyImported"] is True and again["alreadyImportedBatchId"] == batch["id"]


def test_user_corrected_mapping_for_unknown_columns(core_api: CoreApi) -> None:
    content = b"c1,c2,c3\n2024-05-01T10:00:00Z,quarantine,host-7\n2024-05-01T11:00:00Z,clean,host-8\n"
    body = post_preview(core_api, content).json()
    assert body["needsReview"] is True
    assert all(item["confidence"] in ("none", "low") for item in body["suggestions"])
    spec = {"recordType": "security_event", "timestampFormat": "iso8601",
            "fields": {"occurred_at": "c1", "event_type": "c2"}}  # fmt: skip
    response = post_import(core_api, content, spec)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["eventsCreated"] == 2
    assert result["eventCoverage"]["withoutAddress"] == 2
    with core_api.session_factory() as session:
        event = session.scalars(select(SecurityEvent).order_by(SecurityEvent.source_row)).first()
        assert event is not None and event.raw_data["unmappedColumns"] == ["c3"]
        assert event.raw_data["assetLink"]["result"] == "event has no IP address to match"


def test_reordered_copy_with_new_bytes_stores_only_duplicates(core_api: CoreApi) -> None:
    first = post_import(core_api, FLOW_CSV, FLOW_MAPPING).json()
    assert first["eventsCreated"] == 2
    reordered = (
        "proto,dst_port,dst,src,ts,sport\n"
        "6,443,198.51.100.20,192.0.2.10,1714557600,51515\n"
        "17,53,198.51.100.21,192.0.2.10,1714557601,51516\n"
    ).encode()
    response = post_import(core_api, reordered, mapping(FLOW_MAPPING, delimiter=","))
    assert response.status_code == 201
    second = response.json()
    assert (second["eventsCreated"], second["duplicateRows"]) == (0, 2)
    assert second["eventCoverage"] is None and second["normalization"] is None
    assert counts(core_api) == (2, 2)


def test_rejected_files_store_nothing(core_api: CoreApi) -> None:
    header_only = post_import(core_api, b"Event Time,Event Type\n", {
        "recordType": "security_event", "timestampFormat": "iso8601",
        "fields": {"occurred_at": "Event Time", "event_type": "Event Type"},
    }).json()  # fmt: skip
    assert header_only["status"] == "REJECTED"
    assert header_only["errorSample"][0]["rule"] == "file.no_rows"
    blank_rows = post_import(core_api, b"Event Time,Event Type\n,\n,\n", {
        "recordType": "security_event", "timestampFormat": "iso8601",
        "fields": {"occurred_at": "Event Time", "event_type": "Event Type"},
    }).json()  # fmt: skip
    assert blank_rows["status"] == "REJECTED" and blank_rows["totalRows"] == 0
    wrong_header = post_import(core_api, FLOW_CSV, AUTH_MAPPING).json()
    assert wrong_header["status"] == "REJECTED"
    assert {issue["rule"] for issue in wrong_header["errorSample"]} == {"header.missing_column"}
    assert counts(core_api) == (3, 0)


def test_partially_valid_file_stores_only_accepted_rows_and_reports_the_rest(core_api: CoreApi) -> None:
    content = FLOW_CSV + f"{SECRET};192.0.2.10;198.51.100.20;1;2;6\n".encode()
    batch = post_import(core_api, content, FLOW_MAPPING).json()
    assert (batch["status"], batch["acceptedRows"], batch["rejectedRows"], batch["eventsCreated"]) == ("VALIDATED", 2, 1, 2)
    assert batch["errorSample"] == [
        {"rule": "row.invalid_timestamp", "message": "must be a whole number of Unix seconds", "row": 4,
         "column": "occurred_at", "columnIndex": 1},
    ]  # fmt: skip
    detail = core_api.client.get(f"{IMPORTS}/{batch['id']}", headers=core_api.headers)
    assert SECRET not in detail.text


def test_cic_ids2017_imports_are_unchanged(core_api: CoreApi) -> None:
    response = core_api.client.post(
        IMPORTS,
        files={"file": ("flows.csv", csv_bytes(row(), row(label="DDoS")), "text/csv")},
        data={"profile": "cic-ids2017"},
        headers=core_api.headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["datasetProfile"], body["eventsCreated"]) == ("cic-ids2017", 2)
    assert body["normalization"] == {"profile": "cic-ids2017", "profileVersion": "1"}
    assert body["eventCoverage"]["addressWithoutAsset"] == 2
    with core_api.session_factory() as session:
        uids = list(session.scalars(select(SecurityEvent.event_uid)))
        assert all(uid.startswith("dataset:cic-ids2017:") for uid in uids)
