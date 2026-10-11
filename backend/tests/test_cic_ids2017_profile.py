"""CIC-IDS2017 profile tests.

The header below is the real 85-column CIC-IDS2017 header (column names only, spaces as in the
files). Every data row is synthetic: documentation addresses, invented values, no dataset rows.
"""

import io
import os
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from app.models import ImportBatch, SecurityEvent
from app.services import dataset_profiler
from app.services.dataset_import import FileDigest, validate_upload
from app.services.dataset_profiles import (
    CIC_IDS2017_COLUMNS,
    PROFILES,
    CicIds2017Profile,
    GenericCsvProfile,
)
from tests.conftest import CoreApi

REAL_HEADER = (
    "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, "
    "Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets, "
    "Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,"
    "Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,"
    "Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,"
    "Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,"
    "Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,"
    "Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length,"
    "Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, "
    "Packet Length Variance,FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, "
    "URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, "
    "Avg Bwd Segment Size, Fwd Header Length,Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, "
    "Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate,Subflow Fwd Packets, Subflow Fwd Bytes, "
    "Subflow Bwd Packets, Subflow Bwd Bytes,Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, "
    "min_seg_size_forward,Active Mean, Active Std, Active Max, Active Min,Idle Mean, Idle Std, Idle Max, Idle Min, Label"
)
HEADER = REAL_HEADER.split(",")
PROFILE = CicIds2017Profile()
SECRET = "SECRET7f3a9"
EN_DASH = "–"


def row(**overrides: str) -> list[str]:
    """A synthetic, valid record; overrides use profile keys (e.g. source_ip, fwd_header_length_2)."""
    values = {key: "1" for key in PROFILE.keys}
    values.update(
        flow_id="192.0.2.10-198.51.100.20-51515-443-6",
        source_ip="192.0.2.10",
        source_port="51515",
        destination_ip="198.51.100.20",
        destination_port="443",
        protocol="6",
        timestamp="7/7/2017 3:30",
        flow_bytes_s="1234.5",
        flow_iat_min="-1",
        fwd_header_length="32",
        fwd_header_length_2="32",
        label="BENIGN",
    )
    values.update(overrides)
    return [values[key] for key in PROFILE.keys]


def check(**overrides: str) -> list[dict[str, Any]]:
    record = row(**overrides)
    return [issue.as_dict() for issue in PROFILE.check_row(dict(zip(PROFILE.keys, record)))]


def rules(**overrides: str) -> list[tuple[str, str | None]]:
    return [(issue["rule"], issue["column"]) for issue in check(**overrides)]


def csv_bytes(*records: list[str], header: str = REAL_HEADER, encoding: str = "cp1252", newline: str = "\n") -> bytes:
    lines = [header, *(",".join(record) for record in records)]
    return (newline.join(lines) + newline).encode(encoding)


def validate(content: bytes) -> Any:
    digest = FileDigest(sha256="0" * 64, size_bytes=len(content), contains_nul=b"\x00" in content)
    return validate_upload(io.BytesIO(content), PROFILE, digest, max_rows=1000)


# --- Header ------------------------------------------------------------------------------------------


def test_profile_is_registered_and_versioned() -> None:
    assert PROFILES["cic-ids2017"].version == "1"
    assert PROFILES["cic-ids2017"].encoding == "cp1252"
    assert len(CIC_IDS2017_COLUMNS) == 85


def test_real_header_is_accepted_and_both_fwd_header_length_columns_are_kept() -> None:
    assert len(HEADER) == 85
    assert sum(name != name.strip() for name in HEADER) == 70
    assert PROFILE.check_header(HEADER) == []
    positions = PROFILE.column_positions(HEADER)
    assert len(positions) == 85
    assert positions["fwd_header_length"] == 40
    assert positions["fwd_header_length_2"] == 61
    assert positions["label"] == 84


def test_generic_profile_still_rejects_the_repeated_column() -> None:
    issues = GenericCsvProfile().check_header(HEADER)
    assert [(issue.rule, issue.column_index) for issue in issues] == [("header.duplicate_column", 62)]


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (HEADER[:61] + HEADER[62:], [("header.column_count", None)]),  # second Fwd Header Length removed
        (HEADER + [" Extra"], [("header.column_count", None)]),
        (HEADER[:40] + [" Bwd Header Length", " Fwd Header Length"] + HEADER[42:], [("header.unexpected_column", 41), ("header.unexpected_column", 42)]),
        (HEADER[:61] + [" Bwd Header Length"] + HEADER[62:], [("header.unexpected_column", 62)]),  # repeat replaced
        (HEADER[:6] + [" timestamp"] + HEADER[7:], [("header.unexpected_column", 7)]),  # case differs
        (HEADER[:84] + [f" {SECRET}"], [("header.unexpected_column", 85)]),
    ],
)
def test_header_variants_are_rejected_by_position(header: list[str], expected: list[tuple[str, int | None]]) -> None:
    issues = PROFILE.check_header(header)
    assert [(issue.rule, issue.column_index) for issue in issues] == expected
    assert all(SECRET not in str(issue.as_dict()) for issue in issues)


def test_moved_repeat_is_rejected() -> None:
    moved = HEADER[:61] + HEADER[62:]
    moved.insert(50, " Fwd Header Length")
    assert all(issue.rule == "header.unexpected_column" for issue in PROFILE.check_header(moved))
    assert PROFILE.check_header(moved)


# --- Rows ----------------------------------------------------------------------------------------------


def test_valid_synthetic_row_is_accepted() -> None:
    assert check() == []


def test_flow_id_may_list_either_endpoint_first() -> None:
    assert check(flow_id="198.51.100.20-192.0.2.10-443-51515-6") == []


@pytest.mark.parametrize("value", ["Infinity", "-Infinity", "NaN"])
def test_non_finite_values_are_accepted_as_written(value: str) -> None:
    assert check(flow_bytes_s=value, flow_packets_s=value) == []


@pytest.mark.parametrize("value", ["inf", "nan", "INFINITY", "1_000", " 5", "5 ", "1e", "--1", "0x10", SECRET])
def test_other_number_spellings_are_rejected(value: str) -> None:
    assert rules(flow_bytes_s=value) == [("row.invalid_number", "Flow Bytes/s")]


@pytest.mark.parametrize("value", ["0", "-1", "3.5", "1.0E-05", "2e+3", ".5", "123."])
def test_number_forms_are_accepted(value: str) -> None:
    assert check(flow_iat_min=value) == []


def test_empty_record_is_one_rejection() -> None:
    issues = PROFILE.check_row(dict.fromkeys(PROFILE.keys, ""))
    assert [issue.rule for issue in issues] == ["row.empty_record"]
    whitespace = PROFILE.check_row(dict.fromkeys(PROFILE.keys, " "))
    assert [issue.rule for issue in whitespace] == ["row.empty_record"]


def test_missing_values_are_named_by_column() -> None:
    assert rules(flow_duration="", label="") == [
        ("row.missing_value", "Flow Duration"),
        ("row.missing_value", "Label"),
    ]


@pytest.mark.parametrize("value", ["7/7/2017 3:30", "03/07/2017 08:55:58", "5/7/2017 12:59", "4/7/2017 1:00"])
def test_both_timestamp_shapes_are_accepted(value: str) -> None:
    assert check(timestamp=value) == []


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        ("2017-07-07 03:30", "row.invalid_timestamp"),
        ("7/7/2017 3:30 PM", "row.invalid_timestamp"),
        ("7/7/2017", "row.invalid_timestamp"),
        ("31/6/2017 3:30", "row.invalid_timestamp"),  # no 31 June
        ("7/7/2017 3:60", "row.invalid_timestamp"),
        ("7/3/2017 3:30", "row.timestamp_out_of_range"),  # day/month: 7 March
        ("2/7/2017 3:30", "row.timestamp_out_of_range"),
        ("8/7/2017 3:30", "row.timestamp_out_of_range"),
        ("7/7/2017 0:30", "row.timestamp_hour_unverified"),
        ("7/7/2017 6:30", "row.timestamp_hour_unverified"),
        ("7/7/2017 7:30", "row.timestamp_hour_unverified"),
        ("7/7/2017 13:30", "row.timestamp_hour_unverified"),
    ],
)
def test_questionable_timestamps_are_rejected(value: str, rule: str) -> None:
    assert rules(timestamp=value) == [(rule, "Timestamp")]


@pytest.mark.parametrize(
    "label",
    ["BENIGN", "DDoS", "PortScan", "Bot", "SSH-Patator", "DoS Hulk", "DoS GoldenEye", f"Web Attack {EN_DASH} Brute Force", "FTP-Patator"],
)
def test_known_labels_are_accepted(label: str) -> None:
    assert check(label=label) == []


@pytest.mark.parametrize("label", ["benign", "BENIGN ", "Web Attack - Brute Force", "Web Attack â€“ Brute Force", SECRET])
def test_unknown_labels_are_rejected(label: str) -> None:
    assert rules(label=label) == [("row.unknown_label", "Label")]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"source_ip": "192.0.2.300"}, ("row.invalid_ip", "Source IP")),
        ({"destination_ip": SECRET}, ("row.invalid_ip", "Destination IP")),
        ({"source_port": "65536"}, ("row.invalid_port", "Source Port")),
        ({"destination_port": "-1"}, ("row.invalid_port", "Destination Port")),
        ({"protocol": "256"}, ("row.invalid_protocol", "Protocol")),
        ({"protocol": "tcp"}, ("row.invalid_protocol", "Protocol")),
    ],
)
def test_addresses_ports_and_protocols_are_checked(overrides: dict[str, str], expected: tuple[str, str]) -> None:
    # Changing an endpoint also breaks Flow ID consistency; that is reported separately.
    assert expected in rules(**overrides)


def test_ipv6_addresses_and_protocol_zero_are_accepted() -> None:
    assert check(source_ip="2001:db8::1", flow_id="2001:db8::1-198.51.100.20-51515-443-0", protocol="0") == []


def test_fwd_header_length_mismatch_rejects_the_row() -> None:
    assert check(fwd_header_length="32", fwd_header_length_2="40") == [
        {
            "rule": "row.duplicate_column_mismatch",
            "message": "differs from Fwd Header Length (column 41)",
            "row": None,
            "column": "Fwd Header Length",
            "columnIndex": 62,
        }
    ]


@pytest.mark.parametrize(
    ("flow_id", "rule"),
    [
        ("192.0.2.10-198.51.100.20-51515-443", "row.invalid_flow_id"),
        ("192.0.2.10-198.51.100.20-51515-443-6-1", "row.invalid_flow_id"),
        ("192.0.2.10-198.51.100.20-51515-80-6", "row.flow_id_mismatch"),
        ("192.0.2.10-198.51.100.20-51515-443-17", "row.flow_id_mismatch"),
        ("198.51.100.20-192.0.2.10-51515-443-6", "row.flow_id_mismatch"),  # endpoints swapped, ports not
    ],
)
def test_flow_id_format_is_checked(flow_id: str, rule: str) -> None:
    assert rules(flow_id=flow_id) == [(rule, "Flow ID")]


def test_issues_never_contain_cell_values() -> None:
    issues = check(
        source_ip=SECRET, source_port=SECRET, protocol=SECRET, timestamp=SECRET, label=SECRET,
        flow_duration=SECRET, flow_id=SECRET, fwd_header_length_2=SECRET,
    )  # fmt: skip
    assert len(issues) >= 8
    assert SECRET not in str(issues)


# --- Whole files through the upload validator ---------------------------------------------------------


def test_windows_1252_label_and_mixed_line_endings_validate() -> None:
    content = csv_bytes(row(), row(label=f"Web Attack {EN_DASH} Brute Force"), newline="\r\n")
    content += (",".join(row(label="PortScan")) + "\n").encode("cp1252")
    assert b"\x96" in content

    report = validate(content)

    assert not report.file_rejected
    assert (report.total_rows, report.accepted_rows, report.rejected_rows) == (3, 3, 0)


def test_undefined_windows_1252_byte_rejects_the_file() -> None:
    content = csv_bytes(row()) + b"\x81\n"
    report = validate(content)
    assert report.file_rejected
    assert [issue["rule"] for issue in report.error_sample] == ["file.encoding"]


def test_utf8_encoded_dash_is_not_guessed() -> None:
    content = csv_bytes(row(label=f"Web Attack {EN_DASH} Brute Force"), encoding="utf-8")
    report = validate(content)
    assert (report.accepted_rows, report.rejected_rows) == (0, 1)
    assert [issue["rule"] for issue in report.error_sample] == ["row.unknown_label"]


def test_empty_records_count_as_rejected_rows() -> None:
    content = csv_bytes(row(), [""] * 85, [""] * 85)
    report = validate(content)
    assert (report.total_rows, report.accepted_rows, report.rejected_rows) == (3, 1, 2)
    assert [(issue["rule"], issue["row"]) for issue in report.error_sample] == [("row.empty_record", 3), ("row.empty_record", 4)]


def test_wrong_header_rejects_the_file_without_reading_rows() -> None:
    content = csv_bytes(row(), header=",".join(HEADER[:61] + HEADER[62:]))
    report = validate(content)
    assert report.file_rejected and report.total_rows == 0


# --- Upload API ------------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_import_rate_limit() -> Any:
    from app.services.dataset_import import import_user_limiter

    import_user_limiter.clear()
    yield
    import_user_limiter.clear()


def test_upload_validates_synthetic_cic_file_without_storing_rows(core_api: CoreApi) -> None:
    content = csv_bytes(row(), row(fwd_header_length_2="99"), [""] * 85, row(flow_bytes_s="Infinity"))
    response = core_api.client.post(
        "/api/imports",
        files={"file": ("cic-sample.csv", content, "text/csv")},
        data={"profile": "cic-ids2017"},
        headers=core_api.headers,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["status"], body["datasetProfile"], body["profileVersion"]) == ("VALIDATED", "cic-ids2017", "1")
    assert (body["totalRows"], body["acceptedRows"], body["rejectedRows"]) == (4, 2, 2)
    assert [issue["rule"] for issue in body["errorSample"]] == ["row.duplicate_column_mismatch", "row.empty_record"]
    with core_api.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 0
        assert session.scalar(select(func.count()).select_from(ImportBatch)) == 1


# --- Local profiler --------------------------------------------------------------------------------------


def test_profiler_reports_aggregates_only(tmp_path: Path) -> None:
    content = csv_bytes(
        row(),
        row(label=f"Web Attack {EN_DASH} Brute Force", flow_id="198.51.100.20-192.0.2.10-443-51515-6"),
        row(flow_bytes_s="Infinity", timestamp="03/07/2017 08:55:58"),
        row(fwd_header_length_2="40"),
        row(label=SECRET, flow_duration=SECRET),
        [""] * 85,
        newline="\r\n",
    )
    path = tmp_path / "synthetic.csv"
    path.write_bytes(content)

    result = dataset_profiler.profile_file(path, PROFILE)

    assert result.size_bytes == len(content)
    assert result.non_ascii_bytes == {0x96: 1}
    assert result.crlf_lines == 7 and result.lf_lines == 0
    assert not result.header_issues and result.stopped is None
    assert (result.records, result.accepted, result.rejected) == (6, 3, 3)
    assert result.issues[("row.empty_record", "")] == 1
    assert result.issues[("row.duplicate_column_mismatch", "Fwd Header Length")] == 1
    assert result.first_row[("row.duplicate_column_mismatch", "Fwd Header Length")] == 5
    facts = {name: dict(tally.counts) for name, tally in result.facts.items()}
    assert facts["fwd header length columns"] == {"equal": 4, "differ": 1}
    assert facts["flow id order"] == {"source columns first": 4, "destination columns first": 1}
    assert facts["timestamp hour (as written)"] == {"03": 4, "08": 1}
    assert facts["timestamp date (day/month/year)"] == {"2017-07-07": 4, "2017-07-03": 1}
    assert facts["non-finite values"] == {"Flow Bytes/s = Infinity": 1}
    assert facts["negative values"] == {"Flow IAT Min": 5}
    # Unknown labels are listed as categories; free-text numeric cells are never printed.
    assert facts["label"][f"[unknown] {SECRET}"] == 1
    serialized = str(dataset_profiler.file_json(result))
    assert serialized.count(SECRET) == 1


def test_profiler_tallies_are_bounded() -> None:
    tally = dataset_profiler.BoundedTally(limit=2)
    for key in ("a", "b", "c", "a", "d"):
        tally.add(key)
    assert tally.counts == {"a": 2, "b": 1}
    assert tally.overflow == 2


def test_profiler_rejects_non_csv_paths(tmp_path: Path) -> None:
    other = tmp_path / "notes.txt"
    other.write_text("x")
    with pytest.raises(SystemExit):
        dataset_profiler.collect_paths([str(other)])


# --- Opt-in check against the real dataset (header only) --------------------------------------------------


@pytest.mark.skipif(not os.environ.get("NETRA_CIC_DATASET_DIR"), reason="set NETRA_CIC_DATASET_DIR to check local files")
def test_real_dataset_headers_match_the_profile() -> None:
    folder = Path(os.environ["NETRA_CIC_DATASET_DIR"])
    files = sorted(folder.glob("*.csv"))
    assert files
    for path in files:
        with path.open("rb") as stream:
            header = stream.readline().decode("cp1252").rstrip("\r\n").split(",")
        assert PROFILE.check_header(header) == [], path.name
