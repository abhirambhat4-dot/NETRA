"""Dataset import API tests (PostgreSQL schema per test, always rolled back).

The ``test-flows`` profile below is synthetic: it exercises the profile interface only. The
CIC-IDS2017 profile has its own tests in test_cic_ids2017_profile.py.
"""

import hashlib
from collections.abc import Iterator, Mapping
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.api import imports as imports_api
from app.core.config import get_settings
from app.models import Asset, Incident, ImportBatch, SecurityAssessment, SecurityEvent, User
from app.models.enums import ImportBatchStatus
from app.services import dataset_import
from app.services.auth import create_access_token
from app.services.dataset_import import MAX_ERROR_SAMPLE, import_user_limiter
from app.services.dataset_profiles import PROFILES, DatasetProfile, ValidationIssue
from tests.conftest import CoreApi

IMPORTS = "/api/imports"
SECRET = "SECRET-CELL-7f3a9"


class SyntheticFlowProfile(DatasetProfile):
    identifier = "test-flows"
    version = "1"
    title = "Synthetic test profile"
    required_columns = ("alpha", "beta")

    def check_row(self, values: Mapping[str, str]) -> list[ValidationIssue]:
        issues = []
        if not values["alpha"].strip().isdigit():
            issues.append(ValidationIssue("row.not_integer", "must be a non-negative integer", column="alpha"))
        if not values["beta"].strip():
            issues.append(ValidationIssue("row.required", "must not be empty", column="beta"))
        return issues


@pytest.fixture(autouse=True)
def import_test_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setitem(PROFILES, SyntheticFlowProfile.identifier, SyntheticFlowProfile())
    import_user_limiter.clear()
    yield
    import_user_limiter.clear()


def upload(
    api: CoreApi,
    content: bytes,
    *,
    profile: str | None = "generic-csv",
    filename: str = "sample.csv",
    content_type: str = "text/csv",
    headers: dict[str, str] | None = None,
) -> Any:
    data = {"profile": profile} if profile is not None else {}
    return api.client.post(
        IMPORTS,
        files={"file": (filename, content, content_type)},
        data=data,
        headers=api.headers if headers is None else headers,
    )


def other_user_headers(api: CoreApi) -> dict[str, str]:
    with api.session_factory() as session:
        user = User(email=f"other-{uuid4().hex[:8]}@example.com", full_name="Other", password_hash="unused")
        session.add(user)
        session.commit()
        return {"Authorization": f"Bearer {create_access_token(user)}"}


def batch_count(api: CoreApi) -> int:
    with api.session_factory() as session:
        return int(session.scalar(select(func.count()).select_from(ImportBatch)) or 0)


VALID_CSV = b"alpha,beta\n1,x\n2,y\n"


# --- Authentication and request shape --------------------------------------------------------------


def test_endpoints_require_authentication(core_api: CoreApi) -> None:
    assert upload(core_api, VALID_CSV, headers={}).status_code == 401
    assert upload(core_api, VALID_CSV, headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    assert core_api.client.get(IMPORTS).status_code == 401
    assert core_api.client.get(f"{IMPORTS}/{uuid4()}").status_code == 401
    assert batch_count(core_api) == 0


def test_valid_csv_is_validated_and_recorded_without_storing_rows(core_api: CoreApi) -> None:
    response = upload(core_api, VALID_CSV, filename="C:\\fakepath\\flows.csv")

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "VALIDATED"
    assert body["datasetProfile"] == "generic-csv"
    assert body["profileVersion"] == "1"
    assert body["originalFilename"] == "flows.csv"
    assert body["fileSha256"] == hashlib.sha256(VALID_CSV).hexdigest()
    assert body["fileSizeBytes"] == len(VALID_CSV)
    assert (body["totalRows"], body["acceptedRows"], body["rejectedRows"], body["errorTotal"]) == (2, 2, 0, 0)
    assert body["errorSample"] == [] and body["errorSampleTruncated"] is False
    assert body["completedAt"] is not None

    with core_api.session_factory() as session:
        batch = session.scalars(select(ImportBatch)).one()
        assert batch.status == ImportBatchStatus.VALIDATED
        assert batch.uploaded_by_id is not None
        for model in (SecurityEvent, Incident, Asset, SecurityAssessment):
            assert session.scalar(select(func.count()).select_from(model)) == 0


@pytest.mark.parametrize(
    ("filename", "content_type"),
    [("flows.txt", "text/csv"), ("flows", "text/csv"), ("flows.csv", "image/png"), ("flows.csv", "application/pdf")],
)
def test_non_csv_files_are_unsupported(core_api: CoreApi, filename: str, content_type: str) -> None:
    response = upload(core_api, VALID_CSV, filename=filename, content_type=content_type)
    assert response.status_code == 415
    assert batch_count(core_api) == 0


def test_non_multipart_body_is_unsupported(core_api: CoreApi) -> None:
    response = core_api.client.post(IMPORTS, json={"profile": "generic-csv"}, headers=core_api.headers)
    assert response.status_code == 415


@pytest.mark.parametrize("profile", [None, "", "   ", "cic-ids2018", "../etc/passwd", "x" * 500])
def test_missing_or_unknown_profile_is_rejected_without_echo(core_api: CoreApi, profile: str | None) -> None:
    response = upload(core_api, VALID_CSV, profile=profile)
    assert response.status_code == 422
    if profile and profile.strip():
        assert profile.strip() not in response.text
    assert batch_count(core_api) == 0


def test_extra_fields_and_multiple_files_are_rejected(core_api: CoreApi) -> None:
    extra = core_api.client.post(
        IMPORTS,
        files={"file": ("a.csv", VALID_CSV, "text/csv")},
        data={"profile": "generic-csv", "note": "x"},
        headers=core_api.headers,
    )
    assert extra.status_code == 422
    two_files = core_api.client.post(
        IMPORTS,
        files=[("file", ("a.csv", VALID_CSV, "text/csv")), ("file", ("b.csv", VALID_CSV, "text/csv"))],
        data={"profile": "generic-csv"},
        headers=core_api.headers,
    )
    assert two_files.status_code == 422
    missing_file = core_api.client.post(
        IMPORTS, data={"profile": "generic-csv"}, files={"other": ("a.csv", b"", "text/csv")}, headers=core_api.headers
    )
    assert missing_file.status_code == 422
    assert batch_count(core_api) == 0


# --- File-level validation ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "rule"),
    [
        (b"", "header.missing"),
        (b"alpha,beta\n", "file.no_rows"),
        (b"alpha,beta\n\n\n", "file.no_rows"),
        (b"alpha,beta\n1,\x00" + SECRET.encode() + b"\n", "file.not_text"),
        (b"alpha,beta\n1,\xff\xfe" + SECRET.encode() + b"\n", "file.encoding"),
        (b'alpha,beta\n1,"' + SECRET.encode() + b'"trailing\n', "file.malformed"),
    ],
)
def test_unreadable_files_are_recorded_as_rejected(core_api: CoreApi, content: bytes, rule: str) -> None:
    response = upload(core_api, content)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "REJECTED"
    assert [issue["rule"] for issue in body["errorSample"]] == [rule]
    assert SECRET not in response.text


def test_overlong_lines_are_rejected(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dataset_import, "MAX_LINE_CHARACTERS", 40)
    response = upload(core_api, b"alpha,beta\n1,2\n3," + b"9" * 60 + b"\n")

    body = response.json()
    assert body["status"] == "REJECTED"
    assert body["errorSample"] == [
        {"rule": "file.line_too_long", "message": "line is longer than 40 characters", "row": 3, "column": None, "columnIndex": None}
    ]


# --- Profile header and row validation --------------------------------------------------------------


def test_header_profile_mismatch_rejects_the_file(core_api: CoreApi) -> None:
    response = upload(core_api, b"alpha," + SECRET.encode() + b"\n1,2\n", profile="test-flows")

    body = response.json()
    assert response.status_code == 201
    assert body["status"] == "REJECTED"
    assert body["totalRows"] == 0
    assert body["errorSample"] == [
        {"rule": "header.missing_column", "message": "required column is missing", "row": 1, "column": "beta", "columnIndex": None}
    ]
    assert SECRET not in response.text


def test_header_problems_name_positions_not_file_text(core_api: CoreApi) -> None:
    header = f"Alpha,beta,{SECRET},,{SECRET.lower()}\n".encode()
    response = upload(core_api, header + b"1,2,3,4,5\n", profile="test-flows")

    body = response.json()
    assert body["status"] == "REJECTED"
    assert [(issue["rule"], issue["columnIndex"], issue["column"]) for issue in body["errorSample"]] == [
        ("header.empty_column", 4, None),
        ("header.duplicate_column", 5, None),
    ]
    assert SECRET not in response.text and SECRET.lower() not in response.text


def test_row_errors_report_row_column_and_rule_without_cell_contents(core_api: CoreApi) -> None:
    content = (
        "alpha,beta,extra\n"
        "1,ok,x\n"
        f"{SECRET},ok,x\n"  # row 3: alpha not an integer
        "\n"  # row 4: blank, skipped but still numbered
        f"2,,{SECRET}\n"  # row 5: beta empty
        f"3,{SECRET}\n"  # row 6: wrong field count
    ).encode()
    response = upload(core_api, content, profile="test-flows")

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "VALIDATED"
    assert (body["totalRows"], body["acceptedRows"], body["rejectedRows"], body["errorTotal"]) == (4, 1, 3, 3)
    assert [(issue["row"], issue["column"], issue["rule"]) for issue in body["errorSample"]] == [
        (3, "alpha", "row.not_integer"),
        (5, "beta", "row.required"),
        (6, None, "row.column_count"),
    ]
    assert body["errorSample"][2]["message"] == "row has 2 fields; the header has 3"

    detail = core_api.client.get(f"{IMPORTS}/{body['id']}", headers=core_api.headers)
    listing = core_api.client.get(IMPORTS, headers=core_api.headers)
    for text in (response.text, detail.text, listing.text):
        assert SECRET not in text
    with core_api.session_factory() as session:
        assert SECRET not in str(session.scalars(select(ImportBatch.error_sample)).one())
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 0


def test_error_sample_is_capped_but_counted(core_api: CoreApi) -> None:
    rows = "".join(f"bad{index},x\n" for index in range(MAX_ERROR_SAMPLE + 25))
    response = upload(core_api, f"alpha,beta\n{rows}".encode(), profile="test-flows")

    body = response.json()
    assert body["errorTotal"] == MAX_ERROR_SAMPLE + 25
    assert len(body["errorSample"]) == MAX_ERROR_SAMPLE
    assert body["errorSampleTruncated"] is True


# --- Limits -------------------------------------------------------------------------------------------------


def test_file_over_byte_limit_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "import_max_upload_bytes", 64)
    content = b"alpha,beta\n" + b"1,2\n" * 30  # 131 bytes: under the request cap, over the file cap

    response = upload(core_api, content)

    assert response.status_code == 413
    assert response.json()["detail"] == "File exceeds the upload limit of 64 bytes"
    assert batch_count(core_api) == 0


def test_declared_body_over_limit_is_refused_before_reading(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "import_max_upload_bytes", 64)
    response = upload(core_api, b"alpha,beta\n" + b"1,2\n" * 30_000)
    assert response.status_code == 413
    assert batch_count(core_api) == 0


def test_streamed_body_over_limit_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "import_max_upload_bytes", 64)
    boundary = "netra-test-boundary"
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="profile"\r\n\r\ngeneric-csv\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="big.csv"\r\n'
        "Content-Type: text/csv\r\n\r\nalpha,beta\n"
    ).encode()

    def chunked_body() -> Iterator[bytes]:  # no Content-Length: the stream cap must apply
        yield head
        for _ in range(200):
            yield b"1,2\n" * 256
        yield f"\r\n--{boundary}--\r\n".encode()

    response = core_api.client.post(
        IMPORTS,
        content=chunked_body(),
        headers={**core_api.headers, "Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert response.status_code == 413
    assert batch_count(core_api) == 0


def test_row_limit_is_enforced(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "import_max_rows", 3)

    at_limit = upload(core_api, b"alpha,beta\n1,2\n3,4\n5,6\n\n")
    over_limit = upload(core_api, b"alpha,beta\n1,2\n3,4\n5,6\n7,8\n")

    assert at_limit.status_code == 201 and at_limit.json()["totalRows"] == 3
    assert over_limit.status_code == 413
    assert over_limit.json()["detail"] == "File has more than 3 data rows"
    assert batch_count(core_api) == 1


def test_uploads_are_rate_limited_per_user(core_api: CoreApi) -> None:
    for _ in range(10):
        assert upload(core_api, b"").status_code == 201  # rejected files can be retried
    assert upload(core_api, b"").status_code == 429


# --- Duplicates ---------------------------------------------------------------------------------------------


def test_duplicate_validated_file_is_refused(core_api: CoreApi) -> None:
    first = upload(core_api, VALID_CSV, filename="one.csv")
    second = upload(core_api, VALID_CSV, filename="renamed.csv")

    assert first.status_code == 201
    assert second.status_code == 409
    assert first.json()["id"] in second.json()["detail"]
    assert batch_count(core_api) == 1


def test_duplicate_detail_hides_other_users_batch(core_api: CoreApi) -> None:
    first = upload(core_api, VALID_CSV)
    second = upload(core_api, VALID_CSV, headers=other_user_headers(core_api))

    assert second.status_code == 409
    assert first.json()["id"] not in second.json()["detail"]


def test_rejected_files_do_not_block_retries_and_profiles_are_independent(core_api: CoreApi) -> None:
    assert upload(core_api, b"alpha,beta\n").json()["status"] == "REJECTED"
    assert upload(core_api, b"alpha,beta\n").json()["status"] == "REJECTED"
    assert upload(core_api, VALID_CSV, profile="generic-csv").status_code == 201
    assert upload(core_api, VALID_CSV, profile="test-flows").status_code == 201
    assert batch_count(core_api) == 4


def test_concurrent_duplicate_is_caught_by_unique_index(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    first = upload(core_api, VALID_CSV)
    # Simulate a racing request whose pre-check ran before the first upload committed.
    monkeypatch.setattr(imports_api, "find_validated_batch", lambda *_args: None)

    second = upload(core_api, VALID_CSV)

    assert second.status_code == 409
    assert first.json()["id"] in second.json()["detail"]
    assert batch_count(core_api) == 1


# --- History --------------------------------------------------------------------------------------------------


def test_history_is_paginated_and_limited_to_the_uploader(core_api: CoreApi) -> None:
    ids = [upload(core_api, f"alpha,beta\n{index},x\n".encode()).json()["id"] for index in range(3)]

    first_page = core_api.client.get(IMPORTS, params={"pageSize": 2}, headers=core_api.headers).json()
    second_page = core_api.client.get(IMPORTS, params={"pageSize": 2, "page": 2}, headers=core_api.headers).json()
    assert first_page["total"] == 3 and first_page["pageSize"] == 2
    assert [item["id"] for item in first_page["items"] + second_page["items"]] == list(reversed(ids))
    assert "errorSample" not in first_page["items"][0]

    other = other_user_headers(core_api)
    assert core_api.client.get(IMPORTS, headers=other).json()["total"] == 0
    assert core_api.client.get(f"{IMPORTS}/{ids[0]}", headers=other).status_code == 404
    assert core_api.client.get(f"{IMPORTS}/{uuid4()}", headers=core_api.headers).status_code == 404
    assert core_api.client.get(f"{IMPORTS}/{ids[0]}", headers=core_api.headers).status_code == 200


def test_temporary_upload_files_are_closed_on_success_and_failure(
    core_api: CoreApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    original = imports_api._upload_from_form

    def capture(form: Any) -> Any:
        result = original(form)
        seen.append(result.file.file)
        return result

    monkeypatch.setattr(imports_api, "_upload_from_form", capture)
    assert upload(core_api, VALID_CSV).status_code == 201
    monkeypatch.setattr(get_settings(), "import_max_upload_bytes", 8)
    assert upload(core_api, VALID_CSV + b"3,z\n").status_code == 413

    assert len(seen) == 2 and all(file.closed for file in seen)


def test_long_filenames_keep_their_extension(core_api: CoreApi) -> None:
    response = upload(core_api, VALID_CSV, filename="../../" + "n" * 400 + ".csv")
    name = response.json()["originalFilename"]
    assert len(name) == 255 and name.endswith(".csv") and "/" not in name
