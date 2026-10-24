"""ThreatFox client and mapping: mocked HTTP only (httpx.MockTransport), synthetic records, no database.

The key used here is a dummy; no test needs a real ThreatFox key or network access.
"""

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from app.models.enums import IndicatorType
from app.services import threatfox
from app.services.threatfox import (
    MAX_RESPONSE_BYTES,
    THREATFOX_API_URL,
    ThreatFoxError,
    fetch_recent_iocs,
    map_iocs,
    parse_response_body,
    parse_timestamp,
)

DUMMY_KEY = "dummy-threatfox-key-for-tests"


def record(ioc_type: str, ioc: str, **extra: Any) -> dict[str, Any]:
    base = {
        "id": "1",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_type": "botnet_cc",
        "malware": "win.example",
        "confidence_level": 75,
        "first_seen": "2026-10-23 10:00:00 UTC",
        "last_seen": None,
        "tags": ["example"],
        # Only an explicit boolean false is imported (fail closed); tests override it where relevant.
        "is_compromised": False,
    }
    return {**base, **extra}


def client_returning(status: int = 200, body: Any = None, *, raw: bytes | None = None, seen: list[httpx.Request] | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        content = raw if raw is not None else json.dumps(body).encode()
        return httpx.Response(status, content=content)

    return httpx.Client(transport=httpx.MockTransport(handler))


def client_raising(error: Exception) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    return httpx.Client(transport=httpx.MockTransport(handler))


def expect_error(kind: str, client: httpx.Client, **kwargs: Any) -> ThreatFoxError:
    with pytest.raises(ThreatFoxError) as caught:
        fetch_recent_iocs(kwargs.pop("key", DUMMY_KEY), kwargs.pop("days", 1), client=client)
    assert caught.value.kind == kind
    assert DUMMY_KEY not in str(caught.value)
    return caught.value


# --- client ---------------------------------------------------------------------------------------


def test_successful_retrieval_sends_the_documented_request() -> None:
    seen: list[httpx.Request] = []
    data = [record("domain", "evil.example"), record("ip:port", "8.8.4.4:443")]
    records = fetch_recent_iocs(DUMMY_KEY, 1, client=client_returning(body={"query_status": "ok", "data": data}, seen=seen))
    assert records == data
    [request] = seen
    assert request.method == "POST"
    assert str(request.url) == THREATFOX_API_URL
    assert request.headers["Auth-Key"] == DUMMY_KEY
    assert json.loads(request.content) == {"query": "get_iocs", "days": 1}
    # The key travels only in the Auth-Key header, never in the URL or body.
    assert DUMMY_KEY not in str(request.url) and DUMMY_KEY.encode() not in request.content


def test_empty_results() -> None:
    assert fetch_recent_iocs(DUMMY_KEY, 1, client=client_returning(body={"query_status": "no_result", "data": "Your search did not yield any results"})) == []
    assert fetch_recent_iocs(DUMMY_KEY, 1, client=client_returning(body={"query_status": "ok", "data": []})) == []


def test_missing_key_fails_before_any_request() -> None:
    seen: list[httpx.Request] = []
    for key in (None, ""):
        error = expect_error("not_configured", client_returning(body={}, seen=seen), key=key)
        assert "THREATFOX_AUTH_KEY" in str(error)
    assert seen == []


def test_days_outside_the_api_window_are_refused_before_any_request() -> None:
    seen: list[httpx.Request] = []
    for days in (0, 8, -1):
        expect_error("api", client_returning(body={}, seen=seen), days=days)
    assert seen == []


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_errors_by_http_status(status: int) -> None:
    expect_error("auth", client_returning(status, body={"query_status": "unknown_auth_key"}))


@pytest.mark.parametrize("token", ["unknown_auth_key", "illegal_auth_key"])
def test_authentication_errors_by_query_status(token: str) -> None:
    error = expect_error("auth", client_returning(body={"query_status": token}))
    assert token in str(error)


def test_api_errors_report_only_a_safe_status_token() -> None:
    assert "illegal_search_term" in str(expect_error("api", client_returning(body={"query_status": "illegal_search_term"})))
    leaked = expect_error("api", client_returning(body={"query_status": f"<html>{DUMMY_KEY}</html>"}))
    assert "unexpected" in str(leaked)


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_other_http_errors(status: int) -> None:
    assert str(status) in str(expect_error("http", client_returning(status, body={})))


def test_timeouts_and_network_failures() -> None:
    expect_error("timeout", client_raising(httpx.ReadTimeout("slow")))
    expect_error("timeout", client_raising(httpx.ConnectTimeout("slow")))
    expect_error("network", client_raising(httpx.ConnectError(f"refused {DUMMY_KEY}")))


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b'"ok"', json.dumps({"query_status": "ok"}).encode(), json.dumps({"query_status": "ok", "data": {}}).encode(), b"\xff\xfe"],
)
def test_malformed_responses(raw: bytes) -> None:
    expect_error("malformed", client_returning(raw=raw))


def test_oversized_responses_are_refused() -> None:
    expect_error("too_large", client_returning(raw=b" " * (MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(ThreatFoxError) as caught:
        parse_response_body(b" " * (MAX_RESPONSE_BYTES + 1))
    assert caught.value.kind == "too_large"


def test_the_client_module_reads_no_settings_and_opens_no_database() -> None:
    # The caller passes the key; the client never reads configuration or touches the database.
    imports = [line for line in open(threatfox.__file__, encoding="utf-8") if line.startswith(("import ", "from "))]
    assert not [line for line in imports if "app.core.config" in line or "app.db" in line or "sqlalchemy" in line]


# --- mapping --------------------------------------------------------------------------------------


def test_supported_types_map_to_existing_indicator_types() -> None:
    result = map_iocs(
        [
            record("ip:port", "8.8.4.4:443"),
            record("ip:port", "[2001:4860:4860::8888]:8080"),
            record("domain", "Evil.Example."),
            record("url", "HTTP://Evil.Example/Path/"),
            record("md5_hash", "D41D8CD98F00B204E9800998ECF8427E"),
            record("sha1_hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            record("sha256_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ]
    )
    assert result.received == 7 and not result.skipped
    assert [(c.indicator_type, c.value) for c in result.indicators] == [
        (IndicatorType.IP, "8.8.4.4"),
        (IndicatorType.IP, "2001:4860:4860::8888"),
        (IndicatorType.DOMAIN, "evil.example"),
        (IndicatorType.URL, "http://evil.example/path"),
        (IndicatorType.HASH, "d41d8cd98f00b204e9800998ecf8427e"),
        (IndicatorType.HASH, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (IndicatorType.HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ]


def test_values_are_normalised_the_way_correlation_matches_them() -> None:
    from app.services.context_enrichment import _normalize_domain

    [domain] = map_iocs([record("domain", "MiXeD.Example.")]).indicators
    assert domain.value == _normalize_domain("MiXeD.Example.")
    [url] = map_iocs([record("url", "https://Example.org/A/")]).indicators
    # Correlation case-folds event URLs and strips a trailing "/" before comparing.
    assert url.value == "https://Example.org/A/".rstrip("/").casefold()


def test_unsupported_and_invalid_records_are_skipped_not_coerced() -> None:
    result = map_iocs(
        [
            record("ip:port", "10.0.0.5:443"),
            record("ip:port", "127.0.0.1:80"),
            record("ip:port", "192.168.1.1:8080"),
            record("ip:port", "8.8.8.8"),
            record("ip:port", "8.8.8.8:70000"),
            record("ip:port", "not-an-ip:443"),
            record("domain", "bad domain"),
            record("domain", "8.8.8.8"),
            record("url", "ftp://evil.example/file"),
            record("url", "evil.example/no-scheme"),
            record("md5_hash", "abc"),
            record("sha256_hash", "z" * 64),
            record("envelope_from", "a@b.example"),
            record("cve", "CVE-2024-0001"),
            {"ioc": "x"},
            "not a record",
            record("domain", "a" * 2050),
        ]
    )
    assert result.indicators == []
    assert result.skipped == {
        "non_public_ip": 3,
        "invalid_value": 9,
        "unsupported_type": 2,
        "malformed_record": 2,
        "value_too_long": 1,
    }


def test_confidence_is_threatfox_level_over_100_or_unknown() -> None:
    def confidence(level: Any) -> float | None:
        return map_iocs([record("domain", "c.example", confidence_level=level)]).indicators[0].confidence

    assert confidence(75) == 0.75
    assert confidence(100) == 1.0
    assert confidence(0) == 0.0
    for unusable in (None, "75", 101, -1, True):
        assert confidence(unusable) is None


def test_timestamps_are_utc_and_last_seen_falls_back_to_first_seen() -> None:
    [only_first] = map_iocs([record("domain", "t.example", first_seen="2026-10-23 10:00:00 UTC", last_seen=None)]).indicators
    assert only_first.first_seen == only_first.last_seen == datetime(2026, 10, 23, 10, tzinfo=UTC)
    [both] = map_iocs([record("domain", "u.example", first_seen="2026-10-20 08:00:00 UTC", last_seen="2026-10-23 09:30:00 UTC")]).indicators
    assert both.last_seen == datetime(2026, 10, 23, 9, 30, tzinfo=UTC)
    assert parse_timestamp("2026-10-23T10:00:00+05:30") == datetime(2026, 10, 23, 4, 30, tzinfo=UTC)
    for bad in (None, "", "yesterday", 12345):
        assert parse_timestamp(bad) is None
    skipped = map_iocs([record("domain", "v.example", first_seen="soon"), record("domain", "w.example", last_seen="later")])
    assert skipped.skipped == {"invalid_timestamp": 2}


def test_duplicates_are_merged_by_type_and_value() -> None:
    result = map_iocs(
        [
            record("ip:port", "8.8.4.4:443", confidence_level=50, first_seen="2026-10-23 10:00:00 UTC"),
            record("ip:port", "8.8.4.4:8443", confidence_level=90, first_seen="2026-10-22 10:00:00 UTC", last_seen="2026-10-23 12:00:00 UTC"),
        ]
    )
    [merged] = result.indicators
    assert (merged.value, merged.confidence) == ("8.8.4.4", 0.9)
    assert merged.first_seen == datetime(2026, 10, 22, 10, tzinfo=UTC)
    assert merged.last_seen == datetime(2026, 10, 23, 12, tzinfo=UTC)


# --- is_compromised, counts and timestamp trust ---------------------------------------------------

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def without_flag(ioc_type: str, ioc: str) -> dict[str, Any]:
    entry = record(ioc_type, ioc)
    del entry["is_compromised"]
    return entry


def test_only_an_explicit_false_flag_is_imported() -> None:
    result = map_iocs(
        [
            record("domain", "hijacked.example", is_compromised=True),
            record("ip:port", "8.8.4.4:443", is_compromised=True),
            record("domain", "evil.example", is_compromised=False),
            record("domain", "null.example", is_compromised=None),
            without_flag("domain", "absent.example"),
            record("domain", "odd.example", is_compromised="yes"),
            # Compromised and invalid: the compromised flag decides the reason.
            record("md5_hash", "abc", is_compromised=True),
        ],
        now=NOW,
    )
    assert result.skipped == {"compromised_asset": 3, "compromised_flag_missing": 2, "compromised_flag_unrecognized": 1}
    assert result.compromised == {"true": 3, "false": 1, "missing": 2, "unrecognized": 1}
    assert [c.value for c in result.indicators] == ["evil.example"]


@pytest.mark.parametrize(
    ("value", "flag", "reason"),
    [
        (True, "true", "compromised_asset"),
        (None, "missing", "compromised_flag_missing"),
        ("true", "unrecognized", "compromised_flag_unrecognized"),
        ("false", "unrecognized", "compromised_flag_unrecognized"),
        (1, "unrecognized", "compromised_flag_unrecognized"),
        (0, "unrecognized", "compromised_flag_unrecognized"),
        ([], "unrecognized", "compromised_flag_unrecognized"),
        ({"value": False}, "unrecognized", "compromised_flag_unrecognized"),
    ],
)
def test_anything_but_boolean_false_is_skipped(value: Any, flag: str, reason: str) -> None:
    result = map_iocs([record("domain", "flag.example", is_compromised=value)], now=NOW)
    assert result.indicators == []
    assert result.compromised == {flag: 1}
    assert result.skipped == {reason: 1}


def test_boolean_false_is_imported() -> None:
    result = map_iocs([record("domain", "ok.example", is_compromised=False)], now=NOW)
    assert [c.value for c in result.indicators] == ["ok.example"] and result.compromised == {"false": 1}


def test_received_and_mapped_counts_by_type() -> None:
    result = map_iocs(
        [
            record("ip:port", "8.8.4.4:443"),
            record("ip:port", "8.8.4.4:8080"),  # same address: merged into one indicator
            record("sha256_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            record("md5_hash", "d41d8cd98f00b204e9800998ecf8427e"),
            record("domain", "evil.example", is_compromised=True),
            record("Weird Type!", "x"),
        ],
        now=NOW,
    )
    assert result.received_types == {"ip:port": 2, "sha256_hash": 1, "md5_hash": 1, "domain": 1, "<other>": 1}
    assert result.mapped_types() == {"ip": 1, "hash": 2}
    assert result.received == 6 and len(result.indicators) == 3
    assert result.skipped == {"compromised_asset": 1, "unsupported_type": 1}


def test_skipped_duplicates_neither_add_to_nor_suppress_a_valid_record() -> None:
    for skipped in (
        record("ip:port", "8.8.4.4:80", confidence_level=100, is_compromised=True),
        record("ip:port", "8.8.4.4:81", confidence_level=100, is_compromised=None),
        record("ip:port", "8.8.4.4:82", confidence_level=100, is_compromised="true"),
    ):
        valid = record("ip:port", "8.8.4.4:443", confidence_level=50, is_compromised=False)
        for order in ([skipped, valid], [valid, skipped]):
            [only] = map_iocs(order, now=NOW).indicators
            assert (only.value, only.confidence) == ("8.8.4.4", 0.5)  # the skipped duplicate contributes nothing


def test_future_timestamps_are_rejected_beyond_one_day_of_skew() -> None:
    def outcome(first: str, last: str | None = None):  # type: ignore[no-untyped-def]
        result = map_iocs([record("domain", "f.example", first_seen=first, last_seen=last)], now=NOW)
        return result.skipped or len(result.indicators)

    assert outcome("2026-10-25 12:00:00 UTC") == 1  # exactly now + 24h: accepted
    assert outcome("2026-10-25 12:00:01 UTC") == {"future_timestamp": 1}
    assert outcome("2026-10-20 12:00:00 UTC", "2026-11-30 00:00:00 UTC") == {"future_timestamp": 1}


def test_records_without_usable_timestamps_are_never_mapped() -> None:
    result = map_iocs([record("domain", "a.example", first_seen=None), record("domain", "b.example", first_seen="")], now=NOW)
    assert result.indicators == [] and result.skipped == {"invalid_timestamp": 2}
