"""ThreatFox (abuse.ch) client and indicator mapping.

ThreatFox is queried with ``get_iocs`` for indicators reported in the last 1-7 days; it is a recent-history
feed, not a real-time stream. Records are mapped onto NETRA's existing ``threat_indicators`` types only:

- ``ip:port``   -> ``ip``    (the address; the port has no column and is not stored)
- ``domain``    -> ``domain`` (normalised exactly as event correlation normalises domains)
- ``url``       -> ``url``   (http/https only, case-folded, trailing "/" removed, as correlation matches)
- ``md5_hash`` / ``sha1_hash`` / ``sha256_hash`` -> ``hash`` (lower-case hex of the exact length)

Anything else is skipped and counted, never coerced into a type with a different meaning. Addresses that
are not publicly routable are rejected so a feed entry can never match an internal asset.

Fail closed on ``is_compromised``: only records whose flag is exactly boolean ``false`` are imported. ``true``
(a legitimate asset that was compromised) is skipped as ``compromised_asset``; a missing or null flag as
``compromised_flag_missing``; any other value (``"true"``, ``1``, ``0``, ...) as ``compromised_flag_unrecognized``.
Flag values are counted, never logged. Skipped records are dropped before duplicates are merged, so they can
neither add to nor suppress a valid record for the same indicator.
Timestamps more than ``MAX_FUTURE_SKEW`` ahead of now are rejected: an expiry policy keyed on them must not
be kept alive by a bad date.

This module has no database or settings imports: the caller passes the key, so it never reads or logs
configuration, and the key appears only in the request header. Error messages never include the key.
"""

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.models.enums import IndicatorType
from app.services.context_enrichment import _normalize_domain

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
#: Attribution stored on every indicator; also the scope of every write the sync makes.
THREATFOX_SOURCE = "ThreatFox (abuse.ch)"
MIN_DAYS, MAX_DAYS = 1, 7
REQUEST_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_VALUE_LENGTH = 2048
MAX_FUTURE_SKEW = timedelta(hours=24)

HASH_LENGTHS = {"md5_hash": 32, "sha1_hash": 40, "sha256_hash": 64}
HEX = re.compile(r"^[0-9a-f]+$")
# query_status values are short API tokens; anything else is reported as "unexpected".
STATUS_TOKEN = re.compile(r"^[a-z_]{1,40}$")


class ThreatFoxError(Exception):
    """A failed ThreatFox request. ``kind`` is one of: not_configured, auth, timeout, network, http,
    api, malformed, too_large. The message never contains the API key or response body."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def fetch_recent_iocs(api_key: str | None, days: int = 1, *, client: httpx.Client | None = None) -> list[Any]:
    """POST ``{"query": "get_iocs", "days": days}`` and return the raw ``data`` records (empty on no_result)."""
    if not api_key:
        raise ThreatFoxError("not_configured", "THREATFOX_AUTH_KEY is not set")
    if not isinstance(days, int) or not MIN_DAYS <= days <= MAX_DAYS:
        raise ThreatFoxError("api", f"days must be an integer from {MIN_DAYS} to {MAX_DAYS}")

    owned = client is None
    http = client or httpx.Client(timeout=REQUEST_TIMEOUT)
    try:
        with http.stream(
            "POST",
            THREATFOX_API_URL,
            headers={"Auth-Key": api_key, "Accept": "application/json"},
            json={"query": "get_iocs", "days": days},
            timeout=REQUEST_TIMEOUT,
        ) as response:
            if response.status_code in (401, 403):
                raise ThreatFoxError("auth", f"ThreatFox rejected the API key (HTTP {response.status_code})")
            if not 200 <= response.status_code < 300:
                raise ThreatFoxError("http", f"ThreatFox returned HTTP {response.status_code}")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ThreatFoxError("too_large", f"ThreatFox response exceeded {MAX_RESPONSE_BYTES} bytes")
    except httpx.TimeoutException:
        raise ThreatFoxError("timeout", "ThreatFox request timed out") from None
    except httpx.HTTPError as error:
        # Exception type only: messages can echo request details.
        raise ThreatFoxError("network", f"ThreatFox request failed ({type(error).__name__})") from None
    finally:
        if owned:
            http.close()
    return parse_response_body(bytes(body))


def parse_response_body(body: bytes) -> list[Any]:
    """The ``data`` records of a ``get_iocs`` response body (empty on no_result); also used for fixtures."""
    if len(body) > MAX_RESPONSE_BYTES:
        raise ThreatFoxError("too_large", f"ThreatFox response exceeded {MAX_RESPONSE_BYTES} bytes")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ThreatFoxError("malformed", "ThreatFox response is not valid JSON") from None
    if not isinstance(payload, dict):
        raise ThreatFoxError("malformed", "ThreatFox response is not a JSON object")

    status = payload.get("query_status")
    if status == "ok":
        data = payload.get("data")
        if not isinstance(data, list):
            raise ThreatFoxError("malformed", "ThreatFox response has no data list")
        return data
    if status == "no_result":
        return []
    token = status if isinstance(status, str) and STATUS_TOKEN.fullmatch(status) else "unexpected"
    if "auth" in token:
        raise ThreatFoxError("auth", f"ThreatFox rejected the API key ({token})")
    raise ThreatFoxError("api", f"ThreatFox query failed ({token})")


@dataclass(frozen=True)
class IndicatorCandidate:
    indicator_type: IndicatorType
    value: str
    #: 0-1 (ThreatFox confidence_level / 100), or None when ThreatFox gave no usable value.
    confidence: float | None
    first_seen: datetime
    last_seen: datetime


@dataclass
class MappingResult:
    received: int = 0
    indicators: list[IndicatorCandidate] = field(default_factory=list)
    #: Skipped records by reason; never the values themselves.
    skipped: Counter[str] = field(default_factory=Counter)
    #: Received records by ThreatFox ioc_type token (unexpected tokens count as "<other>").
    received_types: Counter[str] = field(default_factory=Counter)
    #: is_compromised across received records: "true", "false", "missing" (absent or null), "unrecognized".
    compromised: Counter[str] = field(default_factory=Counter)

    def mapped_types(self) -> Counter[str]:
        """Indicators after mapping and merging, by NETRA type."""
        return Counter(candidate.indicator_type.value for candidate in self.indicators)


TYPE_TOKEN = re.compile(r"^[a-z0-9_:]{1,40}$")


def map_iocs(records: list[Any], *, now: datetime | None = None) -> MappingResult:
    """Validate and map ThreatFox records; duplicates (same type and value) are merged."""
    now = now or datetime.now(UTC)
    result = MappingResult(received=len(records))
    merged: dict[tuple[IndicatorType, str], IndicatorCandidate] = {}
    for record in records:
        if isinstance(record, dict):
            ioc_type = record.get("ioc_type")
            result.received_types[ioc_type if isinstance(ioc_type, str) and TYPE_TOKEN.fullmatch(ioc_type) else "<other>"] += 1
            result.compromised[_compromised_flag(record)] += 1
        mapped = _map_record(record, now)
        if isinstance(mapped, str):
            result.skipped[mapped] += 1
            continue
        key = (mapped.indicator_type, mapped.value)
        merged[key] = _merge(merged[key], mapped) if key in merged else mapped
    result.indicators = list(merged.values())
    return result


def _compromised_flag(record: dict[str, Any]) -> str:
    value = record.get("is_compromised")
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "missing" if value is None else "unrecognized"


def _map_record(record: Any, now: datetime) -> IndicatorCandidate | str:
    """The candidate, or the reason it was skipped."""
    if not isinstance(record, dict):
        return "malformed_record"
    ioc_type, ioc = record.get("ioc_type"), record.get("ioc")
    if not isinstance(ioc_type, str) or not isinstance(ioc, str) or not ioc.strip():
        return "malformed_record"
    flag = _compromised_flag(record)
    if flag != "false":
        return {"true": "compromised_asset", "missing": "compromised_flag_missing"}.get(flag, "compromised_flag_unrecognized")
    mapped = _map_value(ioc_type.strip().lower(), ioc.strip())
    if isinstance(mapped, str):
        return mapped
    indicator_type, value = mapped

    first_seen = parse_timestamp(record.get("first_seen"))
    if first_seen is None:
        return "invalid_timestamp"
    last_seen_raw = record.get("last_seen")
    last_seen = first_seen if last_seen_raw in (None, "") else parse_timestamp(last_seen_raw)
    if last_seen is None:
        return "invalid_timestamp"
    if max(first_seen, last_seen) > now + MAX_FUTURE_SKEW:
        return "future_timestamp"
    return IndicatorCandidate(indicator_type, value, _confidence(record.get("confidence_level")), first_seen, max(first_seen, last_seen))


def _map_value(ioc_type: str, ioc: str) -> tuple[IndicatorType, str] | str:
    if len(ioc) > MAX_VALUE_LENGTH:
        return "value_too_long"
    if ioc_type == "ip:port":
        address = _ip_from_ip_port(ioc)
        if address is None:
            return "invalid_value"
        if not address.is_global:
            return "non_public_ip"
        return IndicatorType.IP, str(address)
    if ioc_type == "domain":
        domain = _normalize_domain(ioc)
        return (IndicatorType.DOMAIN, domain) if domain else "invalid_value"
    if ioc_type == "url":
        parts = urlsplit(ioc)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname or any(c.isspace() for c in ioc):
            return "invalid_value"
        return IndicatorType.URL, ioc.rstrip("/").casefold()
    if ioc_type in HASH_LENGTHS:
        digest = ioc.lower()
        if len(digest) != HASH_LENGTHS[ioc_type] or not HEX.fullmatch(digest):
            return "invalid_value"
        return IndicatorType.HASH, digest
    return "unsupported_type"


def _ip_from_ip_port(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """``1.2.3.4:443`` or ``[2001:db8::1]:443``; the port must be 0-65535."""
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.rpartition(":")
    if not separator or not port.isdigit() or int(port) > 65535:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _confidence(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if not 0 <= value <= 100:
        return None
    return round(float(value) / 100, 4)


def parse_timestamp(value: Any) -> datetime | None:
    """ThreatFox ``YYYY-MM-DD HH:MM:SS UTC`` (or ISO 8601); naive values are read as UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(" UTC"):
        text = text[:-4]
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _merge(left: IndicatorCandidate, right: IndicatorCandidate) -> IndicatorCandidate:
    confidences = [value for value in (left.confidence, right.confidence) if value is not None]
    return IndicatorCandidate(
        left.indicator_type,
        left.value,
        max(confidences) if confidences else None,
        min(left.first_seen, right.first_seen),
        max(left.last_seen, right.last_seen),
    )
