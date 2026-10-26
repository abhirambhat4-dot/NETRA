"""NETRA live network monitor: parsing, rules, collector payloads and the local-only send guard.

Pure tests: netstat and tasklist output is synthetic (in the format this Windows host prints), commands, clock and
HTTP are stubbed, and nothing is sent or stored.
"""

import json
import re
from typing import Any

import pytest

from app.schemas.collector import CollectorEventIn
from scripts import netra_live_monitor as monitor

HEADER = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n"


def netstat(*rows: str) -> str:
    return HEADER + "".join(f"  {row}\n" for row in rows)


BASE_V4 = netstat(
    "TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1904",
    "TCP    0.0.0.0:5432           0.0.0.0:0              LISTENING       7760",
    "TCP    192.168.1.5:50000      20.10.10.10:443        ESTABLISHED     4242",
)
BASE_V6 = netstat("TCP    [::]:135               [::]:0                 LISTENING       1904")
TASKLIST = '"System","4","Services","0","5,472 K"\n"chrome.exe","4242","Console","1","200,000 K"\n"mstsc.exe","5000","Console","1","50,000 K"\n'


def connections(text: str) -> list[monitor.Connection]:
    return monitor.parse_netstat(text)


def started(include_loopback: bool = False) -> monitor.Detector:
    detector = monitor.Detector(include_loopback=include_loopback)
    assert detector.observe(connections(BASE_V4 + BASE_V6), {}, now=1000.0) == []  # baseline never alerts
    return detector


# --- parsing --------------------------------------------------------------------------------------


def test_netstat_rows_are_parsed_for_ipv4_and_ipv6_and_other_lines_skipped() -> None:
    text = BASE_V4 + netstat(
        "TCP    [fe80::1%12]:49700     [fe80::2%12]:445       ESTABLISHED     4",
        "UDP    0.0.0.0:5353           *:*                                    2000",
        "TCP    garbage                0.0.0.0:0              LISTENING       1",
    )

    parsed = connections(text)

    assert [(c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.state, c.pid) for c in parsed] == [
        ("0.0.0.0", 135, "0.0.0.0", 0, "LISTENING", 1904),
        ("0.0.0.0", 5432, "0.0.0.0", 0, "LISTENING", 7760),
        ("192.168.1.5", 50000, "20.10.10.10", 443, "ESTABLISHED", 4242),
        ("fe80::1", 49700, "fe80::2", 445, "ESTABLISHED", 4),  # zone index dropped
    ]


def test_tasklist_csv_maps_pids_to_names() -> None:
    assert monitor.parse_tasklist(TASKLIST) == {4: "System", 4242: "chrome.exe", 5000: "mstsc.exe"}


# --- rules ----------------------------------------------------------------------------------------


def test_r1_flags_a_new_connection_to_a_remote_administration_port() -> None:
    detector = started()
    snapshot = connections(BASE_V4 + netstat("TCP    192.168.1.5:51515      203.0.113.9:3389       ESTABLISHED     5000"))

    (alert,) = detector.observe(snapshot, {5000: "mstsc.exe"}, now=1003.0)

    assert (alert.rule_id, alert.severity, alert.event_type) == ("R1", "LOW", "live_monitor_remote_admin_port")
    assert (alert.src_ip, alert.src_port, alert.dest_ip, alert.dest_port) == ("192.168.1.5", 51515, "203.0.113.9", 3389)
    assert alert.signature.startswith("NETRA-LNM R1: outbound connection to a remote-administration port observed (RDP 3389)")
    assert "mstsc.exe (pid 5000)" in alert.signature


def test_r1_rates_telnet_higher_and_ignores_baseline_loopback_and_closed_connections() -> None:
    detector = monitor.Detector()
    baseline = BASE_V4 + netstat("TCP    192.168.1.5:40000      198.51.100.1:22        ESTABLISHED     5000")
    assert detector.observe(connections(baseline), {}, now=0.0) == []
    snapshot = connections(baseline + netstat(
        "TCP    127.0.0.1:40001        127.0.0.1:3389         ESTABLISHED     5000",  # loopback peer
        "TCP    192.168.1.5:40002      198.51.100.2:5900      TIME_WAIT       0",      # not outbound/open
        "TCP    192.168.1.5:40003      198.51.100.3:23        SYN_SENT        5000",
    ))

    alerts = detector.observe(snapshot, {}, now=3.0)

    assert [(a.rule_id, a.dest_port, a.severity) for a in alerts] == [("R1", 23, "MEDIUM")]  # baseline SSH never alerts


def test_loopback_peers_count_only_when_requested() -> None:
    detector = started(include_loopback=True)
    snapshot = connections(BASE_V4 + netstat("TCP    127.0.0.1:40001        127.0.0.1:22           ESTABLISHED     5000"))

    assert [a.rule_id for a in detector.observe(snapshot, {}, now=1003.0)] == ["R1"]


def test_r2_flags_one_process_reaching_many_hosts_within_the_window() -> None:
    detector = started()
    rows = [f"TCP    192.168.1.5:{41000 + i}      198.51.100.{i + 1}:443      ESTABLISHED     4242"
            for i in range(monitor.BURST_DISTINCT_HOSTS)]

    alerts = detector.observe(connections(BASE_V4 + netstat(*rows)), {4242: "chrome.exe"}, now=1005.0)

    (burst,) = [a for a in alerts if a.rule_id == "R2"]
    assert burst.severity == "MEDIUM" and burst.subject == "4242"
    assert f"to {monitor.BURST_DISTINCT_HOSTS} distinct remote hosts within {monitor.WINDOW_SECONDS} s" in burst.signature


def test_r2_does_not_count_connections_older_than_the_window() -> None:
    detector = started()
    half = monitor.BURST_DISTINCT_HOSTS // 2
    first = [f"TCP    192.168.1.5:{41000 + i}      198.51.100.{i + 1}:443      ESTABLISHED     4242" for i in range(half)]
    second = [f"TCP    192.168.1.5:{42000 + i}      198.51.101.{i + 1}:443      ESTABLISHED     4242" for i in range(half)]
    assert detector.observe(connections(BASE_V4 + netstat(*first)), {}, now=1003.0) == []

    alerts = detector.observe(connections(BASE_V4 + netstat(*second)), {}, now=1003.0 + monitor.WINDOW_SECONDS + 1)

    assert [a for a in alerts if a.rule_id == "R2"] == []


def test_r3_flags_many_ports_on_one_host_as_a_pattern_not_a_conclusion() -> None:
    detector = started()
    rows = [f"TCP    192.168.1.5:{43000 + i}      192.168.1.1:{20 + i}         SYN_SENT        6000"
            for i in range(monitor.FANOUT_DISTINCT_PORTS) if 20 + i not in monitor.REMOTE_ADMIN_PORTS]
    rows += [f"TCP    192.168.1.5:{44000 + i}      192.168.1.1:{8000 + i}       SYN_SENT        6000" for i in range(3)]

    alerts = detector.observe(connections(BASE_V4 + netstat(*rows)), {}, now=1004.0)

    (fanout,) = [a for a in alerts if a.rule_id == "R3"]
    assert fanout.dest_ip == "192.168.1.1" and fanout.details["distinct_ports"] >= monitor.FANOUT_DISTINCT_PORTS
    assert "a pattern consistent with port scanning" in fanout.signature


def test_r4_flags_a_listener_opened_after_start_up_once() -> None:
    detector = started()
    snapshot = connections(BASE_V4 + BASE_V6 + netstat(
        "TCP    0.0.0.0:8765           0.0.0.0:0              LISTENING       7000",
        "TCP    [::]:8765              [::]:0                 LISTENING       7000",
    ))

    alerts = detector.observe(snapshot, {7000: "python.exe"}, now=1003.0)

    assert [(a.rule_id, a.dest_ip, a.dest_port) for a in alerts] == [("R4", "0.0.0.0", 8765), ("R4", "::", 8765)]
    assert detector.observe(snapshot, {7000: "python.exe"}, now=1006.0) == []  # still open: cooldown, no repeat


def test_r4_flags_a_loopback_listener_opened_after_the_baseline() -> None:
    # The "loopback peers ignored" setting applies to R1-R3 (remote peers); a listener's own address never matters.
    detector = started(include_loopback=False)
    snapshot = connections(BASE_V4 + netstat("TCP    127.0.0.1:8767         0.0.0.0:0              LISTENING       7000"))

    (alert,) = detector.observe(snapshot, {7000: "python.exe"}, now=1003.0)

    assert (alert.rule_id, alert.severity, alert.dest_ip, alert.dest_port, alert.subject) == ("R4", "LOW", "127.0.0.1", 8767, "127.0.0.1:8767")
    assert "TCP 127.0.0.1:8767, python.exe (pid 7000)" in alert.signature


def test_a_listener_already_open_at_start_up_is_baseline_and_never_alerts() -> None:
    detector = monitor.Detector()
    snapshot = connections(BASE_V4 + netstat("TCP    127.0.0.1:8767         0.0.0.0:0              LISTENING       7000"))

    assert detector.observe(snapshot, {}, now=1000.0) == []
    assert detector.observe(snapshot, {}, now=1003.0) == []


def test_each_rule_and_subject_alerts_at_most_once_per_cooldown() -> None:
    detector = started()
    with_rdp = connections(BASE_V4 + netstat("TCP    192.168.1.5:51515      203.0.113.9:3389       ESTABLISHED     5000"))
    assert len(detector.observe(with_rdp, {}, now=1003.0)) == 1
    detector.observe(connections(BASE_V4), {}, now=1006.0)  # closed
    reopened = connections(BASE_V4 + netstat("TCP    192.168.1.5:51600      203.0.113.9:3389       ESTABLISHED     5000"))

    assert detector.observe(reopened, {}, now=1009.0) == []
    detector.observe(connections(BASE_V4), {}, now=1010.0)
    assert len(detector.observe(reopened, {}, now=1003.0 + monitor.COOLDOWN_SECONDS + 1)) == 1


# --- collector payloads ----------------------------------------------------------------------------


def sample_alerts() -> list[monitor.Alert]:
    detector = started()
    rows = [
        "TCP    192.168.1.5:51515      203.0.113.9:3389       ESTABLISHED     5000",
        "TCP    0.0.0.0:8765           0.0.0.0:0              LISTENING       7000",
        *[f"TCP    192.168.1.5:{41000 + i}      198.51.100.{i + 1}:443      ESTABLISHED     4242"
          for i in range(monitor.BURST_DISTINCT_HOSTS)],
        *[f"TCP    192.168.1.5:{43000 + i}      192.168.1.1:{8000 + i}       SYN_SENT        6000"
          for i in range(monitor.FANOUT_DISTINCT_PORTS)],
    ]
    alerts = detector.observe(connections(BASE_V4 + netstat(*rows)), {5000: "mstsc.exe"}, now=1003.0)
    assert {a.rule_id for a in alerts} == {"R1", "R2", "R3", "R4"}
    return alerts


def test_every_event_is_accepted_by_the_collector_schema_and_says_what_it_is() -> None:
    for alert in sample_alerts():
        event = monitor.collector_event(alert, now=1_790_000_000.0, host="demo-host")
        parsed = CollectorEventIn.model_validate(event)  # the server's own validation of a submitted event

        assert parsed.event_type.startswith("live_monitor_") and parsed.signature.startswith(f"NETRA-LNM {alert.rule_id}:")
        assert parsed.attack_technique_ids is None  # nothing is inferred
        details = event["rawData"]["monitor"]
        assert (details["name"], details["rule_id"], details["note"]) == (monitor.MONITOR_NAME, alert.rule_id, monitor.DISCLAIMER)
        assert "collector" not in event["rawData"]  # reserved for the server's attribution
        assert event["occurredAt"].endswith("+00:00")


def test_idempotency_keys_are_stable_within_a_cooldown_and_valid() -> None:
    (alert, *_) = sample_alerts()
    start = (1_790_000_000 // monitor.COOLDOWN_SECONDS) * monitor.COOLDOWN_SECONDS
    same = monitor.idempotency_key(alert, start + 1), monitor.idempotency_key(alert, start + monitor.COOLDOWN_SECONDS - 1)
    later = monitor.idempotency_key(alert, start + monitor.COOLDOWN_SECONDS)

    assert same[0] == same[1] != later
    assert re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", same[0])  # the collector's idempotencyKey rule
    assert same[0].startswith(f"lnm-{alert.rule_id.lower()}-")


def test_the_send_budget_stays_below_the_collector_rate_limit() -> None:
    budget = monitor.SendBudget()
    assert budget.take(40, now=0) == 40
    assert budget.take(40, now=10) == monitor.SEND_BUDGET_PER_MINUTE - 40
    assert budget.take(5, now=30) == 0
    assert budget.take(5, now=61) == 5


# --- the command: dry run by default, and --send only to this machine -------------------------------


def fake_run(snapshots: list[str]) -> Any:
    queue = list(snapshots)

    def run(args: list[str]) -> str:
        if args[0] == "tasklist":
            return TASKLIST
        if args[-1] == "TCPv6":
            return BASE_V6
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return run


def test_a_dry_run_prints_alerts_and_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_http(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a dry run must not create an HTTP client")

    monkeypatch.setattr(monitor, "CollectorClient", no_http)
    lines: list[str] = []
    snapshots = [BASE_V4, BASE_V4 + netstat("TCP    192.168.1.5:51515      203.0.113.9:3389       ESTABLISHED     5000")]

    code = monitor.main(["--once"], run=fake_run(snapshots), clock=iter([1000.0, 1003.0, 1003.0]).__next__,
                        sleep=lambda _s: None, out=lines.append, environ={})

    assert code == 0
    assert any("dry run (nothing is sent)" in line for line in lines)
    assert any(line.startswith("[LOW] NETRA-LNM R1:") for line in lines)


@pytest.mark.parametrize(
    "api",
    ["https://netra-micc.onrender.com", "http://10.0.0.5:8001", "http://user:pw@127.0.0.1:8001",
     "ftp://127.0.0.1", "http://127.0.0.1:8001/api", "http://127.0.0.1.example.com:8001"],
)
def test_send_is_refused_for_any_api_not_on_this_machine(api: str) -> None:
    lines: list[str] = []
    environ = {"NETRA_MONITOR_EMAIL": "monitor@example.com", "NETRA_MONITOR_PASSWORD": "not-printed-0123"}

    code = monitor.main(["--send", "--api", api, "--once"], run=fake_run([BASE_V4]), out=lines.append, environ=environ)

    assert code == 2 and lines and lines[0].startswith("REFUSED:")
    assert "not-printed-0123" not in "\n".join(lines)


def test_send_needs_credentials_from_the_environment() -> None:
    lines: list[str] = []

    assert monitor.main(["--send", "--once"], run=fake_run([BASE_V4]), out=lines.append, environ={}) == 2
    assert "NETRA_MONITOR_EMAIL and NETRA_MONITOR_PASSWORD" in lines[0]


@pytest.mark.parametrize("api", ["http://127.0.0.1:8001", "http://localhost:8001", "http://[::1]:8001", "http://127.0.0.1:8001/"])
def test_local_api_addresses_are_accepted(api: str) -> None:
    assert monitor.api_refusal(api) is None


# --- the collector client: mocked HTTP only ---------------------------------------------------------

PASSWORD = "client-test-password-not-real"


def mocked_client(monkeypatch: pytest.MonkeyPatch, handler: Any) -> monitor.CollectorClient:
    """A CollectorClient whose httpx.Client uses httpx.MockTransport; no request leaves the process."""
    import httpx

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    return monitor.CollectorClient("http://127.0.0.1:8001", "monitor@example.com", PASSWORD)


def collector_reply(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"created": len(events), "duplicates": 0, "rejected": 0,
            "results": [{"index": i, "idempotencyKey": e["idempotencyKey"], "status": "created"} for i, e in enumerate(events)]}


def test_the_client_signs_in_once_and_submits_with_the_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    seen: list[tuple[str, str, dict[str, Any] | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body, request.headers.get("authorization")))
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, json={"access_token": "token-A", "token_type": "bearer"})
        return httpx.Response(200, json=collector_reply(body["events"]))

    client = mocked_client(monkeypatch, handler)
    events = [monitor.collector_event(alert, now=1_790_000_000.0, host="demo-host") for alert in sample_alerts()[:2]]
    first, second = client.submit(events[:1]), client.submit(events[1:])
    client.close()

    assert (first["created"], second["created"]) == (1, 1)
    assert [(method, path) for method, path, _, _ in seen] == [
        ("POST", "/api/auth/login"), ("POST", "/api/collector/events"), ("POST", "/api/collector/events"),
    ]  # signed in once, token reused
    assert seen[0][2] == {"email": "monitor@example.com", "password": PASSWORD} and seen[0][3] is None
    assert seen[1][2] == {"events": events[:1]} and seen[1][3] == seen[2][3] == "Bearer token-A"


def test_the_client_signs_in_again_once_after_a_401(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    tokens = iter(["token-old", "token-new"])
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.headers.get("authorization")))
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, json={"access_token": next(tokens)})
        if request.headers.get("authorization") == "Bearer token-old":
            return httpx.Response(401, json={"detail": "Not authenticated"})
        return httpx.Response(200, json=collector_reply(json.loads(request.content)["events"]))

    client = mocked_client(monkeypatch, handler)
    event = monitor.collector_event(sample_alerts()[0], now=1_790_000_000.0, host="demo-host")

    assert client.submit([event])["created"] == 1
    assert seen == [
        ("/api/auth/login", None), ("/api/collector/events", "Bearer token-old"),
        ("/api/auth/login", None), ("/api/collector/events", "Bearer token-new"),
    ]


@pytest.mark.parametrize(
    ("login_status", "submit_statuses", "message"),
    [
        (401, [], "sign-in failed (HTTP 401)"),
        (200, [401, 401], "collector refused the batch (HTTP 401)"),  # after one fresh sign-in
        (200, [429], "collector refused the batch (HTTP 429)"),
    ],
)
def test_client_failures_stop_without_revealing_the_password(
    monkeypatch: pytest.MonkeyPatch, login_status: int, submit_statuses: list[int], message: str
) -> None:
    import httpx

    statuses = iter(submit_statuses)
    logins: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            logins.append(1)
            return httpx.Response(login_status, json={"access_token": "token"} if login_status == 200 else {"detail": "Invalid"})
        return httpx.Response(next(statuses), json={"detail": "refused"})

    client = mocked_client(monkeypatch, handler)

    with pytest.raises(RuntimeError) as error:
        client.submit([monitor.collector_event(sample_alerts()[0], now=1_790_000_000.0, host="demo-host")])
    assert str(error.value) == message and PASSWORD not in str(error.value)
    assert len(logins) == (2 if submit_statuses == [401, 401] else 1)  # a 401 leads to exactly one more sign-in
