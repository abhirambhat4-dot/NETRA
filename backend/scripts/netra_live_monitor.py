"""NETRA live network monitor (Windows): local TCP connection metadata, a few transparent rules, collector events.

Run from backend/ with the project virtual environment:

    .\\.venv\\Scripts\\python.exe -I -B scripts\\netra_live_monitor.py              # dry run: prints alerts, sends nothing
    .\\.venv\\Scripts\\python.exe -I -B scripts\\netra_live_monitor.py --once       # one comparison, then exit
    .\\.venv\\Scripts\\python.exe -I -B scripts\\netra_live_monitor.py --send       # also submit alerts to a LOCAL NETRA API

What it observes: snapshots of `netstat -ano -p TCP` and `-p TCPv6` (no administrator rights needed), taken every
--interval seconds, with process names from `tasklist`. Polled snapshots miss connections shorter than the interval.
Connections and listeners present at start-up are the baseline and never alert.

Rules (all thresholds are below; every alert names its rule):
  R1  a new outbound connection to a remote-administration port (SSH 22, Telnet 23, RDP 3389, VNC 5900);
  R2  one process opens new connections to at least BURST_DISTINCT_HOSTS distinct remote hosts within WINDOW;
  R3  new connections to at least FANOUT_DISTINCT_PORTS distinct ports on one remote host within WINDOW
      (a pattern consistent with port scanning);
  R4  a new listening port that was not open at start-up.
Each (rule, subject) alerts at most once per COOLDOWN. Loopback peers are ignored unless --include-loopback.

These are observations of connection metadata only. An alert is not evidence of malicious activity: every event
says so, and none carries an ATT&CK technique ID (nothing is inferred).

Events go to POST /api/collector/events (the NETRA Web Collector), which stores them as source MANUAL with server
attribution. --send is refused unless the API address is on this machine (localhost, 127.0.0.1 or ::1), so this
tool cannot write to a deployed backend. Credentials come only from NETRA_MONITOR_EMAIL and NETRA_MONITOR_PASSWORD;
neither they nor the access token are ever printed.
"""

import argparse
import csv
import hashlib
import io
import ipaddress
import os
import socket
import subprocess
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

MONITOR_NAME = "netra-live-monitor"
MONITOR_VERSION = "1.0"
DEFAULT_API = "http://127.0.0.1:8001"
LOCAL_API_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
REMOTE_ADMIN_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
WINDOW_SECONDS = 60
BURST_DISTINCT_HOSTS = 20
FANOUT_DISTINCT_PORTS = 10
COOLDOWN_SECONDS = 300
#: The collector accepts at most 20 events per request and 60 per minute per user; stay below both.
BATCH_SIZE = 20
SEND_BUDGET_PER_MINUTE = 50
OUTBOUND_STATES = frozenset({"ESTABLISHED", "SYN_SENT"})
DISCLAIMER = "Connection metadata only; this alert is not evidence of malicious activity."
BASIS = "Windows netstat TCP connection metadata, polled snapshots"


@dataclass(frozen=True)
class Connection:
    protocol: str  # "TCP" (IPv4 and IPv6 alike)
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: int

    @property
    def key(self) -> tuple[str, int, str, int]:
        return self.local_ip, self.local_port, self.remote_ip, self.remote_port

    @property
    def listening(self) -> bool:
        return self.state == "LISTENING"


@dataclass(frozen=True)
class Alert:
    rule_id: str
    event_type: str
    severity: str
    signature: str
    #: What the cooldown is keyed on, e.g. the remote endpoint or the listening port.
    subject: str
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    pid: int | None = None
    process: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


# --- parsing -------------------------------------------------------------------------------------


def split_endpoint(text: str) -> tuple[str, int] | None:
    """``1.2.3.4:443`` or ``[2001:db8::1%5]:443`` -> (normalised IP, port); None when it is not an IP endpoint."""
    if text.startswith("["):
        host, separator, port = text[1:].partition("]:")
    else:
        host, separator, port = text.rpartition(":")
    if not separator or not port.isdigit() or int(port) > 65535:
        return None
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])  # drop an IPv6 zone index such as %5
    except ValueError:
        return None
    return str(address), int(port)


def parse_netstat(text: str) -> list[Connection]:
    """TCP rows of ``netstat -ano`` output (English state names); anything else is skipped."""
    connections = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 5 or parts[0] != "TCP" or not parts[4].isdigit():
            continue
        local, remote = split_endpoint(parts[1]), split_endpoint(parts[2])
        if local is None or remote is None:
            continue
        connections.append(Connection("TCP", local[0], local[1], remote[0], remote[1], parts[3], int(parts[4])))
    return connections


def parse_tasklist(text: str) -> dict[int, str]:
    """``tasklist /FO CSV /NH`` -> {pid: image name}."""
    names: dict[int, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]
    return names


def read_snapshot(run: Callable[[list[str]], str]) -> tuple[list[Connection], dict[int, str]]:
    connections = parse_netstat(run(["netstat", "-ano", "-p", "TCP"])) + parse_netstat(run(["netstat", "-ano", "-p", "TCPv6"]))
    return connections, parse_tasklist(run(["tasklist", "/FO", "CSV", "/NH"]))


def run_command(args: list[str]) -> str:
    completed = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"{args[0]} exited with status {completed.returncode}")
    return completed.stdout


# --- detection -----------------------------------------------------------------------------------


def _is_loopback(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_loopback


def _is_unspecified(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_unspecified


def _endpoint(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


class Detector:
    """Compares each snapshot with the previous one and applies R1-R4. The first snapshot is the baseline."""

    def __init__(self, *, include_loopback: bool = False) -> None:
        self.include_loopback = include_loopback
        self.baseline_listeners: set[tuple[str, int]] | None = None
        self.previous: set[tuple[str, int, str, int]] = set()
        self.recent: deque[tuple[float, Connection]] = deque()  # new outbound connections within WINDOW
        self.last_alerted: dict[tuple[str, str], float] = {}

    def _peer_in_scope(self, connection: Connection) -> bool:
        if _is_unspecified(connection.remote_ip) or connection.remote_port == 0:
            return False
        return self.include_loopback or not _is_loopback(connection.remote_ip)

    def _cooled(self, alert: Alert, now: float) -> bool:
        key = (alert.rule_id, alert.subject)
        if now - self.last_alerted.get(key, float("-inf")) < COOLDOWN_SECONDS:
            return False
        self.last_alerted[key] = now
        return True

    def observe(self, connections: Iterable[Connection], names: dict[int, str], now: float) -> list[Alert]:
        snapshot = list(connections)
        listeners = {(c.local_ip, c.local_port) for c in snapshot if c.listening}
        current = {c.key for c in snapshot if not c.listening}
        if self.baseline_listeners is None:  # start-up: record, never alert
            self.baseline_listeners, self.previous = listeners, current
            return []

        fresh = [c for c in snapshot if not c.listening and c.key not in self.previous
                 and c.state in OUTBOUND_STATES and self._peer_in_scope(c)]
        self.previous = current
        for connection in fresh:
            self.recent.append((now, connection))
        while self.recent and now - self.recent[0][0] > WINDOW_SECONDS:
            self.recent.popleft()

        alerts = [*self._remote_admin(fresh, names), *self._burst(names), *self._fanout(names),
                  *self._new_listeners(snapshot, names)]
        return [alert for alert in alerts if self._cooled(alert, now)]

    def _remote_admin(self, fresh: list[Connection], names: dict[int, str]) -> list[Alert]:
        alerts = []
        for c in fresh:
            service = REMOTE_ADMIN_PORTS.get(c.remote_port)
            if service is None:
                continue
            process = names.get(c.pid)
            alerts.append(Alert(
                rule_id="R1",
                event_type="live_monitor_remote_admin_port",
                severity="MEDIUM" if c.remote_port == 23 else "LOW",  # Telnet sends credentials in clear text
                signature=(f"NETRA-LNM R1: outbound connection to a remote-administration port observed ({service} "
                           f"{c.remote_port}): TCP {_endpoint(c.local_ip, c.local_port)} -> {_endpoint(c.remote_ip, c.remote_port)}, "
                           f"{process or 'unknown process'} (pid {c.pid})"),
                subject=f"{c.pid}->{_endpoint(c.remote_ip, c.remote_port)}",
                src_ip=c.local_ip, src_port=c.local_port, dest_ip=c.remote_ip, dest_port=c.remote_port,
                pid=c.pid, process=process,
                details={"service": service, "state": c.state},
            ))
        return alerts

    def _burst(self, names: dict[int, str]) -> list[Alert]:
        hosts_by_pid: dict[int, set[str]] = {}
        for _, c in self.recent:
            hosts_by_pid.setdefault(c.pid, set()).add(c.remote_ip)
        alerts = []
        for pid, hosts in sorted(hosts_by_pid.items()):
            if len(hosts) < BURST_DISTINCT_HOSTS:
                continue
            process = names.get(pid)
            alerts.append(Alert(
                rule_id="R2",
                event_type="live_monitor_connection_burst",
                severity="MEDIUM",
                signature=(f"NETRA-LNM R2: connection burst observed: {process or 'unknown process'} (pid {pid}) opened "
                           f"connections to {len(hosts)} distinct remote hosts within {WINDOW_SECONDS} s"),
                subject=str(pid),
                pid=pid, process=process,
                details={"distinct_remote_hosts": len(hosts), "window_seconds": WINDOW_SECONDS,
                         "threshold": BURST_DISTINCT_HOSTS, "sample_hosts": sorted(hosts)[:10]},
            ))
        return alerts

    def _fanout(self, names: dict[int, str]) -> list[Alert]:
        by_host: dict[str, list[Connection]] = {}
        for _, c in self.recent:
            by_host.setdefault(c.remote_ip, []).append(c)
        alerts = []
        for host, connections in sorted(by_host.items()):
            ports = sorted({c.remote_port for c in connections})
            if len(ports) < FANOUT_DISTINCT_PORTS:
                continue
            first = connections[0]
            alerts.append(Alert(
                rule_id="R3",
                event_type="live_monitor_port_fanout",
                severity="MEDIUM",
                signature=(f"NETRA-LNM R3: connections to {len(ports)} distinct ports on {host} observed within "
                           f"{WINDOW_SECONDS} s (a pattern consistent with port scanning)"),
                subject=host,
                src_ip=first.local_ip, dest_ip=host, pid=first.pid, process=names.get(first.pid),
                details={"distinct_ports": len(ports), "window_seconds": WINDOW_SECONDS,
                         "threshold": FANOUT_DISTINCT_PORTS, "sample_ports": ports[:20]},
            ))
        return alerts

    def _new_listeners(self, snapshot: list[Connection], names: dict[int, str]) -> list[Alert]:
        assert self.baseline_listeners is not None
        alerts = []
        seen: set[tuple[str, int]] = set()
        for c in snapshot:
            endpoint = (c.local_ip, c.local_port)
            if not c.listening or endpoint in self.baseline_listeners or endpoint in seen:
                continue
            seen.add(endpoint)
            process = names.get(c.pid)
            alerts.append(Alert(
                rule_id="R4",
                event_type="live_monitor_new_listener",
                severity="LOW",
                signature=(f"NETRA-LNM R4: new listening port observed: TCP {_endpoint(c.local_ip, c.local_port)}, "
                           f"{process or 'unknown process'} (pid {c.pid}); not open when monitoring started"),
                subject=_endpoint(c.local_ip, c.local_port),
                dest_ip=c.local_ip, dest_port=c.local_port, pid=c.pid, process=process,
            ))
        return alerts


# --- collector events ----------------------------------------------------------------------------


def idempotency_key(alert: Alert, now: float) -> str:
    """Stable for one (rule, subject) within a cooldown period, so a resent batch is reported as a duplicate."""
    bucket = int(now // COOLDOWN_SECONDS)
    digest = hashlib.sha256(f"{alert.rule_id}\x00{alert.subject}\x00{bucket}".encode()).hexdigest()[:40]
    return f"lnm-{alert.rule_id.lower()}-{digest}"


def collector_event(alert: Alert, now: float, host: str) -> dict[str, Any]:
    """The collector payload (POST /api/collector/events item); source and attribution are set by the server."""
    event: dict[str, Any] = {
        "idempotencyKey": idempotency_key(alert, now),
        "occurredAt": datetime.fromtimestamp(now, UTC).isoformat(),
        "eventType": alert.event_type,
        "severity": alert.severity,
        "signature": alert.signature[:512],
        "protocol": "TCP",
        "rawData": {
            "monitor": {
                "name": MONITOR_NAME,
                "version": MONITOR_VERSION,
                "rule_id": alert.rule_id,
                "host": host,
                "pid": alert.pid,
                "process": alert.process,
                "basis": BASIS,
                "note": DISCLAIMER,
                **alert.details,
            }
        },
    }
    for name, value in (("srcIp", alert.src_ip), ("srcPort", alert.src_port), ("destIp", alert.dest_ip), ("destPort", alert.dest_port)):
        if value is not None:
            event[name] = value
    return event


def api_refusal(api: str) -> str | None:
    """Why ``--send`` may not use this API address, or None. Only an API on this machine is allowed."""
    parts = urlsplit(api)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "the API address must be an http(s) URL"
    if parts.username or parts.password:
        return "the API address must not contain credentials"
    if parts.hostname.lower() not in LOCAL_API_HOSTS:
        return f"--send only submits to a NETRA API on this machine ({', '.join(sorted(LOCAL_API_HOSTS))}), not {parts.hostname}"
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return "the API address must be a bare origin such as http://127.0.0.1:8001"
    return None


class SendBudget:
    """Client-side limit below the collector's 60 events per minute."""

    def __init__(self, per_minute: int = SEND_BUDGET_PER_MINUTE) -> None:
        self.per_minute = per_minute
        self.sent: deque[float] = deque()

    def take(self, wanted: int, now: float) -> int:
        while self.sent and now - self.sent[0] >= 60:
            self.sent.popleft()
        allowed = max(0, min(wanted, self.per_minute - len(self.sent)))
        self.sent.extend([now] * allowed)
        return allowed


class CollectorClient:
    """Signs in and submits events. Never prints the credentials or the token."""

    def __init__(self, api: str, email: str, password: str) -> None:
        import httpx

        self._http = httpx.Client(base_url=api.rstrip("/"), timeout=15)
        self._email, self._password = email, password
        self._token: str | None = None

    def _login(self) -> None:
        response = self._http.post("/api/auth/login", json={"email": self._email, "password": self._password})
        if response.status_code != 200:
            raise RuntimeError(f"sign-in failed (HTTP {response.status_code})")
        self._token = response.json()["access_token"]

    def submit(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if self._token is None:
            self._login()
        for attempt in (1, 2):
            response = self._http.post("/api/collector/events", json={"events": events},
                                       headers={"Authorization": f"Bearer {self._token}"})
            if response.status_code == 401 and attempt == 1:
                self._login()  # the token expired; sign in again once
                continue
            if response.status_code != 200:
                raise RuntimeError(f"collector refused the batch (HTTP {response.status_code})")
            return response.json()
        raise RuntimeError("collector refused the batch after signing in again")

    def close(self) -> None:
        self._http.close()


# --- command -------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NETRA live network monitor (dry run unless --send).")
    parser.add_argument("--send", action="store_true", help="submit alerts to the local NETRA collector")
    parser.add_argument("--api", default=DEFAULT_API, help=f"local NETRA API origin (default {DEFAULT_API})")
    parser.add_argument("--interval", type=float, default=3.0, help="seconds between snapshots (default 3, minimum 1)")
    parser.add_argument("--once", action="store_true", help="take the baseline and one comparison, then exit")
    parser.add_argument("--duration", type=float, default=0, help="stop after this many seconds (0 = until Ctrl+C)")
    parser.add_argument("--include-loopback", action="store_true", help="also apply R1-R3 to loopback peers (for demos)")
    return parser


def main(argv: list[str] | None = None, *, run: Callable[[list[str]], str] = run_command,
         clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
         out: Callable[[str], None] = print, environ: dict[str, str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    environ = dict(os.environ) if environ is None else environ
    if options.interval < 1:
        out("REFUSED: --interval must be at least 1 second")
        return 2
    client = None
    if options.send:
        if refusal := api_refusal(options.api):
            out(f"REFUSED: {refusal}; nothing was sent")
            return 2
        email, password = environ.get("NETRA_MONITOR_EMAIL"), environ.get("NETRA_MONITOR_PASSWORD")
        if not email or not password:
            out("REFUSED: set NETRA_MONITOR_EMAIL and NETRA_MONITOR_PASSWORD for --send; nothing was sent")
            return 2
        client = CollectorClient(options.api, email, password)
    out(f"{MONITOR_NAME} {MONITOR_VERSION}: {'sending to ' + options.api if client else 'dry run (nothing is sent)'}; "
        f"interval {options.interval:g} s; loopback peers {'included' if options.include_loopback else 'ignored'}")
    out(f"note: {DISCLAIMER}")

    detector, budget, host = Detector(include_loopback=options.include_loopback), SendBudget(), socket.gethostname()
    pending: list[dict[str, Any]] = []
    started = clock()
    comparisons = 0
    try:
        while True:
            now = clock()
            connections, names = read_snapshot(run)
            alerts = detector.observe(connections, names, now)
            for alert in alerts:
                out(f"[{alert.severity}] {alert.signature}")
                pending.append(collector_event(alert, now, host))
            if client and pending:
                allowed = budget.take(min(len(pending), BATCH_SIZE), now)
                if allowed:
                    batch, pending = pending[:allowed], pending[allowed:]
                    result = client.submit(batch)
                    out(f"sent {len(batch)}: {result['created']} created, {result['duplicates']} duplicate, {result['rejected']} rejected")
                    for item in result["results"]:
                        if item["status"] == "rejected":
                            out(f"  rejected #{item['index']}: {item.get('reason')}")
                if pending:
                    out(f"{len(pending)} alert(s) waiting for the send budget")
            elif not client:
                pending.clear()
            comparisons += 1
            if options.once and comparisons >= 2:
                break
            if options.duration and clock() - started >= options.duration:
                break
            sleep(options.interval)
    except KeyboardInterrupt:
        out("stopped")
    except RuntimeError as error:
        out(f"STOPPED: {error}")
        return 1
    finally:
        if client:
            client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
