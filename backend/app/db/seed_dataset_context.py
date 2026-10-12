"""Local demonstration context for imported CIC-IDS2017 events: one asset and one IP threat indicator.

Imported dataset events are linked to an asset only at import time, by exact IP match (rule
exact-ip-match-v1), and Security Assessment cites them only through its existing evidence rules,
such as matches of active IP threat indicators. Neither assets nor indicators can be created through
the API, so this module creates the minimum context needed to demonstrate that path:

- Asset ``CIC-DEMO-WEB-50`` with IP 192.168.10.50, the server that receives most traffic in the
  CIC-IDS2017 Friday-afternoon file (its descriptive fields are demonstration values).
- An active IP indicator for 172.16.0.1, the source of that traffic in the same file, entered by an
  analyst for the demonstration. It is not from a threat feed, and it is not a NETRA detection.
  Choosing it was informed by the dataset's own labels, which remain ground truth only.

It never creates, changes or links events, and never updates or deletes existing records: events
stored before the asset existed stay unlinked, so the demonstration needs a new upload afterwards.
Records that exist with different values are reported as conflicts and nothing is written.

Dry run (read-only, the default):  python -m app.db.seed_dataset_context
Write (local database only):       python -m app.db.seed_dataset_context --apply --confirm-target localhost:5432/netra
"""

import argparse
import os
import sys
from collections.abc import Callable, Mapping
from ipaddress import ip_address
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.enums import AssetEnvironment, AssetStatus, AssetType, Criticality, Exposure, IndicatorType, Severity
from app.models.threat_indicator import ThreatIndicator

ASSET_KEY = "CIC-DEMO-WEB-50"
ASSET_FIELDS: dict[str, Any] = {
    "name": "[DATASET DEMO] CIC-IDS2017 server 192.168.10.50",
    "hostname": None,
    "ip_address": "192.168.10.50",
    "asset_type": AssetType.SERVER,
    "environment": AssetEnvironment.TEST,
    "criticality": Criticality.MEDIUM,
    "exposure": Exposure.INTERNET_FACING,
    "owner": "NETRA dataset demo (CIC-IDS2017)",
    "status": AssetStatus.ACTIVE,
}
INDICATOR_VALUE = "172.16.0.1"
INDICATOR_SOURCE = "NETRA dataset demo (analyst-entered, not a threat feed)"
INDICATOR_FIELDS: dict[str, Any] = {"severity": Severity.MEDIUM, "confidence": None, "is_active": True}

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# libpq variables that could send the connection somewhere other than the URL says.
REDIRECTING_ENV_VARS = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGSERVICE", "PGSERVICEFILE")

EXIT_OK = 0
EXIT_BLOCKED = 2


def describe(url: URL) -> str:
    """host:port/database only: never the user name, password or query options."""
    return f"{url.host or '?'}:{url.port or 5432}/{url.database or '?'}"


def write_refusal(url: URL, confirmation: str | None, environ: Mapping[str, str]) -> str | None:
    """Why a write to ``url`` is refused, or None. Never connects."""
    if url.get_backend_name() != "postgresql" or (url.host or "").lower() not in LOCAL_HOSTS:
        return "writes are allowed only to a local PostgreSQL database"
    if url.query:
        return "DATABASE_URL carries query options; use a plain local URL"
    set_vars = [name for name in REDIRECTING_ENV_VARS if environ.get(name)]
    if set_vars:
        return f"unset {', '.join(set_vars)} first"
    if confirmation is None or confirmation.strip().lower() != describe(url).lower():
        return f"--confirm-target must equal {describe(url)}"
    return None


def _same(record: Any, fields: Mapping[str, Any]) -> list[str]:
    differences = []
    for name, expected in fields.items():
        actual = getattr(record, name)
        if name == "ip_address" and actual is not None:
            actual = str(ip_address(str(actual)))
        if actual != expected:
            differences.append(name)
    return differences


def plan(session: Session) -> tuple[list[str], list[str]]:
    """(records to create, conflicts). Read-only."""
    to_create: list[str] = []
    conflicts: list[str] = []

    asset = session.scalar(select(Asset).where(Asset.asset_key == ASSET_KEY))
    if asset is None:
        to_create.append(f"asset {ASSET_KEY}")
    elif differences := _same(asset, ASSET_FIELDS):
        conflicts.append(f"asset {ASSET_KEY} exists with different {', '.join(differences)}")
    # Another asset on the same address would make the import-time link ambiguous (no link at all).
    others = session.scalars(
        select(Asset.asset_key).where(Asset.ip_address == ASSET_FIELDS["ip_address"], Asset.asset_key != ASSET_KEY)
    ).all()
    if others:
        conflicts.append(f"{ASSET_FIELDS['ip_address']} already belongs to asset(s) {', '.join(sorted(others))}")

    indicator = session.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.indicator_type == IndicatorType.IP,
            ThreatIndicator.value == INDICATOR_VALUE,
            ThreatIndicator.source == INDICATOR_SOURCE,
        )
    )
    if indicator is None:
        to_create.append(f"IP indicator {INDICATOR_VALUE}")
    elif differences := _same(indicator, INDICATOR_FIELDS):
        conflicts.append(f"indicator {INDICATOR_VALUE} exists with different {', '.join(differences)}")
    return to_create, conflicts


def run(session: Session, *, apply: bool, out: Callable[[str], None] = print) -> int:
    to_create, conflicts = plan(session)
    for conflict in conflicts:
        out(f"CONFLICT: {conflict}")
    if conflicts:
        out("Nothing was written.")
        return EXIT_BLOCKED
    if not to_create:
        out("Already present: asset and indicator match; nothing to write.")
        return EXIT_OK
    if not apply:
        out(f"Dry run: would create {'; '.join(to_create)}. Nothing was written.")
        return EXIT_OK

    if session.scalar(select(Asset).where(Asset.asset_key == ASSET_KEY)) is None:
        session.add(Asset(asset_key=ASSET_KEY, **ASSET_FIELDS))
    if "IP indicator" in " ".join(to_create):
        session.add(
            ThreatIndicator(
                indicator_type=IndicatorType.IP, value=INDICATOR_VALUE, source=INDICATOR_SOURCE, **INDICATOR_FIELDS
            )
        )
    session.commit()
    out(f"Created: {'; '.join(to_create)}.")
    return EXIT_OK


def main(argv: list[str] | None = None, environ: Mapping[str, str] = os.environ) -> int:
    parser = argparse.ArgumentParser(description="Create the local CIC-IDS2017 demonstration asset and indicator.")
    parser.add_argument("--apply", action="store_true", help="write missing records (default: dry run)")
    parser.add_argument("--confirm-target", metavar="HOST:PORT/DATABASE", help="required with --apply")
    args = parser.parse_args(argv)

    from app.db.session import SessionLocal, engine

    print(f"target: {describe(engine.url)}")
    if args.apply and (refusal := write_refusal(engine.url, args.confirm_target, environ)):
        print(f"REFUSED: {refusal}; nothing was written.")
        return EXIT_BLOCKED
    try:
        with SessionLocal() as session:
            if not args.apply:
                # Any accidental write in a dry run fails instead of committing.
                session.execute(text("SET TRANSACTION READ ONLY"))
            code = run(session, apply=args.apply)
            if not args.apply:
                session.rollback()
    finally:
        engine.dispose()
    return code


if __name__ == "__main__":
    sys.exit(main())
