"""Store the accepted rows of a VALIDATED import batch as security events.

Runs inside the transaction that records the batch, so a batch and its events are stored together
or not at all. Only rows that passed every profile check are stored; rejected rows stay reported in
the batch's error sample and are never stored.

- Provenance: each event names its batch (import_batch_id) and file row (source_row, header = row 1).
- Duplicates: an event's uid is derived from the row's content, so a row identical to one already
  stored (earlier in the file or in an earlier batch) is not stored again; it is counted in the
  batch's duplicate_rows instead of being dropped silently.
- Severity is INFO for every imported row: the dataset's label is ground truth for evaluation, not a
  NETRA detection, and is kept only in raw_data.
- Assets: an event is linked to an asset only when exactly one asset's ip_address equals the row's
  source or destination address (ASSET_LINK_RULE). The rule and its outcome are recorded on the event.
"""

import uuid
from collections import defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, BinaryIO

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.enums import DetectionSource, Severity
from app.models.event import SecurityEvent
from app.models.import_batch import ImportBatch
from app.services.dataset_profiles import DatasetProfile, NormalizedEvent

NORMALIZE_CHUNK_ROWS = 1000
ASSET_LINK_RULE = "exact-ip-match-v1"


@dataclass
class NormalizationOutcome:
    events_created: int = 0
    duplicate_rows: int = 0


def event_uid(profile: DatasetProfile, event: NormalizedEvent) -> str:
    return f"dataset:{profile.identifier}:{event.content_sha256}"


def _canonical_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def asset_ip_index(db: Session) -> dict[str, set[uuid.UUID]]:
    index: dict[str, set[uuid.UUID]] = defaultdict(set)
    for asset_id, address in db.execute(select(Asset.id, Asset.ip_address).where(Asset.ip_address.is_not(None))):
        canonical = _canonical_ip(str(address))
        if canonical is not None:
            index[canonical].add(asset_id)
    return index


def link_asset(event: NormalizedEvent, index: Mapping[str, set[uuid.UUID]]) -> tuple[uuid.UUID | None, dict[str, Any]]:
    matches: dict[uuid.UUID, list[str]] = defaultdict(list)
    for field, value in (("source IP", event.src_ip), ("destination IP", event.dest_ip)):
        for asset_id in index.get(_canonical_ip(value) or "", ()):
            matches[asset_id].append(field)
    if len(matches) == 1:
        ((asset_id, fields),) = matches.items()
        return asset_id, {"rule": ASSET_LINK_RULE, "result": "linked", "assetId": str(asset_id), "matchedOn": fields}
    if event.src_ip is None and event.dest_ip is None:
        # Asset-based assessment reads only asset-linked events, so this event cannot inform one.
        return None, {"rule": ASSET_LINK_RULE, "result": "event has no IP address to match"}
    if not matches:
        return None, {"rule": ASSET_LINK_RULE, "result": "no asset has the source or destination IP"}
    return None, {"rule": ASSET_LINK_RULE, "result": f"not linked: {len(matches)} assets match", "candidates": sorted(map(str, matches))}


def accepted_rows(file: BinaryIO, profile: DatasetProfile) -> Iterator[tuple[int, dict[str, str]]]:
    """(row number, values) for each row that passes the profile, numbered exactly as validation numbers them."""
    from app.services.dataset_import import check_record, is_blank, open_csv

    with open_csv(file, profile) as reader:
        header = next(reader)
        positions = profile.column_positions(header)
        row_number = 1
        for record in reader:
            row_number += 1
            if is_blank(profile, record) or check_record(profile, header, positions, record, row_number):
                continue
            yield row_number, {name: record[index] for name, index in positions.items()}


def _insert_chunk(db: Session, rows: list[dict[str, Any]]) -> int:
    statement = (
        insert(SecurityEvent).values(rows).on_conflict_do_nothing(index_elements=["event_uid"]).returning(SecurityEvent.id)
    )
    return len(db.execute(statement).all())


def store_batch_events(db: Session, batch: ImportBatch, file: BinaryIO, profile: DatasetProfile) -> NormalizationOutcome:
    """Insert the batch's accepted rows in bounded chunks. The caller commits (or rolls back) with the batch."""
    outcome = NormalizationOutcome()
    if not profile.normalizes:
        return outcome
    index = asset_ip_index(db)
    chunk: list[dict[str, Any]] = []

    def flush_chunk() -> None:
        created = _insert_chunk(db, chunk)
        outcome.events_created += created
        outcome.duplicate_rows += len(chunk) - created
        chunk.clear()

    for row_number, values in accepted_rows(file, profile):
        event = profile.normalize_row(values)
        if event is None:
            raise RuntimeError(f"profile {profile.identifier} declares normalisation but mapped no event")
        asset_id, asset_link = link_asset(event, index)
        chunk.append(
            {
                "id": uuid.uuid4(),
                "event_uid": event_uid(profile, event),
                "occurred_at": event.occurred_at,
                "source": DetectionSource.DATASET_IMPORT,
                "event_type": event.event_type,
                "signature": None,
                "severity": Severity.INFO,
                "src_ip": event.src_ip,
                "dest_ip": event.dest_ip,
                "src_port": event.src_port,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "anomaly_score": None,
                "raw_data": {
                    **event.raw_data,
                    "importBatchId": str(batch.id),
                    "sourceRow": row_number,
                    "fileSha256": batch.file_sha256,
                    "assetLink": asset_link,
                },
                "asset_id": asset_id,
                "import_batch_id": batch.id,
                "source_row": row_number,
            }
        )
        if len(chunk) >= NORMALIZE_CHUNK_ROWS:
            flush_chunk()
    if chunk:
        flush_chunk()
    return outcome
