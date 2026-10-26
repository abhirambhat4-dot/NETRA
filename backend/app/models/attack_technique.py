import re
import uuid
from collections.abc import Iterable

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin

#: An ATT&CK technique or sub-technique ID: T1110 or T1110.001 (PostgreSQL regular expression).
TECHNIQUE_ID_PATTERN = r"^T[0-9]{4}(\.[0-9]{3})?$"
#: Only technique IDs that the submitting source itself reported. Inferred or mapped techniques are not
#: stored here; adding such a kind would need its own migration and must stay distinguishable.
ATTACK_EVIDENCE_KINDS = ("source_supplied",)
#: Where the ID was supplied: the event ingest API's field, or the live event collector's field.
ATTACK_EVIDENCE_ORIGINS = ("ingest_field", "collector_field")
#: Distinct technique IDs one event may carry, and raw list items accepted before de-duplication.
MAX_ATTACK_TECHNIQUES_PER_EVENT = 20
MAX_SUBMITTED_ATTACK_TECHNIQUE_IDS = 100
# The Python form of TECHNIQUE_ID_PATTERN, used with fullmatch (ASCII digits only, nothing before or after).
_TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")


def normalize_attack_technique_ids(values: Iterable[object] | None) -> list[str]:
    """Source-supplied technique IDs, trimmed, upper-cased and de-duplicated (first occurrence kept).

    Raises ValueError for a non-string, a malformed ID (tactic IDs such as TA0006 included) or more than
    MAX_ATTACK_TECHNIQUES_PER_EVENT distinct IDs. Messages give positions, never the submitted values.
    """
    if values is None:
        return []
    items = list(values)
    if len(items) > MAX_SUBMITTED_ATTACK_TECHNIQUE_IDS:
        raise ValueError(f"at most {MAX_SUBMITTED_ATTACK_TECHNIQUE_IDS} items may be submitted")
    normalized: list[str] = []
    for position, value in enumerate(items):
        if not isinstance(value, str):
            raise ValueError(f"item {position} must be a string")
        candidate = value.strip().upper()
        if not _TECHNIQUE_ID.fullmatch(candidate):
            raise ValueError(f"item {position} must be an ATT&CK technique ID such as T1110 or T1110.001")
        if candidate not in normalized:
            normalized.append(candidate)
    if len(normalized) > MAX_ATTACK_TECHNIQUES_PER_EVENT:
        raise ValueError(f"at most {MAX_ATTACK_TECHNIQUES_PER_EVENT} distinct technique IDs per event")
    return normalized


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class EventAttackTechnique(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One ATT&CK technique ID reported for a security event by the source that submitted it.

    Evidence, not inference: rows exist only for IDs a source explicitly supplied, with their origin kept.
    A well-formed ID is stored even when no bundled catalogue knows it; catalogue status (unknown,
    deprecated, revoked) is a reading concern and never changes or drops the stored evidence. Rows are
    removed only with their event.
    """

    __tablename__ = "event_attack_techniques"
    __table_args__ = (
        CheckConstraint(f"technique_id ~ '{TECHNIQUE_ID_PATTERN}'", name="technique_id_format"),
        CheckConstraint(_in("evidence_kind", ATTACK_EVIDENCE_KINDS), name="evidence_kind_values"),
        CheckConstraint(_in("evidence_origin", ATTACK_EVIDENCE_ORIGINS), name="evidence_origin_values"),
        # One row per technique per event and evidence kind; also serves lookups by event.
        UniqueConstraint("event_id", "technique_id", "evidence_kind"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_events.id", ondelete="CASCADE"))
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    evidence_kind: Mapped[str] = mapped_column(String(16))
    evidence_origin: Mapped[str] = mapped_column(String(32))
