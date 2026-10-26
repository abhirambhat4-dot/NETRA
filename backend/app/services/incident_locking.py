from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Select, func, select
from sqlalchemy.orm import Session

from app.models.incident import Incident


def locked_incident_statement(incident_id: UUID) -> Select[tuple[Incident]]:
    """The incident row, locked until the transaction commits or rolls back.

    FOR NO KEY UPDATE serialises the workflow transitions of one incident: under READ COMMITTED a second
    request waits here, then reads the committed state and is refused (409), so it cannot repeat a
    transition or its history entry. Unlike FOR UPDATE it does not block other transactions' inserts that
    only reference the incident. populate_existing refreshes an incident the session already holds
    (seed_demo uses one long-lived session), so the state check sees the locked row's values.
    """
    return (
        select(Incident)
        .where(Incident.id == incident_id)
        .with_for_update(key_share=True)
        .execution_options(populate_existing=True)
    )


def lock_incident(db: Session, incident_id: UUID) -> Incident | None:
    """Lock the incident row; every workflow transition takes this lock first, and only this one, so
    competing transitions of one incident run one at a time and cannot deadlock on each other.

    Records reached through the incident (decisions, authorizations, containment actions) must be read
    after this call, with populate_existing, so their state checks see what the previous holder committed.
    """
    return db.scalars(locked_incident_statement(incident_id)).one_or_none()


def serialized_timestamp(column: Any, *scope: ColumnElement[bool]) -> ColumnElement[Any]:
    """An insert-time value for ``column`` that orders rows by the incident lock, not by transaction start.

    ``now()`` (the column default) is when a transaction began; one that waited for the incident lock can commit
    after another that began later, so its row would sort first. This value is ``clock_timestamp()`` at the
    insert, made strictly later than every committed row in ``scope`` (``greatest`` with their latest value plus
    one microsecond, which also covers a clock stepping backwards). Use it only while holding the incident lock:
    the lock then makes the rows' order match the order the transactions ran in. It is still a real timestamp.
    """
    latest = select(func.max(column)).where(*scope).scalar_subquery()
    return func.greatest(func.clock_timestamp(), latest + timedelta(microseconds=1))
