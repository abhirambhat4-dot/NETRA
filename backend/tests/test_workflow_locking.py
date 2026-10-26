"""Workflow transitions lock the incident row before any state check or write.

These tests do not run concurrent transactions: the ``core_api`` fixture keeps each test's schema inside one
uncommitted transaction on a single connection, which no second connection can see. They check what the code
controls instead:

* statement order: the recorded SQL of every transition takes the incident lock (FOR NO KEY UPDATE) before
  it reads workflow state or writes anything; and
* re-validation: a competing request that commits while this request waits for the lock (simulated by running
  it, in another session, at the moment the lock is requested) is seen after the lock, so this request is
  refused and exactly one outcome and one history entry remain.

PostgreSQL's blocking of the second locker is relied on, not exercised.
"""

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import event, func, select

from app.db.session import engine as postgres_engine
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.enums import AuthorizationStatus, IncidentState
from app.models.incident import Incident, IncidentHistory
from app.services import controlled_response, decision_workflow, incident_locking
from tests.conftest import APPROVER_EMAIL, CoreApi
from tests.test_authorization import request_authorization
from tests.test_containment import contain, create_approved_authorization, create_pending_authorization
from tests.test_cyber_memory import create_memory, create_verified_containment
from tests.test_decision import request_decision, seed_prioritised_incident
from tests.test_incident_verification import request_incident_verification
from tests.test_verification import verify

COMPETITOR = "competitor@example.com"
WORKFLOW_TABLES = ("incidents", "incident_history", "decisions", "authorizations", "containment_actions", "cyber_memories")
LOCK = re.compile(r"\bFROM \S*incidents\b.*\bFOR NO KEY UPDATE\b", re.S)
# The only workflow read allowed before the lock: a child's incident_id, which never changes.
INCIDENT_ID_LOOKUP = re.compile(r"^SELECT \S+\.incident_id\s+FROM \S+\s+WHERE \S+\.id = %\(id_1\)s", re.S)


@contextmanager
def recorded_sql() -> Iterator[list[str]]:
    statements: list[str] = []

    def record(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        statements.append(statement)

    event.listen(postgres_engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        event.remove(postgres_engine, "before_cursor_execute", record)


def touches_workflow(statement: str) -> bool:
    return any(re.search(rf"\b(?:\w+\.)?{table}\b", statement) for table in WORKFLOW_TABLES)


def assert_locks_before_reading_or_writing(statements: list[str]) -> None:
    locks = [index for index, statement in enumerate(statements) if LOCK.search(statement)]
    assert locks, "the transition never locked the incident row"
    before = statements[: locks[0]]
    assert not [s for s in before if s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))]
    assert not [s for s in before if touches_workflow(s) and not INCIDENT_ID_LOOKUP.match(s.strip())]
    assert any(s.lstrip().upper().startswith(("INSERT", "UPDATE")) for s in statements[locks[0] :])


def count(core_api: CoreApi, model: type, **filters: Any) -> int:
    with core_api.session_factory() as session:
        return session.scalar(select(func.count()).select_from(model).filter_by(**filters)) or 0


def actions(core_api: CoreApi, incident_id: UUID) -> list[str]:
    with core_api.session_factory() as session:
        return list(
            session.scalars(
                select(IncidentHistory.action)
                .where(IncidentHistory.incident_id == incident_id)
                .order_by(IncidentHistory.occurred_at, IncidentHistory.id)
            )
        )


def compete_at_lock(monkeypatch: pytest.MonkeyPatch, core_api: CoreApi, competitor: Callable[[Any], object]) -> list[bool]:
    """When the request under test asks for the incident lock, first run ``competitor`` to completion and
    commit it in a separate session: what a transaction holding the lock would leave behind."""
    ran: list[bool] = []
    real_lock = incident_locking.lock_incident

    def lock_after_competitor(db: Any, incident_id: UUID) -> Incident | None:
        if not ran:
            ran.append(True)
            with core_api.session_factory() as other:
                competitor(other)
        return real_lock(db, incident_id)

    for module in (decision_workflow, controlled_response):
        monkeypatch.setattr(module, "lock_incident", lock_after_competitor)
    return ran


# --- statement order -------------------------------------------------------------------------------------


def test_verification_and_decision_lock_before_reading_state(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)
    with recorded_sql() as decision_sql:
        assert request_decision(core_api, incident_id).status_code == 201
    with recorded_sql() as verify_sql:
        assert request_incident_verification(core_api, incident_id).status_code == 200

    assert_locks_before_reading_or_writing(decision_sql)
    assert_locks_before_reading_or_writing(verify_sql)


def test_authorization_request_approval_and_rejection_lock_first(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    with recorded_sql() as request_sql:
        authorization_id = request_authorization(core_api, decision_id).json()["id"]
    assert request_incident_verification(core_api, incident_id).status_code == 200
    with recorded_sql() as approve_sql:
        approved = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)
    _, _, pending_id = create_pending_authorization(core_api)
    with recorded_sql() as reject_sql:
        rejected = core_api.client.post(
            f"/api/authorizations/{pending_id}/reject", headers=core_api.approver_headers, json={"reason": "Not justified"}
        )

    assert (approved.status_code, rejected.status_code) == (200, 200)
    for statements in (request_sql, approve_sql, reject_sql):
        assert_locks_before_reading_or_writing(statements)


def test_containment_verification_and_cyber_memory_lock_first(core_api: CoreApi) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    with recorded_sql() as contain_sql:
        containment_id = UUID(contain(core_api, authorization_id).json()["id"])
    with recorded_sql() as verify_sql:
        assert verify(core_api, containment_id).status_code == 200
    with recorded_sql() as memory_sql:
        assert create_memory(core_api, incident_id).status_code == 201

    for statements in (contain_sql, verify_sql, memory_sql):
        assert_locks_before_reading_or_writing(statements)


def test_a_refused_transition_still_locks_before_its_checks(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api, state=IncidentState.UNDERSTOOD)
    with recorded_sql() as statements:
        assert request_incident_verification(core_api, incident_id).status_code == 409

    assert any(LOCK.search(s) for s in statements)
    assert not [s for s in statements if s.lstrip().upper().startswith(("INSERT", "UPDATE"))]


def test_risk_scoring_uses_the_shared_lock() -> None:
    from app.services import risk_engine

    incident_id = UUID(int=1)
    assert str(risk_engine._locked_incident(incident_id)) == str(incident_locking.locked_incident_statement(incident_id))


# --- a competitor commits while this request waits for the lock ----------------------------------------
# Both sessions share the fixture's one connection, and this request's savepoint opens (with its incident_id
# lookup) before the competitor's, so its rollback after the 409 also discards the competitor's writes. The
# final rows therefore cannot be inspected here; the refusal message shows which committed state was seen.


def refused(response: Any, detail: str) -> bool:
    return response.status_code == 409 and response.json()["detail"] == detail


def test_approval_waiting_behind_a_rejection_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id, _, authorization_id = create_pending_authorization(core_api)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    ran = compete_at_lock(
        monkeypatch,
        core_api,
        lambda db: decision_workflow.reject_decision_authorization(db, authorization_id, actor=COMPETITOR, reason="Too risky"),
    )

    response = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)

    # Without re-reading after the lock, this approval would set the incident AUTHORIZED beside a REJECTED authorization.
    assert ran and refused(response, "Authorization in REJECTED state cannot be resolved")


def test_rejection_waiting_behind_an_approval_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id, _, authorization_id = create_pending_authorization(core_api)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    ran = compete_at_lock(
        monkeypatch,
        core_api,
        lambda db: decision_workflow.approve_decision_authorization(db, authorization_id, actor=COMPETITOR),
    )

    response = core_api.client.post(
        f"/api/authorizations/{authorization_id}/reject", headers=core_api.approver_headers, json={"reason": "Late"}
    )

    assert ran and refused(response, "Authorization in APPROVED state cannot be resolved")


def test_a_second_decision_request_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = seed_prioritised_incident(core_api)
    ran = compete_at_lock(
        monkeypatch, core_api, lambda db: decision_workflow.recommend_incident_decision(db, incident_id, actor=COMPETITOR)
    )

    response = request_decision(core_api, incident_id)

    assert ran and refused(response, "A decision already exists for this incident")


def test_a_second_authorization_request_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = seed_prioritised_incident(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    ran = compete_at_lock(
        monkeypatch, core_api, lambda db: decision_workflow.request_decision_authorization(db, decision_id, actor=COMPETITOR)
    )

    response = request_authorization(core_api, decision_id)

    assert ran and refused(response, "An authorization request already exists for this decision")


def test_a_second_verification_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = seed_prioritised_incident(core_api)
    assert request_decision(core_api, incident_id).status_code == 201  # verification needs a current decision
    ran = compete_at_lock(monkeypatch, core_api, lambda db: decision_workflow.verify_incident(db, incident_id, actor=COMPETITOR))

    response = request_incident_verification(core_api, incident_id)

    assert ran and refused(response, "Incident must be PRIORITISED before verification")


def test_a_second_containment_execution_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)
    ran = compete_at_lock(
        monkeypatch,
        core_api,
        lambda db: controlled_response.simulate_authorized_containment(db, authorization_id, actor=COMPETITOR),
    )

    response = contain(core_api, authorization_id)

    assert ran and refused(response, "A containment action already exists for this authorization")


def test_a_second_containment_verification_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)
    containment_id = UUID(contain(core_api, authorization_id).json()["id"])
    ran = compete_at_lock(
        monkeypatch, core_api, lambda db: controlled_response.verify_containment(db, containment_id, actor=COMPETITOR)
    )

    response = verify(core_api, containment_id)

    assert ran and refused(response, "Containment is already resolved")


def test_a_second_cyber_memory_request_is_refused(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id, _, _, _ = create_verified_containment(core_api)
    ran = compete_at_lock(
        monkeypatch, core_api, lambda db: controlled_response.create_incident_cyber_memory(db, incident_id, actor=COMPETITOR)
    )

    response = create_memory(core_api, incident_id)

    assert ran and refused(response, "Cyber Memory already exists for this incident")


# --- a failure inside a locked transition leaves nothing behind ------------------------------------------


def test_a_failed_approval_rolls_back_the_state_change_and_releases_the_incident(
    core_api: CoreApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id, _, authorization_id = create_pending_authorization(core_api)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    history_before = actions(core_api, incident_id)

    def failing_history(**_kwargs: Any) -> IncidentHistory:
        raise RuntimeError("history write failed")

    with monkeypatch.context() as patch:
        patch.setattr(decision_workflow, "IncidentHistory", failing_history)
        with pytest.raises(RuntimeError, match="history write failed"):
            core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)

    with core_api.session_factory() as session:
        authorization = session.get(Authorization, authorization_id)
        assert (authorization.status, authorization.approved_by) == (AuthorizationStatus.PENDING, None)
        assert session.get(Incident, incident_id).state == IncidentState.VERIFIED
    assert actions(core_api, incident_id) == history_before
    # Nothing was left half-done, so the approval can be repeated.
    retried = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)
    assert (retried.status_code, retried.json()["approvedBy"]) == (200, APPROVER_EMAIL)


def test_a_containment_failing_after_its_row_is_flushed_leaves_no_containment(
    core_api: CoreApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    history_before = actions(core_api, incident_id)
    real_history = controlled_response._history

    def fail_on_execution_entry(incident: Incident, **kwargs: Any) -> IncidentHistory:
        if kwargs["action"] == "containment_executed":
            raise RuntimeError("history write failed")
        return real_history(incident, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(controlled_response, "_history", fail_on_execution_entry)
        with pytest.raises(RuntimeError, match="history write failed"):
            contain(core_api, authorization_id)

    assert count(core_api, ContainmentAction, authorization_id=authorization_id) == 0
    assert actions(core_api, incident_id) == history_before
    assert contain(core_api, authorization_id).status_code == 201
