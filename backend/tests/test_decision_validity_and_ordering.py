"""Decision validity (verification needs a current decision; responses say which decisions are current) and the
lock-ordered timestamps of evaluations, risk history entries and decisions.

No concurrent transactions run here (the fixture's schema lives inside one uncommitted transaction on a single
connection). That single transaction is useful for ordering: PostgreSQL's now() is constant inside it, so rows
written with the old now() default would tie, while the lock-ordered timestamps must still increase.
"""

from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import select

from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.decision import Decision
from app.models.enums import AuthorizationStatus, IncidentState, VulnerabilityStatus
from app.models.incident import Incident, IncidentHistory
from app.models.risk_evaluation import RiskEvaluation
from app.services.decision_validity import decision_validity
from tests.conftest import CoreApi
from tests.test_authorization import request_authorization
from tests.test_containment import contain, create_pending_authorization
from tests.test_cyber_memory import create_memory
from tests.test_decision import request_decision, seed_prioritised_incident
from tests.test_incident_verification import request_incident_verification
from tests.test_risk_v2_and_reevaluation import add_vulnerability, evaluations, incident_row, prioritised, reevaluate
from tests.test_verification import verify
from tests.test_workflow_locking import recorded_sql
from tests.test_workflow_policies import approve, failed_and_verified, reject

NEEDS_CURRENT = "A current decision is required before verification: recommend a decision for the incident's current risk score first"


def verified_entries(core_api: CoreApi, incident_id: UUID) -> int:
    with core_api.session_factory() as session:
        return len(session.scalars(
            select(IncidentHistory.id).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == "incident_verified")
        ).all())


def verification_refused(core_api: CoreApi, incident_id: UUID) -> None:
    before = verified_entries(core_api, incident_id)
    response = request_incident_verification(core_api, incident_id)
    assert (response.status_code, response.json()["detail"]) == (409, NEEDS_CURRENT)
    assert incident_row(core_api, incident_id).state == IncidentState.PRIORITISED
    assert verified_entries(core_api, incident_id) == before  # the refused attempt wrote no history


def decisions_in_detail(core_api: CoreApi, incident_id: UUID) -> dict[str, dict]:
    detail = core_api.client.get(f"/api/incidents/{incident_id}", headers=core_api.headers).json()
    return {row["id"]: row for row in detail["decisions"]}


def score_change(core_api: CoreApi, incident_id: UUID) -> float:
    """Raise the score through the real path: a new OPEN vulnerability and an explicit re-evaluation."""
    add_vulnerability(core_api, incident_id, 9.8, VulnerabilityStatus.OPEN)
    response = reevaluate(core_api, incident_id)
    assert response.status_code == 200
    return response.json()["riskScore"]


# --- decision validity (pure) ----------------------------------------------------------------------------


def test_validity_is_computed_from_the_stored_score_and_requests() -> None:
    request = lambda status: SimpleNamespace(status=status)  # noqa: E731
    decision = lambda score, *statuses: SimpleNamespace(risk_score=score, authorizations=[request(s) for s in statuses])  # noqa: E731

    assert decision_validity(decision(60.0), 60.0) == "CURRENT"
    assert decision_validity(decision(60.0, AuthorizationStatus.PENDING), 60.0) == "CURRENT"
    assert decision_validity(decision(60.0, AuthorizationStatus.REJECTED), 60.0) == "REJECTED"
    assert decision_validity(decision(60.0, AuthorizationStatus.REJECTED, AuthorizationStatus.PENDING), 60.0) == "CURRENT"
    assert decision_validity(decision(60.0), 65.0) == "SUPERSEDED"
    assert decision_validity(decision(60.0, AuthorizationStatus.REJECTED), 65.0) == "SUPERSEDED"  # superseded wins


# --- H1: verification needs a current decision -----------------------------------------------------------


def test_verification_with_a_current_decision_succeeds(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    assert request_decision(core_api, incident_id).status_code == 201

    assert request_incident_verification(core_api, incident_id).status_code == 200


def test_verification_without_any_decision_is_refused(core_api: CoreApi) -> None:
    verification_refused(core_api, seed_prioritised_incident(core_api))


def test_verification_with_only_a_superseded_decision_is_refused(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    assert request_decision(core_api, incident_id).status_code == 201
    score_change(core_api, incident_id)

    verification_refused(core_api, incident_id)


def test_verification_with_only_a_rejected_decision_is_refused_until_a_request_is_open_again(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    assert reject(core_api, UUID(request_authorization(core_api, decision_id).json()["id"])).status_code == 200

    verification_refused(core_api, incident_id)
    # A new request for the same decision (the U1 retry) makes it current again.
    assert request_authorization(core_api, decision_id).status_code == 201
    assert request_incident_verification(core_api, incident_id).status_code == 200


def test_the_reported_dead_end_cannot_be_reached(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    assert request_decision(core_api, incident_id).status_code == 201
    assert request_incident_verification(core_api, incident_id).status_code == 200
    new_score = score_change(core_api, incident_id)  # VERIFIED -> PRIORITISED

    verification_refused(core_api, incident_id)  # verifying again before a new decision is refused
    decided = request_decision(core_api, incident_id)  # so a new decision can still be recommended
    assert (decided.status_code, decided.json()["riskScore"], decided.json()["validity"]) == (201, new_score, "CURRENT")


def test_after_a_new_decision_the_full_path_completes_and_the_old_decision_stays_unusable(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    old_id = UUID(request_decision(core_api, incident_id).json()["id"])
    assert request_incident_verification(core_api, incident_id).status_code == 200
    score_change(core_api, incident_id)
    new_id = UUID(request_decision(core_api, incident_id).json()["id"])

    assert request_incident_verification(core_api, incident_id).status_code == 200
    stale = request_authorization(core_api, old_id)
    authorization_id = UUID(request_authorization(core_api, new_id).json()["id"])
    self_approval = approve(core_api, authorization_id, core_api.headers)
    approved = approve(core_api, authorization_id)
    containment = contain(core_api, authorization_id)

    assert stale.status_code == 409
    assert self_approval.status_code == 403  # separation of duties is unchanged
    assert approved.status_code == 200 and containment.status_code == 201
    decisions = decisions_in_detail(core_api, incident_id)
    assert (decisions[str(old_id)]["validity"], decisions[str(new_id)]["validity"]) == ("SUPERSEDED", "CURRENT")


# --- M1: validity in API responses -----------------------------------------------------------------------


def test_responses_mark_superseded_and_rejected_decisions_and_keep_their_scores(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    old_score = incident_row(core_api, incident_id).risk_score
    created = request_decision(core_api, incident_id).json()
    assert created["validity"] == "CURRENT"
    assert reject(core_api, UUID(request_authorization(core_api, UUID(created["id"])).json()["id"])).status_code == 200
    assert decisions_in_detail(core_api, incident_id)[created["id"]]["validity"] == "REJECTED"

    new_score = score_change(core_api, incident_id)
    replacement = request_decision(core_api, incident_id).json()

    decisions = decisions_in_detail(core_api, incident_id)
    assert (decisions[created["id"]]["validity"], decisions[created["id"]]["riskScore"]) == ("SUPERSEDED", old_score)
    assert (decisions[replacement["id"]]["validity"], decisions[replacement["id"]]["riskScore"]) == ("CURRENT", new_score)
    listed = core_api.client.get("/api/incidents", headers=core_api.headers).json()["items"]
    latest = next(item for item in listed if item["id"] == str(incident_id))["latestDecision"]
    assert (latest["id"], latest["validity"]) == (replacement["id"], "CURRENT")


def test_a_memory_reports_its_decision_as_current(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    authorization_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert request_incident_verification(core_api, incident_id).status_code == 200
    assert approve(core_api, authorization_id).status_code == 200
    assert verify(core_api, UUID(contain(core_api, authorization_id).json()["id"])).status_code == 200

    memory = create_memory(core_api, incident_id).json()

    assert memory["decision"]["validity"] == "CURRENT"


# --- L1: lock-ordered timestamps -------------------------------------------------------------------------


def test_evaluations_are_ordered_by_when_they_were_written_and_chain_their_previous_scores(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    for _ in range(3):
        assert reevaluate(core_api, incident_id).status_code == 200
    score_change(core_api, incident_id)

    rows = sorted(evaluations(core_api, incident_id), key=lambda row: row.created_at)
    listed = core_api.client.get(f"/api/incidents/{incident_id}/risk-evaluations", headers=core_api.headers).json()

    assert len({row.created_at for row in rows}) == 5  # strictly increasing, though now() is constant here
    assert [row.trigger for row in rows] == ["initial"] + ["reevaluation"] * 4
    assert all(later.previous_risk_score == earlier.risk_score for earlier, later in zip(rows, rows[1:]))
    assert [row["id"] for row in listed] == [str(row.id) for row in rows]
    assert listed[-1]["riskScore"] == incident_row(core_api, incident_id).risk_score  # the latest is the current score


def test_a_later_write_sorts_last_even_after_a_row_dated_in_the_future(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    with core_api.session_factory() as session:
        (initial,) = session.scalars(select(RiskEvaluation).where(RiskEvaluation.incident_id == incident_id)).all()
        future = initial.created_at + timedelta(days=1)  # as if the clock had stepped back since it was written
        session.execute(
            RiskEvaluation.__table__.update().where(RiskEvaluation.id == initial.id).values(created_at=future)
        )
        session.commit()

    assert reevaluate(core_api, incident_id).status_code == 200

    listed = core_api.client.get(f"/api/incidents/{incident_id}/risk-evaluations", headers=core_api.headers).json()
    assert [row["trigger"] for row in listed] == ["initial", "reevaluation"]
    with core_api.session_factory() as session:
        latest = session.scalars(
            select(RiskEvaluation).where(RiskEvaluation.incident_id == incident_id, RiskEvaluation.trigger == "reevaluation")
        ).one()
    assert latest.created_at == future + timedelta(microseconds=1)


def test_a_decision_cites_the_latest_risk_calculation(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    score_change(core_api, incident_id)

    decision_id = request_decision(core_api, incident_id).json()["id"]

    with core_api.session_factory() as session:
        reevaluated = session.scalars(
            select(IncidentHistory).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == "risk_reevaluated")
        ).one()
        recommended = session.scalars(
            select(IncidentHistory).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == "decision_recommended")
        ).one()
        calculated = session.scalars(
            select(IncidentHistory).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == "risk_calculated")
        ).one()
    assert calculated.occurred_at < reevaluated.occurred_at
    assert (recommended.details["decision_id"], recommended.details["risk_history_id"]) == (decision_id, str(reevaluated.id))


def test_the_latest_decision_is_the_one_made_last_without_adjusting_timestamps(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    first_id = UUID(request_decision(core_api, incident_id).json()["id"])
    assert reject(core_api, UUID(request_authorization(core_api, first_id).json()["id"])).status_code == 200
    second_id = UUID(request_decision(core_api, incident_id).json()["id"])

    with core_api.session_factory() as session:
        first, second = session.get(Decision, first_id), session.get(Decision, second_id)
        assert first.created_at < second.created_at
    superseded_request = request_authorization(core_api, first_id)
    assert (superseded_request.status_code, superseded_request.json()["detail"]) == (
        409, "Authorization can only be requested for the incident's latest decision",
    )
    assert request_authorization(core_api, second_id).status_code == 201


def test_the_ordered_rows_are_written_with_the_lock_ordered_timestamp(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    with recorded_sql() as statements:
        assert reevaluate(core_api, incident_id).status_code == 200
        assert request_decision(core_api, incident_id).status_code == 201

    inserts = {
        table: next(s for s in statements if s.lstrip().upper().startswith("INSERT") and f".{table} " in s)
        for table in ("risk_evaluations", "incident_history", "decisions")
    }
    for table, statement in inserts.items():
        assert "greatest(clock_timestamp()" in statement, table
    locks = [index for index, statement in enumerate(statements) if "FOR NO KEY UPDATE" in statement]
    first_insert = min(index for index, statement in enumerate(statements) if statement.lstrip().upper().startswith("INSERT"))
    assert locks and locks[0] < first_insert  # computed only while the incident lock is held


# --- retries: containment attempts and authorization requests keep their order ------------------------
# An overlapping transaction can begin before an earlier attempt committed, so a now()-based timestamp could
# date the new row before it. That is simulated by dating the earlier row later than this transaction began.


def date_later(core_api: CoreApi, model: type, row_id: UUID, column: str) -> object:
    with core_api.session_factory() as session:
        row = session.get(model, row_id)
        later = getattr(row, column) + timedelta(days=1)
        setattr(row, column, later)
        session.commit()
        return later


def requested_history(core_api: CoreApi, incident_id: UUID, action: str) -> dict[str, dict]:
    with core_api.session_factory() as session:
        rows = session.scalars(
            select(IncidentHistory).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == action)
        ).all()
    return {row.details.get("containment_id") or row.details["authorization_id"]: row.details for row in rows}


def detail(core_api: CoreApi, incident_id: UUID) -> dict:
    return core_api.client.get(f"/api/incidents/{incident_id}", headers=core_api.headers).json()


def test_a_containment_retry_sorts_after_an_attempt_dated_later_than_its_transaction(core_api: CoreApi) -> None:
    incident_id, authorization_id, failed_id = failed_and_verified(core_api)
    failed_at = date_later(core_api, ContainmentAction, failed_id, "created_at")

    retry = contain(core_api, authorization_id)

    assert retry.status_code == 201
    with core_api.session_factory() as session:
        assert session.get(ContainmentAction, UUID(retry.json()["id"])).created_at == failed_at + timedelta(microseconds=1)
    assert [row["id"] for row in detail(core_api, incident_id)["containmentActions"]] == [str(failed_id), retry.json()["id"]]
    assert requested_history(core_api, incident_id, "containment_requested")[retry.json()["id"]]["retry_of_containment_id"] == str(failed_id)


def test_successive_containment_retries_keep_their_order_and_name_the_latest_failure(core_api: CoreApi) -> None:
    incident_id, authorization_id, first_id = failed_and_verified(core_api)
    second_id = UUID(contain(core_api, authorization_id, simulate_failure=True).json()["id"])
    assert verify(core_api, second_id).status_code == 200

    third = contain(core_api, authorization_id)

    third_id = UUID(third.json()["id"])
    with core_api.session_factory() as session:
        stamps = [session.get(ContainmentAction, row_id).created_at for row_id in (first_id, second_id, third_id)]
    assert stamps[0] < stamps[1] < stamps[2]  # strictly increasing, though now() is constant in this transaction
    history = requested_history(core_api, incident_id, "containment_requested")
    assert (history[str(second_id)]["retry_of_containment_id"], history[str(third_id)]["retry_of_containment_id"]) == (
        str(first_id), str(second_id),
    )
    assert [row["id"] for row in detail(core_api, incident_id)["containmentActions"]] == [str(first_id), str(second_id), str(third_id)]


def test_a_new_request_sorts_after_a_rejected_one_dated_later_than_its_transaction(core_api: CoreApi) -> None:
    incident_id, decision_id, rejected_id = create_pending_authorization(core_api)
    assert reject(core_api, rejected_id).status_code == 200
    rejected_at = date_later(core_api, Authorization, rejected_id, "requested_at")

    retried = request_authorization(core_api, decision_id)

    assert retried.status_code == 201
    with core_api.session_factory() as session:
        assert session.get(Authorization, UUID(retried.json()["id"])).requested_at == rejected_at + timedelta(microseconds=1)
    assert [row["id"] for row in detail(core_api, incident_id)["authorizations"]] == [str(rejected_id), retried.json()["id"]]
    assert requested_history(core_api, incident_id, "authorization_requested")[retried.json()["id"]]["previous_authorization_id"] == str(rejected_id)


def test_successive_requests_keep_their_order_and_name_the_previous_one(core_api: CoreApi) -> None:
    incident_id, decision_id, first_id = create_pending_authorization(core_api)
    assert reject(core_api, first_id).status_code == 200
    second_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert reject(core_api, second_id).status_code == 200

    third_id = UUID(request_authorization(core_api, decision_id).json()["id"])

    with core_api.session_factory() as session:
        stamps = [session.get(Authorization, row_id).requested_at for row_id in (first_id, second_id, third_id)]
    assert stamps[0] < stamps[1] < stamps[2]
    history = requested_history(core_api, incident_id, "authorization_requested")
    assert "previous_authorization_id" not in history[str(first_id)]
    assert (history[str(second_id)]["previous_authorization_id"], history[str(third_id)]["previous_authorization_id"]) == (
        str(first_id), str(second_id),
    )
    assert [row["id"] for row in detail(core_api, incident_id)["authorizations"]] == [str(first_id), str(second_id), str(third_id)]


def test_containment_and_request_rows_are_written_with_the_lock_ordered_timestamp(core_api: CoreApi) -> None:
    incident_id, decision_id, rejected_id = create_pending_authorization(core_api)
    assert reject(core_api, rejected_id).status_code == 200
    with recorded_sql() as request_sql:
        authorization_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert request_incident_verification(core_api, incident_id).status_code == 200
    assert approve(core_api, authorization_id).status_code == 200
    with recorded_sql() as contain_sql:
        assert contain(core_api, authorization_id).status_code == 201

    for statements, table in ((request_sql, "authorizations"), (contain_sql, "containment_actions")):
        insert = next(i for i, s in enumerate(statements) if s.lstrip().upper().startswith("INSERT") and f".{table} " in s)
        assert "greatest(clock_timestamp()" in statements[insert], table
        lock = next(i for i, s in enumerate(statements) if "FOR NO KEY UPDATE" in s)
        assert lock < insert, table  # computed only while the incident lock is held
