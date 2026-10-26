"""Correlation and event-linking locks, and the retry, review and closed-incident policies (U1-U4).

As in test_workflow_locking, no concurrent transactions run here: the fixture's schema lives inside one
uncommitted transaction on a single connection. Competing requests are simulated by committing them in another
session at the moment the request under test asks for the incident lock.
"""

from collections.abc import Callable
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select

from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.decision import Decision
from app.models.enums import AuthorizationStatus, ContainmentStatus, DetectionSource, IncidentState
from app.models.incident import Incident, IncidentEvent, IncidentHistory
from app.services import event_correlation, incident_locking, intake
from tests.conftest import APPROVER_EMAIL, CoreApi
from tests.test_authorization import request_authorization
from tests.test_containment import contain, create_approved_authorization, create_pending_authorization
from tests.test_core_api import add_correlation_candidate, ingest_minimal_event, seed_enrichment_case
from tests.test_cyber_memory import create_memory
from tests.test_decision import request_decision, seed_prioritised_incident
from tests.test_incident_verification import request_incident_verification
from tests.test_role_permissions import headers_for
from tests.test_verification import verify
from tests.test_workflow_locking import actions, assert_locks_before_reading_or_writing, count, recorded_sql

USER = "core-api-test@example.com"


def history_rows(core_api: CoreApi, incident_id: UUID) -> list[tuple[str, str, str | None, str | None, Any]]:
    with core_api.session_factory() as session:
        rows = session.scalars(
            select(IncidentHistory)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.occurred_at, IncidentHistory.id)
        ).all()
        return [(str(row.id), row.action, row.actor, row.to_state and row.to_state.name, row.details) for row in rows]


def new_rows(before: list[tuple], after: list[tuple]) -> list[tuple]:
    """Rows added since ``before``, after checking every earlier row is still present and unchanged. Rows
    are matched by id: inside the fixture's single transaction now() is constant, so occurred_at ties."""
    current = {row[0]: row for row in after}
    assert all(current.get(row[0]) == row for row in before)
    known = {row[0] for row in before}
    return [row for row in after if row[0] not in known]


def compete_at_lock(monkeypatch: pytest.MonkeyPatch, core_api: CoreApi, competitor: Callable[[Any], object]) -> list[bool]:
    ran: list[bool] = []
    real_lock = incident_locking.lock_incident

    def lock_after_competitor(db: Any, incident_id: UUID) -> Incident | None:
        if not ran:
            ran.append(True)
            with core_api.session_factory() as other:
                competitor(other)
        return real_lock(db, incident_id)

    for module in (event_correlation, intake):
        monkeypatch.setattr(module, "lock_incident", lock_after_competitor)
    return ran


def link(core_api: CoreApi, incident_id: UUID, event_id: UUID, headers: dict[str, str] | None = None):
    return core_api.client.post(
        f"/api/incidents/{incident_id}/events", json={"event_id": str(event_id)}, headers=headers or core_api.headers
    )


def set_state(core_api: CoreApi, incident_id: UUID, state: IncidentState) -> None:
    with core_api.session_factory() as session:
        session.get(Incident, incident_id).state = state
        session.commit()


def reject(core_api: CoreApi, authorization_id: UUID, reason: str = "Not justified yet"):
    return core_api.client.post(
        f"/api/authorizations/{authorization_id}/reject", headers=core_api.approver_headers, json={"reason": reason}
    )


def approve(core_api: CoreApi, authorization_id: UUID, headers: dict[str, str] | None = None):
    return core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=headers or core_api.approver_headers)


def review(core_api: CoreApi, incident_id: UUID, body: dict[str, Any] | None, headers: dict[str, str] | None = None):
    return core_api.client.post(
        f"/api/incidents/{incident_id}/review",
        json=body,
        headers=core_api.headers if headers is None else headers,
    )


# --- Phase A: correlation and event linking take the incident lock ---------------------------------------


def test_correlation_and_linking_lock_before_reading_or_writing(core_api: CoreApi) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    add_correlation_candidate(core_api, incident_id, asset_id=asset_id, source=DetectionSource.ML_ANOMALY)
    with recorded_sql() as correlate_sql:
        assert core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers).status_code == 200
    event_id = ingest_minimal_event(core_api)
    with recorded_sql() as link_sql:
        assert link(core_api, incident_id, event_id).status_code == 201

    assert_locks_before_reading_or_writing(correlate_sql)
    assert_locks_before_reading_or_writing(link_sql)


def test_correlation_waiting_behind_another_correlation_adds_no_duplicate_link_or_history(
    core_api: CoreApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id, asset_id = seed_enrichment_case(core_api)
    candidate_id = add_correlation_candidate(core_api, incident_id, asset_id=asset_id, source=DetectionSource.ML_ANOMALY)
    ran = compete_at_lock(
        monkeypatch, core_api, lambda db: event_correlation.correlate_incident_events(db, incident_id, actor="competitor@example.com")
    )

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    # This request saw the competitor's committed link and state: nothing new to correlate, no transition.
    assert ran and response.status_code == 200
    assert (response.json()["state"], response.json()["stateTransition"], response.json()["correlatedEvents"]) == (
        "UNDERSTOOD",
        None,
        [],
    )
    assert count(core_api, IncidentEvent, incident_id=incident_id, event_id=candidate_id) == 1
    correlated = [row for row in history_rows(core_api, incident_id) if row[1] == "events_correlated"]
    assert [(row[2], row[3]) for row in correlated] == [("competitor@example.com", "UNDERSTOOD")]


def test_identical_link_waiting_behind_the_same_link_stays_idempotent(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    event_id = ingest_minimal_event(core_api)
    ran = compete_at_lock(
        monkeypatch, core_api, lambda db: intake.link_event_to_incident(db, incident_id, event_id, actor="competitor@example.com")
    )

    response = link(core_api, incident_id, event_id)

    assert ran and (response.status_code, response.json()["status"]) == (201, "linked")
    assert count(core_api, IncidentEvent, incident_id=incident_id, event_id=event_id) == 1
    assert [row[2] for row in history_rows(core_api, incident_id) if row[1] == "event_linked"] == ["competitor@example.com"]


# --- U4: completed incidents accept no new events --------------------------------------------------------


@pytest.mark.parametrize("state", [IncidentState.CONTAINED, IncidentState.LEARNED])
def test_new_events_cannot_be_linked_to_a_completed_incident(core_api: CoreApi, state: IncidentState) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    set_state(core_api, incident_id, state)
    history_before = history_rows(core_api, incident_id)
    event_id = ingest_minimal_event(core_api)

    response = link(core_api, incident_id, event_id)

    assert (response.status_code, response.json()["detail"]) == (409, f"Incident in {state.name} state cannot accept new events")
    assert count(core_api, IncidentEvent, event_id=event_id) == 0
    assert history_rows(core_api, incident_id) == history_before
    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == state


def test_resending_an_existing_link_to_a_completed_incident_changes_nothing(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    event_id = ingest_minimal_event(core_api)
    assert link(core_api, incident_id, event_id).status_code == 201
    set_state(core_api, incident_id, IncidentState.LEARNED)
    history_before = history_rows(core_api, incident_id)

    response = link(core_api, incident_id, event_id)

    assert (response.status_code, response.json()["eventId"]) == (201, str(event_id))
    assert count(core_api, IncidentEvent, incident_id=incident_id) == 2
    assert history_rows(core_api, incident_id) == history_before


@pytest.mark.parametrize("state", [IncidentState.DETECTED, IncidentState.PRIORITISED, IncidentState.AUTHORIZED])
def test_events_can_still_be_linked_to_an_incident_in_progress(core_api: CoreApi, state: IncidentState) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    set_state(core_api, incident_id, state)

    assert link(core_api, incident_id, ingest_minimal_event(core_api)).status_code == 201


# --- U1: a new attempt after a rejected authorization ----------------------------------------------------


def test_a_rejected_request_can_be_made_again_and_approved_without_touching_the_rejection(core_api: CoreApi) -> None:
    incident_id, decision_id, rejected_id = create_pending_authorization(core_api)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    assert reject(core_api, rejected_id).status_code == 200
    history_before = history_rows(core_api, incident_id)

    retried = request_authorization(core_api, decision_id)
    self_approval = approve(core_api, UUID(retried.json()["id"]), core_api.headers)
    approved = approve(core_api, UUID(retried.json()["id"]))

    assert (retried.status_code, retried.json()["status"], retried.json()["decisionId"]) == (201, "PENDING", str(decision_id))
    assert self_approval.status_code == 403  # the requester still cannot approve their own request
    assert (approved.status_code, approved.json()["approvedBy"]) == (200, APPROVER_EMAIL)
    with core_api.session_factory() as session:
        rejected = session.get(Authorization, rejected_id)
        assert (rejected.status, rejected.approved_by, rejected.reason) == (
            AuthorizationStatus.REJECTED,
            APPROVER_EMAIL,
            "Not justified yet",
        )
        assert session.get(Incident, incident_id).state == IncidentState.AUTHORIZED
    # Earlier entries, the rejection included, are unchanged; the new request names the rejected one.
    added = new_rows(history_before, history_rows(core_api, incident_id))
    assert [row[4]["previous_authorization_id"] for row in added if row[1] == "authorization_requested"] == [str(rejected_id)]


def test_a_request_cannot_be_repeated_while_one_is_open(core_api: CoreApi) -> None:
    incident_id, decision_id, rejected_id = create_pending_authorization(core_api)
    duplicate_while_pending = request_authorization(core_api, decision_id)
    assert reject(core_api, rejected_id).status_code == 200
    assert request_authorization(core_api, decision_id).status_code == 201
    duplicate_retry = request_authorization(core_api, decision_id)

    for response in (duplicate_while_pending, duplicate_retry):
        assert (response.status_code, response.json()["detail"]) == (409, "An authorization request already exists for this decision")
    assert count(core_api, Authorization, decision_id=decision_id) == 2
    assert actions(core_api, incident_id).count("authorization_requested") == 2


def test_an_approved_request_cannot_be_requested_again(core_api: CoreApi) -> None:
    _, decision_id, _ = create_approved_authorization(core_api)

    response = request_authorization(core_api, decision_id)

    assert response.status_code == 409  # the incident is AUTHORIZED: the existing state rule applies
    assert count(core_api, Authorization, decision_id=decision_id) == 1


def test_a_new_decision_is_allowed_only_after_the_previous_one_was_rejected(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)
    first_id = UUID(request_decision(core_api, incident_id).json()["id"])
    without_request = request_decision(core_api, incident_id)
    pending_id = UUID(request_authorization(core_api, first_id).json()["id"])
    while_pending = request_decision(core_api, incident_id)
    assert reject(core_api, pending_id).status_code == 200

    second = request_decision(core_api, incident_id)

    for response in (without_request, while_pending):
        assert (response.status_code, response.json()["detail"]) == (409, "A decision already exists for this incident")
    assert second.status_code == 201 and second.json()["id"] != str(first_id)
    assert count(core_api, Decision, incident_id=incident_id) == 2
    recommended = {row[4]["decision_id"]: row[4] for row in history_rows(core_api, incident_id) if row[1] == "decision_recommended"}
    assert "previous_decision_id" not in recommended[str(first_id)]
    assert recommended[second.json()["id"]]["previous_decision_id"] == str(first_id)


def test_only_the_latest_decision_can_be_authorized_and_only_one_request_is_open(core_api: CoreApi) -> None:
    incident_id = seed_prioritised_incident(core_api)
    first_id = UUID(request_decision(core_api, incident_id).json()["id"])
    assert reject(core_api, UUID(request_authorization(core_api, first_id).json()["id"])).status_code == 200
    second_id = UUID(request_decision(core_api, incident_id).json()["id"])
    # Separate requests commit at different times; inside the fixture's one transaction now() is constant.
    with core_api.session_factory() as session:
        first, second = session.get(Decision, first_id), session.get(Decision, second_id)
        first.created_at = second.created_at - timedelta(minutes=1)
        session.commit()

    superseded = request_authorization(core_api, first_id)
    current = request_authorization(core_api, second_id)
    while_open = request_authorization(core_api, first_id)

    assert (superseded.status_code, superseded.json()["detail"]) == (
        409,
        "Authorization can only be requested for the incident's latest decision",
    )
    assert current.status_code == 201
    assert (while_open.status_code, while_open.json()["detail"]) == (409, "Another authorization request is already open for this incident")
    assert count(core_api, Authorization, decision_id=first_id) == 1


# --- U2: a new containment attempt after a verified failure ----------------------------------------------


def failed_and_verified(core_api: CoreApi) -> tuple[UUID, UUID, UUID]:
    incident_id, _, authorization_id = create_approved_authorization(core_api)
    failed_id = UUID(contain(core_api, authorization_id, simulate_failure=True).json()["id"])
    verification = verify(core_api, failed_id)
    assert (verification.status_code, verification.json()["status"]) == (200, "FAILED")
    return incident_id, authorization_id, failed_id


def test_a_verified_failure_can_be_retried_with_a_new_record(core_api: CoreApi) -> None:
    incident_id, authorization_id, failed_id = failed_and_verified(core_api)
    with core_api.session_factory() as session:
        failed = session.get(ContainmentAction, failed_id)
        failed_before = (failed.status, failed.result, failed.error_message, failed.verified_at)
    history_before = history_rows(core_api, incident_id)

    retry = contain(core_api, authorization_id)
    verified = verify(core_api, UUID(retry.json()["id"]))
    memory = create_memory(core_api, incident_id)

    assert (retry.status_code, retry.json()["status"]) == (201, "SUCCEEDED") and retry.json()["id"] != str(failed_id)
    assert (verified.status_code, verified.json()["status"]) == (200, "VERIFIED")
    assert memory.status_code == 201
    with core_api.session_factory() as session:
        failed = session.get(ContainmentAction, failed_id)
        assert (failed.status, failed.result, failed.error_message, failed.verified_at) == failed_before
        assert session.get(Incident, incident_id).state == IncidentState.LEARNED
    added = new_rows(history_before, history_rows(core_api, incident_id))
    assert [row[4]["retry_of_containment_id"] for row in added if row[1] == "containment_requested"] == [str(failed_id)]
    assert verify(core_api, failed_id).status_code == 409  # the failed attempt stays resolved


def test_a_failed_retry_can_be_retried_again_after_its_verification(core_api: CoreApi) -> None:
    incident_id, authorization_id, _ = failed_and_verified(core_api)
    second_id = UUID(contain(core_api, authorization_id, simulate_failure=True).json()["id"])
    before_verification = contain(core_api, authorization_id)
    assert verify(core_api, second_id).status_code == 200

    third = contain(core_api, authorization_id)

    assert (before_verification.status_code, before_verification.json()["detail"]) == (
        409,
        "A containment action already exists for this authorization",
    )
    assert third.status_code == 201
    assert count(core_api, ContainmentAction, authorization_id=authorization_id) == 3
    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == IncidentState.AUTHORIZED


def test_containment_cannot_be_repeated_while_an_attempt_is_unresolved_or_after_success(core_api: CoreApi) -> None:
    incident_id, authorization_id, _ = failed_and_verified(core_api)
    retry_id = UUID(contain(core_api, authorization_id).json()["id"])
    repeated = contain(core_api, authorization_id)
    assert verify(core_api, retry_id).status_code == 200
    after_success = contain(core_api, authorization_id)

    assert (repeated.status_code, repeated.json()["detail"]) == (409, "A containment action already exists for this authorization")
    assert (after_success.status_code, after_success.json()["detail"]) == (409, "Incident must be AUTHORIZED before containment")
    assert count(core_api, ContainmentAction, authorization_id=authorization_id) == 2
    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == IncidentState.CONTAINED


def test_an_unverified_failure_cannot_be_retried(core_api: CoreApi) -> None:
    _, _, authorization_id = create_approved_authorization(core_api)
    assert contain(core_api, authorization_id, simulate_failure=True).status_code == 201

    response = contain(core_api, authorization_id)

    assert (response.status_code, response.json()["detail"]) == (409, "A containment action already exists for this authorization")
    assert count(core_api, ContainmentAction, authorization_id=authorization_id) == 1


# --- U3: analyst review when correlation finds no related events ------------------------------------------


def test_correlation_without_related_events_does_not_advance_the_incident(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)

    response = core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers)

    assert (response.status_code, response.json()["state"], response.json()["stateTransition"]) == (200, "DETECTED", None)
    assert "analyst_reviewed" not in actions(core_api, incident_id)


def test_an_analyst_review_moves_an_uncorrelated_incident_to_understood_and_is_audited(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    assert core_api.client.post(f"/api/incidents/{incident_id}/correlate", headers=core_api.headers).json()["state"] == "DETECTED"

    with recorded_sql() as statements:
        response = review(core_api, incident_id, {"reason": "  Single isolated alert, confirmed by the asset owner.  "})
    scored = core_api.client.post(f"/api/incidents/{incident_id}/risk-score", headers=core_api.headers)

    assert (response.status_code, response.json()["state"], response.json()["id"]) == (200, "UNDERSTOOD", str(incident_id))
    assert_locks_before_reading_or_writing(statements)
    entry = next(row for row in history_rows(core_api, incident_id) if row[1] == "analyst_reviewed")
    assert (entry[2], entry[3], entry[4]) == (
        USER,
        "UNDERSTOOD",
        {"reason": "Single isolated alert, confirmed by the asset owner.", "linked_event_count": 1},
    )
    assert scored.status_code == 200  # the rest of the lifecycle continues as before


def test_review_is_refused_outside_detected_or_without_events(core_api: CoreApi) -> None:
    understood_id, _ = seed_enrichment_case(core_api)
    set_state(core_api, understood_id, IncidentState.UNDERSTOOD)
    empty = core_api.client.post("/api/incidents", json={"title": "No events yet"}, headers=core_api.headers).json()

    wrong_state = review(core_api, understood_id, {"reason": "Looks fine"})
    no_events = review(core_api, UUID(empty["id"]), {"reason": "Looks fine"})

    assert (wrong_state.status_code, wrong_state.json()["detail"]) == (409, "Incident in UNDERSTOOD state cannot be reviewed")
    assert (no_events.status_code, no_events.json()["detail"]) == (409, "Incident must have at least one linked event before review")
    assert "analyst_reviewed" not in actions(core_api, understood_id) + actions(core_api, UUID(empty["id"]))


def test_review_requires_a_reason_a_known_incident_and_the_workflow_permission(core_api: CoreApi) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    viewer = headers_for(core_api, role="viewer")

    responses = {
        "missing reason": review(core_api, incident_id, {}),
        "empty reason": review(core_api, incident_id, {"reason": ""}),
        "blank reason": review(core_api, incident_id, {"reason": "   "}),
        "unauthenticated": review(core_api, incident_id, {"reason": "ok"}, headers={}),
        "no permission": review(core_api, incident_id, {"reason": "ok"}, headers=viewer),
    }
    unknown = review(core_api, UUID(int=7), {"reason": "ok"})

    assert {name: response.status_code for name, response in responses.items()} == {
        "missing reason": 422,
        "empty reason": 422,
        "blank reason": 422,
        "unauthenticated": 401,
        "no permission": 403,
    }
    assert unknown.status_code == 404
    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == IncidentState.DETECTED
    assert "analyst_reviewed" not in actions(core_api, incident_id)


def test_a_failed_review_rolls_back_the_transition(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id, _ = seed_enrichment_case(core_api)
    history_before = history_rows(core_api, incident_id)

    def failing_history(**_kwargs: Any) -> IncidentHistory:
        raise RuntimeError("history write failed")

    with monkeypatch.context() as patch:
        patch.setattr(event_correlation, "IncidentHistory", failing_history)
        with pytest.raises(RuntimeError, match="history write failed"):
            review(core_api, incident_id, {"reason": "Isolated alert"})

    with core_api.session_factory() as session:
        assert session.get(Incident, incident_id).state == IncidentState.DETECTED
    assert history_rows(core_api, incident_id) == history_before
    assert review(core_api, incident_id, {"reason": "Isolated alert"}).status_code == 200
