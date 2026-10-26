"""risk-v2 (OPEN-only vulnerabilities) and explicit risk re-evaluation.

The pure tests pin risk-v2 by hand-computed figures and by parity with the risk-v1 snapshot; risk-v1 itself stays
pinned, unchanged, by test_risk_engine.py. As elsewhere, no concurrent transactions run: the fixture's schema lives
inside one uncommitted transaction on a single connection, so a competing request is simulated at the lock point.
"""

from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.decision import Decision
from app.models.enums import AuthorizationStatus, IncidentState, Severity, VulnerabilityStatus
from app.models.incident import Incident, IncidentHistory
from app.models.risk_evaluation import RiskEvaluation
from app.models.vulnerability import Vulnerability
from app.schemas.enrichment import VulnerabilityContext
from app.services import decision_workflow, risk_engine
from tests.conftest import CoreApi
from tests.test_authorization import request_authorization
from tests.test_containment import contain
from tests.test_decision import request_decision
from tests.test_incident_verification import request_incident_verification
from tests.test_risk_engine import (
    SNAPSHOT_CASES,
    _expected,
    _scored_view,
    _snapshot_asset,
    _snapshot_bundle,
    _snapshot_event,
    calculate,
    seed_risk_case,
)
from tests.test_role_permissions import headers_for
from tests.test_workflow_locking import assert_locks_before_reading_or_writing, recorded_sql

STATUSES = ("OPEN", "MITIGATED", "ACCEPTED", "FALSE_POSITIVE")
# risk-v2 keeps these factors' values and evidence but drops risk-v1's "V1" from their reason text.
REWORDED_FACTORS = ("asset_criticality", "detection")


def vulnerability(index: int, cvss: float | None, status: str) -> VulnerabilityContext:
    return VulnerabilityContext(
        id=UUID(int=500 + index),
        cve_id=f"CVE-2026-{30000 + index}",
        title=f"v2 vulnerability {index}",
        description=None,
        cvss_score=cvss,
        severity="HIGH",
        status=status,
    )


def bundle(*vulnerabilities: VulnerabilityContext):
    # HIGH asset (18.75) and one SURICATA port scan without anomaly score (detection 12.75; attack context 0).
    return _snapshot_bundle(_snapshot_asset("HIGH"), [_snapshot_event(0, "port_scan", "SURICATA", None)], vulnerabilities)


# --- risk-v2 scoring (pure) ------------------------------------------------------------------------------

V2_CASES: dict[str, tuple[tuple[VulnerabilityContext, ...], float, str, float]] = {
    # name: (vulnerabilities, risk-v2 score, level, risk-v1 score for the same context)
    "mixed_statuses": (
        (vulnerability(0, 5.0, "OPEN"), vulnerability(1, 9.8, "MITIGATED"), vulnerability(2, 9.0, "ACCEPTED"), vulnerability(3, 10.0, "FALSE_POSITIVE")),
        41.5, "MEDIUM", 51.5,
    ),
    "only_open": ((vulnerability(0, 8.0, "OPEN"),), 47.5, "MEDIUM", 47.5),
    "only_mitigated": ((vulnerability(0, 8.0, "MITIGATED"),), 31.5, "MEDIUM", 47.5),
    "only_accepted": ((vulnerability(0, 8.0, "ACCEPTED"),), 31.5, "MEDIUM", 47.5),
    "only_false_positive": ((vulnerability(0, 8.0, "FALSE_POSITIVE"),), 31.5, "MEDIUM", 47.5),
    "open_without_cvss_and_closed_with_cvss": ((vulnerability(0, None, "OPEN"), vulnerability(1, 9.8, "MITIGATED")), 31.5, "MEDIUM", 51.1),
    "no_vulnerabilities": ((), 31.5, "MEDIUM", 31.5),
}


@pytest.mark.parametrize("name", sorted(V2_CASES))
def test_risk_v2_counts_only_open_vulnerabilities(name: str) -> None:
    vulnerabilities, v2_score, v2_level, v1_score = V2_CASES[name]
    v2 = risk_engine.score_context_v2(bundle(*vulnerabilities))
    v1 = risk_engine.score_context(bundle(*vulnerabilities))

    assert (v2.methodology_version, v2.risk_score, v2.severity) == ("risk-v2", v2_score, v2_level)
    assert (v1.methodology_version, v1.risk_score) == ("risk-v1", v1_score)  # risk-v1 still counts every status
    # Only the vulnerability factor differs between the versions.
    # Only the vulnerability factor differs in value; two shared factors only reword their reason (see below).
    for factor in ("asset_criticality", "anomaly", "detection", "threat_intelligence", "attack_context"):
        assert v2.factors[factor].model_dump(exclude={"reason"}) == v1.factors[factor].model_dump(exclude={"reason"})
        if factor not in REWORDED_FACTORS:
            assert v2.factors[factor].reason == v1.factors[factor].reason


def test_risk_v2_evidence_names_every_vulnerability_and_why_it_does_not_count() -> None:
    vulnerabilities = V2_CASES["mixed_statuses"][0]
    factor = risk_engine.score_context_v2(bundle(*vulnerabilities)).factors["vulnerability"]

    assert factor.evidence == [
        "CVE-2026-30000: CVSS 5.0, severity HIGH, status OPEN.",
        "CVE-2026-30001: CVSS 9.8, severity HIGH, status MITIGATED. Not counted in risk-v2: only OPEN vulnerabilities count.",
        "CVE-2026-30002: CVSS 9.0, severity HIGH, status ACCEPTED. Not counted in risk-v2: the risk was accepted; "
        "the vulnerability may still be present.",
        "CVE-2026-30003: CVSS 10.0, severity HIGH, status FALSE_POSITIVE. Not counted in risk-v2: only OPEN vulnerabilities count.",
    ]
    assert (factor.normalized_value, factor.contribution) == (50.0, 10.0)
    assert "among OPEN vulnerabilities (5)" in factor.reason


def test_risk_v2_reports_missing_open_evidence_instead_of_inventing_it() -> None:
    scored = risk_engine.score_context_v2(bundle(*V2_CASES["only_accepted"][0]))

    assert scored.factors["vulnerability"].contribution == 0
    assert "No OPEN vulnerability with a CVSS score is available." in scored.missing_evidence
    assert risk_engine.score_context_v2(bundle()).factors["vulnerability"].evidence == ["No vulnerabilities are linked to the asset."]


@pytest.mark.parametrize("name", sorted(SNAPSHOT_CASES))
def test_risk_v2_matches_every_risk_v1_snapshot_figure_when_all_vulnerabilities_are_open(name: str) -> None:
    # Every risk-v1 snapshot case has only OPEN vulnerabilities, so risk-v2 must give the same numbers; only the
    # vulnerability factor's wording (and its missing-evidence note) may differ.
    expected = _expected(name)
    actual = _scored_view(risk_engine.score_context_v2(SNAPSHOT_CASES[name]()))

    assert (actual["riskScore"], actual["severity"]) == (expected["riskScore"], expected["severity"])
    for factor, values in expected["factors"].items():
        numbers = ("normalizedValue", "weight", "contribution")
        assert {key: actual["factors"][factor][key] for key in numbers} == {key: values[key] for key in numbers}
        if factor != "vulnerability":
            assert {k: v for k, v in actual["factors"][factor].items() if k != "reason"} == {
                k: v for k, v in values.items() if k != "reason"
            }
            if factor not in REWORDED_FACTORS:
                assert actual["factors"][factor]["reason"] == values["reason"]


def test_risk_v2_reasons_do_not_call_the_shared_factors_v1_and_v1_wording_is_unchanged() -> None:
    context = bundle(*V2_CASES["mixed_statuses"][0])
    v1, v2 = risk_engine.score_context(context), risk_engine.score_context_v2(context)

    assert all("V1" not in reason for reason in v2.reasons)
    assert v2.factors["asset_criticality"].reason.endswith("context only in this factor, unchanged from risk-v1.")
    assert v2.factors["detection"].reason.startswith("The highest linked-event source mapping is used as a confidence proxy, unchanged from risk-v1;")
    assert v1.factors["asset_criticality"].reason.endswith("exposure and status are context only in this V1 factor.")
    assert v1.factors["detection"].reason.startswith("The highest linked-event source mapping is used as a V1 confidence proxy;")


def test_risk_v1_is_still_the_pinned_score_context() -> None:
    assert risk_engine.RISK_METHODOLOGY_VERSION == "risk-v1" and risk_engine.RISK_V2_METHODOLOGY_VERSION == "risk-v2"
    assert risk_engine.score_context(bundle(*V2_CASES["mixed_statuses"][0])).methodology_version == "risk-v1"


# --- database-backed helpers -----------------------------------------------------------------------------


def asset_id_of(core_api: CoreApi, incident_id: UUID) -> UUID:
    with core_api.session_factory() as session:
        return session.get(Incident, incident_id).asset_id


def add_vulnerability(core_api: CoreApi, incident_id: UUID, cvss: float, status: VulnerabilityStatus) -> UUID:
    with core_api.session_factory() as session:
        row = Vulnerability(
            asset_id=asset_id_of(core_api, incident_id),
            cve_id=None,
            title=f"Added {status.name} vulnerability",
            cvss_score=cvss,
            severity=Severity.CRITICAL,
            status=status,
        )
        session.add(row)
        session.commit()
        return row.id


def set_status(core_api: CoreApi, vulnerability_id: UUID, status: VulnerabilityStatus) -> None:
    with core_api.session_factory() as session:
        session.get(Vulnerability, vulnerability_id).status = status
        session.commit()


def make_earlier(core_api: CoreApi, decision_id: UUID) -> None:
    """Separate requests commit at different times; inside the fixture's one transaction now() is constant, so
    the decision made first is dated a minute earlier to keep "latest decision" unambiguous."""
    with core_api.session_factory() as session:
        decision = session.get(Decision, decision_id)
        decision.created_at = decision.created_at - timedelta(minutes=1)
        session.commit()


def prioritised(core_api: CoreApi) -> UUID:
    incident_id = seed_risk_case(core_api, cvss_scores=[7.1])
    assert calculate(core_api, incident_id).status_code == 200
    return incident_id


def reevaluate(core_api: CoreApi, incident_id: UUID, headers: dict[str, str] | None = None):
    return core_api.client.post(
        f"/api/incidents/{incident_id}/risk-reevaluation", headers=core_api.headers if headers is None else headers
    )


def evaluations(core_api: CoreApi, incident_id: UUID) -> list[RiskEvaluation]:
    with core_api.session_factory() as session:
        return list(session.scalars(select(RiskEvaluation).where(RiskEvaluation.incident_id == incident_id)))


def history(core_api: CoreApi, incident_id: UUID, action: str) -> list[IncidentHistory]:
    with core_api.session_factory() as session:
        return list(
            session.scalars(select(IncidentHistory).where(IncidentHistory.incident_id == incident_id, IncidentHistory.action == action))
        )


def incident_row(core_api: CoreApi, incident_id: UUID) -> Incident:
    with core_api.session_factory() as session:
        return session.get(Incident, incident_id)


# --- risk-v2 through the API -----------------------------------------------------------------------------


def test_a_new_calculation_ignores_closed_vulnerabilities(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[5.0])
    for status in (VulnerabilityStatus.MITIGATED, VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.FALSE_POSITIVE):
        add_vulnerability(core_api, incident_id, 9.9, status)

    body = calculate(core_api, incident_id).json()

    assert (body["factors"]["vulnerability"]["normalizedValue"], body["factors"]["vulnerability"]["contribution"]) == (50.0, 10.0)
    (evaluation,) = evaluations(core_api, incident_id)
    assert (evaluation.methodology_version, evaluation.risk_score) == ("risk-v2", body["riskScore"])


def test_stored_risk_v1_evaluations_stay_readable_and_labelled(core_api: CoreApi) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[7.1], state=IncidentState.PRIORITISED)
    with core_api.session_factory() as session:
        session.add(
            RiskEvaluation(
                incident_id=incident_id, methodology_version="risk-v1", risk_score=12.0, risk_level="LOW",
                previous_risk_score=None, factors={}, missing_evidence=[], matched_indicators=[],
                trigger="initial", actor="legacy@example.com",
            )
        )
        session.commit()

    assert reevaluate(core_api, incident_id).status_code == 200
    listed = core_api.client.get(f"/api/incidents/{incident_id}/risk-evaluations", headers=core_api.headers).json()

    by_trigger = {row["trigger"]: row for row in listed}
    assert (by_trigger["initial"]["methodologyVersion"], by_trigger["initial"]["riskScore"], by_trigger["initial"]["actor"]) == (
        "risk-v1", 12.0, "legacy@example.com",
    )
    assert (by_trigger["reevaluation"]["methodologyVersion"], by_trigger["reevaluation"]["previousRiskScore"]) == ("risk-v2", 12.0)


# --- explicit re-evaluation ------------------------------------------------------------------------------


def test_an_unchanged_score_appends_an_evaluation_and_keeps_the_decision_usable(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    score = incident_row(core_api, incident_id).risk_score
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])

    with recorded_sql() as statements:
        response = reevaluate(core_api, incident_id)

    assert response.status_code == 200
    assert (response.json()["riskScore"], response.json()["stateTransition"]) == (
        score, {"fromState": "PRIORITISED", "toState": "PRIORITISED", "action": "risk_reevaluated"},
    )
    assert_locks_before_reading_or_writing(statements)
    rows = evaluations(core_api, incident_id)
    assert sorted(row.trigger for row in rows) == ["initial", "reevaluation"]
    reevaluation = next(row for row in rows if row.trigger == "reevaluation")
    assert (reevaluation.previous_risk_score, reevaluation.risk_score, reevaluation.actor) == (score, score, "core-api-test@example.com")
    (entry,) = history(core_api, incident_id, "risk_reevaluated")
    assert (entry.details["score_changed"], entry.details["previous_risk_score"]) == (False, score)
    assert request_authorization(core_api, decision_id).status_code == 201  # the decision still matches the score


def test_a_changed_score_supersedes_the_decision_and_a_new_one_can_be_authorized(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    old_score = incident_row(core_api, incident_id).risk_score
    old_decision = UUID(request_decision(core_api, incident_id).json()["id"])
    make_earlier(core_api, old_decision)
    add_vulnerability(core_api, incident_id, 9.8, VulnerabilityStatus.OPEN)

    response = reevaluate(core_api, incident_id)
    stale_request = request_authorization(core_api, old_decision)
    new_decision = request_decision(core_api, incident_id)

    new_score = response.json()["riskScore"]
    assert response.status_code == 200 and new_score > old_score
    assert incident_row(core_api, incident_id).state == IncidentState.PRIORITISED
    assert (stale_request.status_code, stale_request.json()["detail"]) == (
        409, "Decision risk score no longer matches the incident risk score",
    )
    assert new_decision.status_code == 201 and new_decision.json()["riskScore"] == new_score
    assert request_authorization(core_api, UUID(new_decision.json()["id"])).status_code == 201
    with core_api.session_factory() as session:
        assert session.get(Decision, old_decision).risk_score == old_score  # the earlier decision is kept as it was


def test_a_changed_score_returns_a_verified_incident_to_prioritised_and_needs_new_verification(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    old_decision = UUID(request_decision(core_api, incident_id).json()["id"])
    make_earlier(core_api, old_decision)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    add_vulnerability(core_api, incident_id, 9.8, VulnerabilityStatus.OPEN)

    response = reevaluate(core_api, incident_id)
    decided = request_decision(core_api, incident_id)
    assert decided.status_code == 201, decided.json()
    new_decision = UUID(decided.json()["id"])
    authorization_id = UUID(request_authorization(core_api, new_decision).json()["id"])
    before_verification = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    self_approval = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.headers)
    approved = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)

    assert response.json()["stateTransition"] == {"fromState": "VERIFIED", "toState": "PRIORITISED", "action": "risk_reevaluated"}
    assert (before_verification.status_code, before_verification.json()["detail"]) == (409, "Incident must be VERIFIED before authorization approval")
    assert self_approval.status_code == 403  # separation of duties still applies
    assert approved.status_code == 200
    assert contain(core_api, authorization_id).status_code == 201
    assert len(history(core_api, incident_id, "incident_verified")) == 2  # verification was repeated, not skipped


def test_an_unchanged_score_keeps_a_verified_incident_verified(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    assert request_incident_verification(core_api, incident_id).status_code == 200

    response = reevaluate(core_api, incident_id)

    assert response.json()["stateTransition"]["toState"] == "VERIFIED"
    assert incident_row(core_api, incident_id).state == IncidentState.VERIFIED
    authorization_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers).status_code == 200


@pytest.mark.parametrize("state", [IncidentState.UNDERSTOOD, IncidentState.AUTHORIZED, IncidentState.CONTAINED, IncidentState.LEARNED])
def test_reevaluation_is_refused_outside_prioritised_and_verified(core_api: CoreApi, state: IncidentState) -> None:
    incident_id = seed_risk_case(core_api, cvss_scores=[7.1], state=state)

    response = reevaluate(core_api, incident_id)

    assert (response.status_code, response.json()["detail"]) == (409, "Risk can be re-evaluated only for a scored PRIORITISED or VERIFIED incident")
    assert evaluations(core_api, incident_id) == [] and history(core_api, incident_id, "risk_reevaluated") == []


def test_reevaluation_needs_authentication_permission_and_a_known_incident(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)

    assert reevaluate(core_api, incident_id, headers={}).status_code == 401
    assert reevaluate(core_api, incident_id, headers=headers_for(core_api, role="viewer")).status_code == 403
    assert reevaluate(core_api, UUID(int=3)).status_code == 404
    assert len(evaluations(core_api, incident_id)) == 1


def test_reevaluation_is_refused_while_an_authorization_request_is_open(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    assert request_authorization(core_api, decision_id).status_code == 201
    add_vulnerability(core_api, incident_id, 9.8, VulnerabilityStatus.OPEN)
    score = incident_row(core_api, incident_id).risk_score

    response = reevaluate(core_api, incident_id)

    assert (response.status_code, response.json()["detail"]) == (409, "Risk cannot be re-evaluated while an authorization request is open")
    assert incident_row(core_api, incident_id).risk_score == score
    assert len(evaluations(core_api, incident_id)) == 1


def test_repeated_reevaluations_append_a_chain_of_evaluations(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    first = reevaluate(core_api, incident_id).json()["riskScore"]
    vulnerability_id = add_vulnerability(core_api, incident_id, 9.8, VulnerabilityStatus.OPEN)
    second = reevaluate(core_api, incident_id).json()["riskScore"]
    set_status(core_api, vulnerability_id, VulnerabilityStatus.FALSE_POSITIVE)
    third = reevaluate(core_api, incident_id).json()["riskScore"]

    assert third == first != second  # a false positive stops counting again
    rows = [row for row in evaluations(core_api, incident_id) if row.trigger == "reevaluation"]
    assert sorted((row.previous_risk_score, row.risk_score) for row in rows) == sorted([(first, first), (first, second), (second, third)])
    assert len(history(core_api, incident_id, "risk_reevaluated")) == 3


def test_a_failed_reevaluation_rolls_back_every_write(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = prioritised(core_api)
    request_decision(core_api, incident_id)
    assert request_incident_verification(core_api, incident_id).status_code == 200
    add_vulnerability(core_api, incident_id, 9.8, VulnerabilityStatus.OPEN)
    before = incident_row(core_api, incident_id)
    # An empty methodology version violates the evaluation's CHECK constraint inside the single commit.
    monkeypatch.setattr(risk_engine, "RISK_V2_METHODOLOGY_VERSION", "")

    with pytest.raises(IntegrityError, match="ck_risk_evaluations_methodology_version_present"):
        reevaluate(core_api, incident_id)

    after = incident_row(core_api, incident_id)
    assert (after.risk_score, after.state) == (before.risk_score, IncidentState.VERIFIED)
    assert len(evaluations(core_api, incident_id)) == 1 and history(core_api, incident_id, "risk_reevaluated") == []


def test_reevaluation_rechecks_open_requests_after_taking_the_lock(core_api: CoreApi, monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    real_statement = risk_engine._locked_incident
    ran: list[bool] = []

    def competitor_first(locked_id: UUID) -> Any:
        if not ran:
            ran.append(True)
            with core_api.session_factory() as other:
                decision_workflow.request_decision_authorization(other, decision_id, actor="competitor@example.com")
        return real_statement(locked_id)

    monkeypatch.setattr(risk_engine, "_locked_incident", competitor_first)
    response = reevaluate(core_api, incident_id)

    assert ran and (response.status_code, response.json()["detail"]) == (409, "Risk cannot be re-evaluated while an authorization request is open")


# --- a score change can never reuse an approval made for another score -----------------------------------


def change_score(core_api: CoreApi, incident_id: UUID, delta: float = 5.0) -> None:
    """Any path that leaves the incident with a score other than the decision's (simulated directly)."""
    with core_api.session_factory() as session:
        incident = session.get(Incident, incident_id)
        incident.risk_score = round(float(incident.risk_score) + delta, 2)
        session.commit()


def test_a_pending_request_cannot_be_approved_against_a_different_score(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    authorization_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert request_incident_verification(core_api, incident_id).status_code == 200
    change_score(core_api, incident_id)

    response = core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers)

    assert (response.status_code, response.json()["detail"]) == (409, "Decision risk score no longer matches the incident risk score")
    with core_api.session_factory() as session:
        assert session.get(Authorization, authorization_id).status == AuthorizationStatus.PENDING
        assert session.get(Incident, incident_id).state == IncidentState.VERIFIED


def test_an_approval_cannot_run_containment_against_a_different_score(core_api: CoreApi) -> None:
    incident_id = prioritised(core_api)
    decision_id = UUID(request_decision(core_api, incident_id).json()["id"])
    authorization_id = UUID(request_authorization(core_api, decision_id).json()["id"])
    assert request_incident_verification(core_api, incident_id).status_code == 200
    assert core_api.client.post(f"/api/authorizations/{authorization_id}/approve", headers=core_api.approver_headers).status_code == 200
    change_score(core_api, incident_id)

    response = contain(core_api, authorization_id)

    assert (response.status_code, response.json()["detail"]) == (409, "Decision risk score no longer matches the incident risk score")
    with core_api.session_factory() as session:
        assert session.scalar(select(ContainmentAction.id).where(ContainmentAction.authorization_id == authorization_id)) is None
        assert session.get(Incident, incident_id).state == IncidentState.AUTHORIZED
