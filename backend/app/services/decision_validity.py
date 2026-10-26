from typing import Literal

from app.models.decision import Decision
from app.models.enums import AuthorizationStatus

DecisionValidity = Literal["CURRENT", "SUPERSEDED", "REJECTED"]


def rejected(decision: Decision) -> bool:
    """A decision whose every authorization request was rejected; it can no longer lead to containment."""
    return bool(decision.authorizations) and all(
        authorization.status == AuthorizationStatus.REJECTED for authorization in decision.authorizations
    )


def decision_validity(decision: Decision, incident_risk_score: float | None) -> DecisionValidity:
    """Whether a stored decision can still be acted on, from persisted state only.

    - ``SUPERSEDED``: made for a risk score the incident no longer has (a re-evaluation changed it). Its record and
      original score are kept, but it can never be authorized; this takes precedence over ``REJECTED``.
    - ``REJECTED``: made for the current score, but every authorization request for it was rejected.
    - ``CURRENT``: made for the current score and not rejected; the incident can be verified against it and its
      authorization requested and approved.
    """
    if decision.risk_score != incident_risk_score:
        return "SUPERSEDED"
    if rejected(decision):
        return "REJECTED"
    return "CURRENT"
