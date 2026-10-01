from uuid import UUID

from app.schemas.core import CoreResponse


class RiskFactorExplanation(CoreResponse):
    normalized_value: float
    weight: float
    contribution: float
    evidence: list[str]
    reason: str


class RiskStateTransition(CoreResponse):
    from_state: str
    to_state: str
    action: str


class RiskScoreResult(CoreResponse):
    incident_id: UUID
    risk_score: float
    severity: str
    factors: dict[str, RiskFactorExplanation]
    reasons: list[str]
    missing_evidence: list[str]
    state_transition: RiskStateTransition