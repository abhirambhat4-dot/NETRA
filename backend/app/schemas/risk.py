from datetime import datetime
from typing import Any
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


class RiskEvaluationResponse(CoreResponse):
    """One stored risk scoring run (risk_evaluations); read-only history, never recalculated."""

    id: UUID
    incident_id: UUID
    methodology_version: str
    risk_score: float
    risk_level: str
    previous_risk_score: float | None
    # Stored exactly as the risk-score API reported them (camelCase keys).
    factors: dict[str, Any]
    missing_evidence: list[str]
    matched_indicators: list[dict[str, Any]]
    trigger: str
    actor: str
    created_at: datetime
