import uuid
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin

#: Risk levels as the risk engine reports them (risk_engine._risk_severity); not the lower-case Severity enum.
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
#: Why an evaluation was recorded: the incident's first risk calculation, or a later re-evaluation.
RISK_EVALUATION_TRIGGERS = ("initial", "reevaluation")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class RiskEvaluation(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One risk scoring run for an incident, kept as history.

    Append-only: a row is never changed or deleted on its own; rows go only with their incident, like
    incident_history. This is enforced by ORM mapper events (see below), which refuse a flush that would update
    or delete a row; raw SQL and ORM bulk UPDATE/DELETE statements bypass those events and are not prevented.
    Recording an evaluation never changes the incident: its risk_score is the score the workflow adopted, which
    decisions and authorizations are checked against.
    """

    __tablename__ = "risk_evaluations"
    __table_args__ = (
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint(
            "previous_risk_score IS NULL OR previous_risk_score BETWEEN 0 AND 100", name="previous_risk_score_range"
        ),
        CheckConstraint(_in("risk_level", RISK_LEVELS), name="risk_level_values"),
        CheckConstraint(_in("trigger", RISK_EVALUATION_TRIGGERS), name="trigger_values"),
        CheckConstraint("methodology_version <> ''", name="methodology_version_present"),
        # An incident's evaluations in order: its history, and the latest one for a change since the last run.
        Index("ix_risk_evaluations_incident_id_created_at", "incident_id", "created_at"),
    )

    # Indexed by the composite (incident_id, created_at) index above.
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    #: The scoring methodology that produced this row, e.g. "risk-v1" (risk_engine.RISK_METHODOLOGY_VERSION).
    methodology_version: Mapped[str] = mapped_column(String(32))
    risk_score: Mapped[float]
    risk_level: Mapped[str] = mapped_column(String(16))
    #: The incident's risk score when this evaluation was made, or None when it had none.
    previous_risk_score: Mapped[float | None]
    #: The factor breakdown exactly as the risk API reports it (normalised value, weight, contribution, evidence, reason).
    factors: Mapped[dict[str, Any]] = mapped_column(JSONB)
    missing_evidence: Mapped[list[str]] = mapped_column(JSONB)
    #: The active threat indicators the evaluation used: identifiers and sources, so a later change is explainable.
    matched_indicators: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    trigger: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str] = mapped_column(String(255))


class AppendOnlyError(RuntimeError):
    pass


@event.listens_for(RiskEvaluation, "before_update")
def _refuse_update(_mapper: object, _connection: object, target: RiskEvaluation) -> None:
    raise AppendOnlyError(f"risk evaluation {target.id} is append-only and cannot be changed")


@event.listens_for(RiskEvaluation, "before_delete")
def _refuse_delete(_mapper: object, _connection: object, target: RiskEvaluation) -> None:
    raise AppendOnlyError(f"risk evaluation {target.id} is append-only; it is removed only with its incident")
