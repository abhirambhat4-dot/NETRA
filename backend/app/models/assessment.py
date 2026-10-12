import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text, UniqueConstraint, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin, enum_type
from app.models.enums import AssessmentGrade, FindingResult, Severity

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.user import User


class SecurityAssessment(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """An append-only assessment snapshot; kept, with its asset key, even if the asset is deleted."""

    __tablename__ = "security_assessments"
    __table_args__ = (
        CheckConstraint("score BETWEEN 0 AND 100", name="score_range"),
        CheckConstraint(
            "passed >= 0 AND warnings >= 0 AND failed >= 0 AND informational >= 0", name="result_counts"
        ),
        Index("ix_security_assessments_asset_id_as_of", "asset_id", "as_of"),
    )

    # Indexed by the composite (asset_id, as_of) index above.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    asset_key: Mapped[str] = mapped_column(String(64))
    methodology_version: Mapped[str] = mapped_column(String(32), index=True)
    # Evidence cut-off used for both loading and scoring; also the run time that orders snapshots.
    as_of: Mapped[datetime]
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[AssessmentGrade] = mapped_column(enum_type(AssessmentGrade), index=True)
    summary: Mapped[str] = mapped_column(Text)
    passed: Mapped[int] = mapped_column(Integer)
    warnings: Mapped[int] = mapped_column(Integer)
    failed: Mapped[int] = mapped_column(Integer)
    informational: Mapped[int] = mapped_column(Integer)
    missing_evidence: Mapped[list[str]] = mapped_column(JSONB)
    # Number of records of each kind that the snapshot was built from.
    input_counts: Mapped[dict[str, Any]] = mapped_column(JSONB)
    requested_by: Mapped[str] = mapped_column(String(320))
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    asset: Mapped["Asset | None"] = relationship()
    requested_by_user: Mapped["User | None"] = relationship()
    findings: Mapped[list["AssessmentFinding"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AssessmentFinding.position",
    )


class AssessmentFinding(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "assessment_findings"
    __table_args__ = (
        UniqueConstraint("assessment_id", "check_key"),
        UniqueConstraint("assessment_id", "position"),
        CheckConstraint("deduction BETWEEN 0 AND 100", name="deduction_range"),
        CheckConstraint("position >= 0", name="position_range"),
        CheckConstraint(
            "vulnerability_total >= 0 AND incident_total >= 0 AND event_total >= 0", name="reference_totals"
        ),
    )

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_assessments.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    check_key: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    result: Mapped[FindingResult] = mapped_column(enum_type(FindingResult), index=True)
    severity: Mapped[Severity | None] = mapped_column(enum_type(Severity))
    deduction: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[list[str]] = mapped_column(JSONB)
    recommendation: Mapped[str | None] = mapped_column(Text)
    # Referenced record IDs as JSON lists of UUID strings; plain references, not foreign keys. Each list
    # holds at most the engine's MAX_REFERENCE_IDS; the matching total counts every record, so a total
    # above the list length records that the list was capped.
    vulnerability_ids: Mapped[list[str]] = mapped_column(JSONB)
    incident_ids: Mapped[list[str]] = mapped_column(JSONB)
    event_ids: Mapped[list[str]] = mapped_column(JSONB)
    vulnerability_total: Mapped[int] = mapped_column(Integer)
    incident_total: Mapped[int] = mapped_column(Integer)
    event_total: Mapped[int] = mapped_column(Integer)

    assessment: Mapped["SecurityAssessment"] = relationship(back_populates="findings")


@event.listens_for(SecurityAssessment, "before_update")
@event.listens_for(AssessmentFinding, "before_update")
def _reject_snapshot_update(_mapper: Any, _connection: Any, target: Base) -> None:
    raise ValueError(f"{type(target).__name__} records are append-only snapshots and cannot be updated")
