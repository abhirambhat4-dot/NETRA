from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.api.auth import get_current_user, require_permission
from app.api.core_serializers import asset_reference, enum_text
from app.core.permissions import Permission
from app.db.dependencies import get_db
from app.models.assessment import AssessmentFinding, SecurityAssessment
from app.models.enums import AssessmentGrade
from app.models.user import User
from app.schemas.assessment import (
    AssessmentCreateRequest,
    AssessmentDetailResponse,
    AssessmentFindingResponse,
    AssessmentSummaryResponse,
)
from app.schemas.core import PageResponse
from app.services.assessment import consume_rate_limit, get_assessment, run_assessment

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _summary_fields(assessment: SecurityAssessment) -> dict[str, object]:
    return {
        "id": assessment.id,
        "asset_id": assessment.asset_id,
        "asset_key": assessment.asset_key,
        "asset": asset_reference(assessment.asset),
        "methodology_version": assessment.methodology_version,
        "as_of": assessment.as_of,
        "score": assessment.score,
        "grade": enum_text(assessment.grade),
        "summary": assessment.summary,
        "passed": assessment.passed,
        "warnings": assessment.warnings,
        "failed": assessment.failed,
        "informational": assessment.informational,
        "requested_by": assessment.requested_by,
        "created_at": assessment.created_at,
    }


def _finding_response(finding: AssessmentFinding) -> AssessmentFindingResponse:
    return AssessmentFindingResponse(
        id=finding.id,
        position=finding.position,
        check_key=finding.check_key,
        category=finding.category,
        title=finding.title,
        result=enum_text(finding.result),
        severity=enum_text(finding.severity),
        deduction=finding.deduction,
        evidence=finding.evidence,
        recommendation=finding.recommendation,
        vulnerability_ids=finding.vulnerability_ids,
        incident_ids=finding.incident_ids,
        event_ids=finding.event_ids,
        vulnerability_total=finding.vulnerability_total,
        incident_total=finding.incident_total,
        event_total=finding.event_total,
    )


def assessment_detail_response(assessment: SecurityAssessment) -> AssessmentDetailResponse:
    return AssessmentDetailResponse(
        **_summary_fields(assessment),
        missing_evidence=assessment.missing_evidence,
        input_counts=assessment.input_counts,
        findings=[_finding_response(finding) for finding in assessment.findings],
    )


@router.post(
    "",
    response_model=AssessmentDetailResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Asset not found"},
        status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Assessment rate limit exceeded"},
    },
)
def create_assessment(
    request: AssessmentCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_permission(Permission.OPERATE_WORKFLOW))],
) -> AssessmentDetailResponse:
    consume_rate_limit(current_user)
    return assessment_detail_response(run_assessment(db, current_user, request.asset_id, request.as_of))


@router.get("", response_model=PageResponse[AssessmentSummaryResponse])
def list_assessments(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 25,
    asset_id: Annotated[UUID | None, Query(alias="assetId")] = None,
    grade: Literal["A", "B", "C", "D", "F"] | None = None,
) -> PageResponse[AssessmentSummaryResponse]:
    conditions = []
    if asset_id is not None:
        conditions.append(SecurityAssessment.asset_id == asset_id)
    if grade is not None:
        conditions.append(SecurityAssessment.grade == AssessmentGrade[grade])

    total = int(db.scalar(select(func.count()).select_from(SecurityAssessment).where(*conditions)) or 0)
    assessments = db.scalars(
        select(SecurityAssessment)
        .where(*conditions)
        .options(joinedload(SecurityAssessment.asset))
        # as_of is assigned per run by the application; created_at is the transaction time.
        .order_by(SecurityAssessment.as_of.desc(), SecurityAssessment.created_at.desc(), SecurityAssessment.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return PageResponse[AssessmentSummaryResponse](
        items=[AssessmentSummaryResponse(**_summary_fields(item)) for item in assessments],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{assessment_id}",
    response_model=AssessmentDetailResponse,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Assessment not found"}},
)
def get_assessment_detail(
    assessment_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> AssessmentDetailResponse:
    assessment = get_assessment(db, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return assessment_detail_response(assessment)
