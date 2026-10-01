from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.enums import AssetStatus, Criticality, IncidentState, Severity
from app.models.incident import Incident, IncidentEvent

ACTIVE_STATES = tuple(
    state
    for state in IncidentState
    if state not in (IncidentState.CONTAINED, IncidentState.LEARNED)
)

SEVERITY_ORDER = case(
    (Incident.severity == Severity.CRITICAL, 0),
    (Incident.severity == Severity.HIGH, 1),
    (Incident.severity == Severity.MEDIUM, 2),
    (Incident.severity == Severity.LOW, 3),
    (Incident.severity == Severity.INFO, 4),
    else_=5,
)

ASSET_CRITICALITY_ORDER = case(
    (Asset.criticality == Criticality.CRITICAL, 0),
    (Asset.criticality == Criticality.HIGH, 1),
    (Asset.criticality == Criticality.MEDIUM, 2),
    (Asset.criticality == Criticality.LOW, 3),
    else_=4,
)


def _priority_reason(
    risk_score: float | None,
    severity: Severity,
    criticality: Criticality | None,
    event_count: int,
) -> str:
    reason_parts = []
    if risk_score is None:
        reason_parts.append("Risk not calculated; unassessed incidents are placed after scored incidents")
    else:
        reason_parts.append(f"Calculated risk score {risk_score:.2f}")

    reason_parts.append(f"{severity.name.upper()} severity")
    if criticality is not None:
        reason_parts.append(f"{criticality.name.upper()} asset")
    else:
        reason_parts.append("asset criticality unavailable")
    if event_count > 1:
        reason_parts.append(f"multiple correlated events ({event_count})")
    elif event_count == 1:
        reason_parts.append("1 linked event")
    else:
        reason_parts.append("no linked events")

    return "; ".join(reason_parts) + ". Ordering uses risk score, severity, asset criticality, event count, then updated time."


def get_prioritized_incidents(db: Session) -> list[dict[str, Any]]:
    event_count = (
        select(func.count(IncidentEvent.event_id))
        .where(IncidentEvent.incident_id == Incident.id)
        .scalar_subquery()
    )
    risk_missing_order = case((Incident.risk_score.is_(None), 1), else_=0)
    statement = (
        select(Incident, Asset.criticality, event_count.label("event_count"))
        .outerjoin(Asset, Incident.asset_id == Asset.id)
        .where(Incident.state.in_(ACTIVE_STATES))
        .order_by(
            risk_missing_order.asc(),
            Incident.risk_score.desc(),
            SEVERITY_ORDER.asc(),
            ASSET_CRITICALITY_ORDER.asc(),
            event_count.desc(),
            Incident.updated_at.desc(),
            Incident.id.asc(),
        )
    )
    rows = db.execute(statement).all()

    prioritized: list[dict[str, Any]] = []
    for priority_rank, (incident, asset_criticality, count) in enumerate(rows, start=1):
        prioritized.append(
            {
                "incidentId": str(incident.id),
                "state": incident.state.name.upper(),
                "riskScore": float(incident.risk_score) if incident.risk_score is not None else None,
                "severity": incident.severity.name.upper(),
                "assetCriticality": (
                    asset_criticality.name.upper() if asset_criticality is not None else None
                ),
                "eventCount": int(count or 0),
                "updatedAt": incident.updated_at.isoformat(),
                "priorityRank": priority_rank,
                "priorityReason": _priority_reason(
                    float(incident.risk_score) if incident.risk_score is not None else None,
                    incident.severity,
                    asset_criticality,
                    int(count or 0),
                ),
            }
        )
    return prioritized