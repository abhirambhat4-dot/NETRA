from collections import Counter
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.enums import (
    AuthorizationStatus,
    ContainmentStatus,
    Effectiveness,
    IncidentState,
    ResponseAction,
)
from app.models.incident import Incident, IncidentHistory
from app.models.event import SecurityEvent


def _history(
    incident: Incident,
    *,
    action: str,
    actor: str,
    from_state: IncidentState,
    to_state: IncidentState,
    details: dict[str, object],
) -> IncidentHistory:
    return IncidentHistory(
        incident_id=incident.id,
        from_state=from_state,
        to_state=to_state,
        action=action,
        actor=actor,
        occurred_at=datetime.now(UTC),
        details=details,
    )


def _approved_authorization(db: Session, authorization_id: UUID) -> Authorization:
    authorization = db.scalars(
        select(Authorization)
        .where(Authorization.id == authorization_id)
        .options(
            joinedload(Authorization.incident).joinedload(Incident.asset),
            joinedload(Authorization.decision),
        )
    ).unique().one_or_none()
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization not found")
    if authorization.status != AuthorizationStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authorization must be APPROVED before containment",
        )
    decision = authorization.decision
    if decision is None or authorization.decision_id is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Authorization has no valid decision")
    if (
        decision.incident_id != authorization.incident_id
        or authorization.requested_action != decision.action
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authorization action and incident must match the persisted decision",
        )
    if authorization.incident.state != IncidentState.AUTHORIZED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must be AUTHORIZED before containment",
        )
    return authorization


def _target_for_action(
    incident: Incident,
    decision: Decision,
    events: list[SecurityEvent],
) -> str:
    if decision.action == ResponseAction.ISOLATE_HOST:
        if incident.asset is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No asset is available as an isolation target",
            )
        target = incident.asset.hostname or incident.asset.ip_address
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The incident asset has no hostname or IP isolation target",
            )
        return str(target)

    if decision.action == ResponseAction.BLOCK_IP:
        source_ips = [str(event.src_ip) for event in events if event.src_ip is not None]
        if not source_ips:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No observed source IP is available as a block target",
            )
        frequencies = Counter(source_ips)
        return sorted(frequencies, key=lambda value: (-frequencies[value], value))[0]

    if decision.action in (
        ResponseAction.INVESTIGATE,
        ResponseAction.MONITOR,
        ResponseAction.ESCALATE,
        ResponseAction.NO_ACTION,
    ):
        return incident.incident_key

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"No safe simulated target policy exists for {decision.action.name}",
    )


def simulate_authorized_containment(
    db: Session,
    authorization_id: UUID,
    *,
    actor: str,
    simulate_failure: bool = False,
) -> ContainmentAction:
    authorization = _approved_authorization(db, authorization_id)
    incident = authorization.incident
    decision = authorization.decision
    existing = db.scalar(
        select(ContainmentAction.id)
        .where(ContainmentAction.authorization_id == authorization.id)
        .limit(1)
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A containment action already exists for this authorization",
        )

    events = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.incidents.any(Incident.id == incident.id))
        .order_by(SecurityEvent.occurred_at, SecurityEvent.id)
    ).all()
    target = _target_for_action(incident, decision, events)
    now = datetime.now(UTC)
    containment = ContainmentAction(
        incident_id=incident.id,
        authorization_id=authorization.id,
        action_type=decision.action,
        target=target,
        status=ContainmentStatus.EXECUTING,
        executed_at=None,
        verified_at=None,
        result=None,
        error_message=None,
    )
    db.add(containment)
    db.flush()
    db.add(
        _history(
            incident,
            action="containment_requested",
            actor=actor,
            from_state=incident.state,
            to_state=incident.state,
            details={
                "containment_id": str(containment.id),
                "authorization_id": str(authorization.id),
                "decision_id": str(decision.id),
                "action": decision.action.name,
                "target": target,
            },
        )
    )

    containment.executed_at = now
    if simulate_failure:
        containment.status = ContainmentStatus.FAILED
        containment.result = (
            f"Controlled simulation attempted {decision.action.name} for {target}; "
            "no real system or network changes were made."
        )
        containment.error_message = "Simulated containment failure requested for verification testing."
    else:
        containment.status = ContainmentStatus.SUCCEEDED
        containment.result = (
            f"Simulated containment action {decision.action.name} for {target}; "
            "no real system or network changes were made."
        )
    db.add(
        _history(
            incident,
            action="containment_executed",
            actor=actor,
            from_state=incident.state,
            to_state=incident.state,
            details={
                "containment_id": str(containment.id),
                "authorization_id": str(authorization.id),
                "decision_id": str(decision.id),
                "action": decision.action.name,
                "target": target,
                "status": containment.status.name,
                "result": containment.result,
                "error_message": containment.error_message,
                "simulated": True,
            },
        )
    )
    db.commit()
    db.refresh(containment)
    return containment


def verify_containment(
    db: Session,
    containment_id: UUID,
    *,
    actor: str,
) -> ContainmentAction:
    containment = db.scalars(
        select(ContainmentAction)
        .where(ContainmentAction.id == containment_id)
        .options(
            joinedload(ContainmentAction.incident),
            joinedload(ContainmentAction.authorization).joinedload(Authorization.decision),
        )
    ).unique().one_or_none()
    if containment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Containment action not found")
    if containment.verified_at is not None or containment.status in (
        ContainmentStatus.VERIFIED,
        ContainmentStatus.ROLLED_BACK,
    ):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Containment is already resolved")
    if containment.executed_at is None or containment.status not in (
        ContainmentStatus.SUCCEEDED,
        ContainmentStatus.FAILED,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Containment must have a completed execution result before verification",
        )

    incident = containment.incident
    authorization = containment.authorization
    decision = authorization.decision
    if (
        authorization.status != AuthorizationStatus.APPROVED
        or decision is None
        or authorization.decision_id is None
        or authorization.incident_id != incident.id
        or decision.incident_id != incident.id
        or authorization.requested_action != decision.action
        or containment.action_type != decision.action
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Containment must match an approved authorization and its decision",
        )
    if incident.state != IncidentState.AUTHORIZED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must remain AUTHORIZED until containment verification succeeds",
        )

    previous_state = incident.state
    now = datetime.now(UTC)
    containment.verified_at = now
    if containment.status == ContainmentStatus.SUCCEEDED:
        containment.status = ContainmentStatus.VERIFIED
        containment.result = f"{containment.result or ''} Verification succeeded at {now.isoformat()}.".strip()
        incident.state = IncidentState.CONTAINED
        history_action = "containment_verified"
        next_state = IncidentState.CONTAINED
        history_result = containment.result
    else:
        containment.error_message = containment.error_message or "Controlled containment simulation failed."
        containment.result = f"{containment.result or ''} Verification failed at {now.isoformat()}.".strip()
        history_action = "containment_failed"
        next_state = previous_state
        history_result = containment.result

    db.add(
        _history(
            incident,
            action=history_action,
            actor=actor,
            from_state=previous_state,
            to_state=next_state,
            details={
                "containment_id": str(containment.id),
                "authorization_id": str(authorization.id),
                "decision_id": str(decision.id),
                "action": containment.action_type.name,
                "status": containment.status.name,
                "verified_at": now.isoformat(),
                "result": history_result,
                "error_message": containment.error_message,
            },
        )
    )
    db.commit()
    db.refresh(containment)
    return containment


def create_incident_cyber_memory(
    db: Session,
    incident_id: UUID,
    *,
    actor: str,
) -> CyberMemory:
    incident = db.scalars(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            joinedload(Incident.asset),
            selectinload(Incident.events),
            selectinload(Incident.decisions),
            selectinload(Incident.containment_actions)
            .joinedload(ContainmentAction.authorization)
            .joinedload(Authorization.decision),
        )
    ).unique().one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    existing_memory = db.scalar(
        select(CyberMemory.id).where(CyberMemory.incident_id == incident.id).limit(1)
    )
    if existing_memory is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cyber Memory already exists for this incident")
    if incident.state != IncidentState.CONTAINED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incident must be CONTAINED after successful verification before Cyber Memory can be created",
        )

    verified_containments = [
        item
        for item in incident.containment_actions
        if item.status == ContainmentStatus.VERIFIED and item.verified_at is not None
    ]
    if not verified_containments:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A successfully verified containment action is required for Cyber Memory",
        )
    containment = max(verified_containments, key=lambda item: (item.verified_at, str(item.id)))
    authorization = containment.authorization
    decision = authorization.decision
    if (
        authorization.status != AuthorizationStatus.APPROVED
        or authorization.incident_id != incident.id
        or authorization.requested_action != containment.action_type
        or decision is None
        or decision.incident_id != incident.id
        or decision.action != containment.action_type
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cyber Memory requires a valid decision and matching approved containment authorization",
        )

    event_types = sorted({event.event_type for event in incident.events})
    observations = (
        f"Observed {len(incident.events)} linked event(s): {', '.join(event_types)}."
        if incident.events
        else "No linked event details are available."
    )
    if incident.asset is not None:
        asset_observation = (
            f"Asset {incident.asset.asset_key} had {incident.asset.criticality.name.upper()} criticality."
        )
    else:
        asset_observation = "The incident has no associated asset."
    lesson = (
        f"{observations} {asset_observation} NETRA recommended {decision.action.name}; "
        f"the approved {authorization.requested_action.name} action was simulated and verified."
    )
    outcome = (
        f"{containment.result or 'Controlled containment simulation result unavailable.'} "
        f"Verification succeeded at {containment.verified_at.isoformat()}"
    )
    memory = CyberMemory(
        incident=incident,
        decision=decision,
        lesson=lesson,
        outcome=outcome,
        action_taken=containment.action_type,
        effectiveness=Effectiveness.EFFECTIVE,
    )
    db.add(memory)
    db.flush()
    previous_state = incident.state
    incident.state = IncidentState.LEARNED
    db.add(
        _history(
            incident,
            action="cyber_memory_created",
            actor=actor,
            from_state=previous_state,
            to_state=IncidentState.LEARNED,
            details={
                "memory_id": str(memory.id),
                "decision_id": str(decision.id),
                "authorization_id": str(authorization.id),
                "containment_id": str(containment.id),
                "action": containment.action_type.name,
                "outcome": outcome,
                "effectiveness": Effectiveness.EFFECTIVE.name,
            },
        )
    )
    db.commit()
    db.refresh(memory)
    return memory