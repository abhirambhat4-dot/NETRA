from enum import Enum

from app.models.asset import Asset
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.threat_indicator import ThreatIndicator
from app.schemas.core import (
    AssetReference,
    AssetResponse,
    AuthorizationResponse,
    ContainmentResponse,
    CyberMemoryReference,
    CyberMemoryResponse,
    DecisionResponse,
    EventResponse,
    IncidentReference,
    IncidentResponse,
    ThreatIndicatorResponse,
)


def enum_text(value: Enum | str | None) -> str | None:
    if value is None:
        return None
    return value.name if isinstance(value, Enum) else str(value).upper()


def asset_reference(asset: Asset | None) -> AssetReference | None:
    if asset is None:
        return None
    return AssetReference(
        id=asset.id,
        asset_key=asset.asset_key,
        name=asset.name,
        hostname=asset.hostname,
        ip_address=str(asset.ip_address) if asset.ip_address is not None else None,
        criticality=enum_text(asset.criticality),
        status=enum_text(asset.status),
    )


def asset_response(asset: Asset, vulnerability_count: int) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        asset_key=asset.asset_key,
        name=asset.name,
        hostname=asset.hostname,
        ip_address=str(asset.ip_address) if asset.ip_address is not None else None,
        criticality=enum_text(asset.criticality),
        status=enum_text(asset.status),
        asset_type=enum_text(asset.asset_type),
        environment=enum_text(asset.environment),
        exposure=enum_text(asset.exposure),
        owner=asset.owner,
        vulnerability_count=vulnerability_count,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def event_response(event: SecurityEvent) -> EventResponse:
    incidents = event.incidents
    return EventResponse(
        id=event.id,
        event_uid=event.event_uid,
        occurred_at=event.occurred_at,
        source_ip=str(event.src_ip) if event.src_ip is not None else None,
        source_port=event.src_port,
        destination_ip=str(event.dest_ip) if event.dest_ip is not None else None,
        destination_port=event.dest_port,
        protocol=event.protocol,
        event_type=event.event_type,
        signature=event.signature,
        severity=enum_text(event.severity),
        detection_source=enum_text(event.source),
        status="CORRELATED" if incidents else "NEW",
        anomaly_score=event.anomaly_score,
        incident_ids=[incident.id for incident in incidents],
        asset_id=event.asset_id,
        asset=asset_reference(event.asset),
    )


def decision_response(decision: Decision) -> DecisionResponse:
    return DecisionResponse(
        id=decision.id,
        incident_id=decision.incident_id,
        action=enum_text(decision.action),
        rationale=decision.rationale,
        risk_score=decision.risk_score,
        confidence=decision.confidence,
        recommendation=decision.recommendation,
        created_at=decision.created_at,
    )


def authorization_response(authorization: Authorization) -> AuthorizationResponse:
    return AuthorizationResponse(
        id=authorization.id,
        incident_id=authorization.incident_id,
        decision_id=authorization.decision_id,
        requested_action=enum_text(authorization.requested_action),
        status=enum_text(authorization.status),
        requested_by=authorization.requested_by,
        approved_by=authorization.approved_by,
        reason=authorization.reason,
        requested_at=authorization.requested_at,
        approved_at=authorization.approved_at,
    )


def containment_response(action: ContainmentAction) -> ContainmentResponse:
    return ContainmentResponse(
        id=action.id,
        incident_id=action.incident_id,
        authorization_id=action.authorization_id,
        action_type=enum_text(action.action_type),
        target=action.target,
        status=enum_text(action.status),
        executed_at=action.executed_at,
        verified_at=action.verified_at,
        result=action.result,
        error_message=action.error_message,
        created_at=action.created_at,
    )


def incident_response(
    incident: Incident,
    event_count: int,
    latest_decision: Decision | None = None,
) -> IncidentResponse:
    latest = latest_decision
    if latest is None and incident.decisions:
        latest = max(incident.decisions, key=lambda decision: decision.created_at)
    return IncidentResponse(
        id=incident.id,
        incident_key=incident.incident_key,
        title=incident.title,
        description=incident.description,
        severity=enum_text(incident.severity),
        risk_score=float(incident.risk_score) if incident.risk_score is not None else None,
        state=enum_text(incident.state),
        detection_source=enum_text(incident.detection_source),
        recommended_action=enum_text(incident.recommended_action),
        asset_id=incident.asset_id,
        asset=asset_reference(incident.asset),
        event_count=event_count,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        latest_decision=decision_response(latest) if latest is not None else None,
    )


def threat_indicator_response(indicator: ThreatIndicator) -> ThreatIndicatorResponse:
    return ThreatIndicatorResponse(
        id=indicator.id,
        value=indicator.value,
        indicator_type=enum_text(indicator.indicator_type),
        source=indicator.source,
        confidence=indicator.confidence,
        severity=enum_text(indicator.severity),
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        is_active=indicator.is_active,
    )


def cyber_memory_reference(memory: CyberMemory) -> CyberMemoryReference:
    return CyberMemoryReference(id=memory.id, lesson=memory.lesson, outcome=memory.outcome)


def cyber_memory_response(memory: CyberMemory) -> CyberMemoryResponse:
    incident = memory.incident
    return CyberMemoryResponse(
        id=memory.id,
        incident_id=memory.incident_id,
        decision_id=memory.decision_id,
        lesson=memory.lesson,
        outcome=memory.outcome,
        action_taken=enum_text(memory.action_taken),
        effectiveness=enum_text(memory.effectiveness),
        created_at=memory.created_at,
        incident=(
            IncidentReference(
                id=incident.id,
                incident_key=incident.incident_key,
                title=incident.title,
                state=enum_text(incident.state),
                severity=enum_text(incident.severity),
                risk_score=float(incident.risk_score) if incident.risk_score is not None else None,
            )
            if incident is not None
            else None
        ),
        decision=decision_response(memory.decision) if memory.decision is not None else None,
        authorizations=(
            [authorization_response(item) for item in incident.authorizations]
            if incident is not None
            else []
        ),
        containment_actions=(
            [containment_response(item) for item in incident.containment_actions]
            if incident is not None
            else []
        ),
    )