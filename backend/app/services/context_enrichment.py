import ipaddress
import re
from collections import defaultdict
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.api.core_serializers import enum_text
from app.models.asset import Asset
from app.models.enums import IndicatorType
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentHistory
from app.models.threat_indicator import ThreatIndicator
from app.models.vulnerability import Vulnerability
from app.schemas.enrichment import (
    AssetContext,
    EnrichmentFinding,
    EventContext,
    IncidentContext,
    IncidentContextBundle,
    ThreatMatchContext,
    VulnerabilityContext,
)

DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _strings(value: object) -> list[str]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, (list, tuple, set)):
        return [item for child in value for item in _strings(child)]
    if isinstance(value, str):
        return [value]
    return []


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or any(character.isspace() for character in candidate):
        return None

    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    elif "/" in candidate:
        candidate = urlsplit(f"//{candidate}").hostname or ""

    candidate = candidate.rstrip(".")
    labels = candidate.split(".")
    if not candidate or not all(DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return None


def _event_indicators(event: SecurityEvent) -> dict[IndicatorType, set[str]]:
    values: dict[IndicatorType, set[str]] = defaultdict(set)
    event_strings = _strings(event.raw_data)
    event_strings.extend(value for value in (event.signature, event.event_type) if value)

    for address in (event.src_ip, event.dest_ip):
        if address is not None:
            values[IndicatorType.IP].add(str(ipaddress.ip_address(str(address))))

    for raw_value in event_strings:
        value = raw_value.strip()
        if not value:
            continue
        try:
            values[IndicatorType.IP].add(str(ipaddress.ip_address(value)))
        except ValueError:
            pass

        domain = _normalize_domain(value)
        if domain is not None:
            values[IndicatorType.DOMAIN].add(domain)

        values[IndicatorType.HASH].add(value.casefold())
        if "://" in value:
            values[IndicatorType.URL].add(value.rstrip("/").casefold())

    return values


def enrich_incident_context(
    db: Session,
    incident_id: UUID,
    *,
    actor: str,
    record_history: bool = True,
) -> IncidentContextBundle:
    incident = db.scalars(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(joinedload(Incident.asset), selectinload(Incident.events))
    ).unique().one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    events = sorted(incident.events, key=lambda event: (event.occurred_at, str(event.id)))
    asset = incident.asset
    vulnerabilities = []
    if asset is not None:
        vulnerabilities = db.scalars(
            select(Vulnerability)
            .where(Vulnerability.asset_id == asset.id)
            .order_by(Vulnerability.cve_id, Vulnerability.id)
        ).all()

    candidates_by_type: dict[IndicatorType, set[str]] = defaultdict(set)
    candidate_events: dict[tuple[IndicatorType, str], set[UUID]] = defaultdict(set)
    for event in events:
        for indicator_type, candidates in _event_indicators(event).items():
            candidates_by_type[indicator_type].update(candidates)
            for candidate in candidates:
                candidate_events[(indicator_type, candidate)].add(event.id)

    indicator_conditions = [
        and_(
            ThreatIndicator.indicator_type == indicator_type,
            func.lower(ThreatIndicator.value).in_(candidates),
        )
        for indicator_type, candidates in candidates_by_type.items()
        if candidates
    ]
    indicators = (
        db.scalars(
            select(ThreatIndicator)
            .where(or_(*indicator_conditions))
            .order_by(ThreatIndicator.value, ThreatIndicator.source, ThreatIndicator.id)
        ).all()
        if indicator_conditions
        else []
    )

    matched_indicators: list[ThreatMatchContext] = []
    inactive_matches = 0
    for indicator in indicators:
        indicator_type = indicator.indicator_type
        normalized_value = indicator.value.casefold()
        if indicator_type == IndicatorType.IP:
            try:
                normalized_value = str(ipaddress.ip_address(indicator.value))
            except ValueError:
                continue
        matched_event_ids = sorted(
            candidate_events.get((indicator_type, normalized_value), set()), key=str
        )
        if not matched_event_ids:
            continue
        if not indicator.is_active:
            inactive_matches += 1
            continue
        matched_indicators.append(
            ThreatMatchContext(
                id=indicator.id,
                value=indicator.value,
                indicator_type=enum_text(indicator.indicator_type),
                confidence=indicator.confidence,
                severity=enum_text(indicator.severity),
                source=indicator.source,
                is_active=indicator.is_active,
                matched_event_ids=matched_event_ids,
            )
        )

    findings = [
        EnrichmentFinding(
            category="asset_context",
            reason="Asset context was loaded for the incident." if asset else "The incident has no associated asset.",
        ),
        EnrichmentFinding(
            category="vulnerability_context",
            reason=(
                "Vulnerabilities were found for the incident asset."
                if vulnerabilities
                else "No vulnerabilities are associated with the incident asset."
            ),
            count=len(vulnerabilities),
        ),
        EnrichmentFinding(
            category="threat_intelligence",
            reason=(
                "Active threat indicators matched linked event values."
                if matched_indicators
                else "No active threat-intelligence indicators matched linked event values."
            ),
            count=len(matched_indicators),
        ),
    ]
    if inactive_matches:
        findings.append(
            EnrichmentFinding(
                category="inactive_indicators_ignored",
                reason="Matching inactive indicators were excluded from threat-intelligence matches.",
                count=inactive_matches,
            )
        )
    if not events:
        findings.append(
            EnrichmentFinding(
                category="event_context",
                reason="The incident has no linked security events.",
                count=0,
            )
        )

    bundle = IncidentContextBundle(
        incident=IncidentContext(
            id=incident.id,
            incident_key=incident.incident_key,
            title=incident.title,
            description=incident.description,
            severity=enum_text(incident.severity),
            state=enum_text(incident.state),
            detection_source=enum_text(incident.detection_source),
            asset_id=incident.asset_id,
        ),
        asset=(
            AssetContext(
                id=asset.id,
                asset_key=asset.asset_key,
                name=asset.name,
                hostname=asset.hostname,
                ip_address=str(asset.ip_address) if asset.ip_address is not None else None,
                criticality=enum_text(asset.criticality),
                exposure=enum_text(asset.exposure),
                status=enum_text(asset.status),
                asset_type=enum_text(asset.asset_type),
                environment=enum_text(asset.environment),
            )
            if asset is not None
            else None
        ),
        vulnerabilities=[
            VulnerabilityContext(
                id=vulnerability.id,
                cve_id=vulnerability.cve_id,
                title=vulnerability.title,
                description=vulnerability.description,
                cvss_score=(float(vulnerability.cvss_score) if vulnerability.cvss_score is not None else None),
                severity=enum_text(vulnerability.severity),
                status=enum_text(vulnerability.status),
            )
            for vulnerability in vulnerabilities
        ],
        threat_intelligence_matches=matched_indicators,
        events=[
            EventContext(
                id=event.id,
                event_uid=event.event_uid,
                occurred_at=event.occurred_at,
                event_type=event.event_type,
                signature=event.signature,
                severity=enum_text(event.severity),
                anomaly_score=event.anomaly_score,
                detection_source=enum_text(event.source),
                source_ip=str(event.src_ip) if event.src_ip is not None else None,
                destination_ip=str(event.dest_ip) if event.dest_ip is not None else None,
                source_port=event.src_port,
                destination_port=event.dest_port,
                protocol=event.protocol,
            )
            for event in events
        ],
        findings=findings,
    )

    if record_history:
        db.add(
            IncidentHistory(
                incident_id=incident.id,
                from_state=incident.state,
                to_state=incident.state,
                action="context_enriched",
                actor=actor,
                details={
                    "asset_id": str(asset.id) if asset is not None else None,
                    "event_count": len(events),
                    "vulnerability_count": len(vulnerabilities),
                    "threat_match_count": len(matched_indicators),
                },
            )
        )
        db.commit()
    return bundle