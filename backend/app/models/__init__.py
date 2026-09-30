"""Import every model so Base.metadata knows about all tables."""

from app.models.asset import Asset
from app.models.authorization import Authorization
from app.models.containment import ContainmentAction
from app.models.cyber_memory import CyberMemory
from app.models.decision import Decision
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvent, IncidentHistory
from app.models.threat_indicator import ThreatIndicator
from app.models.user import User
from app.models.vulnerability import Vulnerability

__all__ = [
    "Asset",
    "Authorization",
    "ContainmentAction",
    "CyberMemory",
    "Decision",
    "Incident",
    "IncidentEvent",
    "IncidentHistory",
    "SecurityEvent",
    "ThreatIndicator",
    "User",
    "Vulnerability",
]
