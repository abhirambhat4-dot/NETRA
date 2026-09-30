from enum import StrEnum


class AssetType(StrEnum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"
    CLOUD_INSTANCE = "cloud_instance"
    IOT = "iot"
    APPLICATION = "application"
    OTHER = "other"


class AssetEnvironment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Exposure(StrEnum):
    INTERNAL = "internal"
    DMZ = "dmz"
    INTERNET_FACING = "internet_facing"


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionSource(StrEnum):
    SURICATA = "suricata"
    ML_ANOMALY = "ml_anomaly"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY_SCAN = "vulnerability_scan"
    MANUAL = "manual"


class IncidentState(StrEnum):
    """NETRA lifecycle: DETECT -> UNDERSTAND -> PRIORITISE -> VERIFY -> (AUTHORIZE) -> CONTAIN -> LEARN."""

    DETECTED = "detected"
    UNDERSTOOD = "understood"
    PRIORITISED = "prioritised"
    VERIFIED = "verified"
    AUTHORIZED = "authorized"
    CONTAINED = "contained"
    LEARNED = "learned"


class ResponseAction(StrEnum):
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    NO_ACTION = "no_action"


class VulnerabilityStatus(StrEnum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ContainmentStatus(StrEnum):
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"


class Effectiveness(StrEnum):
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    UNKNOWN = "unknown"
