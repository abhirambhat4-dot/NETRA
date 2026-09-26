/**
 * NETRA API contract — shared data types.
 *
 * This file is the single source of truth for the shapes exchanged between
 * the frontend and the FastAPI backend. The backend MUST return JSON matching
 * these interfaces (camelCase keys, ISO-8601 UTC timestamps, string IDs).
 *
 * Entity chain:
 *   SecurityEvent → Incident → Asset → RiskAssessment → Decision
 *   → Authorization → ContainmentAction → CyberMemoryEntry
 *
 * Conventions:
 *   - IDs are prefixed strings: EVT-, INC-, AST-, RSK-, DEC-, AUT-, CNT-, MEM-
 *   - Timestamps are ISO-8601 strings, e.g. "2026-09-26T08:14:03Z"
 *   - Scores in 0–1 range: novelty, confidence, anomalyScore, factor values
 *   - Scores in 0–100 range: riskScore, overallRisk
 *   - CVSS is 0.0–10.0
 */

// ---------------------------------------------------------------------------
// Shared enums (string unions — map 1:1 to backend Enum values)
// ---------------------------------------------------------------------------

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

/** NETRA workflow: Detect → Understand → Prioritise → Verify → Contain → Learn */
export type WorkflowStage =
  | 'DETECT'
  | 'UNDERSTAND'
  | 'PRIORITISE'
  | 'VERIFY'
  | 'CONTAIN'
  | 'LEARN'

export type DetectionSource = 'SURICATA' | 'ML_ANOMALY' | 'THREAT_INTEL' | 'HYBRID'

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'SSH' | 'DNS' | 'SMB' | 'FTP' | 'RDP'

export type EventStatus = 'NEW' | 'CORRELATED' | 'DISMISSED'

export type IncidentStatus =
  | 'NEW'
  | 'INVESTIGATING'
  | 'AWAITING_AUTHORIZATION'
  | 'CONTAINING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'

export type AssetType =
  | 'DATABASE'
  | 'SERVER'
  | 'WEB_APPLICATION'
  | 'WORKSTATION'
  | 'NETWORK_DEVICE'

export type AssetCriticality = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type AssetStatus = 'ONLINE' | 'ISOLATED' | 'OFFLINE'

export type AssetExposure = 'EXTERNAL' | 'INTERNAL'

/** Security posture derived from active incidents and vulnerabilities. */
export type AssetPosture = 'AT_RISK' | 'MONITORED' | 'SECURE'

export type ContainmentActionType =
  | 'BLOCK_IP'
  | 'ISOLATE_HOST'
  | 'DISABLE_ACCOUNT'
  | 'RATE_LIMIT'
  | 'MONITOR'

export type DecisionStatus = 'PENDING_AUTHORIZATION' | 'APPROVED' | 'REJECTED' | 'EXECUTED'

export type AuthorizationStatus = 'PENDING' | 'OTP_SENT' | 'APPROVED' | 'REJECTED' | 'EXPIRED'

export type ContainmentStatus =
  | 'PENDING'
  | 'IN_PROGRESS'
  | 'EXECUTED'
  | 'VERIFIED'
  | 'FAILED'
  | 'ROLLED_BACK'

export type MemoryOutcome = 'CONTAINED' | 'FALSE_POSITIVE' | 'ESCALATED'

export type HealthStatus = 'HEALTHY' | 'DEGRADED' | 'DOWN'

export type UserRole = 'SOC_ANALYST' | 'SECURITY_ADMIN' | 'APPROVER'

// ---------------------------------------------------------------------------
// Threat intelligence
// ---------------------------------------------------------------------------

export interface MitreTechnique {
  id: string // e.g. "T1110"
  name: string // e.g. "Brute Force"
  tactic: string // e.g. "Credential Access"
  description: string
  url: string // https://attack.mitre.org/techniques/T1110/
}

export type IndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH'

/** GET /threat-intel/indicators — indicator of compromise known to NETRA. */
export interface ThreatIndicator {
  id: string // IND-xxx
  type: IndicatorType
  value: string // stored raw; UI displays defanged
  source: string // feed name, e.g. "abuse.ch ThreatFox"
  confidence: number // 0–1
  severity: Severity
  description: string
  tags: string[]
  firstSeen: string
  lastSeen: string
  matchCount: number // correlated events matching this indicator
  incidentIds: string[]
  mitreTechniqueIds: string[]
}

export interface Vulnerability {
  cveId: string // e.g. "CVE-2024-6387"
  title: string
  cvss: number // 0.0–10.0
  severity: Severity
}

// ---------------------------------------------------------------------------
// Detect
// ---------------------------------------------------------------------------

export interface SecurityEvent {
  id: string // EVT-xxxx
  timestamp: string
  sourceIp: string
  sourcePort: number | null
  destinationIp: string
  destinationPort: number | null
  protocol: Protocol
  eventType: string // e.g. "SSH Authentication Failure"
  signature: string | null // Suricata rule message, if any
  severity: Severity
  detectionSource: DetectionSource
  status: EventStatus
  anomalyScore: number // 0–1, from ML detector
  incidentId: string | null // set once correlated into an incident
  assetId: string | null // destination asset, if known
  mitreTechniqueId: string | null
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

export interface Asset {
  id: string // AST-xxx
  name: string // e.g. "Database Server"
  hostname: string
  ipAddress: string
  type: AssetType
  criticality: AssetCriticality
  owner: string
  operatingSystem: string
  services: string[] // e.g. ["ssh:22", "postgresql:5432"]
  vulnerabilities: Vulnerability[]
  status: AssetStatus // operational state
  exposure: AssetExposure
  riskScore: number // 0–100, driven by active incidents on this asset
  posture: AssetPosture
  activeIncidentIds: string[]
  lastSeen: string
}

// ---------------------------------------------------------------------------
// Understand / Prioritise
// ---------------------------------------------------------------------------

export type RiskFactorKey =
  | 'ASSET_CRITICALITY'
  | 'VULNERABILITY_SEVERITY'
  | 'ANOMALY_NOVELTY'
  | 'DETECTION_CONFIDENCE'
  | 'ATTACK_TECHNIQUE'
  | 'THREAT_INTELLIGENCE'

export interface RiskFactor {
  key: RiskFactorKey
  label: string
  weight: number // 0–1, weights sum to 1
  value: number // 0–1, normalised factor value
  contribution: number // points contributed to riskScore (weight × value × 100)
  explanation: string
}

export interface RiskAssessment {
  id: string // RSK-xxxx
  incidentId: string
  riskScore: number // 0–100
  severity: Severity
  novelty: number // 0–1
  confidence: number // 0–1
  cvss: number // highest relevant CVSS on the affected asset
  factors: RiskFactor[]
  explanation: string[] // human-readable "why NETRA prioritised this"
  assessedAt: string
  modelVersion: string
}

export interface TimelineEntry {
  id: string
  timestamp: string
  stage: WorkflowStage
  title: string
  description: string
  actor: string // "NETRA" for system actions, otherwise username
}

export interface Incident {
  id: string // INC-1042
  threatName: string // e.g. "SSH Brute Force"
  description: string
  severity: Severity
  riskScore: number // 0–100 (mirrors RiskAssessment.riskScore)
  status: IncidentStatus
  sourceIp: string
  destinationIp: string
  assetId: string
  mitreTechniqueId: string | null
  detectionSource: DetectionSource
  eventIds: string[]
  eventCount: number // total correlated events (eventIds holds representative samples)
  containedAt: string | null
  firstSeen: string
  lastSeen: string
  riskAssessmentId: string | null
  decisionId: string | null
  authorizationId: string | null
  containmentActionId: string | null
  memoryEntryId: string | null
  timeline: TimelineEntry[]
}

/** Aggregate returned by GET /incidents/{id} — everything the details page needs. */
export interface IncidentDetail {
  incident: Incident
  asset: Asset
  riskAssessment: RiskAssessment | null
  mitreTechnique: MitreTechnique | null
  events: SecurityEvent[]
  decision: Decision | null
  authorization: Authorization | null
  containmentAction: ContainmentAction | null
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export interface Decision {
  id: string // DEC-xxxx
  incidentId: string
  recommendedAction: ContainmentActionType
  target: string // IP / hostname / account the action applies to
  rationale: string // e.g. "Block the source IP."
  alternativeActions: ContainmentActionType[]
  requiresAuthorization: boolean
  status: DecisionStatus
  decidedAt: string
}

export interface Authorization {
  id: string // AUT-xxxx
  decisionId: string
  incidentId: string
  requestedBy: string
  requestedAt: string
  approver: string | null
  status: AuthorizationStatus
  otpVerified: boolean
  respondedAt: string | null
  comment: string | null
}

// ---------------------------------------------------------------------------
// Contain
// ---------------------------------------------------------------------------

export interface ContainmentAction {
  id: string // CNT-xxxx
  incidentId: string
  authorizationId: string
  actionType: ContainmentActionType
  target: string
  status: ContainmentStatus
  executedAt: string | null
  verifiedAt: string | null
  verificationResult: string | null // e.g. "No traffic from 192.168.1.25 in 10 min"
}

// ---------------------------------------------------------------------------
// Learn
// ---------------------------------------------------------------------------

export interface CyberMemoryEntry {
  id: string // MEM-xxxx
  incidentId: string
  threatName: string
  mitreTechniqueId: string | null
  sourceIp: string
  assetId: string
  riskScore: number
  actionTaken: ContainmentActionType
  outcome: MemoryOutcome
  lessonsLearned: string
  tags: string[]
  similarIncidentIds: string[]
  recordedAt: string
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export type TrendRange = '24h' | '7d'

/** One bucket of the system risk / activity trend. */
export interface RiskTrendPoint {
  timestamp: string // bucket start
  riskScore: number // 0–100 system risk at bucket end
  activeIncidents: number
  events: Record<Exclude<DetectionSource, 'HYBRID'>, number> // event volume by source
}

export interface SystemComponentHealth {
  component:
    | 'SURICATA'
    | 'COLLECTOR'
    | 'DETECTION_ENGINE'
    | 'RISK_ENGINE'
    | 'DATABASE'
    | 'CYBER_MEMORY'
  name: string
  status: HealthStatus
  latencyMs: number | null
  throughput: string | null // e.g. "1.4k events/min"
  uptime: number // 0–1 over last 30 days
  lastHeartbeat: string
  message: string | null
}

/** GET /threat-intel/observed — ATT&CK techniques seen in NETRA incidents. */
export interface TechniqueObservation {
  technique: MitreTechnique
  incidentCount: number
  activeIncidentCount: number
  incidentIds: string[]
  eventCount: number
  highestSeverity: Severity
  lastSeen: string
}

export interface DashboardStats {
  overallRisk: number // 0–100
  overallRiskLevel: Severity
  overallRiskChange: number // % change vs 24h ago, e.g. 8.4 or -3.1
  incidentsBySeverity: Record<Severity, number> // active incidents only
  activeIncidents: number
  criticalThreats: number // active CRITICAL incidents
  containedThreats: number // contained in the last 7 days
  assetsAtRisk: number
  totalAssets: number
  criticalAssets: number
  eventsLast24h: number
  riskDrivers: RiskFactor[] // factors aggregated across active incidents
  systemHealth: SystemComponentHealth[]
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface User {
  id: string
  username: string
  fullName: string
  email: string
  role: UserRole
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  accessToken: string
  tokenType: 'bearer'
  user: User
}

export interface AuthorizationRejectRequest {
  reason: string
}

export interface OtpVerifyRequest {
  authorizationId: string
  otp: string // 6 digits
}

// ---------------------------------------------------------------------------
// Generic API wrappers
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

/** FastAPI default error body. */
export interface ApiError {
  detail: string
}

export interface SecurityEventFilters {
  search?: string
  severity?: Severity
  detectionSource?: DetectionSource
  status?: EventStatus
  page?: number
  pageSize?: number
}

export interface IncidentFilters {
  search?: string
  severity?: Severity
  status?: IncidentStatus
  page?: number
  pageSize?: number
}
