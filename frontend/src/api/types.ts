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

/** Mock indicator shape retained for demo-only intelligence panels. */
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

export type BackendEventSource =
  | 'SURICATA'
  | 'ML_ANOMALY'
  | 'THREAT_INTEL'
  | 'VULNERABILITY_SCAN'
  | 'MANUAL'

export interface BackendEventAssetReference {
  id: string
  assetKey?: string
  name: string
  hostname: string | null
  ipAddress: string | null
  criticality: string
  status: string
}

export interface BackendEventResponse {
  id: string
  eventUid: string
  occurredAt: string
  sourceIp: string | null
  sourcePort: number | null
  destinationIp: string | null
  destinationPort: number | null
  protocol: string | null
  eventType: string
  signature: string | null
  severity: Severity
  detectionSource: BackendEventSource
  status: 'NEW' | 'CORRELATED'
  anomalyScore: number | null
  incidentIds: string[]
  assetId: string | null
  asset: BackendEventAssetReference | null
}

export interface BackendEventsPage {
  items: BackendEventResponse[]
  total: number
  page: number
  pageSize: number
}

export interface BackendDatabaseHealthResponse {
  status: 'healthy' | 'unhealthy'
  service: string
  version: string
  database: 'connected' | 'unreachable'
}

export type IncidentLifecycleState =
  | 'DETECTED'
  | 'UNDERSTOOD'
  | 'PRIORITISED'
  | 'VERIFIED'
  | 'AUTHORIZED'
  | 'CONTAINED'
  | 'LEARNED'

export type BackendResponseAction =
  | 'MONITOR'
  | 'INVESTIGATE'
  | 'ESCALATE'
  | 'BLOCK_IP'
  | 'ISOLATE_HOST'
  | 'DISABLE_ACCOUNT'
  | 'KILL_PROCESS'
  | 'QUARANTINE_FILE'
  | 'NO_ACTION'

export interface BackendIncidentDecisionResponse {
  id: string
  incidentId: string
  action: BackendResponseAction
  rationale: string
  riskScore: number
  confidence: number
  recommendation: string | null
  createdAt: string
}

/** GET /incidents item as serialized by the backend. */
export interface BackendIncidentResponse {
  id: string
  incidentKey: string
  title: string
  description: string | null
  severity: Severity
  riskScore: number | null
  state: IncidentLifecycleState
  detectionSource: BackendEventSource
  recommendedAction: BackendResponseAction | null
  assetId: string | null
  asset: BackendEventAssetReference | null
  eventCount: number
  createdAt: string
  updatedAt: string
  latestDecision: BackendIncidentDecisionResponse | null
}

export interface BackendIncidentPage {
  items: BackendIncidentResponse[]
  total: number
  page: number
  pageSize: number
}

export interface BackendIncidentAsset extends BackendEventAssetReference {
  assetKey: string
  assetType: string
  environment: string
  exposure: string
  owner: string | null
  vulnerabilityCount: number
  createdAt: string
  updatedAt: string
}

export interface BackendIncidentAuthorizationResponse {
  id: string
  incidentId: string
  decisionId: string | null
  requestedAction: string
  status: string
  requestedBy: string
  approvedBy: string | null
  reason: string | null
  requestedAt: string
  approvedAt: string | null
}

export interface BackendIncidentContainmentResponse {
  id: string
  incidentId: string
  authorizationId: string
  actionType: string
  target: string
  status: string
  executedAt: string | null
  verifiedAt: string | null
  result: string | null
  errorMessage: string | null
  createdAt: string
}

export interface BackendIncidentTimelineEntry {
  id: string
  timestamp: string
  source: string
  stage: string | null
  title: string
  description: string
  actor: string | null
  eventId: string | null
}

export interface BackendIncidentCyberMemoryReference {
  id: string
  lesson: string
  outcome: string | null
}

export interface BackendIncidentDetailResponse {
  incident: BackendIncidentResponse
  asset: BackendIncidentAsset | null
  events: BackendEventResponse[]
  timeline: BackendIncidentTimelineEntry[]
  decisions: BackendIncidentDecisionResponse[]
  authorizations: BackendIncidentAuthorizationResponse[]
  containmentActions: BackendIncidentContainmentResponse[]
  cyberMemories: BackendIncidentCyberMemoryReference[]
}

export type BackendAssetStatus = 'ACTIVE' | 'INACTIVE' | 'DECOMMISSIONED'
export type BackendAssetExposure = 'INTERNAL' | 'DMZ' | 'INTERNET_FACING'

export interface BackendAssetResponse {
  id: string
  assetKey: string
  name: string
  hostname: string | null
  ipAddress: string | null
  criticality: AssetCriticality
  status: BackendAssetStatus
  assetType: string
  environment: string
  exposure: BackendAssetExposure
  owner: string | null
  vulnerabilityCount: number
  createdAt: string
  updatedAt: string
}

export interface BackendAssetPage {
  items: BackendAssetResponse[]
  total: number
  page: number
  pageSize: number
}

/** Page-facing asset data; null enrichment means the live endpoint omits it. */
export interface AssetInventoryItem {
  id: string
  name: string
  hostname: string | null
  ipAddress: string | null
  type: AssetType | null
  criticality: AssetCriticality
  owner: string | null
  operatingSystem: string | null
  services: string[] | null
  vulnerabilities: Vulnerability[] | null
  vulnerabilityCount: number | null
  status: AssetStatus | BackendAssetStatus
  exposure: AssetExposure | BackendAssetExposure
  riskScore: number | null
  posture: AssetPosture | null
  activeIncidentIds: string[] | null
  lastSeen: string | null
  assetKey?: string
  assetType?: string | null
  environment?: string
  createdAt?: string | null
  updatedAt?: string | null
}

export interface AssetInventoryFilters {
  search?: string
  criticality?: AssetCriticality
  exposure?: BackendAssetExposure
  status?: BackendAssetStatus
  sortBy?: 'name' | 'criticality' | 'createdAt' | 'updatedAt'
  sortOrder?: 'asc' | 'desc'
}

export interface BackendThreatIndicatorResponse {
  id: string
  value: string
  indicatorType: IndicatorType
  source: string
  confidence: number | null
  severity: Severity
  firstSeen: string
  lastSeen: string
  isActive: boolean
}

export interface BackendThreatIndicatorPage {
  items: BackendThreatIndicatorResponse[]
  total: number
  page: number
  pageSize: number
}

/** Page-facing indicator data; null enrichment means the live endpoint omits it. */
export interface ThreatIndicatorInventoryItem {
  id: string
  type: IndicatorType
  value: string
  source: string
  confidence: number | null
  severity: Severity
  description: string | null
  tags: string[] | null
  firstSeen: string
  lastSeen: string
  matchCount: number | null
  incidentIds: string[] | null
  mitreTechniqueIds: string[] | null
  isActive?: boolean | null
}

export interface ThreatIndicatorInventoryFilters {
  indicatorType?: IndicatorType
  severity?: Severity
  minConfidence?: number
  maxConfidence?: number
  source?: string
  search?: string
  sortBy?: 'firstSeen' | 'lastSeen' | 'confidence' | 'severity'
  sortOrder?: 'asc' | 'desc'
}

/** UI-facing live model; retains backend names, nulls, enums, and collections. */
export interface LiveIncidentDetailsViewModel {
  incident: BackendIncidentResponse
  asset: BackendIncidentAsset | null
  events: BackendEventResponse[]
  timeline: BackendIncidentTimelineEntry[]
  decisions: BackendIncidentDecisionResponse[]
  authorizations: BackendIncidentAuthorizationResponse[]
  containmentActions: BackendIncidentContainmentResponse[]
  cyberMemories: BackendIncidentCyberMemoryReference[]
}

/** Queue-facing model; retains backend lifecycle and mock statuses without inventing missing fields. */
export interface IncidentQueueItem {
  id: string
  key: string
  title: string
  description: string | null
  severity: Severity
  riskScore: number | null
  lifecycle: IncidentLifecycleState | IncidentStatus
  detectionSource: BackendEventSource | DetectionSource
  recommendedAction: BackendResponseAction | null
  asset: BackendEventAssetReference | null
  eventCount: number
  createdAt: string
  updatedAt: string
  latestDecision: BackendIncidentDecisionResponse | null
}

export type IncidentQueueStateFilter = 'ALL' | 'ACTIVE' | 'CONTAINED' | 'LEARNED'
export type IncidentQueueSort = 'risk' | 'recent'

export interface IncidentQueueFilters {
  search?: string
  severity?: Severity
  state?: IncidentQueueStateFilter
  sort?: IncidentQueueSort
}

export type EventsPageItem = Omit<
  SecurityEvent,
  | 'id'
  | 'timestamp'
  | 'sourceIp'
  | 'destinationIp'
  | 'protocol'
  | 'detectionSource'
  | 'status'
  | 'anomalyScore'
  | 'incidentId'
  | 'assetId'
  | 'mitreTechniqueId'
> & {
  id: string
  eventUid?: string
  timestamp: string
  sourceIp: string | null
  destinationIp: string | null
  protocol: string | null
  detectionSource: BackendEventSource | DetectionSource
  status: EventStatus
  anomalyScore: number | null
  incidentIds: string[]
  assetId: string | null
  asset: BackendEventAssetReference | null
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
  incidentId: string | null
  threatName: string | null
  mitreTechniqueId: string | null
  sourceIp: string | null
  assetId: string | null
  riskScore: number | null
  actionTaken: ContainmentActionType | BackendResponseAction | null
  outcome: MemoryOutcome | string | null
  lessonsLearned: string
  tags: string[] | null
  similarIncidentIds: string[] | null
  recordedAt: string
  effectiveness?: string | null
}

export type BackendMemoryEffectiveness = 'EFFECTIVE' | 'PARTIALLY_EFFECTIVE' | 'INEFFECTIVE' | 'UNKNOWN'

export interface BackendCyberMemoryResponse {
  id: string
  incidentId: string | null
  decisionId: string | null
  lesson: string
  outcome: string | null
  actionTaken: BackendResponseAction | null
  effectiveness: BackendMemoryEffectiveness
  createdAt: string
  incident: {
    id: string
    incidentKey: string
    title: string
    state: string
    severity: Severity
    riskScore: number | null
  } | null
  decision: BackendIncidentDecisionResponse | null
  authorizations: BackendIncidentAuthorizationResponse[]
  containmentActions: BackendIncidentContainmentResponse[]
}

export interface BackendCyberMemoryPage {
  items: BackendCyberMemoryResponse[]
  total: number
  page: number
  pageSize: number
}

export interface CyberMemoryFilters {
  page?: number
  pageSize?: number
  incidentId?: string
  effectiveness?: BackendMemoryEffectiveness
  actionTaken?: BackendResponseAction
  search?: string
}

// ---------------------------------------------------------------------------
// Live Event Collector
// ---------------------------------------------------------------------------

/** GET /api/collector/status — counts cover every user's collector submissions. */
export interface BackendCollectorStatusResponse {
  collector: string
  status: 'receiving' | 'idle'
  totalEvents: number
  eventsLast24h: number
  lastReceivedAt: string | null
  recentEvents: BackendEventResponse[]
}

export interface CollectorStatus {
  collector: string
  status: 'receiving' | 'idle'
  totalEvents: number
  eventsLast24h: number
  lastReceivedAt: string | null
  recentEvents: EventsPageItem[]
}

/** One event for POST /api/collector/events. Source is always assigned by the server. */
export interface CollectorEventSubmission {
  idempotencyKey: string
  occurredAt: string
  eventType: string
  severity: Severity
  signature?: string
  srcIp?: string
  destIp?: string
  srcPort?: number
  destPort?: number
  protocol?: string
  anomalyScore?: number
  assetId?: string
  rawData?: Record<string, unknown>
}

export interface CollectorEventResult {
  index: number
  idempotencyKey: string | null
  status: 'created' | 'duplicate' | 'rejected'
  eventId: string | null
  eventUid: string | null
  reason: string | null
}

export interface CollectorSubmitResponse {
  created: number
  duplicates: number
  rejected: number
  results: CollectorEventResult[]
}

/** Body for the existing POST /api/incidents. */
export interface IncidentCreateRequest {
  title: string
  description?: string
  severity?: Severity
  detectionSource?: BackendEventSource
  assetId?: string
  eventIds?: string[]
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

/** Mock-only ATT&CK observations; the backend does not expose this collection. */
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
  overallRisk: number | null // 0–100; null when no system-level score is available
  averageRiskScore?: number | null // mean score of active incidents, when provided by the backend
  overallRiskLevel: Severity | null
  overallRiskChange: number | null // % change vs 24h ago
  incidentsBySeverity: Record<Severity, number | null> // active incidents only
  activeIncidents: number
  criticalThreats: number | null // unavailable when the backend does not report critical indicators
  containedThreats: number | null
  assetsAtRisk: number | null
  totalAssets: number
  criticalAssets: number
  eventsLast24h: number
  criticalEvents?: number
  highEvents?: number
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
