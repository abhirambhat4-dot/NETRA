import type {
  Asset,
  Authorization,
  ContainmentAction,
  CyberMemoryEntry,
  DashboardStats,
  Decision,
  DecisionStatus,
  Incident,
  IncidentDetail,
  IncidentStatus,
  RiskAssessment,
  RiskFactor,
  RiskFactorKey,
  RiskTrendPoint,
  SecurityEvent,
  Severity,
  SystemComponentHealth,
  TechniqueObservation,
  ThreatIndicator,
  TimelineEntry,
  TrendRange,
} from '@/api/types'
import { SEVERITY_ORDER, riskToSeverity } from '@/lib/tones'
import { ASSET_SEEDS } from './assets'
import { HOUR, MINUTE, NOW, minutesAgo, seeded } from './clock'
import { INDICATOR_SEEDS } from './intel'
import { mitreById } from './mitre'
import { BACKGROUND_EVENTS, SCENARIOS, type IncidentScenario } from './scenarios'

/**
 * In-memory NETRA world, derived entirely from scenarios.ts + assets.ts.
 * Every number shown in the UI traces back to these records, so the
 * chain events → incidents → assets → risk → decision → authorization →
 * containment → cyber memory is always consistent.
 */

const ACTIVE_STATUSES: IncidentStatus[] = ['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING']
export const isActive = (status: IncidentStatus) => ACTIVE_STATUSES.includes(status)

const num = (incidentId: string) => incidentId.slice(4) // "INC-1042" → "1042"
const round1 = (n: number) => Math.round(n * 10) / 10
const pct = (v: number) => `${Math.round(v * 100)}%`

// ---------------------------------------------------------------------------
// Risk model (mirrors what the backend risk engine will compute)
// ---------------------------------------------------------------------------

const WEIGHTS: Record<RiskFactorKey, number> = {
  ASSET_CRITICALITY: 0.25,
  VULNERABILITY_SEVERITY: 0.2,
  ANOMALY_NOVELTY: 0.2,
  DETECTION_CONFIDENCE: 0.15,
  ATTACK_TECHNIQUE: 0.1,
  THREAT_INTELLIGENCE: 0.1,
}

const FACTOR_LABELS: Record<RiskFactorKey, string> = {
  ASSET_CRITICALITY: 'Asset criticality',
  VULNERABILITY_SEVERITY: 'Vulnerability severity',
  ANOMALY_NOVELTY: 'Behavioural novelty',
  DETECTION_CONFIDENCE: 'Detection confidence',
  ATTACK_TECHNIQUE: 'Attack technique',
  THREAT_INTELLIGENCE: 'Threat intelligence',
}

const CRITICALITY_VALUE = { CRITICAL: 1, HIGH: 0.75, MEDIUM: 0.5, LOW: 0.25 } as const

function factor(key: RiskFactorKey, value: number, explanation: string): RiskFactor {
  const weight = WEIGHTS[key]
  return { key, label: FACTOR_LABELS[key], weight, value, contribution: round1(weight * value * 100), explanation }
}

/** System risk: residual baseline + saturating aggregation of active incident risk. */
const SYSTEM_BASELINE = 40
function systemRisk(incidentRisks: number[]): number {
  const remaining = incidentRisks.reduce((p, r) => p * (1 - 0.17 * (r / 100)), 1)
  return SYSTEM_BASELINE + (100 - SYSTEM_BASELINE) * (1 - remaining)
}

const assetSeedById = new Map(ASSET_SEEDS.map((a) => [a.id, a]))
const maxCvss = (assetId: string) =>
  Math.max(0, ...(assetSeedById.get(assetId)?.vulnerabilities.map((v) => v.cvss) ?? []))

// ---------------------------------------------------------------------------
// Risk assessments
// ---------------------------------------------------------------------------

const riskAssessments: RiskAssessment[] = SCENARIOS.map((s) => {
  const asset = assetSeedById.get(s.assetId)!
  const technique = mitreById.get(s.mitreTechniqueId)!
  const cvss = maxCvss(s.assetId)
  const sourceCount = new Set(s.events.map((e) => e.source)).size

  const factors = [
    factor('ASSET_CRITICALITY', CRITICALITY_VALUE[asset.criticality], `${asset.name} is rated ${asset.criticality.toLowerCase()} criticality`),
    factor('VULNERABILITY_SEVERITY', cvss / 10, cvss ? `Highest open vulnerability on asset: CVSS ${cvss.toFixed(1)}` : 'No open vulnerabilities on asset'),
    factor('ANOMALY_NOVELTY', s.risk.novelty, `${pct(s.risk.novelty)} deviation from the 30-day behavioural baseline`),
    factor('DETECTION_CONFIDENCE', s.risk.confidence, `${pct(s.risk.confidence)} confidence across ${sourceCount} detection source${sourceCount > 1 ? 's' : ''}`),
    factor('ATTACK_TECHNIQUE', s.risk.technique, `Mapped to ${technique.id} ${technique.name} (${technique.tactic})`),
    factor('THREAT_INTELLIGENCE', s.risk.intel, s.risk.intel >= 0.5 ? 'Indicators matched threat-intelligence feeds' : 'Limited threat-intelligence corroboration'),
  ]
  const riskScore = Math.round(factors.reduce((sum, f) => sum + f.contribution, 0))

  return {
    id: `RSK-${num(s.id)}`,
    incidentId: s.id,
    riskScore,
    severity: riskToSeverity(riskScore),
    novelty: s.risk.novelty,
    confidence: s.risk.confidence,
    cvss,
    factors,
    explanation: s.explanation,
    assessedAt: minutesAgo(s.firstSeenMin - 3),
    modelVersion: 'netra-risk 1.4.0',
  }
})
const riskByIncident = new Map(riskAssessments.map((r) => [r.incidentId, r]))

// ---------------------------------------------------------------------------
// Security events
// ---------------------------------------------------------------------------

const assetByIp = new Map(ASSET_SEEDS.map((a) => [a.ipAddress, a.id]))

type EventDraft = Omit<SecurityEvent, 'id'> & { min: number }

const eventDrafts: EventDraft[] = [
  ...SCENARIOS.flatMap((s) =>
    s.events.map<EventDraft>((e) => ({
      min: e.min,
      timestamp: minutesAgo(e.min),
      sourceIp: s.sourceIp,
      sourcePort: e.srcPort ?? null,
      destinationIp: s.destinationIp,
      destinationPort: e.dstPort ?? null,
      protocol: e.protocol,
      eventType: e.eventType,
      signature: e.signature ?? null,
      severity: e.severity,
      detectionSource: e.source,
      status: 'CORRELATED',
      anomalyScore: e.anomaly,
      incidentId: s.id,
      assetId: s.assetId,
      mitreTechniqueId: s.mitreTechniqueId,
    })),
  ),
  ...BACKGROUND_EVENTS.map<EventDraft>((e) => ({
    min: e.min,
    timestamp: minutesAgo(e.min),
    sourceIp: e.srcIp,
    sourcePort: e.srcPort ?? null,
    destinationIp: e.dstIp,
    destinationPort: e.dstPort ?? null,
    protocol: e.protocol,
    eventType: e.eventType,
    signature: e.signature ?? null,
    severity: e.severity,
    detectionSource: e.source,
    status: e.status,
    anomalyScore: e.anomaly,
    incidentId: null,
    assetId: assetByIp.get(e.dstIp) ?? assetByIp.get(e.srcIp) ?? null,
    mitreTechniqueId: null,
  })),
]

// Oldest first gets the lowest ID; stored newest first.
const events: SecurityEvent[] = eventDrafts
  .sort((a, b) => b.min - a.min)
  .map(({ min: _min, ...e }, i) => ({ id: `EVT-${88100 + i}`, ...e }))
  .reverse()

// ---------------------------------------------------------------------------
// Decision → Authorization → Containment → Cyber Memory
// ---------------------------------------------------------------------------

const decisions: Decision[] = []
const authorizations: Authorization[] = []
const containmentActions: ContainmentAction[] = []
const memoryEntries: CyberMemoryEntry[] = []

for (const s of SCENARIOS) {
  const r = s.response
  const n = num(s.id)
  const auth = r.authorization
  const cnt = r.containment

  let decisionStatus: DecisionStatus = 'PENDING_AUTHORIZATION'
  if (r.action === 'MONITOR') decisionStatus = 'APPROVED'
  if (auth?.status === 'APPROVED') decisionStatus = 'APPROVED'
  if (auth?.status === 'REJECTED') decisionStatus = 'REJECTED'
  if (cnt && (cnt.status === 'EXECUTED' || cnt.status === 'VERIFIED')) decisionStatus = 'EXECUTED'

  decisions.push({
    id: `DEC-${n}`,
    incidentId: s.id,
    recommendedAction: r.action,
    target: r.target,
    rationale: r.rationale,
    alternativeActions: r.alternatives,
    requiresAuthorization: r.action !== 'MONITOR',
    status: decisionStatus,
    decidedAt: minutesAgo(s.firstSeenMin - 3),
  })

  if (auth) {
    authorizations.push({
      id: `AUT-${n}`,
      decisionId: `DEC-${n}`,
      incidentId: s.id,
      requestedBy: 'analyst',
      requestedAt: minutesAgo(auth.requestedMin),
      approver: 'admin',
      status: auth.status,
      otpVerified: auth.status === 'APPROVED',
      respondedAt: auth.respondedMin !== undefined ? minutesAgo(auth.respondedMin) : null,
      comment: auth.comment ?? null,
    })
  }

  if (auth && cnt) {
    containmentActions.push({
      id: `CNT-${n}`,
      incidentId: s.id,
      authorizationId: `AUT-${n}`,
      actionType: r.action,
      target: r.target,
      status: cnt.status,
      executedAt: cnt.executedMin !== undefined ? minutesAgo(cnt.executedMin) : null,
      verifiedAt: cnt.verifiedMin !== undefined ? minutesAgo(cnt.verifiedMin) : null,
      verificationResult: cnt.result ?? null,
    })
  }

  if (r.memory) {
    memoryEntries.push({
      id: r.memory.id,
      incidentId: s.id,
      threatName: s.threatName,
      mitreTechniqueId: s.mitreTechniqueId,
      sourceIp: s.sourceIp,
      assetId: s.assetId,
      riskScore: riskByIncident.get(s.id)!.riskScore,
      actionTaken: r.action,
      outcome: r.memory.outcome,
      lessonsLearned: r.memory.lessons,
      tags: r.memory.tags,
      similarIncidentIds: r.memory.similar,
      recordedAt: minutesAgo((s.closedMin ?? s.lastSeenMin) - 5),
    })
  }
}

const ACTION_LABEL = {
  BLOCK_IP: 'Block IP',
  ISOLATE_HOST: 'Isolate host',
  DISABLE_ACCOUNT: 'Disable account',
  RATE_LIMIT: 'Rate limit',
  MONITOR: 'Monitor',
} as const

// ---------------------------------------------------------------------------
// Incidents (+ timeline)
// ---------------------------------------------------------------------------

function buildTimeline(s: IncidentScenario, risk: RiskAssessment): TimelineEntry[] {
  const first = s.events[0]
  const t: (Omit<TimelineEntry, 'id' | 'timestamp'> & { min: number })[] = [
    { min: s.firstSeenMin, stage: 'DETECT', title: 'First detection', description: `${first.eventType} (${first.source === 'ML_ANOMALY' ? 'ML detector' : first.source === 'THREAT_INTEL' ? 'threat intel' : 'Suricata'})`, actor: 'NETRA' },
    { min: s.firstSeenMin - 2, stage: 'UNDERSTAND', title: 'Events correlated', description: `Correlated into ${s.id} on ${assetSeedById.get(s.assetId)!.name}`, actor: 'NETRA' },
    { min: s.firstSeenMin - 3, stage: 'PRIORITISE', title: `Risk scored ${risk.riskScore}/100`, description: `${risk.severity} — recommended action: ${ACTION_LABEL[s.response.action]} ${s.response.target}`, actor: 'NETRA' },
  ]
  if (s.lastSeenMin < s.firstSeenMin - 5) {
    t.push({ min: s.lastSeenMin, stage: 'DETECT', title: 'Latest activity', description: `${s.eventCount} correlated events so far`, actor: 'NETRA' })
  }
  const auth = s.response.authorization
  if (auth) {
    t.push({ min: auth.requestedMin, stage: 'VERIFY', title: 'Authorization requested', description: `${ACTION_LABEL[s.response.action]} ${s.response.target}`, actor: 'analyst' })
    if (auth.status === 'OTP_SENT') t.push({ min: auth.requestedMin - 0.5, stage: 'VERIFY', title: 'OTP sent to approver', description: 'Awaiting one-time-password verification', actor: 'NETRA' })
    if (auth.respondedMin !== undefined) t.push({ min: auth.respondedMin, stage: 'VERIFY', title: auth.status === 'APPROVED' ? 'Authorization approved (OTP verified)' : 'Authorization rejected', description: auth.comment ?? 'Approver identity verified by OTP', actor: 'admin' })
  }
  const cnt = s.response.containment
  if (cnt?.executedMin !== undefined) t.push({ min: cnt.executedMin, stage: 'CONTAIN', title: cnt.status === 'IN_PROGRESS' ? 'Containment in progress' : 'Containment executed', description: `${ACTION_LABEL[s.response.action]} ${s.response.target}`, actor: 'NETRA' })
  if (cnt?.verifiedMin !== undefined) t.push({ min: cnt.verifiedMin, stage: 'CONTAIN', title: 'Containment verified', description: cnt.result ?? 'Threat activity stopped', actor: 'NETRA' })
  if (s.status === 'FALSE_POSITIVE' && s.closedMin !== undefined) t.push({ min: s.closedMin, stage: 'VERIFY', title: 'Marked false positive', description: 'Benign activity confirmed by asset owner', actor: 'analyst' })
  if (s.response.memory) t.push({ min: (s.closedMin ?? s.lastSeenMin) - 5, stage: 'LEARN', title: 'Stored in Cyber Memory', description: s.response.memory.lessons, actor: 'NETRA' })

  return t
    .sort((a, b) => b.min - a.min)
    .map(({ min, ...e }, i) => ({ id: `${s.id}-T${i + 1}`, timestamp: minutesAgo(min), ...e }))
}

const incidents: Incident[] = SCENARIOS.map((s) => {
  const risk = riskByIncident.get(s.id)!
  const n = num(s.id)
  return {
    id: s.id,
    threatName: s.threatName,
    description: s.description,
    severity: risk.severity,
    riskScore: risk.riskScore,
    status: s.status,
    sourceIp: s.sourceIp,
    destinationIp: s.destinationIp,
    assetId: s.assetId,
    mitreTechniqueId: s.mitreTechniqueId,
    detectionSource: s.detectionSource,
    eventIds: events.filter((e) => e.incidentId === s.id).map((e) => e.id),
    eventCount: s.eventCount,
    firstSeen: minutesAgo(s.firstSeenMin),
    lastSeen: minutesAgo(s.lastSeenMin),
    containedAt: s.closedMin !== undefined && s.status === 'CONTAINED' ? minutesAgo(s.closedMin) : null,
    riskAssessmentId: risk.id,
    decisionId: `DEC-${n}`,
    authorizationId: s.response.authorization ? `AUT-${n}` : null,
    containmentActionId: s.response.authorization && s.response.containment ? `CNT-${n}` : null,
    memoryEntryId: s.response.memory?.id ?? null,
    timeline: buildTimeline(s, risk),
  }
}).sort((a, b) => b.riskScore - a.riskScore)

const getActiveIncidents = () => incidents.filter((i) => isActive(i.status))

// ---------------------------------------------------------------------------
// Assets (risk + posture derived from active incidents — recomputed on read
// so mock containment actions are reflected everywhere)
// ---------------------------------------------------------------------------

/** Operational status overrides written by containment (e.g. ISOLATE_HOST). */
const assetStatusOverride = new Map<string, Asset['status']>()

function deriveAssets(): Asset[] {
  const active = getActiveIncidents()
  return ASSET_SEEDS.map(({ baselineRisk, ...seed }) => {
    const mine = active.filter((i) => i.assetId === seed.id)
    const riskScore = mine.length ? Math.max(...mine.map((i) => i.riskScore)) : baselineRisk
    const posture: Asset['posture'] = mine.some((i) => i.riskScore >= 75)
      ? 'AT_RISK'
      : mine.length || maxCvss(seed.id) >= 9
        ? 'MONITORED'
        : 'SECURE'
    return {
      ...seed,
      status: assetStatusOverride.get(seed.id) ?? seed.status,
      riskScore,
      posture,
      activeIncidentIds: mine.map((i) => i.id),
    }
  }).sort((a, b) => b.riskScore - a.riskScore)
}

// ---------------------------------------------------------------------------
// Trends
// ---------------------------------------------------------------------------

const scenarioActiveAt = (s: IncidentScenario, minAgo: number) =>
  s.firstSeenMin >= minAgo && (s.closedMin === undefined || s.closedMin < minAgo)

function riskAt(minAgo: number) {
  const risks = SCENARIOS.filter((s) => scenarioActiveAt(s, minAgo)).map((s) => riskByIncident.get(s.id)!.riskScore)
  return { risk: systemRisk(risks), active: risks.length }
}

function buildTrend(range: TrendRange): RiskTrendPoint[] {
  const bucketMs = range === '24h' ? HOUR : 6 * HOUR
  const buckets = range === '24h' ? 24 : 28
  const rand = seeded(range === '24h' ? 24 : 7)
  const bucketMin = bucketMs / MINUTE

  return Array.from({ length: buckets }, (_, i) => {
    const endMin = (buckets - 1 - i) * bucketMin // minutes ago at bucket end
    const startMin = endMin + bucketMin
    const { risk, active } = riskAt(endMin)
    const noise = i === buckets - 1 ? 0 : (rand() - 0.5) * 3

    // Background alert volume with a daily rhythm (UTC hour of bucket start).
    const hour = new Date(NOW - startMin * MINUTE).getUTCHours()
    const diurnal = 0.65 + 0.45 * Math.sin(((hour - 6) / 24) * Math.PI * 2) ** 2
    const scale = (bucketMs / HOUR) * diurnal
    const volume = {
      SURICATA: Math.round((42 + rand() * 26) * scale),
      THREAT_INTEL: Math.round((4 + rand() * 6) * scale),
      ML_ANOMALY: Math.round((9 + rand() * 9) * scale),
    }

    // Incident-correlated events spread across each incident's activity window.
    for (const s of SCENARIOS) {
      const overlap = Math.min(startMin, s.firstSeenMin) - Math.max(endMin, s.lastSeenMin)
      if (overlap <= 0) continue
      const span = Math.max(1, s.firstSeenMin - s.lastSeenMin)
      const share = Math.round(s.eventCount * (overlap / span))
      const sources = s.events.map((e) => e.source)
      for (const src of sources) volume[src] += Math.round(share / sources.length)
    }

    return {
      timestamp: new Date(NOW - startMin * MINUTE).toISOString(),
      riskScore: Math.max(0, Math.min(100, Math.round(risk + noise))),
      activeIncidents: active,
      events: volume,
    }
  })
}

const trends: Record<TrendRange, RiskTrendPoint[]> = { '24h': buildTrend('24h'), '7d': buildTrend('7d') }

// ---------------------------------------------------------------------------
// System health
// ---------------------------------------------------------------------------

const heartbeat = (s: number) => new Date(NOW - s * 1000).toISOString()

const systemHealth: SystemComponentHealth[] = [
  { component: 'SURICATA', name: 'Suricata IDS', status: 'HEALTHY', latencyMs: 3, throughput: '1.3k pkts/s', uptime: 0.9998, lastHeartbeat: heartbeat(4), message: null },
  { component: 'COLLECTOR', name: 'Log Collector', status: 'HEALTHY', latencyMs: 12, throughput: '2.1k rec/min', uptime: 0.9995, lastHeartbeat: heartbeat(6), message: null },
  { component: 'DETECTION_ENGINE', name: 'ML Detection Engine', status: 'HEALTHY', latencyMs: 48, throughput: '310 inf/min', uptime: 0.999, lastHeartbeat: heartbeat(3), message: null },
  { component: 'RISK_ENGINE', name: 'Risk Engine', status: 'HEALTHY', latencyMs: 21, throughput: '42 scores/h', uptime: 1, lastHeartbeat: heartbeat(2), message: null },
  { component: 'DATABASE', name: 'PostgreSQL', status: 'HEALTHY', latencyMs: 4, throughput: '180 q/s', uptime: 0.9999, lastHeartbeat: heartbeat(5), message: null },
  { component: 'CYBER_MEMORY', name: 'Cyber Memory', status: 'HEALTHY', latencyMs: 9, throughput: `${memoryEntries.length} entries`, uptime: 0.9997, lastHeartbeat: heartbeat(8), message: null },
]

// ---------------------------------------------------------------------------
// Threat-intelligence indicators (linked to incidents / events by value + ID)
// ---------------------------------------------------------------------------

function deriveIndicators(): ThreatIndicator[] {
  return INDICATOR_SEEDS.map(({ firstSeenMin, ...seed }) => {
    const host = seed.type === 'URL' ? new URL(seed.value).hostname : seed.value
    const direct = events.filter(
      (e) => e.sourceIp === seed.value || e.destinationIp === seed.value || e.signature?.includes(host),
    )
    const linked = events.filter((e) => e.incidentId && seed.incidentIds.includes(e.incidentId))
    const matched = direct.length ? direct : linked
    const related = incidents.filter((i) => seed.incidentIds.includes(i.id))
    const lastSeen = [...matched.map((e) => e.timestamp), ...related.map((i) => i.lastSeen)].sort().at(-1)
    return {
      ...seed,
      firstSeen: minutesAgo(firstSeenMin),
      lastSeen: lastSeen ?? minutesAgo(firstSeenMin),
      matchCount: matched.length,
    }
  }).sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen))
}

// ---------------------------------------------------------------------------
// Aggregates (recomputed on read)
// ---------------------------------------------------------------------------

const maxSeverity = (list: Severity[]) => SEVERITY_ORDER.find((s) => list.includes(s)) ?? 'INFO'

function deriveTechniqueObservations(): TechniqueObservation[] {
  return [...new Set(incidents.map((i) => i.mitreTechniqueId!))]
    .map((id) => {
      const related = incidents.filter((i) => i.mitreTechniqueId === id)
      return {
        technique: mitreById.get(id)!,
        incidentCount: related.length,
        activeIncidentCount: related.filter((i) => isActive(i.status)).length,
        incidentIds: related.map((i) => i.id),
        eventCount: related.reduce((sum, i) => sum + i.eventCount, 0),
        highestSeverity: maxSeverity(related.map((i) => i.severity)),
        lastSeen: related.map((i) => i.lastSeen).sort().at(-1)!,
      }
    })
    .sort((a, b) => b.activeIncidentCount - a.activeIncidentCount || b.eventCount - a.eventCount)
}

function currentSystemRisk() {
  return Math.round(systemRisk(getActiveIncidents().map((i) => i.riskScore)))
}

/** Historical trend is static; the final bucket reflects the live state. */
function getTrend(range: TrendRange): RiskTrendPoint[] {
  const points = trends[range].map((p) => ({ ...p }))
  const last = points.at(-1)!
  last.riskScore = currentSystemRisk()
  last.activeIncidents = getActiveIncidents().length
  return points
}

function getSystemHealth(): SystemComponentHealth[] {
  return systemHealth.map((c) =>
    c.component === 'CYBER_MEMORY' ? { ...c, throughput: `${memoryEntries.length} entries` } : c,
  )
}

function buildDashboardStats(): DashboardStats {
  const active = getActiveIncidents()
  const assets = deriveAssets()
  const current = currentSystemRisk()
  const dayAgo = Math.round(riskAt(24 * 60).risk)
  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>
  active.forEach((i) => bySeverity[i.severity]++)

  const activeRisk = active.map((i) => riskByIncident.get(i.id)!)
  const riskDrivers = (Object.keys(WEIGHTS) as RiskFactorKey[])
    .map((key) => {
      const values = activeRisk.map((r) => r.factors.find((f) => f.key === key)!.value)
      const value = values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0
      return factor(key, round1(value * 100) / 100, `Average across ${values.length} active incidents`)
    })
    .sort((a, b) => b.contribution - a.contribution)

  return {
    overallRisk: current,
    overallRiskLevel: riskToSeverity(current),
    overallRiskChange: round1(((current - dayAgo) / dayAgo) * 100),
    incidentsBySeverity: bySeverity,
    activeIncidents: active.length,
    criticalThreats: active.filter((i) => i.severity === 'CRITICAL').length,
    containedThreats: incidents.filter((i) => i.containedAt && Date.now() - Date.parse(i.containedAt) < 7 * 24 * HOUR).length,
    assetsAtRisk: assets.filter((a) => a.posture === 'AT_RISK').length,
    totalAssets: assets.length,
    criticalAssets: assets.filter((a) => a.criticality === 'CRITICAL').length,
    eventsLast24h: trends['24h'].reduce((sum, p) => sum + p.events.SURICATA + p.events.THREAT_INTEL + p.events.ML_ANOMALY, 0),
    riskDrivers,
    systemHealth: getSystemHealth(),
  }
}

function buildIncidentDetail(id: string): IncidentDetail | null {
  const incident = incidents.find((i) => i.id === id)
  if (!incident) return null
  return {
    incident,
    asset: deriveAssets().find((a) => a.id === incident.assetId)!,
    riskAssessment: riskByIncident.get(id) ?? null,
    mitreTechnique: incident.mitreTechniqueId ? (mitreById.get(incident.mitreTechniqueId) ?? null) : null,
    events: events.filter((e) => e.incidentId === id),
    decision: decisions.find((d) => d.incidentId === id) ?? null,
    authorization: authorizations.find((a) => a.incidentId === id) ?? null,
    containmentAction: containmentActions.find((c) => c.incidentId === id) ?? null,
  }
}

// ---------------------------------------------------------------------------
// Mock workflow actions — UI SIMULATION ONLY.
// Verify → Contain → Learn transitions mirroring the future endpoints
// POST /incidents/{id}/authorization, /authorizations/{id}/otp/verify,
// /authorizations/{id}/reject, /containment/{id}/execute, /containment/{id}/verify.
// Nothing here touches a real system or network.
// ---------------------------------------------------------------------------

/** Demo one-time password shown in the UI. Real OTP delivery is a backend concern. */
export const DEMO_OTP = '246810'
const CURRENT_USER = 'admin'

let memorySeq = 213
const nowIso = () => new Date().toISOString()

function requireIncident(id: string) {
  const incident = incidents.find((i) => i.id === id)
  if (!incident) throw new Error(`Incident ${id} not found`)
  return incident
}

function addTimeline(incident: Incident, entry: Omit<TimelineEntry, 'id' | 'timestamp'>) {
  incident.timeline.push({ id: `${incident.id}-T${incident.timeline.length + 1}`, timestamp: nowIso(), ...entry })
}

function upsert<T extends { id: string }>(list: T[], item: T) {
  const i = list.findIndex((x) => x.id === item.id)
  if (i >= 0) list[i] = item
  else list.push(item)
}

const VERIFICATION_RESULT: Record<Decision['recommendedAction'], (target: string) => string> = {
  BLOCK_IP: (t) => `No traffic from ${t} observed in the 10-minute window after the block`,
  ISOLATE_HOST: (t) => `${t} unreachable from production VLANs; outbound beaconing stopped`,
  DISABLE_ACCOUNT: (t) => `${t} disabled; no further authentication attempts recorded`,
  RATE_LIMIT: (t) => `Connection rate from ${t} held below threshold`,
  MONITOR: (t) => `${t} under enhanced monitoring; no escalation observed`,
}

function requestAuthorization(incidentId: string): Authorization {
  const incident = requireIncident(incidentId)
  const decision = decisions.find((d) => d.incidentId === incidentId)
  if (!decision?.requiresAuthorization) throw new Error('This decision does not require authorization')
  const existing = authorizations.find((a) => a.incidentId === incidentId)
  if (existing && ['PENDING', 'OTP_SENT', 'APPROVED'].includes(existing.status)) {
    throw new Error('Authorization already in progress')
  }

  const auth: Authorization = {
    id: `AUT-${num(incidentId)}`,
    decisionId: decision.id,
    incidentId,
    requestedBy: CURRENT_USER,
    requestedAt: nowIso(),
    approver: CURRENT_USER,
    status: 'OTP_SENT',
    otpVerified: false,
    respondedAt: null,
    comment: null,
  }
  upsert(authorizations, auth)
  decision.status = 'PENDING_AUTHORIZATION'
  incident.authorizationId = auth.id
  incident.status = 'AWAITING_AUTHORIZATION'
  addTimeline(incident, { stage: 'VERIFY', title: 'Authorization requested', description: `${ACTION_LABEL[decision.recommendedAction]} ${decision.target}`, actor: CURRENT_USER })
  addTimeline(incident, { stage: 'VERIFY', title: 'OTP sent to approver', description: 'Awaiting one-time-password verification', actor: 'NETRA' })
  return auth
}

function verifyOtp(authorizationId: string, otp: string): Authorization {
  const auth = authorizations.find((a) => a.id === authorizationId)
  if (!auth || auth.status !== 'OTP_SENT') throw new Error('No authorization awaiting OTP')
  if (otp !== DEMO_OTP) throw new Error('Invalid one-time password')
  const incident = requireIncident(auth.incidentId)
  const decision = decisions.find((d) => d.id === auth.decisionId)!

  Object.assign(auth, { status: 'APPROVED', otpVerified: true, respondedAt: nowIso(), comment: 'Approved — approver identity verified by OTP' })
  decision.status = 'APPROVED'
  const containment: ContainmentAction = {
    id: `CNT-${num(incident.id)}`,
    incidentId: incident.id,
    authorizationId: auth.id,
    actionType: decision.recommendedAction,
    target: decision.target,
    status: 'PENDING',
    executedAt: null,
    verifiedAt: null,
    verificationResult: null,
  }
  upsert(containmentActions, containment)
  incident.containmentActionId = containment.id
  incident.status = 'CONTAINING'
  addTimeline(incident, { stage: 'VERIFY', title: 'Authorization approved (OTP verified)', description: 'Approver identity verified by OTP', actor: CURRENT_USER })
  return auth
}

function rejectAuthorization(authorizationId: string, reason: string): Authorization {
  const auth = authorizations.find((a) => a.id === authorizationId)
  if (!auth || !['PENDING', 'OTP_SENT'].includes(auth.status)) throw new Error('No pending authorization')
  const incident = requireIncident(auth.incidentId)
  Object.assign(auth, { status: 'REJECTED', respondedAt: nowIso(), comment: reason || 'Rejected by approver' })
  decisions.find((d) => d.id === auth.decisionId)!.status = 'REJECTED'
  incident.status = 'INVESTIGATING'
  addTimeline(incident, { stage: 'VERIFY', title: 'Authorization rejected', description: auth.comment!, actor: CURRENT_USER })
  return auth
}

function executeContainment(containmentId: string): ContainmentAction {
  const action = containmentActions.find((c) => c.id === containmentId)
  if (!action || !['PENDING', 'IN_PROGRESS'].includes(action.status)) throw new Error('Containment is not ready to execute')
  const auth = authorizations.find((a) => a.id === action.authorizationId)
  if (auth?.status !== 'APPROVED') throw new Error('Containment requires an approved authorization')
  const incident = requireIncident(action.incidentId)

  Object.assign(action, { status: 'EXECUTED', executedAt: nowIso() })
  if (action.actionType === 'ISOLATE_HOST') assetStatusOverride.set(incident.assetId, 'ISOLATED')
  addTimeline(incident, { stage: 'CONTAIN', title: 'Containment executed', description: `${ACTION_LABEL[action.actionType]} ${action.target}`, actor: 'NETRA' })
  return action
}

function verifyContainment(containmentId: string): ContainmentAction {
  const action = containmentActions.find((c) => c.id === containmentId)
  if (!action || action.status !== 'EXECUTED') throw new Error('Containment has not been executed')
  const incident = requireIncident(action.incidentId)
  const result = VERIFICATION_RESULT[action.actionType](action.target)

  Object.assign(action, { status: 'VERIFIED', verifiedAt: nowIso(), verificationResult: result })
  decisions.find((d) => d.incidentId === incident.id)!.status = 'EXECUTED'
  incident.status = 'CONTAINED'
  incident.containedAt = nowIso()

  const technique = incident.mitreTechniqueId ? mitreById.get(incident.mitreTechniqueId) : undefined
  const memory: CyberMemoryEntry = {
    id: `MEM-0${memorySeq++}`,
    incidentId: incident.id,
    threatName: incident.threatName,
    mitreTechniqueId: incident.mitreTechniqueId,
    sourceIp: incident.sourceIp,
    assetId: incident.assetId,
    riskScore: incident.riskScore,
    actionTaken: action.actionType,
    outcome: 'CONTAINED',
    lessonsLearned: `${ACTION_LABEL[action.actionType]} on ${action.target} stopped the ${incident.threatName.toLowerCase()}; ${technique ? `${technique.id} ${technique.name}` : 'this pattern'} will be prioritised faster on similar assets.`,
    tags: [technique?.tactic.toLowerCase().replace(/ /g, '-') ?? 'response', action.actionType.toLowerCase().replace('_', '-')],
    similarIncidentIds: incidents.filter((i) => i.id !== incident.id && i.mitreTechniqueId === incident.mitreTechniqueId).map((i) => i.id),
    recordedAt: nowIso(),
  }
  memoryEntries.push(memory)
  incident.memoryEntryId = memory.id

  addTimeline(incident, { stage: 'CONTAIN', title: 'Containment verified', description: result, actor: 'NETRA' })
  addTimeline(incident, { stage: 'LEARN', title: 'Stored in Cyber Memory', description: memory.lessonsLearned, actor: 'NETRA' })
  return action
}

export const db = {
  events,
  incidents,
  riskAssessments,
  decisions,
  authorizations,
  containmentActions,
  memoryEntries,
  getAssets: deriveAssets,
  getIndicators: deriveIndicators,
  getTechniqueObservations: deriveTechniqueObservations,
  getSystemHealth,
  getTrend,
  getDashboardStats: buildDashboardStats,
  buildIncidentDetail,
  actions: { requestAuthorization, verifyOtp, rejectAuthorization, executeContainment, verifyContainment },
}

