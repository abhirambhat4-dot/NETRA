import type {
  AssetInventoryItem,
  BackendImportBatchSummary,
  CyberMemoryEntry,
  IncidentQueueItem,
  ThreatIndicatorInventoryItem,
} from '@/api/types'

/**
 * Security Workspace capability summaries. Each one only counts fields the API returned; nothing is
 * scored, inferred or filled in. Type-only imports keep this module loadable by `node --test`
 * (tests/workspaceSummary.test.ts).
 */

// --- 1. Security Data Ingestion -------------------------------------------------------------------

export interface IngestionSummary {
  batches: number
  validated: number
  rejected: number
  totalRows: number
  acceptedRows: number
  rejectedRows: number
  duplicateRows: number
  eventsCreated: number
}

/** Totals over the import batches passed in (the page loaded, not necessarily every import). */
export function ingestionSummary(batches: readonly BackendImportBatchSummary[]): IngestionSummary {
  const summary: IngestionSummary = { batches: batches.length, validated: 0, rejected: 0, totalRows: 0, acceptedRows: 0, rejectedRows: 0, duplicateRows: 0, eventsCreated: 0 }
  for (const batch of batches) {
    if (batch.status === 'VALIDATED') summary.validated += 1
    else summary.rejected += 1
    summary.totalRows += batch.totalRows
    summary.acceptedRows += batch.acceptedRows
    summary.rejectedRows += batch.rejectedRows
    summary.duplicateRows += batch.duplicateRows
    summary.eventsCreated += batch.eventsCreated
  }
  return summary
}

// --- 2. Detection & Evidence Correlation ----------------------------------------------------------

export interface DetectionSummary {
  incidents: number
  /** Incidents with at least one correlated security event. */
  withEvidence: number
  /** Incidents per detection source, most first; ties by name. */
  bySource: Array<{ source: IncidentQueueItem['detectionSource']; count: number }>
}

export function detectionSummary(incidents: readonly IncidentQueueItem[]): DetectionSummary {
  const sources = new Map<IncidentQueueItem['detectionSource'], number>()
  for (const incident of incidents) sources.set(incident.detectionSource, (sources.get(incident.detectionSource) ?? 0) + 1)
  return {
    incidents: incidents.length,
    withEvidence: incidents.filter((incident) => incident.eventCount > 0).length,
    bySource: [...sources].map(([source, count]) => ({ source, count })).sort((l, r) => r.count - l.count || l.source.localeCompare(r.source)),
  }
}

// --- 3. Explainable Risk Assessment / 4. Decision & Controlled Response ---------------------------

export interface ResponseSummary {
  /** Incidents the risk engine has scored. */
  scored: number
  /** Incidents with a recorded decision recommendation. */
  decisions: number
  /** Incidents per lifecycle stage, as stored; no stage is inferred. */
  stages: Record<'VERIFIED' | 'AUTHORIZED' | 'CONTAINED' | 'LEARNED', number>
}

export function responseSummary(incidents: readonly IncidentQueueItem[]): ResponseSummary {
  const stages: ResponseSummary['stages'] = { VERIFIED: 0, AUTHORIZED: 0, CONTAINED: 0, LEARNED: 0 }
  for (const incident of incidents) {
    if (incident.lifecycle in stages) stages[incident.lifecycle as keyof typeof stages] += 1
  }
  return {
    scored: incidents.filter((incident) => incident.riskScore !== null).length,
    decisions: incidents.filter((incident) => incident.latestDecision !== null).length,
    stages,
  }
}

// --- 5. Cyber Memory ------------------------------------------------------------------------------

export interface MemorySummary {
  entries: number
  effective: number
  /** Entries newest first. */
  latest: CyberMemoryEntry[]
  /** Entries left out because they belong to an explicitly marked demo incident. */
  demo: number
}

/** How a memory's effectiveness is shown. UNKNOWN is stated as such: NETRA's containment is simulated, and a
 * successful simulation is not evidence of real-world effect. */
export function effectivenessLabel(value: string): string {
  return value === 'UNKNOWN' ? 'effectiveness unknown' : value.replaceAll('_', ' ').toLowerCase()
}

/** Entries of demo incidents (by id, from the explicit demo markers) are counted separately, not shown. */
export function memorySummary(entries: readonly CyberMemoryEntry[], demoIncidentIds: ReadonlySet<string> = new Set()): MemorySummary {
  const genuine = entries.filter((entry) => !(entry.incidentId && demoIncidentIds.has(entry.incidentId)))
  return {
    entries: genuine.length,
    effective: genuine.filter((entry) => entry.effectiveness === 'EFFECTIVE').length,
    latest: [...genuine].sort((l, r) => Date.parse(r.recordedAt) - Date.parse(l.recordedAt)),
    demo: entries.length - genuine.length,
  }
}

// --- 6. Security Assessment inventory -------------------------------------------------------------

export interface InventorySummary {
  assets: number
  /** Sum of the vulnerability counts the API returned; assets without a count are listed separately. */
  vulnerabilities: number
  assetsWithoutVulnerabilityCount: number
  indicators: number
  /** Only indicators the API explicitly marks active. */
  activeIndicators: number
}

export function inventorySummary(assets: readonly AssetInventoryItem[], indicators: readonly ThreatIndicatorInventoryItem[]): InventorySummary {
  return {
    assets: assets.length,
    vulnerabilities: assets.reduce((sum, asset) => sum + (asset.vulnerabilityCount ?? 0), 0),
    assetsWithoutVulnerabilityCount: assets.filter((asset) => asset.vulnerabilityCount === null).length,
    indicators: indicators.length,
    activeIndicators: indicators.filter((indicator) => indicator.isActive === true).length,
  }
}
