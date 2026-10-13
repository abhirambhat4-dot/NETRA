import type {
  AssessmentFindingResult,
  BackendAssessmentDetail,
  BackendAssessmentSummary,
  BackendImportBatchSummary,
  BackendPrioritizedIncident,
  EventsPageItem,
  ImportEventCoverage,
  IncidentQueueItem,
  Severity,
} from '@/api/types'

/**
 * Landing-page attention items for Live Tracking and Security Workspace.
 *
 * Nothing here scores anything. Incidents keep the order of the backend prioritisation engine
 * (GET /api/incidents/prioritized); assessment findings are ranked only by fields the assessment
 * engine stored (result, severity, deduction, assessment score), across every assessment passed in.
 * Reasons list the factors the API returned and leave missing ones out. Imported dataset rows are never treated as detections.
 * Type-only imports keep this module loadable by `node --test` (tests/attention.test.ts).
 */

/** Detail destinations; must match src/lib/navigation.ts (asserted by tests). */
export const ATTENTION_LINKS = {
  incident: (id: string) => `/incidents/${encodeURIComponent(id)}`,
  event: (id: string) => `/events?event=${encodeURIComponent(id)}`,
  assessment: (id: string) => `/assessments?assessment=${encodeURIComponent(id)}`,
  importBatch: (id: string) => `/imports?batch=${encodeURIComponent(id)}`,
} as const

/** Landing pages show at most this many items in a list. */
export const ATTENTION_LIMIT = 3

export type AttentionKind = 'incident' | 'event' | 'activity' | 'assessment' | 'dataset'

export interface AttentionItem {
  key: string
  kind: AttentionKind
  title: string
  /** Where the item comes from, e.g. "INC-0042" or "Assessment · web-01". */
  source: string
  /** Evidence severity when the API returned one; dataset issues never carry one. */
  severity: Severity | null
  /** Only factors the API returned, joined with " · ". */
  reason: string
  /** Longer explanation from the API, when it gave one. */
  detail?: string
  to: string
  at: string | null
}

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const RESULT_RANK: Partial<Record<AssessmentFindingResult, number>> = { FAIL: 0, WARN: 1 }

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`
const joinReason = (parts: Array<string | null | undefined | false>) => parts.filter(Boolean).join(' · ')

// --- Live Tracking -------------------------------------------------------------------------------

/**
 * Active incidents in the backend's priority order, joined to the incident list for titles.
 * Prioritized entries the list did not return (e.g. an unsupported state) are skipped, not guessed.
 */
export function incidentAttention(prioritized: readonly BackendPrioritizedIncident[], incidents: readonly IncidentQueueItem[]): AttentionItem[] {
  const byId = new Map(incidents.map((incident) => [incident.id, incident]))
  return [...prioritized]
    .sort((left, right) => left.priorityRank - right.priorityRank)
    .flatMap((entry) => {
      const incident = byId.get(entry.incidentId)
      if (!incident) return []
      const confidence = incident.latestDecision?.confidence
      return [{
        key: `incident-${entry.incidentId}`,
        kind: 'incident' as const,
        title: incident.title,
        source: incident.key,
        severity: entry.severity,
        reason: joinReason([
          entry.riskScore === null ? 'Risk not calculated' : `Risk ${Math.round(entry.riskScore)}`,
          entry.assetCriticality && `${entry.assetCriticality} asset`,
          entry.eventCount > 0 && plural(entry.eventCount, 'event'),
          typeof confidence === 'number' && Number.isFinite(confidence) && `decision confidence ${Math.round(confidence * 100)}%`,
        ]),
        detail: entry.priorityReason,
        to: ATTENTION_LINKS.incident(entry.incidentId),
        at: entry.updatedAt,
      }]
    })
}

// --- Demo records --------------------------------------------------------------------------------

/**
 * Markers written by the NETRA demo seed (backend app/db/seed_demo.py) on every record it creates:
 * incident keys INC-DEMO-*, titles "[NETRA DEMO] ...", event UIDs netra-demo-*, signatures
 * "NETRA DEMO ..." and assets on *.netra-demo.example. Only these explicit markers count; nothing
 * is guessed from addresses or wording, so genuine records are never hidden.
 */
const DEMO_HOST_SUFFIX = '.netra-demo.example'
export const isDemoAsset = (asset: { hostname: string | null } | null | undefined) => Boolean(asset?.hostname?.toLowerCase().endsWith(DEMO_HOST_SUFFIX))

export function isDemoIncident(incident: Pick<IncidentQueueItem, 'key' | 'title' | 'asset'>): boolean {
  return incident.key.startsWith('INC-DEMO-') || incident.title.startsWith('[NETRA DEMO]') || isDemoAsset(incident.asset)
}

export function isDemoEvent(event: Pick<EventsPageItem, 'eventUid' | 'signature' | 'asset'>): boolean {
  return Boolean(event.eventUid?.startsWith('netra-demo-')) || Boolean(event.signature?.startsWith('NETRA DEMO')) || isDemoAsset(event.asset)
}

/** "Demo records excluded: 2 incidents, 1 event", or null when nothing was excluded. */
export function demoExclusionNote(demoIncidents: number, demoEvents: number): string | null {
  const parts = [demoIncidents > 0 && plural(demoIncidents, 'incident'), demoEvents > 0 && plural(demoEvents, 'event')].filter(Boolean)
  return parts.length ? `Demo records excluded: ${parts.join(', ')} from the NETRA demo dataset` : null
}

/**
 * Shown while the collector is idle (no event in the last 5 minutes). The collector only receives
 * events submitted to it, so an idle collector means no live activity, not quiet monitoring.
 */
export function collectorIdleNote(totalCollectorEvents: number): string {
  return totalCollectorEvents === 0
    ? 'The collector is idle: no live events have been received yet. NETRA is not monitoring a network feed; events appear here only when they are submitted to the Live Event Collector.'
    : 'The collector is idle: no live events have been received in the last 5 minutes.'
}

/** True for events stored from a dataset upload; their labels are ground truth, not detections. */
export function isImportedEvent(event: Pick<EventsPageItem, 'detectionSource' | 'importBatchId'>): boolean {
  return Boolean(event.importBatchId) || event.detectionSource === 'DATASET_IMPORT'
}

/** HIGH/CRITICAL events no incident covers yet, most severe then newest. Imported rows are excluded. */
export function unlinkedEventAttention(events: readonly EventsPageItem[]): AttentionItem[] {
  return events
    .filter((event) => !isImportedEvent(event) && event.incidentIds.length === 0)
    .filter((event) => event.severity === 'CRITICAL' || event.severity === 'HIGH')
    .sort((left, right) => SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] || Date.parse(right.timestamp) - Date.parse(left.timestamp))
    .map((event) => ({
      key: `event-${event.id}`,
      kind: 'event' as const,
      title: event.signature || event.eventType,
      source: event.asset?.name ?? 'No asset linked',
      severity: event.severity,
      reason: joinReason(['Not linked to an incident', event.asset?.criticality && `${event.asset.criticality} asset`]),
      to: ATTENTION_LINKS.event(event.id),
      at: event.timestamp,
    }))
}

/**
 * Latest events received by the Live Event Collector, newest first. Imported dataset rows and demo seed
 * records are left out; each row says whether an incident already covers the event.
 */
export function collectorActivityAttention(events: readonly EventsPageItem[], limit = ATTENTION_LIMIT): AttentionItem[] {
  return events
    .filter((event) => !isImportedEvent(event) && !isDemoEvent(event))
    .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
    .slice(0, limit)
    .map((event) => ({
      key: `activity-${event.id}`,
      kind: 'activity' as const,
      title: event.signature || event.eventType,
      source: event.asset?.name ?? 'No asset linked',
      severity: event.severity,
      reason: event.incidentIds.length > 0 ? `Linked to ${plural(event.incidentIds.length, 'incident')}` : 'Not linked to an incident',
      to: ATTENTION_LINKS.event(event.id),
      at: event.timestamp,
    }))
}

/** Count per severity, every severity present (0 when none); only the severities given are counted. */
export function severityMix(entries: ReadonlyArray<{ severity: Severity }>): Record<Severity, number> {
  const mix: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const entry of entries) mix[entry.severity] += 1
  return mix
}

/** Prioritised incidents first (the engine's order), then unlinked high-severity events. */
export function liveAttention(incidents: readonly AttentionItem[], events: readonly AttentionItem[], limit = ATTENTION_LIMIT): AttentionItem[] {
  return [...incidents, ...events].slice(0, limit)
}

/**
 * Active incidents the prioritisation engine ranked but this view could not show: their lifecycle state
 * is not one the client supports, or they left the active list between the two requests.
 */
export function hiddenIncidentCount(activeIncidents: number, shownIncidents: number): number {
  return Math.max(0, activeIncidents - shownIncidents)
}

/** Empty "Needs attention" list: only claims there are no active incidents when the engine ranked none. */
export function liveEmptyState(activeIncidents: number): { title: string; description: string } {
  if (activeIncidents === 0) {
    return { title: 'Nothing needs attention right now.', description: 'There are no active incidents and no unlinked high or critical events.' }
  }
  return {
    title: `${plural(activeIncidents, 'active incident')} could not be shown.`,
    description: 'NETRA reports active incidents, but their lifecycle state is not supported by this view or changed while loading. There are no unlinked high or critical events.',
  }
}

/** Footer note when some ranked incidents are not in the list above; null when all are shown. */
export function hiddenIncidentsNote(activeIncidents: number, shownIncidents: number): string | null {
  const hidden = hiddenIncidentCount(activeIncidents, shownIncidents)
  return hidden > 0 ? `${plural(hidden, 'incident')} not shown (unsupported or changed state)` : null
}

// --- Security Workspace: assessments -------------------------------------------------------------

const assetLabel = (assessment: Pick<BackendAssessmentSummary, 'asset' | 'assetKey'>) => assessment.asset?.name ?? assessment.assetKey

/** FAIL then WARN findings, by stored severity, then the engine's deduction, then the assessment's score. */
export function assessmentFindingAttention(details: readonly BackendAssessmentDetail[]): AttentionItem[] {
  const rows = details.flatMap((assessment) =>
    assessment.findings
      .filter((finding) => RESULT_RANK[finding.result] !== undefined)
      .map((finding) => ({ assessment, finding })),
  )
  rows.sort(
    (left, right) =>
      RESULT_RANK[left.finding.result]! - RESULT_RANK[right.finding.result]! ||
      (left.finding.severity ? SEVERITY_RANK[left.finding.severity] : 5) - (right.finding.severity ? SEVERITY_RANK[right.finding.severity] : 5) ||
      right.finding.deduction - left.finding.deduction ||
      left.assessment.score - right.assessment.score ||
      left.finding.position - right.finding.position,
  )
  return rows.map(({ assessment, finding }) => ({
    key: `finding-${finding.id}`,
    kind: 'assessment' as const,
    title: finding.title,
    source: `Assessment · ${assetLabel(assessment)}`,
    severity: finding.severity,
    reason: joinReason([
      finding.result === 'FAIL' ? 'Failed check' : 'Warning',
      finding.deduction > 0 && `−${finding.deduction} points`,
      assessment.asset?.criticality && `${assessment.asset.criticality} asset`,
      `grade ${assessment.grade}`,
    ]),
    detail: finding.recommendation ?? undefined,
    to: ATTENTION_LINKS.assessment(assessment.id),
    at: assessment.asOf,
  }))
}

// --- Security Workspace: datasets ----------------------------------------------------------------

/**
 * Import-quality issues of one or more batches: rejected uploads, rejected rows and, when the batch
 * detail was loaded, events that cannot be linked to an asset. These are data-quality findings about
 * the upload, not threats, so they carry no severity.
 */
export function datasetIssueAttention(
  batches: readonly BackendImportBatchSummary[],
  coverage: Readonly<Record<string, ImportEventCoverage | null | undefined>> = {},
): AttentionItem[] {
  const items: Array<AttentionItem & { rank: number; count: number }> = []
  for (const batch of batches) {
    const base = { kind: 'dataset' as const, source: `Dataset · ${batch.originalFilename}`, severity: null, to: ATTENTION_LINKS.importBatch(batch.id), at: batch.completedAt ?? batch.createdAt }
    if (batch.status === 'REJECTED') {
      items.push({ ...base, key: `batch-rejected-${batch.id}`, title: 'Import rejected', reason: joinReason([plural(batch.errorTotal, 'validation issue'), 'no rows stored']), rank: 0, count: batch.errorTotal })
    } else if (batch.rejectedRows > 0) {
      items.push({ ...base, key: `batch-rows-${batch.id}`, title: `${plural(batch.rejectedRows, 'row')} rejected`, reason: joinReason([`${batch.acceptedRows.toLocaleString('en-US')} of ${plural(batch.totalRows, 'row')} accepted`]), rank: 1, count: batch.rejectedRows })
    }
    const gaps = coverage[batch.id]
    const unlinked = gaps ? gaps.addressWithoutAsset + gaps.withoutAddress : 0
    if (gaps && unlinked > 0) {
      items.push({
        ...base,
        key: `batch-coverage-${batch.id}`,
        title: `${plural(unlinked, 'event')} not linked to an asset`,
        reason: joinReason([
          gaps.addressWithoutAsset > 0 && `${gaps.addressWithoutAsset.toLocaleString('en-US')} with an unregistered address`,
          gaps.withoutAddress > 0 && `${gaps.withoutAddress.toLocaleString('en-US')} without an address`,
          'assessments cannot use them',
        ]),
        rank: 2,
        count: unlinked,
      })
    }
  }
  return items
    .sort((left, right) => left.rank - right.rank || right.count - left.count || Date.parse(right.at ?? '') - Date.parse(left.at ?? ''))
    .map(({ rank: _rank, count: _count, ...item }) => item)
}
