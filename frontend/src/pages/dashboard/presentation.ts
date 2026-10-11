/**
 * Command Center display rules. Pure and import-free so tests/commandCenterPresentation.test.ts can
 * load them with `node --test`. They only format values the API returned; nothing is estimated.
 */

export const NOT_SCORED = 'Not scored'

export const DEMO_NOTICE = 'Demo data — illustrative only'

/** An incident's own risk score. Never substitute a dashboard-wide figure for a missing score. */
export function incidentRiskLabel(riskScore: number | null | undefined): string {
  return typeof riskScore === 'number' && Number.isFinite(riskScore) ? String(Math.round(riskScore)) : NOT_SCORED
}

/** Readable incident key when present, otherwise a shortened record id. */
export function incidentIdentity(incident: { key?: string | null; id: string }): string {
  const key = incident.key?.trim()
  if (key) return key
  return incident.id.length > 8 ? `Incident ${incident.id.slice(0, 8)}` : `Incident ${incident.id}`
}

/** `criticalEvents` / `highEvents` from /dashboard/stats count every stored event, not the last 24h. */
export function allTimeEventSeverityHint(critical: number | null | undefined, high: number | null | undefined): string {
  return `All-time: Critical ${critical ?? 0} / High ${high ?? 0}`
}

/** The "pts / 100" scale only makes sense when there are drivers to measure against it. */
export function showRiskDriverScale(drivers: readonly unknown[] | null | undefined): boolean {
  return Array.isArray(drivers) && drivers.length > 0
}

/** `PRIORITISED` → `Prioritised`, `IN_PROGRESS` → `In progress`. Shows the state as returned, not a mapped one. */
export function formatLifecycleState(state: string): string {
  const words = state.trim().replace(/_/g, ' ').toLowerCase()
  return words ? words[0].toUpperCase() + words.slice(1) : 'Unknown'
}

export function unsupportedIncidentsNotice(count: number): string | null {
  if (count <= 0) return null
  return count === 1
    ? 'One incident has a lifecycle state this version of NETRA does not recognise, so it is not shown.'
    : `${count} incidents have a lifecycle state this version of NETRA does not recognise, so they are not shown.`
}
