// Dependency-free so it runs under `node --test` (tests/observedTechniques.test.ts).
//
// GET /api/threat-intelligence/techniques/observed: ATT&CK technique IDs that detection sources explicitly reported
// (source-supplied evidence only; never inferred). No ATT&CK catalogue is bundled, so names, tactics and URLs are
// unknown and are never invented here.

/** backend/app/schemas/attack.py TechniqueCatalogueEntry */
export interface BackendTechniqueCatalogueEntry {
  status: 'known' | 'deprecated' | 'revoked' | 'unknown'
  name: string | null
  tactics: string[]
  url: string | null
}

/** backend/app/schemas/attack.py ObservedTechniqueResponse */
export interface BackendObservedTechnique {
  techniqueId: string
  evidenceKind: 'source_supplied'
  eventCount: number
  incidentCount: number
  activeIncidentCount: number
  /** Up to 100, ordered by id; incidentCount is the full count. */
  incidentIds: string[]
  highestSeverity: string
  firstSeen: string
  lastSeen: string
  sources: Record<string, number>
  origins: Record<string, number>
  catalogue: BackendTechniqueCatalogueEntry
}

/** backend/app/schemas/attack.py ObservedTechniquePage */
export interface BackendObservedTechniquePage {
  items: BackendObservedTechnique[]
  total: number
  page: number
  pageSize: number
  asOf: string
  windowDays: number
  catalogue: { name: string; version: string; attribution: string } | null
}

export const OBSERVED_SOURCES = ['SURICATA', 'ML_ANOMALY', 'THREAT_INTEL', 'VULNERABILITY_SCAN', 'MANUAL', 'DATASET_IMPORT'] as const
export type ObservedSource = (typeof OBSERVED_SOURCES)[number]
export const OBSERVED_ORIGINS = ['ingest_field', 'collector_field'] as const
export type ObservedOrigin = (typeof OBSERVED_ORIGINS)[number]
export type ObservedSortBy = 'eventCount' | 'lastSeen' | 'techniqueId'
export type ObservedSortOrder = 'asc' | 'desc'
export const OBSERVED_WINDOWS = [1, 7, 30, 90] as const

export interface ObservedTechniqueFilters {
  days: number
  source: ObservedSource | 'ALL'
  origin: ObservedOrigin | 'ALL'
  /** As typed; applied only once it is a valid ID (see techniqueFilter). */
  techniqueId: string
  page: number
  pageSize: number
  sortBy: ObservedSortBy
  sortOrder: ObservedSortOrder
}

export const DEFAULT_OBSERVED_FILTERS: ObservedTechniqueFilters = {
  days: 7,
  source: 'ALL',
  origin: 'ALL',
  techniqueId: '',
  page: 1,
  pageSize: 25,
  sortBy: 'eventCount',
  sortOrder: 'desc',
}

export const ORIGIN_LABELS: Record<ObservedOrigin, string> = {
  ingest_field: 'Event ingest API',
  collector_field: 'Live collector',
}

// The backend's rule (app/models/attack_technique.py): trimmed, upper-cased, T1234 or T1234.567, ASCII digits.
const TECHNIQUE_ID = /^T[0-9]{4}(\.[0-9]{3})?$/

/** The technique filter to send: the normalised ID, `null` when empty, or `'invalid'` (nothing is sent). */
export function techniqueFilter(value: string): string | null | 'invalid' {
  const normalized = value.trim().toUpperCase()
  if (!normalized) return null
  return TECHNIQUE_ID.test(normalized) ? normalized : 'invalid'
}

/** Query parameters for the API; filters left at "all" or empty are omitted. */
export function observedTechniqueParams(filters: ObservedTechniqueFilters): Record<string, string | number> {
  const technique = techniqueFilter(filters.techniqueId)
  return {
    days: filters.days,
    ...(filters.source !== 'ALL' && { source: filters.source }),
    ...(filters.origin !== 'ALL' && { origin: filters.origin }),
    ...(technique && technique !== 'invalid' && { techniqueId: technique }),
    page: filters.page,
    pageSize: filters.pageSize,
    sortBy: filters.sortBy,
    sortOrder: filters.sortOrder,
  }
}

/** A query key that changes with every parameter sent, so a superseded request can never overwrite a newer one. */
export function observedTechniquesKey(filters: ObservedTechniqueFilters): string {
  return `observed-techniques:${new URLSearchParams(Object.entries(observedTechniqueParams(filters)).map(([k, v]) => [k, String(v)])).toString()}`
}

/** Apply a filter change; any change other than the page itself returns to page 1. */
export function updateObservedFilters(current: ObservedTechniqueFilters, change: Partial<ObservedTechniqueFilters>): ObservedTechniqueFilters {
  const next = { ...current, ...change }
  return 'page' in change ? next : { ...next, page: 1 }
}

/** "SURICATA 2 · MANUAL 1": a breakdown, largest first, ties by name. */
export function breakdown(counts: Record<string, number>, labels: Record<string, string> = {}): string {
  return Object.entries(counts)
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
    .map(([key, count]) => `${labels[key] ?? key} ${count}`)
    .join(' · ')
}

/** The technique's catalogue name only when a catalogue knows it; otherwise null (never invented). */
export function catalogueName(entry: BackendTechniqueCatalogueEntry): string | null {
  return entry.status !== 'unknown' && entry.name ? entry.name : null
}

export interface ObservedErrorView {
  title: string
  message?: string
  retry: boolean
  signIn: boolean
}

/** How to present a failed request, following the Threat Intelligence page's conventions. */
export function observedErrorView(status: number | null, message: string): ObservedErrorView {
  if (status === 401) return { title: 'Authentication required', retry: false, signIn: true }
  if (status === 422) return { title: 'Invalid filter', message, retry: false, signIn: false }
  if (status !== null && status >= 500) {
    return {
      title: 'Observed techniques unavailable',
      message: 'The server could not return technique observations. If the backend has not yet been upgraded to migration 0007, this data is not available yet.',
      retry: true,
      signIn: false,
    }
  }
  return { title: 'Observed techniques unavailable', message, retry: true, signIn: false }
}
