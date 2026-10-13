import type { BackendAssessmentPage, BackendAssessmentSummary, BackendImportBatchPage } from '@/api/types'
import type { Tone } from '@/lib/tones'

/**
 * Status and scope rules for the Live Tracking and Security Workspace landing pages. They only count
 * and classify what the API returned; nothing is estimated. Type-only imports keep this module
 * loadable by `node --test` (tests/workspaceStatus.test.ts).
 */

// --- Health --------------------------------------------------------------------------------------

/** One health request: the parsed body when the API answered (success or error), or no response at all. */
export type HealthOutcome =
  | { responded: true; ok: boolean; status: number; body: unknown }
  | { responded: false }

export type ApiHealthState = 'HEALTHY' | 'ERROR' | 'UNREACHABLE'
export type DatabaseHealthState = 'HEALTHY' | 'DOWN' | 'UNKNOWN'

const field = (body: unknown, key: string): unknown =>
  body && typeof body === 'object' ? (body as Record<string, unknown>)[key] : undefined

/** GET /health: healthy only when it answers 200 with status "healthy". */
export function apiHealthState(api: HealthOutcome): ApiHealthState {
  if (!api.responded) return 'UNREACHABLE'
  return api.ok && field(api.body, 'status') === 'healthy' ? 'HEALTHY' : 'ERROR'
}

/**
 * GET /health/db, judged only by its own response, and only while the API itself is healthy: when the
 * API is down or unreachable the database state is unknown. DOWN needs the endpoint's own "unhealthy"
 * / "unreachable" body (it answers 503 with one); any other failure leaves the state unknown.
 */
export function databaseHealthState(api: HealthOutcome, database: HealthOutcome): DatabaseHealthState {
  if (apiHealthState(api) !== 'HEALTHY' || !database.responded) return 'UNKNOWN'
  if (database.ok && field(database.body, 'status') === 'healthy') return 'HEALTHY'
  if (field(database.body, 'status') === 'unhealthy' || field(database.body, 'database') === 'unreachable') return 'DOWN'
  return 'UNKNOWN'
}

/** The sidebar's one-line system status. */
export interface HealthSummary {
  tone: Tone
  pulse: boolean
  title: string
  detail: string
  tooltip: string
}

/** Shown while no health report has arrived, or when none could be obtained. */
export const HEALTH_PENDING: HealthSummary = {
  tone: 'neutral',
  pulse: false,
  title: 'Status unavailable',
  detail: 'No health report',
  tooltip: 'System health is not available from the current API',
}

/** The one live reading shared by the sidebar and the header, so they cannot contradict each other. */
export type LiveHealthState = 'OPERATIONAL' | 'DATABASE_DOWN' | 'DATABASE_UNKNOWN' | 'API_UNREACHABLE' | 'API_ERROR'

/**
 * Live API: the API and the database are judged separately (see databaseHealthState). The database
 * is called down only when its own health response says so; otherwise it is unknown.
 */
export function liveHealthState(checks: { api: HealthOutcome; database: HealthOutcome }): LiveHealthState {
  const api = apiHealthState(checks.api)
  if (api === 'UNREACHABLE') return 'API_UNREACHABLE'
  if (api === 'ERROR') return 'API_ERROR'
  const database = databaseHealthState(checks.api, checks.database)
  return database === 'HEALTHY' ? 'OPERATIONAL' : database === 'DOWN' ? 'DATABASE_DOWN' : 'DATABASE_UNKNOWN'
}

const LIVE_HEALTH_SUMMARY: Record<LiveHealthState, HealthSummary> = {
  OPERATIONAL: { tone: 'low', pulse: false, title: 'All systems operational', detail: '2/2 components healthy', tooltip: '2 of 2 components healthy' },
  DATABASE_DOWN: { tone: 'medium', pulse: true, title: 'Degraded service', detail: 'Database down · API healthy', tooltip: 'The database health check reported it unreachable' },
  DATABASE_UNKNOWN: { tone: 'neutral', pulse: false, title: 'Database status unknown', detail: 'API healthy', tooltip: 'The database health check gave no usable answer' },
  API_UNREACHABLE: { tone: 'medium', pulse: true, title: 'API unreachable', detail: 'Database status unknown', tooltip: 'API unreachable; the database cannot be checked without it' },
  API_ERROR: { tone: 'medium', pulse: true, title: 'API error', detail: 'Database status unknown', tooltip: 'API error; the database cannot be checked without it' },
}

/** The sidebar's status line for the live API. */
export function liveHealthSummary(checks: { api: HealthOutcome; database: HealthOutcome }): HealthSummary {
  return LIVE_HEALTH_SUMMARY[liveHealthState(checks)]
}

/** The header's compact status chip. */
export interface HealthChip {
  tone: Tone
  pulse: boolean
  label: string
  tooltip: string
}

/** Shown while no health report has arrived, or when none could be obtained (unchanged wording). */
export const HEALTH_CHIP_PENDING: HealthChip = {
  tone: 'neutral',
  pulse: false,
  label: 'Health unavailable',
  tooltip: 'System health is not available from the current API',
}

/** Same reading and tones as the sidebar; "Operational" and "Degraded" keep their previous meaning. */
export function liveHealthChip(checks: { api: HealthOutcome; database: HealthOutcome }): HealthChip {
  const state = liveHealthState(checks)
  const { tone, pulse, tooltip } = LIVE_HEALTH_SUMMARY[state]
  const label = { OPERATIONAL: 'Operational', DATABASE_DOWN: 'Degraded', DATABASE_UNKNOWN: 'Database unknown', API_UNREACHABLE: 'API unreachable', API_ERROR: 'API error' }[state]
  return { tone, pulse, label, tooltip: state === 'OPERATIONAL' ? 'Health reported by the API' : tooltip }
}

/** Demo data: the mock component list, labelled exactly as before. */
export function componentListChip(components: ReadonlyArray<{ status: string }>): HealthChip {
  if (components.length === 0) return HEALTH_CHIP_PENDING
  const healthy = components.every((component) => component.status === 'HEALTHY')
  return {
    tone: healthy ? 'low' : 'medium',
    pulse: !healthy,
    label: `Demo health ${healthy ? 'operational' : 'degraded'}`,
    tooltip: 'Demo health data',
  }
}

/** Demo data: the component list the mock API reports, summarised exactly as before. */
export function componentListSummary(components: ReadonlyArray<{ status: string }>): HealthSummary {
  if (components.length === 0) return HEALTH_PENDING
  const healthy = components.filter((component) => component.status === 'HEALTHY').length
  const allHealthy = healthy === components.length
  return {
    tone: allHealthy ? 'low' : 'medium',
    pulse: !allHealthy,
    title: allHealthy ? 'All systems operational' : 'Degraded service',
    detail: `${healthy}/${components.length} components healthy`,
    tooltip: `${healthy} of ${components.length} components healthy`,
  }
}

// --- Assessments ---------------------------------------------------------------------------------

/** The API's largest page; the newest assessment of each asset is read from it. */
export const ASSESSMENT_PAGE_SIZE = 100
/** Assessment details are requested this many at a time. */
export const DETAIL_CONCURRENCY = 4

/** The newest assessment of each asset; the API lists newest first. */
export function latestAssessmentPerAsset(assessments: readonly BackendAssessmentSummary[]): BackendAssessmentSummary[] {
  const seen = new Set<string>()
  return assessments.filter((assessment) => {
    const asset = assessment.assetId ?? `key:${assessment.assetKey}`
    if (seen.has(asset)) return false
    seen.add(asset)
    return true
  })
}

export interface AssessmentScope {
  /** Newest assessment of each asset in the loaded page. */
  latest: BackendAssessmentSummary[]
  /** Of those, every one with failed or warning checks; all of them have their details read. */
  review: BackendAssessmentSummary[]
  /** Failed plus warning checks across `review`, from the summary counts. */
  checkTotal: number
  /** Assessments the API holds in total, and how many of them are older than the loaded page. */
  total: number
  olderNotLoaded: number
}

/** Summary-only scope: needs no assessment details, so a failed detail request cannot change it. */
export function assessmentScope(page: BackendAssessmentPage): AssessmentScope {
  const latest = latestAssessmentPerAsset(page.items)
  const review = latest.filter((assessment) => assessment.failed > 0 || assessment.warnings > 0)
  return {
    latest,
    review,
    checkTotal: review.reduce((sum, assessment) => sum + assessment.failed + assessment.warnings, 0),
    total: page.total,
    olderNotLoaded: Math.max(0, page.total - page.items.length),
  }
}

/** "12" or, when older assessments are outside the loaded page, "12+". */
export function countWithWindow(count: number, truncated: boolean): string {
  return `${count.toLocaleString('en-US')}${truncated ? '+' : ''}`
}

/**
 * Runs `task` over `items` with at most `limit` in flight and settles every one, so one failure
 * neither stops the rest nor discards their results. Results keep the input order.
 */
export async function settleWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length)
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const index = next++
      try {
        results[index] = { status: 'fulfilled', value: await task(items[index]) }
      } catch (reason) {
        results[index] = { status: 'rejected', reason }
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(Math.max(1, limit), items.length) }, worker))
  return results
}

// --- Datasets ------------------------------------------------------------------------------------

/** The newest imports read for the dataset filter and issue list. */
export const IMPORT_PAGE_SIZE = 25

export interface ImportScope {
  loaded: number
  total: number
  /** The caller's older imports that were not read, so not checked. */
  notChecked: number
}

export function importScope(page: BackendImportBatchPage): ImportScope {
  return { loaded: page.items.length, total: page.total, notChecked: Math.max(0, page.total - page.items.length) }
}

/** "Showing 3 of 7 failed or warning checks", or null when nothing is hidden. */
export function showingOf(shown: number, total: number, noun: string): string | null {
  return total > shown ? `Showing ${shown.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} ${noun}` : null
}

/** "2 more issues", or null when nothing is hidden. */
export function moreLabel(shown: number, total: number, [one, many]: readonly [string, string]): string | null {
  const more = total - shown
  return more > 0 ? `${more.toLocaleString('en-US')} more ${more === 1 ? one : many}` : null
}
