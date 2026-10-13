import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import type { BackendAssessmentDetail, BackendAssessmentFinding, BackendAssessmentSummary, BackendImportBatchSummary } from '../src/api/types.ts'
import { assessmentFindingAttention } from '../src/lib/attention.ts'
import {
  ASSESSMENT_PAGE_SIZE,
  DETAIL_CONCURRENCY,
  HEALTH_CHIP_PENDING,
  HEALTH_PENDING,
  IMPORT_PAGE_SIZE,
  apiHealthState,
  assessmentScope,
  componentListChip,
  componentListSummary,
  countWithWindow,
  databaseHealthState,
  importScope,
  latestAssessmentPerAsset,
  liveHealthChip,
  liveHealthState,
  liveHealthSummary,
  moreLabel,
  settleWithConcurrency,
  showingOf,
  type HealthOutcome,
} from '../src/lib/workspaceStatus.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

const summary = (id: string, assetId: string, overrides: Partial<BackendAssessmentSummary> = {}): BackendAssessmentSummary => ({
  id,
  assetId,
  assetKey: `KEY-${assetId}`,
  asset: null,
  methodologyVersion: 'assessment-v2',
  asOf: '2026-10-12T10:00:00Z',
  score: 80,
  grade: 'B',
  summary: '',
  passed: 5,
  warnings: 0,
  failed: 0,
  informational: 0,
  requestedBy: 'operator',
  createdAt: '2026-10-12T10:00:00Z',
  ...overrides,
})

const finding = (id: string, overrides: Partial<BackendAssessmentFinding> = {}): BackendAssessmentFinding => ({
  id,
  position: 1,
  checkKey: id,
  category: 'exposure',
  title: id,
  result: 'FAIL',
  severity: 'MEDIUM',
  deduction: 10,
  evidence: [],
  recommendation: null,
  vulnerabilityIds: [],
  incidentIds: [],
  eventIds: [],
  vulnerabilityTotal: 0,
  incidentTotal: 0,
  eventTotal: 0,
  ...overrides,
})

const page = <T>(items: T[], total = items.length) => ({ items, total, page: 1, pageSize: 100 })

// --- health --------------------------------------------------------------------------------------

const ok = (body: unknown): HealthOutcome => ({ responded: true, ok: true, status: 200, body })
const failed = (status: number, body: unknown = null): HealthOutcome => ({ responded: true, ok: false, status, body })
const noResponse: HealthOutcome = { responded: false }
const API_OK = ok({ status: 'healthy', service: 'NETRA API', version: '1.0.0' })
const DB_OK = ok({ status: 'healthy', service: 'NETRA API', version: '1.0.0', database: 'connected' })
const DB_DOWN = failed(503, { status: 'unhealthy', service: 'NETRA API', version: '1.0.0', database: 'unreachable' })

test('API health is healthy, an error, or unreachable', () => {
  assert.equal(apiHealthState(API_OK), 'HEALTHY')
  assert.equal(apiHealthState(failed(500)), 'ERROR')
  assert.equal(apiHealthState(ok({ status: 'starting' })), 'ERROR')
  assert.equal(apiHealthState(noResponse), 'UNREACHABLE')
})

test('the database is unknown whenever the API health check fails, whatever its own check said', () => {
  for (const api of [noResponse, failed(500), failed(503)]) {
    for (const database of [DB_OK, DB_DOWN, noResponse]) assert.equal(databaseHealthState(api, database), 'UNKNOWN')
  }
})

test('the database is down only when its own health response says so', () => {
  assert.equal(databaseHealthState(API_OK, DB_OK), 'HEALTHY')
  assert.equal(databaseHealthState(API_OK, DB_DOWN), 'DOWN')
  // A 503 (or any failure) without the endpoint's own unhealthy body proves nothing about the database.
  assert.equal(databaseHealthState(API_OK, failed(503)), 'UNKNOWN')
  assert.equal(databaseHealthState(API_OK, failed(502, { detail: 'Bad gateway' })), 'UNKNOWN')
  assert.equal(databaseHealthState(API_OK, noResponse), 'UNKNOWN')
})

test('the HTTP client keeps the error body so the database state can be read from it', () => {
  const http = source('../src/services/http.ts')
  assert.match(http, /readonly body: unknown/)
  assert.match(http, /throw new HttpError\(errorMessage\(err\?\.detail\) \?\? `Request failed \(\$\{res\.status\}\)`, res\.status, err\)/)
})

test('sidebar: the database is down only when its own health response says so', () => {
  const summary = (api: HealthOutcome, database: HealthOutcome) => {
    const s = liveHealthSummary({ api, database })
    return [s.title, s.detail, s.tone]
  }
  assert.deepEqual(summary(API_OK, DB_OK), ['All systems operational', '2/2 components healthy', 'low'])
  assert.deepEqual(summary(API_OK, DB_DOWN), ['Degraded service', 'Database down · API healthy', 'medium'])
  // A failed database check that does not confirm the database is down is unknown, not down.
  assert.deepEqual(summary(API_OK, failed(503)), ['Database status unknown', 'API healthy', 'neutral'])
  assert.deepEqual(summary(API_OK, failed(502, { detail: 'Bad gateway' })), ['Database status unknown', 'API healthy', 'neutral'])
  assert.deepEqual(summary(API_OK, noResponse), ['Database status unknown', 'API healthy', 'neutral'])
})

test('sidebar: when the API is unavailable the database is unknown, whatever its own check said', () => {
  for (const database of [DB_OK, DB_DOWN, noResponse]) {
    const unreachable = liveHealthSummary({ api: noResponse, database })
    assert.deepEqual([unreachable.title, unreachable.detail], ['API unreachable', 'Database status unknown'])
    const error = liveHealthSummary({ api: failed(500), database })
    assert.deepEqual([error.title, error.detail], ['API error', 'Database status unknown'])
  }
})

test('sidebar: demo data and the pending state keep their previous wording', () => {
  assert.deepEqual(HEALTH_PENDING, {
    tone: 'neutral',
    pulse: false,
    title: 'Status unavailable',
    detail: 'No health report',
    tooltip: 'System health is not available from the current API',
  })
  assert.deepEqual(componentListSummary([]), HEALTH_PENDING)
  assert.deepEqual(componentListSummary([{ status: 'HEALTHY' }, { status: 'HEALTHY' }]), {
    tone: 'low', pulse: false, title: 'All systems operational', detail: '2/2 components healthy', tooltip: '2 of 2 components healthy',
  })
  assert.deepEqual(componentListSummary([{ status: 'HEALTHY' }, { status: 'DEGRADED' }, { status: 'DOWN' }]), {
    tone: 'medium', pulse: true, title: 'Degraded service', detail: '1/3 components healthy', tooltip: '1 of 3 components healthy',
  })
})

test('header, sidebar and Live Tracking share one polled health reading (live checks, or the mock list in demo mode)', () => {
  const hook = source('../src/hooks/useHealthPoll.ts')
  assert.match(hook, /USE_MOCKS\s+\? \{ mode: 'demo', components: await dashboardService\.getSystemHealth\(\) \}\s+: \{ mode: 'live', checks: await dashboardService\.getHealthChecks\(\) \}/)
  assert.match(source('../src/layouts/Header.tsx'), /healthReading\.mode === 'demo' \? componentListChip\(healthReading\.components\) : liveHealthChip\(healthReading\.checks\)/)
  assert.match(source('../src/layouts/Sidebar.tsx'), /healthReading\.mode === 'demo' \? componentListSummary\(healthReading\.components\) : liveHealthSummary\(healthReading\.checks\)/)
  assert.match(source('../src/pages/LiveTrackingPage.tsx'), /healthReading\?\.mode === 'live' \? healthReading\.checks : undefined/)
  for (const path of ['../src/layouts/Header.tsx', '../src/layouts/Sidebar.tsx', '../src/pages/LiveTrackingPage.tsx']) {
    assert.doesNotMatch(source(path), /getHealthChecks|getSystemHealth/, `${path} should read the shared poll, not request health itself`)
  }
})

const HEALTH_CASES: Array<[string, HealthOutcome, HealthOutcome, string]> = [
  ['healthy', API_OK, DB_OK, 'OPERATIONAL'],
  ['database confirmed down', API_OK, DB_DOWN, 'DATABASE_DOWN'],
  ['database check inconclusive (503 without the endpoint body)', API_OK, failed(503), 'DATABASE_UNKNOWN'],
  ['database check unanswered', API_OK, noResponse, 'DATABASE_UNKNOWN'],
  ['API unreachable', noResponse, DB_DOWN, 'API_UNREACHABLE'],
  ['API error', failed(500), DB_OK, 'API_ERROR'],
]

test('header chip: same reading as the sidebar, with the previous labels where they still apply', () => {
  const chips = Object.fromEntries(HEALTH_CASES.map(([name, api, database]) => {
    const chip = liveHealthChip({ api, database })
    return [name, [chip.label, chip.tone, chip.pulse]]
  }))
  assert.deepEqual(chips, {
    healthy: ['Operational', 'low', false],
    'database confirmed down': ['Degraded', 'medium', true],
    'database check inconclusive (503 without the endpoint body)': ['Database unknown', 'neutral', false],
    'database check unanswered': ['Database unknown', 'neutral', false],
    'API unreachable': ['API unreachable', 'medium', true],
    'API error': ['API error', 'medium', true],
  })
  assert.equal(liveHealthChip({ api: API_OK, database: DB_OK }).tooltip, 'Health reported by the API')
})

test('header, sidebar and Live Tracking never contradict each other', () => {
  for (const [name, api, database, state] of HEALTH_CASES) {
    assert.equal(liveHealthState({ api, database }), state, name)
    const chip = liveHealthChip({ api, database })
    const sidebar = liveHealthSummary({ api, database })
    assert.deepEqual([chip.tone, chip.pulse], [sidebar.tone, sidebar.pulse], name)
    // Live Tracking's status line reads the same two classifiers.
    const db = databaseHealthState(api, database)
    assert.equal(db === 'DOWN', state === 'DATABASE_DOWN', name)
    assert.equal(db === 'HEALTHY', state === 'OPERATIONAL', name)
    assert.equal(apiHealthState(api) === 'HEALTHY', !state.startsWith('API_'), name)
  }
})

test('header chip: demo data and the pending state keep their previous wording', () => {
  assert.deepEqual(HEALTH_CHIP_PENDING, { tone: 'neutral', pulse: false, label: 'Health unavailable', tooltip: 'System health is not available from the current API' })
  assert.deepEqual(componentListChip([]), HEALTH_CHIP_PENDING)
  assert.deepEqual(componentListChip([{ status: 'HEALTHY' }, { status: 'HEALTHY' }]), { tone: 'low', pulse: false, label: 'Demo health operational', tooltip: 'Demo health data' })
  assert.deepEqual(componentListChip([{ status: 'HEALTHY' }, { status: 'DEGRADED' }]), { tone: 'medium', pulse: true, label: 'Demo health degraded', tooltip: 'Demo health data' })
})

// --- assessments ---------------------------------------------------------------------------------

test('a critical finding on a well-scored asset is not hidden by lower-scoring assets', () => {
  // Ten low-scoring assets with MEDIUM failures, and one high-scoring asset with a CRITICAL failure.
  const list = [
    ...Array.from({ length: 10 }, (_, i) => summary(`low${i}`, `low${i}`, { score: 30 + i, failed: 3 })),
    summary('good', 'good', { score: 85, failed: 1 }),
  ]
  const scope = assessmentScope(page(list))
  assert.equal(scope.review.length, 11, 'every assessment needing review has its details read')
  const details: BackendAssessmentDetail[] = scope.review.map((assessment) => ({
    ...assessment,
    missingEvidence: [],
    inputCounts: {},
    findings: assessment.id === 'good'
      ? [finding('critical-fail', { severity: 'CRITICAL', deduction: 15 })]
      : [finding(`${assessment.id}-medium`)],
  }))
  assert.equal(assessmentFindingAttention(details)[0].title, 'critical-fail')
})

test('assessment scope uses each asset’s newest assessment and summary counts only', () => {
  const scope = assessmentScope(page([
    summary('new-1', 'a1', { failed: 0, warnings: 0 }),
    summary('old-1', 'a1', { failed: 4 }),
    summary('a2', 'a2', { failed: 2, warnings: 1 }),
    summary('a3', 'a3', { warnings: 2 }),
    summary('deleted', null as unknown as string, { assetId: null, assetKey: 'GONE', failed: 1 }),
  ]))
  assert.deepEqual(scope.latest.map((a) => a.id), ['new-1', 'a2', 'a3', 'deleted'])
  assert.deepEqual(scope.review.map((a) => a.id), ['a2', 'a3', 'deleted'])
  assert.equal(scope.checkTotal, 6)
  assert.equal(scope.olderNotLoaded, 0)
  assert.deepEqual(latestAssessmentPerAsset([]), [])
})

test('assessment counts are marked when older assessments are outside the loaded window', () => {
  const items = Array.from({ length: ASSESSMENT_PAGE_SIZE }, (_, i) => summary(`s${i}`, `a${i}`, { failed: i % 2 }))
  const scope = assessmentScope(page(items, 130))
  assert.equal(scope.total, 130)
  assert.equal(scope.olderNotLoaded, 30)
  assert.equal(countWithWindow(scope.review.length, scope.olderNotLoaded > 0), '50+')
  assert.equal(countWithWindow(scope.latest.length, scope.olderNotLoaded > 0), '100+')
  assert.equal(countWithWindow(7, false), '7')
})

test('"Showing 3 of N" appears only when checks are hidden', () => {
  assert.equal(showingOf(3, 7, 'failed or warning checks'), 'Showing 3 of 7 failed or warning checks')
  assert.equal(showingOf(3, 3, 'failed or warning checks'), null)
  assert.equal(showingOf(2, 2, 'failed or warning checks'), null)
})

test('detail requests run with a small concurrency limit and a failure does not discard the others', async () => {
  let running = 0
  let peak = 0
  const results = await settleWithConcurrency(Array.from({ length: 11 }, (_, i) => i), DETAIL_CONCURRENCY, async (i) => {
    running++
    peak = Math.max(peak, running)
    await new Promise((resolve) => setTimeout(resolve, 5))
    running--
    if (i === 3 || i === 7) throw new Error(`detail ${i} failed`)
    return i * 10
  })
  assert.ok(peak <= DETAIL_CONCURRENCY && DETAIL_CONCURRENCY <= 5, `peak ${peak}`)
  assert.equal(results.length, 11)
  assert.deepEqual(results.map((r) => r.status === 'fulfilled' ? r.value : 'failed'), [0, 10, 20, 'failed', 40, 50, 60, 'failed', 80, 90, 100])
  assert.deepEqual(await settleWithConcurrency([], DETAIL_CONCURRENCY, async () => 1), [])
})

test('summary counts are loaded independently of assessment details', () => {
  const pageSource = source('../src/pages/SecurityWorkspacePage.tsx')
  // Status counts come from the list query; details are a separate, settled query.
  assert.match(pageSource, /statusItems\(imports\.data, imports\.error, scope, summaries\.error\)/)
  assert.match(pageSource, /settleWithConcurrency\(review, DETAIL_CONCURRENCY/)
  assert.doesNotMatch(pageSource, /review\.slice\(/)
})

// --- datasets ------------------------------------------------------------------------------------

const batch = (id: string): BackendImportBatchSummary => ({
  id,
  datasetProfile: 'security-csv',
  profileVersion: '1',
  originalFilename: `${id}.csv`,
  fileSha256: '0'.repeat(64),
  fileSizeBytes: 100,
  status: 'VALIDATED',
  totalRows: 1,
  acceptedRows: 1,
  rejectedRows: 0,
  errorTotal: 0,
  eventsCreated: 1,
  duplicateRows: 0,
  createdAt: '2026-10-12T10:00:00Z',
  completedAt: null,
})

test('dataset limits: only the newest imports are checked, and the rest are counted', () => {
  const items = Array.from({ length: IMPORT_PAGE_SIZE }, (_, i) => batch(`b${i}`))
  assert.deepEqual(importScope(page(items, 31)), { loaded: 25, total: 31, notChecked: 6 })
  assert.deepEqual(importScope(page(items.slice(0, 4))), { loaded: 4, total: 4, notChecked: 0 })
  assert.equal(moreLabel(25, 31, ['import', 'imports']), '6 more imports')
  assert.equal(moreLabel(3, 4, ['issue', 'issues']), '1 more issue')
  assert.equal(moreLabel(3, 3, ['issue', 'issues']), null)
})
