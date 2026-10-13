import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import type {
  AssetInventoryItem,
  BackendImportBatchSummary,
  CyberMemoryEntry,
  EventsPageItem,
  IncidentQueueItem,
  ThreatIndicatorInventoryItem,
} from '../src/api/types.ts'
import { ATTENTION_LINKS, collectorActivityAttention, severityMix } from '../src/lib/attention.ts'
import { NAV_GROUPS, ROUTES, navGroupsForPath } from '../src/lib/navigation.ts'
import { detectionSummary, ingestionSummary, inventorySummary, memorySummary, responseSummary } from '../src/lib/workspaceSummary.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const routesOf = (groups: ReturnType<typeof navGroupsForPath>) => groups.flatMap((group) => group.items.map((item) => item.to))
const allRoutes = routesOf(NAV_GROUPS)

// --- contextual sidebar ---------------------------------------------------------------------------

test('Live Tracking and the Live Event Collector show the collector and hide Dataset Import; everything else is unchanged', () => {
  for (const path of ['/live', '/live/', '/collector', '/collector/']) {
    const routes = routesOf(navGroupsForPath(path))
    assert.ok(routes.includes(ROUTES.collector))
    assert.ok(!routes.includes(ROUTES.imports))
    assert.deepEqual(routes, allRoutes.filter((route) => route !== ROUTES.imports))
  }
})

test('Security Workspace shows Dataset Import and hides the Live Event Collector; everything else is unchanged', () => {
  for (const path of ['/workspace', '/workspace/']) {
    const routes = routesOf(navGroupsForPath(path))
    assert.ok(routes.includes(ROUTES.imports))
    assert.ok(!routes.includes(ROUTES.collector))
    assert.deepEqual(routes, allRoutes.filter((route) => route !== ROUTES.collector))
  }
})

test('regression: navigating /live → /collector keeps Dataset Import hidden; /workspace still hides the collector', () => {
  // The sidebar recomputes its groups from each new pathname, as on a sidebar click.
  const [live, collector, workspace] = ['/live', '/collector', '/workspace'].map((path) => routesOf(navGroupsForPath(path)))
  assert.deepEqual(collector, live)
  for (const routes of [live, collector]) {
    assert.ok(routes.includes(ROUTES.collector) && !routes.includes(ROUTES.imports))
  }
  assert.ok(workspace.includes(ROUTES.imports) && !workspace.includes(ROUTES.collector))
})

test('every other route keeps the full sidebar, and the hidden routes stay registered', () => {
  for (const path of ['/dashboard', '/imports', '/incidents', '/incidents/abc', '/events', '/settings', '/live-x', '/workspaces', '/']) {
    assert.equal(navGroupsForPath(path), NAV_GROUPS, path)
  }
  assert.ok(allRoutes.includes(ROUTES.collector) && allRoutes.includes(ROUTES.imports))
  const router = source('../src/router.tsx')
  assert.match(router, /path: ROUTES\.collector,/)
  assert.match(router, /path: ROUTES\.imports,/)
})

test('the sidebar builds its groups from the current path', () => {
  const sidebar = source('../src/layouts/Sidebar.tsx')
  assert.match(sidebar, /const \{ pathname \} = useLocation\(\)/)
  assert.match(sidebar, /navGroupsForPath\(pathname\)\.map/)
  assert.doesNotMatch(sidebar, /NAV_GROUPS\.map/)
})

// --- Live Tracking helpers ------------------------------------------------------------------------

const event = (id: string, overrides: Partial<EventsPageItem> = {}): EventsPageItem => ({
  id,
  eventUid: `uid-${id}`,
  timestamp: '2026-10-12T10:00:00Z',
  sourceIp: null,
  sourcePort: null,
  destinationIp: null,
  destinationPort: null,
  protocol: null,
  eventType: 'alert',
  signature: null,
  severity: 'LOW',
  detectionSource: 'MANUAL',
  status: 'NEW',
  anomalyScore: null,
  incidentIds: [],
  assetId: null,
  asset: null,
  mitreTechniqueId: null,
  importBatchId: null,
  sourceRow: null,
  ...overrides,
}) as EventsPageItem

test('collector activity lists live events newest first and leaves out imported and demo records', () => {
  const items = collectorActivityAttention([
    event('old', { timestamp: '2026-10-12T08:00:00Z' }),
    event('new', { timestamp: '2026-10-12T11:00:00Z', incidentIds: ['i1'] }),
    event('imported', { importBatchId: 'b1', timestamp: '2026-10-12T12:00:00Z' }),
    event('dataset', { detectionSource: 'DATASET_IMPORT', timestamp: '2026-10-12T12:00:00Z' }),
    event('demo', { eventUid: 'netra-demo-1', timestamp: '2026-10-12T12:00:00Z' }),
  ], 5)
  assert.deepEqual(items.map((item) => item.key), ['activity-new', 'activity-old'])
  assert.equal(items[0].reason, 'Linked to 1 incident')
  assert.equal(items[1].reason, 'Not linked to an incident')
  assert.equal(items[0].to, ATTENTION_LINKS.event('new'))
  assert.equal(collectorActivityAttention([event('a'), event('b'), event('c')], 2).length, 2)
})

test('severity mix counts every severity, with zeros for the ones not present', () => {
  assert.deepEqual(severityMix([{ severity: 'CRITICAL' }, { severity: 'HIGH' }, { severity: 'HIGH' }]), { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 })
  assert.deepEqual(severityMix([]), { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 })
})

test('Live Tracking separates live activity from imported datasets and says when there is no live feed', () => {
  const live = source('../src/pages/LiveTrackingPage.tsx')
  assert.match(live, /collectorActivityAttention\(collector\.data\.recentEvents, LIST_LIMIT\)/)
  assert.match(live, /No live feed connected/)
  // Imported dataset events are a compact status-strip note, still kept apart from live counts.
  assert.match(live, /footer=\{collector\.data && collector\.data\.importedEventsTotal > 0 \? <ImportedNote total=\{collector\.data\.importedEventsTotal\} \/> : undefined\}/)
  assert.match(live, /they are not live monitoring and are not counted on this page/)
  assert.doesNotMatch(live, /ImportedSeparation/)
  // Severity counts and metrics use the demo-filtered list, never the raw API response.
  assert.match(live, /const mix = severityMix\(prioritized\)/)
  assert.doesNotMatch(live, /severityMix\(incidents\.data/)
  assert.match(live, /<AttentionList items=\{incidentItems\.slice\(0, LIST_LIMIT\)\} \/>/)
})

// --- Security Workspace summaries -----------------------------------------------------------------

const batch = (id: string, overrides: Partial<BackendImportBatchSummary> = {}): BackendImportBatchSummary => ({
  id,
  datasetProfile: 'security-csv',
  profileVersion: '1',
  originalFilename: `${id}.csv`,
  fileSha256: '0'.repeat(64),
  fileSizeBytes: 100,
  status: 'VALIDATED',
  totalRows: 10,
  acceptedRows: 8,
  rejectedRows: 2,
  errorTotal: 2,
  eventsCreated: 6,
  duplicateRows: 2,
  createdAt: '2026-10-12T10:00:00Z',
  completedAt: null,
  ...overrides,
})

const incident = (id: string, overrides: Partial<IncidentQueueItem> = {}): IncidentQueueItem => ({
  id,
  key: `INC-${id}`,
  title: `Incident ${id}`,
  description: null,
  severity: 'HIGH',
  riskScore: 70,
  lifecycle: 'DETECTED',
  detectionSource: 'SURICATA',
  recommendedAction: null,
  asset: null,
  eventCount: 2,
  createdAt: '2026-10-12T09:00:00Z',
  updatedAt: '2026-10-12T10:00:00Z',
  latestDecision: null,
  ...overrides,
})

test('ingestion totals add up the batches given', () => {
  assert.deepEqual(ingestionSummary([batch('a'), batch('b', { status: 'REJECTED', totalRows: 3, acceptedRows: 0, rejectedRows: 3, eventsCreated: 0, duplicateRows: 0 })]), {
    batches: 2, validated: 1, rejected: 1, totalRows: 13, acceptedRows: 8, rejectedRows: 5, duplicateRows: 2, eventsCreated: 6,
  })
})

test('detection summary counts evidence-backed incidents and ranks sources', () => {
  const summary = detectionSummary([
    incident('1'),
    incident('2', { detectionSource: 'ML_ANOMALY', eventCount: 0 }),
    incident('3', { detectionSource: 'ML_ANOMALY' }),
    incident('4', { detectionSource: 'ML_ANOMALY' }),
  ])
  assert.equal(summary.incidents, 4)
  assert.equal(summary.withEvidence, 3)
  assert.deepEqual(summary.bySource, [{ source: 'ML_ANOMALY', count: 3 }, { source: 'SURICATA', count: 1 }])
})

test('response summary reads stored scores, decisions and lifecycle stages only', () => {
  const decision = { id: 'd', incidentId: '1', action: 'BLOCK_IP' as const, rationale: 'r', riskScore: 80, confidence: 0.8, recommendation: null, createdAt: '2026-10-12T10:00:00Z' }
  const summary = responseSummary([
    incident('1', { lifecycle: 'VERIFIED', latestDecision: decision }),
    incident('2', { lifecycle: 'CONTAINED', latestDecision: decision }),
    incident('3', { lifecycle: 'LEARNED', riskScore: null }),
    incident('4', { lifecycle: 'DETECTED', riskScore: null }),
  ])
  assert.deepEqual(summary, { scored: 2, decisions: 2, stages: { VERIFIED: 1, AUTHORIZED: 0, CONTAINED: 1, LEARNED: 1 } })
})

const memory = (id: string, overrides: Partial<CyberMemoryEntry> = {}): CyberMemoryEntry => ({
  id,
  incidentId: null,
  threatName: null,
  mitreTechniqueId: null,
  sourceIp: null,
  assetId: null,
  riskScore: null,
  actionTaken: null,
  outcome: null,
  lessonsLearned: `lesson ${id}`,
  tags: null,
  similarIncidentIds: null,
  recordedAt: '2026-10-12T10:00:00Z',
  effectiveness: 'EFFECTIVE',
  ...overrides,
})

test('memory summary orders lessons newest first and leaves out entries of demo incidents', () => {
  const summary = memorySummary(
    [
      memory('a', { recordedAt: '2026-10-11T10:00:00Z', effectiveness: 'UNKNOWN' }),
      memory('b', { recordedAt: '2026-10-12T10:00:00Z' }),
      memory('demo', { incidentId: 'demo-incident' }),
    ],
    new Set(['demo-incident']),
  )
  assert.equal(summary.entries, 2)
  assert.equal(summary.effective, 1)
  assert.equal(summary.demo, 1)
  assert.deepEqual(summary.latest.map((entry) => entry.id), ['b', 'a'])
})

test('inventory summary sums reported vulnerabilities and counts only explicitly active indicators', () => {
  const asset = (vulnerabilityCount: number | null) => ({ vulnerabilityCount }) as AssetInventoryItem
  const indicator = (isActive: boolean | null) => ({ isActive }) as ThreatIndicatorInventoryItem
  assert.deepEqual(inventorySummary([asset(3), asset(null), asset(2)], [indicator(true), indicator(false), indicator(null)]), {
    assets: 3, vulnerabilities: 5, assetsWithoutVulnerabilityCount: 1, indicators: 3, activeIndicators: 1,
  })
})

test('Security Workspace covers the six capabilities, states its limits and keeps containment simulated', () => {
  const page = source('../src/pages/SecurityWorkspacePage.tsx')
  for (const title of [
    'Security Data Ingestion',
    'Detection & Evidence Correlation',
    'Explainable Risk Assessment',
    'Decision & Controlled Response',
    'Cyber Memory & Learning',
    'Security Assessment',
  ]) {
    assert.match(page, new RegExp(`title="${title}"`), title)
  }
  assert.match(page, /Containment is simulated/)
  assert.match(page, /NETRA does not learn autonomously/)
  assert.match(page, /never counted as detections/)
  // Demo incidents are filtered by the explicit markers before any summary is taken.
  assert.match(page, /const genuine = allIncidents\.filter\(\(incident\) => !demoIncidentIds\.has\(incident\.id\)\)/)
  assert.match(page, /detectionSummary\(genuine\)/)
  assert.match(page, /responseSummary\(genuine\)/)
})

test('workspace lists link to existing detail pages and the landing pages add no bottom navigation rows', () => {
  const page = source('../src/pages/SecurityWorkspacePage.tsx')
  assert.match(page, /ATTENTION_LINKS\.importBatch\(batch\.id\)/)
  assert.match(page, /ATTENTION_LINKS\.incident\(entry\.incidentId\)/)
  for (const path of ['../src/pages/LiveTrackingPage.tsx', '../src/pages/SecurityWorkspacePage.tsx']) {
    assert.doesNotMatch(source(path), /QuickLinks|Workspace tools|Tracking tools|BottomNav/, path)
  }
})
