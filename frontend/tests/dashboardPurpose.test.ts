import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import type { EventsPageItem, IncidentQueueItem } from '../src/api/types.ts'
import { ATTENTION_LINKS, RESPONSE_STEPS, liveCollectorEvents, responseQueue } from '../src/lib/attention.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const live = source('../src/pages/LiveTrackingPage.tsx')
const workspace = source('../src/pages/SecurityWorkspacePage.tsx')

// --- distinct purposes ----------------------------------------------------------------------------

test('Live Tracking is monitoring: its own eyebrow, active incidents without priority reasons, no workspace panels', () => {
  assert.equal((live.match(/eyebrow="Monitoring"/g) ?? []).length, 2)
  assert.doesNotMatch(live, /eyebrow="Command Home"|eyebrow="Investigation"/)
  assert.match(live, /title="Active incidents"/)
  assert.doesNotMatch(live, /title="Priority incidents"|Risk and priority rationale|showDetail/)
  assert.doesNotMatch(live, /responseQueue|assessmentService|memoryService|importService/)
})

test('Live Tracking shows incoming event severity from live collector events, not incident severity', () => {
  assert.match(live, /const incoming = collector\.data \? liveCollectorEvents\(collector\.data\.recentEvents\) : \[\]/)
  assert.match(live, /<SeverityBreakdown mix=\{severityMix\(incoming\)\} label="Incoming event severity" \/>/)
  assert.doesNotMatch(live, /<SeverityBreakdown mix=\{mix\}/)
  // The panel states that it covers the latest events received, not a period total.
  assert.match(live, /Severity of the latest \$\{formatNumber\(incoming\.length\)\} live/)
  assert.match(live, /No live events received yet\./)
})

test('Security Workspace is investigation: its own eyebrow and description, investigation strip first', () => {
  assert.equal((workspace.match(/eyebrow="Investigation"/g) ?? []).length, 2)
  assert.doesNotMatch(workspace, /eyebrow="Command Home"|eyebrow="Monitoring"/)
  assert.match(workspace, /const DESCRIPTION = 'Investigate prioritised incidents, move them through authorization and simulated containment/)
  assert.doesNotMatch(workspace, /collectorService/)
  for (const label of ['Active incidents', 'Awaiting authorization', 'Awaiting containment', 'Awaiting Cyber Memory', 'Open assessment findings']) {
    assert.match(workspace, new RegExp(`'${label}'`), label)
  }
})

test('Security Workspace order: investigation and response first, ingestion lower, nothing removed', () => {
  // The page body is laid out by WorkspaceOverview; the panels passed to it are placed there.
  const overview = workspace.slice(workspace.indexOf('function WorkspaceOverview('))
  const at = (needle: string) => {
    const index = overview.indexOf(needle)
    assert.ok(index >= 0, needle)
    return index
  }
  const order = [
    'label="Investigation status"',
    'title="Response queue"',
    'title="Risk and priority rationale"',
    '{findingsPanel}',
    'title="Recent lessons"',
    'id="workspace-capabilities"',
    'id="workspace-ingestion"',
    '{importStatus}',
    '{datasetIssuesPanel}',
    'title="Recent imports"',
    'title="Known limits"',
  ].map(at)
  assert.deepEqual(order, [...order].sort((a, b) => a - b))
  // The ingestion capability card is kept, now last.
  assert.match(workspace, /index=\{6\}\s+icon=\{FileUp\}\s+title="Security Data Ingestion"/)
  // Existing import functionality is unchanged.
  assert.match(workspace, /title="Dataset import issues"/)
  assert.match(workspace, /label="Dataset and assessment coverage"/)
})

test('Risk and priority rationale stays on Security Workspace only', () => {
  assert.match(workspace, /<AttentionList items=\{rationale\.slice\(0, LIST_LIMIT\)\} showDetail \/>/)
  assert.doesNotMatch(live, /rationale/i)
})

// --- response queue -------------------------------------------------------------------------------

const incident = (id: string, overrides: Partial<IncidentQueueItem> = {}): IncidentQueueItem => ({
  id,
  key: `INC-${id}`,
  title: `Incident ${id}`,
  description: null,
  severity: 'HIGH',
  riskScore: 50,
  lifecycle: 'DETECTED',
  detectionSource: 'SURICATA',
  recommendedAction: null,
  asset: null,
  eventCount: 1,
  createdAt: '2026-10-12T09:00:00Z',
  updatedAt: '2026-10-12T10:00:00Z',
  latestDecision: null,
  ...overrides,
})

test('the response queue groups incidents by their next step, as the backend lifecycle enforces it', () => {
  assert.deepEqual(
    RESPONSE_STEPS.map(({ step, state }) => [step, state]),
    [['authorize', 'VERIFIED'], ['contain', 'AUTHORIZED'], ['record', 'CONTAINED']],
  )
  const groups = responseQueue([
    incident('v1', { lifecycle: 'VERIFIED' }),
    incident('a1', { lifecycle: 'AUTHORIZED' }),
    incident('c1', { lifecycle: 'CONTAINED' }),
    incident('c2', { lifecycle: 'CONTAINED' }),
    incident('d1', { lifecycle: 'DETECTED' }),
    incident('p1', { lifecycle: 'PRIORITISED' }),
    incident('l1', { lifecycle: 'LEARNED' }),
  ], 5)
  assert.deepEqual(groups.map((group) => [group.step, group.title, group.total]), [
    ['authorize', 'Authorize response', 1],
    ['contain', 'Contain and verify', 1],
    ['record', 'Record in Cyber Memory', 2],
  ])
  // Steps not waiting on a response (detected, prioritised, learned) are never queued.
  const queued = groups.flatMap((group) => group.items.map((item) => item.key))
  assert.ok(!queued.some((key) => /-(d1|p1|l1)$/.test(key)), JSON.stringify(queued))
})

test('each queued incident links to its existing detail page, with its stored severity and risk', () => {
  const [authorize] = responseQueue([incident('v 1', { lifecycle: 'VERIFIED', severity: 'CRITICAL', riskScore: 81.6 })])
  const [item] = authorize.items
  assert.equal(item.to, ATTENTION_LINKS.incident('v 1'))
  assert.equal(item.to, '/incidents/v%201')
  assert.equal(item.kind, 'incident')
  assert.equal(item.source, 'INC-v 1')
  assert.equal(item.severity, 'CRITICAL')
  assert.equal(item.reason, 'Verified · needs an approved authorization · Risk 82')
  assert.match(workspace, /<AttentionList items=\{group\.items\} \/>/)
})

test('within a step: highest stored risk first, unscored last, then longest waiting; the total counts every one', () => {
  const [, contain] = responseQueue([
    incident('unscored', { lifecycle: 'AUTHORIZED', riskScore: null, updatedAt: '2026-10-10T00:00:00Z' }),
    incident('low', { lifecycle: 'AUTHORIZED', riskScore: 20 }),
    incident('high-new', { lifecycle: 'AUTHORIZED', riskScore: 90, updatedAt: '2026-10-12T12:00:00Z' }),
    incident('high-old', { lifecycle: 'AUTHORIZED', riskScore: 90, updatedAt: '2026-10-11T12:00:00Z' }),
  ], 3)
  assert.deepEqual(contain.items.map((item) => item.key), ['queue-contain-high-old', 'queue-contain-high-new', 'queue-contain-low'])
  assert.equal(contain.total, 4)
  assert.match(workspace, /Showing \{group\.items\.length\} of \{formatNumber\(group\.total\)\}/)
})

test('response queue empty states: nothing waiting at all, or nothing at one step', () => {
  const groups = responseQueue([incident('d', { lifecycle: 'DETECTED' }), incident('l', { lifecycle: 'LEARNED' })])
  assert.deepEqual(groups.map((group) => group.total), [0, 0, 0])
  assert.ok(groups.every((group) => group.items.length === 0))
  assert.deepEqual(responseQueue([]).map((group) => group.total), [0, 0, 0])
  assert.match(workspace, /queue\.every\(\(group\) => group\.total === 0\)/)
  assert.match(workspace, /Nothing waiting for a response step\./)
  assert.match(workspace, /None waiting\./)
  // Demo incidents are excluded before grouping.
  assert.match(workspace, /const queue = responseQueue\(genuine, LIST_LIMIT\)/)
})

// --- live collector events ------------------------------------------------------------------------

const event = (id: string, overrides: Partial<EventsPageItem> = {}): EventsPageItem => ({
  id,
  eventUid: `collector-web-${id}`,
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

test('incoming event severity counts only live collector events (imported and demo rows left out)', () => {
  const kept = liveCollectorEvents([
    event('live', { severity: 'HIGH' }),
    event('imported', { importBatchId: 'b1' }),
    event('dataset', { detectionSource: 'DATASET_IMPORT' }),
    event('demo', { eventUid: 'netra-demo-1' }),
  ])
  assert.deepEqual(kept.map((item) => item.id), ['live'])
})
