import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import type {
  BackendAssessmentDetail,
  BackendAssessmentFinding,
  BackendAssessmentSummary,
  BackendImportBatchSummary,
  BackendPrioritizedIncident,
  EventsPageItem,
  IncidentQueueItem,
} from '../src/api/types.ts'
import {
  ATTENTION_LIMIT,
  ATTENTION_LINKS,
  assessmentFindingAttention,
  collectorIdleNote,
  demoExclusionNote,
  datasetIssueAttention,
  hiddenIncidentsNote,
  incidentAttention,
  isDemoEvent,
  isDemoIncident,
  liveAttention,
  liveEmptyState,
  unlinkedEventAttention,
} from '../src/lib/attention.ts'
import { ROUTES } from '../src/lib/navigation.ts'

const prioritized = (id: string, rank: number, overrides: Partial<BackendPrioritizedIncident> = {}): BackendPrioritizedIncident => ({
  incidentId: id,
  state: 'DETECTED',
  riskScore: 70,
  severity: 'HIGH',
  assetCriticality: 'CRITICAL',
  eventCount: 2,
  updatedAt: '2026-10-12T10:00:00Z',
  priorityRank: rank,
  priorityReason: `reason ${id}`,
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
  severity: 'HIGH',
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

const summary = (id: string, assetId: string, overrides: Partial<BackendAssessmentSummary> = {}): BackendAssessmentSummary => ({
  id,
  assetId,
  assetKey: `KEY-${assetId}`,
  asset: { id: assetId, name: `asset-${assetId}`, hostname: null, ipAddress: null, criticality: 'HIGH', status: 'ACTIVE' },
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
  title: `Finding ${id}`,
  result: 'FAIL',
  severity: 'HIGH',
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

const detail = (base: BackendAssessmentSummary, findings: BackendAssessmentFinding[]): BackendAssessmentDetail => ({
  ...base,
  missingEvidence: [],
  inputCounts: {},
  findings,
})

const batch = (id: string, overrides: Partial<BackendImportBatchSummary> = {}): BackendImportBatchSummary => ({
  id,
  datasetProfile: 'security-csv',
  profileVersion: '1',
  originalFilename: `${id}.csv`,
  fileSha256: '0'.repeat(64),
  fileSizeBytes: 100,
  status: 'VALIDATED',
  totalRows: 10,
  acceptedRows: 10,
  rejectedRows: 0,
  errorTotal: 0,
  eventsCreated: 10,
  duplicateRows: 0,
  createdAt: '2026-10-12T10:00:00Z',
  completedAt: '2026-10-12T10:00:01Z',
  ...overrides,
})

test('detail links point at the existing detail routes', () => {
  assert.equal(ATTENTION_LINKS.incident('a'), ROUTES.incident('a'))
  assert.equal(ATTENTION_LINKS.event('e1'), `${ROUTES.events}?event=e1`)
  assert.equal(ATTENTION_LINKS.assessment('s1'), `${ROUTES.assessments}?assessment=s1`)
  assert.equal(ATTENTION_LINKS.importBatch('b1'), `${ROUTES.imports}?batch=b1`)
  assert.equal(ATTENTION_LIMIT, 3)
})

test('incidents keep the backend prioritisation order and skip entries the list did not return', () => {
  const items = incidentAttention(
    [prioritized('b', 2), prioritized('missing', 1), prioritized('a', 3)],
    [incident('a'), incident('b')],
  )
  assert.deepEqual(items.map((item) => item.to), [ROUTES.incident('b'), ROUTES.incident('a')])
  assert.equal(items[0].detail, 'reason b')
  assert.equal(items[0].source, 'INC-b')
})

test('incident reasons list only the factors the API returned', () => {
  const [unscored] = incidentAttention([prioritized('a', 1, { riskScore: null, assetCriticality: null, eventCount: 0 })], [incident('a')])
  assert.equal(unscored.reason, 'Risk not calculated')
  const [scored] = incidentAttention(
    [prioritized('a', 1, { riskScore: 72.4 })],
    [incident('a', { latestDecision: { id: 'd', incidentId: 'a', action: 'MONITOR', rationale: '', riskScore: 72, confidence: 0.81, recommendation: null, createdAt: '' } })],
  )
  assert.equal(scored.reason, 'Risk 72 · CRITICAL asset · 2 events · decision confidence 81%')
})

test('live notifications never include imported dataset rows or events already in an incident', () => {
  const items = unlinkedEventAttention([
    event('imported', { severity: 'CRITICAL', importBatchId: 'b1' }),
    event('dataset', { severity: 'CRITICAL', detectionSource: 'DATASET_IMPORT' }),
    event('linked', { severity: 'CRITICAL', incidentIds: ['i1'] }),
    event('medium', { severity: 'MEDIUM' }),
    event('high-old', { severity: 'HIGH', timestamp: '2026-10-12T08:00:00Z' }),
    event('high-new', { severity: 'HIGH', timestamp: '2026-10-12T09:00:00Z' }),
    event('critical', { severity: 'CRITICAL', timestamp: '2026-10-12T07:00:00Z' }),
  ])
  assert.deepEqual(items.map((item) => item.key), ['event-critical', 'event-high-new', 'event-high-old'])
  assert.equal(items[0].to, `${ROUTES.events}?event=critical`)
})

test('live attention puts prioritised incidents first and caps the list', () => {
  const incidents = incidentAttention([prioritized('a', 1), prioritized('b', 2)], [incident('a'), incident('b')])
  const events = unlinkedEventAttention([event('e1'), event('e2')])
  assert.deepEqual(liveAttention(incidents, events).map((item) => item.kind), ['incident', 'incident', 'event'])
  assert.equal(liveAttention([], []).length, 0)
})

test('assessment findings: FAIL before WARN, then severity and deduction; passes are omitted', () => {
  const low = summary('s-low', 'asset-1', { score: 30, grade: 'F' })
  const high = summary('s-high', 'asset-2', { score: 70, grade: 'C', asset: null })
  const items = assessmentFindingAttention([
    detail(low, [
      finding('warn', { result: 'WARN', severity: 'CRITICAL', deduction: 30 }),
      finding('pass', { result: 'PASS', severity: null, deduction: 0 }),
      finding('fail-medium', { severity: 'MEDIUM', deduction: 20 }),
    ]),
    detail(high, [finding('fail-high', { severity: 'HIGH', deduction: 5, recommendation: 'Patch it' })]),
  ])
  assert.deepEqual(items.map((item) => item.key), ['finding-fail-high', 'finding-fail-medium', 'finding-warn'])
  assert.equal(items[0].source, 'Assessment · KEY-asset-2')
  assert.equal(items[0].reason, 'Failed check · −5 points · grade C')
  assert.equal(items[0].detail, 'Patch it')
  assert.equal(items[0].to, `${ROUTES.assessments}?assessment=s-high`)
  assert.equal(items[1].reason, 'Failed check · −20 points · HIGH asset · grade F')
})

test('dataset issues are labelled by file, carry no severity and are never detections', () => {
  const items = datasetIssueAttention(
    [
      batch('clean'),
      batch('partial', { acceptedRows: 7, rejectedRows: 3 }),
      batch('rejected', { status: 'REJECTED', acceptedRows: 0, rejectedRows: 10, errorTotal: 12, eventsCreated: 0 }),
    ],
    { clean: { events: 10, linkedToAsset: 6, addressWithoutAsset: 3, withoutAddress: 1 } },
  )
  assert.deepEqual(items.map((item) => item.key), ['batch-rejected-rejected', 'batch-rows-partial', 'batch-coverage-clean'])
  assert.ok(items.every((item) => item.kind === 'dataset' && item.severity === null))
  assert.deepEqual(items.map((item) => item.source), ['Dataset · rejected.csv', 'Dataset · partial.csv', 'Dataset · clean.csv'])
  assert.equal(items[0].reason, '12 validation issues · no rows stored')
  assert.equal(items[1].title, '3 rows rejected')
  assert.equal(items[2].title, '4 events not linked to an asset')
  assert.equal(items[2].to, `${ROUTES.imports}?batch=clean`)
})

test('a clean dataset with full coverage has no issues; filtering is by the batches passed in', () => {
  assert.deepEqual(datasetIssueAttention([batch('clean')], { clean: { events: 10, linkedToAsset: 10, addressWithoutAsset: 0, withoutAddress: 0 } }), [])
  assert.deepEqual(datasetIssueAttention([batch('clean')], { clean: null }), [])
  const partial = batch('partial', { rejectedRows: 2, acceptedRows: 8 })
  assert.deepEqual(datasetIssueAttention([partial]).map((item) => item.key), ['batch-rows-partial'])
})

test('regression: active incidents that cannot be shown are never reported as "no active incidents"', () => {
  // The engine ranks two active incidents, but neither is in the supported list (unsupported state).
  const prioritizedList = [prioritized('x', 1, { state: 'ARCHIVED' }), prioritized('y', 2)]
  const shown = incidentAttention(prioritizedList, [])
  assert.equal(shown.length, 0)
  const empty = liveEmptyState(prioritizedList.length)
  assert.equal(empty.title, '2 active incidents could not be shown.')
  assert.doesNotMatch(`${empty.title} ${empty.description}`, /no active incidents/i)
  assert.match(empty.description, /lifecycle state is not supported by this view or changed while loading/)
  assert.equal(hiddenIncidentsNote(prioritizedList.length, shown.length), '2 incidents not shown (unsupported or changed state)')
})

test('a genuinely empty incident list keeps the original message; partial lists add a note and keep their order', () => {
  assert.deepEqual(liveEmptyState(0), { title: 'Nothing needs attention right now.', description: 'There are no active incidents and no unlinked high or critical events.' })
  assert.equal(liveEmptyState(1).title, '1 active incident could not be shown.')
  const items = incidentAttention([prioritized('a', 1), prioritized('hidden', 2), prioritized('b', 3)], [incident('a'), incident('b')])
  assert.deepEqual(items.map((item) => item.to), [ROUTES.incident('a'), ROUTES.incident('b')])
  assert.equal(hiddenIncidentsNote(3, items.length), '1 incident not shown (unsupported or changed state)')
  assert.equal(hiddenIncidentsNote(2, 2), null)
})

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const demoAsset = { id: 'd', name: 'Customer DB', hostname: 'db-01.netra-demo.example', ipAddress: '10.250.20.20', criticality: 'CRITICAL', status: 'ACTIVE' }
const realAsset = { id: 'r', name: 'web-01', hostname: 'web-01.corp.internal', ipAddress: '10.0.0.5', criticality: 'HIGH', status: 'ACTIVE' }

test('demo seed incidents are recognised only by their explicit markers', () => {
  assert.ok(isDemoIncident(incident('a', { key: 'INC-DEMO-0002' })))
  assert.ok(isDemoIncident(incident('b', { title: '[NETRA DEMO] Credential attack on public portal' })))
  assert.ok(isDemoIncident(incident('c', { asset: demoAsset })))
  // Genuine records are never hidden, even when their wording mentions demos or tests.
  assert.ok(!isDemoIncident(incident('d', { key: 'INC-0042', title: 'Brute force against demo-signup page', asset: realAsset })))
  assert.ok(!isDemoIncident(incident('e', { key: 'INC-TEST-1', title: 'Test of SSH alerting' })))
})

test('demo seed events are recognised only by their explicit markers', () => {
  assert.ok(isDemoEvent(event('a', { eventUid: 'netra-demo-a4-outbound-beacon' })))
  assert.ok(isDemoEvent(event('b', { signature: 'NETRA DEMO outbound beacon to listed command-and-control domain' })))
  assert.ok(isDemoEvent(event('c', { asset: demoAsset })))
  assert.ok(!isDemoEvent(event('d', { eventUid: 'web-collector-1f2e', signature: 'ET SCAN demo scanner', asset: realAsset })))
  assert.ok(!isDemoEvent(event('e', { eventUid: undefined, signature: null, asset: null })))
})

test('excluded demo records are stated, not silently dropped', () => {
  assert.equal(demoExclusionNote(2, 1), 'Demo records excluded: 2 incidents, 1 event from the NETRA demo dataset')
  assert.equal(demoExclusionNote(0, 3), 'Demo records excluded: 3 events from the NETRA demo dataset')
  assert.equal(demoExclusionNote(0, 0), null)
})

test('an idle collector says no live activity was received, never that monitoring is active', () => {
  const never = collectorIdleNote(0)
  assert.match(never, /no live events have been received yet/)
  assert.match(never, /not monitoring a network feed/)
  assert.match(collectorIdleNote(12), /no live events have been received in the last 5 minutes/)
  for (const note of [never, collectorIdleNote(12)]) assert.doesNotMatch(note, /\bmonitoring (is )?active|continuous(ly)? monitor/i)
})

test('Live Tracking leaves demo records out of alerts and counts; both landing pages drop the bottom link rows', () => {
  const live = source('../src/pages/LiveTrackingPage.tsx')
  assert.match(live, /filter\(\(entry\) => !demoIncidentIds\.has\(entry\.incidentId\)\)/)
  assert.match(live, /filter\(\(event\) => !isDemoEvent\(event\)\)/)
  assert.match(live, /incidentAttention\(prioritized, incidents\.data\.incidents\)/)
  assert.match(live, /collectorIdleNote\(collector\.data\.totalEvents\)/)
  for (const path of ['../src/pages/LiveTrackingPage.tsx', '../src/pages/SecurityWorkspacePage.tsx', '../src/pages/workspaces/shared.tsx']) {
    assert.doesNotMatch(source(path), /QuickLinks|Workspace tools|Tracking tools/, path)
  }
})
