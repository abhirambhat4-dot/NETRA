import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  breakdown,
  catalogueName,
  DEFAULT_OBSERVED_FILTERS,
  observedErrorView,
  observedTechniqueParams,
  observedTechniquesKey,
  techniqueFilter,
  updateObservedFilters,
  type ObservedTechniqueFilters,
} from '../src/lib/observedTechniques.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const filters = (change: Partial<ObservedTechniqueFilters> = {}): ObservedTechniqueFilters => ({ ...DEFAULT_OBSERVED_FILTERS, ...change })

test('the frontend types carry every field the backend schema returns', () => {
  const schema = source('../../backend/app/schemas/attack.py')
  const lib = source('../src/lib/observedTechniques.ts')
  const camel = (name: string) => name.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
  for (const model of ['TechniqueCatalogueEntry', 'ObservedTechniqueResponse', 'ObservedTechniquePage']) {
    const body = schema.split(`class ${model}(`)[1].split(/\nclass /)[0]
    const fields = [...body.matchAll(/^ {4}([a-z_]+): /gm)].map((match) => camel(match[1]))
    assert.ok(fields.length >= 4, model)
    for (const field of fields) assert.match(lib, new RegExp(`\\b${field}\\??:`), `${model}.${field}`)
  }
})

test('default parameters match the API defaults', () => {
  assert.deepEqual(observedTechniqueParams(filters()), { days: 7, page: 1, pageSize: 25, sortBy: 'eventCount', sortOrder: 'desc' })
})

test('every filter maps to its query parameter; "all" and empty filters are omitted', () => {
  assert.deepEqual(
    observedTechniqueParams(filters({ days: 30, source: 'SURICATA', origin: 'collector_field', techniqueId: ' t1110.001 ', page: 3, pageSize: 50, sortBy: 'lastSeen', sortOrder: 'asc' })),
    { days: 30, source: 'SURICATA', origin: 'collector_field', techniqueId: 'T1110.001', page: 3, pageSize: 50, sortBy: 'lastSeen', sortOrder: 'asc' },
  )
  assert.equal('source' in observedTechniqueParams(filters({ source: 'ALL' })), false)
  assert.equal('origin' in observedTechniqueParams(filters({ origin: 'ALL' })), false)
})

test('the technique filter follows the backend rule and is not sent until valid', () => {
  for (const [typed, expected] of [['T1110', 'T1110'], [' t1110 ', 'T1110'], ['t1110.001', 'T1110.001'], ['', null], ['   ', null]] as const) {
    assert.equal(techniqueFilter(typed), expected, typed)
  }
  for (const typed of ['T11', 'TA0006', 'T1110.01', 'T 1110', 'T1110x', 'T１１１０', 'T١١١٠']) {
    assert.equal(techniqueFilter(typed), 'invalid', typed)
    assert.equal('techniqueId' in observedTechniqueParams(filters({ techniqueId: typed })), false, typed)
  }
})

test('the query key changes with every sent parameter, so a stale response cannot replace newer results', () => {
  const base = observedTechniquesKey(filters())
  for (const change of [{ days: 30 }, { source: 'MANUAL' as const }, { origin: 'ingest_field' as const }, { techniqueId: 'T1059' }, { page: 2 }, { pageSize: 50 }, { sortBy: 'techniqueId' as const }, { sortOrder: 'asc' as const }]) {
    assert.notEqual(observedTechniquesKey(filters(change)), base, JSON.stringify(change))
  }
  // A half-typed technique ID sends the same request as no ID: no needless refetch.
  assert.equal(observedTechniquesKey(filters({ techniqueId: 'T11' })), base)
  // useQuery drops the response of a superseded key (effect cleanup), and the panel keys its query by the parameters.
  const hook = source('../src/hooks/useQuery.ts')
  assert.match(hook, /cancelled = true/)
  assert.match(hook, /\[key, attempt\]/)
  assert.match(source('../src/pages/intel/ObservedTechniquesPanel.tsx'), /useQuery\(observedTechniquesKey\(filters\), \(\) => observedTechniquesService\.list\(filters\)\)/)
})

test('changing a filter returns to page 1; paging keeps the filters', () => {
  const onPage3 = filters({ page: 3, source: 'SURICATA' })
  assert.equal(updateObservedFilters(onPage3, { sortBy: 'lastSeen' }).page, 1)
  assert.equal(updateObservedFilters(onPage3, { days: 30 }).page, 1)
  assert.deepEqual(updateObservedFilters(onPage3, { page: 4 }), { ...onPage3, page: 4 })
})

test('breakdowns list the largest first and label origins', () => {
  assert.equal(breakdown({ MANUAL: 1, SURICATA: 2, THREAT_INTEL: 1 }), 'SURICATA 2 · MANUAL 1 · THREAT_INTEL 1')
  assert.equal(breakdown({ collector_field: 1, ingest_field: 3 }, { ingest_field: 'Event ingest API', collector_field: 'Live collector' }), 'Event ingest API 3 · Live collector 1')
  assert.equal(breakdown({}), '')
})

test('catalogue names are shown only when a catalogue knows them; nothing is invented', () => {
  assert.equal(catalogueName({ status: 'unknown', name: null, tactics: [], url: null }), null)
  assert.equal(catalogueName({ status: 'unknown', name: 'Brute Force', tactics: [], url: null }), null)
  assert.equal(catalogueName({ status: 'known', name: 'Brute Force', tactics: ['Credential Access'], url: null }), 'Brute Force')
  const panel = source('../src/pages/intel/ObservedTechniquesPanel.tsx')
  assert.match(panel, /Name not in catalogue/)
  assert.match(panel, /no ATT&CK catalogue is bundled with NETRA/)
  assert.doesNotMatch(panel, /\.tactics|\.url|description:\s*item/) // no tactic, URL or description is rendered from the response
})

test('errors follow the page conventions: sign-in for 401, retry for server and network failures', () => {
  assert.deepEqual(observedErrorView(401, 'Unauthorized'), { title: 'Authentication required', retry: false, signIn: true })
  const server = observedErrorView(500, 'Internal Server Error')
  assert.equal(server.retry, true)
  assert.match(server.message!, /migration 0007/) // a missing table is explained, never filled with data
  assert.deepEqual(observedErrorView(422, 'techniqueId must be…'), { title: 'Invalid filter', message: 'techniqueId must be…', retry: false, signIn: false })
  assert.deepEqual(observedErrorView(null, 'Failed to fetch'), { title: 'Observed techniques unavailable', message: 'Failed to fetch', retry: true, signIn: false })
})

test('the panel handles loading, error with retry, empty and success states and pages through results', () => {
  const panel = source('../src/pages/intel/ObservedTechniquesPanel.tsx')
  assert.match(panel, /<ErrorState title=\{error\.title\} message=\{error\.message\} onRetry=\{error\.retry \? observed\.reload : undefined\} \/>/)
  assert.match(panel, /<Link to=\{ROUTES\.login\}>Sign in<\/Link>/)
  assert.match(panel, /!page \? \(\s*<LoadingState/)
  assert.match(panel, /page\.items\.length === 0 \? \(\s*<EmptyState/)
  assert.match(panel, /<Pagination page=\{page\.page\} pageSize=\{page\.pageSize\} total=\{page\.total\} onChange=\{\(next\) => change\(\{ page: next \}\)\} \/>/)
  for (const label of ['Time window', 'label="Source"', 'label="Origin"', 'label="Sort"', 'Exact technique ID']) assert.ok(panel.includes(label), label)
  assert.match(panel, /source-supplied evidence, not inferred and not ATT&CK coverage/)
  assert.match(panel, /formatDateTime\(item\.firstSeen\)/)
  assert.match(panel, /First \/ last seen \(UTC\)/)
  assert.match(panel, /\+\{formatNumber\(hidden\)\} more/) // incidentCount is the full count; at most 100 ids are returned
})

test('the live service calls the endpoint with the built parameters; mock mode is untouched', () => {
  const services = source('../src/services/index.ts')
  assert.match(services, /http\.get<BackendObservedTechniquePage>\('\/threat-intelligence\/techniques\/observed', observedTechniqueParams\(filters\)\)/)
  assert.match(services, /if \(USE_MOCKS\) throw new Error\('Observed techniques require the NETRA API\.'\)/)
  const page = source('../src/pages/ThreatIntelligencePage.tsx')
  assert.match(page, /\{!USE_MOCKS && <ObservedTechniquesPanel \/>\}/)
  assert.match(page, /\{USE_MOCKS && <MitreSection techniques=\{techniques\.data\} \/>\}/)
  assert.doesNotMatch(page, /Correlation data is not returned by the live API/)
})
