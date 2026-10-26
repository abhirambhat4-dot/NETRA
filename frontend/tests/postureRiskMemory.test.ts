import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { LEGACY_RISK_HISTORY_MESSAGE, riskEvaluationSummary } from '../src/lib/riskEvaluation.ts'
import { effectivenessLabel, memorySummary } from '../src/lib/workspaceSummary.ts'
import type { CyberMemoryEntry } from '../src/api/types.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

test('a scored incident without stored evaluations is described as legacy, not as unscored', () => {
  assert.equal(riskEvaluationSummary(null, 42.5), '42.5/100 · scored before evaluation history was recorded')
  assert.equal(riskEvaluationSummary(null, null), 'Not calculated yet')
  assert.equal(riskEvaluationSummary(null), 'Not calculated yet')
  assert.match(LEGACY_RISK_HISTORY_MESSAGE, /not recalculated automatically/)
  const page = source('../src/pages/incident/LiveIncidentDetails.tsx')
  assert.match(page, /riskEvaluationSummary\(latestEvaluation, incident\.riskScore\)/)
  assert.match(page, /incident\.riskScore != null \? LEGACY_RISK_HISTORY_MESSAGE : 'No risk evaluation has been recorded yet/)
})

test('unknown effectiveness is stated as unknown and never counted as effective', () => {
  assert.equal(effectivenessLabel('UNKNOWN'), 'effectiveness unknown')
  assert.equal(effectivenessLabel('PARTIALLY_EFFECTIVE'), 'partially effective')
  const entry = (effectiveness: string): CyberMemoryEntry => ({
    id: effectiveness, incidentId: null, threatName: null, mitreTechniqueId: null, sourceIp: null, assetId: null, riskScore: null,
    actionTaken: null, outcome: null, lessonsLearned: '', tags: null, similarIncidentIds: null, recordedAt: '2026-10-25T00:00:00Z', effectiveness,
  } as CyberMemoryEntry)
  assert.equal(memorySummary([entry('UNKNOWN'), entry('UNKNOWN'), entry('EFFECTIVE')]).effective, 1)
  for (const page of ['../src/pages/CyberMemoryPage.tsx', '../src/pages/SecurityWorkspacePage.tsx']) {
    assert.match(source(page), /effectivenessLabel\(/, page)
    assert.doesNotMatch(source(page), /effectiveness\.replaceAll\('_', ' '\)/, page)
  }
})

test('the dashboard count is labelled by incident severity, which is what it counts', () => {
  const page = source('../src/pages/CommandCenterPage.tsx')
  assert.match(page, /'Critical-severity incidents'/)
  assert.doesNotMatch(page, /'Critical incidents'/)
  assert.match(source('../../backend/app/api/dashboard.py'), /Incident\.severity == Severity\.CRITICAL/)
})

test('the Cyber Memory type carries every field the backend response returns', () => {
  const schema = source('../../backend/app/schemas/core.py')
  const body = schema.split('class CyberMemoryResponse(')[1].split(/\nclass /)[0]
  const camel = (name: string) => name.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
  const fields = [...body.matchAll(/^ {4}([a-z_]+): /gm)].map((match) => camel(match[1]))
  const types = source('../src/api/types.ts').split('export interface BackendCyberMemoryResponse {')[1].split('\n}\n')[0]
  assert.ok(fields.includes('authorizationId') && fields.includes('containmentId'))
  for (const field of fields) assert.match(types, new RegExp(`\\b${field}\\??:`), field)
})
