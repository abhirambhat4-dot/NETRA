import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  adaptRiskEvaluation,
  factorLabel,
  latestRiskEvaluation,
  riskChange,
  riskEvaluationSummary,
  type BackendRiskEvaluation,
} from '../src/lib/riskEvaluation.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

const stored = (overrides: Partial<BackendRiskEvaluation> = {}): BackendRiskEvaluation => ({
  id: 'eval-1',
  incidentId: 'inc-1',
  methodologyVersion: 'risk-v1',
  riskScore: 51.25,
  riskLevel: 'HIGH',
  previousRiskScore: null,
  factors: {
    asset_criticality: { normalizedValue: 75, weight: 0.25, contribution: 18.75, reason: 'HIGH asset' },
    vulnerability: { normalizedValue: 60, weight: 0.2, contribution: 12, reason: 'CVSS 6' },
    anomaly: { normalizedValue: 50, weight: 0.2, contribution: 10, reason: 'anomaly' },
    detection: { normalizedValue: 70, weight: 0.15, contribution: 10.5, reason: 'ML' },
    threat_intelligence: { normalizedValue: 0, weight: 0.1, contribution: 0, reason: 'none' },
    attack_context: { normalizedValue: 0, weight: 0.1, contribution: 0, reason: 'single event' },
  },
  missingEvidence: ['No active threat-intelligence match is available; absence is not evidence of benign activity.'],
  matchedIndicators: [],
  trigger: 'initial',
  actor: 'analyst@example.com',
  createdAt: '2026-10-25T10:00:00Z',
  ...overrides,
})

test('a stored evaluation is adapted with its factors ranked by contribution', () => {
  const view = adaptRiskEvaluation(stored())
  assert.deepEqual(
    view.factors.map((factor) => [factor.label, factor.contribution]),
    [['Asset criticality', 18.75], ['Vulnerability', 12], ['Detection source', 10.5], ['Behavioural anomaly', 10], ['Threat intelligence', 0], ['Attack context', 0]],
  )
  assert.equal(view.factors[0].reason, 'HIGH asset')
  assert.deepEqual([view.riskScore, view.riskLevel, view.methodologyVersion, view.trigger, view.actor], [51.25, 'HIGH', 'risk-v1', 'initial', 'analyst@example.com'])
  assert.equal(view.missingEvidence.length, 1)
})

test('matched indicators keep their attribution', () => {
  const view = adaptRiskEvaluation(stored({
    matchedIndicators: [{ id: 'i-1', indicatorType: 'IP', value: '198.51.100.23', source: 'ThreatFox (abuse.ch)' }],
  }))
  assert.deepEqual(view.matchedIndicators, ['ThreatFox (abuse.ch): IP 198.51.100.23'])
})

test('summary, latest evaluation and score change', () => {
  assert.equal(riskEvaluationSummary(null), 'Not calculated yet')
  const first = adaptRiskEvaluation(stored())
  const second = adaptRiskEvaluation(stored({ id: 'eval-2', riskScore: 63.75, riskLevel: 'HIGH', previousRiskScore: 51.25, trigger: 'reevaluation' }))
  assert.equal(latestRiskEvaluation([]), null)
  assert.equal(latestRiskEvaluation([first, second])?.id, 'eval-2')
  assert.equal(riskEvaluationSummary(second), '63.75/100 HIGH · risk-v1')
  assert.equal(riskChange(first), null)
  assert.equal(riskChange(second), '+12.5 since the previous score (51.25)')
  assert.equal(factorLabel('new_factor'), 'new factor')
})

test('the live incident page reads stored evaluations through the read-only endpoint', () => {
  const services = source('../src/services/index.ts')
  assert.match(services, /http\.get<BackendRiskEvaluation\[\]>\(`\/incidents\/\$\{id\}\/risk-evaluations`\)/)
  const page = source('../src/pages/incident/LiveIncidentDetails.tsx')
  assert.match(page, /liveIncidentDetailsService\.riskEvaluations\(incident\.id\)/)
  assert.match(page, /<Panel title="Risk evaluations"/)
  assert.doesNotMatch(page, /label="Risk assessment" value="Unavailable from this endpoint"/)
  // Loading, error and empty states are all handled.
  assert.match(page, /riskEvaluations\.error \?/)
  assert.match(page, /No risk evaluation has been recorded yet/)
})
