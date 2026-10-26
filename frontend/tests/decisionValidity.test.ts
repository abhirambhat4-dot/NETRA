import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  canVerifyIncident,
  currentDecisions,
  currentLatestDecision,
  decisionValidityLabel,
  verificationBlockedReason,
} from '../src/lib/incidentVerification.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')
const decision = (id: string, validity: 'CURRENT' | 'SUPERSEDED' | 'REJECTED') => ({ id, validity })

test('only current decisions count toward verification', () => {
  const history = [decision('old', 'SUPERSEDED'), decision('rejected', 'REJECTED')]
  assert.deepEqual(currentDecisions([...history, decision('now', 'CURRENT')]).map((d) => d.id), ['now'])
  assert.equal(canVerifyIncident('PRIORITISED', currentDecisions(history).length), false)
  assert.equal(canVerifyIncident('PRIORITISED', currentDecisions([...history, decision('now', 'CURRENT')]).length), true)
})

test('blocked verification is explained, and only when it is blocked', () => {
  assert.match(verificationBlockedReason('PRIORITISED', [decision('old', 'SUPERSEDED')])!, /needs a current decision.*recommend a new decision/)
  assert.match(verificationBlockedReason('PRIORITISED', [decision('r', 'REJECTED')])!, /needs a current decision/)
  assert.equal(verificationBlockedReason('PRIORITISED', []), null) // the "Recommend decision" action is the guide here
  assert.equal(verificationBlockedReason('PRIORITISED', [decision('old', 'SUPERSEDED'), decision('now', 'CURRENT')]), null)
  assert.equal(verificationBlockedReason('VERIFIED', [decision('old', 'SUPERSEDED')]), null)
})

test('decisions are labelled current, superseded (with both scores) or rejected', () => {
  assert.equal(decisionValidityLabel('CURRENT', 60, 60), 'Current decision')
  assert.equal(decisionValidityLabel('SUPERSEDED', 60, 72.5), "Superseded · made for risk 60; the incident's risk is now 72.5")
  assert.match(decisionValidityLabel('REJECTED', 60, 60), /^Rejected/)
})

test('summaries use the latest decision only when it is current', () => {
  const current = { ...decision('d', 'CURRENT'), action: 'MONITOR' }
  assert.equal(currentLatestDecision(current), current)
  assert.equal(currentLatestDecision({ ...current, validity: 'SUPERSEDED' as const }), null)
  assert.equal(currentLatestDecision({ ...current, validity: 'REJECTED' as const }), null)
  assert.equal(currentLatestDecision(null), null)
  for (const page of ['../src/pages/CommandCenterPage.tsx', '../src/pages/IncidentsPage.tsx']) {
    assert.match(source(page), /currentLatestDecision\(/, page)
  }
  // attention.ts stays dependency-free for node --test; its own test pins the superseded case.
  assert.match(source('../src/lib/attention.ts'), /latestDecision\?\.validity === 'CURRENT' \? incident\.latestDecision\.confidence : undefined/)
})

test('the incident page offers actions by decision validity', () => {
  const page = source('../src/pages/incident/LiveIncidentDetails.tsx')
  // "Request authorization" only for a current decision; never for a superseded one.
  assert.match(page, /\{decision\?\.validity === 'CURRENT' &&\s*\(incident\.state === 'PRIORITISED' \|\| incident\.state === 'VERIFIED'\) &&\s*!authorization &&/)
  // "Recommend decision" when PRIORITISED without a current decision; verification needs one.
  assert.match(page, /incident\.state === 'PRIORITISED' && current\.length === 0 && \(/)
  assert.match(page, /canVerifyIncident\(incident\.state, current\.length\) && \(/)
  assert.doesNotMatch(page, /canVerifyIncident\(incident\.state, detail\.decisions\.length\)/)
  assert.match(page, /\{verificationBlocked && <p className="text-xs text-muted-foreground">\{verificationBlocked\}<\/p>\}/)
  assert.match(page, /decisionValidityLabel\(decision\.validity, decision\.riskScore, incident\.riskScore\)/)
})

test('the decision type carries every field the backend decision response returns', () => {
  const schema = source('../../backend/app/schemas/core.py')
  const body = schema.split('class DecisionResponse(')[1].split(/\nclass /)[0]
  const camel = (name: string) => name.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
  const fields = [...body.matchAll(/^ {4}([a-z_]+): /gm)].map((match) => camel(match[1]))
  const types = source('../src/api/types.ts').split('export interface BackendIncidentDecisionResponse {')[1].split('\n}\n')[0]
  assert.ok(fields.includes('validity'))
  for (const field of fields) assert.match(types, new RegExp(`\\b${field}\\??:`), field)
  assert.match(source('../../backend/app/schemas/core.py'), /validity: Literal\["CURRENT", "SUPERSEDED", "REJECTED"\]/)
})
