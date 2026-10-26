import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const details = readFileSync(new URL('../src/pages/incident/LiveIncidentDetails.tsx', import.meta.url), 'utf8')

test('the incident page shows the latest authorization and containment attempt, not the first', () => {
  // The API allows a new request after a rejection and a new containment after a verified failure; the detail
  // response lists both oldest first, so the earlier attempts must not hide the current one.
  assert.match(details, /detail\.authorizations\.findLast\(\(item\) => item\.decisionId === decision\.id\)/)
  assert.match(details, /detail\.containmentActions\.findLast\(\(item\) => item\.authorizationId === authorization\.id\)/)
  assert.doesNotMatch(details, /detail\.(authorizations|containmentActions)\.find\(/)
})
