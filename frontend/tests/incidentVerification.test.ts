import assert from 'node:assert/strict'
import test from 'node:test'
import {
  canVerifyIncident,
  shouldRefreshAfterVerifyError,
  verifyIncidentPath,
} from '../src/lib/incidentVerification.ts'
import { buildRequestInit } from '../src/services/httpRequest.ts'

const INCIDENT_ID = '0b9c2a3e-5d41-4c1f-9a7e-2f3d4b5c6d7e'
const STATES = ['DETECTED', 'UNDERSTOOD', 'PRIORITISED', 'VERIFIED', 'AUTHORIZED', 'CONTAINED', 'LEARNED']

test('a PRIORITISED incident with a stored decision can be verified', () => {
  assert.equal(canVerifyIncident('PRIORITISED', 1), true)
  assert.equal(canVerifyIncident('PRIORITISED', 3), true)
})

test('a PRIORITISED incident without a decision cannot be verified', () => {
  assert.equal(canVerifyIncident('PRIORITISED', 0), false)
})

test('no other state can be verified, with or without a decision', () => {
  for (const decisions of [0, 1]) {
    assert.deepEqual(STATES.filter((state) => canVerifyIncident(state, decisions)), decisions ? ['PRIORITISED'] : [])
  }
})

test('verify targets the backend endpoint for the incident', () => {
  assert.equal(verifyIncidentPath(INCIDENT_ID), `/incidents/${INCIDENT_ID}/verify`)
  assert.equal(verifyIncidentPath('a/b'), '/incidents/a%2Fb/verify')
})

test('verify is a bodyless authenticated POST', async () => {
  const init = buildRequestInit('POST', 'token-1')
  const request = new Request(`http://127.0.0.1:8000/api${verifyIncidentPath(INCIDENT_ID)}`, init)
  assert.equal(request.method, 'POST')
  assert.equal(request.headers.get('authorization'), 'Bearer token-1')
  assert.equal(new URL(request.url).pathname, `/api/incidents/${INCIDENT_ID}/verify`)
  assert.equal(await request.text(), '')
})

test('only a 409 conflict triggers a reload of the incident', () => {
  assert.equal(shouldRefreshAfterVerifyError(409), true)
  for (const status of [null, 401, 404, 422, 500]) assert.equal(shouldRefreshAfterVerifyError(status), false, String(status))
})
