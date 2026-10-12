import assert from 'node:assert/strict'
import test from 'node:test'
import { assessmentAsOf } from '../src/lib/assessment.ts'

const NOW = new Date('2026-10-12T10:00:00Z')

test('an empty window end means the API default (now)', () => {
  assert.deepEqual(assessmentAsOf('', NOW), {})
  assert.deepEqual(assessmentAsOf('   ', NOW), {})
})

test('a past date ends the event window at the end of that UTC day', () => {
  assert.deepEqual(assessmentAsOf('2017-07-07', NOW), { asOf: '2017-07-07T23:59:59Z' })
})

test("today's date is sent as now, because the API refuses a future asOf", () => {
  assert.deepEqual(assessmentAsOf('2026-10-12', NOW), {})
})

test('future, malformed and impossible dates are refused before any request', () => {
  assert.equal(assessmentAsOf('2026-10-13', NOW).error, 'The event window cannot end in the future.')
  assert.equal(assessmentAsOf('07/07/2017', NOW).error, 'Use a date in YYYY-MM-DD format.')
  assert.equal(assessmentAsOf('2017-02-30', NOW).error, 'Enter a valid calendar date.')
})
