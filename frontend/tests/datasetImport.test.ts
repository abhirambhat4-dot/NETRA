import assert from 'node:assert/strict'
import test from 'node:test'
import type { BackendImportBatchSummary } from '../src/api/types.ts'
import {
  IMPORT_PROFILES,
  MAX_UPLOAD_BYTES,
  checkSelectedFile,
  describeImportFailure,
  describeImportOutcome,
  formatBytes,
  issueLocation,
} from '../src/lib/datasetImport.ts'

const BATCH_ID = '0b9c2a3e-5d41-4c1f-9a7e-2f3d4b5c6d7e'

function batch(overrides: Partial<BackendImportBatchSummary> = {}): BackendImportBatchSummary {
  return {
    id: BATCH_ID,
    datasetProfile: 'generic-csv',
    profileVersion: '1',
    originalFilename: 'flows.csv',
    fileSha256: 'a'.repeat(64),
    fileSizeBytes: 20,
    status: 'VALIDATED',
    totalRows: 3,
    acceptedRows: 3,
    rejectedRows: 0,
    errorTotal: 0,
    createdAt: '2026-10-11T12:00:00Z',
    completedAt: '2026-10-11T12:00:01Z',
    ...overrides,
  }
}

test('only implemented profiles are offered', () => {
  assert.deepEqual(IMPORT_PROFILES.map((profile) => profile.id), ['generic-csv', 'cic-ids2017'])
})

test('file precheck accepts .csv within the limit and explains anything else', () => {
  assert.equal(checkSelectedFile({ name: 'flows.csv', size: 10 }), null)
  assert.equal(checkSelectedFile({ name: 'FLOWS.CSV', size: MAX_UPLOAD_BYTES }), null)
  assert.match(checkSelectedFile({ name: 'flows.xlsx', size: 10 }) ?? '', /Only \.csv files/)
  const oversized = checkSelectedFile({ name: 'Friday-DDos.csv', size: 96_101_069 }) ?? ''
  assert.match(oversized, /91\.6 MiB/)
  assert.match(oversized, /25\.0 MiB/)
})

test('formatBytes uses binary units', () => {
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(2048), '2.0 KiB')
  assert.equal(formatBytes(MAX_UPLOAD_BYTES), '25.0 MiB')
})

test('a confirmed clean batch reads as validated', () => {
  assert.deepEqual(describeImportOutcome(batch()), { tone: 'low', label: 'Validated', summary: 'All 3 data rows passed validation.' })
})

test('row errors and file rejections are not reported as success', () => {
  const partial = describeImportOutcome(batch({ acceptedRows: 1, rejectedRows: 2, errorTotal: 2 }))
  assert.equal(partial.tone, 'medium')
  assert.equal(partial.label, 'Validated with row errors')
  assert.equal(partial.summary, '1 of 3 data rows passed; 2 failed validation.')

  const rejected = describeImportOutcome(batch({ status: 'REJECTED', totalRows: 0, acceptedRows: 0, errorTotal: 1 }))
  assert.equal(rejected.tone, 'critical')
  assert.equal(rejected.label, 'File rejected')
})

test('no response means the outcome is unknown, never success', () => {
  const failure = describeImportFailure(null, 'Failed to fetch')
  assert.equal(failure.kind, 'network')
  assert.equal(failure.title, 'Upload not confirmed')
  assert.match(failure.message, /result is unknown/)
})

test('HTTP failures map to specific states', () => {
  const cases: [number, string, string][] = [
    [401, 'Could not validate credentials', 'auth'],
    [413, 'File exceeds the upload limit of 26214400 bytes', 'tooLarge'],
    [415, 'Only CSV files (.csv) are accepted', 'unsupported'],
    [422, 'profile is not a known dataset profile', 'invalid'],
    [429, 'Import rate limit exceeded. Try again in a minute.', 'rateLimited'],
    [500, 'Request failed (500)', 'server'],
  ]
  for (const [status, detail, kind] of cases) assert.equal(describeImportFailure(status, detail).kind, kind, `status ${status}`)
  assert.match(describeImportFailure(413, 'File has more than 100000 data rows').message, /100000 data rows/)
  assert.equal(describeImportFailure(422, 'profile is required').message, 'profile is required')
})

test('duplicates link to the existing batch only when the API names it', () => {
  const own = describeImportFailure(409, `This file has already been validated with this dataset profile (import batch ${BATCH_ID})`)
  assert.equal(own.kind, 'duplicate')
  assert.equal(own.existingBatchId, BATCH_ID)

  const other = describeImportFailure(409, 'This file has already been validated with this dataset profile')
  assert.equal(other.existingBatchId, null)
})

test('issue locations use the row, the profile column name, or the column position', () => {
  const issue = { rule: 'r', message: 'm', row: null, column: null, columnIndex: null }
  assert.equal(issueLocation({ ...issue, row: 3, column: 'alpha' }), 'Row 3 · column alpha')
  assert.equal(issueLocation({ ...issue, row: 1, columnIndex: 4 }), 'Row 1 · column 4')
  assert.equal(issueLocation({ ...issue, row: 6 }), 'Row 6')
  assert.equal(issueLocation({ ...issue, column: 'beta' }), 'Column beta')
  assert.equal(issueLocation(issue), 'File')
})
