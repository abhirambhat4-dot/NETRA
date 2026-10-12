import assert from 'node:assert/strict'
import test from 'node:test'
import type { BackendImportBatchSummary, BackendImportPreview } from '../src/api/types.ts'
import {
  CONFIDENCE_META,
  IMPORT_PROFILES,
  MAX_UPLOAD_BYTES,
  buildImportFormData,
  buildPreviewFormData,
  checkSelectedFile,
  delimiterLabel,
  describeCoverage,
  draftProblems,
  draftToMapping,
  initialDraft,
  mappableColumns,
  requiredFields,
  describeImportFailure,
  describeImportOutcome,
  describeStoredRows,
  eventProvenance,
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
    eventsCreated: 0,
    duplicateRows: 0,
    createdAt: '2026-10-11T12:00:00Z',
    completedAt: '2026-10-11T12:00:01Z',
    ...overrides,
  }
}

test('only implemented profiles are offered, field-mapped Security CSV first', () => {
  assert.deepEqual(IMPORT_PROFILES.map((profile) => profile.id), ['security-csv', 'generic-csv', 'cic-ids2017'])
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

test('stored rows are described only when a validated batch stored or deduplicated events', () => {
  assert.equal(describeStoredRows(batch()), null)
  assert.equal(describeStoredRows(batch({ status: 'REJECTED', acceptedRows: 0 })), null)
  assert.equal(describeStoredRows(batch({ eventsCreated: 1 })), '1 accepted row stored as security event.')
  assert.equal(
    describeStoredRows(batch({ eventsCreated: 2, duplicateRows: 1 })),
    '2 accepted rows stored as security events; 1 duplicate of existing events not stored again.',
  )
})

test('event provenance is shown only for events that name both their import batch and file row', () => {
  assert.deepEqual(eventProvenance({ importBatchId: BATCH_ID, sourceRow: 1234 }), {
    batchId: BATCH_ID,
    row: 1234,
    label: 'File row 1,234',
  })
  assert.equal(eventProvenance({ importBatchId: null, sourceRow: null }), null)
  assert.equal(eventProvenance({}), null)
  assert.equal(eventProvenance({ importBatchId: BATCH_ID, sourceRow: null }), null)
})

// --- Security CSV field mapping -----------------------------------------------------------------

function preview(overrides: Partial<BackendImportPreview> = {}): BackendImportPreview {
  return {
    originalFilename: 'auth.csv',
    fileSizeBytes: 100,
    fileSha256: 'b'.repeat(64),
    encoding: 'utf-8',
    encodingConfident: true,
    delimiter: ';',
    delimiterConfident: true,
    columns: [
      { index: 1, name: 'Event Time', mappable: true, inferredKind: 'timestamp', nonEmpty: 3 },
      { index: 2, name: 'Source', mappable: true, inferredKind: 'text', nonEmpty: 3 },
      { index: 3, name: 'Kind', mappable: true, inferredKind: 'text', nonEmpty: 3 },
      { index: 4, name: '', mappable: false, inferredKind: 'text', nonEmpty: 1 },
    ],
    rows: [["2024-05-01T10:00:00Z", 'web-01', 'login', "'=1+1"]],
    sampledRows: 1,
    moreRows: false,
    suggestedRecordType: 'security_event',
    suggestions: [
      { field: 'occurred_at', column: 'Event Time', columnIndex: 1, confidence: 'high', reason: 'agree', candidates: [] },
      { field: 'src_ip', column: 'Source', columnIndex: 2, confidence: 'low', reason: 'values do not fit', candidates: [] },
      { field: 'event_type', column: null, columnIndex: null, confidence: 'ambiguous', reason: 'several', candidates: ['Kind', 'Type'] },
    ],
    suggestedTimestampFormat: 'iso8601',
    timestampFormatCandidates: ['iso8601'],
    timestampHasZone: true,
    recognizedProfile: null,
    warnings: [],
    needsReview: true,
    alreadyImported: false,
    alreadyImportedBatchId: null,
    fields: [
      { name: 'occurred_at', label: 'Timestamp', kind: 'timestamp', description: '' },
      { name: 'event_type', label: 'Event type', kind: 'text', description: '' },
      { name: 'src_ip', label: 'Source IP', kind: 'ip', description: '' },
      { name: 'dest_ip', label: 'Destination IP', kind: 'ip', description: '' },
    ],
    recordTypes: [
      { name: 'security_event', title: 'Security event', description: '', required: ['occurred_at', 'event_type'] },
      { name: 'network_flow', title: 'Network flow', description: '', required: ['occurred_at', 'src_ip', 'dest_ip'] },
    ],
    timestampFormats: [{ name: 'iso8601', label: 'ISO 8601' }],
    encodings: ['utf-8', 'utf-16', 'cp1252', 'iso-8859-1'],
    delimiters: [{ value: ',', label: 'Comma' }, { value: ';', label: 'Semicolon' }],
    ...overrides,
  }
}

test('only high-confidence suggestions are preselected; low and ambiguous ones wait for the user', () => {
  const draft = initialDraft(preview())
  assert.deepEqual(draft.fields, { occurred_at: 'Event Time' })
  assert.equal(draft.recordType, 'security_event')
  assert.equal(draft.timestampFormat, 'iso8601')
  assert.equal(draft.delimiter, ';')
  assert.equal(draft.utcOffset, '+00:00')
  assert.equal(initialDraft(preview({ suggestedTimestampFormat: null })).timestampFormat, '')
})

test('blank and repeated header names are not offered for mapping', () => {
  assert.deepEqual(mappableColumns(preview()), ['Event Time', 'Source', 'Kind'])
})

test('missing required fields explain what to choose for the selected record type', () => {
  const p = preview()
  const draft = initialDraft(p)
  assert.deepEqual(draftProblems(draft, p), [
    'Event type is required for Security event records: choose its column or enter a default event type.',
  ])
  assert.deepEqual(draftProblems({ ...draft, defaultEventType: 'authentication' }, p), [])
  assert.deepEqual(draftProblems({ ...draft, recordType: 'network_flow' }, p), [
    'Source IP is required for Network flow records: choose its column.',
    'Destination IP is required for Network flow records: choose its column.',
  ])
  assert.deepEqual(requiredFields(p, 'network_flow'), ['occurred_at', 'src_ip', 'dest_ip'])
})

test('format, offset, default type and duplicate columns are checked before import', () => {
  const p = preview()
  const draft = { ...initialDraft(p), fields: { occurred_at: 'Event Time', event_type: 'Kind' } }
  assert.deepEqual(draftProblems({ ...draft, timestampFormat: '' }, p), ['Choose the timestamp format.'])
  assert.deepEqual(draftProblems({ ...draft, utcOffset: '5:30' }, p), ['The UTC offset must look like +00:00 or -05:30.'])
  assert.deepEqual(draftProblems({ ...draft, fields: { ...draft.fields, src_ip: 'kind' } }, p), [
    'Column "kind" is mapped to both Event type and Source IP.',
  ])
  const noType = { ...draft, fields: { occurred_at: 'Event Time' }, defaultEventType: '=cmd' }
  assert.match(draftProblems(noType, p)[0], /default event type may use/)
})

test('the confirmed draft becomes the API mapping without empty fields', () => {
  const p = preview()
  const draft = { ...initialDraft(p), fields: { occurred_at: 'Event Time', src_ip: '', event_type: '' }, defaultEventType: ' auth ' }
  assert.deepEqual(draftToMapping(draft), {
    recordType: 'security_event',
    fields: { occurred_at: 'Event Time' },
    timestampFormat: 'iso8601',
    utcOffset: '+00:00',
    encoding: 'utf-8',
    delimiter: ';',
    defaultEventType: 'auth',
  })
  // A default event type is sent only when no column is mapped to event_type.
  assert.equal(draftToMapping({ ...draft, fields: { occurred_at: 'Event Time', event_type: 'Kind' } }).defaultEventType, undefined)
})

test('the mapping travels as one JSON form field next to the profile and file', () => {
  const mapping = draftToMapping({ ...initialDraft(preview()), defaultEventType: 'auth' })
  const form = buildImportFormData(new Blob(['a']), 'auth.csv', 'security-csv', mapping)
  assert.equal(form.get('profile'), 'security-csv')
  assert.deepEqual(JSON.parse(String(form.get('mapping'))), mapping)
  assert.equal(buildImportFormData(new Blob(['a']), 'f.csv', 'cic-ids2017').get('mapping'), null)
  const previewForm = buildPreviewFormData(new Blob(['a']), 'auth.csv', { delimiter: '\t' })
  assert.equal(previewForm.get('delimiter'), '\t')
  assert.equal(previewForm.get('encoding'), null)
  assert.ok(previewForm.get('file') instanceof Blob)
})

test('coverage notes say which events Security Assessment can and cannot use', () => {
  assert.deepEqual(describeCoverage({ events: 3, linkedToAsset: 1, addressWithoutAsset: 0, withoutAddress: 2 }), [
    "1 event matched a registered asset by IP address and can inform that asset's Security Assessment.",
    '2 events have no IP address. They are listed as events but cannot be linked to an asset, so Security Assessment cannot use them.',
  ])
  assert.deepEqual(describeCoverage({ events: 0, linkedToAsset: 0, addressWithoutAsset: 0, withoutAddress: 0 }), [])
})

test('confidence labels never present a guess as detected', () => {
  assert.equal(CONFIDENCE_META.high.label, 'Detected')
  assert.notEqual(CONFIDENCE_META.low.label, 'Detected')
  assert.notEqual(CONFIDENCE_META.ambiguous.label, 'Detected')
  assert.equal(delimiterLabel('\t'), 'Tab')
})
