import type {
  BackendImportBatchSummary,
  BackendImportPreview,
  CanonicalFieldName,
  FieldMappingRequest,
  ImportEventCoverage,
  ImportIssue,
  ImportPreviewOverrides,
  ImportRecordType,
  SuggestionConfidence,
} from '@/api/types'
import type { Tone } from '@/lib/tones'

// Dataset import helpers. Type-only imports keep this module runnable under `node --test`.

export interface ImportProfileOption {
  id: string
  label: string
  description: string
}

/** Field-mapped import of security CSVs from any source (backend: app/services/security_csv.py). */
export const SECURITY_CSV_PROFILE = 'security-csv'

/** Only profiles the backend implements (app/services/dataset_profiles.py, security_csv.py). */
export const IMPORT_PROFILES: readonly ImportProfileOption[] = [
  {
    id: SECURITY_CSV_PROFILE,
    label: 'Security CSV (map your columns)',
    description:
      'Any security CSV. NETRA previews the file and suggests which columns hold the timestamp, addresses, event type and other fields. Nothing is imported until you confirm the mapping.',
  },
  {
    id: 'generic-csv',
    label: 'Generic CSV (structure only)',
    description: 'Checks for a usable header and a consistent number of fields per row. No dataset semantics.',
  },
  {
    id: 'cic-ids2017',
    label: 'CIC-IDS2017 labelled flows (v1)',
    description:
      'Checks the exact 85-column header and each flow: addresses, ports, protocol, timestamp, label and numeric features. Rows that pass are stored as security events with their batch and row.',
  },
]

/** Backend defaults (IMPORT_MAX_UPLOAD_BYTES, IMPORT_MAX_ROWS). The API enforces the configured values. */
export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024
export const MAX_ROWS = 100_000

/** Exact multipart field names read by POST /api/imports; `mapping` is sent only for security-csv. */
export function buildImportFormData(
  file: Blob,
  filename: string,
  profile: string,
  mapping?: FieldMappingRequest,
): FormData {
  const form = new FormData()
  form.append('profile', profile)
  if (mapping) form.append('mapping', JSON.stringify(mapping))
  form.append('file', file, filename)
  return form
}

/** Exact multipart field names read by POST /api/imports/preview. */
export function buildPreviewFormData(file: Blob, filename: string, overrides: ImportPreviewOverrides = {}): FormData {
  const form = new FormData()
  if (overrides.encoding) form.append('encoding', overrides.encoding)
  if (overrides.delimiter) form.append('delimiter', overrides.delimiter)
  form.append('file', file, filename)
  return form
}

/** Client-side precheck so obviously unusable files are not sent. The API remains the authority. */
export function checkSelectedFile(file: { name: string; size: number }): string | null {
  if (!file.name.toLowerCase().endsWith('.csv')) return 'Only .csv files can be validated.'
  if (file.size > MAX_UPLOAD_BYTES) {
    return `This file is ${formatBytes(file.size)}; the upload limit is ${formatBytes(MAX_UPLOAD_BYTES)}. Split it into smaller CSV files.`
  }
  return null
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

export type ImportFailureKind =
  | 'auth'
  | 'duplicate'
  | 'tooLarge'
  | 'unsupported'
  | 'invalid'
  | 'rateLimited'
  | 'server'
  | 'network'

export interface ImportFailure {
  kind: ImportFailureKind
  title: string
  message: string
  /** Set for a duplicate the current user uploaded: the backend names it only to its uploader. */
  existingBatchId: string | null
}

const BATCH_ID_PATTERN = /import batch ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i

/**
 * Explains a failed upload. `status` is the HTTP status, or null when no response arrived; in that
 * case the outcome is unknown, so the message never claims the file was or was not recorded.
 */
export function describeImportFailure(status: number | null, detail: string): ImportFailure {
  const failure = (kind: ImportFailureKind, title: string, message: string): ImportFailure => ({
    kind,
    title,
    message,
    existingBatchId: null,
  })
  switch (status) {
    case null:
      return failure(
        'network',
        'Upload not confirmed',
        'NETRA did not respond, so the result is unknown. Check your connection and retry; a file is never validated twice.',
      )
    case 401:
      return failure('auth', 'Sign in required', 'Your session has expired. Sign in again, then upload the file.')
    case 409:
      return {
        ...failure('duplicate', 'Already validated', `${detail}. Nothing new was recorded.`),
        existingBatchId: BATCH_ID_PATTERN.exec(detail)?.[1] ?? null,
      }
    case 413:
      return failure('tooLarge', 'File too large', `${detail}. Split the file into smaller CSV files and validate each one.`)
    case 415:
      return failure('unsupported', 'Unsupported file', 'Only CSV files (.csv) can be validated.')
    case 422:
      return failure('invalid', 'Upload not accepted', detail)
    case 429:
      return failure('rateLimited', 'Rate limit reached', 'At most 10 uploads per minute. Wait a minute, then try again.')
    default:
      return failure('server', 'Validation failed', `NETRA could not validate the file (${detail}). Try again later.`)
  }
}

export interface ImportOutcome {
  tone: Tone
  label: string
  summary: string
}

/** Result shown only after the API has confirmed and recorded the batch. */
export function describeImportOutcome(batch: BackendImportBatchSummary): ImportOutcome {
  const rows = `${batch.totalRows} data row${batch.totalRows === 1 ? '' : 's'}`
  if (batch.status === 'REJECTED') {
    return { tone: 'critical', label: 'File rejected', summary: 'The file could not be validated. See the issues below.' }
  }
  if (batch.rejectedRows > 0) {
    return {
      tone: 'medium',
      label: 'Validated with row errors',
      summary: `${batch.acceptedRows} of ${rows} passed; ${batch.rejectedRows} failed validation.`,
    }
  }
  return { tone: 'low', label: 'Validated', summary: `All ${rows} passed validation.` }
}

/**
 * What the batch stored, or null when nothing was (rejected file, or a validation-only profile).
 * Only rows that passed validation are ever stored; duplicates of existing events are counted, not stored.
 */
export function describeStoredRows(batch: BackendImportBatchSummary): string | null {
  const created = batch.eventsCreated ?? 0
  const duplicates = batch.duplicateRows ?? 0
  if (batch.status !== 'VALIDATED' || created + duplicates === 0) return null
  const events = `${created.toLocaleString('en-US')} accepted row${created === 1 ? '' : 's'} stored as security event${created === 1 ? '' : 's'}`
  return duplicates > 0
    ? `${events}; ${duplicates.toLocaleString('en-US')} duplicate${duplicates === 1 ? '' : 's'} of existing events not stored again.`
    : `${events}.`
}

/** Where an imported event came from, or null for events that did not come from a dataset upload. */
export function eventProvenance(event: { importBatchId?: string | null; sourceRow?: number | null }): {
  batchId: string
  row: number
  label: string
} | null {
  if (!event.importBatchId || event.sourceRow == null) return null
  return { batchId: event.importBatchId, row: event.sourceRow, label: `File row ${event.sourceRow.toLocaleString('en-US')}` }
}

export function statusTone(batch: BackendImportBatchSummary): Tone {
  return describeImportOutcome(batch).tone
}

/** "Row 3 · column alpha", "Row 1 · column 4", or "File". */
export function issueLocation(issue: ImportIssue): string {
  const parts: string[] = []
  if (issue.row !== null) parts.push(`Row ${issue.row}`)
  if (issue.column !== null) parts.push(`column ${issue.column}`)
  else if (issue.columnIndex !== null) parts.push(`column ${issue.columnIndex}`)
  if (parts.length === 0) return 'File'
  const [first, ...rest] = parts
  return [first.charAt(0).toUpperCase() + first.slice(1), ...rest].join(' · ')
}

// ---------------------------------------------------------------------------
// Security CSV field mapping
// ---------------------------------------------------------------------------

/** The user's working mapping; an empty string means "not mapped" or "not chosen". */
export interface MappingDraft {
  recordType: ImportRecordType
  fields: Partial<Record<CanonicalFieldName, string>>
  timestampFormat: string
  utcOffset: string
  encoding: string
  delimiter: string
  defaultEventType: string
}

export const UTC_OFFSET_PATTERN = /^[+-](0\d|1[0-4]):[0-5]\d$/
const DEFAULT_EVENT_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 _.:/-]*$/

export const CONFIDENCE_META: Record<SuggestionConfidence, { label: string; tone: Tone }> = {
  high: { label: 'Detected', tone: 'low' },
  low: { label: 'Check', tone: 'medium' },
  ambiguous: { label: 'Ambiguous', tone: 'medium' },
  none: { label: 'Not found', tone: 'neutral' },
}

/**
 * Starting point for the mapping form. Only high-confidence suggestions (column name and sampled values
 * agree) are preselected; everything else is left for the user, so nothing is silently guessed.
 */
export function initialDraft(preview: BackendImportPreview): MappingDraft {
  const fields: Partial<Record<CanonicalFieldName, string>> = {}
  for (const suggestion of preview.suggestions) {
    if (suggestion.confidence === 'high' && suggestion.column) fields[suggestion.field] = suggestion.column
  }
  return {
    recordType: preview.suggestedRecordType,
    fields,
    timestampFormat: preview.suggestedTimestampFormat ?? '',
    utcOffset: '+00:00',
    encoding: preview.encoding,
    delimiter: preview.delimiter,
    defaultEventType: '',
  }
}

/** Header names that can be mapped: blank and repeated names cannot be addressed by name. */
export function mappableColumns(preview: BackendImportPreview): string[] {
  return preview.columns.filter((column) => column.mappable).map((column) => column.name)
}

export function requiredFields(preview: BackendImportPreview, recordType: ImportRecordType): CanonicalFieldName[] {
  return preview.recordTypes.find((type) => type.name === recordType)?.required ?? []
}

/** Why the draft cannot be imported yet; empty when it is complete. Mirrors the API's FieldMapping checks. */
export function draftProblems(draft: MappingDraft, preview: BackendImportPreview): string[] {
  const problems: string[] = []
  const label = (name: CanonicalFieldName) => preview.fields.find((field) => field.name === name)?.label ?? name
  const typeTitle = preview.recordTypes.find((type) => type.name === draft.recordType)?.title ?? draft.recordType
  const defaultType = draft.defaultEventType.trim()
  for (const name of requiredFields(preview, draft.recordType)) {
    if (draft.fields[name]) continue
    if (name !== 'event_type') problems.push(`${label(name)} is required for ${typeTitle} records: choose its column.`)
    else if (!defaultType) {
      problems.push(`${label(name)} is required for ${typeTitle} records: choose its column or enter a default event type.`)
    }
  }
  if (!draft.timestampFormat) problems.push('Choose the timestamp format.')
  if (!UTC_OFFSET_PATTERN.test(draft.utcOffset)) problems.push('The UTC offset must look like +00:00 or -05:30.')
  if (!draft.fields.event_type && defaultType && (defaultType.length > 100 || !DEFAULT_EVENT_TYPE_PATTERN.test(defaultType))) {
    problems.push('The default event type may use letters, digits, spaces and _ . : / - (up to 100 characters).')
  }
  const seen = new Map<string, CanonicalFieldName>()
  for (const [name, column] of Object.entries(draft.fields) as [CanonicalFieldName, string][]) {
    if (!column) continue
    const first = seen.get(column.toLowerCase())
    if (first) problems.push(`Column "${column}" is mapped to both ${label(first)} and ${label(name)}.`)
    else seen.set(column.toLowerCase(), name)
  }
  return problems
}

/** The confirmed draft as the API's mapping field; unmapped fields are omitted. */
export function draftToMapping(draft: MappingDraft): FieldMappingRequest {
  const fields: Partial<Record<CanonicalFieldName, string>> = {}
  for (const [name, column] of Object.entries(draft.fields) as [CanonicalFieldName, string][]) {
    if (column) fields[name] = column
  }
  const mapping: FieldMappingRequest = {
    recordType: draft.recordType,
    fields,
    timestampFormat: draft.timestampFormat,
    utcOffset: draft.utcOffset,
    encoding: draft.encoding,
    delimiter: draft.delimiter,
  }
  const defaultType = draft.defaultEventType.trim()
  if (!fields.event_type && defaultType) mapping.defaultEventType = defaultType
  return mapping
}

/** Plain-language notes on what the stored events can and cannot support. */
export function describeCoverage(coverage: ImportEventCoverage): string[] {
  const notes: string[] = []
  const events = (count: number) => `${count.toLocaleString('en-US')} event${count === 1 ? '' : 's'}`
  if (coverage.linkedToAsset > 0) {
    notes.push(`${events(coverage.linkedToAsset)} matched a registered asset by IP address and can inform that asset's Security Assessment.`)
  }
  if (coverage.addressWithoutAsset > 0) {
    notes.push(`${events(coverage.addressWithoutAsset)} have IP addresses that match no single registered asset, so no asset assessment uses them.`)
  }
  if (coverage.withoutAddress > 0) {
    notes.push(
      `${events(coverage.withoutAddress)} have no IP address. They are listed as events but cannot be linked to an asset, so Security Assessment cannot use them.`,
    )
  }
  return notes
}

const DELIMITER_LABELS: Record<string, string> = { ',': 'Comma', ';': 'Semicolon', '\t': 'Tab', '|': 'Pipe' }

export function delimiterLabel(value: string): string {
  return DELIMITER_LABELS[value] ?? value
}
