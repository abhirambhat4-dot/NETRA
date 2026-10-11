import type { BackendImportBatchSummary, ImportIssue } from '@/api/types'
import type { Tone } from '@/lib/tones'

// Dataset import helpers. Type-only imports keep this module runnable under `node --test`.

export interface ImportProfileOption {
  id: string
  label: string
  description: string
}

/** Only profiles the backend implements (app/services/dataset_profiles.py). */
export const IMPORT_PROFILES: readonly ImportProfileOption[] = [
  {
    id: 'generic-csv',
    label: 'Generic CSV (structure only)',
    description: 'Checks for a usable header and a consistent number of fields per row. No dataset semantics.',
  },
  {
    id: 'cic-ids2017',
    label: 'CIC-IDS2017 labelled flows (v1)',
    description:
      'Checks the exact 85-column header and each flow: addresses, ports, protocol, timestamp, label and numeric features. Validation only.',
  },
]

/** Backend defaults (IMPORT_MAX_UPLOAD_BYTES, IMPORT_MAX_ROWS). The API enforces the configured values. */
export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024
export const MAX_ROWS = 100_000

/** Exact multipart field names read by POST /api/imports. */
export function buildImportFormData(file: Blob, filename: string, profile: string): FormData {
  const form = new FormData()
  form.append('profile', profile)
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
