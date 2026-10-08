import type { CollectorEventSubmission, Severity } from '@/api/types'

/**
 * Collector form drafts. Client checks mirror the backend's limits so most mistakes are caught
 * before submitting; the API remains authoritative.
 */

export const MAX_BATCH_EVENTS = 20
const MAX_FUTURE_MS = 5 * 60_000
const MAX_AGE_MS = 30 * 24 * 60 * 60_000
const MAX_RAW_DATA_BYTES = 16 * 1024
const MAX_RAW_DATA_DEPTH = 20
const LIMITS = { eventType: 100, signature: 512, protocol: 16 } as const

export interface EventDraft {
  /** Idempotency key: created with the draft and reused for every retry of it. */
  key: string
  eventType: string
  severity: Severity | ''
  signature: string
  srcIp: string
  destIp: string
  srcPort: string
  destPort: string
  protocol: string
  anomalyScore: string
  assetId: string
  /** `datetime-local` value, interpreted in the operator's local time zone. */
  occurredAt: string
  rawJson: string
  /** Safe reason from the backend when this draft was rejected. */
  rejection?: string
}

export type DraftErrors = Partial<Record<keyof EventDraft, string>>

export function toLocalInput(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

export function newDraft(): EventDraft {
  return {
    key: crypto.randomUUID(),
    eventType: '',
    severity: '',
    signature: '',
    srcIp: '',
    destIp: '',
    srcPort: '',
    destPort: '',
    protocol: '',
    anomalyScore: '',
    assetId: '',
    occurredAt: toLocalInput(new Date()),
    rawJson: '',
  }
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const looksLikeIp = (value: string) => IPV4.test(value) || (value.includes(':') && /^[0-9a-fA-F:.]+$/.test(value))

function portError(value: string): string | undefined {
  if (!value.trim()) return undefined
  return /^\d+$/.test(value.trim()) && Number(value) <= 65535 ? undefined : 'Use a whole number from 0 to 65535.'
}

/** Iterative nesting check matching the backend: objects and arrays count, the outer object is level 1. */
function exceedsDepth(value: unknown, limit: number): boolean {
  const stack: [unknown, number][] = [[value, 1]]
  while (stack.length) {
    const [current, depth] = stack.pop()!
    if (typeof current !== 'object' || current === null) continue
    if (depth > limit) return true
    for (const child of Object.values(current)) stack.push([child, depth + 1])
  }
  return false
}

function parseRawJson(value: string): { data?: Record<string, unknown>; error?: string } {
  if (!value.trim()) return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    return { error: 'Enter valid JSON.' }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { error: 'Raw data must be a JSON object, not an array or a single value.' }
  }
  if ('collector' in parsed) return { error: '"collector" is reserved for server attribution.' }
  if (exceedsDepth(parsed, MAX_RAW_DATA_DEPTH)) {
    return { error: `rawData is nested too deeply (maximum ${MAX_RAW_DATA_DEPTH} levels)` }
  }
  if (new TextEncoder().encode(JSON.stringify(parsed)).length > MAX_RAW_DATA_BYTES) {
    return { error: 'Raw data must be 16 KB or smaller.' }
  }
  return { data: parsed as Record<string, unknown> }
}

export function validateDraft(draft: EventDraft, now = Date.now()): DraftErrors {
  const errors: DraftErrors = {}
  const eventType = draft.eventType.trim()
  if (!eventType) errors.eventType = 'Enter an event type.'
  else if (eventType.length > LIMITS.eventType) errors.eventType = `Use ${LIMITS.eventType} characters or fewer.`
  if (!draft.severity) errors.severity = 'Select a severity.'
  if (draft.signature.trim().length > LIMITS.signature) errors.signature = `Use ${LIMITS.signature} characters or fewer.`
  if (draft.protocol.trim().length > LIMITS.protocol) errors.protocol = `Use ${LIMITS.protocol} characters or fewer.`
  if (draft.srcIp.trim() && !looksLikeIp(draft.srcIp.trim())) errors.srcIp = 'Enter a valid IPv4 or IPv6 address.'
  if (draft.destIp.trim() && !looksLikeIp(draft.destIp.trim())) errors.destIp = 'Enter a valid IPv4 or IPv6 address.'
  const srcPort = portError(draft.srcPort)
  if (srcPort) errors.srcPort = srcPort
  const destPort = portError(draft.destPort)
  if (destPort) errors.destPort = destPort
  if (draft.anomalyScore.trim()) {
    const score = Number(draft.anomalyScore)
    if (!Number.isFinite(score) || score < 0 || score > 1) errors.anomalyScore = 'Enter a number from 0 to 1, e.g. 0.85.'
  }
  const occurred = new Date(draft.occurredAt).getTime()
  if (!draft.occurredAt || Number.isNaN(occurred)) errors.occurredAt = 'Enter when the event occurred.'
  else if (occurred > now + MAX_FUTURE_MS) errors.occurredAt = 'Cannot be more than 5 minutes in the future.'
  else if (occurred < now - MAX_AGE_MS) errors.occurredAt = 'Cannot be older than 30 days.'
  const raw = parseRawJson(draft.rawJson)
  if (raw.error) errors.rawJson = raw.error
  return errors
}

/** Build the API payload. Only call with a draft that passed validation; source is never sent. */
export function toSubmission(draft: EventDraft): CollectorEventSubmission {
  const optional = (value: string) => value.trim() || undefined
  const number = (value: string) => (value.trim() ? Number(value) : undefined)
  return {
    idempotencyKey: draft.key,
    occurredAt: new Date(draft.occurredAt).toISOString(),
    eventType: draft.eventType.trim(),
    severity: draft.severity as Severity,
    signature: optional(draft.signature),
    srcIp: optional(draft.srcIp),
    destIp: optional(draft.destIp),
    srcPort: number(draft.srcPort),
    destPort: number(draft.destPort),
    protocol: optional(draft.protocol),
    anomalyScore: number(draft.anomalyScore),
    assetId: optional(draft.assetId),
    rawData: parseRawJson(draft.rawJson).data,
  }
}
