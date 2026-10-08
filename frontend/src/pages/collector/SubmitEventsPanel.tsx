import type * as React from 'react'
import { useState } from 'react'
import { CircleAlert, CircleCheck, Copy, Loader2, Plus, Send, Trash2 } from 'lucide-react'
import type { AssetInventoryItem, CollectorSubmitResponse, Severity } from '@/api/types'
import { Disclosure, Panel, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useQuery } from '@/hooks/useQuery'
import { SEVERITY_ORDER } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetInventoryService, collectorService } from '@/services'
import { HttpError } from '@/services/http'
import {
  MAX_BATCH_EVENTS,
  newDraft,
  toSubmission,
  validateDraft,
  type DraftErrors,
  type EventDraft,
} from './eventDraft'

const NO_ASSET = 'none'
const OPTIONAL_FIELDS: (keyof EventDraft)[] = ['signature', 'srcIp', 'destIp', 'srcPort', 'destPort', 'protocol', 'anomalyScore', 'rawJson']

interface SubmittedEvent {
  label: string
  status: 'created' | 'duplicate' | 'rejected'
  reason: string | null
}

function requestErrorMessage(error: unknown): string {
  if (error instanceof HttpError) {
    if (error.status === 401) return 'Your session has expired. Sign in again to submit events.'
    if (error.status === 413) return 'Submission is too large.'
    if (error.status === 429) return 'Collector rate limit reached. Please wait before submitting more events.'
    if (error.status === 422) return `Submission rejected: ${error.message}`
  }
  return 'The collector could not be reached and the events were not confirmed. Retry to resend them safely; already received events are reported as duplicates.'
}

export function SubmitEventsPanel() {
  const [drafts, setDrafts] = useState<EventDraft[]>(() => [newDraft()])
  const [errors, setErrors] = useState<Record<string, DraftErrors>>({})
  // Bumped per draft when a submit attempt finds errors in its collapsed optional section.
  const [reveal, setReveal] = useState<Record<string, number>>({})
  const [submitting, setSubmitting] = useState(false)
  const [requestError, setRequestError] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<{ response: CollectorSubmitResponse; events: SubmittedEvent[] } | null>(null)
  const assets = useQuery('collector-assets', () => assetInventoryService.list())

  const update = (key: string, patch: Partial<EventDraft>) => {
    setDrafts((current) => current.map((draft) => (draft.key === key ? { ...draft, ...patch, rejection: undefined } : draft)))
    setErrors((current) => {
      const next = { ...current, [key]: { ...current[key] } }
      for (const field of Object.keys(patch)) delete next[key][field as keyof EventDraft]
      return next
    })
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (submitting) return
    setRequestError(null)
    const now = Date.now()
    const found = Object.fromEntries(drafts.map((draft) => [draft.key, validateDraft(draft, now)]))
    setErrors(found)
    setReveal((current) => {
      const next = { ...current }
      for (const [key, fieldErrors] of Object.entries(found)) {
        if (OPTIONAL_FIELDS.some((field) => fieldErrors[field])) next[key] = (current[key] ?? 0) + 1
      }
      return next
    })
    if (Object.values(found).some((fieldErrors) => Object.keys(fieldErrors).length > 0)) return

    const batch = drafts
    setSubmitting(true)
    try {
      const response = await collectorService.submit(batch.map(toSubmission))
      const byIndex = new Map(response.results.map((result) => [result.index, result]))
      setOutcome({
        response,
        events: batch.map((draft, index) => ({
          label: `Event ${index + 1} · ${draft.eventType.trim()}`,
          status: byIndex.get(index)?.status ?? 'rejected',
          reason: byIndex.get(index)?.reason ?? (byIndex.has(index) ? null : 'No result returned for this event.'),
        })),
      })
      // Received events leave the form; rejected ones stay, with the same key, for correction.
      const remaining = batch
        .map((draft, index) => ({ draft, result: byIndex.get(index) }))
        .filter(({ result }) => result?.status !== 'created' && result?.status !== 'duplicate')
        .map(({ draft, result }) => ({ ...draft, rejection: result?.reason ?? undefined }))
      setDrafts(remaining.length ? remaining : [newDraft()])
    } catch (cause) {
      // Drafts and their keys are kept, so retrying cannot create duplicate events.
      setRequestError(requestErrorMessage(cause))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Panel
      title="Submit events"
      description="Record operator-provided security signals. NETRA stores them as events; it does not create incidents automatically."
      actions={<ToneBadge tone="neutral" size="sm">{drafts.length} / {MAX_BATCH_EVENTS} events</ToneBadge>}
    >
      <form onSubmit={submit} className="space-y-4" noValidate aria-busy={submitting}>
        <ol className="space-y-3">
          {drafts.map((draft, index) => (
            <DraftRow
              key={draft.key}
              draft={draft}
              index={index}
              errors={errors[draft.key] ?? {}}
              revealOptional={reveal[draft.key] ?? 0}
              assets={assets.data}
              assetsError={!!assets.error}
              disabled={submitting}
              canRemove={drafts.length > 1}
              onChange={(patch) => update(draft.key, patch)}
              onRemove={() => setDrafts((current) => current.filter((item) => item.key !== draft.key))}
            />
          ))}
        </ol>

        {requestError && (
          <p role="alert" className="flex gap-2 rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">
            <CircleAlert className="mt-0.5 size-3.5 shrink-0" /> {requestError}
          </p>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={submitting || drafts.length >= MAX_BATCH_EVENTS}
            onClick={() => setDrafts((current) => [...current, newDraft()])}
          >
            <Plus /> Add event
          </Button>
          <Button type="submit" disabled={submitting}>
            {submitting ? <Loader2 className="animate-spin" /> : <Send />}
            {submitting
              ? `Submitting ${drafts.length} event${drafts.length === 1 ? '' : 's'}…`
              : `${requestError ? 'Retry submission' : 'Submit'} ${drafts.length} event${drafts.length === 1 ? '' : 's'}`}
          </Button>
        </div>
      </form>

      {outcome && <SubmissionOutcome {...outcome} />}
    </Panel>
  )
}

function DraftRow({
  draft,
  index,
  errors,
  revealOptional,
  assets,
  assetsError,
  disabled,
  canRemove,
  onChange,
  onRemove,
}: {
  draft: EventDraft
  index: number
  errors: DraftErrors
  revealOptional: number
  assets?: AssetInventoryItem[]
  assetsError: boolean
  disabled: boolean
  canRemove: boolean
  onChange: (patch: Partial<EventDraft>) => void
  onRemove: () => void
}) {
  const id = (field: string) => `event-${draft.key}-${field}`

  return (
    <li className={cn('surface-inset rounded-lg p-3.5', draft.rejection && 'border border-critical/35')}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <span className="text-xs font-medium text-foreground/85">Event {index + 1}</span>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-muted-foreground">Source <span className="font-medium text-foreground/85">MANUAL</span> — operator-provided signal</span>
          {canRemove && (
            <Button type="button" variant="ghost" size="icon-sm" disabled={disabled} onClick={onRemove} aria-label={`Remove event ${index + 1}`}>
              <Trash2 />
            </Button>
          )}
        </div>
      </div>

      {draft.rejection && (
        <p role="alert" className="mb-3 rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">
          Rejected by the collector: {draft.rejection}
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Field label="Event type" htmlFor={id('type')} error={errors.eventType} required>
          <Input id={id('type')} value={draft.eventType} maxLength={100} placeholder="e.g. suspicious_login" disabled={disabled}
            aria-invalid={!!errors.eventType} onChange={(e) => onChange({ eventType: e.target.value })} className="h-9 bg-black/20" />
        </Field>
        <Field label="Severity" htmlFor={id('severity')} error={errors.severity} required>
          <Select value={draft.severity || undefined} onValueChange={(value) => onChange({ severity: value as Severity })} disabled={disabled}>
            <SelectTrigger id={id('severity')} aria-invalid={!!errors.severity} className="h-9 w-full bg-black/20">
              <SelectValue placeholder="Select severity" />
            </SelectTrigger>
            <SelectContent>
              {SEVERITY_ORDER.map((severity) => (
                <SelectItem key={severity} value={severity}>{severity.charAt(0) + severity.slice(1).toLowerCase()}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field label="Occurred at (local time)" htmlFor={id('occurred')} error={errors.occurredAt}>
          <Input id={id('occurred')} type="datetime-local" value={draft.occurredAt} disabled={disabled}
            aria-invalid={!!errors.occurredAt} onChange={(e) => onChange({ occurredAt: e.target.value })} className="h-9 bg-black/20" />
        </Field>
        <Field label="Asset" htmlFor={id('asset')}>
          <Select value={draft.assetId || NO_ASSET} onValueChange={(value) => onChange({ assetId: value === NO_ASSET ? '' : value })} disabled={disabled}>
            <SelectTrigger id={id('asset')} className="h-9 w-full bg-black/20">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NO_ASSET}>
                {assets && assets.length === 0 ? 'No assets available' : assetsError ? 'Assets unavailable — no asset' : 'No asset'}
              </SelectItem>
              {(assets ?? []).map((asset) => (
                <SelectItem key={asset.id} value={asset.id}>
                  {asset.name} · {(asset.assetType ?? asset.type ?? 'asset').replaceAll('_', ' ').toLowerCase()} · {asset.criticality.toLowerCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
      </div>

      <Disclosure
        // Remounts open only after a submit attempt that found errors here, never while editing.
        key={`optional-${revealOptional}`}
        label="Network details and raw data"
        hint="optional"
        defaultOpen={revealOptional > 0}
        className="mt-3"
      >
        <div className="grid gap-3 pt-2 sm:grid-cols-2 xl:grid-cols-4">
          <Field label="Signature" htmlFor={id('signature')} error={errors.signature} className="sm:col-span-2">
            <Input id={id('signature')} value={draft.signature} maxLength={512} disabled={disabled} placeholder="What was observed"
              aria-invalid={!!errors.signature} onChange={(e) => onChange({ signature: e.target.value })} className="h-9 bg-black/20" />
          </Field>
          <Field label="Protocol" htmlFor={id('protocol')} error={errors.protocol}>
            <Input id={id('protocol')} value={draft.protocol} maxLength={16} disabled={disabled} placeholder="TCP"
              aria-invalid={!!errors.protocol} onChange={(e) => onChange({ protocol: e.target.value })} className="h-9 bg-black/20" />
          </Field>
          <Field label="Anomaly score (0–1)" htmlFor={id('anomaly')} error={errors.anomalyScore}>
            <Input id={id('anomaly')} type="number" inputMode="decimal" min={0} max={1} step={0.01} placeholder="0.85" disabled={disabled}
              value={draft.anomalyScore} aria-invalid={!!errors.anomalyScore} onChange={(e) => onChange({ anomalyScore: e.target.value })} className="h-9 bg-black/20" />
          </Field>
          <Field label="Source IP" htmlFor={id('src-ip')} error={errors.srcIp}>
            <Input id={id('src-ip')} value={draft.srcIp} disabled={disabled} placeholder="198.51.100.20" className="h-9 bg-black/20 font-mono"
              aria-invalid={!!errors.srcIp} onChange={(e) => onChange({ srcIp: e.target.value })} />
          </Field>
          <Field label="Source port" htmlFor={id('src-port')} error={errors.srcPort}>
            <Input id={id('src-port')} inputMode="numeric" value={draft.srcPort} disabled={disabled} placeholder="51515" className="h-9 bg-black/20 font-mono"
              aria-invalid={!!errors.srcPort} onChange={(e) => onChange({ srcPort: e.target.value })} />
          </Field>
          <Field label="Destination IP" htmlFor={id('dest-ip')} error={errors.destIp}>
            <Input id={id('dest-ip')} value={draft.destIp} disabled={disabled} placeholder="10.0.0.12" className="h-9 bg-black/20 font-mono"
              aria-invalid={!!errors.destIp} onChange={(e) => onChange({ destIp: e.target.value })} />
          </Field>
          <Field label="Destination port" htmlFor={id('dest-port')} error={errors.destPort}>
            <Input id={id('dest-port')} inputMode="numeric" value={draft.destPort} disabled={disabled} placeholder="443" className="h-9 bg-black/20 font-mono"
              aria-invalid={!!errors.destPort} onChange={(e) => onChange({ destPort: e.target.value })} />
          </Field>
          <Field label="Raw JSON data" htmlFor={id('raw')} error={errors.rawJson} className="sm:col-span-2 xl:col-span-4"
            hint="Optional JSON object. Do not paste passwords, API keys, tokens, or personal data.">
            <Textarea id={id('raw')} value={draft.rawJson} disabled={disabled} rows={3} spellCheck={false} placeholder='{"note": "observed by operator"}'
              aria-invalid={!!errors.rawJson} onChange={(e) => onChange({ rawJson: e.target.value })} className="bg-black/20 font-mono text-xs" />
          </Field>
        </div>
      </Disclosure>
    </li>
  )
}

function Field({ label, htmlFor, error, hint, required, className, children }: {
  label: string
  htmlFor: string
  error?: string
  hint?: string
  required?: boolean
  className?: string
  children: React.ReactNode
}) {
  return (
    <div className={cn('min-w-0 space-y-1.5', className)}>
      <Label htmlFor={htmlFor} className="text-[11px] text-foreground/80">
        {label}
        {required && <span className="text-muted-foreground"> (required)</span>}
      </Label>
      {children}
      {error ? (
        <p className="text-[11px] text-critical" role="alert">{error}</p>
      ) : hint ? (
        <p className="text-[11px] text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  )
}

function SubmissionOutcome({ response, events }: { response: CollectorSubmitResponse; events: SubmittedEvent[] }) {
  const summary = [
    { key: 'created', count: response.created, text: `${response.created} event${response.created === 1 ? '' : 's'} successfully received`, tone: 'text-low', icon: CircleCheck },
    { key: 'duplicate', count: response.duplicates, text: `${response.duplicates} event${response.duplicates === 1 ? ' was' : 's were'} already received`, tone: 'text-medium', icon: Copy },
    { key: 'rejected', count: response.rejected, text: `${response.rejected} event${response.rejected === 1 ? '' : 's'} could not be accepted`, tone: 'text-critical', icon: CircleAlert },
  ].filter((item) => item.count > 0)

  return (
    <section aria-live="polite" aria-label="Submission results" className="mt-4 border-t border-border pt-4">
      <div className="flex flex-wrap gap-x-5 gap-y-1.5">
        {summary.map((item) => (
          <span key={item.key} className={cn('inline-flex items-center gap-1.5 text-xs font-medium', item.tone)}>
            <item.icon className="size-3.5" />
            <span className="capitalize">{item.key}</span>
            <span className="font-normal text-muted-foreground">{item.text}</span>
          </span>
        ))}
      </div>
      <ul className="mt-3 space-y-1">
        {events.map((event, index) => (
          <li key={index} className="flex flex-wrap items-baseline gap-x-2 text-[11px]">
            <span className="text-foreground/85">{event.label}</span>
            <span className={cn('font-medium', event.status === 'created' ? 'text-low' : event.status === 'duplicate' ? 'text-medium' : 'text-critical')}>
              {event.status === 'created' ? 'received' : event.status === 'duplicate' ? 'already received' : 'rejected'}
            </span>
            {event.status === 'rejected' && event.reason && <span className="text-muted-foreground">— {event.reason}</span>}
          </li>
        ))}
      </ul>
      {response.created + response.duplicates > 0 && (
        <p className="mt-3 text-[11px] text-muted-foreground">Received events appear in Recent collected events, where you can select them for an incident.</p>
      )}
    </section>
  )
}
