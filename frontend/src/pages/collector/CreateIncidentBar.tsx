import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CircleAlert, Loader2, ShieldPlus } from 'lucide-react'
import { toast } from 'sonner'
import type { EventsPageItem, IncidentCreateRequest } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ROUTES } from '@/lib/navigation'
import { SEVERITY_ORDER } from '@/lib/tones'
import { collectorService } from '@/services'
import { HttpError } from '@/services/http'

const TITLE_MAX_LENGTH = 255

function byOccurrence(left: EventsPageItem, right: EventsPageItem) {
  return Date.parse(left.timestamp) - Date.parse(right.timestamp) || left.id.localeCompare(right.id)
}

function defaultTitle(events: EventsPageItem[]): string {
  const types = [...new Set(events.map((event) => event.eventType))]
  const asset = events.find((event) => event.asset)?.asset?.name
  const subject = types.length > 2 ? `${types.slice(0, 2).join(', ')} +${types.length - 2}` : types.join(', ')
  return `[Collector] ${subject}${asset ? ` on ${asset}` : ''}`.slice(0, TITLE_MAX_LENGTH)
}

/**
 * Hands selected collector events to the existing POST /api/incidents. Only the earliest event is
 * linked: correlation in Incident Details links the related ones, so the workflow can progress.
 */
export function CreateIncidentBar({ selected, onClearSelection }: {
  selected: EventsPageItem[]
  onClearSelection: () => void
}) {
  const navigate = useNavigate()
  const [title, setTitle] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const ordered = [...selected].sort(byOccurrence)
  const earliest = ordered[0]
  const assetIds = new Set(ordered.map((event) => event.assetId).filter(Boolean))
  const effectiveTitle = (title ?? (selected.length ? defaultTitle(ordered) : '')).trim()

  async function create() {
    if (!earliest || creating || !effectiveTitle) return
    setCreating(true)
    setError(null)
    const severity = SEVERITY_ORDER.find((level) => ordered.some((event) => event.severity === level))
    const request: IncidentCreateRequest = {
      title: effectiveTitle,
      description: `Created from ${ordered.length} NETRA Web Collector event${ordered.length === 1 ? '' : 's'} (operator-provided signals).`,
      severity,
      detectionSource: 'MANUAL',
      assetId: earliest.assetId ?? ordered.find((event) => event.assetId)?.assetId ?? undefined,
      eventIds: [earliest.id],
    }
    try {
      const incident = await collectorService.createIncident(request)
      toast.success(`Incident ${incident.incidentKey} created`, { description: 'Continue the workflow in Incident Details.' })
      onClearSelection()
      setTitle(null)
      navigate(ROUTES.incident(incident.id))
    } catch (cause) {
      // Selection is kept so the operator can retry; nothing claims an incident was created.
      setError(
        cause instanceof HttpError && cause.status === 429
          ? 'Too many requests. Please wait and try again.'
          : 'The incident could not be created. Your selection is kept; try again.',
      )
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="space-y-3 border-t border-border px-5 py-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1 space-y-1.5 sm:min-w-64">
          <Label htmlFor="collector-incident-title" className="text-[11px] text-foreground/80">Incident title</Label>
          <Input
            id="collector-incident-title"
            value={title ?? (selected.length ? defaultTitle(ordered) : '')}
            onChange={(event) => setTitle(event.target.value)}
            maxLength={TITLE_MAX_LENGTH}
            disabled={!selected.length || creating}
            placeholder="Select events to create an incident"
            className="h-9 bg-black/20"
          />
        </div>
        <span className="pb-2 text-xs text-muted-foreground" aria-live="polite">Selected: {selected.length}</span>
        <Button onClick={create} disabled={!selected.length || creating || !effectiveTitle}>
          {creating ? <Loader2 className="animate-spin" /> : <ShieldPlus />}
          {creating ? 'Creating incident…' : 'Create incident from selected events'}
        </Button>
      </div>

      {selected.length > 0 && (
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          The incident starts at DETECTED and links the earliest selected event. Run correlation in Incident Details to link
          the other selected events that share its asset and an IP address within 30 minutes.
          {assetIds.size > 1 && ' The selection spans several assets; events on other assets will not be correlated.'}
        </p>
      )}

      {error && (
        <p role="alert" className="flex gap-2 rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">
          <CircleAlert className="mt-0.5 size-3.5 shrink-0" /> {error}
        </p>
      )}
    </div>
  )
}
