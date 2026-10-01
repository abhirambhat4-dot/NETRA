import { ArrowRight, Copy, Link2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import type { EventsPageItem } from '@/api/types'
import { DetailSection, DetailSheet, ErrorState, KeyValueList, LoadingState, MeterBar, SeverityBadge, StatusBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatDateTime } from '@/lib/format'
import { eventSourceMeta } from '@/lib/sources'
import { ROUTES } from '@/lib/navigation'

interface Props {
  event?: EventsPageItem
  eventId: string | null
  relatedEvents: EventsPageItem[]
  onOpenRelated: (id: string | null) => void
  onClose: () => void
  loading: boolean
  error?: Error
  onRetry: () => void
}

/**
 * Event drawer — the Summary tab answers "what is this and does it matter";
 * network, detection, anomaly and raw data are one tab away.
 */
export function EventDetailSheet({ event, eventId, relatedEvents, onOpenRelated, onClose, loading, error, onRetry }: Props) {
  return (
    <DetailSheet
      open={!!eventId}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={event ? `${event.eventUid ?? event.id} · ${formatDateTime(event.timestamp)} UTC` : eventId ?? undefined}
      title={event?.eventType ?? (loading ? 'Loading event' : 'Security event')}
      description={event?.signature ?? undefined}
    >
      {loading && !event && <LoadingState variant="inline" label="Loading event details…" />}
      {error && (
        <ErrorState
          title={error instanceof Error && 'status' in error && error.status === 401 ? 'Authentication required' : 'Event details unavailable'}
          message={error instanceof Error && 'status' in error && error.status === 401 ? undefined : error.message}
          onRetry={error instanceof Error && 'status' in error && error.status === 401 ? undefined : onRetry}
        />
      )}
      {error instanceof Error && 'status' in error && error.status === 401 && (
        <div className="-mt-8 pb-8 text-center">
          <Button asChild><Link to={ROUTES.login}>Sign in</Link></Button>
        </div>
      )}
      {event && <Body key={event.id} event={event} relatedEvents={relatedEvents} onOpenRelated={onOpenRelated} />}
    </DetailSheet>
  )
}

const TABS = [
  { value: 'summary', label: 'Summary' },
  { value: 'network', label: 'Network' },
  { value: 'detection', label: 'Detection' },
  { value: 'anomaly', label: 'Anomaly' },
  { value: 'raw', label: 'Raw' },
] as const

function anomalyReading(score: number) {
  if (score >= 0.75) return 'Highly abnormal compared with the learned behavioural baseline.'
  if (score >= 0.5) return 'Moderately unusual — worth correlating with other signals.'
  return 'Within normal variation for this source.'
}

function Body({ event: e, relatedEvents, onOpenRelated }: { event: EventsPageItem; relatedEvents: EventsPageItem[]; onOpenRelated: (id: string | null) => void }) {
  const src = eventSourceMeta(e.detectionSource)
  const anomalyTone = e.anomalyScore === null ? 'accent' : e.anomalyScore >= 0.75 ? 'critical' : e.anomalyScore >= 0.5 ? 'high' : 'accent'

  const copyRaw = () => {
    navigator.clipboard
      ?.writeText(JSON.stringify(e, null, 2))
      .then(() => toast.success('Raw event copied'))
      .catch(() => toast.error('Clipboard unavailable'))
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={e.severity} />
        <StatusBadge status={e.status} />
        <span className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-0.5 text-[11px] text-foreground/85">
          <src.icon className="size-3.5" />
          {src.label}
        </span>
      </div>

      <Tabs defaultValue="summary" className="gap-5">
        <TabsList variant="line" className="w-full justify-start gap-0 border-b border-border pb-px">
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value} className="flex-none px-2.5 text-xs">
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* SUMMARY */}
        <TabsContent value="summary" className="space-y-6 motion-safe:animate-in motion-safe:fade-in-0">
          <DetailSection title="Evidence relationship">
            <div className="relative space-y-4 pl-4 before:absolute before:inset-y-2 before:left-[5px] before:w-px before:bg-border">
              <div className="relative">
                <span className="absolute -left-4 top-1 size-2.5 rounded-full border border-primary bg-background" />
                <div className="text-[10px] font-medium text-primary">EVENT</div>
                <div className="mt-1 font-mono text-[11px] text-foreground/85">{e.id} · {e.eventType}</div>
              </div>
              <div className="relative">
                <span className="absolute -left-4 top-1 size-2.5 rounded-full border border-border bg-surface" />
                <div className="text-[10px] font-medium text-muted-foreground">RELATED EVENTS</div>
                {relatedEvents.length ? (
                  <div className="mt-1.5 space-y-1">
                    {relatedEvents.map((related) => (
                      <button
                        key={related.id}
                        type="button"
                        onClick={() => onOpenRelated(related.id)}
                        className="flex w-full items-center justify-between gap-2 rounded-sm py-1 text-left transition-colors hover:text-primary focus-visible:outline-2 focus-visible:outline-primary"
                      >
                        <span className="min-w-0 truncate text-[11px] text-foreground/85">{related.eventType}</span>
                        <span className="flex shrink-0 items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                          {related.id}<ArrowRight className="size-3" aria-hidden />
                        </span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="mt-1 text-[11px] text-muted-foreground">No sibling events share this incident correlation.</p>
                )}
              </div>
              <div className="relative">
                <span className="absolute -left-4 top-1 size-2.5 rounded-full border border-primary/60 bg-primary/15" />
                <div className="text-[10px] font-medium text-muted-foreground">INCIDENT</div>
                {e.incidentIds.length ? (
                  <div className="mt-1.5 space-y-1">
                    {e.incidentIds.map((incidentId) => (
                      <Link key={incidentId} to={ROUTES.incident(incidentId)} className="flex items-center gap-1.5 font-mono text-[11px] text-primary hover:underline">
                        <Link2 className="size-3" aria-hidden />{incidentId}
                      </Link>
                    ))}
                  </div>
                ) : (
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                    Not correlated. This event remains evidence for context and does not affect incident risk by itself.
                  </p>
                )}
              </div>
            </div>
          </DetailSection>

          <DetailSection title="Affected asset">
            {e.asset ? (
              <div className="surface-inset flex items-center justify-between gap-3 rounded-lg p-3.5">
                <div>
                  <div className="text-[13px] font-medium">{e.asset.name}</div>
                  <div className="font-mono text-[11px] text-muted-foreground">
                    {e.asset.hostname ?? '—'} · {e.asset.ipAddress ?? '—'}
                  </div>
                  <div className="mt-1 text-[10px] text-muted-foreground">{e.asset.criticality} · {e.asset.status}</div>
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No managed asset matched this event.</p>
            )}
          </DetailSection>

          <KeyValueList
            columns={2}
            items={[
              { label: 'Flow', value: `${e.sourceIp ?? '—'} → ${e.destinationIp ?? '—'}`, mono: true },
              { label: 'Anomaly score', value: e.anomalyScore === null ? '—' : `${Math.round(e.anomalyScore * 100)}%`, mono: true },
            ]}
          />
        </TabsContent>

        {/* NETWORK */}
        <TabsContent value="network" className="motion-safe:animate-in motion-safe:fade-in-0">
          <KeyValueList
            columns={2}
            items={[
              { label: 'Source IP', value: e.sourceIp ?? '—', mono: true },
              { label: 'Source port', value: e.sourcePort ?? '—', mono: true },
              { label: 'Destination IP', value: e.destinationIp ?? '—', mono: true },
              { label: 'Destination port', value: e.destinationPort ?? '—', mono: true },
              { label: 'Protocol', value: e.protocol ?? '—' },
              { label: 'Destination asset', value: e.asset?.name ?? 'Unmanaged' },
            ]}
          />
        </TabsContent>

        {/* DETECTION */}
        <TabsContent value="detection" className="space-y-5 motion-safe:animate-in motion-safe:fade-in-0">
          <KeyValueList
            columns={2}
            items={[
              { label: 'Detection source', value: src.label },
              { label: 'Detected at', value: `${formatDateTime(e.timestamp)} UTC` },
              { label: 'MITRE technique', value: e.mitreTechniqueId ?? '—', mono: true },
              { label: 'Event status', value: <StatusBadge status={e.status} size="sm" /> },
            ]}
          />
          <DetailSection title="Signature">
            {e.signature ? (
              <p className="surface-inset rounded-lg p-3.5 font-mono text-[11px] leading-relaxed text-foreground/85">{e.signature}</p>
            ) : (
              <p className="text-xs text-muted-foreground">No rule signature — raised by behavioural detection.</p>
            )}
          </DetailSection>
        </TabsContent>

        {/* ANOMALY */}
        <TabsContent value="anomaly" className="motion-safe:animate-in motion-safe:fade-in-0">
          {e.anomalyScore === null ? (
            <p className="text-xs text-muted-foreground">No anomaly score was recorded for this event.</p>
          ) : (
            <div className="surface-inset space-y-3 rounded-lg p-4">
              <div className="flex items-baseline justify-between">
                <span className="text-xs text-muted-foreground">ML anomaly score</span>
                <span className="metric text-2xl">{Math.round(e.anomalyScore * 100)}%</span>
              </div>
              <MeterBar value={e.anomalyScore * 100} tone={anomalyTone} />
              <p className="text-xs leading-relaxed text-foreground/80">{anomalyReading(e.anomalyScore)}</p>
            </div>
          )}
        </TabsContent>

        {/* RAW */}
        <TabsContent value="raw" className="space-y-2 motion-safe:animate-in motion-safe:fade-in-0">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-muted-foreground">Event record as received from the API</span>
            <Button variant="ghost" size="xs" onClick={copyRaw} className="text-muted-foreground">
              <Copy /> Copy
            </Button>
          </div>
          <pre className="surface-inset max-h-[55vh] overflow-auto rounded-lg p-3.5 font-mono text-[11px] leading-relaxed text-foreground/85">
            {JSON.stringify(e, null, 2)}
          </pre>
        </TabsContent>
      </Tabs>
    </>
  )
}
