import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Link2 } from 'lucide-react'
import type { BackendEventSource, EventStatus, EventsPageItem, Severity } from '@/api/types'
import {
  EmptyState,
  ErrorState,
  FilterChips,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  Pagination,
  SearchInput,
  SelectFilter,
  SeverityBadge,
  StatusBadge,
  SurfaceCard,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useCountUp } from '@/hooks/useCountUp'
import { useNow } from '@/hooks/useNow'
import { useQuery } from '@/hooks/useQuery'
import { formatClock, formatNumber, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { BACKEND_EVENT_SOURCES, eventSourceMeta } from '@/lib/sources'
import { SEVERITY_ORDER, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { eventService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { EventDetailSheet } from './events/EventDetailSheet'

const PAGE_SIZE = 14
type SevFilter = Severity | 'ALL'
type SrcFilter = BackendEventSource | 'HYBRID' | 'ALL'
type StatusFilter = EventStatus | 'ALL'
const EVENT_SOURCES = USE_MOCKS ? [...BACKEND_EVENT_SOURCES, 'HYBRID' as const] : BACKEND_EVENT_SOURCES

export function SecurityEventsPage() {
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState(params.get('q') ?? '')
  const [severity, setSeverity] = useState<SevFilter>('ALL')
  const [source, setSource] = useState<SrcFilter>('ALL')
  const [status, setStatus] = useState<StatusFilter>('ALL')
  const [page, setPage] = useState(1)
  const now = useNow(60_000)

  const events = useQuery('events-all', () => eventService.listForEventsPage())

  const all = useMemo(() => events.data?.items ?? [], [events.data])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all.filter(
      (e) =>
        (severity === 'ALL' || e.severity === severity) &&
        (source === 'ALL' || e.detectionSource === source) &&
        (status === 'ALL' || e.status === status) &&
        (!q ||
          [e.id, e.eventType, e.signature, e.sourceIp, e.destinationIp, ...e.incidentIds, e.asset?.name, e.asset?.hostname, e.asset?.ipAddress]
            .filter(Boolean)
            .some((f) => String(f).toLowerCase().includes(q))),
    )
  }, [all, search, severity, source, status])

  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const selectedId = params.get('event')
  const selected = all.find((e) => e.id === selectedId)
  const eventDetail = useQuery(
    `event-detail-${selectedId ?? 'none'}`,
    () => selectedId ? eventService.getForEventsPage(selectedId) : Promise.resolve(undefined),
  )
  const relatedEvents = selected
    ? all
        .filter((event) => event.id !== selected.id && event.incidentIds.some((id) => selected.incidentIds.includes(id)))
        .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
        .slice(0, 5)
    : []

  const resetPage = <T,>(set: (v: T) => void) => (v: T) => {
    set(v)
    setPage(1)
  }
  const openEvent = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('event', id)
    else next.delete('event')
    setParams(next, { replace: true })
  }

  const count = (pred: (e: EventsPageItem) => boolean) => all.filter(pred).length
  const correlated = count((e) => e.status === 'CORRELATED')
  const filtersActive = severity !== 'ALL' || source !== 'ALL' || status !== 'ALL' || search !== ''
  const criticalHigh = count((e) => e.severity === 'CRITICAL' || e.severity === 'HIGH')
  const sourceCount = new Set(all.map((event) => event.detectionSource)).size
  const totalAnimated = useCountUp(all.length, 700)
  const priorityAnimated = useCountUp(criticalHigh, 700)
  const sourcesAnimated = useCountUp(sourceCount, 700)
  const correlatedAnimated = useCountUp(correlated, 700)

  return (
    <PageContainer>
      <PageHeader
        eyebrow={`Evidence stream · ${events.data ? `${filtered.length} matching events` : 'loading event context'}`}
        title="SECURITY EVENTS"
        description="Investigate the signals behind each situation. Events are evidence; correlation connects them to incidents."
      />

      <MetricStrip
        metrics={[
          {
            label: 'Total events',
            value: events.data ? formatNumber(Math.round(totalAnimated)) : '—',
            hint: events.data ? `${count((e) => e.status === 'NEW')} awaiting triage` : 'Event data unavailable',
          },
          {
            label: 'Critical / high',
            value: events.data ? formatNumber(Math.round(priorityAnimated)) : '—',
            valueClassName: 'text-high',
            hint: `${count((e) => e.severity === 'CRITICAL')} critical · ${count((e) => e.severity === 'HIGH')} high`,
          },
          {
            label: 'Detection sources',
            value: events.data ? Math.round(sourcesAnimated) : '—',
            valueClassName: 'text-cyan',
            hint: events.data ? [...new Set(all.map((event) => event.detectionSource))].map((s) => eventSourceMeta(s).short).join(' · ') : 'Event data unavailable',
          },
          {
            label: 'Correlated events',
            value: events.data ? formatNumber(Math.round(correlatedAnimated)) : '—',
            hint: events.data ? `${all.length ? Math.round((correlated / all.length) * 100) : 0}% linked to incidents` : 'Event data unavailable',
          },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden" data-guide-target="event-stream">
        {/* Filter bar */}
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex items-baseline justify-between gap-3">
            <div>
              <h2 className="text-[15px] font-semibold tracking-tight">Evidence feed</h2>
              <p className="mt-0.5 text-xs text-muted-foreground">Detection signals with their asset and network context</p>
            </div>
            <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
              {filtered.length} of {all.length}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput
              value={search}
              onChange={resetPage(setSearch)}
              placeholder="Search IP, event, signature, incident…"
              className="w-full sm:w-80"
            />
            <SelectFilter
              label="Source"
              value={source}
              onChange={resetPage(setSource)}
              options={[{ value: 'ALL', label: 'All' }, ...EVENT_SOURCES.map((s) => ({ value: s, label: eventSourceMeta(s).short }))]}
            />
            <SelectFilter
              label="Status"
              value={status}
              onChange={resetPage(setStatus)}
              options={[
                { value: 'ALL', label: 'All' },
                { value: 'NEW', label: 'New' },
                { value: 'CORRELATED', label: 'Correlated' },
                ...(USE_MOCKS ? [{ value: 'DISMISSED' as const, label: 'Dismissed' }] : []),
              ]}
            />
            {!USE_MOCKS && <span className="text-[11px] text-muted-foreground">Dismissed status is unavailable from the live API.</span>}
            {filtersActive && (
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                onClick={() => {
                  setSearch('')
                  setSeverity('ALL')
                  setSource('ALL')
                  setStatus('ALL')
                  setPage(1)
                }}
              >
                Clear filters
              </Button>
            )}
          </div>
          <FilterChips
            aria-label="Severity"
            value={severity}
            onChange={resetPage(setSeverity)}
            options={[
              { value: 'ALL', label: 'All severities', count: all.length },
              ...SEVERITY_ORDER.map((s) => ({
                value: s,
                label: s.charAt(0) + s.slice(1).toLowerCase(),
                count: count((e) => e.severity === s),
                dot: toneStyles[severityTone[s]].solid,
              })),
            ]}
          />
        </div>

          {events.error ? (
          <div>
            <ErrorState
              title={events.error instanceof HttpError && events.error.status === 401 ? 'Authentication required' : 'Security events unavailable'}
              message={events.error instanceof HttpError && events.error.status === 401 ? undefined : events.error.message}
              onRetry={events.error instanceof HttpError && events.error.status === 401 ? undefined : events.reload}
            />
            {events.error instanceof HttpError && events.error.status === 401 && (
              <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
            )}
          </div>
        ) : !events.data ? (
          <LoadingState className="p-5" count={10} />
        ) : filtered.length === 0 ? (
          <EmptyState
            title={all.length ? 'No events match these filters' : 'No security events'}
            description={all.length ? 'Try widening the severity, source, status or search filters.' : 'No security events are available in the current event feed.'}
          />
        ) : (
          <>
            <ol aria-label="Security event evidence feed">
              {pageItems.map((e, index) => {
                const src = eventSourceMeta(e.detectionSource)
                const flow = [e.sourceIp, e.destinationIp].filter(Boolean).join(' → ') || 'No network flow recorded'
                return (
                  <li
                    key={`${e.id}-${severity}-${source}-${status}-${search}`}
                    className={cn(
                      'group relative border-b border-border/60 px-4 py-3.5 transition-colors last:border-b-0 hover:bg-foreground/2.5 sm:px-5',
                      selectedId === e.id && 'bg-primary/6',
                      'motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1',
                    )}
                    style={{ animationDelay: `${Math.min(index, 8) * 35}ms` }}
                  >
                    <span aria-hidden className={cn('absolute inset-y-3 left-0 w-0.5 opacity-70 transition-opacity group-hover:opacity-100', toneStyles[severityTone[e.severity]].solid)} />
                    <div className="flex flex-col gap-2.5">
                      <button
                        type="button"
                        aria-label={`${e.severity} ${e.eventType}, open event details`}
                        onClick={() => openEvent(e.id)}
                        className="grid w-full grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-2 text-left outline-none focus-visible:ring-2 focus-visible:ring-primary/50 md:grid-cols-[auto_minmax(0,1.25fr)_minmax(105px,.7fr)_minmax(125px,.8fr)] xl:grid-cols-[auto_minmax(0,1.25fr)_minmax(105px,.7fr)_minmax(125px,.8fr)_minmax(170px,1fr)_minmax(90px,.55fr)]"
                      >
                        <span className="pt-0.5"><SeverityBadge severity={e.severity} size="sm" /></span>
                        <span className="min-w-0">
                          <span className="block truncate text-[13px] font-medium text-foreground/95 transition-colors group-hover:text-primary">{e.eventType}</span>
                          <span className="mt-1 block truncate text-[11px] text-muted-foreground">
                            <span className="font-mono text-foreground/70">{e.eventUid ?? e.id}</span> · {e.signature ?? (e.anomalyScore === null ? 'No signature or anomaly score' : `Anomaly score ${Math.round(e.anomalyScore * 100)}%`)}
                          </span>
                        </span>
                        <span className="hidden min-w-0 md:block">
                          <span className="block text-[10px] text-muted-foreground">DETECTION ENGINE</span>
                          <span className="mt-1 inline-flex items-center gap-1.5 truncate text-xs text-foreground/85">
                            <span className="size-1.5 shrink-0 rounded-full" style={{ background: src.color }} />{src.short}
                          </span>
                        </span>
                        <span className="hidden min-w-0 md:block">
                          <span className="block text-[10px] text-muted-foreground">AFFECTED ASSET</span>
                          <span className="mt-1 block truncate text-xs text-foreground/85">{e.asset?.name ?? 'Unmanaged source'}</span>
                        </span>
                        <span className="hidden min-w-0 xl:block">
                          <span className="block text-[10px] text-muted-foreground">NETWORK FLOW</span>
                          <span className="mt-1 block truncate font-mono text-[11px] text-foreground/75">{flow}</span>
                        </span>
                        <span className="hidden text-right xl:block">
                          <span className="block font-mono text-xs text-foreground/90 tabular-nums">{formatClock(e.timestamp)}</span>
                          <span className="mt-1 block text-[10px] text-muted-foreground">{timeAgo(e.timestamp, now.getTime())}</span>
                        </span>
                      </button>
                      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 pl-0 md:pl-11 xl:hidden">
                        <span className="min-w-0 truncate text-[10px] text-foreground/75 md:hidden">
                          {src.short} · {e.asset?.name ?? 'Unmanaged source'}
                        </span>
                        <span className="max-w-full truncate font-mono text-[10px] text-muted-foreground">{flow}</span>
                        <span className="inline-flex items-center gap-1.5 text-[10px] text-muted-foreground">
                          {formatClock(e.timestamp)} · {timeAgo(e.timestamp, now.getTime())}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center justify-between gap-2 pl-0 md:pl-11">
                        <span className="inline-flex items-center gap-2 text-[10px] text-muted-foreground">
                          <StatusBadge status={e.status} size="sm" />
                          <span>Correlation</span>
                        </span>
                        {e.incidentIds.length > 0 ? (
                          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[10px] text-primary/90">
                            <Link2 className="size-3" aria-hidden />
                            <span className="font-sans text-muted-foreground">Incident</span>
                            {e.incidentIds.map((incidentId) => (
                              <Link key={incidentId} to={ROUTES.incident(incidentId)} className="underline-offset-2 hover:underline">
                                {incidentId}
                              </Link>
                            ))}
                          </div>
                        ) : (
                          <span className="text-[10px] text-muted-foreground">Uncorrelated evidence</span>
                        )}
                      </div>
                    </div>
                  </li>
                )
              })}
            </ol>
            <div className="border-t border-border">
              <Pagination page={page} pageSize={PAGE_SIZE} total={filtered.length} onChange={setPage} />
            </div>
          </>
        )}
      </SurfaceCard>

      <EventDetailSheet
        event={eventDetail.error ? undefined : eventDetail.data ?? selected}
        eventId={selectedId}
        relatedEvents={relatedEvents}
        onOpenRelated={openEvent}
        onClose={() => openEvent(null)}
        loading={Boolean(selectedId && eventDetail.loading)}
        error={eventDetail.error}
        onRetry={eventDetail.reload}
      />
    </PageContainer>
  )
}
