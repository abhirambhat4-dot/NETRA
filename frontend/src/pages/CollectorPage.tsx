import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRight, MonitorSmartphone, RadioTower, ServerOff } from 'lucide-react'
import type { CollectorStatus, EventsPageItem } from '@/api/types'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  Panel,
  SeverityBadge,
  StatusDot,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { useQuery } from '@/hooks/useQuery'
import { formatDateTime, formatNumber, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { eventSourceMeta } from '@/lib/sources'
import { collectorService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { CreateIncidentBar } from './collector/CreateIncidentBar'
import { SubmitEventsPanel } from './collector/SubmitEventsPanel'

const REFRESH_INTERVAL_MS = 15_000
const DESCRIPTION = "Capture security signals directly into NETRA's intelligence pipeline."

export function CollectorPage() {
  return USE_MOCKS ? <CollectorUnavailable /> : <LiveCollectorPage />
}

function LiveCollectorPage() {
  const { data, error, reload } = useQuery('collector-status', collectorService.getStatus)
  const unauthorized = error instanceof HttpError && error.status === 401
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(() => new Set())
  // Only events currently displayed by the collector can be selected.
  const selected = (data?.recentEvents ?? []).filter((event) => selectedIds.has(event.id))
  const toggle = (id: string, checked: boolean) =>
    setSelectedIds((current) => {
      const next = new Set(current)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })

  // Poll while mounted; skip hidden tabs so background pages do not keep requesting.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') reload()
    }, REFRESH_INTERVAL_MS)
    return () => window.clearInterval(id)
  }, [reload])

  return (
    <PageContainer>
      <PageHeader eyebrow="Intake" title="Live Event Collector" description={DESCRIPTION} />

      <MetricStrip metrics={statusMetrics(data, error)} />

      <SubmitEventsPanel />

      <div className="grid items-start gap-4 xl:grid-cols-12">
        <CollectorIdentity className="xl:col-span-4" />

        <Panel
          title="Recent collected events"
          description="Latest events received by the collector · select events to create an incident, or open one for its full record"
          flush
          className="xl:col-span-8"
        >
          {error ? (
            <div>
              <ErrorState
                title={unauthorized ? 'Authentication required' : 'Collector status unavailable'}
                message={unauthorized ? undefined : error.message}
                onRetry={unauthorized ? undefined : reload}
              />
              {unauthorized && (
                <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
              )}
            </div>
          ) : !data ? (
            <LoadingState className="px-5 pt-1" count={5} label="Loading collector status…" />
          ) : data.totalEvents === 0 ? (
            <EmptyState
              icon={RadioTower}
              title="No collector events received yet."
              description="Events appear here after the collector receives its first submission."
            />
          ) : (
            <>
              <ul className="border-t border-border">
                {data.recentEvents.map((event, index) => (
                  <CollectedEventRow
                    key={event.id}
                    event={event}
                    entryIndex={index}
                    selected={selectedIds.has(event.id)}
                    onSelectedChange={(checked) => toggle(event.id, checked)}
                  />
                ))}
              </ul>
              <CreateIncidentBar selected={selected} onClearSelection={() => setSelectedIds(new Set())} />
            </>
          )}
        </Panel>
      </div>
    </PageContainer>
  )
}

function statusMetrics(data: CollectorStatus | undefined, error: Error | undefined) {
  const status = error ? 'Error' : data ? (data.status === 'receiving' ? 'Receiving' : 'Idle') : '—'
  const statusTone = error ? 'critical' : data?.status === 'receiving' ? 'low' : 'neutral'
  const value = (metric: (status: CollectorStatus) => string) => (error || !data ? '—' : metric(data))
  return [
    {
      label: 'Collector status',
      value: (
        <span className="inline-flex items-center gap-2">
          {(error || data) && <StatusDot tone={statusTone} pulse={!error && data?.status === 'receiving'} />}
          {status}
        </span>
      ),
      valueClassName: error ? 'text-critical' : data?.status === 'receiving' ? 'text-low' : undefined,
      hint: error ? 'status request failed' : 'receiving = an event in the last 5 minutes',
    },
    { label: 'Total events', value: value((s) => formatNumber(s.totalEvents)), hint: 'received by the web collector' },
    { label: 'Events · 24h', value: value((s) => formatNumber(s.eventsLast24h)), hint: 'received in the last 24 hours' },
    {
      label: 'Last received',
      value: value((s) => (s.lastReceivedAt ? timeAgo(s.lastReceivedAt) : 'Never')),
      hint: data?.lastReceivedAt && !error ? `${formatDateTime(data.lastReceivedAt)} UTC` : 'no submission recorded',
    },
  ]
}

function CollectorIdentity({ className }: { className?: string }) {
  const manual = eventSourceMeta('MANUAL')
  return (
    <Panel title="NETRA Web Collector" description="Browser-based event intake" className={className}>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <ToneBadge tone="accent" size="sm">
            <MonitorSmartphone className="size-3" /> Browser-based
          </ToneBadge>
          <ToneBadge tone="neutral" size="sm">
            <manual.icon className="size-3" /> Source: MANUAL
          </ToneBadge>
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">
          Browser-submitted events are treated as operator-provided signals and enter NETRA as MANUAL events.
          They are not verified telemetry; NETRA weighs them as unconfirmed input during risk calculation.
        </p>
        <dl className="surface-inset divide-y divide-border/70 rounded-lg text-xs">
          <div className="flex items-center justify-between gap-3 px-3.5 py-2.5">
            <dt className="text-muted-foreground">Intake</dt>
            <dd className="text-right">Signed-in NETRA operators</dd>
          </div>
          <div className="flex items-center justify-between gap-3 px-3.5 py-2.5">
            <dt className="text-muted-foreground">Pipeline</dt>
            <dd className="text-right">Security Events → incident workflow</dd>
          </div>
          <div className="flex items-center justify-between gap-3 px-3.5 py-2.5">
            <dt className="text-muted-foreground">Status refresh</dt>
            <dd className="text-right">Every {REFRESH_INTERVAL_MS / 1000} seconds</dd>
          </div>
        </dl>
      </div>
    </Panel>
  )
}

function CollectedEventRow({ event: e, entryIndex, selected, onSelectedChange }: {
  event: EventsPageItem
  entryIndex: number
  selected: boolean
  onSelectedChange: (checked: boolean) => void
}) {
  const src = eventSourceMeta(e.detectionSource)
  return (
    <li
      className={`flex items-center border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1 ${selected ? 'bg-primary/6' : ''}`}
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 35}ms` }}
    >
      <div className="flex shrink-0 items-center self-stretch pl-5">
        <Checkbox
          checked={selected}
          onCheckedChange={(value) => onSelectedChange(value === true)}
          aria-label={`Select ${e.eventType} event ${(e.eventUid ?? e.id).slice(-8)} for an incident`}
        />
      </div>
      <Link
        to={`${ROUTES.events}?event=${e.id}`}
        className="group grid min-w-0 flex-1 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 py-3 pr-5 pl-3.5 transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_auto_16px]"
      >
        <div className="min-w-0">
          <div className="truncate text-[13px] font-medium">{e.eventType}</div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground" title={e.eventUid}>
            {e.eventUid}
          </div>
        </div>
        <div className="min-w-0 text-[11px] text-muted-foreground max-md:col-span-2 max-md:row-start-2">
          <span className="inline-flex items-center gap-1 text-foreground/75">
            <src.icon className="size-3" /> {src.short}
          </span>
          <span className="text-muted-foreground/40"> · </span>
          <span>{e.asset?.name ?? 'No asset'}</span>
          <span className="text-muted-foreground/40"> · </span>
          <time dateTime={e.timestamp} title={`${formatDateTime(e.timestamp)} UTC`}>{timeAgo(e.timestamp)}</time>
        </div>
        <SeverityBadge severity={e.severity} size="sm" />
        <ChevronRight className="size-4 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground max-md:hidden" />
      </Link>
    </li>
  )
}

function CollectorUnavailable() {
  return (
    <PageContainer>
      <PageHeader eyebrow="Intake" title="Live Event Collector" description={DESCRIPTION} />
      <Panel title="NETRA Web Collector" description="Browser-based event intake">
        <EmptyState
          icon={ServerOff}
          title="Live Event Collector requires the NETRA API."
          description="The collector is unavailable in demo mode. Collector activity is never simulated, because fake telemetry would be misleading. Run NETRA against the API to use it."
        />
      </Panel>
    </PageContainer>
  )
}
