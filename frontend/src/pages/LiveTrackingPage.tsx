import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { CircleCheck, Inbox, RadioTower, ServerOff, ShieldAlert } from 'lucide-react'
import type { CollectorStatus } from '@/api/types'
import { EmptyState, LoadingState, MetricStrip, PageContainer, PageHeader, Panel, SurfaceCard, type Metric } from '@/components/netra'
import { useHealthPoll } from '@/hooks/useHealthPoll'
import { useQuery } from '@/hooks/useQuery'
import {
  collectorActivityAttention,
  collectorIdleNote,
  demoExclusionNote,
  hiddenIncidentsNote,
  incidentAttention,
  isDemoEvent,
  isDemoIncident,
  liveCollectorEvents,
  liveEmptyState,
  severityMix,
  unlinkedEventAttention,
} from '@/lib/attention'
import { formatDateTime, formatNumber, timeAgo } from '@/lib/format'
import { HEALTH_REFRESH_MS } from '@/lib/healthPoller'
import { ROUTES } from '@/lib/navigation'
import { apiHealthState, databaseHealthState, type ApiHealthState, type DatabaseHealthState, type HealthOutcome } from '@/lib/workspaceStatus'
import { collectorService, eventService, incidentQueueService } from '@/services'
import { USE_MOCKS } from '@/services/http'
import { AttentionList, ListNotes, PanelError, SeverityBreakdown, StatusRow, type StatusItem } from './workspaces/shared'

/** Same cycle as the shared health reading in the header and sidebar. */
const REFRESH_INTERVAL_MS = HEALTH_REFRESH_MS
/** Rows per dashboard list; each list links to its full page. */
const LIST_LIMIT = 5
const DESCRIPTION = 'Live collector activity, service health, and the active incidents and events that need attention now.'

export function LiveTrackingPage() {
  return USE_MOCKS ? <LiveTrackingUnavailable /> : <LiveTracking />
}

/**
 * HIGH and CRITICAL events no incident covers yet; one API page each. `complete` is true when those
 * pages held every matching event, so counts taken from `items` are exact.
 */
async function listUnlinkedHighSeverityEvents() {
  const [critical, high] = await Promise.all(
    (['CRITICAL', 'HIGH'] as const).map((severity) =>
      eventService.listForEventsPage({ severity, status: 'NEW' }, { maxEvents: LIST_LIMIT }),
    ),
  )
  return {
    items: [...critical.items, ...high.items],
    complete: critical.items.length >= critical.total && high.items.length >= high.total,
  }
}

const PENDING = '—'
const UNAVAILABLE = 'Unavailable'
const MUTED_VALUE = 'text-base text-muted-foreground'

function LiveTracking() {
  const collector = useQuery('live-collector-status', collectorService.getStatus)
  // Shared with the header and sidebar: one health request set per 15 s, not one per component.
  const healthReading = useHealthPoll()
  const incidents = useQuery('live-prioritized-incidents', incidentQueueService.listPrioritized)
  const events = useQuery('live-unlinked-events', listUnlinkedHighSeverityEvents)
  const reloads = [collector.reload, incidents.reload, events.reload]

  // Same cadence as the collector page; hidden tabs do not poll.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') reloads.forEach((reload) => reload())
    }, REFRESH_INTERVAL_MS)
    return () => window.clearInterval(id)
    // reload callbacks are stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Demo seed records (explicitly marked, see isDemoIncident/isDemoEvent) are not operational alerts:
  // they are left out of the lists and the counts, and the number left out is stated.
  const demoIncidentIds = new Set((incidents.data?.incidents ?? []).filter(isDemoIncident).map((incident) => incident.id))
  const prioritized = (incidents.data?.prioritized ?? []).filter((entry) => !demoIncidentIds.has(entry.incidentId))
  const demoIncidents = (incidents.data?.prioritized.length ?? 0) - prioritized.length
  const genuineEvents = (events.data?.items ?? []).filter((event) => !isDemoEvent(event))
  const demoEvents = (events.data?.items.length ?? 0) - genuineEvents.length
  const incidentItems = incidents.data ? incidentAttention(prioritized, incidents.data.incidents) : []
  const eventItems = unlinkedEventAttention(genuineEvents)
  const hiddenNote = hiddenIncidentsNote(prioritized.length, incidentItems.length)
  // Exact when every matching event was loaded; otherwise at least this many.
  const eventCount = `${formatNumber(eventItems.length)}${events.data?.complete ? '' : '+'}`
  const incidentDemoNote = demoExclusionNote(demoIncidents, 0)
  const eventDemoNote = demoExclusionNote(0, demoEvents)
  const mix = severityMix(prioritized)

  const recentCollected = collector.data ? collectorActivityAttention(collector.data.recentEvents, LIST_LIMIT) : []
  // Severity of incoming events: only the latest events the collector status returns carry a severity,
  // so this covers those (stated as such), never a 24-hour total.
  const incoming = collector.data ? liveCollectorEvents(collector.data.recentEvents) : []
  const collectedDemoNote = demoExclusionNote(0, collector.data ? collector.data.recentEvents.filter(isDemoEvent).length : 0)

  const metrics: Metric[] = [
    {
      label: 'Active incidents',
      value: incidents.error ? UNAVAILABLE : incidents.data ? formatNumber(prioritized.length) : PENDING,
      hint: incidents.data && !incidents.error ? `${formatNumber(mix.CRITICAL)} critical · ${formatNumber(mix.HIGH)} high` : 'Ranked by NETRA prioritisation',
      valueClassName: incidents.error ? MUTED_VALUE : mix.CRITICAL > 0 ? 'text-critical' : undefined,
    },
    {
      label: 'Unlinked high / critical',
      value: events.error ? UNAVAILABLE : events.data ? eventCount : PENDING,
      hint: 'Live events not yet in an incident',
      valueClassName: events.error ? MUTED_VALUE : eventItems.length > 0 ? 'text-high' : undefined,
    },
    {
      label: 'Live events · 24h',
      value: collector.error ? UNAVAILABLE : collector.data ? formatNumber(collector.data.eventsLast24h) : PENDING,
      hint: 'Received by the Live Event Collector',
      valueClassName: collector.error ? MUTED_VALUE : undefined,
    },
    {
      label: 'Live events · all time',
      value: collector.error ? UNAVAILABLE : collector.data ? formatNumber(collector.data.totalEvents) : PENDING,
      hint: collector.data?.lastReceivedAt ? `Last received ${timeAgo(collector.data.lastReceivedAt)}` : collector.data ? 'None received yet' : undefined,
      valueClassName: collector.error ? MUTED_VALUE : undefined,
    },
  ]

  return (
    <PageContainer>
      <PageHeader icon={RadioTower} eyebrow="Monitoring" title="Live Tracking" description={DESCRIPTION} />

      {collector.data && collector.data.status === 'idle' && (
        <FeedNotice neverReceived={collector.data.totalEvents === 0} note={collectorIdleNote(collector.data.totalEvents)} />
      )}

      <StatusRow
        label="Live status"
        items={statusItems(collector.data, collector.error, healthReading?.mode === 'live' ? healthReading.checks : undefined)}
        footer={collector.data && collector.data.importedEventsTotal > 0 ? <ImportedNote total={collector.data.importedEventsTotal} /> : undefined}
      />

      <MetricStrip metrics={metrics} />

      <div className="grid items-start gap-4 lg:grid-cols-3">
        <Panel
          className="lg:col-span-2"
          title="Active incidents"
          description="Incidents being handled now, highest priority first."
          actions={<Link to={ROUTES.incidents} className="text-[12px] font-medium text-primary hover:underline">All incidents</Link>}
          flush
        >
          {incidents.error ? (
            <PanelError error={incidents.error} title="Active incidents unavailable" onRetry={incidents.reload} />
          ) : !incidents.data ? (
            <LoadingState className="px-5 pt-1" count={3} label="Loading active incidents…" />
          ) : incidentItems.length === 0 ? (
            <>
              <EmptyState
                icon={prioritized.length === 0 ? CircleCheck : ShieldAlert}
                {...(prioritized.length === 0
                  ? { title: 'No active incidents.', description: 'NETRA has no active incidents to prioritise right now.' }
                  : liveEmptyState(prioritized.length))}
              />
              <ListNotes centered notes={[incidentDemoNote]} />
            </>
          ) : (
            <>
              <AttentionList items={incidentItems.slice(0, LIST_LIMIT)} />
              <ListNotes
                notes={[
                  incidentItems.length > LIST_LIMIT && `Showing ${LIST_LIMIT} of ${formatNumber(incidentItems.length)} active incidents`,
                  hiddenNote,
                  incidentDemoNote,
                ]}
              />
            </>
          )}
        </Panel>

        <Panel
          title="Incoming event severity"
          description={
            incoming.length > 0
              ? `Severity of the latest ${formatNumber(incoming.length)} live ${incoming.length === 1 ? 'event' : 'events'} received by the collector.`
              : 'Severity of the latest live events received by the collector.'
          }
        >
          {collector.error ? (
            <p className="text-[13px] text-muted-foreground">Unavailable while the collector status cannot be loaded.</p>
          ) : !collector.data ? (
            <LoadingState count={2} label="Loading incoming events…" />
          ) : incoming.length === 0 ? (
            <p className="text-[13px] text-muted-foreground">No live events received yet.</p>
          ) : (
            <SeverityBreakdown mix={severityMix(incoming)} label="Incoming event severity" />
          )}
        </Panel>
      </div>

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Panel
          title="Unlinked high and critical events"
          description="New high or critical events that no incident covers yet. Imported dataset rows are never listed here."
          actions={<Link to={ROUTES.events} className="text-[12px] font-medium text-primary hover:underline">Security Events</Link>}
          flush
        >
          {events.error ? (
            <PanelError error={events.error} title="Security events unavailable" onRetry={events.reload} />
          ) : !events.data ? (
            <LoadingState className="px-5 pt-1" count={3} label="Loading events…" />
          ) : eventItems.length === 0 ? (
            <>
              <EmptyState
                icon={CircleCheck}
                title="No unlinked high or critical events."
                description="Every new high or critical event is already covered by an incident, or none have been recorded."
              />
              <ListNotes centered notes={[eventDemoNote]} />
            </>
          ) : (
            <>
              <AttentionList items={eventItems.slice(0, LIST_LIMIT)} />
              <ListNotes
                notes={[
                  `${eventCount} unlinked high or critical ${eventItems.length === 1 && events.data.complete ? 'event' : 'events'}`,
                  eventDemoNote,
                ]}
              />
            </>
          )}
        </Panel>

        <Panel
          title="Recent collector activity"
          description="The latest events submitted to the Live Event Collector, newest first."
          actions={<Link to={ROUTES.collector} className="text-[12px] font-medium text-primary hover:underline">Live Event Collector</Link>}
          flush
        >
          {collector.error ? (
            <PanelError error={collector.error} title="Collector status unavailable" onRetry={collector.reload} />
          ) : !collector.data ? (
            <LoadingState className="px-5 pt-1" count={3} label="Loading collector activity…" />
          ) : recentCollected.length === 0 ? (
            <>
              <EmptyState
                icon={Inbox}
                title={collector.data.totalEvents === 0 ? 'No live events received yet.' : 'No recent live events to show.'}
                description={
                  collector.data.totalEvents === 0
                    ? 'Nothing has been submitted to the Live Event Collector. Live events appear here as soon as they are received.'
                    : 'The collector returned no recent live events other than demo records.'
                }
              />
              <ListNotes centered notes={[collectedDemoNote]} />
            </>
          ) : (
            <>
              <AttentionList items={recentCollected} />
              <ListNotes notes={[collectedDemoNote]} />
            </>
          )}
        </Panel>
      </div>
    </PageContainer>
  )
}

/** Shown while the collector is idle: states plainly that there is no live feed, never quiet monitoring. */
function FeedNotice({ neverReceived, note }: { neverReceived: boolean; note: string }) {
  return (
    <SurfaceCard role="status" className="flex flex-col gap-3 border-medium/30 bg-medium/5 sm:flex-row sm:items-start">
      <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-medium/10 text-medium" aria-hidden>
        <RadioTower className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-[14px] font-semibold text-foreground">
          {neverReceived ? 'No live feed connected' : 'No live events in the last 5 minutes'}
        </p>
        <p className="mt-1 text-[13px] leading-relaxed text-muted-foreground">{note}</p>
      </div>
      <Link to={ROUTES.collector} className="shrink-0 text-[13px] font-medium text-primary hover:underline sm:self-center">
        Open Live Event Collector
      </Link>
    </SurfaceCard>
  )
}

/** Imported dataset events are reported apart from live activity and never counted in it. */
function ImportedNote({ total }: { total: number }) {
  return (
    <>
      {formatNumber(total)} events from uploaded datasets are stored separately: they are not live monitoring and are not counted on this page.{' '}
      <Link to={ROUTES.securityWorkspace} className="text-primary hover:underline">Review in Security Workspace</Link>
    </>
  )
}

const API_STATUS: Record<ApiHealthState, StatusItem> = {
  HEALTHY: { label: 'API', value: 'Healthy', tone: 'low' },
  ERROR: { label: 'API', value: 'Error', tone: 'critical', hint: 'The API health check returned an error' },
  UNREACHABLE: { label: 'API', value: 'Unreachable', tone: 'critical', hint: 'No response from the API' },
}

/** The database is only reported down when its own health check says so; otherwise its state is unknown. */
const DATABASE_STATUS: Record<DatabaseHealthState, (apiHealthy: boolean) => StatusItem> = {
  HEALTHY: () => ({ label: 'Database', value: 'Healthy', tone: 'low' }),
  DOWN: () => ({ label: 'Database', value: 'Down', tone: 'critical', hint: 'The database health check reported it unreachable' }),
  UNKNOWN: (apiHealthy) => ({
    label: 'Database',
    value: 'Unknown',
    tone: 'neutral',
    hint: apiHealthy ? 'The database health check gave no usable answer' : 'Unknown while the API is not healthy',
  }),
}

function statusItems(
  collector: CollectorStatus | undefined,
  collectorError: Error | undefined,
  health: { api: HealthOutcome; database: HealthOutcome } | undefined,
): StatusItem[] {
  const pending = '—'
  const api = health && apiHealthState(health.api)
  const database = health && databaseHealthState(health.api, health.database)
  const collectorValue = (value: (status: CollectorStatus) => string) => (collectorError ? 'Unavailable' : collector ? value(collector) : pending)

  return [
    {
      label: 'Collector',
      value: collectorError ? 'Unavailable' : collector ? (collector.status === 'receiving' ? 'Receiving' : 'Idle') : pending,
      tone: collectorError ? 'critical' : collector ? (collector.status === 'receiving' ? 'low' : 'neutral') : undefined,
      pulse: collector?.status === 'receiving' && !collectorError,
      hint: 'Receiving = an event in the last 5 minutes',
    },
    {
      label: 'Last received',
      value: collectorValue((s) => (s.lastReceivedAt ? timeAgo(s.lastReceivedAt) : 'Never')),
      hint: collector?.lastReceivedAt ? `${formatDateTime(collector.lastReceivedAt)} UTC` : undefined,
    },
    { label: 'Collected · 24h', value: collectorValue((s) => formatNumber(s.eventsLast24h)), hint: 'Events received by the web collector' },
    api ? API_STATUS[api] : { label: 'API', value: pending },
    database ? DATABASE_STATUS[database](api === 'HEALTHY') : { label: 'Database', value: pending },
  ]
}

function LiveTrackingUnavailable() {
  return (
    <PageContainer>
      <PageHeader icon={RadioTower} eyebrow="Monitoring" title="Live Tracking" description={DESCRIPTION} />
      <Panel title="Live status">
        <EmptyState
          icon={ServerOff}
          title="Live Tracking requires the NETRA API."
          description="Collector activity and incident priority are never simulated in demo mode. Run NETRA against the API to use this view."
        />
      </Panel>
    </PageContainer>
  )
}
