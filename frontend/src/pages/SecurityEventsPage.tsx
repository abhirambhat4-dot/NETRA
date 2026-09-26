import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Link2 } from 'lucide-react'
import type { DetectionSource, EventStatus, SecurityEvent, Severity } from '@/api/types'
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
import { useQuery } from '@/hooks/useQuery'
import { formatClock, formatNumber } from '@/lib/format'
import { EVENT_SOURCES, detectionSourceMeta } from '@/lib/sources'
import { SEVERITY_ORDER, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetService, dashboardService, eventService } from '@/services'
import { EventDetailSheet } from './events/EventDetailSheet'

const PAGE_SIZE = 14
type SevFilter = Severity | 'ALL'
type SrcFilter = Exclude<DetectionSource, 'HYBRID'> | 'ALL'
type StatusFilter = EventStatus | 'ALL'

export function SecurityEventsPage() {
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState(params.get('q') ?? '')
  const [severity, setSeverity] = useState<SevFilter>('ALL')
  const [source, setSource] = useState<SrcFilter>('ALL')
  const [status, setStatus] = useState<StatusFilter>('ALL')
  const [page, setPage] = useState(1)

  const events = useQuery('events-all', () => eventService.list({ pageSize: 1000 }))
  const assets = useQuery('events-assets', assetService.list)
  const stats = useQuery('events-stats', dashboardService.getStats)

  const all = useMemo(() => events.data?.items ?? [], [events.data])
  const assetsById = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all.filter(
      (e) =>
        (severity === 'ALL' || e.severity === severity) &&
        (source === 'ALL' || e.detectionSource === source) &&
        (status === 'ALL' || e.status === status) &&
        (!q ||
          [e.id, e.eventType, e.signature, e.sourceIp, e.destinationIp, e.incidentId, e.assetId && assetsById.get(e.assetId)?.name]
            .filter(Boolean)
            .some((f) => String(f).toLowerCase().includes(q))),
    )
  }, [all, search, severity, source, status, assetsById])

  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const selectedId = params.get('event')
  const selected = all.find((e) => e.id === selectedId)

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

  const count = (pred: (e: SecurityEvent) => boolean) => all.filter(pred).length
  const correlated = count((e) => e.incidentId !== null)
  const filtersActive = severity !== 'ALL' || source !== 'ALL' || status !== 'ALL' || search !== ''

  return (
    <PageContainer>
      <PageHeader
        title="Security Events"
        description="Notable detections from Suricata, the ML anomaly detector and threat intelligence — correlated into incidents by NETRA."
      />

      <MetricStrip
        metrics={[
          { label: 'Notable events', value: all.length || '—', hint: 'retained for investigation' },
          { label: 'Raw detections · 24h', value: stats.data ? formatNumber(stats.data.eventsLast24h) : '—', hint: 'all sensor alerts' },
          { label: 'Correlated', value: correlated, hint: `${all.length ? Math.round((correlated / all.length) * 100) : 0}% linked to incidents` },
          { label: 'Critical / High', value: `${count((e) => e.severity === 'CRITICAL')} / ${count((e) => e.severity === 'HIGH')}`, valueClassName: 'text-critical' },
          { label: 'Awaiting triage', value: count((e) => e.status === 'NEW'), hint: 'status NEW' },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden">
        {/* Filter bar */}
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
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
              options={[{ value: 'ALL', label: 'All' }, ...EVENT_SOURCES.map((s) => ({ value: s, label: detectionSourceMeta[s].short }))]}
            />
            <SelectFilter
              label="Status"
              value={status}
              onChange={resetPage(setStatus)}
              options={[
                { value: 'ALL', label: 'All' },
                { value: 'NEW', label: 'New' },
                { value: 'CORRELATED', label: 'Correlated' },
                { value: 'DISMISSED', label: 'Dismissed' },
              ]}
            />
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
          <ErrorState onRetry={events.reload} />
        ) : !events.data ? (
          <LoadingState className="p-5" count={10} />
        ) : filtered.length === 0 ? (
          <EmptyState title="No events match these filters" description="Try widening the severity or source filter." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[980px] text-left text-[13px]">
                <thead>
                  <tr className="border-b border-border text-[11px] text-muted-foreground">
                    <th className="py-2.5 pr-3 pl-5 font-medium">Time (UTC)</th>
                    <th className="px-3 font-medium">Severity</th>
                    <th className="px-3 font-medium">Event</th>
                    <th className="px-3 font-medium">Source</th>
                    <th className="px-3 font-medium">Source → Destination</th>
                    <th className="px-3 font-medium">Asset</th>
                    <th className="px-3 font-medium">Status</th>
                    <th className="py-2.5 pr-5 pl-3 text-right font-medium">Incident</th>
                  </tr>
                </thead>
                <tbody>
                  {pageItems.map((e) => {
                    const src = detectionSourceMeta[e.detectionSource]
                    const asset = e.assetId ? assetsById.get(e.assetId) : undefined
                    return (
                      <tr
                        key={e.id}
                        onClick={() => openEvent(e.id)}
                        className={cn(
                          'group cursor-pointer border-b border-border/60 transition-colors last:border-b-0 hover:bg-foreground/2.5',
                          selectedId === e.id && 'bg-primary/6',
                        )}
                      >
                        <td className="py-2.5 pr-3 pl-5 align-top">
                          <div className="font-mono text-xs text-foreground/90 tabular-nums">{formatClock(e.timestamp)}</div>
                          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{e.id}</div>
                        </td>
                        <td className="px-3 py-2.5 align-top">
                          <SeverityBadge severity={e.severity} size="sm" />
                        </td>
                        <td className="max-w-[340px] px-3 py-2.5 align-top">
                          <div className="truncate font-medium">{e.eventType}</div>
                          <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{e.signature ?? `Anomaly score ${Math.round(e.anomalyScore * 100)}%`}</div>
                        </td>
                        <td className="px-3 py-2.5 align-top">
                          <span className="inline-flex items-center gap-1.5 text-xs text-foreground/85">
                            <span className="size-1.5 rounded-full" style={{ background: src.color }} />
                            {src.short}
                          </span>
                          <div className="mt-0.5 text-[11px] text-muted-foreground">{e.protocol}</div>
                        </td>
                        <td className="px-3 py-2.5 align-top font-mono text-xs text-foreground/85">
                          {e.sourceIp}
                          <span className="text-muted-foreground"> → </span>
                          {e.destinationIp}
                          {e.destinationPort && <span className="text-muted-foreground">:{e.destinationPort}</span>}
                        </td>
                        <td className="px-3 py-2.5 align-top text-xs">{asset?.name ?? <span className="text-muted-foreground">—</span>}</td>
                        <td className="px-3 py-2.5 align-top">
                          <StatusBadge status={e.status} size="sm" />
                        </td>
                        <td className="py-2.5 pr-5 pl-3 text-right align-top">
                          {e.incidentId ? (
                            <span className="inline-flex items-center gap-1 rounded border border-primary/20 bg-primary/8 px-1.5 py-0.5 font-mono text-[10px] text-primary">
                              <Link2 className="size-3" />
                              {e.incidentId}
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="border-t border-border">
              <Pagination page={page} pageSize={PAGE_SIZE} total={filtered.length} onChange={setPage} />
            </div>
          </>
        )}
      </SurfaceCard>

      <EventDetailSheet
        event={selected}
        asset={selected?.assetId ? assetsById.get(selected.assetId) : undefined}
        onClose={() => openEvent(null)}
      />
    </PageContainer>
  )
}
