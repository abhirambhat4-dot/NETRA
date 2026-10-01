import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import { ChevronRight, FileCode2, Globe, Link2, Network } from 'lucide-react'
import type { IndicatorType, TechniqueObservation, ThreatIndicatorInventoryItem } from '@/api/types'
import {
  Disclosure,
  EmptyState,
  ErrorState,
  FilterChips,
  LoadingState,
  MeterBar,
  MetricStrip,
  PageContainer,
  PageHeader,
  Panel,
  SearchInput,
  SegmentedControl,
  SeverityBadge,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useQuery } from '@/hooks/useQuery'
import { useCountUp } from '@/hooks/useCountUp'
import { defang, shortHash } from '@/lib/defang'
import { formatClock, formatNumber, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { SEVERITY_ORDER, severityRowAccent } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { eventService, threatIntelInventoryService, threatIntelService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { IndicatorDetailSheet } from './intel/IndicatorDetailSheet'

const TYPE_META: Record<IndicatorType, { label: string; icon: LucideIcon }> = {
  IP: { label: 'IP', icon: Network },
  DOMAIN: { label: 'Domain', icon: Globe },
  URL: { label: 'URL', icon: Link2 },
  HASH: { label: 'Hash', icon: FileCode2 },
}

/** ATT&CK tactics in kill-chain order (only those NETRA has observed are shown). */
const TACTIC_ORDER = [
  'Initial Access',
  'Execution',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Command and Control',
  'Exfiltration',
]

type Sort = 'priority' | 'recent'
const sevRank = (i: ThreatIndicatorInventoryItem) => SEVERITY_ORDER.indexOf(i.severity)

export function ThreatIntelligencePage() {
  const [params, setParams] = useSearchParams()
  const [type, setType] = useState<IndicatorType | 'ALL'>('ALL')
  const [search, setSearch] = useState('')
  const [sort, setSort] = useState<Sort>('priority')

  const queryKey = JSON.stringify([type, search, sort])
  const indicators = useQuery(`intel-indicators-${USE_MOCKS ? 'mock' : queryKey}`, () =>
    threatIntelInventoryService.list(
      USE_MOCKS
        ? undefined
        : {
            indicatorType: type === 'ALL' ? undefined : type,
            search: search.trim() || undefined,
            sortBy: sort === 'recent' ? 'lastSeen' : 'severity',
            sortOrder: 'desc',
          },
    ),
  )
  const techniques = useQuery('intel-techniques', () =>
    USE_MOCKS ? threatIntelService.getObservedTechniques() : Promise.resolve([]),
  )
  const intelEvents = useQuery('intel-events', () => eventService.listForEventsPage({ detectionSource: 'THREAT_INTEL' }))
  const allEvents = useQuery('intel-all-events', () => eventService.listForEventsPage())

  const all = useMemo(() => indicators.data ?? [], [indicators.data])
  // Live filters run server-side, so metrics, type counts and the mix come from an unfiltered read.
  const inventory = useQuery(`intel-inventory-${USE_MOCKS ? 'mock' : 'live'}`, () =>
    USE_MOCKS ? Promise.resolve(undefined) : threatIntelInventoryService.list(),
  )
  const inventoryData = USE_MOCKS ? indicators.data : inventory.data
  const inventoryItems = useMemo(() => inventoryData ?? [], [inventoryData])
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all
      .filter(
        (i) =>
          (type === 'ALL' || i.type === type) &&
          (!q || [i.value, i.source, i.description ?? '', ...(i.tags ?? []), ...(i.incidentIds ?? [])].some((f) => f.toLowerCase().includes(q))),
      )
      .sort((a, b) =>
        sort === 'priority'
          ? sevRank(a) - sevRank(b) ||
            (b.incidentIds?.length ?? 0) - (a.incidentIds?.length ?? 0) ||
            (b.confidence ?? -1) - (a.confidence ?? -1)
          : Date.parse(b.lastSeen) - Date.parse(a.lastSeen),
      )
  }, [all, type, search, sort])

  const selectedId = params.get('indicator')
  const listedSelection = all.find((indicator) => indicator.id === selectedId)
  const selectedDetail = useQuery(`intel-indicator-${USE_MOCKS ? 'mock' : selectedId ?? 'none'}`, () =>
    !USE_MOCKS && selectedId ? threatIntelInventoryService.get(selectedId) : Promise.resolve(undefined),
  )
  const selected = USE_MOCKS
    ? listedSelection
    : selectedDetail.data?.id === selectedId
      ? selectedDetail.data
      : listedSelection

  const confidenceAvailable = inventoryItems.every((i) => i.confidence !== null)
  const activeAvailable = inventoryItems.every((i) => i.isActive !== undefined && i.isActive !== null)
  const feeds = [...new Set(inventoryItems.map((i) => i.source))]
  const openIndicator = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('indicator', id)
    else next.delete('indicator')
    setParams(next, { replace: true })
  }
  const bySev = (s: ThreatIndicatorInventoryItem['severity']) => inventoryItems.filter((i) => i.severity === s).length
  const activeCount = inventoryItems.filter((indicator) => indicator.isActive === true).length
  const highConfidenceCount = inventoryItems.filter((indicator) => indicator.confidence !== null && indicator.confidence >= 0.8).length
  const highSeverityCount = bySev('CRITICAL') + bySev('HIGH')
  const totalAnimated = useCountUp(inventoryItems.length, 650)
  const activeAnimated = useCountUp(activeCount, 650)
  const confidenceAnimated = useCountUp(highConfidenceCount, 650)
  const severityAnimated = useCountUp(highSeverityCount, 650)

  return (
    <PageContainer>
      <PageHeader
        title="Threat Intelligence"
        description={USE_MOCKS
          ? 'Indicators of compromise and ATT&CK techniques that NETRA correlates with detections to raise or lower incident risk.'
          : 'Feed-reported indicators with source, severity, optional confidence and observed dates.'}
      />

      <MetricStrip
        metrics={[
          {
            label: 'Total indicators',
            value: inventoryData ? formatNumber(Math.round(totalAnimated)) : '—',
            hint: `${feeds.length} observed feeds`,
          },
          {
            label: 'Active indicators',
            value: inventoryData && activeAvailable ? formatNumber(Math.round(activeAnimated)) : '—',
            valueClassName: 'text-cyan',
            hint: activeAvailable ? 'feed-reported status' : 'status not returned for all indicators',
          },
          {
            label: 'High confidence',
            value: inventoryData && confidenceAvailable ? formatNumber(Math.round(confidenceAnimated)) : '—',
            hint: confidenceAvailable ? 'feed confidence ≥80%' : 'confidence not returned for all indicators',
          },
          {
            label: 'High severity',
            value: inventoryData ? formatNumber(Math.round(severityAnimated)) : '—',
            valueClassName: 'text-high',
            hint: `${bySev('CRITICAL')} critical · ${bySev('HIGH')} high`,
          },
        ]}
      />

      <div className="grid items-start gap-4 xl:grid-cols-12">
        {/* Indicators */}
        <div className="rounded-xl xl:col-span-8" data-guide-target="indicators">
          <Panel
            title="Indicators of compromise"
            description="Values are defanged for safe display · open an indicator for full metadata"
            flush
            actions={
              <SegmentedControl
                aria-label="Sort indicators"
                value={sort}
                onChange={setSort}
                options={[
                  { value: 'priority', label: 'Priority' },
                  { value: 'recent', label: 'Recent' },
                ]}
              />
            }
          >
            <div className="flex flex-col gap-3 border-y border-border px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
              <FilterChips
                aria-label="Indicator type"
                value={type}
                onChange={setType}
                options={[
                  { value: 'ALL', label: 'All', count: inventoryItems.length },
                  ...(Object.keys(TYPE_META) as IndicatorType[]).map((t) => ({
                    value: t,
                    label: TYPE_META[t].label,
                    count: inventoryItems.filter((i) => i.type === t).length,
                  })),
                ]}
              />
              <SearchInput
                value={search}
                onChange={setSearch}
                placeholder={USE_MOCKS ? 'Search indicator, tag, feed…' : 'Search indicator or feed…'}
                className="sm:w-64"
              />
            </div>
            {indicators.error ? (
              <div>
                <ErrorState
                  title={indicators.error instanceof HttpError && indicators.error.status === 401 ? 'Authentication required' : 'Threat indicators unavailable'}
                  message={indicators.error instanceof HttpError && indicators.error.status === 401 ? undefined : indicators.error.message}
                  onRetry={indicators.error instanceof HttpError && indicators.error.status === 401 ? undefined : indicators.reload}
                />
                {indicators.error instanceof HttpError && indicators.error.status === 401 && (
                  <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
                )}
              </div>
            ) : !indicators.data ? (
              <LoadingState className="p-5" count={8} />
            ) : filtered.length === 0 ? (
              <EmptyState
                title={inventoryItems.length ? 'No indicators match' : 'No threat indicators'}
                description={inventoryItems.length ? 'Adjust the type filter or search terms.' : 'No indicators are available from the current intelligence sources.'}
              />
            ) : (
              <ul>
                {filtered.map((i, index) => (
                  <IndicatorRow key={i.id} indicator={i} active={selected?.id === i.id} onOpen={() => openIndicator(i.id)} entryIndex={index} />
                ))}
              </ul>
            )}
          </Panel>
        </div>

        {/* Recent matches first; the mix is secondary */}
        <div className="flex flex-col gap-4 xl:col-span-4">
          <Panel title="Recent threat-intelligence events" description="Events reported with the THREAT_INTEL source">
            {intelEvents.error ? (
              <ErrorState onRetry={intelEvents.reload} />
            ) : !intelEvents.data ? (
              <LoadingState count={4} />
            ) : intelEvents.data.items.length === 0 ? (
              <EmptyState title="No threat-intelligence events" description="No retained event references use the threat-intelligence detection source." />
            ) : (
              <ul className="space-y-3">
                {intelEvents.data.items.slice(0, 8).map((e) => (
                  <li key={e.id} className="grid grid-cols-[56px_minmax(0,1fr)] gap-2.5">
                    <span className="pt-0.5 font-mono text-[11px] text-muted-foreground">{formatClock(e.timestamp)}</span>
                    <div className="min-w-0">
                      <Link to={`${ROUTES.events}?event=${e.id}`} className="block truncate text-[13px] font-medium transition-colors hover:text-primary">
                        {e.eventType}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-1.5 truncate text-[11px] text-muted-foreground">
                        <span className="truncate">{e.signature}</span>
                        {e.incidentIds[0] && (
                          <Link to={ROUTES.incident(e.incidentIds[0])} className="shrink-0 font-mono text-primary hover:underline">
                            {e.incidentIds[0]}
                          </Link>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Indicator mix" description="By type and source">
            <ul className="space-y-2.5">
              {(Object.keys(TYPE_META) as IndicatorType[]).map((t) => {
                const n = inventoryItems.filter((i) => i.type === t).length
                const Icon = TYPE_META[t].icon
                return (
                  <li key={t} className="grid grid-cols-[88px_1fr_24px] items-center gap-3 text-xs">
                    <span className="inline-flex items-center gap-1.5 text-muted-foreground">
                      <Icon className="size-3.5" /> {TYPE_META[t].label}
                    </span>
                    <MeterBar value={n} max={Math.max(1, inventoryItems.length)} tone="accent" />
                    <span className="text-right font-mono">{n}</span>
                  </li>
                )
              })}
            </ul>
            <Disclosure label="Intelligence sources" hint={feeds.length} className="mt-3 border-t border-border pt-2">
              <div className="flex flex-wrap gap-1.5">
                {feeds.map((f) => (
                  <span key={f} className="rounded-md border border-border bg-foreground/3 px-2 py-0.5 text-[11px] text-foreground/80">
                    {f} <span className="font-mono text-muted-foreground">{inventoryItems.filter((i) => i.source === f).length}</span>
                  </span>
                ))}
              </div>
            </Disclosure>
          </Panel>
        </div>
      </div>

      {!USE_MOCKS && (
        <Panel title="ATT&CK correlations" description="Correlation data is not returned by the live API.">
          <p className="text-sm text-muted-foreground">Unavailable</p>
        </Panel>
      )}

      {USE_MOCKS && <MitreSection techniques={techniques.data} />}

      <IndicatorDetailSheet
        indicator={selectedDetail.error ? undefined : selected}
        indicatorId={selectedId}
        loading={selectedDetail.loading}
        error={selectedDetail.error}
        onRetry={selectedDetail.reload}
        events={allEvents.data?.items ?? []}
        onClose={() => openIndicator(null)}
      />
    </PageContainer>
  )
}

/** Primary fields only: indicator, severity, source, confidence, linked incident. */
function IndicatorRow({ indicator: i, active, onOpen, entryIndex }: { indicator: ThreatIndicatorInventoryItem; active: boolean; onOpen: () => void; entryIndex: number }) {
  const Icon = TYPE_META[i.type].icon
  return (
    <li
      className="border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1"
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 35}ms` }}
    >
      <button
        type="button"
        onClick={onOpen}
        aria-label={`${TYPE_META[i.type].label} indicator, ${i.severity}, open details`}
        className={cn(
          'group grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 px-5 py-3 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6 md:grid-cols-[minmax(0,1.6fr)_110px_84px_78px_auto_16px]',
          severityRowAccent[i.severity],
          active && 'bg-primary/6',
        )}
      >
        <div className="flex min-w-0 items-center gap-3">
          <span className="surface-inset grid size-8 shrink-0 place-items-center rounded-md text-muted-foreground" title={TYPE_META[i.type].label}>
            <Icon className="size-4" />
          </span>
          <div className="min-w-0">
            <div className="truncate font-mono text-xs text-foreground/95">{i.type === 'HASH' ? shortHash(i.value) : defang(i.value, i.type)}</div>
            <div className="mt-0.5 truncate text-[11px] text-muted-foreground">
              {TYPE_META[i.type].label} · {i.source} · seen {timeAgo(i.lastSeen)}
              <span className="md:hidden"> · {i.confidence === null ? 'confidence not provided' : `${Math.round(i.confidence * 100)}% confidence`}</span>
            </div>
          </div>
        </div>

        <div className="max-md:hidden">
          <div className="mb-1 flex justify-between text-[11px]">
            <span className="text-muted-foreground">confidence</span>
            <span className="font-mono">{i.confidence === null ? 'Not provided' : `${Math.round(i.confidence * 100)}%`}</span>
          </div>
          {i.confidence !== null && <MeterBar value={i.confidence * 100} tone={i.confidence >= 0.8 ? 'accent' : 'neutral'} />}
        </div>

        <div className="font-mono text-[11px] max-md:hidden">
          {i.incidentIds === null ? (
            <span className="font-sans text-muted-foreground">Not provided</span>
          ) : i.incidentIds.length ? (
            <span className="text-foreground/85">
              {i.incidentIds[0]}
              {i.incidentIds.length > 1 && <span className="text-muted-foreground"> +{i.incidentIds.length - 1}</span>}
            </span>
          ) : (
            <span className="font-sans text-muted-foreground">no incident</span>
          )}
        </div>

        <div className="hidden justify-end md:flex">
          <ToneBadge tone={i.isActive === true ? 'low' : 'neutral'} size="sm" className="bg-transparent">
            {i.isActive === undefined || i.isActive === null ? 'Unreported' : i.isActive ? 'Active' : 'Inactive'}
          </ToneBadge>
        </div>
        <div className="flex justify-end gap-2 md:col-auto">
          <ToneBadge tone={i.isActive === true ? 'low' : 'neutral'} size="sm" className="bg-transparent md:hidden">
            {i.isActive === undefined || i.isActive === null ? 'Unreported' : i.isActive ? 'Active' : 'Inactive'}
          </ToneBadge>
          <SeverityBadge severity={i.severity} size="sm" />
        </div>
        <ChevronRight className="size-4 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground max-md:hidden" />
      </button>
    </li>
  )
}

function MitreSection({ techniques }: { techniques?: TechniqueObservation[] }) {
  const max = Math.max(1, ...(techniques ?? []).map((t) => t.eventCount))
  const tactics = TACTIC_ORDER.filter((tac) => techniques?.some((t) => t.technique.tactic === tac))

  return (
    <Panel
      title="MITRE ATT&CK activity"
      description={
        techniques
          ? `${techniques.length} techniques across ${tactics.length} tactics observed in NETRA incidents`
          : 'Techniques observed across NETRA incidents'
      }
    >
      {!techniques ? (
        <LoadingState variant="inline" />
      ) : techniques.length === 0 ? (
        <EmptyState title="No observed ATT&CK activity" description="No techniques are linked to the current incident set." />
      ) : (
        <Tabs defaultValue="matrix" className="gap-4">
          <TabsList variant="line" className="justify-start gap-0 border-b border-border pb-px">
            <TabsTrigger value="matrix" className="flex-none px-2.5 text-xs">
              By tactic
            </TabsTrigger>
            <TabsTrigger value="table" className="flex-none px-2.5 text-xs">
              Technique table
            </TabsTrigger>
          </TabsList>

          <TabsContent value="matrix" className="motion-safe:animate-in motion-safe:fade-in-0">
            <p className="mb-3 text-[11px] text-muted-foreground">Shading = observed event volume · counts show active / total incidents</p>
            <div className="overflow-x-auto pb-1">
              <div className="grid min-w-[760px] gap-2" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))` }}>
                {tactics.map((tac) => (
                  <div key={tac} className="flex flex-col gap-2">
                    <div className="border-b border-border pb-2 text-[11px] font-medium text-muted-foreground">{tac}</div>
                    {techniques
                      .filter((t) => t.technique.tactic === tac)
                      .map((t) => {
                        const intensity = 0.06 + 0.28 * (t.eventCount / max)
                        return (
                          <div
                            key={t.technique.id}
                            className="rounded-lg border border-primary/20 p-2.5 transition-colors hover:border-primary/40"
                            style={{ background: `rgb(79 140 255 / ${intensity})` }}
                            title={`${t.technique.id} ${t.technique.name}: ${t.eventCount} events`}
                          >
                            <div className="font-mono text-[11px] text-foreground/90">{t.technique.id}</div>
                            <div className="mt-0.5 text-xs leading-snug font-medium">{t.technique.name}</div>
                            <div className="mt-2 flex items-center justify-between text-[10px] text-foreground/70">
                              <span>{formatNumber(t.eventCount)} ev</span>
                              <span>
                                {t.activeIncidentCount}/{t.incidentCount}
                              </span>
                            </div>
                          </div>
                        )
                      })}
                  </div>
                ))}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="table" className="motion-safe:animate-in motion-safe:fade-in-0">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-left text-[13px]">
                <thead>
                  <tr className="border-b border-border text-[11px] text-muted-foreground">
                    <th className="py-2 pr-3 font-medium">Technique</th>
                    <th className="px-3 font-medium">Tactic</th>
                    <th className="px-3 text-right font-medium">Observed events</th>
                    <th className="px-3 font-medium">Associated incidents</th>
                    <th className="py-2 pl-3 text-right font-medium">Highest severity</th>
                  </tr>
                </thead>
                <tbody>
                  {techniques.map((t) => (
                    <TechniqueRow key={t.technique.id} t={t} />
                  ))}
                </tbody>
              </table>
            </div>
          </TabsContent>
        </Tabs>
      )}
    </Panel>
  )
}

function TechniqueRow({ t }: { t: TechniqueObservation }) {
  return (
    <tr className="border-b border-border/60 transition-colors last:border-b-0 hover:bg-foreground/2">
      <td className="py-2.5 pr-3">
        <span className="font-mono text-xs text-primary">{t.technique.id}</span>
        <span className="ml-2">{t.technique.name}</span>
      </td>
      <td className="px-3 text-xs text-muted-foreground">{t.technique.tactic}</td>
      <td className="px-3 text-right font-mono text-xs">{formatNumber(t.eventCount)}</td>
      <td className="px-3">
        <div className="flex flex-wrap gap-1">
          {t.incidentIds.map((id) => (
            <Link key={id} to={ROUTES.incident(id)} className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-foreground/85 transition-colors hover:border-primary/30 hover:text-primary">
              {id}
            </Link>
          ))}
          <span className={cn('self-center text-[11px]', t.activeIncidentCount ? 'text-foreground/80' : 'text-muted-foreground')}>
            {t.activeIncidentCount} active
          </span>
        </div>
      </td>
      <td className="py-2.5 pl-3 text-right">
        <SeverityBadge severity={t.highestSeverity} size="sm" />
      </td>
    </tr>
  )
}
