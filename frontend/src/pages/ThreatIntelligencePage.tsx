import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import { FileCode2, Globe, Link2, Network } from 'lucide-react'
import type { IndicatorType, TechniqueObservation, ThreatIndicator } from '@/api/types'
import {
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
  SeverityBadge,
} from '@/components/netra'
import { useNow } from '@/hooks/useNow'
import { useQuery } from '@/hooks/useQuery'
import { defang, shortHash } from '@/lib/defang'
import { formatClock, formatNumber, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { eventService, threatIntelService } from '@/services'

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

export function ThreatIntelligencePage() {
  const [type, setType] = useState<IndicatorType | 'ALL'>('ALL')
  const [search, setSearch] = useState('')
  const now = useNow(60_000)

  const indicators = useQuery('intel-indicators', threatIntelService.listIndicators)
  const techniques = useQuery('intel-techniques', threatIntelService.getObservedTechniques)
  const intelEvents = useQuery('intel-events', () => eventService.list({ detectionSource: 'THREAT_INTEL', pageSize: 8 }))

  const all = useMemo(() => indicators.data ?? [], [indicators.data])
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all.filter(
      (i) =>
        (type === 'ALL' || i.type === type) &&
        (!q || [i.value, i.source, i.description, ...i.tags, ...i.incidentIds].some((f) => f.toLowerCase().includes(q))),
    )
  }, [all, type, search])

  const linked = all.filter((i) => i.incidentIds.length > 0)
  const feeds = [...new Set(all.map((i) => i.source))]

  return (
    <PageContainer>
      <PageHeader
        title="Threat Intelligence"
        description="Indicators of compromise and ATT&CK techniques that NETRA correlates with detections to raise or lower incident risk."
      />

      <MetricStrip
        metrics={[
          { label: 'Indicators', value: all.length || '—', hint: `${feeds.length} intelligence sources` },
          { label: 'Matched to incidents', value: linked.length, hint: `${new Set(linked.flatMap((i) => i.incidentIds)).size} incidents enriched` },
          { label: 'High confidence', value: all.filter((i) => i.confidence >= 0.8).length, valueClassName: 'text-primary', hint: 'confidence ≥ 80%' },
          { label: 'Recent matches · 24h', value: all.filter((i) => now.getTime() - Date.parse(i.lastSeen) < 86_400_000).length, hint: 'indicator seen again' },
          { label: 'ATT&CK techniques', value: techniques.data?.length ?? '—', hint: `${new Set((techniques.data ?? []).map((t) => t.technique.tactic)).size} tactics` },
        ]}
      />

      <div className="grid items-start gap-4 xl:grid-cols-12">
        {/* Indicators */}
        <Panel
          title="Indicators of compromise"
          description="Values are defanged for safe display"
          flush
          className="xl:col-span-8"
        >
          <div className="flex flex-col gap-3 border-y border-border px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
            <FilterChips
              aria-label="Indicator type"
              value={type}
              onChange={setType}
              options={[
                { value: 'ALL', label: 'All', count: all.length },
                ...(Object.keys(TYPE_META) as IndicatorType[]).map((t) => ({
                  value: t,
                  label: TYPE_META[t].label,
                  count: all.filter((i) => i.type === t).length,
                })),
              ]}
            />
            <SearchInput value={search} onChange={setSearch} placeholder="Search indicator, tag, feed…" className="sm:w-64" />
          </div>
          {indicators.error ? (
            <ErrorState onRetry={indicators.reload} />
          ) : !indicators.data ? (
            <LoadingState className="p-5" count={8} />
          ) : filtered.length === 0 ? (
            <EmptyState title="No indicators match" />
          ) : (
            <ul>
              {filtered.map((i) => (
                <IndicatorRow key={i.id} indicator={i} />
              ))}
            </ul>
          )}
        </Panel>

        {/* Sidebar: mix + feed + recent matches */}
        <div className="flex flex-col gap-4 xl:col-span-4">
          <Panel title="Indicator mix" description="By type and source">
            <ul className="space-y-2.5">
              {(Object.keys(TYPE_META) as IndicatorType[]).map((t) => {
                const n = all.filter((i) => i.type === t).length
                const Icon = TYPE_META[t].icon
                return (
                  <li key={t} className="grid grid-cols-[88px_1fr_24px] items-center gap-3 text-xs">
                    <span className="inline-flex items-center gap-1.5 text-muted-foreground">
                      <Icon className="size-3.5" /> {TYPE_META[t].label}
                    </span>
                    <MeterBar value={n} max={Math.max(1, all.length)} tone="accent" />
                    <span className="text-right font-mono">{n}</span>
                  </li>
                )
              })}
            </ul>
            <div className="mt-4 flex flex-wrap gap-1.5 border-t border-border pt-3.5">
              {feeds.map((f) => (
                <span key={f} className="rounded-md border border-border bg-foreground/3 px-2 py-0.5 text-[11px] text-foreground/80">
                  {f} <span className="font-mono text-muted-foreground">{all.filter((i) => i.source === f).length}</span>
                </span>
              ))}
            </div>
          </Panel>

          <Panel title="Recent intelligence matches" description="Events raised by threat-intel correlation">
            {!intelEvents.data ? (
              <LoadingState count={4} />
            ) : (
              <ul className="space-y-3">
                {intelEvents.data.items.map((e) => (
                  <li key={e.id} className="grid grid-cols-[56px_minmax(0,1fr)] gap-2.5">
                    <span className="pt-0.5 font-mono text-[11px] text-muted-foreground">{formatClock(e.timestamp)}</span>
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-medium">{e.eventType}</div>
                      <div className="mt-0.5 flex items-center gap-1.5 truncate text-[11px] text-muted-foreground">
                        <span className="truncate">{e.signature}</span>
                        {e.incidentId && (
                          <Link to={ROUTES.incident(e.incidentId)} className="shrink-0 font-mono text-primary hover:underline">
                            {e.incidentId}
                          </Link>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      <MitreSection techniques={techniques.data} />
    </PageContainer>
  )
}

function IndicatorRow({ indicator: i }: { indicator: ThreatIndicator }) {
  const Icon = TYPE_META[i.type].icon
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 border-b border-border/70 px-5 py-3 transition-colors last:border-b-0 hover:bg-foreground/2 md:grid-cols-[minmax(0,1.6fr)_110px_minmax(90px,0.6fr)_110px_84px]">
      <div className="flex min-w-0 items-start gap-3">
        <span className="surface-inset mt-0.5 grid size-8 shrink-0 place-items-center rounded-md text-muted-foreground" title={TYPE_META[i.type].label}>
          <Icon className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="truncate font-mono text-xs text-foreground/95" title={i.type === 'HASH' ? i.value : undefined}>
            {i.type === 'HASH' ? shortHash(i.value) : defang(i.value, i.type)}
          </div>
          <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{i.description}</div>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {i.mitreTechniqueIds.map((t) => (
              <span key={t} className="rounded border border-primary/20 bg-primary/8 px-1 font-mono text-[10px] text-primary">
                {t}
              </span>
            ))}
            {i.tags.slice(0, 2).map((t) => (
              <span key={t} className="rounded border border-border px-1 text-[10px] text-muted-foreground">
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="text-[11px] max-md:hidden">
        <div className="truncate text-foreground/85">{i.source}</div>
        <div className="mt-0.5 text-muted-foreground">seen {timeAgo(i.lastSeen)}</div>
      </div>

      <div className="max-md:hidden">
        <div className="mb-1 flex justify-between text-[11px]">
          <span className="text-muted-foreground">confidence</span>
          <span className="font-mono">{Math.round(i.confidence * 100)}%</span>
        </div>
        <MeterBar value={i.confidence * 100} tone={i.confidence >= 0.8 ? 'accent' : 'neutral'} />
      </div>

      <div className="flex flex-wrap gap-1 max-md:hidden">
        {i.incidentIds.length ? (
          i.incidentIds.map((id) => (
            <Link key={id} to={ROUTES.incident(id)} className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-foreground/85 transition-colors hover:border-primary/30 hover:text-primary">
              {id}
            </Link>
          ))
        ) : (
          <span className="text-[11px] text-muted-foreground">no incident</span>
        )}
      </div>

      <div className="flex justify-end">
        <SeverityBadge severity={i.severity} size="sm" />
      </div>
    </li>
  )
}

function MitreSection({ techniques }: { techniques?: TechniqueObservation[] }) {
  const max = Math.max(1, ...(techniques ?? []).map((t) => t.eventCount))
  const tactics = TACTIC_ORDER.filter((tac) => techniques?.some((t) => t.technique.tactic === tac))

  return (
    <Panel title="MITRE ATT&CK activity" description="Techniques observed across NETRA incidents, arranged by tactic · shading = event volume">
      {!techniques ? (
        <LoadingState variant="inline" />
      ) : (
        <div className="space-y-6">
          <div className="overflow-x-auto pb-1">
            <div className="grid min-w-[760px] gap-2" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(0, 1fr))` }}>
              {tactics.map((tac) => (
                <div key={tac} className="flex flex-col gap-2">
                  <div className="border-b border-border pb-2 text-[11px] font-medium text-muted-foreground">{tac}</div>
                  {techniques
                    .filter((t) => t.technique.tactic === tac)
                    .map((t) => {
                      const intensity = 0.08 + 0.32 * (t.eventCount / max)
                      return (
                        <div
                          key={t.technique.id}
                          className="rounded-lg border border-primary/20 p-2.5"
                          style={{ background: `rgb(79 140 255 / ${intensity})` }}
                          title={`${t.technique.id} ${t.technique.name}: ${t.eventCount} events`}
                        >
                          <div className="font-mono text-[11px] text-foreground/90">{t.technique.id}</div>
                          <div className="mt-0.5 text-xs leading-snug font-medium">{t.technique.name}</div>
                          <div className="mt-2 flex items-center justify-between text-[10px] text-foreground/70">
                            <span>{formatNumber(t.eventCount)} ev</span>
                            <span>
                              {t.activeIncidentCount}/{t.incidentCount} active
                            </span>
                          </div>
                        </div>
                      )
                    })}
                </div>
              ))}
            </div>
          </div>

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
        </div>
      )}
    </Panel>
  )
}

function TechniqueRow({ t }: { t: TechniqueObservation }) {
  return (
    <tr className="border-b border-border/60 last:border-b-0">
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
