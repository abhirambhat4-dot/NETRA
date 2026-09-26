import { useMemo, useState } from 'react'
import type { Incident, Severity } from '@/api/types'
import { IncidentRow } from '@/components/incidents/IncidentRow'
import {
  EmptyState,
  ErrorState,
  FilterChips,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  SearchInput,
  SegmentedControl,
  SurfaceCard,
} from '@/components/netra'
import { useQuery } from '@/hooks/useQuery'
import { SEVERITY_ORDER, riskToSeverity, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetService, incidentService } from '@/services'

type SevFilter = Exclude<Severity, 'INFO'> | 'ALL'
type StateFilter = 'ALL' | 'ACTIVE' | 'CONTAINED' | 'RESOLVED'
type Sort = 'risk' | 'recent'

const ACTIVE = new Set(['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING'])
const stateOf = (i: Incident): Exclude<StateFilter, 'ALL'> =>
  ACTIVE.has(i.status) ? 'ACTIVE' : i.status === 'CONTAINED' ? 'CONTAINED' : 'RESOLVED'

export function IncidentsPage() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<SevFilter>('ALL')
  const [state, setState] = useState<StateFilter>('ALL')
  const [sort, setSort] = useState<Sort>('risk')

  const incidents = useQuery('incidents-all', () => incidentService.list({ pageSize: 500 }))
  const assets = useQuery('incidents-assets', assetService.list)

  const all = useMemo(() => incidents.data?.items ?? [], [incidents.data])
  const assetsById = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])
  const active = all.filter((i) => ACTIVE.has(i.status))

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all
      .filter(
        (i) =>
          (severity === 'ALL' || i.severity === severity) &&
          (state === 'ALL' || stateOf(i) === state) &&
          (!q ||
            [i.id, i.threatName, i.sourceIp, i.destinationIp, i.mitreTechniqueId, assetsById.get(i.assetId)?.name]
              .filter(Boolean)
              .some((f) => String(f).toLowerCase().includes(q))),
      )
      .sort((a, b) => (sort === 'risk' ? b.riskScore - a.riskScore : Date.parse(b.lastSeen) - Date.parse(a.lastSeen)))
  }, [all, search, severity, state, sort, assetsById])

  const groups: { label: string; items: Incident[] }[] =
    state === 'ALL'
      ? [
          { label: 'Active', items: filtered.filter((i) => ACTIVE.has(i.status)) },
          { label: 'Closed', items: filtered.filter((i) => !ACTIVE.has(i.status)) },
        ].filter((g) => g.items.length)
      : [{ label: '', items: filtered }]

  const meanRisk = active.length ? Math.round(active.reduce((s, i) => s + i.riskScore, 0) / active.length) : 0
  const countState = (s: Exclude<StateFilter, 'ALL'>) => all.filter((i) => stateOf(i) === s).length

  return (
    <PageContainer>
      <PageHeader
        title="Incidents"
        description="Correlated threats ranked by NETRA risk score — from detection through authorization, containment and memory."
      />

      <MetricStrip
        metrics={[
          { label: 'Active incidents', value: active.length, hint: `${all.length} total in the last 7 days` },
          { label: 'Critical', value: active.filter((i) => i.severity === 'CRITICAL').length, valueClassName: 'text-critical', hint: 'active, risk ≥ 85' },
          { label: 'Awaiting authorization', value: all.filter((i) => i.status === 'AWAITING_AUTHORIZATION').length, valueClassName: 'text-medium', hint: 'decision needs approval' },
          { label: 'Contained', value: countState('CONTAINED'), valueClassName: 'text-low', hint: 'verified containment' },
          {
            label: 'Mean active risk',
            value: meanRisk,
            valueClassName: toneStyles[severityTone[riskToSeverity(meanRisk)]].text,
            hint: riskToSeverity(meanRisk).toLowerCase(),
          },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <SearchInput value={search} onChange={setSearch} placeholder="Search incident, IP, asset, technique…" className="w-full sm:w-80" />
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              Sort
              <SegmentedControl
                aria-label="Sort"
                value={sort}
                onChange={setSort}
                options={[
                  { value: 'risk', label: 'Risk' },
                  { value: 'recent', label: 'Recent' },
                ]}
              />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <FilterChips
              aria-label="Severity"
              value={severity}
              onChange={setSeverity}
              options={[
                { value: 'ALL', label: 'All', count: all.length },
                ...SEVERITY_ORDER.filter((s): s is Exclude<Severity, 'INFO'> => s !== 'INFO').map((s) => ({
                  value: s,
                  label: s.charAt(0) + s.slice(1).toLowerCase(),
                  count: all.filter((i) => i.severity === s).length,
                  dot: toneStyles[severityTone[s]].solid,
                })),
              ]}
            />
            <span className="hidden h-5 w-px bg-border sm:block" />
            <FilterChips
              aria-label="State"
              value={state}
              onChange={setState}
              options={[
                { value: 'ALL', label: 'Any state' },
                { value: 'ACTIVE', label: 'Active', count: countState('ACTIVE') },
                { value: 'CONTAINED', label: 'Contained', count: countState('CONTAINED') },
                { value: 'RESOLVED', label: 'Resolved', count: countState('RESOLVED') },
              ]}
            />
          </div>
          {all.length > 0 && <SeverityBar incidents={active} />}
        </div>

        {incidents.error ? (
          <ErrorState onRetry={incidents.reload} />
        ) : !incidents.data ? (
          <LoadingState className="p-5" count={8} />
        ) : filtered.length === 0 ? (
          <EmptyState title="No incidents match" description="Adjust the severity or state filters." />
        ) : (
          groups.map((g) => (
            <div key={g.label || 'all'}>
              {g.label && (
                <div className="flex items-center justify-between border-b border-border bg-foreground/1.5 px-5 py-2 text-[11px] font-medium text-muted-foreground">
                  <span>{g.label}</span>
                  <span className="font-mono">{g.items.length}</span>
                </div>
              )}
              <ul>
                {g.items.map((i) => (
                  <IncidentRow key={i.id} incident={i} asset={assetsById.get(i.assetId)} variant="full" />
                ))}
              </ul>
            </div>
          ))
        )}
      </SurfaceCard>
    </PageContainer>
  )
}

/** Active incidents by severity as a single segmented bar. */
function SeverityBar({ incidents }: { incidents: Incident[] }) {
  const total = incidents.length || 1
  const parts = SEVERITY_ORDER.map((s) => ({ s, n: incidents.filter((i) => i.severity === s).length })).filter((p) => p.n)
  return (
    <div className="flex items-center gap-3">
      <span className="shrink-0 text-[11px] text-muted-foreground">Active by severity</span>
      <div className="flex h-1.5 flex-1 gap-0.5 overflow-hidden rounded-full">
        {parts.map((p) => (
          <div
            key={p.s}
            className={cn('h-full', toneStyles[severityTone[p.s]].solid)}
            style={{ width: `${(p.n / total) * 100}%` }}
            title={`${p.s}: ${p.n}`}
          />
        ))}
      </div>
      <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
        {parts.map((p) => `${p.n} ${p.s.toLowerCase()}`).join(' · ')}
      </span>
    </div>
  )
}
