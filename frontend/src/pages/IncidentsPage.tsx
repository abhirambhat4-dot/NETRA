import { useMemo, useState } from 'react'
import type { Incident, IncidentDetail, Severity } from '@/api/types'
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
import { ACTION_LABEL } from '@/lib/format'
import { SEVERITY_ORDER, riskToSeverity, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetService, incidentService } from '@/services'

type SevFilter = Exclude<Severity, 'INFO'> | 'ALL'
type StateFilter = 'ALL' | 'ACTIVE' | 'CONTAINED' | 'RESOLVED'
type Sort = 'risk' | 'recent'

const ACTIVE = new Set(['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING'])
const stateOf = (i: Incident): Exclude<StateFilter, 'ALL'> =>
  ACTIVE.has(i.status) ? 'ACTIVE' : i.status === 'CONTAINED' ? 'CONTAINED' : 'RESOLVED'

/** "Block IP 192.168.1.25" — short form of the decision for the queue. */
function actionLabel(d: IncidentDetail): string | undefined {
  if (!d.decision) return undefined
  const { recommendedAction: a, target } = d.decision
  return a === 'MONITOR' ? 'Monitor — no containment' : `${ACTION_LABEL[a]} ${target}`
}

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

  // The list endpoint has no decision field, so recommended actions come from
  // each active incident's detail (existing GET /incidents/{id}). Closed
  // incidents don't need one in the queue.
  const activeIds = active.map((i) => i.id).join(',')
  const decisions = useQuery(`incidents-decisions-${activeIds}`, () =>
    activeIds ? Promise.all(activeIds.split(',').map((id) => incidentService.get(id))) : Promise.resolve([]),
  )
  const actionById = useMemo(
    () => new Map((decisions.data ?? []).map((d) => [d.incident.id, actionLabel(d)])),
    [decisions.data],
  )

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

  const groups: { label: string; items: Incident[]; bar?: boolean }[] =
    state === 'ALL'
      ? [
          { label: 'Active', items: filtered.filter((i) => ACTIVE.has(i.status)), bar: true },
          { label: 'Closed', items: filtered.filter((i) => !ACTIVE.has(i.status)) },
        ].filter((g) => g.items.length)
      : [{ label: '', items: filtered }]

  const meanRisk = active.length ? Math.round(active.reduce((s, i) => s + i.riskScore, 0) / active.length) : 0
  const countState = (s: Exclude<StateFilter, 'ALL'>) => all.filter((i) => stateOf(i) === s).length
  const filtersActive = severity !== 'ALL' || state !== 'ALL' || search !== ''

  return (
    <PageContainer>
      <PageHeader
        title="Incidents"
        description="The incident command queue — correlated threats ranked by NETRA contextual risk, from detection through authorization, containment and memory."
      />

      <MetricStrip
        metrics={[
          {
            label: 'Active incidents',
            value: active.length,
            hint: (
              <>
                mean risk <span className={toneStyles[severityTone[riskToSeverity(meanRisk)]].text}>{meanRisk}</span> · {all.length} in 7 days
              </>
            ),
          },
          { label: 'Critical', value: active.filter((i) => i.severity === 'CRITICAL').length, valueClassName: 'text-critical', hint: 'active, risk ≥ 85' },
          { label: 'Awaiting authorization', value: all.filter((i) => i.status === 'AWAITING_AUTHORIZATION').length, valueClassName: 'text-medium', hint: 'decision needs approval' },
          { label: 'Contained', value: countState('CONTAINED'), valueClassName: 'text-low', hint: 'verified containment' },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden" data-guide-target="incident-queue">
        {/* Filters: search + state + sort on one line; severity as quiet chips below */}
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2.5">
            <SearchInput value={search} onChange={setSearch} placeholder="Search incident, IP, asset, technique…" className="w-full sm:w-72" />
            <SegmentedControl
              aria-label="State"
              value={state}
              onChange={setState}
              options={[
                { value: 'ALL', label: 'All' },
                { value: 'ACTIVE', label: `Active ${countState('ACTIVE')}` },
                { value: 'CONTAINED', label: `Contained ${countState('CONTAINED')}` },
                { value: 'RESOLVED', label: `Resolved ${countState('RESOLVED')}` },
              ]}
            />
            <div className="flex items-center gap-2 text-xs text-muted-foreground sm:ml-auto">
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
          <div className="flex flex-wrap items-center justify-between gap-2">
            <FilterChips
              aria-label="Severity"
              value={severity}
              onChange={setSeverity}
              options={[
                { value: 'ALL', label: 'All severities', count: all.length },
                ...SEVERITY_ORDER.filter((s): s is Exclude<Severity, 'INFO'> => s !== 'INFO').map((s) => ({
                  value: s,
                  label: s.charAt(0) + s.slice(1).toLowerCase(),
                  count: all.filter((i) => i.severity === s).length,
                  dot: toneStyles[severityTone[s]].solid,
                })),
              ]}
            />
            {filtersActive && (
              <button
                type="button"
                className="text-xs text-muted-foreground transition-colors hover:text-foreground"
                onClick={() => {
                  setSearch('')
                  setSeverity('ALL')
                  setState('ALL')
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        </div>

        {/* Column legend (desktop) */}
        {filtered.length > 0 && (
          <div className="hidden items-center gap-4 border-b border-border px-5 py-2 text-[11px] font-medium text-muted-foreground lg:flex">
            <span className="w-11 shrink-0">Risk</span>
            <span className="flex-1">Incident</span>
            <span className="w-36 shrink-0">Affected asset</span>
            <span className="hidden w-52 shrink-0 xl:block">Recommended action</span>
            <span className="w-44 shrink-0 text-right">Current state</span>
            <span className="w-4 shrink-0" />
          </div>
        )}

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
                <div className="flex items-center gap-3 border-b border-border bg-foreground/1.5 px-5 py-2 text-[11px] font-medium text-muted-foreground">
                  <span>{g.label}</span>
                  <span className="font-mono">{g.items.length}</span>
                  {g.bar && <SeverityBar incidents={g.items} />}
                </div>
              )}
              <ul>
                {g.items.map((i) => (
                  <IncidentRow key={i.id} incident={i} asset={assetsById.get(i.assetId)} variant="full" action={actionById.get(i.id)} />
                ))}
              </ul>
            </div>
          ))
        )}
      </SurfaceCard>
    </PageContainer>
  )
}

/** Incidents in a group by severity as a slim segmented bar. */
function SeverityBar({ incidents }: { incidents: Incident[] }) {
  const total = incidents.length || 1
  const parts = SEVERITY_ORDER.map((s) => ({ s, n: incidents.filter((i) => i.severity === s).length })).filter((p) => p.n)
  return (
    <div className="ml-auto flex min-w-0 flex-1 items-center justify-end gap-3">
      <div className="hidden h-1 w-full max-w-60 gap-0.5 overflow-hidden rounded-full sm:flex" aria-hidden>
        {parts.map((p) => (
          <div key={p.s} className={cn('h-full', toneStyles[severityTone[p.s]].solid)} style={{ width: `${(p.n / total) * 100}%` }} />
        ))}
      </div>
      <span className="shrink-0 font-mono text-[10px]">{parts.map((p) => `${p.n} ${p.s.toLowerCase()}`).join(' · ')}</span>
    </div>
  )
}
