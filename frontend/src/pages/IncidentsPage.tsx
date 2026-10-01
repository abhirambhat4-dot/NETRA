import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import type {
  BackendResponseAction,
  IncidentQueueItem,
  IncidentQueueSort,
  IncidentQueueStateFilter,
  Severity,
} from '@/api/types'
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
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { useCountUp } from '@/hooks/useCountUp'
import { ACTION_LABEL } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { SEVERITY_ORDER, riskToSeverity, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { incidentQueueService } from '@/services'
import { HttpError } from '@/services/http'

type SevFilter = Exclude<Severity, 'INFO'> | 'ALL'
type StateFilter = IncidentQueueStateFilter
type Sort = IncidentQueueSort

const ACTIVE = new Set([
  'DETECTED',
  'UNDERSTOOD',
  'PRIORITISED',
  'VERIFIED',
  'AUTHORIZED',
  'NEW',
  'INVESTIGATING',
  'AWAITING_AUTHORIZATION',
  'CONTAINING',
])
const stateOf = (incident: IncidentQueueItem): Exclude<StateFilter, 'ALL'> | undefined => {
  if (ACTIVE.has(incident.lifecycle)) return 'ACTIVE'
  if (incident.lifecycle === 'CONTAINED') return 'CONTAINED'
  if (incident.lifecycle === 'LEARNED') return 'LEARNED'
  return undefined
}

function actionLabel(incident: IncidentQueueItem): string | undefined {
  const action = incident.latestDecision?.action ?? incident.recommendedAction
  if (!action) return undefined
  return ACTION_LABEL[action as keyof typeof ACTION_LABEL] ?? readableAction(action)
}

function readableAction(action: BackendResponseAction): string {
  return action.replaceAll('_', ' ').toLowerCase().replace(/^\w/, (letter) => letter.toUpperCase())
}

export function IncidentsPage() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<SevFilter>('ALL')
  const [state, setState] = useState<StateFilter>('ALL')
  const [sort, setSort] = useState<Sort>('risk')

  const filterKey = [search.trim(), severity, state, sort].join(':')
  const incidents = useQuery(`incidents-live-${filterKey}`, () =>
    incidentQueueService.list({
      search: search.trim() || undefined,
      severity: severity === 'ALL' ? undefined : severity,
      state,
      sort,
    }),
  )

  const all = useMemo(() => incidents.data ?? [], [incidents.data])
  const active = all.filter((incident) => ACTIVE.has(incident.lifecycle))
  const filtered = all

  const groups: { label: string; items: IncidentQueueItem[]; bar?: boolean }[] =
    state === 'ALL'
      ? [
          { label: 'Active', items: filtered.filter((incident) => ACTIVE.has(incident.lifecycle)), bar: true },
          { label: 'Closed', items: filtered.filter((incident) => !ACTIVE.has(incident.lifecycle)) },
        ].filter((g) => g.items.length)
      : [{ label: '', items: filtered }]

  const activeRisks = active.flatMap((incident) => (incident.riskScore === null ? [] : [incident.riskScore]))
  const meanRisk = activeRisks.length
    ? Math.round(activeRisks.reduce((sum, risk) => sum + risk, 0) / activeRisks.length)
    : null
  const criticalCount = active.filter((incident) => incident.severity === 'CRITICAL').length
  const highRiskCount = active.filter((incident) => incident.riskScore !== null && incident.riskScore >= 65).length
  const awaitingActionCount = all.filter((incident) => incident.lifecycle === 'VERIFIED' || incident.lifecycle === 'AWAITING_AUTHORIZATION').length
  const activeAnimated = useCountUp(active.length, 700)
  const criticalAnimated = useCountUp(criticalCount, 700)
  const highRiskAnimated = useCountUp(highRiskCount, 700)
  const awaitingAnimated = useCountUp(awaitingActionCount, 700)
  const countState = (s: Exclude<StateFilter, 'ALL'>) => all.filter((i) => stateOf(i) === s).length
  const filtersActive = severity !== 'ALL' || state !== 'ALL' || search !== ''

  return (
    <PageContainer>
      <PageHeader
        eyebrow="Prioritisation workspace"
        title="INCIDENTS"
        description="See which correlated situations matter most, why their risk is elevated, and where analyst action is waiting."
      />

      <MetricStrip
        metrics={[
          {
            label: 'Active incidents',
            value: incidents.data ? Math.round(activeAnimated) : '—',
            hint: (
              <>
                mean risk{' '}
                <span className={meanRisk === null ? 'text-muted-foreground' : toneStyles[severityTone[riskToSeverity(meanRisk)]].text}>
                  {incidents.data ? meanRisk ?? 'N/A' : '—'}
                </span>{' '}
                  · {incidents.data ? all.length : '—'} in queue
              </>
            ),
          },
          { label: 'Critical incidents', value: incidents.data ? Math.round(criticalAnimated) : '—', valueClassName: 'text-critical', hint: 'active situations' },
          { label: 'High risk', value: incidents.data ? Math.round(highRiskAnimated) : '—', valueClassName: 'text-high', hint: 'risk score ≥65' },
          { label: 'Awaiting action', value: incidents.data ? Math.round(awaitingAnimated) : '—', valueClassName: 'text-medium', hint: 'verification or authorization gate' },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden" data-guide-target="incident-queue">
        {/* Filters: search + state + sort on one line; severity as quiet chips below */}
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2.5">
            <SearchInput value={search} onChange={setSearch} placeholder="Search incident, description, asset…" className="w-full sm:w-72" />
            <SegmentedControl
              aria-label="State"
              value={state}
              onChange={setState}
              options={[
                { value: 'ALL', label: 'All' },
                { value: 'ACTIVE', label: `Active ${countState('ACTIVE')}` },
                { value: 'CONTAINED', label: `Contained ${countState('CONTAINED')}` },
                { value: 'LEARNED', label: `Learned ${countState('LEARNED')}` },
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
          <div>
            <ErrorState
              title={incidents.error instanceof HttpError && incidents.error.status === 401 ? 'Authentication required' : 'Incidents unavailable'}
              message={incidents.error instanceof HttpError && incidents.error.status === 401 ? undefined : incidents.error.message}
              onRetry={incidents.error instanceof HttpError && incidents.error.status === 401 ? undefined : incidents.reload}
            />
            {incidents.error instanceof HttpError && incidents.error.status === 401 && (
              <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
            )}
          </div>
        ) : !incidents.data ? (
          <LoadingState className="p-5" count={8} />
        ) : filtered.length === 0 ? (
          <EmptyState
            title={filtersActive ? 'No incidents match' : 'No incidents available'}
            description={filtersActive ? 'Adjust the severity, state or search filters.' : 'No incident situations are currently available in the queue.'}
          />
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
                {g.items.map((i, index) => (
                  <IncidentRow
                    key={i.id}
                    incident={i}
                    variant="full"
                    action={actionLabel(i)}
                    entryIndex={index}
                    priorityRank={sort === 'risk' && ACTIVE.has(i.lifecycle) && i.riskScore !== null && index < 3 ? index + 1 : undefined}
                  />
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
function SeverityBar({ incidents }: { incidents: IncidentQueueItem[] }) {
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
