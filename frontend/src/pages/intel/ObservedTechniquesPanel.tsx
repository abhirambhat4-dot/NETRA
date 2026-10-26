import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { Severity } from '@/api/types'
import { EmptyState, ErrorState, LoadingState, Pagination, Panel, SearchInput, SegmentedControl, SelectFilter, SeverityBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { formatDateTime, formatNumber } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import {
  breakdown,
  catalogueName,
  DEFAULT_OBSERVED_FILTERS,
  OBSERVED_ORIGINS,
  OBSERVED_SOURCES,
  OBSERVED_WINDOWS,
  observedErrorView,
  observedTechniquesKey,
  ORIGIN_LABELS,
  techniqueFilter,
  updateObservedFilters,
  type BackendObservedTechnique,
  type ObservedTechniqueFilters,
} from '@/lib/observedTechniques'
import { cn } from '@/lib/utils'
import { observedTechniquesService } from '@/services'
import { HttpError } from '@/services/http'

const SEVERITIES = new Set<string>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
const INCIDENT_LINKS_SHOWN = 5
const SORT_OPTIONS = [
  { value: 'eventCount:desc', label: 'Most events' },
  { value: 'eventCount:asc', label: 'Fewest events' },
  { value: 'lastSeen:desc', label: 'Most recent' },
  { value: 'lastSeen:asc', label: 'Least recent' },
  { value: 'techniqueId:asc', label: 'Technique ID A–Z' },
  { value: 'techniqueId:desc', label: 'Technique ID Z–A' },
] as const
type SortOption = (typeof SORT_OPTIONS)[number]['value']

/**
 * Live ATT&CK observations: technique IDs that detection sources explicitly reported with their events
 * (GET /api/threat-intelligence/techniques/observed). Source-supplied evidence only — never inferred, and not a
 * measure of ATT&CK coverage. No catalogue is bundled, so technique names and tactics are not shown or invented.
 */
export function ObservedTechniquesPanel() {
  const [filters, setFilters] = useState<ObservedTechniqueFilters>(DEFAULT_OBSERVED_FILTERS)
  const change = (update: Partial<ObservedTechniqueFilters>) => setFilters((current) => updateObservedFilters(current, update))
  const technique = techniqueFilter(filters.techniqueId)
  // The key changes with every parameter sent; useQuery ignores the response of a superseded key.
  const observed = useQuery(observedTechniquesKey(filters), () => observedTechniquesService.list(filters))
  const page = observed.data
  const error = observed.error ? observedErrorView(observed.error instanceof HttpError ? observed.error.status : null, observed.error.message) : null

  return (
    <Panel
      title="Observed ATT&CK techniques"
      description={`Technique IDs reported by detection sources with their events · last ${filters.days} ${filters.days === 1 ? 'day' : 'days'} · source-supplied evidence, not inferred and not ATT&CK coverage`}
      actions={
        <SegmentedControl
          aria-label="Time window"
          value={String(filters.days)}
          onChange={(days) => change({ days: Number(days) })}
          options={OBSERVED_WINDOWS.map((days) => ({ value: String(days), label: `${days}d` }))}
        />
      }
    >
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <SelectFilter
          label="Source"
          value={filters.source}
          onChange={(source) => change({ source })}
          options={[{ value: 'ALL', label: 'All' }, ...OBSERVED_SOURCES.map((source) => ({ value: source, label: source }))]}
        />
        <SelectFilter
          label="Origin"
          value={filters.origin}
          onChange={(origin) => change({ origin })}
          options={[{ value: 'ALL', label: 'All' }, ...OBSERVED_ORIGINS.map((origin) => ({ value: origin, label: ORIGIN_LABELS[origin] }))]}
        />
        <SelectFilter<SortOption>
          label="Sort"
          value={`${filters.sortBy}:${filters.sortOrder}` as SortOption}
          onChange={(value) => {
            const [sortBy, sortOrder] = value.split(':') as [ObservedTechniqueFilters['sortBy'], ObservedTechniqueFilters['sortOrder']]
            change({ sortBy, sortOrder })
          }}
          options={[...SORT_OPTIONS]}
        />
        <SearchInput
          value={filters.techniqueId}
          onChange={(techniqueId) => change({ techniqueId })}
          placeholder="Exact technique ID, e.g. T1110"
          className="min-w-52 flex-1"
        />
      </div>
      {technique === 'invalid' && (
        <p role="note" className="-mt-2 mb-3 text-xs text-muted-foreground">
          Enter a full technique ID such as T1110 or T1110.001; the technique filter is not applied until then.
        </p>
      )}

      {error ? (
        <div>
          <ErrorState title={error.title} message={error.message} onRetry={error.retry ? observed.reload : undefined} />
          {error.signIn && (
            <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
          )}
        </div>
      ) : !page ? (
        <LoadingState count={4} />
      ) : page.items.length === 0 ? (
        <EmptyState
          title="No observed techniques"
          description={`No detection source reported ATT&CK technique IDs for events in the last ${page.windowDays} ${page.windowDays === 1 ? 'day' : 'days'} matching these filters.`}
        />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[13px]">
              <thead>
                <tr className="border-b border-border text-[11px] text-muted-foreground">
                  <th className="py-2 pr-3 font-medium">Technique</th>
                  <th className="px-3 text-right font-medium">Observed events</th>
                  <th className="px-3 font-medium">First / last seen (UTC)</th>
                  <th className="px-3 font-medium">Sources · origins</th>
                  <th className="px-3 font-medium">Associated incidents</th>
                  <th className="py-2 pl-3 text-right font-medium">Highest severity</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((item) => (
                  <ObservedRow key={item.techniqueId} item={item} />
                ))}
              </tbody>
            </table>
          </div>
          <div className="-mx-5 -mb-5 mt-3 border-t border-border">
            <Pagination page={page.page} pageSize={page.pageSize} total={page.total} onChange={(next) => change({ page: next })} />
          </div>
          <p className="mt-3 text-[11px] text-muted-foreground">
            As of {formatDateTime(page.asOf)} UTC. Technique names and tactics are not shown: no ATT&CK catalogue is bundled with NETRA.
          </p>
        </>
      )}
    </Panel>
  )
}

function ObservedRow({ item }: { item: BackendObservedTechnique }) {
  const name = catalogueName(item.catalogue)
  const hidden = Math.max(0, item.incidentCount - Math.min(item.incidentIds.length, INCIDENT_LINKS_SHOWN))
  return (
    <tr className="border-b border-border/60 align-top transition-colors last:border-b-0 hover:bg-foreground/2">
      <td className="py-2.5 pr-3">
        <span className="font-mono text-xs text-primary">{item.techniqueId}</span>
        {name ? <span className="ml-2">{name}</span> : <span className="ml-2 text-[11px] text-muted-foreground">Name not in catalogue</span>}
      </td>
      <td className="px-3 py-2.5 text-right font-mono text-xs">{formatNumber(item.eventCount)}</td>
      <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground">
        {formatDateTime(item.firstSeen)}
        <br />
        {formatDateTime(item.lastSeen)}
      </td>
      <td className="px-3 py-2.5 text-[11px] text-muted-foreground">
        <div>{breakdown(item.sources)}</div>
        <div>{breakdown(item.origins, ORIGIN_LABELS)}</div>
      </td>
      <td className="px-3 py-2.5">
        <div className="flex flex-wrap gap-1">
          {item.incidentIds.slice(0, INCIDENT_LINKS_SHOWN).map((id) => (
            <Link key={id} to={ROUTES.incident(id)} className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-foreground/85 transition-colors hover:border-primary/30 hover:text-primary">
              {id.slice(0, 8)}
            </Link>
          ))}
          {hidden > 0 && <span className="self-center text-[11px] text-muted-foreground">+{formatNumber(hidden)} more</span>}
          <span className={cn('self-center text-[11px]', item.activeIncidentCount ? 'text-foreground/80' : 'text-muted-foreground')}>
            {item.incidentCount === 0 ? 'None linked' : `${item.activeIncidentCount} of ${item.incidentCount} active`}
          </span>
        </div>
      </td>
      <td className="py-2.5 pl-3 text-right">
        {SEVERITIES.has(item.highestSeverity) ? <SeverityBadge severity={item.highestSeverity as Severity} /> : <span className="text-xs">{item.highestSeverity}</span>}
      </td>
    </tr>
  )
}
