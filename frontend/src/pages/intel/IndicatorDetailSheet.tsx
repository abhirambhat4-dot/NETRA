import { Link } from 'react-router-dom'
import type { EventsPageItem, ThreatIndicatorInventoryItem } from '@/api/types'
import { Button } from '@/components/ui/button'
import { DetailSection, DetailSheet, ErrorState, KeyValueList, LoadingState, MeterBar, SeverityBadge, StatusBadge, ToneBadge } from '@/components/netra'
import { defang, shortHash } from '@/lib/defang'
import { formatClock, formatDateTime, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { HttpError } from '@/services/http'

interface Props {
  indicator?: ThreatIndicatorInventoryItem
  indicatorId: string | null
  loading: boolean
  error?: Error
  onRetry: () => void
  /** Notable events, used to list observed matches for IP indicators. */
  events: EventsPageItem[]
  onClose: () => void
}

/** Full indicator context: metadata, history and where NETRA saw it. */
export function IndicatorDetailSheet({ indicator, indicatorId, loading, error, onRetry, events, onClose }: Props) {
  const display = indicator && (indicator.type === 'HASH' ? shortHash(indicator.value) : defang(indicator.value, indicator.type))
  return (
    <DetailSheet
      open={!!indicatorId || !!indicator}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={indicator ? `${indicator.id} · ${indicator.type} indicator` : indicatorId ?? undefined}
      title={<span className="font-mono text-base break-all">{display ?? (loading ? 'Loading indicator' : 'Threat indicator')}</span>}
      description={indicator?.description ?? undefined}
    >
      {loading && !indicator && <LoadingState variant="inline" label="Loading indicator details…" />}
      {error && (
        <ErrorState
          title={error instanceof HttpError && error.status === 401 ? 'Authentication required' : 'Indicator details unavailable'}
          message={error instanceof HttpError && error.status === 401 ? undefined : error.message}
          onRetry={error instanceof HttpError && error.status === 401 ? undefined : onRetry}
        />
      )}
      {error instanceof HttpError && error.status === 401 && (
        <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
      )}
      {indicator && !error && <Body indicator={indicator} events={events} />}
    </DetailSheet>
  )
}

function Body({ indicator: i, events }: { indicator: ThreatIndicatorInventoryItem; events: EventsPageItem[] }) {
  const matches = i.type === 'IP' ? events.filter((e) => e.sourceIp === i.value || e.destinationIp === i.value) : []

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={i.severity} />
        <span className="rounded-md border border-border px-2 py-0.5 text-[11px] text-foreground/85">{i.source}</span>
        <ToneBadge tone={i.isActive === true ? 'low' : 'neutral'} size="sm">
          {i.isActive === undefined || i.isActive === null ? 'Status not provided' : i.isActive ? 'Active' : 'Inactive'}
        </ToneBadge>
      </div>

      <div className="surface-inset space-y-2 rounded-lg p-3.5">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Feed confidence</span>
          <span className="font-mono">{i.confidence === null ? 'Not provided' : `${Math.round(i.confidence * 100)}%`}</span>
        </div>
        {i.confidence !== null && <MeterBar value={i.confidence * 100} tone={i.confidence >= 0.8 ? 'accent' : 'neutral'} />}
      </div>

      <DetailSection title="History">
        <KeyValueList
          columns={2}
          items={[
            { label: 'First seen', value: `${formatDateTime(i.firstSeen)} UTC` },
            { label: 'Last seen', value: timeAgo(i.lastSeen) },
            { label: 'Correlated events', value: i.matchCount === null ? 'Not provided' : i.matchCount.toLocaleString('en-US'), mono: true },
            { label: 'Raw value', value: i.type === 'HASH' ? i.value : defang(i.value, i.type), mono: true },
          ]}
        />
      </DetailSection>

      <DetailSection title="Classification">
        {i.mitreTechniqueIds === null && i.tags === null ? (
          <p className="text-xs text-muted-foreground">Classification data is not provided by this endpoint.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {(i.mitreTechniqueIds ?? []).map((t) => (
              <span key={t} className="rounded border border-primary/20 bg-primary/8 px-1.5 py-0.5 font-mono text-[11px] text-primary">
                {t}
              </span>
            ))}
            {(i.tags ?? []).map((t) => (
              <span key={t} className="rounded border border-border px-1.5 py-0.5 text-[11px] text-muted-foreground">
                {t}
              </span>
            ))}
          </div>
        )}
      </DetailSection>

      <DetailSection title={`Linked incidents (${i.incidentIds?.length ?? '—'})`}>
        {i.incidentIds === null ? (
          <p className="text-xs text-muted-foreground">Incident links are not provided by this endpoint.</p>
        ) : i.incidentIds.length === 0 ? (
          <p className="text-xs text-muted-foreground">Not linked to an incident — kept as context for future correlation.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {(i.incidentIds ?? []).map((id) => (
              <Link
                key={id}
                to={ROUTES.incident(id)}
                className="rounded-md border border-border px-2 py-1 font-mono text-[11px] text-foreground/85 transition-colors hover:border-primary/30 hover:text-primary"
              >
                {id} →
              </Link>
            ))}
          </div>
        )}
      </DetailSection>

      {i.type === 'IP' && (
        <DetailSection title={`Matching events (${matches.length})`}>
          {matches.length === 0 ? (
            <p className="text-xs text-muted-foreground">No retained notable event references this address.</p>
          ) : (
            <ul className="surface-inset divide-y divide-border/70 overflow-hidden rounded-lg">
              {matches.slice(0, 8).map((e) => (
                <li key={e.id}>
                  <Link to={`${ROUTES.events}?event=${e.id}`} className="flex items-center gap-3 px-3.5 py-2.5 transition-colors hover:bg-foreground/3">
                    <span className="font-mono text-[11px] text-muted-foreground">{formatClock(e.timestamp)}</span>
                    <span className="min-w-0 flex-1 truncate text-[13px]">{e.eventType}</span>
                    <StatusBadge status={e.status} size="sm" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </DetailSection>
      )}
    </>
  )
}
