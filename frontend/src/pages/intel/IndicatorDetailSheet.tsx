import { Link } from 'react-router-dom'
import type { SecurityEvent, ThreatIndicator } from '@/api/types'
import { DetailSection, DetailSheet, KeyValueList, MeterBar, SeverityBadge, StatusBadge } from '@/components/netra'
import { defang, shortHash } from '@/lib/defang'
import { formatClock, formatDateTime, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'

interface Props {
  indicator?: ThreatIndicator
  /** Notable events, used to list observed matches for IP indicators. */
  events: SecurityEvent[]
  onClose: () => void
}

/** Full indicator context: metadata, history and where NETRA saw it. */
export function IndicatorDetailSheet({ indicator, events, onClose }: Props) {
  const display = indicator && (indicator.type === 'HASH' ? shortHash(indicator.value) : defang(indicator.value, indicator.type))
  return (
    <DetailSheet
      open={!!indicator}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={indicator && `${indicator.id} · ${indicator.type} indicator`}
      title={<span className="font-mono text-base break-all">{display}</span>}
      description={indicator?.description}
    >
      {indicator && <Body indicator={indicator} events={events} />}
    </DetailSheet>
  )
}

function Body({ indicator: i, events }: { indicator: ThreatIndicator; events: SecurityEvent[] }) {
  const matches = i.type === 'IP' ? events.filter((e) => e.sourceIp === i.value || e.destinationIp === i.value) : []

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={i.severity} />
        <span className="rounded-md border border-border px-2 py-0.5 text-[11px] text-foreground/85">{i.source}</span>
      </div>

      <div className="surface-inset space-y-2 rounded-lg p-3.5">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Feed confidence</span>
          <span className="font-mono">{Math.round(i.confidence * 100)}%</span>
        </div>
        <MeterBar value={i.confidence * 100} tone={i.confidence >= 0.8 ? 'accent' : 'neutral'} />
      </div>

      <DetailSection title="History">
        <KeyValueList
          columns={2}
          items={[
            { label: 'First seen', value: `${formatDateTime(i.firstSeen)} UTC` },
            { label: 'Last seen', value: timeAgo(i.lastSeen) },
            { label: 'Correlated events', value: i.matchCount.toLocaleString('en-US'), mono: true },
            { label: 'Raw value', value: i.type === 'HASH' ? i.value : defang(i.value, i.type), mono: true },
          ]}
        />
      </DetailSection>

      <DetailSection title="Classification">
        <div className="flex flex-wrap gap-1.5">
          {i.mitreTechniqueIds.map((t) => (
            <span key={t} className="rounded border border-primary/20 bg-primary/8 px-1.5 py-0.5 font-mono text-[11px] text-primary">
              {t}
            </span>
          ))}
          {i.tags.map((t) => (
            <span key={t} className="rounded border border-border px-1.5 py-0.5 text-[11px] text-muted-foreground">
              {t}
            </span>
          ))}
        </div>
      </DetailSection>

      <DetailSection title={`Linked incidents (${i.incidentIds.length})`}>
        {i.incidentIds.length === 0 ? (
          <p className="text-xs text-muted-foreground">Not linked to an incident — kept as context for future correlation.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {i.incidentIds.map((id) => (
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
