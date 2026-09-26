import { Link } from 'react-router-dom'
import type { IncidentDetail } from '@/api/types'
import { Panel, SeverityBadge } from '@/components/netra'
import { formatClock, formatDateTime } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta } from '@/lib/sources'
import { cn } from '@/lib/utils'

function duration(fromIso: string, toIso: string) {
  const m = Math.max(1, Math.round((Date.parse(toIso) - Date.parse(fromIso)) / 60000))
  return m < 90 ? `${m} min` : m < 2880 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} d`
}

/** WHAT HAPPENED — detection evidence. */
export function EvidencePanel({ detail: d }: { detail: IncidentDetail }) {
  const i = d.incident
  const peak = Math.max(...d.events.map((e) => e.anomalyScore), 0)
  const src = detectionSourceMeta[i.detectionSource]
  const sources = [...new Set(d.events.map((e) => e.detectionSource))]

  const facts = [
    { label: 'Correlated events', value: i.eventCount.toLocaleString('en-US') },
    { label: 'Activity window', value: duration(i.firstSeen, i.lastSeen) },
    { label: 'Peak anomaly', value: `${Math.round(peak * 100)}%` },
    { label: 'Detection confidence', value: d.riskAssessment ? `${Math.round(d.riskAssessment.confidence * 100)}%` : '—' },
  ]

  return (
    <Panel
      title="What happened"
      description="Detection evidence correlated into this incident"
      actions={
        <span className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-[11px] text-foreground/85">
          <src.icon className="size-3.5" /> {src.label}
        </span>
      }
    >
      <p className="mb-4 max-w-3xl text-[13px] leading-relaxed text-foreground/85">{i.description}</p>

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-4">
        {facts.map((f) => (
          <div key={f.label} className="bg-surface px-4 py-3">
            <div className="text-[11px] text-muted-foreground">{f.label}</div>
            <div className="metric mt-1.5 text-xl">{f.value}</div>
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
        <Fact label="Source" value={i.sourceIp} mono />
        <Fact label="Destination" value={i.destinationIp} mono />
        <Fact label="Sensors" value={sources.map((s) => detectionSourceMeta[s].short).join(' + ')} />
      </div>

      <div className="mt-5">
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="font-medium text-foreground/85">Representative events</span>
          <Link to={`${ROUTES.events}?q=${i.id}`} className="text-muted-foreground transition-colors hover:text-primary">
            View in event stream →
          </Link>
        </div>
        <ul className="surface-inset divide-y divide-border/70 rounded-lg">
          {d.events.map((e) => {
            const s = detectionSourceMeta[e.detectionSource]
            return (
              <li key={e.id} className="grid grid-cols-[64px_minmax(0,1fr)_auto] items-center gap-3 px-3.5 py-2.5 sm:grid-cols-[72px_110px_minmax(0,1fr)_60px_auto]">
                <span className="font-mono text-[11px] text-muted-foreground" title={formatDateTime(e.timestamp)}>
                  {formatClock(e.timestamp)}
                </span>
                <span className="hidden items-center gap-1.5 text-[11px] text-foreground/80 sm:inline-flex">
                  <span className="size-1.5 rounded-full" style={{ background: s.color }} />
                  {s.short}
                </span>
                <span className="truncate text-[13px]">{e.eventType}</span>
                <span className={cn('hidden text-right font-mono text-[11px] sm:block', e.anomalyScore >= 0.75 ? 'text-high' : 'text-muted-foreground')}>
                  {Math.round(e.anomalyScore * 100)}%
                </span>
                <SeverityBadge severity={e.severity} size="sm" />
              </li>
            )
          })}
        </ul>
      </div>
    </Panel>
  )
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="surface-inset rounded-lg px-3.5 py-2.5">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className={cn('mt-0.5 truncate text-[13px]', mono && 'font-mono text-xs')}>{value}</div>
    </div>
  )
}
