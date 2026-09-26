import type { DetectionSource, Incident, IncidentStatus, Severity } from '@/api/types'
import { LoadingState, MeterBar, Panel } from '@/components/netra'
import { useCountUp } from '@/hooks/useCountUp'
import { detectionSourceMeta } from '@/lib/sources'
import { SEVERITY_ORDER, severityTone, statusMeta, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: 'var(--sev-critical)',
  HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)',
  LOW: 'var(--sev-low)',
  INFO: 'var(--sev-info)',
}

const PIPELINE: IncidentStatus[] = ['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING']
const SOURCES: DetectionSource[] = ['HYBRID', 'SURICATA', 'ML_ANOMALY', 'THREAT_INTEL']

export function SeverityDistributionPanel({ incidents }: { incidents?: Incident[] }) {
  return (
    <Panel title="Risk distribution" description="Active incidents by severity and response stage" className="h-full">
      {!incidents ? (
        <LoadingState variant="inline" />
      ) : (
        <Content incidents={incidents} />
      )}
    </Panel>
  )
}

function Content({ incidents }: { incidents: Incident[] }) {
  const total = incidents.length
  const counts = SEVERITY_ORDER.map((s) => ({ severity: s, count: incidents.filter((i) => i.severity === s).length }))
  const pipeline = PIPELINE.map((s) => ({ status: s, count: incidents.filter((i) => i.status === s).length }))
  const sources = SOURCES.map((s) => ({ source: s, count: incidents.filter((i) => i.detectionSource === s).length }))

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-6">
        <Donut data={counts.filter((c) => c.count > 0)} total={total} />
        <ul className="min-w-0 flex-1 space-y-2">
          {counts.map(({ severity, count }) => (
            <li key={severity} className={cn('flex items-center gap-2.5 text-xs', count === 0 && 'opacity-40')}>
              <span className={cn('size-2 rounded-xs', toneStyles[severityTone[severity]].solid)} />
              <span className="flex-1 text-muted-foreground capitalize">{severity.toLowerCase()}</span>
              <span className="font-mono font-medium tabular-nums">{count}</span>
              <span className="w-9 text-right font-mono text-muted-foreground tabular-nums">
                {total ? Math.round((count / total) * 100) : 0}%
              </span>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <div className="mb-2.5 text-xs font-medium text-foreground/85">Response pipeline</div>
        <div className="flex h-2 gap-0.5 overflow-hidden rounded-full">
          {pipeline
            .filter((p) => p.count > 0)
            .map((p) => (
              <div
                key={p.status}
                className={cn('h-full first:rounded-l-full last:rounded-r-full', toneStyles[statusMeta[p.status].tone].solid)}
                style={{ flexGrow: p.count }}
                title={`${statusMeta[p.status].label}: ${p.count}`}
              />
            ))}
        </div>
        <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
          {pipeline.map((p) => (
            <div key={p.status} className="flex items-center gap-2 text-xs">
              <span className={cn('size-1.5 rounded-full', toneStyles[statusMeta[p.status].tone].solid)} />
              <span className="flex-1 truncate text-muted-foreground">{statusMeta[p.status].label}</span>
              <span className="font-mono font-medium tabular-nums">{p.count}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-2.5 text-xs font-medium text-foreground/85">Detected by</div>
        <ul className="space-y-2">
          {sources.map(({ source, count }) => {
            const meta = detectionSourceMeta[source]
            return (
              <li key={source} className="grid grid-cols-[minmax(0,9rem)_1fr_1.5rem] items-center gap-3 text-xs">
                <span className="inline-flex items-center gap-1.5 truncate text-muted-foreground">
                  <meta.icon className="size-3.5 shrink-0" />
                  {meta.short}
                </span>
                <MeterBar value={count} max={total} tone="neutral" />
                <span className="text-right font-mono font-medium tabular-nums">{count}</span>
              </li>
            )
          })}
        </ul>
      </div>
    </div>
  )
}

/** Donut with 2px surface gaps between segments; centre shows the total. */
function Donut({ data, total }: { data: { severity: Severity; count: number }[]; total: number }) {
  const shown = useCountUp(total)
  const size = 128
  const stroke = 14
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const gap = data.length > 1 ? 2 : 0
  const segments = data.map((d, i) => {
    const offset = data.slice(0, i).reduce((sum, p) => sum + (p.count / total) * c, 0)
    return { ...d, len: (d.count / total) * c, offset }
  })

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeOpacity={0.06} strokeWidth={stroke} className="text-foreground" />
        {segments.map(({ severity, count, len, offset }) => (
          <circle
            key={severity}
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={SEV_COLOR[severity]}
            strokeWidth={stroke}
            strokeDasharray={`${Math.max(0, len - gap)} ${c}`}
            strokeDashoffset={-offset}
            className="transition-[stroke-dasharray] duration-700"
          >
            <title>{`${severity}: ${count}`}</title>
          </circle>
        ))}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="metric text-3xl">{Math.round(shown)}</span>
        <span className="mt-1 text-[11px] text-muted-foreground">active</span>
      </div>
    </div>
  )
}
