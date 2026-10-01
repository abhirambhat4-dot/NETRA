import type { BackendEventSource, DetectionSource, IncidentLifecycleState, IncidentQueueItem, IncidentStatus, Severity } from '@/api/types'
import { LoadingState, MeterBar, Panel } from '@/components/netra'
import { useCountUp } from '@/hooks/useCountUp'
import { eventSourceMeta } from '@/lib/sources'
import { SEVERITY_ORDER, severityTone, statusMeta, toneStyles, type Tone } from '@/lib/tones'
import { cn } from '@/lib/utils'

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: 'var(--sev-critical)',
  HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)',
  LOW: 'var(--sev-low)',
  INFO: 'var(--sev-info)',
}

const PIPELINE: IncidentStatus[] = ['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING']
const LIVE_PIPELINE: { state: IncidentLifecycleState; tone: Tone }[] = [
  { state: 'DETECTED', tone: 'accent' },
  { state: 'UNDERSTOOD', tone: 'accent' },
  { state: 'PRIORITISED', tone: 'high' },
  { state: 'VERIFIED', tone: 'medium' },
  { state: 'AUTHORIZED', tone: 'medium' },
]
const MOCK_SOURCES: DetectionSource[] = ['HYBRID', 'SURICATA', 'ML_ANOMALY', 'THREAT_INTEL']
const LIVE_SOURCES: BackendEventSource[] = ['SURICATA', 'ML_ANOMALY', 'THREAT_INTEL', 'VULNERABILITY_SCAN', 'MANUAL']

export function SeverityDistributionPanel({ incidents, live }: { incidents?: IncidentQueueItem[]; live: boolean }) {
  return (
    <Panel title="Risk distribution" description="Active incidents by severity and response stage" className="h-full">
      {!incidents ? (
        <LoadingState variant="inline" />
      ) : (
        <Content incidents={incidents} live={live} />
      )}
    </Panel>
  )
}

function Content({ incidents, live }: { incidents: IncidentQueueItem[]; live: boolean }) {
  const total = incidents.length
  const counts = SEVERITY_ORDER.map((s) => ({ severity: s, count: incidents.filter((i) => i.severity === s).length }))
  const pipeline = (live ? LIVE_PIPELINE : PIPELINE.map((state) => ({ state, tone: statusMeta[state].tone }))).map(
    ({ state, tone }) => ({ state, tone, count: incidents.filter((incident) => incident.lifecycle === state).length }),
  )
  const sources = (live ? LIVE_SOURCES : MOCK_SOURCES).map((source) => ({
    source,
    count: incidents.filter((incident) => incident.detectionSource === source).length,
  }))

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
                key={p.state}
                className={cn('h-full first:rounded-l-full last:rounded-r-full', toneStyles[p.tone].solid)}
                style={{ flexGrow: p.count }}
                title={`${pipelineLabel(p.state)}: ${p.count}`}
              />
            ))}
        </div>
        <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
          {pipeline.map((p) => (
            <div key={p.state} className="flex items-center gap-2 text-xs">
              <span className={cn('size-1.5 rounded-full', toneStyles[p.tone].solid)} />
              <span className="flex-1 truncate text-muted-foreground">{pipelineLabel(p.state)}</span>
              <span className="font-mono font-medium tabular-nums">{p.count}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-2.5 text-xs font-medium text-foreground/85">Detected by</div>
        <ul className="space-y-2">
          {sources.map(({ source, count }) => {
            const meta = eventSourceMeta(source)
            return (
              <li key={source} className="grid grid-cols-[minmax(0,9rem)_1fr_1.5rem] items-center gap-3 text-xs">
                <span className="inline-flex items-center gap-1.5 truncate text-muted-foreground">
                  <meta.icon className="size-3.5 shrink-0" />
                  {meta.short}
                </span>
                <MeterBar value={count} max={Math.max(total, 1)} tone="neutral" />
                <span className="text-right font-mono font-medium tabular-nums">{count}</span>
              </li>
            )
          })}
        </ul>
      </div>
    </div>
  )
}

function pipelineLabel(state: IncidentStatus | IncidentLifecycleState): string {
  return state in statusMeta ? statusMeta[state as IncidentStatus].label : state.toLowerCase().replaceAll('_', ' ')
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
