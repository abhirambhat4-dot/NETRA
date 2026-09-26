import type { SystemComponentHealth } from '@/api/types'
import { LoadingState, Panel, StatusDot } from '@/components/netra'
import { statusMeta } from '@/lib/tones'
import { cn } from '@/lib/utils'

export function SystemHealthPanel({ health }: { health?: SystemComponentHealth[] }) {
  const healthy = health?.filter((c) => c.status === 'HEALTHY').length ?? 0
  const allOk = health && healthy === health.length
  const avgUptime = health ? health.reduce((s, c) => s + c.uptime, 0) / health.length : 0

  return (
    <Panel title="System health" description="NETRA pipeline components" className="h-full">
      {!health ? (
        <LoadingState count={6} />
      ) : (
        <div className="flex flex-col gap-4">
          <div className={cn('flex items-center justify-between rounded-lg border px-3.5 py-3', allOk ? 'border-low/20 bg-low/6' : 'border-medium/25 bg-medium/8')}>
            <div className="flex items-center gap-2.5">
              <StatusDot tone={allOk ? 'low' : 'medium'} pulse />
              <span className={cn('text-[13px] font-medium', allOk ? 'text-low' : 'text-medium')}>
                {allOk ? 'All systems operational' : 'Degraded performance'}
              </span>
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              {healthy}/{health.length}
            </span>
          </div>

          <ul className="divide-y divide-border/70">
            {health.map((c) => {
              const meta = statusMeta[c.status]
              return (
                <li key={c.component} className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0">
                  <StatusDot tone={meta.tone} size="sm" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-medium">{c.name}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{c.throughput}</div>
                  </div>
                  <div className="text-right">
                    <div className="font-mono text-xs tabular-nums">{c.latencyMs} ms</div>
                    <div className={cn('text-[11px]', c.status === 'HEALTHY' ? 'text-low/90' : 'text-medium')}>{meta.label}</div>
                  </div>
                </li>
              )
            })}
          </ul>

          <div className="flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
            <span>30-day uptime</span>
            <span className="font-mono text-foreground/90">{(avgUptime * 100).toFixed(2)}%</span>
          </div>
        </div>
      )}
    </Panel>
  )
}
