import type { DashboardStats } from '@/api/types'
import { LoadingState, MeterBar, Panel, RiskGauge } from '@/components/netra'
import { cn } from '@/lib/utils'

export function RiskPosturePanel({ stats, demo = false }: { stats?: DashboardStats; demo?: boolean }) {
  return (
    <Panel title="Current risk posture" description={demo ? 'Overall risk score from interconnected mock data' : 'Overall risk score returned by the dashboard API'} className="h-full">
      {!stats ? (
        <LoadingState variant="inline" label="Scoring…" />
      ) : (
        // Container query: gauge beside details when the panel is wide (tablet / laptop).
        <div className="@container h-full">
          <div className="flex h-full flex-col justify-between gap-5 @2xl:flex-row @2xl:items-center @2xl:gap-10">
            <div className="flex justify-center pt-1 @2xl:pt-0">
              {stats.overallRisk === null ? (
                <div className="grid size-[228px] place-items-center text-sm text-muted-foreground">Risk unavailable</div>
              ) : (
                <RiskGauge score={stats.overallRisk} size={228} />
              )}
            </div>

            <div className="flex flex-col gap-5 @2xl:flex-1">
              <div className="surface-inset grid grid-cols-3 divide-x divide-border rounded-lg">
                <MiniStat
                  label="Risk change"
                  value={stats.overallRiskChange === null ? 'Unavailable' : `${stats.overallRiskChange > 0 ? '+' : ''}${stats.overallRiskChange.toFixed(0)}%`}
                  valueClass={stats.overallRiskChange === null ? 'text-muted-foreground' : stats.overallRiskChange > 0 ? 'text-critical' : 'text-low'}
                />
                <MiniStat label="Critical assets" value={stats.criticalAssets} />
                <MiniStat label="Active incidents" value={stats.activeIncidents} />
              </div>

              <div>
                <div className="mb-2.5 flex items-center justify-between text-xs">
                  <span className="font-medium text-foreground/85">Top risk drivers</span>
                  <span className="text-muted-foreground">pts / 100</span>
                </div>
                <ul className="space-y-2.5">
                  {stats.riskDrivers.length === 0 && <li className="text-xs text-muted-foreground">Risk drivers unavailable</li>}
                  {stats.riskDrivers.slice(0, 4).map((f) => (
                    <li key={f.key} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1.5">
                      <span className="truncate text-xs text-muted-foreground">{f.label}</span>
                      <span className="font-mono text-xs text-foreground/90 tabular-nums">{f.contribution.toFixed(1)}</span>
                      <MeterBar value={f.contribution} max={f.weight * 100} tone="accent" className="col-span-2" />
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}

function MiniStat({ label, value, valueClass }: { label: string; value: string | number; valueClass?: string }) {
  return (
    <div className="px-3 py-2.5 text-center">
    <div className={cn(value === 'Unavailable' ? 'text-[11px] font-medium leading-tight' : 'metric text-lg', valueClass)}>{value}</div>
      <div className="mt-1 truncate text-[11px] text-muted-foreground">{label}</div>
    </div>
  )
}
