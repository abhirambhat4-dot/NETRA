import type { TechniqueObservation } from '@/api/types'
import { LoadingState, MeterBar } from '@/components/netra'
import { formatNumber } from '@/lib/format'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

/** Top observed ATT&CK techniques (Command Center → Detection intelligence). */
export function TechniqueList({ techniques }: { techniques?: TechniqueObservation[] }) {
  const maxEvents = Math.max(1, ...(techniques ?? []).map((t) => t.eventCount))

  return !techniques ? (
        <LoadingState className="px-5 py-2" count={6} />
      ) : (
        <ul>
          {techniques.slice(0, 6).map((t) => {
            const tone = toneStyles[severityTone[t.highestSeverity]]
            return (
              <li key={t.technique.id} className="flex items-center gap-3 border-b border-border/70 px-5 py-2.5 transition-colors last:border-b-0 hover:bg-foreground/2">
                <span className="w-14 shrink-0 rounded-md border border-primary/20 bg-primary/8 py-0.5 text-center font-mono text-[11px] font-medium text-primary">
                  {t.technique.id}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[13px] font-medium">{t.technique.name}</span>
                    {t.activeIncidentCount > 0 && (
                      <span className={cn('size-1.5 shrink-0 rounded-full', tone.solid)} title={`Highest severity: ${t.highestSeverity}`} />
                    )}
                  </div>
                  <div className="mt-1.5 flex items-center gap-2.5">
                    <MeterBar value={t.eventCount} max={maxEvents} tone="accent" className="max-w-32 flex-1 opacity-80" />
                    <span className="truncate text-[11px] text-muted-foreground">{t.technique.tactic}</span>
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <div className="font-mono text-[13px] font-medium tabular-nums">{formatNumber(t.eventCount)}</div>
                  <div className="text-[11px] text-muted-foreground">
                    {t.incidentCount} incident{t.incidentCount > 1 ? 's' : ''}
                  </div>
                </div>
              </li>
            )
          })}
        </ul>
      )
}
