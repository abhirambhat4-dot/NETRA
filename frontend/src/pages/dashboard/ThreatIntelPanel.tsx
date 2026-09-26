import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { TechniqueObservation } from '@/api/types'
import { LoadingState, MeterBar, Panel } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { formatNumber } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

export function ThreatIntelPanel({ techniques }: { techniques?: TechniqueObservation[] }) {
  const maxEvents = Math.max(1, ...(techniques ?? []).map((t) => t.eventCount))
  const tactics = new Set((techniques ?? []).map((t) => t.technique.tactic)).size

  return (
    <Panel
      title="MITRE ATT&CK activity"
      description={techniques ? `${techniques.length} techniques across ${tactics} tactics · last 7 days` : 'Observed techniques'}
      flush
      className="h-full"
      actions={
        <Button variant="ghost" size="sm" asChild className="text-muted-foreground">
          <Link to={ROUTES.threatIntelligence}>
            Intel <ArrowRight />
          </Link>
        </Button>
      }
    >
      {!techniques ? (
        <LoadingState className="px-5 py-2" count={6} />
      ) : (
        <ul className="border-t border-border">
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
      )}
    </Panel>
  )
}
