import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { SecurityEvent } from '@/api/types'
import { LoadingState, Panel, SeverityBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { formatClock } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta } from '@/lib/sources'
import { cn } from '@/lib/utils'

export function RecentEventsPanel({ events }: { events?: SecurityEvent[] }) {
  return (
    <Panel
      title="Recent security events"
      description="Live detections from Suricata, ML detector and threat intelligence"
      className="h-full"
      actions={
        <Button variant="ghost" size="sm" asChild className="text-muted-foreground">
          <Link to={ROUTES.events}>
            Event stream <ArrowRight />
          </Link>
        </Button>
      }
    >
      {!events ? (
        <LoadingState count={7} />
      ) : (
        <ol className="relative">
          {events.map((e, idx) => {
            const src = detectionSourceMeta[e.detectionSource]
            const last = idx === events.length - 1
            return (
              <li key={e.id} className="group relative grid grid-cols-[64px_20px_minmax(0,1fr)] gap-x-2 sm:grid-cols-[72px_20px_minmax(0,1fr)_auto]">
                <time dateTime={e.timestamp} className="pt-0.5 font-mono text-xs text-muted-foreground tabular-nums">
                  {formatClock(e.timestamp)}
                </time>

                {/* rail */}
                <div className="relative flex justify-center">
                  {!last && <span aria-hidden className="absolute top-5 -bottom-1 w-px bg-border" />}
                  <span
                    className="relative mt-0.5 grid size-4 place-items-center rounded-full ring-4 ring-surface"
                    style={{ background: `color-mix(in srgb, ${src.color} 22%, transparent)` }}
                  >
                    <span className="size-1.5 rounded-full" style={{ background: src.color }} />
                  </span>
                </div>

                <div className={cn('min-w-0', !last && 'pb-4')}>
                  <div className="truncate text-[13px] font-medium">{e.eventType}</div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-[11px] text-muted-foreground">
                    <span className="inline-flex items-center gap-1 text-foreground/75">
                      <src.icon className="size-3" />
                      {src.short}
                    </span>
                    <span className="text-muted-foreground/40">·</span>
                    <span className="font-mono">
                      {e.sourceIp} → {e.destinationIp}
                    </span>
                    {e.incidentId && (
                      <Link to={ROUTES.incident(e.incidentId)} className="ml-1 rounded border border-primary/20 bg-primary/8 px-1 font-mono text-[10px] text-primary transition-colors hover:bg-primary/15">
                        {e.incidentId}
                      </Link>
                    )}
                  </div>
                </div>

                <div className="hidden pt-0.5 sm:block">
                  <SeverityBadge severity={e.severity} size="sm" />
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </Panel>
  )
}
