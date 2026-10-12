import type * as React from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { IncidentQueueItem, Severity } from '@/api/types'
import { IncidentRow } from '@/components/incidents/IncidentRow'
import { EmptyState, LoadingState, Panel } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

/** The Command Center shows the top of the queue; the rest is one click away. */
const TOP = 5

const LEVELS: { key: Severity; label: string }[] = [
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'HIGH', label: 'High' },
  { key: 'MEDIUM', label: 'Medium' },
  { key: 'LOW', label: 'Low' },
]

interface Props {
  incidents?: IncidentQueueItem[]
  /** `incidentsBySeverity` exactly as the dashboard stats returned it; `null` means not returned. */
  bySeverity?: Record<Severity, number | null>
  className?: string
  style?: React.CSSProperties
}

export function PrioritizedIncidentsPanel({ incidents, bySeverity, className, style }: Props) {
  return (
    <Panel
      title="Prioritised incidents"
      description="Active incidents ranked by NETRA risk score"
      flush
      className={cn('cc-card h-full rounded-2xl', className)}
      style={style}
      actions={
        <Button variant="ghost" size="sm" asChild className="text-muted-foreground">
          <Link to={ROUTES.incidents}>
            View all <ArrowRight />
          </Link>
        </Button>
      }
    >
      {bySeverity && <SeveritySummary bySeverity={bySeverity} />}

      {!incidents ? (
        <LoadingState className="px-5 py-2" count={6} />
      ) : incidents.length === 0 ? (
        <EmptyState title="No active incidents" description="NETRA has nothing that needs a decision right now." />
      ) : (
        <>
          <ul className="border-t border-border">
            {incidents.slice(0, TOP).map((i, index) => (
              <IncidentRow key={i.id} incident={i} entryIndex={index} priorityRank={index + 1} />
            ))}
          </ul>
          {incidents.length > TOP && (
            <Link
              to={ROUTES.incidents}
              className="flex items-center justify-between border-t border-border px-5 pt-2.5 pb-0.5 text-xs text-muted-foreground transition-colors hover:text-primary"
            >
              <span>
                {incidents.length - TOP} more active incident{incidents.length - TOP > 1 ? 's' : ''} in the queue
              </span>
              <ArrowRight className="size-3.5" />
            </Link>
          )}
        </>
      )}
    </Panel>
  )
}

/**
 * Active incidents per severity, straight from the stats response. A count the API does not
 * return stays "Not returned" — it is never derived from the queue or shown as zero. The
 * proportion bar appears only when every count is known, so it cannot imply a false split.
 */
function SeveritySummary({ bySeverity }: { bySeverity: Record<Severity, number | null> }) {
  const levels = bySeverity.INFO == null ? LEVELS : [...LEVELS, { key: 'INFO' as const, label: 'Info' }]
  const counts = levels.map((level) => ({ ...level, count: bySeverity[level.key] }))
  const allKnown = counts.every((c) => typeof c.count === 'number')
  const total = allKnown ? counts.reduce((sum, c) => sum + (c.count ?? 0), 0) : 0

  return (
    <div className="px-5 pb-4">
      <dl aria-label="Active incidents by severity" className={cn('grid grid-cols-2 gap-2 sm:grid-cols-4', levels.length > 4 && 'sm:grid-cols-5')}>
        {counts.map(({ key, label, count }) => {
          const tone = toneStyles[severityTone[key]]
          const known = typeof count === 'number'
          return (
            <div key={key} className="rounded-xl border border-border bg-foreground/2 px-3.5 py-3">
              <dt className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
                <span aria-hidden className={cn('size-1.5 rounded-full', known ? tone.solid : 'bg-muted-foreground/40')} />
                {label}
              </dt>
              <dd className={cn('mt-2', known ? 'metric text-2xl text-foreground' : 'text-xs font-medium text-muted-foreground')}>
                {known ? count : 'Not returned'}
              </dd>
            </div>
          )
        })}
      </dl>

      {allKnown && total > 0 && (
        <div aria-hidden className="mt-3 flex h-1.5 gap-0.5 overflow-hidden rounded-full">
          {counts.map(({ key, count }) =>
            count ? (
              <span key={key} className={cn('cc-grow h-full rounded-full', toneStyles[severityTone[key]].solid)} style={{ width: `${(count / total) * 100}%` }} />
            ) : null,
          )}
        </div>
      )}

      {!allKnown && (
        <p className="mt-2.5 text-[11px] text-muted-foreground">
          Counts marked “Not returned” are not provided by the current API and are not estimated.
        </p>
      )}
    </div>
  )
}
