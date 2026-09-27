import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { Asset, Incident } from '@/api/types'
import { IncidentRow } from '@/components/incidents/IncidentRow'
import { EmptyState, LoadingState, Panel } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'

/** The Command Center shows the top of the queue; the rest is one click away. */
const TOP = 5

interface Props {
  incidents?: Incident[]
  assetsById: Map<string, Asset>
}

export function PrioritizedIncidentsPanel({ incidents, assetsById }: Props) {
  return (
    <Panel
      title="Prioritised incidents"
      description="Active incidents ranked by NETRA risk score"
      flush
      className="h-full"
      actions={
        <Button variant="ghost" size="sm" asChild className="text-muted-foreground">
          <Link to={ROUTES.incidents}>
            View all <ArrowRight />
          </Link>
        </Button>
      }
    >
      {!incidents ? (
        <LoadingState className="px-5 py-2" count={6} />
      ) : incidents.length === 0 ? (
        <EmptyState title="No active incidents" description="NETRA has nothing that needs a decision right now." />
      ) : (
        <>
          <ul className="border-t border-border">
            {incidents.slice(0, TOP).map((i) => (
              <IncidentRow key={i.id} incident={i} asset={assetsById.get(i.assetId)} />
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
