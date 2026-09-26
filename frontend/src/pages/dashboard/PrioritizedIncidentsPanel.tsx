import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { Asset, Incident } from '@/api/types'
import { IncidentRow } from '@/components/incidents/IncidentRow'
import { EmptyState, LoadingState, Panel } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'

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
        <ul className="border-t border-border">
          {incidents.map((i) => (
            <IncidentRow key={i.id} incident={i} asset={assetsById.get(i.assetId)} />
          ))}
        </ul>
      )}
    </Panel>
  )
}
