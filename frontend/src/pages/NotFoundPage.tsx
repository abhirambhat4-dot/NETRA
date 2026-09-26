import { Link } from 'react-router-dom'
import { Compass } from 'lucide-react'
import { EmptyState, SurfaceCard } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'

export function NotFoundPage() {
  return (
    <SurfaceCard>
      <EmptyState
        icon={Compass}
        title="Page not found"
        description="This route does not exist in NETRA."
        action={
          <Button asChild>
            <Link to={ROUTES.dashboard}>Back to Command Center</Link>
          </Button>
        }
      />
    </SurfaceCard>
  )
}
