import type { LucideIcon } from 'lucide-react'
import { BookOpen, ClipboardCheck, FileUp, Gauge, Network, RadioTower, UserCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Feature, FeatureId } from './content'
import { StatusChip } from './StatusChip'

const ICONS: Record<FeatureId, LucideIcon> = {
  ingestion: FileUp,
  correlation: Network,
  risk: Gauge,
  response: UserCheck,
  memory: BookOpen,
  assessment: ClipboardCheck,
  'live-feed': RadioTower,
}

export function FeatureCard({ feature, wide = false }: { feature: Feature; wide?: boolean }) {
  const Icon = ICONS[feature.id]
  const titleId = `feature-${feature.id}`
  const planned = feature.status === 'planned'

  return (
    <article
      aria-labelledby={titleId}
      className={cn(
        'nl-card flex h-full flex-col gap-5 rounded-3xl border bg-white p-6 shadow-[0_1px_2px_rgba(11,27,51,0.04)]',
        planned ? 'border-dashed border-(--nl-line-strong)' : 'border-(--nl-line)',
        wide && 'lg:grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:gap-10',
      )}
    >
      <div className="flex flex-col">
        <div className="flex items-start justify-between gap-3">
          <span aria-hidden className="grid size-11 place-items-center rounded-2xl bg-(--nl-accent-soft) text-primary">
            <Icon className="size-5" />
          </span>
          <StatusChip status={feature.status} />
        </div>
        <h3 id={titleId} className="mt-5 text-lg font-semibold text-foreground">
          {feature.name}
        </h3>
        <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{feature.description}</p>
      </div>

      <div className={cn('rounded-2xl bg-(--nl-band) p-4', wide ? 'lg:self-end' : 'mt-auto')}>
        <p className="text-xs font-semibold text-foreground">Boundary</p>
        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{feature.boundary}</p>
      </div>
    </article>
  )
}
