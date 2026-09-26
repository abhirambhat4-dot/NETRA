import type * as React from 'react'
import { cn } from '@/lib/utils'

interface SurfaceCardProps extends React.ComponentProps<'div'> {
  /** Lift slightly on hover — use for clickable cards. */
  interactive?: boolean
  /** Remove default padding (tables, lists that bleed to the edge). */
  flush?: boolean
}

/** Base NETRA panel. All cards on every page build on this. */
export function SurfaceCard({ interactive, flush, className, ...props }: SurfaceCardProps) {
  return (
    <div
      data-slot="surface-card"
      className={cn(
        'surface-panel relative rounded-xl transition-[border-color,transform,box-shadow] duration-200',
        !flush && 'p-5',
        interactive
          ? 'cursor-pointer hover:-translate-y-0.5 hover:border-primary/25'
          : 'hover:border-foreground/12',
        className,
      )}
      {...props}
    />
  )
}

interface PanelProps extends Omit<React.ComponentProps<'section'>, 'title'> {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  /** Body without horizontal padding (edge-to-edge rows). */
  flush?: boolean
  bodyClassName?: string
}

/** Titled dashboard region: header row + body. */
export function Panel({ title, description, actions, flush, className, bodyClassName, children, ...props }: PanelProps) {
  return (
    <section
      className={cn(
        'surface-panel flex min-w-0 flex-col rounded-xl transition-[border-color] duration-200 hover:border-foreground/12',
        className,
      )}
      {...props}
    >
      <header className="flex items-start justify-between gap-4 px-5 pt-4.5 pb-3">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold tracking-tight">{title}</h2>
          {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </header>
      <div className={cn('flex-1', flush ? 'pb-2' : 'px-5 pb-5', bodyClassName)}>{children}</div>
    </section>
  )
}
