import type * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface PageHeaderProps {
  eyebrow?: React.ReactNode
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  /** Page icon shown in a tinted tile beside the title. */
  icon?: LucideIcon
  className?: string
}

/** Top of every page body: icon · eyebrow → title → description, actions on the right. */
export function PageHeader({ eyebrow, title, description, actions, icon: Icon, className }: PageHeaderProps) {
  return (
    <div className={cn('app-page-header flex flex-col gap-4 md:flex-row md:items-end md:justify-between', className)}>
      <div className="flex min-w-0 items-start gap-4">
        {Icon && (
          <span aria-hidden className="mt-0.5 hidden size-11 shrink-0 place-items-center rounded-xl border border-primary/15 bg-primary/8 text-primary sm:grid">
            <Icon className="size-5" strokeWidth={1.9} />
          </span>
        )}
        <div className="min-w-0 space-y-1">
          {eyebrow && <div className="text-[11px] font-semibold tracking-widest text-primary uppercase">{eyebrow}</div>}
          <h1 className="text-2xl font-semibold tracking-tight text-balance text-foreground md:text-[1.75rem] md:leading-9">{title}</h1>
          {description && <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

interface SectionHeaderProps {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  className?: string
}

/** Heading inside a card or page section. */
export function SectionHeader({ title, description, actions, className }: SectionHeaderProps) {
  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <div className="min-w-0 space-y-0.5">
        <h2 className="text-sm font-semibold tracking-tight text-foreground">{title}</h2>
        {description && <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}
