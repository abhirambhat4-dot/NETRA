import type * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { AlertTriangle, Inbox, RotateCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

interface StateFrameProps {
  icon: LucideIcon
  iconClassName?: string
  title: string
  description?: React.ReactNode
  action?: React.ReactNode
  className?: string
}

function StateFrame({ icon: Icon, iconClassName, title, description, action, className }: StateFrameProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 py-14 text-center', className)}>
      <div
        className={cn(
          'mb-4 grid size-12 place-items-center rounded-xl border border-border bg-muted/40 text-muted-foreground',
          iconClassName,
        )}
      >
        <Icon className="size-5" />
      </div>
      <h3 className="text-sm font-semibold">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-muted-foreground">{description}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}

// ---------------------------------------------------------------------------

interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  description?: React.ReactNode
  action?: React.ReactNode
  className?: string
}

export function EmptyState({ icon = Inbox, ...props }: EmptyStateProps) {
  return <StateFrame icon={icon} {...props} />
}

// ---------------------------------------------------------------------------

interface ErrorStateProps {
  title?: string
  message?: string
  onRetry?: () => void
  className?: string
}

export function ErrorState({
  title = 'Unable to load data',
  message = 'The NETRA service did not respond. Check your connection and try again.',
  onRetry,
  className,
}: ErrorStateProps) {
  return (
    <StateFrame
      icon={AlertTriangle}
      iconClassName="border-critical/25 bg-critical/10 text-critical"
      title={title}
      description={message}
      className={className}
      action={
        onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry}>
            <RotateCw /> Retry
          </Button>
        )
      }
    />
  )
}

// ---------------------------------------------------------------------------

interface LoadingStateProps {
  /** `rows` = table skeleton, `cards` = stat grid skeleton, `inline` = spinner + label */
  variant?: 'rows' | 'cards' | 'inline'
  count?: number
  label?: string
  className?: string
}

export function LoadingState({ variant = 'rows', count = 5, label = 'Loading…', className }: LoadingStateProps) {
  if (variant === 'inline') {
    return (
      <div role="status" className={cn('flex items-center justify-center gap-3 py-14 text-sm text-muted-foreground', className)}>
        <span className="relative flex size-4">
          <span className="absolute inset-0 rounded-full border-2 border-primary/20" />
          <span className="absolute inset-0 animate-spin rounded-full border-2 border-transparent border-t-primary" />
        </span>
        {label}
      </div>
    )
  }

  if (variant === 'cards') {
    return (
      <div role="status" aria-label={label} className={cn('grid gap-4 sm:grid-cols-2 xl:grid-cols-4', className)}>
        {Array.from({ length: count }, (_, i) => (
          <div key={i} className="surface-panel space-y-4 rounded-xl p-5">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-8 w-16" />
            <Skeleton className="h-3 w-32" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div role="status" aria-label={label} className={cn('space-y-2.5', className)}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="flex items-center gap-4">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 flex-1" />
          <Skeleton className="h-4 w-16" />
        </div>
      ))}
    </div>
  )
}
