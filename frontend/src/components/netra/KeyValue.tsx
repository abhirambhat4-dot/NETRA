import type * as React from 'react'
import { cn } from '@/lib/utils'

export interface KeyValueItem {
  label: string
  value: React.ReactNode
  mono?: boolean
}

/** Label / value rows for detail panels. */
export function KeyValueList({ items, className, columns = 1 }: { items: KeyValueItem[]; className?: string; columns?: 1 | 2 }) {
  return (
    <dl className={cn('grid gap-x-6 gap-y-3', columns === 2 && 'sm:grid-cols-2', className)}>
      {items.map((it) => (
        <div key={it.label} className="min-w-0">
          <dt className="text-[11px] text-muted-foreground">{it.label}</dt>
          <dd className={cn('mt-0.5 truncate text-[13px] text-foreground/90', it.mono && 'font-mono text-xs')}>{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
