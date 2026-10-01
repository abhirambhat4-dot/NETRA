import type * as React from 'react'
import { cn } from '@/lib/utils'

export interface Metric {
  label: string
  value: React.ReactNode
  hint?: React.ReactNode
  valueClassName?: string
}

/** Compact horizontal summary used at the top of list pages. Hairline dividers via gap-px. */
export function MetricStrip({ metrics, className }: { metrics: Metric[]; className?: string }) {
  return (
    <div
      className={cn(
        'grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-3',
        metrics.length >= 5 ? 'lg:grid-cols-5' : 'lg:grid-cols-4',
        className,
      )}
    >
      {metrics.map((m) => (
        <div key={m.label} className="bg-surface/95 px-5 py-4 max-lg:odd:last:col-span-2">
          <div className="text-xs text-muted-foreground">{m.label}</div>
          <div className={cn('metric mt-2 text-2xl', m.valueClassName)}>{m.value}</div>
          {m.hint && <div className="mt-1.5 truncate text-[11px] text-muted-foreground">{m.hint}</div>}
        </div>
      ))}
    </div>
  )
}
