import type * as React from 'react'
import { cn } from '@/lib/utils'

export interface Metric {
  label: string
  value: React.ReactNode
  hint?: React.ReactNode
  valueClassName?: string
}

/** Summary cards used at the top of list pages. */
export function MetricStrip({ metrics, className }: { metrics: Metric[]; className?: string }) {
  return (
    <div
      className={cn(
        'grid grid-cols-2 gap-3 sm:grid-cols-3 lg:gap-4',
        metrics.length >= 5 ? 'lg:grid-cols-5' : 'lg:grid-cols-4',
        className,
      )}
    >
      {metrics.map((m) => (
        <div key={m.label} className="surface-panel min-w-0 rounded-xl px-5 py-4 max-lg:odd:last:col-span-2">
          <div className="text-[12px] font-medium text-muted-foreground">{m.label}</div>
          <div className={cn('metric mt-2.5 text-[1.625rem] text-foreground', m.valueClassName)}>{m.value}</div>
          {m.hint && <div className="mt-2 truncate text-[12px] text-muted-foreground" title={typeof m.hint === 'string' ? m.hint : undefined}>{m.hint}</div>}
        </div>
      ))}
    </div>
  )
}
