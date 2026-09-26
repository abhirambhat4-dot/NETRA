import type * as React from 'react'
import type { TimelineEntry } from '@/api/types'
import { formatDateTime } from '@/lib/format'
import { stageMeta } from '@/lib/stages'
import { cn } from '@/lib/utils'

export interface TimelineItem extends TimelineEntry {
  /** Optional extra element on the right (e.g. incident link on Cyber Memory). */
  aside?: React.ReactNode
}

/** Vertical audit trail of NETRA workflow entries (oldest → newest by default). */
export function DecisionTimeline({ entries, className }: { entries: TimelineItem[]; className?: string }) {
  return (
    <ol className={cn('relative', className)}>
      {entries.map((t, i) => {
        const meta = stageMeta[t.stage]
        const human = t.actor !== 'NETRA'
        const last = i === entries.length - 1
        return (
          <li key={t.id} className="relative grid grid-cols-[28px_minmax(0,1fr)] gap-x-3">
            <div className="relative flex justify-center">
              {!last && <span aria-hidden className="absolute top-7 -bottom-0.5 w-px bg-border" />}
              <span
                className={cn(
                  'relative grid size-7 place-items-center rounded-full border',
                  human ? 'border-violet/35 bg-violet/12 text-violet' : 'border-primary/30 bg-primary/10 text-primary',
                )}
              >
                <meta.icon className="size-3.5" />
              </span>
            </div>
            <div className={cn('min-w-0', !last && 'pb-5')}>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="text-[13px] font-medium">{t.title}</span>
                <span className="rounded border border-border px-1.5 text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
                  {meta.label}
                </span>
                {t.aside && <span className="ml-auto">{t.aside}</span>}
              </div>
              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{t.description}</p>
              <div className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground/80">
                <span className="font-mono">{formatDateTime(t.timestamp)}</span>
                <span>·</span>
                <span className={cn('font-mono', human ? 'text-violet' : 'text-foreground/70')}>{t.actor}</span>
              </div>
            </div>
          </li>
        )
      })}
    </ol>
  )
}
