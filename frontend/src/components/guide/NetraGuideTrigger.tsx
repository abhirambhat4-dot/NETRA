import type * as React from 'react'
import type { GuideTone } from '@/lib/guide'
import { cn } from '@/lib/utils'
import { NetraGuideRobot, type RobotState } from './NetraGuideRobot'

interface NetraGuideTriggerProps extends Omit<React.ComponentProps<'button'>, 'children'> {
  open: boolean
  tone: GuideTone
  state: RobotState
  /** A tip for this page has not been read yet. */
  unread: boolean
  /** Brief lean toward the highlighted section. */
  nudging: boolean
  context: string
}

/** Small floating robot in the corner — the only always-visible piece of the guide. */
export function NetraGuideTrigger({ open, tone, state, unread, nudging, context, className, ...props }: NetraGuideTriggerProps) {
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-haspopup="dialog"
      aria-label={open ? 'Close NETRA Guide' : `Open NETRA Guide: ${context}`}
      title="NETRA Guide"
      data-tone={tone}
      className={cn(
        'ng-trigger group relative grid size-12 place-items-center rounded-2xl border border-[#1B2D4A] bg-[#0B1B33] shadow-[0_2px_6px_rgb(11_27_51/0.12),0_14px_30px_-12px_rgb(11_27_51/0.45),inset_0_1px_0_rgb(255_255_255/0.06)] transition-[border-color,transform,box-shadow] duration-200 outline-none hover:-translate-y-0.5 hover:border-[color:var(--ng-accent)]/40 focus-visible:ring-2 focus-visible:ring-ring active:translate-y-0 sm:size-14',
        open && 'border-[color:var(--ng-accent)]/40',
        nudging && 'ng-nudge',
        className,
      )}
      {...props}
    >
      <NetraGuideRobot tone={tone} state={state} className="size-10 sm:size-11" />
      {unread && !open && (
        <span aria-hidden className="absolute -top-0.5 -right-0.5 flex size-2.5">
          <span className="absolute inset-0 animate-status-pulse rounded-full bg-[var(--ng-accent)]" />
          <span className="relative size-2.5 rounded-full bg-[var(--ng-accent)] ring-2 ring-background" />
        </span>
      )}
    </button>
  )
}
