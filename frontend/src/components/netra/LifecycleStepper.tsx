import { Check, Minus } from 'lucide-react'
import { cn } from '@/lib/utils'

export type StepState = 'done' | 'current' | 'upcoming' | 'skipped'

export interface LifecycleStep {
  key: string
  label: string
  state: StepState
  time?: string
  detail?: string
}

interface LifecycleStepperProps {
  steps: LifecycleStep[]
  /** `responsive`: vertical below lg, horizontal from lg. `horizontal`: always (compact panels). */
  orientation?: 'responsive' | 'horizontal'
  className?: string
}

/** Workflow stepper — NETRA's Detect → … → Learn visual. */
export function LifecycleStepper({ steps, orientation = 'responsive', className }: LifecycleStepperProps) {
  const h = orientation === 'horizontal'
  return (
    <ol className={cn('grid', h ? 'grid-flow-col auto-cols-fr' : 'gap-3 lg:grid-flow-col lg:auto-cols-fr lg:gap-0', className)}>
      {steps.map((s, i) => {
        const last = i === steps.length - 1
        const linkDone = s.state === 'done' && !last && ['done', 'current'].includes(steps[i + 1].state)
        return (
          <li key={s.key} className={cn('relative flex', h ? 'flex-col gap-2' : 'gap-3 lg:flex-col lg:gap-2.5')}>
            {!last && (
              <span
                aria-hidden
                className={cn(
                  'absolute',
                  h ? 'top-3.5 right-0 left-7 h-px' : 'top-7 -bottom-3 left-3.5 w-px lg:top-3.5 lg:right-0 lg:bottom-auto lg:left-7 lg:h-px lg:w-auto',
                  linkDone ? 'bg-primary/45' : 'bg-border',
                )}
              />
            )}

            <span
              className={cn(
                'relative z-10 grid size-7 shrink-0 place-items-center rounded-full border text-[11px] font-semibold transition-colors',
                s.state === 'done' && 'border-primary/40 bg-primary/15 text-primary',
                s.state === 'current' && 'border-primary bg-primary text-primary-foreground',
                s.state === 'upcoming' && 'border-border bg-surface text-muted-foreground',
                s.state === 'skipped' && 'border-dashed border-border bg-surface text-muted-foreground/60',
              )}
            >
              {s.state === 'done' ? <Check className="size-3.5" /> : s.state === 'skipped' ? <Minus className="size-3.5" /> : i + 1}
              {s.state === 'current' && <span className="absolute inset-0 animate-status-pulse rounded-full bg-primary/40" />}
            </span>

            <div className={cn('min-w-0', h ? 'pr-1' : 'pt-0.5 lg:pt-0 lg:pr-3')}>
              <div
                className={cn(
                  'font-semibold tracking-wide uppercase',
                  h ? 'text-[10px]' : 'text-[11px]',
                  s.state === 'upcoming' || s.state === 'skipped' ? 'text-muted-foreground/70' : 'text-foreground',
                  s.state === 'current' && 'text-primary',
                )}
              >
                {s.label}
              </div>
              {s.time && <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{s.time}</div>}
              {s.detail && <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{s.detail}</div>}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
