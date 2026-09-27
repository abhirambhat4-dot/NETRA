import { useEffect, useId, useRef } from 'react'
import { Crosshair, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { GuideContent, GuideTone } from '@/lib/guide'
import { cn } from '@/lib/utils'

const TONE_LABEL: Record<GuideTone, string | null> = {
  normal: null,
  warning: 'Elevated risk',
  critical: 'Critical risk',
}

interface NetraGuideBubbleProps {
  content: GuideContent
  tone: GuideTone
  onDismiss: () => void
  onShowMe?: () => void
  /** Move focus into the bubble — only when the operator opened it, never on an automatic tip. */
  autoFocus?: boolean
}

/** Compact guidance card anchored above the robot. Esc closes it. */
export function NetraGuideBubble({ content, tone, onDismiss, onShowMe, autoFocus }: NetraGuideBubbleProps) {
  const titleId = useId()
  const ackRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (autoFocus) ackRef.current?.focus({ preventScroll: true })
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onDismiss()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onDismiss, autoFocus])

  const toneLabel = TONE_LABEL[tone]

  return (
    <div
      role="dialog"
      aria-labelledby={titleId}
      data-tone={tone}
      className="ng-bubble relative w-[min(20rem,calc(100vw-1.5rem))] overflow-hidden rounded-xl border border-white/10 bg-[linear-gradient(180deg,rgb(21_26_35/0.94),rgb(10_13_19/0.96))] shadow-[0_24px_60px_-20px_rgb(0_0_0/0.95),inset_0_1px_0_rgb(255_255_255/0.05)] backdrop-blur-xl motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-2 motion-safe:zoom-in-95 motion-safe:duration-200 motion-reduce:animate-in motion-reduce:fade-in-0"
    >
      <span aria-hidden className="absolute inset-x-6 top-0 h-px bg-linear-to-r from-transparent via-[var(--ng-accent)] to-transparent opacity-70" />

      <div className="flex items-start justify-between gap-3 px-4 pt-3.5">
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-mono text-[10px] font-medium tracking-[0.18em] text-[var(--ng-accent)] uppercase">
            NETRA Guide
            {toneLabel && (
              <span
                className={cn(
                  'rounded border px-1 py-px text-[9px] tracking-wider',
                  tone === 'critical' ? 'border-critical/30 bg-critical/10 text-critical' : 'border-medium/30 bg-medium/10 text-medium',
                )}
              >
                {toneLabel}
              </span>
            )}
          </div>
          <h2 id={titleId} className="mt-1 text-[13px] font-semibold tracking-tight">
            You're viewing {content.context}.
          </h2>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          className="-mt-0.5 -mr-1.5 grid size-7 shrink-0 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-foreground/5 hover:text-foreground"
          aria-label="Dismiss guidance"
        >
          <X className="size-3.5" />
        </button>
      </div>

      <p className="px-4 pt-1.5 text-[13px] leading-relaxed text-foreground/85">{content.message}</p>

      <div className="mt-3.5 flex items-center justify-end gap-1.5 border-t border-white/6 bg-black/20 px-3 py-2.5">
        {onShowMe && content.targetLabel && (
          <Button variant="ghost" size="sm" onClick={onShowMe} className="mr-auto text-muted-foreground">
            <Crosshair /> Show {content.targetLabel.toLowerCase()}
          </Button>
        )}
        <Button ref={ackRef} size="sm" onClick={onDismiss} className="px-3">
          Got it
        </Button>
      </div>
    </div>
  )
}
