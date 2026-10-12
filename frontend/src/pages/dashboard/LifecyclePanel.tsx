import type * as React from 'react'
import { Info } from 'lucide-react'
import { LIFECYCLE, LIFECYCLE_NOTE } from '@/components/landing/content'

const delay = (ms: number) => ({ '--cc-delay': `${ms}ms` }) as React.CSSProperties

/**
 * NETRA's seven-stage lifecycle as a full-width band, with the PDF's descriptions always visible
 * (no hover-only text). Terminology comes from the landing page content so both screens stay
 * consistent.
 *
 * Layout follows the band's own width (container queries), not the viewport, because the sidebar
 * changes how much room the page has: a vertical rail when narrow, a 2- then 4-column card grid,
 * and a single seven-column row with drawn connectors only from 80rem, where each stage keeps a
 * readable measure. The note fills the eighth cell of the grid layouts.
 */
export function LifecyclePanel({ startDelay = 0 }: { startDelay?: number }) {
  return (
    <section aria-labelledby="cc-lifecycle-title" className="cc-card cc-rise @container rounded-2xl p-5 sm:p-6 lg:p-7" style={delay(startDelay)}>
      <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between md:gap-8">
        <div className="min-w-0">
          <p className="eyebrow text-primary/85">Decision lifecycle</p>
          <h2 id="cc-lifecycle-title" className="mt-2 text-xl font-semibold tracking-tight text-balance text-foreground">
            Seven stages from candidate activity to recorded lesson
          </h2>
        </div>
        <p className="max-w-md text-sm leading-relaxed text-muted-foreground md:text-right">
          Each stage builds on evidence from the one before it, and a person stays in control before any response.
        </p>
      </div>

      <div className="mt-6 grid gap-y-5 @2xl:grid-cols-2 @2xl:gap-4 @5xl:grid-cols-4 @7xl:mt-8 @7xl:grid-cols-7 @7xl:gap-x-0 @7xl:gap-y-6">
        {/* display: contents lets the stages and the note share one grid; role restores list semantics. */}
        <ol role="list" aria-label="NETRA lifecycle, seven stages" className="contents">
          {LIFECYCLE.map((stage, i) => {
            const last = i === LIFECYCLE.length - 1
            const stageDelay = startDelay + 120 + i * 80
            return (
              <li
                key={stage.key}
                className="cc-stage cc-stage-item relative flex gap-4 @2xl:flex-col @2xl:gap-4 @2xl:rounded-2xl @2xl:border @2xl:border-border @2xl:bg-foreground/2 @2xl:p-5 @7xl:rounded-none @7xl:border-0 @7xl:bg-transparent @7xl:p-0 @7xl:pr-6"
                style={delay(stageDelay)}
              >
                {!last && (
                  <>
                    {/* Vertical rail (single column) */}
                    <span aria-hidden className="cc-connector absolute top-11 -bottom-5 left-5 w-px bg-primary/25 @2xl:hidden" style={delay(stageDelay + 160)} />
                    {/* Horizontal connector to the next marker (seven-column row) */}
                    <span aria-hidden className="absolute top-5 right-2 left-12 hidden h-px bg-border @7xl:block" />
                    <span aria-hidden className="cc-connector-x absolute top-5 right-2 left-12 hidden h-px bg-primary/45 @7xl:block" style={delay(stageDelay + 220)} />
                  </>
                )}

                <span
                  aria-hidden
                  className="cc-marker relative z-10 grid size-10 shrink-0 place-items-center rounded-full border border-primary/35 bg-background font-mono text-sm font-semibold text-primary"
                >
                  {String(i + 1).padStart(2, '0')}
                </span>

                <div className="min-w-0 flex-1 pt-1.5 @2xl:pt-0">
                  <h3 className="flex flex-wrap items-center gap-2 text-[15px] font-semibold tracking-tight text-foreground">
                    {stage.label}
                    {stage.key === 'CONTAIN' && (
                      <span className="rounded-full border border-medium/35 bg-medium/10 px-2 py-px text-[11px] font-medium text-medium">
                        Simulated
                      </span>
                    )}
                  </h3>
                  <p className="mt-1 text-[13px] font-medium text-primary/90">{stage.summary}</p>
                  <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">{stage.detail}</p>
                </div>
              </li>
            )
          })}
        </ol>

        <p
          className="cc-stage flex items-start gap-3 rounded-2xl border border-dashed border-medium/30 bg-medium/5 p-4 text-[13px] leading-relaxed text-muted-foreground @2xl:p-5 @7xl:col-span-7 @7xl:py-3.5"
          style={delay(startDelay + 120 + LIFECYCLE.length * 80)}
        >
          <Info className="mt-0.5 size-4 shrink-0 text-medium" aria-hidden />
          <span>{LIFECYCLE_NOTE}</span>
        </p>
      </div>
    </section>
  )
}
