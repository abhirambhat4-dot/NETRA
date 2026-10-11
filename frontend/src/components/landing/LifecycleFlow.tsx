import type * as React from 'react'
import { Info } from 'lucide-react'
import { LIFECYCLE, LIFECYCLE_NOTE } from './content'

// Connector from this stage's marker to the next one: down the left edge below xl, across the
// row from xl. The primary copy draws over the grey one when the stage is revealed.
const SEGMENT =
  'absolute top-10 -bottom-4 left-5 w-px xl:top-5 xl:bottom-auto xl:left-[calc(50%+1.25rem)] xl:h-px xl:w-[calc(100%-2.5rem)]'

const delay = (ms: number) => ({ '--nl-delay': `${ms}ms` }) as React.CSSProperties

export function LifecycleFlow() {
  return (
    <div>
      <ol aria-label="NETRA lifecycle, seven stages" className="grid gap-4 xl:grid-cols-7 xl:gap-0">
        {LIFECYCLE.map((stage, i) => (
          <li
            key={stage.key}
            data-reveal
            style={delay(i * 110)}
            className="nl-stage relative flex gap-4 xl:flex-col xl:items-center xl:gap-5 xl:px-2 xl:text-center"
          >
            {i < LIFECYCLE.length - 1 && (
              <>
                <span aria-hidden className={`${SEGMENT} bg-(--nl-line-strong)`} />
                <span aria-hidden data-reveal="draw" className={`${SEGMENT} bg-primary/70`} style={delay(i * 110 + 280)} />
              </>
            )}

            <span
              aria-hidden
              className="nl-stage-marker relative z-10 grid size-10 shrink-0 place-items-center rounded-full border-2 border-primary/30 bg-white text-sm font-semibold text-primary"
            >
              {i + 1}
            </span>

            <div className="min-w-0 flex-1 rounded-2xl border border-(--nl-line) bg-white p-4 shadow-[0_1px_2px_rgba(11,27,51,0.04)] sm:p-5 md:grid md:grid-cols-[13rem_1fr] md:gap-6 xl:block xl:border-0 xl:bg-transparent xl:p-0 xl:shadow-none">
              <div>
                <h3 className="flex flex-wrap items-center gap-2 text-lg font-semibold text-foreground xl:justify-center xl:text-base">
                  {stage.label}
                  {stage.key === 'CONTAIN' && (
                    <span className="rounded-full border border-[#FDE68A] bg-[#FFFBEB] px-2 py-0.5 text-xs font-semibold text-[#92400E]">
                      Simulated
                    </span>
                  )}
                </h3>
                <p className="mt-1 text-sm font-medium text-primary">{stage.summary}</p>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground md:mt-0 xl:mt-3">{stage.detail}</p>
            </div>
          </li>
        ))}
      </ol>

      <p
        data-reveal
        className="mt-10 flex max-w-3xl items-start gap-3 rounded-2xl border border-(--nl-line) bg-white px-4 py-3.5 text-sm leading-relaxed text-muted-foreground xl:mx-auto"
      >
        <Info className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
        <span>{LIFECYCLE_NOTE}</span>
      </p>
    </div>
  )
}
