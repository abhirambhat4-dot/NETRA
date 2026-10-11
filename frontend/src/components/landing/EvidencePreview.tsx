import type * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { ArrowRight, FileSearch, Gauge, Info, Link2, ScanSearch } from 'lucide-react'
import { EVIDENCE_PREVIEW, type EvidenceStep } from './content'

const ICONS: Record<EvidenceStep['key'], LucideIcon> = {
  evidence: FileSearch,
  reason: ScanSearch,
  risk: Gauge,
  'next-step': ArrowRight,
  traceability: Link2,
}

// The trail draws after the hero has settled; each step lights as the connector reaches it.
const TRAIL_START_MS = 1000
const STEP_GAP_MS = 280

/** The PDF's illustrative finding, shaped as NETRA's evidence trail. Contains no real data. */
export function EvidencePreview() {
  const titleId = 'evidence-preview-title'
  return (
    <div className="relative">
      {/* Layered sheet behind the card */}
      <div aria-hidden className="absolute inset-x-6 -bottom-3 top-6 rounded-3xl border border-(--nl-line) bg-white/70" />

      <figure aria-labelledby={titleId} className="nl-surface relative overflow-hidden rounded-3xl">
        <figcaption className="flex flex-wrap items-center justify-between gap-3 border-b border-(--nl-line) bg-(--nl-band) px-5 py-4 sm:px-6">
          <p id={titleId} className="text-sm font-semibold text-foreground">
            {EVIDENCE_PREVIEW.title}
          </p>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-[#FDE68A] bg-[#FFFBEB] px-2.5 py-1 text-xs font-semibold text-[#92400E]">
            <Info className="size-3.5" aria-hidden />
            {EVIDENCE_PREVIEW.label}
          </span>
        </figcaption>

        <div className="relative px-5 py-5 sm:px-6 sm:py-6">
          <span aria-hidden className="nl-trail-line absolute top-9 bottom-9 left-11.5 w-px bg-primary/35 sm:left-12.5" />
          <ol className="relative grid gap-1">
            {EVIDENCE_PREVIEW.steps.map((step, i) => {
              const Icon = ICONS[step.key]
              const delay = { '--nl-delay': `${TRAIL_START_MS + i * STEP_GAP_MS}ms` } as React.CSSProperties
              return (
                <li key={step.key} className="nl-trail-row flex gap-4 rounded-2xl px-2 py-2.5" style={delay}>
                  <span
                    aria-hidden
                    className="nl-trail-dot relative z-10 grid size-9 shrink-0 place-items-center rounded-full border border-primary bg-primary text-primary-foreground"
                    style={delay}
                  >
                    <Icon className="size-4" />
                  </span>
                  <div className="min-w-0 pt-0.5">
                    <p className="text-sm font-semibold text-foreground">{step.label}</p>
                    <p className="mt-0.5 text-sm leading-relaxed text-muted-foreground">{step.text}</p>
                  </div>
                </li>
              )
            })}
          </ol>
        </div>
      </figure>
    </div>
  )
}
