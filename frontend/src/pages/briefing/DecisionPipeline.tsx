import type { LucideIcon } from 'lucide-react'
import { Gauge, Layers, Radar, Scale, ShieldCheck } from 'lucide-react'

/**
 * Hero visual: one detection travelling DETECTION → ACTION. Horizontal from
 * lg up, vertical below. Stage i lights at i × 1.1s of a 6s cycle (see the
 * bf-* keyframes in index.css); the packet on the connector after it starts
 * at the same moment, so data appears to hand off stage to stage.
 */

const STEP = 1.1

const STAGES: { label: string; detail: string; icon: LucideIcon }[] = [
  { label: 'Detection', detail: 'EVT-88141 · SSH brute force', icon: Radar },
  { label: 'Context', detail: 'db-prod-01 · critical asset', icon: Layers },
  { label: 'Risk', detail: 'Score 91 / 100', icon: Gauge },
  { label: 'Decision', detail: 'Isolate host · confidence 0.87', icon: Scale },
  { label: 'Action', detail: 'Awaiting authorization', icon: ShieldCheck },
]

export function DecisionPipeline() {
  return (
    <figure
      data-guide-target="decision-pipeline"
      aria-label="Decision pipeline: detection, context, risk, decision, action"
      className="relative overflow-hidden rounded-2xl border border-border bg-card p-5 shadow-[var(--panel-shadow-lift)] sm:p-6"
    >
      <span aria-hidden className="absolute inset-x-0 top-0 h-[3px] bg-linear-to-r from-primary via-primary/70 to-cyan/60" />

      <figcaption className="flex items-center justify-between gap-3 font-mono text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
        <span className="flex items-center gap-2">
          <span className="relative flex size-1.5">
            <span className="absolute inset-0 animate-status-pulse rounded-full bg-cyan" />
            <span className="relative size-1.5 rounded-full bg-cyan" />
          </span>
          Decision pipeline
        </span>
        <span className="text-muted-foreground/70">Example detection</span>
      </figcaption>

      <ol className="mt-5 flex flex-col lg:flex-row lg:items-stretch">
        {STAGES.map((s, i) => (
          <li key={s.label} className="flex flex-col lg:flex-1 lg:flex-row lg:items-stretch">
            <div className="relative flex items-center gap-3 rounded-xl border border-border bg-muted/50 px-3.5 py-3 lg:min-w-0 lg:flex-1 lg:flex-col lg:items-start lg:gap-2.5 lg:px-3 lg:py-3.5">
              {/* Activation glow */}
              <span
                aria-hidden
                className="bf-stage absolute inset-0 rounded-xl border border-primary/40 bg-primary/5 shadow-[0_0_0_3px_rgb(29_78_216/0.08)]"
                style={{ animationDelay: `${i * STEP}s` }}
              />
              <span className="relative grid size-8 shrink-0 place-items-center rounded-lg border border-primary/25 bg-primary/10 text-primary">
                <s.icon className="size-4" />
              </span>
              <span className="relative min-w-0">
                <span className="block text-[11px] font-semibold tracking-[0.16em] uppercase">{s.label}</span>
                <span className="mt-0.5 block truncate font-mono text-[10.5px] text-muted-foreground lg:whitespace-normal">{s.detail}</span>
              </span>
            </div>

            {i < STAGES.length - 1 && (
              <span aria-hidden className="relative mx-auto h-6 w-px bg-linear-to-b from-primary/40 to-primary/10 lg:mx-1.5 lg:h-px lg:w-6 lg:self-center lg:shrink-0 lg:bg-linear-to-r">
                <span className="bf-packet-y absolute inset-0 lg:hidden" style={{ animationDelay: `${i * STEP}s` }}>
                  <span className="absolute top-0 left-1/2 size-1.5 -translate-1/2 rounded-full bg-primary" />
                </span>
                <span className="bf-packet-x absolute inset-0 hidden lg:block" style={{ animationDelay: `${i * STEP}s` }}>
                  <span className="absolute top-1/2 left-0 size-1.5 -translate-1/2 rounded-full bg-primary" />
                </span>
              </span>
            )}
          </li>
        ))}
      </ol>

      <p className="mt-5 border-t border-border pt-4 text-xs leading-relaxed text-muted-foreground">
        A critical-severity alert on a low-value host may wait. The same alert on a production database may not. NETRA makes that difference explicit.
      </p>
    </figure>
  )
}
