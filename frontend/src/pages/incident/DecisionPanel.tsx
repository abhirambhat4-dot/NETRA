import { Sparkles } from 'lucide-react'
import type { IncidentDetail } from '@/api/types'
import { StatusBadge } from '@/components/netra'
import { ACTION_LABEL } from '@/lib/format'
import { decisionReasoning, recommendationHeadline } from '@/lib/incident'

/** WHAT NETRA RECOMMENDS — decision intelligence. Risk itself lives in the page header. */
export function DecisionPanel({ detail: d }: { detail: IncidentDetail }) {
  const decision = d.decision

  return (
    <section id="decision" className="relative scroll-mt-20 overflow-hidden rounded-xl border border-primary/25 bg-linear-to-b from-primary/10 via-surface/90 to-surface/90 shadow-[0_12px_32px_-16px_rgb(0_0_0/0.6)]">
      <span aria-hidden className="absolute inset-x-0 top-0 h-px bg-linear-to-r from-transparent via-primary/70 to-transparent" />
      <div className="px-5 pt-4.5 pb-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="inline-flex items-center gap-2 text-[15px] font-semibold tracking-tight">
            <Sparkles className="size-4 text-primary" /> Decision intelligence
          </h2>
          {decision && <StatusBadge status={decision.status} size="sm" />}
        </div>

        <div className="mt-4">
          <div className="text-[11px] font-semibold tracking-[0.12em] text-primary uppercase">Recommended action</div>
          <p className="mt-1.5 text-[15px] leading-snug font-medium">{recommendationHeadline(d)}</p>
          {decision && <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{decision.rationale}</p>}
        </div>

        {d.riskAssessment && (
          <div className="mt-3 flex items-center justify-between gap-3 border-y border-border/70 py-2.5 text-xs">
            <span className="text-muted-foreground">Detection confidence across correlated sources</span>
            <span className="shrink-0 font-mono font-semibold text-foreground/90">{Math.round(d.riskAssessment.confidence * 100)}%</span>
          </div>
        )}

        <div className="mt-4 border-t border-border pt-3.5">
          <div className="text-[11px] text-muted-foreground">Reasoning</div>
          <p className="mt-1 text-[13px] leading-relaxed text-foreground/90">{decisionReasoning(d)}</p>
        </div>

        {decision && decision.alternativeActions.length > 0 && (
          <div className="mt-3.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
            Alternatives:
            {decision.alternativeActions.map((a) => (
              <span key={a} className="rounded-md border border-border px-1.5 py-0.5 text-foreground/80">
                {ACTION_LABEL[a]}
              </span>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
