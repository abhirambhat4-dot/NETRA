import { CheckCircle2 } from 'lucide-react'
import type { RiskAssessment } from '@/api/types'
import { Panel } from '@/components/netra'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

/** WHY NETRA PRIORITISED IT — explainable risk breakdown. */
export function RiskBreakdownPanel({ risk }: { risk: RiskAssessment }) {
  const tone = toneStyles[severityTone[risk.severity]]
  const factors = [...risk.factors].sort((a, b) => b.contribution - a.contribution)

  return (
    <Panel
      title="Why NETRA prioritised it"
      description={`Explainable risk score · ${risk.modelVersion}`}
      actions={
        <div className="text-right">
          <span className={cn('metric text-2xl', tone.text)}>{risk.riskScore}</span>
          <span className="text-xs text-muted-foreground"> /100</span>
        </div>
      }
    >
      {/* Composition bar: each factor's contribution toward 100 */}
      <div className="mb-5">
        <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full bg-foreground/6">
          {factors.map((f, idx) => (
            <div
              key={f.key}
              className="h-full bg-primary transition-[width] duration-700"
              style={{ width: `${f.contribution}%`, opacity: 1 - idx * 0.12 }}
              title={`${f.label}: ${f.contribution.toFixed(1)} pts`}
            />
          ))}
        </div>
        <div className="mt-1.5 flex justify-between font-mono text-[10px] text-muted-foreground">
          <span>0</span>
          <span>{risk.riskScore} of 100 points</span>
          <span>100</span>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <ul className="space-y-3.5">
          {factors.map((f) => (
            <li key={f.key}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-[13px] font-medium">{f.label}</span>
                <span className="font-mono text-xs tabular-nums">
                  <span className="text-foreground">{f.contribution.toFixed(1)}</span>
                  <span className="text-muted-foreground"> / {Math.round(f.weight * 100)}</span>
                </span>
              </div>
              <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-foreground/6">
                <div className="h-full rounded-full bg-primary transition-[width] duration-700" style={{ width: `${f.value * 100}%` }} />
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">{f.explanation}</p>
            </li>
          ))}
        </ul>

        <div className="surface-inset rounded-lg p-4">
          <div className="mb-3 text-xs font-medium text-foreground/85">Analyst summary</div>
          <ul className="space-y-2.5">
            {risk.explanation.map((line) => (
              <li key={line} className="flex gap-2.5 text-[13px] leading-snug text-foreground/85">
                <CheckCircle2 className={cn('mt-0.5 size-4 shrink-0', tone.text)} />
                <span>{line}</span>
              </li>
            ))}
          </ul>
          <div className="mt-4 grid grid-cols-3 gap-2 border-t border-border pt-3 text-center">
            <Mini label="Novelty" value={`${Math.round(risk.novelty * 100)}%`} />
            <Mini label="Confidence" value={`${Math.round(risk.confidence * 100)}%`} />
            <Mini label="CVSS" value={risk.cvss.toFixed(1)} />
          </div>
        </div>
      </div>
    </Panel>
  )
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="metric text-lg">{value}</div>
      <div className="mt-1 text-[11px] text-muted-foreground">{label}</div>
    </div>
  )
}
