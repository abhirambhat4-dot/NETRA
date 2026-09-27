import type { LucideIcon } from 'lucide-react'
import { Bug, CheckCircle2, Crosshair, Globe, Lock, Radar, Server, Target, Waypoints } from 'lucide-react'
import type { Asset, RiskAssessment, RiskFactorKey } from '@/api/types'
import { Disclosure, Panel } from '@/components/netra'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

const FACTOR_ICON: Record<RiskFactorKey, LucideIcon> = {
  ASSET_CRITICALITY: Server,
  VULNERABILITY_SEVERITY: Bug,
  ANOMALY_NOVELTY: Waypoints,
  DETECTION_CONFIDENCE: Radar,
  ATTACK_TECHNIQUE: Target,
  THREAT_INTELLIGENCE: Crosshair,
}

/** Plain-language strength of a 0–1 factor value. */
function strength(v: number): { label: string; className: string } {
  if (v >= 0.85) return { label: 'Very high', className: 'text-critical' }
  if (v >= 0.7) return { label: 'High', className: 'text-high' }
  if (v >= 0.4) return { label: 'Moderate', className: 'text-medium' }
  return { label: 'Low', className: 'text-muted-foreground' }
}

/**
 * WHY NETRA PRIORITISED THIS — each contextual factor as a tile: how strong it
 * is, and how many risk points it contributed. The analyst narrative is one
 * click away.
 */
export function RiskBreakdownPanel({ risk, asset }: { risk: RiskAssessment; asset: Asset }) {
  const tone = toneStyles[severityTone[risk.severity]]
  const factors = [...risk.factors].sort((a, b) => b.contribution - a.contribution)

  return (
    <Panel
      title="Why NETRA prioritised this"
      description={`Contextual factors behind the risk score · ${risk.modelVersion}`}
      actions={
        <div className="text-right">
          <span className={cn('metric text-2xl', tone.text)}>{risk.riskScore}</span>
          <span className="text-xs text-muted-foreground"> /100</span>
        </div>
      }
    >
      {/* Composition bar: each factor's share of the score */}
      <div className="mb-5">
        <div className="flex h-2 gap-0.5 overflow-hidden rounded-full bg-foreground/6" role="img" aria-label={`Risk score composition, ${risk.riskScore} of 100 points`}>
          {factors.map((f, idx) => (
            <div
              key={f.key}
              className="h-full bg-primary transition-[width] duration-700"
              style={{ width: `${f.contribution}%`, opacity: 1 - idx * 0.13 }}
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

      <ul className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-3">
        {factors.map((f) => {
          const Icon = FACTOR_ICON[f.key]
          const s = strength(f.value)
          return (
            <li key={f.key} className="surface-inset flex flex-col rounded-lg p-3.5 transition-colors hover:border-primary/20">
              <div className="flex items-start justify-between gap-3">
                <span className="flex min-w-0 items-center gap-2">
                  <span className="grid size-7 shrink-0 place-items-center rounded-md border border-primary/20 bg-primary/8 text-primary">
                    <Icon className="size-3.5" />
                  </span>
                  <span className="truncate text-[13px] font-medium">{f.label}</span>
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums">
                  <span className="text-foreground">+{f.contribution.toFixed(1)}</span>
                  <span className="text-muted-foreground"> pts</span>
                </span>
              </div>
              <div className="mt-3 flex items-center gap-2.5">
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-foreground/6">
                  <div className="h-full rounded-full bg-primary transition-[width] duration-700" style={{ width: `${f.value * 100}%` }} />
                </div>
                <span className={cn('w-16 shrink-0 text-right text-[11px] font-medium', s.className)}>{s.label}</span>
              </div>
              <p className="mt-2 line-clamp-2 text-[11px] leading-relaxed text-muted-foreground" title={f.explanation}>
                {f.explanation}
              </p>
              {f.key === 'ASSET_CRITICALITY' && (
                <span className={cn('mt-2 inline-flex items-center gap-1 text-[11px]', asset.exposure === 'EXTERNAL' ? 'text-high' : 'text-muted-foreground')}>
                  {asset.exposure === 'EXTERNAL' ? <Globe className="size-3" /> : <Lock className="size-3" />}
                  {asset.exposure === 'EXTERNAL' ? 'Internet-exposed asset' : 'Internal asset'}
                </span>
              )}
            </li>
          )
        })}
      </ul>

      <Disclosure label="Analyst summary" hint={`${risk.explanation.length} findings`} className="mt-4 border-t border-border pt-2.5">
        <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]">
          <ul className="space-y-2.5">
            {risk.explanation.map((line) => (
              <li key={line} className="flex gap-2.5 text-[13px] leading-snug text-foreground/85">
                <CheckCircle2 className={cn('mt-0.5 size-4 shrink-0', tone.text)} />
                <span>{line}</span>
              </li>
            ))}
          </ul>
          <div className="surface-inset grid grid-cols-3 gap-2 self-start rounded-lg px-3 py-3 text-center md:w-56">
            <Mini label="Novelty" value={`${Math.round(risk.novelty * 100)}%`} />
            <Mini label="Confidence" value={`${Math.round(risk.confidence * 100)}%`} />
            <Mini label="CVSS" value={risk.cvss.toFixed(1)} />
          </div>
        </div>
      </Disclosure>
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
