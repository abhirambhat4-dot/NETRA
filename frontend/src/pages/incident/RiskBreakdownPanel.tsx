import type { LucideIcon } from 'lucide-react'
import { ArrowDown, ArrowRight, Bug, CheckCircle2, Crosshair, Globe, Lock, Radar, Server, Target, Waypoints } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Asset, RiskAssessment, RiskFactorKey } from '@/api/types'
import { Disclosure, Panel, RiskGauge } from '@/components/netra'
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
  const [revealed, setRevealed] = useState(() =>
    typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  )

  useEffect(() => {
    if (revealed) return
    const frame = requestAnimationFrame(() => setRevealed(true))
    return () => cancelAnimationFrame(frame)
  }, [revealed])

  return (
    <Panel
      title="Risk explanation"
      description={`Mock risk model inputs · ${risk.modelVersion}`}
    >
      <div className="grid items-center gap-4 lg:grid-cols-[minmax(0,1fr)_28px_156px]">
        <ul className="relative divide-y divide-border/70 before:absolute before:inset-y-3 before:left-3.5 before:w-px before:bg-primary/25">
          {factors.map((f, index) => {
          const Icon = FACTOR_ICON[f.key]
          const s = strength(f.value)
          return (
            <li
              key={f.key}
              className="group relative grid grid-cols-[28px_minmax(0,1fr)] gap-2 py-3 first:pt-0 last:pb-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-left-2 motion-safe:duration-500"
              style={{ animationDelay: `${index * 75}ms` }}
            >
              <span className="relative z-10 grid size-7 place-items-center rounded-full border border-primary/25 bg-surface text-primary">
                <Icon className="size-3.5" />
              </span>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                  <span className="truncate text-[13px] font-medium">{f.label}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">weight {Math.round(f.weight * 100)}%</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px]">
                  <span className={cn('font-medium', s.className)}>{s.label} · {Math.round(f.value * 100)}% input</span>
                  <span className="font-mono font-semibold text-foreground/90">+{f.contribution.toFixed(1)} pts</span>
                </div>
                <div className="mt-2 h-1 overflow-hidden rounded-full bg-foreground/6">
                  <div
                    className="h-full origin-left rounded-full bg-primary transition-transform duration-500 ease-out"
                    style={{ transform: `scaleX(${revealed ? f.value : 0})`, transitionDelay: `${index * 75}ms` }}
                  />
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground" title={f.explanation}>{f.explanation}</p>
                {f.key === 'ASSET_CRITICALITY' && (
                  <span className={cn('mt-1.5 inline-flex items-center gap-1 text-[10px]', asset.exposure === 'EXTERNAL' ? 'text-high' : 'text-muted-foreground')}>
                    {asset.exposure === 'EXTERNAL' ? <Globe className="size-3" /> : <Lock className="size-3" />}
                    {asset.exposure === 'EXTERNAL' ? 'Internet-exposed asset' : 'Internal asset'}
                  </span>
                )}
              </div>
            </li>
          )
          })}
        </ul>

        <div aria-hidden className="flex justify-center text-primary/60">
          <ArrowRight className="hidden size-4 lg:block" />
          <ArrowDown className="size-4 lg:hidden" />
        </div>

        <div className="flex flex-col items-center justify-center border-t border-border pt-4 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-4">
          <div className="mb-1 text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">NETRA risk score</div>
          <RiskGauge score={risk.riskScore} size={144} />
          <div className={cn('mt-1 font-mono text-[10px]', tone.text)}>{risk.severity} · {risk.riskScore}/100</div>
        </div>
      </div>

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
