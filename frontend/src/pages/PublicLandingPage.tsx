import type { LucideIcon } from 'lucide-react'
import {
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Gauge,
  Network,
  Radar,
  ScanSearch,
  ShieldCheck,
  ShieldHalf,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { LandingHero } from '@/components/landing/LandingHero'
import { IntelligencePipeline } from '@/components/landing/IntelligencePipeline'
import { SectionHeader } from '@/components/landing/SectionHeader'
import { Button } from '@/components/ui/button'
import { ROUTES } from '@/lib/navigation'

const WORKFLOW: { label: string; text: string; icon: LucideIcon }[] = [
  { label: 'Detect', text: 'Collect and normalize telemetry from across the environment.', icon: Radar },
  { label: 'Understand', text: 'Map events to assets, identity, behavior, and evidence.', icon: ScanSearch },
  { label: 'Prioritise', text: 'Rank risk by impact, urgency, exposure, and confidence.', icon: Gauge },
  { label: 'Verify', text: 'Confirm facts before any active security action is taken.', icon: ShieldCheck },
  { label: 'Authorize', text: 'Route approval through policy-aware decision controls.', icon: ShieldHalf },
  { label: 'Learn', text: 'Capture outcomes to improve future decisions and context.', icon: BrainCircuit },
]

const RISK_FACTORS = [
  'Asset criticality',
  'Vulnerability exposure',
  'Behavioral novelty',
  'Detection confidence',
  'Threat intelligence',
  'Attack context',
]

const DECISION_CHAIN = [
  { label: 'Evidence', value: '18 correlated signals' },
  { label: 'Risk', value: 'High-confidence escalation' },
  { label: 'Recommendation', value: 'Scope and contain service access' },
  { label: 'Confidence', value: '93% analyst corroboration' },
  { label: 'Authorization', value: 'Policy-gated approval path' },
]

const RESPONSE_STEPS = [
  'Recommendation',
  'Authorization',
  'Controlled containment',
  'Verification',
]

const MEMORY_STEPS = [
  'Outcome',
  'Lesson',
  'Memory',
  'Future decision context',
]

export function PublicLandingPage() {
  return (
    <div className="relative isolate min-h-screen overflow-hidden bg-background">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(56,217,255,0.12),transparent_28%),radial-gradient(ellipse_at_bottom_right,rgba(79,124,255,0.10),transparent_28%)]" />
      <div className="netra-grid pointer-events-none absolute inset-0 opacity-40" />

      <main className="relative z-10 mx-auto max-w-[1500px] px-4 pb-24 pt-6 sm:px-6 lg:px-8">
        <LandingHero />

        <section id="what-netra-is" className="netra-section mt-24 rounded-[32px] p-6 sm:p-8 lg:p-10">
          <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-center">
            <div>
              <SectionHeader
                eyebrow="What NETRA is"
                title="Cyber decision intelligence that turns signals into controlled action."
                description="NETRA connects raw security events to context, impact, decision quality, and response controls so teams can act with confidence instead of noise."
              />

              <div className="mt-8 space-y-4">
                {[
                  'Raw signals',
                  'Context',
                  'Risk',
                  'Decision',
                  'Controlled response',
                  'Learning',
                ].map((item, index) => (
                  <div key={item} className="flex items-center gap-3 rounded-2xl border border-border bg-background/30 px-4 py-3 text-sm text-muted-foreground">
                    <div className="grid size-8 place-items-center rounded-full border border-primary/30 bg-primary/10 text-[10px] font-medium tracking-[0.2em] text-primary">
                      {index + 1}
                    </div>
                    <span className="text-foreground">{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-[28px] border border-border/80 bg-background/20 p-4 sm:p-6">
              <IntelligencePipeline />
            </div>
          </div>
        </section>

        <section className="mt-24">
          <SectionHeader
            eyebrow="How NETRA thinks"
            title="The cycle from signal to decisive action."
            description="Every incident is understood in context, ranked by impact, verified before response, and stored as future decision memory."
            align="center"
          />

          <div className="mt-10 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {WORKFLOW.map((step, index) => {
              const Icon = step.icon
              return (
                <div
                  key={step.label}
                  className="netra-panel relative overflow-hidden rounded-[24px] p-5"
                  style={{ animationDelay: `${index * 80}ms` }}
                >
                  <div className="absolute inset-x-6 top-0 h-px bg-[linear-gradient(90deg,transparent,rgba(56,217,255,0.6),transparent)]" />
                  <div className="flex items-start justify-between gap-3">
                    <span className="grid size-11 place-items-center rounded-2xl border border-primary/25 bg-primary/8 text-primary">
                      <Icon className="size-5" />
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground tabular-nums">0{index + 1}</span>
                  </div>
                  <h3 className="mt-5 text-xl font-semibold tracking-[-0.03em] text-foreground">{step.label}</h3>
                  <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{step.text}</p>
                </div>
              )
            })}
          </div>
        </section>

        <section className="mt-24 rounded-[32px] border border-border/80 bg-[linear-gradient(180deg,rgba(16,23,32,0.82),rgba(8,12,18,0.9))] p-6 sm:p-8 lg:p-10">
          <div className="grid gap-8 lg:grid-cols-[1fr_1.1fr] lg:items-center">
            <div>
              <SectionHeader
                eyebrow="Context-aware risk"
                title="Every event is evaluated in the context that matters."
                description="NETRA does not treat every alert as equal. Criticality, exposure, confidence, and behavior are combined to understand what is actually important."
              />
              <div className="mt-8 grid gap-3 sm:grid-cols-2">
                {RISK_FACTORS.map((factor) => (
                  <div key={factor} className="flex items-center gap-3 rounded-2xl border border-border bg-background/20 px-3 py-3 text-sm text-foreground">
                    <span className="size-2.5 rounded-full bg-primary shadow-[0_0_12px_rgba(56,217,255,0.9)]" />
                    {factor}
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-[28px] border border-border/80 bg-background/20 p-5 sm:p-6">
              <div className="flex items-center justify-between border-b border-border pb-4">
                <div>
                  <p className="text-[10px] tracking-[0.2em] text-muted-foreground uppercase">Risk synthesis</p>
                  <h3 className="mt-2 text-3xl font-semibold tracking-[-0.05em] text-foreground">Priority Model</h3>
                </div>
                <div className="rounded-full border border-critical/30 bg-critical/10 px-3 py-1.5 font-mono text-[11px] text-critical">
                  91 / 100
                </div>
              </div>

              <div className="mt-6 space-y-4">
                {[{ label: 'Asset criticality', value: 'High', tone: 'text-primary' }, { label: 'Threat intelligence', value: 'Matched', tone: 'text-warning' }, { label: 'Detection confidence', value: '94%', tone: 'text-success' }, { label: 'Behavioral novelty', value: 'Elevated', tone: 'text-critical' }].map((item) => (
                  <div key={item.label} className="rounded-2xl border border-border bg-background/25 p-4">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">{item.label}</span>
                      <span className={`font-medium ${item.tone}`}>{item.value}</span>
                    </div>
                    <div className="mt-3 h-2 rounded-full bg-[rgba(148,163,184,0.12)]">
                      <div
                        className="h-full rounded-full bg-[linear-gradient(90deg,#38D9FF,#4F7CFF,#FF8A3D)]"
                        style={{ width: item.label === 'Asset criticality' ? '78%' : item.label === 'Threat intelligence' ? '82%' : item.label === 'Detection confidence' ? '92%' : '86%' }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="mt-24 grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <div className="netra-panel rounded-[28px] p-6 sm:p-8">
            <SectionHeader
              eyebrow="Decision intelligence"
              title="Not just an alert. A recommendation with context."
              description="NETRA moves beyond 'incident detected' to explain what happened, why it matters, and which action best balances impact and control."
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {DECISION_CHAIN.map((item) => (
              <div key={item.label} className="netra-panel rounded-[24px] p-4">
                <p className="text-[10px] font-medium tracking-[0.2em] text-muted-foreground uppercase">{item.label}</p>
                <p className="mt-3 text-base font-medium leading-relaxed text-foreground">{item.value}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-24 rounded-[32px] border border-border/80 bg-[linear-gradient(180deg,rgba(10,16,22,0.9),rgba(17,24,32,0.92))] p-6 sm:p-8 lg:p-10">
          <div className="grid gap-8 lg:grid-cols-[1fr_1fr] lg:items-center">
            <div>
              <SectionHeader
                eyebrow="Controlled response"
                title="Impactful actions require authorization and verification."
                description="Recommendations become controlled responses only when policy, approval, and containment are in harmony with the risk context."
              />
            </div>

            <div className="rounded-[28px] border border-border/80 bg-background/15 p-5">
              <div className="flex flex-wrap gap-3">
                {RESPONSE_STEPS.map((step, index) => (
                  <div key={step} className="flex items-center gap-3 rounded-full border border-border bg-background/20 px-3 py-2 text-xs font-medium tracking-[0.12em] text-muted-foreground uppercase">
                    <span className="grid size-6 place-items-center rounded-full bg-primary/10 text-[9px] text-primary">{index + 1}</span>
                    {step}
                  </div>
                ))}
              </div>

              <div className="mt-6 rounded-2xl border border-border bg-background/20 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-[10px] tracking-[0.2em] text-muted-foreground uppercase">Action path</p>
                    <p className="mt-2 text-lg font-semibold text-foreground">Isolate access to impacted service</p>
                  </div>
                  <CheckCircle2 className="size-6 text-success" />
                </div>
                <div className="mt-4 h-2 rounded-full bg-[rgba(148,163,184,0.1)]">
                  <div className="h-full w-[82%] rounded-full bg-[linear-gradient(90deg,#39D98A,#38D9FF,#4F7CFF)]" />
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="mt-24 grid gap-6 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
          <div className="netra-panel rounded-[28px] p-6 sm:p-8">
            <SectionHeader
              eyebrow="Cyber Memory"
              title="Every outcome becomes future context."
              description="NETRA learns from previous decisions to strengthen the next recommendation, reduce repeat exposure, and improve analyst confidence over time."
            />
          </div>

          <div className="rounded-[28px] border border-border/80 bg-background/15 p-5 sm:p-6">
            <div className="flex flex-wrap gap-2">
              {MEMORY_STEPS.map((step, index) => (
                <div key={step} className="rounded-full border border-border bg-background/20 px-3 py-2 text-[10px] font-medium tracking-[0.16em] text-muted-foreground uppercase">
                  {step}
                  {index < MEMORY_STEPS.length - 1 ? <span className="ml-2 text-primary">→</span> : null}
                </div>
              ))}
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border border-border bg-background/20 p-4">
                <div className="flex items-center gap-2 text-primary">
                  <Network className="size-4" />
                  <span className="text-xs font-medium tracking-[0.18em] uppercase">Memory</span>
                </div>
                <p className="mt-3 text-sm text-muted-foreground">Prior incident patterns and controls are retained as operational context.</p>
              </div>
              <div className="rounded-2xl border border-border bg-background/20 p-4">
                <div className="flex items-center gap-2 text-secondary-accent">
                  <Cpu className="size-4" />
                  <span className="text-xs font-medium tracking-[0.18em] uppercase">Reasoning</span>
                </div>
                <p className="mt-3 text-sm text-muted-foreground">Response outcomes sharpen the next decision path and reduce duplicate signals.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="mt-24 rounded-[32px] border border-primary/20 bg-[radial-gradient(circle_at_top,rgba(56,217,255,0.12),transparent_48%),linear-gradient(180deg,rgba(16,23,32,0.95),rgba(7,11,16,0.96))] p-6 sm:p-8 lg:p-10">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-[10px] font-medium tracking-[0.26em] text-primary uppercase">See more. Understand faster. Respond with control.</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-[-0.06em] text-foreground sm:text-4xl lg:text-[3rem]">
                Enter NETRA and turn signal into strategy.
              </h2>
            </div>

            <Button asChild size="lg" className="h-12 rounded-full px-6 text-[11px] font-semibold tracking-[0.18em] uppercase">
              <Link to={ROUTES.login}>
                Enter NETRA
                <ArrowRight className="ml-2 size-4" />
              </Link>
            </Button>
          </div>
        </section>
      </main>
    </div>
  )
}
