import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  ArrowDown,
  ArrowRight,
  BrainCircuit,
  Bug,
  ChevronRight,
  Crosshair,
  Gauge,
  ListOrdered,
  Radar,
  Scale,
  ScanSearch,
  Server,
  ShieldCheck,
  ShieldHalf,
  Target,
  Waypoints,
} from 'lucide-react'
import { useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { NetraGuide } from '@/components/guide'
import { NetraMark } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { markBriefingCompleted } from '@/lib/briefing'
import { ROUTES } from '@/lib/navigation'
import { BriefingBackdrop } from './briefing/BriefingBackdrop'
import { DecisionPipeline } from './briefing/DecisionPipeline'
import { SecurityInsight } from './briefing/SecurityInsight'
import { usePrefersReducedMotion } from './briefing/reducedMotion'

const WORKFLOW: { label: string; text: string; icon: LucideIcon }[] = [
  { label: 'Detect', text: 'Ingest detections from Suricata, threat intelligence and ML detectors.', icon: Radar },
  { label: 'Understand', text: 'Enrich each event with asset, vulnerability and ATT&CK context.', icon: ScanSearch },
  { label: 'Prioritise', text: 'Rank by contextual risk, not raw severity.', icon: ListOrdered },
  { label: 'Verify', text: 'Confirm the evidence before anyone acts.', icon: ShieldCheck },
  { label: 'Contain', text: 'Take explainable, authorized containment action.', icon: ShieldHalf },
  { label: 'Learn', text: 'Record the decision in Cyber Memory for next time.', icon: BrainCircuit },
]

const SIGNALS: { label: string; icon: LucideIcon }[] = [
  { label: 'Security Events', icon: Activity },
  { label: 'Asset Criticality', icon: Server },
  { label: 'Vulnerabilities / CVSS', icon: Bug },
  { label: 'Threat Intelligence', icon: Crosshair },
  { label: 'MITRE ATT&CK', icon: Target },
  { label: 'Behavioural Analysis', icon: Waypoints },
  { label: 'Risk Context', icon: Gauge },
  { label: 'Decision Intelligence', icon: Scale },
  { label: 'Cyber Memory', icon: BrainCircuit },
]

/**
 * Post-login security briefing, shown once per browser (see lib/briefing).
 * Always reachable directly at /briefing.
 */
export function BriefingPage() {
  const navigate = useNavigate()
  const reduced = usePrefersReducedMotion()
  const workflowRef = useRef<HTMLElement>(null)
  const workflowHeadingRef = useRef<HTMLHeadingElement>(null)

  // Replace so Back from the Command Center returns to sign-in, not the briefing.
  function enterCommandCenter() {
    markBriefingCompleted()
    navigate(ROUTES.dashboard, { replace: true })
  }

  function explore() {
    workflowRef.current?.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' })
    workflowHeadingRef.current?.focus({ preventScroll: true })
  }

  return (
    <div className="relative isolate min-h-svh overflow-x-hidden bg-background">
      <BriefingBackdrop />

      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 pt-5 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3">
          <NetraMark className="size-7" />
          <span className="font-mono text-[10px] tracking-[0.18em] text-muted-foreground uppercase">
            <span className="hidden sm:inline">Security briefing · </span>Session initialised
          </span>
        </div>
        <Button variant="ghost" size="sm" onClick={enterCommandCenter} className="text-muted-foreground">
          Skip briefing <ChevronRight />
        </Button>
      </header>

      <main className="relative z-10 mx-auto max-w-6xl px-4 pb-16 sm:px-6 lg:px-8">
        {/* Hero */}
        <section aria-labelledby="briefing-title" className="flex flex-col items-center pt-14 text-center sm:pt-20">
          <h1 id="briefing-title" className="bg-linear-to-b from-white to-white/60 bg-clip-text pl-[0.34em] text-5xl font-semibold tracking-[0.34em] text-transparent sm:text-6xl lg:text-7xl">
            NETRA
          </h1>
          <p className="mt-3 flex items-center gap-3 font-mono text-[11px] tracking-[0.3em] text-cyan/90 uppercase sm:text-xs">
            <span aria-hidden className="hidden h-px w-8 bg-linear-to-r from-transparent to-cyan/50 sm:block" />
            Cyber Decision Intelligence
            <span aria-hidden className="hidden h-px w-8 bg-linear-to-l from-transparent to-cyan/50 sm:block" />
          </p>

          <p className="mt-9 text-2xl leading-snug font-medium tracking-tight sm:text-3xl lg:text-[2.125rem]">
            <span className="block text-foreground/90">Understand the threat.</span>
            <span className="block text-foreground/90">Prioritise the risk.</span>
            <span className="block bg-linear-to-r from-primary to-cyan bg-clip-text text-transparent">Make the decision.</span>
          </p>

          <p className="mt-5 max-w-xl text-sm leading-relaxed text-muted-foreground sm:text-[15px]">
            NETRA turns security detections into contextual, explainable decisions, so every response is prioritised by real risk and justified before it is taken.
          </p>

          <div className="mt-8 flex w-full flex-col items-stretch gap-3 sm:w-auto sm:flex-row sm:items-center">
            <Button
              size="lg"
              onClick={enterCommandCenter}
              className="h-11 px-6 text-[13px] font-semibold tracking-[0.14em] shadow-[0_10px_28px_-10px] shadow-primary/70"
            >
              ENTER COMMAND CENTER <ArrowRight />
            </Button>
            <Button size="lg" variant="outline" onClick={explore} className="h-11 px-5 text-[13px]">
              Explore NETRA <ArrowDown />
            </Button>
          </div>
        </section>

        {/* Central visual */}
        <div className="mx-auto mt-14 max-w-5xl sm:mt-16">
          <DecisionPipeline />
        </div>

        {/* Workflow */}
        <section ref={workflowRef} aria-labelledby="workflow-title" className="mt-20 scroll-mt-6 sm:mt-24">
          <div className="max-w-2xl">
            <p className="eyebrow">Operating model</p>
            <h2 id="workflow-title" ref={workflowHeadingRef} tabIndex={-1} className="mt-2 text-2xl font-semibold tracking-tight outline-none sm:text-[1.75rem]">
              From detection to decision
            </h2>
          </div>

          <ol className="mt-8 grid grid-cols-1 gap-0 md:grid-cols-3 md:gap-4 lg:grid-cols-6 lg:gap-3">
            {WORKFLOW.map((step, i) => (
              <li key={step.label} className="relative flex gap-4 md:block">
                {/* Mobile rail */}
                <div aria-hidden className="flex flex-col items-center md:hidden">
                  <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-primary/25 bg-primary/10 text-primary">
                    <step.icon className="size-4" />
                  </span>
                  {i < WORKFLOW.length - 1 && <span className="my-1 w-px flex-1 bg-linear-to-b from-primary/35 to-primary/5" />}
                </div>

                <div className="relative h-full flex-1 pb-6 md:overflow-hidden md:rounded-xl md:border md:border-white/8 md:bg-[rgb(13_17_24/0.72)] md:p-4 md:pb-4 md:backdrop-blur-md">
                  <span
                    aria-hidden
                    className="bf-step absolute inset-x-0 top-0 hidden h-px bg-linear-to-r from-transparent via-cyan to-transparent md:block"
                    style={{ animationDelay: `${i * 1.5}s` }}
                  />
                  <div className="flex items-center justify-between">
                    <span className="hidden size-8 place-items-center rounded-lg border border-primary/25 bg-primary/10 text-primary md:grid">
                      <step.icon className="size-4" />
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums md:order-last">{String(i + 1).padStart(2, '0')}</span>
                  </div>
                  <h3 className="mt-1 text-xs font-semibold tracking-[0.18em] uppercase md:mt-4">{step.label}</h3>
                  <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">{step.text}</p>
                </div>

                {i < WORKFLOW.length - 1 && (
                  <ChevronRight aria-hidden className="absolute top-1/2 -right-3 z-10 hidden size-3.5 -translate-y-1/2 text-primary/50 lg:block" />
                )}
              </li>
            ))}
          </ol>
        </section>

        {/* Signals + insight */}
        <section aria-labelledby="signals-title" className="mt-20 grid gap-8 sm:mt-24 lg:grid-cols-[1.35fr_1fr] lg:items-start lg:gap-10">
          <div>
            <p className="eyebrow">Decision context</p>
            <h2 id="signals-title" className="mt-2 text-2xl font-semibold tracking-tight sm:text-[1.75rem]">
              One decision, nine signals
            </h2>
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted-foreground">
              NETRA transforms security detections into contextual, explainable decisions by combining:
            </p>
            <ul className="mt-6 grid grid-cols-1 gap-2 min-[420px]:grid-cols-2 md:grid-cols-3">
              {SIGNALS.map((s) => (
                <li key={s.label} className="surface-inset flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-[13px] text-foreground/85">
                  <s.icon className="size-3.5 shrink-0 text-primary" aria-hidden />
                  {s.label}
                </li>
              ))}
            </ul>
          </div>

          <SecurityInsight />
        </section>

        {/* Close */}
        <div className="mt-20 flex flex-col items-center gap-4 border-t border-white/6 pt-10 text-center sm:mt-24">
          <p className="text-sm text-muted-foreground">Briefing complete. Your Command Center is ready.</p>
          <Button variant="outline" size="lg" onClick={enterCommandCenter} className="h-10 px-5 text-[13px]">
            Enter Command Center <ArrowRight />
          </Button>
          <p className="font-mono text-[10px] tracking-wider text-muted-foreground/60">
            DEMO ENVIRONMENT · SHOWN ON FIRST SIGN-IN · REVISIT AT {ROUTES.briefing.toUpperCase()}
          </p>
        </div>
      </main>

      <NetraGuide page="briefing" />
    </div>
  )
}
