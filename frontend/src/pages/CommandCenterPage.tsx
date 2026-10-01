import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Radar, ShieldAlert, ShieldCheck, Sparkles } from 'lucide-react'
import { Disclosure, ErrorState, LoadingState, PageContainer, PageHeader, Panel, RiskGauge, SurfaceCard, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { ROUTES } from '@/lib/navigation'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetInventoryService, dashboardService, eventService, incidentQueueService, threatIntelService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { EventFeed } from './dashboard/EventFeed'
import { DetectionIntelPanel } from './dashboard/DetectionIntelPanel'
import { PrioritizedIncidentsPanel } from './dashboard/PrioritizedIncidentsPanel'
import { RiskTrendPanel } from './dashboard/RiskTrendPanel'
import { AssetRiskPanel } from './dashboard/AssetRiskPanel'

const reasoningSteps = [
  'ANALYZING SECURITY CONTEXT',
  'EVALUATING RISK',
  'PRIORITISING INCIDENT',
  'PREPARING RECOMMENDATION',
]

const pipelineStages = [
  { label: 'DETECTION', description: 'Signal collection and correlation establish the event surface.' },
  { label: 'CONTEXT', description: 'NETRA enriches the incident with asset and environment context.' },
  { label: 'RISK', description: 'NETRA combines contextual evidence into an explainable risk score.' },
  { label: 'DECISION', description: 'The decision engine weights the likely response path.' },
  { label: 'AUTHORIZATION', description: 'Approval gates prevent impulsive containment and escalation.' },
  { label: 'CONTAINMENT', description: 'Actionable control measures are prepared once the decision is cleared.' },
  { label: 'MEMORY', description: 'Feedback is retained to improve future cyber decisioning.' },
]

export function CommandCenterPage() {
  const stats = useQuery('dash-stats', dashboardService.getStats)
  const incidents = useQuery('dash-incidents', () => incidentQueueService.list({ state: 'ACTIVE', sort: 'risk' }))
  const events = useQuery('dash-events', () => eventService.listForEventsPage())
  const databaseHealth = useQuery('dash-database-health', dashboardService.getDatabaseHealth)
  const demoAssets = useQuery('dash-demo-assets', () => USE_MOCKS ? assetInventoryService.list() : Promise.resolve([]))
  const demoTechniques = useQuery('dash-demo-techniques', () => USE_MOCKS ? threatIntelService.getObservedTechniques() : Promise.resolve(null))
  const [entered, setEntered] = useState(false)
  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const [microToasts, setMicroToasts] = useState<Array<{ id: string; label: string }>>(
    USE_MOCKS && reducedMotion ? [{ id: 'decision-context', label: 'Decision context assembled' }] : [],
  )
  const [recommendationToast, setRecommendationToast] = useState(USE_MOCKS && reducedMotion)
  const primaryIncident = incidents.data?.[0]
  const primaryRisk = primaryIncident?.riskScore ?? stats.data?.overallRisk ?? stats.data?.averageRiskScore ?? null
  const riskScore = USE_MOCKS ? stats.data?.overallRisk ?? null : stats.data?.averageRiskScore ?? null
  const recommendedAction = primaryIncident?.latestDecision?.action ?? primaryIncident?.recommendedAction ?? null
  const recommendationText = primaryIncident?.latestDecision?.recommendation ?? (recommendedAction ? `Recommended action: ${recommendedAction}.` : null)
  const evidenceText = primaryIncident?.latestDecision?.rationale ?? null

  useEffect(() => {
    const motionId = requestAnimationFrame(() => setEntered(true))

    const timers: number[] = []
    if (USE_MOCKS && !reducedMotion) {
      timers.push(window.setTimeout(() => setMicroToasts([{ id: 'risk-assessment', label: 'Risk assessment complete' }]), 1100))
      timers.push(window.setTimeout(() => setMicroToasts([{ id: 'priority-identified', label: 'Priority incident identified' }]), 1700))
      timers.push(window.setTimeout(() => setRecommendationToast(true), 1500))
      timers.push(window.setTimeout(() => setRecommendationToast(false), 4700))
      timers.push(window.setTimeout(() => setMicroToasts([{ id: 'decision-context', label: 'Decision context assembled' }]), 2300))
      timers.push(window.setTimeout(() => setMicroToasts([]), 5000))
    }

    return () => {
      cancelAnimationFrame(motionId)
      timers.forEach((timer) => window.clearTimeout(timer))
    }
  }, [reducedMotion])

  if (stats.error) {
    const authenticationError = stats.error instanceof HttpError && stats.error.status === 401
    return (
      <SurfaceCard className="text-center">
        <ErrorState
          title={authenticationError ? 'Authentication required' : 'Dashboard unavailable'}
          message={authenticationError ? undefined : stats.error.message}
          onRetry={authenticationError ? undefined : stats.reload}
        />
        {authenticationError && <Button asChild><Link to={ROUTES.login}>Sign in</Link></Button>}
      </SurfaceCard>
    )
  }

  return (
    <PageContainer className="space-y-4 overflow-x-hidden">
      <div
        className={cn('transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-3 opacity-0')}
        style={{ transitionDelay: '90ms' }}
      >
        <PageHeader
          eyebrow="Cyber decision intelligence"
          title="Command Center"
          description="Current risk posture, the incidents that matter most, and the evidence behind the queue."
          actions={
            <>
              <ToneBadge tone={USE_MOCKS ? 'medium' : 'low'} size="sm">{USE_MOCKS ? 'Demo data' : 'Live API'}</ToneBadge>
              <Button asChild>
                <Link to={ROUTES.incidents}>
                  <ShieldAlert /> Triage incidents
                </Link>
              </Button>
            </>
          }
        />
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(300px,0.9fr)]">
        <SurfaceCard className="relative overflow-hidden p-0">
          <div className="flex items-center justify-between border-b border-border/80 bg-[radial-gradient(circle_at_left,_rgba(56,217,255,0.1),transparent_25%)] px-5 py-3">
            <div
              className={cn('transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0')}
              style={{ transitionDelay: '300ms' }}
            >
              <div className="eyebrow text-[10px] text-primary/80">Mission posture</div>
              <h2 className="mt-1 text-[15px] font-semibold tracking-tight">{USE_MOCKS ? 'Overall risk posture' : 'Average active incident risk'}</h2>
            </div>
            <span className="rounded-full border border-primary/20 bg-primary/8 px-2 py-1 text-[10px] font-medium text-primary uppercase tracking-[0.18em]">
              {USE_MOCKS ? 'Demo' : 'Live'}
            </span>
          </div>

          <div className="grid gap-5 p-5 xl:grid-cols-[auto_minmax(0,1fr)]">
            <div
              className={cn('flex items-center justify-center transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-8 opacity-0')}
              style={{ transitionDelay: '290ms' }}
            >
              {!stats.data ? (
                <div role="status" className="grid size-[220px] place-items-center rounded-full border border-dashed border-border text-sm text-muted-foreground">
                  Loading risk posture
                </div>
              ) : riskScore === null ? (
                <div className="grid size-[220px] place-items-center rounded-full border border-dashed border-border px-8 text-center text-sm text-muted-foreground">
                  {stats.data.activeIncidents === 0 ? 'No active incidents to score' : 'Risk score unavailable from the API'}
                </div>
              ) : (
                <RiskGauge score={riskScore} label={USE_MOCKS ? undefined : 'Average active risk'} size={220} />
              )}
            </div>

            <div className="space-y-5">
              <div className="grid gap-3 sm:grid-cols-3">
                <MetricTile
                  label={USE_MOCKS ? 'Risk change' : 'Events · 24h'}
                  value={USE_MOCKS
                    ? stats.data?.overallRiskChange == null ? 'Unavailable' : `${stats.data.overallRiskChange > 0 ? '+' : ''}${Math.round(stats.data.overallRiskChange)}%`
                    : stats.data ? String(stats.data.eventsLast24h) : '—'}
                  hint={!USE_MOCKS && stats.data ? `Critical ${stats.data.criticalEvents ?? 0} / High ${stats.data.highEvents ?? 0}` : undefined}
                  tone={USE_MOCKS
                    ? stats.data?.overallRiskChange == null ? 'neutral' : stats.data.overallRiskChange > 0 ? 'critical' : 'low'
                    : 'accent'}
                  entered={entered}
                  delay={420}
                />
                <MetricTile
                  label={USE_MOCKS ? 'Critical assets' : 'Critical incidents'}
                  value={stats.data ? String(USE_MOCKS ? stats.data.criticalAssets : stats.data.incidentsBySeverity.CRITICAL ?? 'Unavailable') : '—'}
                  hint={!USE_MOCKS && stats.data ? `${stats.data.criticalAssets} critical assets` : undefined}
                  tone="accent"
                  entered={entered}
                  delay={520}
                />
                <MetricTile label="Active incidents" value={stats.data ? String(stats.data.activeIncidents) : '—'} tone="high" entered={entered} delay={620} />
              </div>

              <div>
                <div className="mb-3 flex items-center justify-between text-xs">
                  <span className="font-medium text-foreground/85">Top risk drivers</span>
                  <span className="text-muted-foreground">pts / 100</span>
                </div>
                <ul className="space-y-2.5">
                  {stats.data?.riskDrivers.length === 0 && <li className="text-xs text-muted-foreground">Risk drivers unavailable</li>}
                  {(stats.data?.riskDrivers ?? []).slice(0, 4).map((factor, index) => (
                    <RiskFactorRow key={factor.key} factor={factor} index={index} entered={entered} />
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </SurfaceCard>

        <SurfaceCard className="h-full overflow-hidden p-0">
          <div className="flex items-start justify-between border-b border-border/80 px-5 py-3">
            <div
              className={cn('transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0')}
              style={{ transitionDelay: '430ms' }}
            >
              <div className="eyebrow text-[10px] text-cyan/80">Primary incident</div>
              <h2 className="mt-1 text-[15px] font-semibold tracking-tight">Decision priority</h2>
            </div>
            <ShieldCheck className="size-4 text-primary" />
          </div>

          <div className="space-y-4 p-5">
            {incidents.error ? (
              <div>
                <ErrorState
                  title={incidents.error instanceof HttpError && incidents.error.status === 401 ? 'Authentication required' : 'Priority queue unavailable'}
                  message={incidents.error instanceof HttpError && incidents.error.status === 401 ? undefined : incidents.error.message}
                  onRetry={incidents.error instanceof HttpError && incidents.error.status === 401 ? undefined : incidents.reload}
                />
                {incidents.error instanceof HttpError && incidents.error.status === 401 && (
                  <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
                )}
              </div>
            ) : incidents.loading && !incidents.data ? (
              <LoadingState variant="inline" label="Loading priority incident…" />
            ) : !primaryIncident ? (
              <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
                No active incidents in the queue.
              </div>
            ) : (
              <div
                className={cn('transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-6 opacity-0')}
                style={{ transitionDelay: '500ms' }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-muted-foreground">{primaryIncident.id}</div>
                    <h3 className="mt-1 line-clamp-2 text-base font-semibold text-foreground">{primaryIncident.title}</h3>
                  </div>
                  <span className={cn('inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em]', toneStyles[severityTone[primaryIncident.severity]].soft, toneStyles[severityTone[primaryIncident.severity]].border, toneStyles[severityTone[primaryIncident.severity]].text)}>
                    {primaryIncident.severity}
                  </span>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3">
                  <ScorePill label="Risk score" value={primaryRisk === null ? 'Unavailable' : String(primaryRisk)} />
                  <ScorePill label="Asset" value={primaryIncident.asset?.name ?? primaryIncident.asset?.id ?? 'N/A'} />
                </div>

                <div className="mt-4 rounded-lg border border-primary/15 bg-primary/6 p-3 transition-all duration-300 hover:border-primary/25 hover:bg-primary/10">
                  <div className="flex items-center gap-2 text-[11px] font-medium tracking-[0.16em] text-primary uppercase">
                    <Sparkles className="size-3.5" />
                    Recommended action
                  </div>
                  <p className="mt-2 text-sm text-foreground/90">
                    {USE_MOCKS
                      ? `${primaryIncident.title} requires immediate review, because the current signal pattern shows a high-confidence escalation path and a narrow containment window.`
                      : recommendationText ?? 'No recommendation is available from the current API.'}
                  </p>
                </div>

                <div className="mt-4 rounded-lg border border-border bg-foreground/[0.02] p-3 transition-all duration-300 hover:border-border/80 hover:bg-foreground/[0.04]">
                  <div className="flex items-center gap-2 text-[11px] font-medium tracking-[0.16em] text-muted-foreground uppercase">
                    <Radar className="size-3.5" />
                    Evidence summary
                  </div>
                  {USE_MOCKS ? (
                    <ul className="mt-2 space-y-2 text-sm text-muted-foreground">
                      <li>• Escalation path is trending above the median risk threshold.</li>
                      <li>• Related detections are concentrated on a single critical asset.</li>
                      <li>• Containment guidance remains available for rapid approval.</li>
                    </ul>
                  ) : (
                    <p className="mt-2 text-sm text-muted-foreground">{evidenceText ?? 'No decision rationale is available from the current API.'}</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </SurfaceCard>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(300px,0.9fr)]">
        <div className="min-w-0" data-guide-target="incident-queue">
          {incidents.error ? (
            <Panel title="Prioritized incidents">
              <ErrorState onRetry={incidents.reload} />
            </Panel>
          ) : (
            <div className={cn('transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-6 opacity-0')} style={{ transitionDelay: '760ms' }}>
              <PrioritizedIncidentsPanel incidents={incidents.data} />
            </div>
          )}
        </div>

        <div className="space-y-4">
          <Panel title="Decision recommendation" description="The next best action based on the current queue." className="min-h-[200px]">
            <div className={cn('space-y-4 transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-6 opacity-0')} style={{ transitionDelay: '700ms' }}>
              <div className="flex items-center gap-2 text-xs font-medium tracking-[0.14em] text-primary uppercase">
                <Activity className="size-3.5" />
                Priority brief
              </div>

              <div className="grid gap-2">
                {(USE_MOCKS ? reasoningSteps : [
                  `ACTIVE INCIDENTS: ${stats.data?.activeIncidents ?? '—'}`,
                  `PRIORITY INCIDENT: ${primaryIncident?.title ?? 'None returned'}`,
                  `RISK SCORE: ${primaryIncident?.riskScore ?? 'Unavailable'}`,
                  `ACTION: ${recommendedAction ?? 'Not provided by API'}`,
                ]).map((step, index) => (
                  <div
                    key={step}
                    className={cn('netra-reasoning-step flex items-center gap-2 rounded-md border border-border/70 bg-foreground/[0.02] px-3 py-2 text-[11px] font-medium tracking-[0.18em] uppercase text-muted-foreground transition-all duration-300', entered && 'border-primary/15 bg-primary/6 text-primary')}
                    style={{ animationDelay: `${index * 110 + 700}ms`, opacity: entered ? 1 : 0 }}
                  >
                    <span className="inline-flex size-2 rounded-full bg-primary/80" />
                    {step}
                  </div>
                ))}
              </div>

              <div className="rounded-lg border border-primary/20 bg-primary/8 px-3 py-2 text-sm text-foreground/90">
                {USE_MOCKS ? 'NETRA RECOMMENDATION READY' : recommendedAction ? `API recommendation: ${recommendedAction}` : 'No recommendation supplied by the API'}
              </div>

              <p className="text-sm text-muted-foreground">
                {USE_MOCKS
                  ? primaryIncident
                    ? `Focus effort on ${primaryIncident.title}. The asset context and risk contribution pattern justify immediate analyst action before the queue widens.`
                    : 'No active priority is currently driving a decision cycle.'
                  : evidenceText ?? (primaryIncident ? 'No decision rationale is available from the current API.' : 'No active incident is currently driving a decision cycle.')}
              </p>
              <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                <span className={cn('inline-flex size-2 rounded-full', recommendedAction || USE_MOCKS ? 'bg-low' : 'bg-muted-foreground')} />
                {USE_MOCKS ? 'Recommended: advance to triage and containment review' : recommendedAction ? `Recommended: ${recommendedAction}` : 'No recommendation available'}
              </div>
            </div>
          </Panel>

          <Panel title="Intelligence pipeline" description="NETRA decision lifecycle." className="min-h-[200px]">
            <div className={cn('netra-pipeline-track relative mt-2 transition-all duration-500 ease-out', entered ? 'opacity-100' : 'opacity-0')} style={{ transitionDelay: '900ms' }}>
              <span className="netra-pipeline-signal" aria-hidden="true" />
              <div className="flex items-center justify-between gap-2 overflow-x-auto pb-1">
                {pipelineStages.map((stage) => (
                  <div key={stage.label} className="group relative min-w-[58px] flex-1 px-1 first:pl-0 last:pr-0">
                    <div className="rounded-xl border border-border bg-foreground/[0.02] px-2 py-2 text-center transition-all duration-300 hover:border-primary/20 hover:bg-primary/8 hover:shadow-[0_0_0_1px_rgba(56,217,255,0.2)]">
                      <div className="text-[9px] font-medium tracking-[0.18em] text-muted-foreground uppercase">{stage.label}</div>
                    </div>
                    <div className="pointer-events-none absolute left-1/2 top-full z-10 mt-2 w-44 -translate-x-1/2 rounded-md border border-border bg-popover/95 p-2 text-left text-[11px] text-muted-foreground opacity-0 shadow-lg transition-all duration-200 group-hover:opacity-100">
                      {stage.description}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Panel>

          <Panel title="Mission status" description="Consolidated system health summary." className="min-h-[170px]">
            <div className={cn('space-y-3 text-sm transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-6 opacity-0')} style={{ transitionDelay: '900ms' }}>
              {USE_MOCKS ? stats.data?.systemHealth.slice(0, 4).map((component) => (
                <div key={component.component} className="flex items-center justify-between gap-3 rounded-md border border-border bg-foreground/[0.02] px-3 py-2 transition-all duration-300 hover:border-border/80 hover:bg-foreground/[0.04]">
                  <div>
                    <div className="font-medium text-foreground">{component.name}</div>
                    <div className="text-[11px] text-muted-foreground">{component.message ?? 'System heartbeat nominal'}</div>
                  </div>
                  <span className={cn('inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em]', toneStyles[severityTone[component.status === 'HEALTHY' ? 'LOW' : component.status === 'DEGRADED' ? 'MEDIUM' : 'CRITICAL']].soft, toneStyles[severityTone[component.status === 'HEALTHY' ? 'LOW' : component.status === 'DEGRADED' ? 'MEDIUM' : 'CRITICAL']].border, toneStyles[severityTone[component.status === 'HEALTHY' ? 'LOW' : component.status === 'DEGRADED' ? 'MEDIUM' : 'CRITICAL']].text)}>
                    {component.status}
                  </span>
                </div>
              )) : (
                <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-foreground/[0.02] px-3 py-2">
                  <div>
                    <div className="font-medium text-foreground">Database</div>
                    <div className="text-[11px] text-muted-foreground">{databaseHealth.data?.service ?? 'Backend database health check'}</div>
                  </div>
                  <span className={cn('inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em]', databaseHealth.data?.status === 'healthy' ? toneStyles.low.soft : databaseHealth.data ? toneStyles.critical.soft : toneStyles.neutral, databaseHealth.data?.status === 'healthy' ? toneStyles.low.border : databaseHealth.data ? toneStyles.critical.border : toneStyles.neutral, databaseHealth.data?.status === 'healthy' ? toneStyles.low.text : databaseHealth.data ? toneStyles.critical.text : toneStyles.neutral)}>
                    {databaseHealth.loading ? 'Loading' : databaseHealth.data?.database ?? 'Unavailable'}
                  </span>
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(260px,0.8fr)]">
        <Panel title="Recent security activity" description="Events returned by the API, with direct links to correlated incidents" flush>
          {events.error ? (
            <ErrorState onRetry={events.reload} />
          ) : !events.data ? (
            <LoadingState className="p-5" count={6} />
          ) : (
            <div className="px-5 py-4">
              <EventFeed events={events.data.items.slice(0, 6)} />
            </div>
          )}
        </Panel>

        {USE_MOCKS ? (
          <Panel title="Demo-only enrichment" description="Mock analytics are separate from live API-backed posture.">
            <p className="text-sm text-muted-foreground">Additional risk history, asset context and ATT&CK activity are available in the demo section below.</p>
          </Panel>
        ) : (
          <Panel title="Not returned by the current API" description="These signals are not estimated or filled with demo values.">
            <dl className="divide-y divide-border text-[13px]">
              <Availability label="Risk history and drivers" />
              <Availability label="ATT&CK activity" />
              <Availability label="Asset risk scores" />
            </dl>
          </Panel>
        )}
      </div>

      {USE_MOCKS && (
        <Disclosure label="Open demo-only dashboard enrichment" hint="Mock data · not live telemetry">
          <div className="grid items-start gap-4 pt-4 xl:grid-cols-2">
            <AssetRiskPanel assets={demoAssets.data} />
            <RiskTrendPanel />
            <div className="xl:col-span-2">
              <DetectionIntelPanel
                techniques={demoTechniques.data}
                events={events.data?.items.slice(0, 8)}
                health={stats.data?.systemHealth}
              />
            </div>
          </div>
        </Disclosure>
      )}

      {USE_MOCKS && recommendationToast && (
        <div className="pointer-events-none fixed right-4 bottom-4 z-50 max-w-xs rounded-xl border border-primary/20 bg-background/90 px-4 py-3 shadow-[0_18px_55px_-24px_rgba(56,217,255,0.7)] backdrop-blur-xl transition-all duration-500 ease-out">
          <div className="text-[10px] font-medium tracking-[0.18em] text-primary uppercase">NETRA intelligence</div>
          <div className="mt-1 text-sm font-semibold text-foreground">Recommendation ready</div>
          <p className="mt-1 text-xs text-muted-foreground">High-risk incident requires analyst attention.</p>
        </div>
      )}

      {USE_MOCKS && microToasts.length > 0 && (
        <div className="pointer-events-none fixed right-4 top-20 z-50 flex flex-col gap-2">
          {microToasts.map((toast) => (
            <div key={toast.id} className="rounded-lg border border-border bg-background/85 px-3 py-2 text-xs text-foreground shadow-lg backdrop-blur-xl transition-all duration-300">
              {toast.label}
            </div>
          ))}
        </div>
      )}
    </PageContainer>
  )
}

function MetricTile({ label, value, hint, tone, entered, delay }: { label: string; value: string; hint?: string; tone: 'critical' | 'low' | 'accent' | 'neutral' | 'high'; entered: boolean; delay: number }) {
  const toneStyle = {
    critical: 'bg-critical/10 text-critical border-critical/20',
    low: 'bg-low/10 text-low border-low/20',
    accent: 'bg-primary/10 text-primary border-primary/25',
    neutral: 'bg-muted text-muted-foreground border-border',
    high: 'bg-high/10 text-high border-high/25',
  }[tone]

  return (
    <div
      className={cn('rounded-lg border p-3 transition-all duration-500 ease-out', toneStyle, entered ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0')}
      style={{ transitionDelay: `${delay}ms` }}
    >
      <div className="text-[10px] font-medium tracking-[0.14em] uppercase text-current/80">{label}</div>
      <div className="metric mt-2 text-2xl text-current">{value}</div>
      {hint && <div className="mt-1 text-[10px] text-current/75">{hint}</div>}
    </div>
  )
}

function RiskFactorRow({ factor, index, entered }: { factor: { key: string; label: string; contribution: number; weight: number }; index: number; entered: boolean }) {
  const percent = Math.min(100, Math.max(0, (factor.contribution / (factor.weight * 100)) * 100))

  return (
    <li
      className={cn('grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1.5 transition-all duration-500 ease-out', entered ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0')}
      style={{ transitionDelay: `${650 + index * 120}ms` }}
    >
      <span className="truncate text-xs text-muted-foreground">{factor.label}</span>
      <span className="font-mono text-xs text-foreground/90 tabular-nums">{factor.contribution.toFixed(1)}</span>
      <div className="col-span-2 h-1.5 overflow-hidden rounded-full bg-foreground/6">
        <div
          className="h-full rounded-full bg-gradient-to-r from-primary via-violet to-cyan transition-all duration-700 ease-out"
          style={{ width: entered ? `${percent}%` : '0%' }}
        />
      </div>
    </li>
  )
}

function ScorePill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-foreground/[0.02] px-3 py-2.5 transition-all duration-300 hover:border-border/80 hover:bg-foreground/[0.04]">
      <div className="text-[10px] font-medium tracking-[0.14em] text-muted-foreground uppercase">{label}</div>
      <div className="mt-1 text-sm font-semibold text-foreground">{value}</div>
    </div>
  )
}

function Availability({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0">
      <dt>{label}</dt>
      <dd className="shrink-0 text-xs text-muted-foreground">Unavailable</dd>
    </div>
  )
}
