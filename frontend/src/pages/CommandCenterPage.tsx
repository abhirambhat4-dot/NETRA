import type * as React from 'react'
import { Suspense, lazy } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, ClipboardCheck, FileSearch, Info, LayoutDashboard, ShieldAlert } from 'lucide-react'
import {
  Disclosure,
  ErrorState,
  LoadingState,
  PageContainer,
  PageHeader,
  Panel,
  RiskGauge,
  SeverityBadge,
  StatusDot,
  SurfaceCard,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { ROUTES } from '@/lib/navigation'
import { severityTone, toneStyles, type Tone } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetInventoryService, dashboardService, eventService, incidentQueueService, threatIntelService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { EventFeed } from './dashboard/EventFeed'
import { DetectionIntelPanel } from './dashboard/DetectionIntelPanel'
import { LifecyclePanel } from './dashboard/LifecyclePanel'
import { PrioritizedIncidentsPanel } from './dashboard/PrioritizedIncidentsPanel'
import { AssetRiskPanel } from './dashboard/AssetRiskPanel'
import {
  DEMO_NOTICE,
  allTimeEventSeverityHint,
  formatLifecycleState,
  incidentIdentity,
  incidentRiskLabel,
  showRiskDriverScale,
  unsupportedIncidentsNotice,
} from './dashboard/presentation'

// Recharts is only needed by this demo-only panel; loading it lazily keeps it out of live mode.
const RiskTrendPanel = lazy(() => import('./dashboard/RiskTrendPanel').then((m) => ({ default: m.RiskTrendPanel })))

const delay = (ms: number) => ({ '--cc-delay': `${ms}ms` }) as React.CSSProperties

/** Shared column split for every two-column row, so the page keeps one vertical grid line. */
const SPLIT = 'xl:grid-cols-[minmax(0,1.55fr)_minmax(340px,1fr)]'

export function CommandCenterPage() {
  const stats = useQuery('dash-stats', dashboardService.getStats)
  const incidents = useQuery('dash-incidents', () => incidentQueueService.listTolerant({ state: 'ACTIVE', sort: 'risk' }))
  const events = useQuery('dash-events', () => eventService.listForEventsPage())
  const databaseHealth = useQuery('dash-database-health', dashboardService.getDatabaseHealth)
  const demoAssets = useQuery('dash-demo-assets', () => USE_MOCKS ? assetInventoryService.list() : Promise.resolve([]))
  const demoTechniques = useQuery('dash-demo-techniques', () => USE_MOCKS ? threatIntelService.getObservedTechniques() : Promise.resolve(null))

  const queue = incidents.data?.items
  const unsupportedNotice = unsupportedIncidentsNotice(incidents.data?.unsupported ?? 0)
  const primaryIncident = queue?.[0]
  const riskScore = USE_MOCKS ? stats.data?.overallRisk ?? null : stats.data?.averageRiskScore ?? null
  const recommendedAction = primaryIncident?.latestDecision?.action ?? primaryIncident?.recommendedAction ?? null
  const recommendationText = primaryIncident?.latestDecision?.recommendation ?? (recommendedAction ? `Recommended action: ${recommendedAction}.` : null)
  const evidenceText = primaryIncident?.latestDecision?.rationale ?? null
  const drivers = stats.data?.riskDrivers ?? []

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
    <PageContainer className="gap-5 overflow-x-hidden lg:gap-6">
      <PageHeader
        icon={LayoutDashboard}
        eyebrow="Cyber decision intelligence"
        title="Command Center"
        description="Current risk posture, the incidents that matter most, and the evidence behind the queue."
        className="cc-rise"
        actions={
          <>
            <ToneBadge tone={USE_MOCKS ? 'medium' : 'low'}>{USE_MOCKS ? 'Demo data' : 'Live API'}</ToneBadge>
            <Button asChild className="h-9 px-4">
              <Link to={ROUTES.incidents}>
                <ShieldAlert /> Triage incidents
                <ArrowRight className="cc-arrow" aria-hidden />
              </Link>
            </Button>
          </>
        }
      />

      {USE_MOCKS && (
        <p role="note" className="cc-rise flex items-center gap-2.5 rounded-xl border border-medium/30 bg-medium/8 px-4 py-2.5 text-sm text-medium" style={delay(80)}>
          <Info className="size-4 shrink-0" aria-hidden />
          {DEMO_NOTICE}. Values on this page come from the local mock data set, not from the API.
        </p>
      )}

      <div className={cn('grid items-stretch gap-5', SPLIT)}>
        {/* Mission posture */}
        <section
          data-guide-target="security-posture"
          aria-labelledby="cc-posture-title"
          className="cc-card cc-card-hero cc-rise flex flex-col overflow-hidden rounded-2xl"
          style={delay(120)}
        >
          <CardHeading
            eyebrow="Mission posture"
            title={USE_MOCKS ? 'Overall risk posture' : 'Average active incident risk'}
            titleId="cc-posture-title"
            aside={<SourceChip />}
          />

          <div className="@container flex-1 p-5 sm:p-6">
            <div className="grid h-full gap-6 @lg:grid-cols-[13.5rem_minmax(0,1fr)] @lg:items-center @lg:gap-8">
              <div className="flex flex-col items-center gap-3">
                <div className="relative grid place-items-center">
                  <span aria-hidden className="cc-gauge-halo absolute inset-3 rounded-full" />
                  {!stats.data ? (
                    <div role="status" className="relative grid size-50 place-items-center rounded-full border border-dashed border-border px-8 text-center text-sm text-muted-foreground">
                      Loading risk posture
                    </div>
                  ) : riskScore === null ? (
                    <div className="relative grid size-50 place-items-center rounded-full border border-dashed border-border px-9 text-center">
                      <span className="text-sm leading-snug text-muted-foreground">
                        {stats.data.activeIncidents === 0 ? 'No active incidents to score' : 'Risk score unavailable from the API'}
                      </span>
                    </div>
                  ) : (
                    <RiskGauge score={riskScore} label={USE_MOCKS ? undefined : 'Average active risk'} size={200} className="relative" />
                  )}
                </div>
                {!USE_MOCKS && riskScore !== null && (
                  <p className="max-w-52 text-center text-xs leading-relaxed text-muted-foreground">Average of active incidents that have a risk score.</p>
                )}
              </div>

              <div className="min-w-0 space-y-6">
                <div className="@container">
                  <div className="grid gap-2.5 @lg:grid-cols-3 @lg:gap-3">
                    <MetricTile
                      label={USE_MOCKS ? 'Risk change' : 'Events · 24h'}
                      value={USE_MOCKS
                        ? stats.data?.overallRiskChange == null ? 'Unavailable' : `${stats.data.overallRiskChange > 0 ? '+' : ''}${Math.round(stats.data.overallRiskChange)}%`
                        : stats.data ? String(stats.data.eventsLast24h) : '—'}
                      hint={!USE_MOCKS && stats.data ? allTimeEventSeverityHint(stats.data.criticalEvents, stats.data.highEvents) : undefined}
                      tone={USE_MOCKS
                        ? stats.data?.overallRiskChange == null ? 'neutral' : stats.data.overallRiskChange > 0 ? 'critical' : 'low'
                        : 'accent'}
                      style={delay(220)}
                    />
                    <MetricTile
                      label={USE_MOCKS ? 'Critical assets' : 'Critical incidents'}
                      value={stats.data ? String(USE_MOCKS ? stats.data.criticalAssets : stats.data.incidentsBySeverity.CRITICAL ?? 'Unavailable') : '—'}
                      hint={!USE_MOCKS && stats.data ? `${stats.data.criticalAssets} critical assets` : undefined}
                      tone="accent"
                      style={delay(280)}
                    />
                    <MetricTile label="Active incidents" value={stats.data ? String(stats.data.activeIncidents) : '—'} tone="high" style={delay(340)} />
                  </div>
                </div>

                <div>
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h3 className="text-[13px] font-semibold text-foreground">Top risk drivers</h3>
                    {showRiskDriverScale(drivers) && <span className="text-xs text-muted-foreground">Points out of 100</span>}
                  </div>
                  {!stats.data ? (
                    <p className="text-xs text-muted-foreground">Loading risk drivers…</p>
                  ) : drivers.length === 0 ? (
                    <p className="flex items-start gap-2.5 rounded-xl border border-border bg-foreground/2 px-3.5 py-3 text-xs leading-relaxed text-muted-foreground">
                      <Info className="mt-px size-3.5 shrink-0 text-primary/80" aria-hidden />
                      Risk drivers are not returned by the current API.
                    </p>
                  ) : (
                    <ul className="space-y-3.5">
                      {drivers.slice(0, 4).map((factor, index) => (
                        <RiskFactorRow key={factor.key} factor={factor} style={delay(380 + index * 90)} />
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Primary incident — includes what the former "Priority brief" repeated */}
        <section aria-labelledby="cc-primary-title" className="cc-card cc-rise flex flex-col overflow-hidden rounded-2xl" style={delay(200)}>
          <CardHeading
            eyebrow="Primary incident"
            title="Decision priority"
            titleId="cc-primary-title"
            aside={
              <span aria-hidden className="grid size-8 place-items-center rounded-lg border border-primary/25 bg-primary/10 text-primary">
                <ClipboardCheck className="size-4" />
              </span>
            }
          />

          <div className="flex flex-1 flex-col p-5 sm:p-6">
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
              <div className="flex flex-1 flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border px-4 py-8 text-center">
                <ClipboardCheck className="size-5 text-muted-foreground/70" aria-hidden />
                <p className="text-sm text-muted-foreground">No active incidents in the queue.</p>
              </div>
            ) : (
              <div className="flex flex-1 flex-col gap-5">
                <div>
                  <div className="flex items-center justify-between gap-3">
                    <p className="font-mono text-xs text-muted-foreground">{incidentIdentity(primaryIncident)}</p>
                    <SeverityBadge severity={primaryIncident.severity} size="sm" className="shrink-0" />
                  </div>
                  <h3 className="mt-2 line-clamp-2 text-lg leading-snug font-semibold tracking-tight text-balance text-foreground">{primaryIncident.title}</h3>
                </div>

                <dl className="grid grid-cols-3 divide-x divide-border rounded-xl border border-border bg-foreground/2">
                  <Fact label="Risk score" value={incidentRiskLabel(primaryIncident.riskScore)} muted={primaryIncident.riskScore == null} />
                  <Fact label="Stage" value={formatLifecycleState(String(primaryIncident.lifecycle))} />
                  <Fact label="Asset" value={primaryIncident.asset?.name ?? primaryIncident.asset?.id ?? 'None linked'} muted={!primaryIncident.asset} />
                </dl>

                <section aria-labelledby="cc-recommendation" className="relative overflow-hidden rounded-xl border border-primary/20 bg-primary/6 py-3.5 pr-4 pl-5">
                  <span aria-hidden className="absolute inset-y-0 left-0 w-0.75 bg-primary/70" />
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 id="cc-recommendation" className="flex items-center gap-2 text-xs font-semibold text-primary">
                      <ClipboardCheck className="size-3.5" aria-hidden />
                      Recommended action
                    </h4>
                    {recommendedAction && (
                      <span className="inline-flex rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 font-mono text-[11px] text-primary">
                        {recommendedAction}
                      </span>
                    )}
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-foreground/90">
                    {recommendationText ?? 'No recommendation has been recorded for this incident yet.'}
                  </p>
                </section>

                <section aria-labelledby="cc-rationale">
                  <h4 id="cc-rationale" className="flex items-center gap-2 text-xs font-semibold text-muted-foreground">
                    <FileSearch className="size-3.5" aria-hidden />
                    Decision rationale
                  </h4>
                  <p className="mt-1.5 line-clamp-4 text-sm leading-relaxed text-muted-foreground" title={evidenceText ?? undefined}>
                    {evidenceText ?? 'No decision rationale has been recorded for this incident yet.'}
                  </p>
                </section>

                <div className="mt-auto pt-1">
                  <Button asChild variant="outline" className="rounded-full border-primary/30 px-4 text-primary hover:border-primary/60 hover:bg-primary/10 hover:text-primary">
                    <Link to={ROUTES.incident(primaryIncident.id)}>
                      Open incident
                      <ArrowRight className="cc-arrow" aria-hidden />
                    </Link>
                  </Button>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>

      <LifecyclePanel startDelay={260} />

      <div className={cn('grid items-start gap-5', SPLIT)}>
        <div className="min-w-0 space-y-5">
          <div className="cc-rise min-w-0 space-y-3" style={delay(340)} data-guide-target="incident-queue">
            {incidents.error ? (
              <Panel title="Prioritised incidents" className="cc-card rounded-2xl">
                <ErrorState onRetry={incidents.reload} />
              </Panel>
            ) : (
              <PrioritizedIncidentsPanel incidents={queue} bySeverity={stats.data?.incidentsBySeverity} />
            )}
            {unsupportedNotice && (
              <p role="status" className="flex items-start gap-2 rounded-xl border border-medium/30 bg-medium/8 px-3.5 py-2.5 text-xs text-medium">
                <Info className="mt-px size-3.5 shrink-0" aria-hidden />
                {unsupportedNotice}
              </p>
            )}
          </div>

          <Panel
            title="Recent security activity"
            description="Events returned by the API, with direct links to correlated incidents"
            flush
            className="cc-card cc-rise rounded-2xl"
            style={delay(440)}
          >
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
        </div>

        <div className="cc-rise space-y-5" style={delay(400)}>
          <Panel title="Mission status" description={USE_MOCKS ? 'Demo health data.' : 'Health reported by the backend.'} className="cc-card rounded-2xl">
            <div className="space-y-2.5 text-sm">
              {USE_MOCKS ? (stats.data?.systemHealth ?? []).slice(0, 4).map((component) => (
                <HealthRow
                  key={component.component}
                  name={component.name}
                  detail={component.message ?? 'Demo health data'}
                  status={component.status}
                  tone={severityTone[component.status === 'HEALTHY' ? 'LOW' : component.status === 'DEGRADED' ? 'MEDIUM' : 'CRITICAL']}
                />
              )) : (
                <HealthRow
                  name="Database"
                  detail={databaseHealth.data?.service ?? 'Backend database health check'}
                  status={databaseHealth.loading ? 'Loading' : databaseHealth.data?.database ?? 'Unavailable'}
                  tone={databaseHealth.data?.status === 'healthy' ? 'low' : databaseHealth.data ? 'critical' : 'neutral'}
                />
              )}
            </div>
          </Panel>

          {USE_MOCKS ? (
            <Panel title="Demo-only enrichment" description="Mock analytics are kept separate from the posture above." className="cc-card rounded-2xl">
              <p className="text-sm leading-relaxed text-muted-foreground">Additional risk history, asset context and ATT&CK activity from the mock data set are in the section below.</p>
            </Panel>
          ) : (
            <Panel title="Not returned by the current API" description="These signals are not estimated or filled with demo values." className="cc-card rounded-2xl">
              <dl className="divide-y divide-border text-[13px]">
                <Availability label="Risk drivers (risk history is now shown in the trend below)" />
                <Availability label="ATT&CK activity" />
                <Availability label="Asset risk scores" />
              </dl>
            </Panel>
          )}
        </div>
      </div>

      {/* Live risk history: reconstructed by the API from stored incident history (GET /dashboard/risk-trend). */}
      {!USE_MOCKS && (
        <div className="cc-rise" style={delay(460)}>
          <Suspense fallback={<Panel title="Average active incident risk trend" className="cc-card min-h-90 rounded-2xl"><LoadingState variant="inline" label="Loading chart…" /></Panel>}>
            <RiskTrendPanel live className="cc-card rounded-2xl" />
          </Suspense>
        </div>
      )}

      {USE_MOCKS && (
        <Disclosure label="Open demo-only dashboard enrichment" hint="Mock data · not live telemetry">
          <div className="grid items-start gap-4 pt-4 xl:grid-cols-2">
            <AssetRiskPanel assets={demoAssets.data} />
            <Suspense fallback={<Panel title="Risk trend" className="h-full min-h-90"><LoadingState variant="inline" label="Loading chart…" /></Panel>}>
              <RiskTrendPanel />
            </Suspense>
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
    </PageContainer>
  )
}

function CardHeading({ eyebrow, title, titleId, aside }: { eyebrow: string; title: string; titleId: string; aside?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border/70 px-5 py-4 sm:px-6">
      <div className="min-w-0">
        <p className="eyebrow text-primary/85">{eyebrow}</p>
        <h2 id={titleId} className="mt-1.5 text-lg font-semibold tracking-tight text-foreground">{title}</h2>
      </div>
      {aside}
    </div>
  )
}

function SourceChip() {
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-primary/25 bg-primary/8 px-2.5 py-1 text-[11px] font-medium text-primary">
      <span aria-hidden className="size-1.5 rounded-full bg-primary" />
      {USE_MOCKS ? 'Demo data' : 'Live API'}
    </span>
  )
}

const METRIC_ACCENT: Record<'critical' | 'low' | 'accent' | 'neutral' | 'high', string> = {
  critical: 'bg-critical',
  low: 'bg-low',
  accent: 'bg-primary',
  neutral: 'bg-muted-foreground/50',
  high: 'bg-high',
}

/** Neutral tile; tone is carried by a small marker only, so the figures stay the focus. */
function MetricTile({ label, value, hint, tone, style }: { label: string; value: string; hint?: string; tone: keyof typeof METRIC_ACCENT; style?: React.CSSProperties }) {
  const unavailable = value === 'Unavailable'

  return (
    <div
      className="cc-tile cc-rise flex items-center justify-between gap-4 rounded-xl border border-border bg-foreground/2 px-4 py-3.5 @lg:block"
      style={style}
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <span aria-hidden className={cn('size-1.5 shrink-0 rounded-full', METRIC_ACCENT[tone])} />
          {label}
        </div>
        {hint && <div className="mt-1 text-[11px] leading-snug text-muted-foreground/85 @lg:hidden">{hint}</div>}
      </div>
      <div className={cn('shrink-0 @lg:mt-3', unavailable ? 'text-sm font-medium text-muted-foreground' : 'metric text-[1.75rem] text-foreground')}>{value}</div>
      {hint && <div className="mt-2 hidden text-[11px] leading-snug text-muted-foreground/85 @lg:block">{hint}</div>}
    </div>
  )
}

function RiskFactorRow({ factor, style }: { factor: { key: string; label: string; contribution: number; weight: number }; style?: React.CSSProperties }) {
  const percent = Math.min(100, Math.max(0, (factor.contribution / (factor.weight * 100)) * 100))

  return (
    <li className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-2">
      <span className="truncate text-xs text-muted-foreground">{factor.label}</span>
      <span className="font-mono text-xs text-foreground/90 tabular-nums">{factor.contribution.toFixed(1)}</span>
      <div className="col-span-2 h-1.5 overflow-hidden rounded-full bg-foreground/6">
        <div className="cc-grow h-full rounded-full bg-linear-to-r from-primary via-violet to-cyan" style={{ ...style, width: `${percent}%` }} />
      </div>
    </li>
  )
}

function Fact({ label, value, muted }: { label: string; value: string; muted?: boolean }) {
  return (
    <div className="min-w-0 px-3.5 py-3">
      <dt className="text-[11px] font-medium text-muted-foreground">{label}</dt>
      <dd className={cn('mt-1 truncate text-sm font-semibold', muted ? 'text-muted-foreground' : 'text-foreground')} title={value}>
        {value}
      </dd>
    </div>
  )
}

function HealthRow({ name, detail, status, tone }: { name: string; detail: string; status: string; tone: Tone }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-foreground/2 px-3.5 py-3">
      <div className="flex min-w-0 items-center gap-3">
        <StatusDot tone={tone} />
        <div className="min-w-0">
          <div className="font-medium text-foreground">{name}</div>
          <div className="truncate text-xs text-muted-foreground">{detail}</div>
        </div>
      </div>
      <span className={cn('inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-semibold', toneStyles[tone].soft, toneStyles[tone].border, toneStyles[tone].text)}>{status}</span>
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
