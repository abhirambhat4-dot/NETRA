import type * as React from 'react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import {
  Check,
  ChevronRight,
  ClipboardCheck,
  Clock,
  Database,
  FilterX,
  Loader2,
  Play,
  Server,
  ServerOff,
  ShieldCheck,
  Timer,
} from 'lucide-react'
import { toast } from 'sonner'
import type { AssessmentGrade, AssetInventoryItem, BackendAssessmentPage, BackendAssessmentSummary } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import {
  EmptyState,
  ErrorState,
  MeterBar,
  PageContainer,
  PageHeader,
  Pagination,
  Panel,
  SelectFilter,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useQuery } from '@/hooks/useQuery'
import { GRADE_TONE } from '@/lib/assessment'
import { permissionExplanation } from '@/lib/authorizationAccess'
import { formatDateTime, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assessmentService, assetInventoryService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { AssessmentDetailSheet } from './assessments/AssessmentDetailSheet'

const DESCRIPTION =
  'Deterministic, evidence-based assessment of registered assets using records already in NETRA. Each run is stored as a new snapshot.'
const PAGE_SIZE = 10
const GRADES: AssessmentGrade[] = ['A', 'B', 'C', 'D', 'F']
const ASSET_TRIGGER_ID = 'assessment-asset'

// Asset · Grade/score · Findings · Assessed
const COLS = 'lg:grid-cols-[minmax(0,1.6fr)_150px_minmax(0,1.1fr)_170px_16px]'

const EVIDENCE_SOURCES = [
  'The asset record and its registered services',
  'Its vulnerabilities and incidents',
  'Its security events from the last 7 days',
  'Active IP threat indicators',
]

export function SecurityAssessmentPage() {
  return USE_MOCKS ? <AssessmentUnavailable /> : <LiveSecurityAssessmentPage />
}

/** History filters and page live in the URL (with the open assessment), so reloads and shared links keep them. */
function historyState(params: URLSearchParams) {
  const grade = params.get('grade')
  const page = Number(params.get('page'))
  return {
    assetFilter: params.get('assetId') || 'ALL',
    gradeFilter: GRADES.includes(grade as AssessmentGrade) ? (grade as AssessmentGrade) : ('ALL' as const),
    page: Number.isInteger(page) && page > 1 ? page : 1,
  }
}

function LiveSecurityAssessmentPage() {
  const [params, setParams] = useSearchParams()
  const { assetFilter, gradeFilter, page } = historyState(params)
  const updateParams = (changes: Record<string, string | null>) => {
    // Start from the live URL, not the render-time `params`: router updates land in a transition, so a
    // quick second change would otherwise rebuild the query from stale values and drop the first one.
    const next = new URLSearchParams(window.location.search)
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) next.delete(key)
      else next.set(key, value)
    }
    setParams(next, { replace: true })
  }
  // Changing a filter returns to the first page.
  const setAssetFilter = (value: string) => updateParams({ assetId: value === 'ALL' ? null : value, page: null })
  const setGradeFilter = (value: AssessmentGrade | 'ALL') => updateParams({ grade: value === 'ALL' ? null : value, page: null })
  const clearFilters = () => updateParams({ assetId: null, grade: null, page: null })
  const setPage = (value: number) => updateParams({ page: value > 1 ? String(value) : null })

  const assets = useQuery('assessment-assets', () => assetInventoryService.list())
  const history = useQuery(`assessments-${assetFilter}-${gradeFilter}-${page}`, () =>
    assessmentService.list({
      page,
      pageSize: PAGE_SIZE,
      assetId: assetFilter === 'ALL' ? undefined : assetFilter,
      grade: gradeFilter === 'ALL' ? undefined : gradeFilter,
    }),
  )
  // Unfiltered newest snapshot for the summary cards.
  const latest = useQuery('assessments-latest', () => assessmentService.list({ page: 1, pageSize: 1 }))

  const selectedId = params.get('assessment')
  const openAssessment = (id: string | null) => updateParams({ assessment: id })
  const filtered = assetFilter !== 'ALL' || gradeFilter !== 'ALL'
  const assetOptions = (assets.data ?? []).map((asset) => ({ value: asset.id, label: asset.name }))
  // A filter from a shared link can name an asset that is no longer registered; keep it selectable.
  if (assets.data && assetFilter !== 'ALL' && !assetOptions.some((option) => option.value === assetFilter)) {
    assetOptions.push({ value: assetFilter, label: 'Asset no longer registered' })
  }

  const focusAssetPicker = () => {
    const trigger = document.getElementById(ASSET_TRIGGER_ID)
    trigger?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    trigger?.focus({ preventScroll: true })
  }

  const filters = (wide: boolean) => (
    <>
      <SelectFilter
        label="Asset"
        value={assetFilter}
        onChange={setAssetFilter}
        options={[{ value: 'ALL', label: 'All assets' }, ...assetOptions]}
        className={wide ? 'w-full' : 'max-w-60'}
      />
      <SelectFilter
        label="Grade"
        value={gradeFilter}
        onChange={setGradeFilter}
        options={[{ value: 'ALL' as const, label: 'All' }, ...GRADES.map((grade) => ({ value: grade, label: grade }))]}
        className={wide ? 'w-full' : 'min-w-32'}
      />
      {filtered && (
        <Button variant="ghost" size="sm" onClick={clearFilters} className="h-9 text-muted-foreground">
          <FilterX /> Clear
        </Button>
      )}
    </>
  )

  return (
    <PageContainer>
      <PageHeader
        icon={ClipboardCheck}
        eyebrow="Intelligence"
        title="Security Assessment"
        description={DESCRIPTION}
        actions={
          <span className="inline-flex h-8 items-center gap-1.5 rounded-full border border-border bg-card px-3 text-xs font-medium text-muted-foreground">
            <ShieldCheck className="size-3.5 text-low" /> Read-only · no network scanning
          </span>
        }
      />

      <SummaryCards latest={latest.data} latestError={latest.error} assets={assets.data} assetsError={assets.error} />

      <RunAssessmentPanel
        assets={assets.data}
        assetsError={assets.error}
        onRetryAssets={assets.reload}
        onAssessed={openAssessment}
        methodology={latest.data?.items[0]?.methodologyVersion}
      />

      <Panel
        title={
          <span className="inline-flex items-center gap-2">
            Assessment history
            {history.data && (
              <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-[11px] font-medium text-muted-foreground tabular-nums">
                {history.data.total}
              </span>
            )}
          </span>
        }
        description="Append-only snapshots, newest first. Open one for findings, evidence and recommendations."
        flush
        actions={<div className="flex flex-wrap items-center justify-end gap-2 max-md:hidden">{filters(false)}</div>}
      >
        <div className="grid grid-cols-2 gap-2 px-5 pb-4 md:hidden">{filters(true)}</div>

        {history.error ? (
          <RequestError error={history.error} title="Assessment history unavailable" onRetry={history.reload} />
        ) : !history.data ? (
          <HistorySkeleton />
        ) : history.data.items.length === 0 ? (
          <div className="border-t border-border">
            <EmptyState
              icon={ClipboardCheck}
              title={filtered ? 'No assessments match these filters' : 'No assessments recorded yet'}
              description={
                filtered
                  ? 'No stored snapshot matches the selected asset and grade.'
                  : 'Assessments appear here after the first run. Choose a registered asset above to create one.'
              }
              action={
                filtered ? (
                  <Button variant="outline" size="sm" onClick={clearFilters}><FilterX /> Clear filters</Button>
                ) : assets.data && assets.data.length > 0 ? (
                  <Button size="sm" onClick={focusAssetPicker}><Play /> Choose an asset</Button>
                ) : undefined
              }
            />
          </div>
        ) : (
          <>
            <div className={cn('app-table-head hidden gap-4 border-y border-border px-5 py-2.5 lg:grid', COLS)}>
              <span>Asset</span>
              <span>Grade · score</span>
              <span>Findings</span>
              <span>Evidence as of</span>
              <span />
            </div>
            <ul className="max-lg:border-t max-lg:border-border">
              {history.data.items.map((item, index) => (
                <AssessmentRow
                  key={item.id}
                  assessment={item}
                  entryIndex={index}
                  active={item.id === selectedId}
                  onOpen={() => openAssessment(item.id)}
                />
              ))}
            </ul>
            {history.data.total > PAGE_SIZE && (
              <div className="border-t border-border">
                <Pagination page={page} pageSize={PAGE_SIZE} total={history.data.total} onChange={setPage} />
              </div>
            )}
          </>
        )}
      </Panel>

      <AssessmentDetailSheet assessmentId={selectedId} onClose={() => openAssessment(null)} />
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

function SummaryCards({ latest, latestError, assets, assetsError }: {
  latest: BackendAssessmentPage | undefined
  latestError: Error | undefined
  assets: AssetInventoryItem[] | undefined
  assetsError: Error | undefined
}) {
  const newest = latest?.items[0]
  const historyHint = latestError ? 'history request failed' : !latest ? 'loading…' : 'no assessment recorded'
  return (
    <div className="grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 lg:gap-4 xl:grid-cols-4">
      <SummaryCard
        icon={Database}
        label="Assessments recorded"
        value={latest ? latest.total.toLocaleString('en-US') : '—'}
        hint={latest ? 'stored snapshots across all assets' : historyHint}
      />
      <SummaryCard
        icon={ClipboardCheck}
        label="Latest grade"
        value={
          newest ? (
            <span className="flex items-center gap-3">
              <GradeBadge grade={newest.grade} size="lg" />
              <span className="font-mono text-xl text-foreground tabular-nums">
                {newest.score}<span className="text-sm text-muted-foreground">/100</span>
              </span>
            </span>
          ) : '—'
        }
        hint={newest ? newest.asset?.name ?? newest.assetKey : historyHint}
      />
      <SummaryCard
        icon={Clock}
        label="Last assessed"
        value={newest ? timeAgo(newest.asOf) : '—'}
        hint={newest ? `${formatDateTime(newest.asOf)} UTC` : historyHint}
      />
      <SummaryCard
        icon={Server}
        label="Registered assets"
        value={assets ? assets.length.toLocaleString('en-US') : '—'}
        hint={assetsError ? 'asset list unavailable' : !assets ? 'loading…' : 'available to assess'}
      />
    </div>
  )
}

function SummaryCard({ icon: Icon, label, value, hint }: { icon: LucideIcon; label: string; value: React.ReactNode; hint: string }) {
  return (
    <div className="surface-panel flex min-w-0 flex-col rounded-xl px-5 py-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-[13px] font-medium text-muted-foreground">{label}</span>
        <span className="grid size-8 place-items-center rounded-lg bg-muted text-muted-foreground">
          <Icon className="size-4" />
        </span>
      </div>
      <div className="metric mt-2 flex min-h-10 items-center text-[1.75rem] text-foreground">{value}</div>
      <div className="mt-1.5 truncate text-xs text-muted-foreground" title={hint}>{hint}</div>
    </div>
  )
}

function GradeBadge({ grade, size = 'md' }: { grade: AssessmentGrade; size?: 'md' | 'lg' }) {
  const tone = toneStyles[GRADE_TONE[grade]]
  return (
    <span
      className={cn(
        'grid shrink-0 place-items-center rounded-lg border font-semibold',
        size === 'lg' ? 'size-10 text-xl' : 'size-8 text-[15px]',
        tone.text,
        tone.soft,
        tone.border,
      )}
      aria-label={`Grade ${grade}`}
    >
      {grade}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Run assessment
// ---------------------------------------------------------------------------

function RunAssessmentPanel({ assets, assetsError, onRetryAssets, onAssessed, methodology }: {
  assets: AssetInventoryItem[] | undefined
  assetsError: Error | undefined
  onRetryAssets: () => void
  onAssessed: (id: string) => void
  methodology: string | undefined
}) {
  const [assetId, setAssetId] = useState<string>('')
  const [running, setRunning] = useState(false)
  const [rateLimited, setRateLimited] = useState(false)
  const selected = assets?.find((asset) => asset.id === assetId)
  // Presentation only: the API enforces the role, and answers 403 for a role that is not recognised.
  const roleBlocked = permissionExplanation(useAuth().user, 'workflow', 'Running assessments')

  async function run() {
    if (!assetId || roleBlocked) return
    setRunning(true)
    setRateLimited(false)
    try {
      const result = await assessmentService.run(assetId)
      toast.success(`Assessment stored · grade ${result.grade} (${result.score}/100)`)
      onAssessed(result.id)
    } catch (e) {
      if (e instanceof HttpError && e.status === 429) setRateLimited(true)
      toast.error(e instanceof Error ? e.message : 'Assessment failed')
    } finally {
      setRunning(false)
    }
  }

  return (
    <section id="run-assessment" aria-labelledby="run-assessment-title" className="surface-panel relative overflow-hidden rounded-xl">
      <span aria-hidden className="absolute inset-x-0 top-0 h-[3px] bg-linear-to-r from-primary via-primary/70 to-cyan/60" />
      <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="p-5 sm:p-6">
          <div className="flex items-start gap-3.5">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary text-primary-foreground shadow-sm">
              <Play className="size-4.5" />
            </span>
            <div className="min-w-0">
              <h2 id="run-assessment-title" className="text-base font-semibold tracking-tight text-foreground">Run an assessment</h2>
              <p className="mt-1 text-[13px] leading-relaxed text-muted-foreground">
                Assess one registered asset against the current assessment methodology. The result is stored as a new snapshot and opens automatically.
              </p>
            </div>
          </div>

          <div className="mt-5">
            {assetsError ? (
              <RequestError error={assetsError} title="Assets unavailable" onRetry={onRetryAssets} />
            ) : (
              <div className="space-y-3">
                <Label htmlFor={ASSET_TRIGGER_ID} className="text-[13px] font-medium text-foreground">Asset</Label>
                <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center">
                  <Select value={assetId} onValueChange={setAssetId} disabled={!assets || assets.length === 0 || running}>
                    <SelectTrigger id={ASSET_TRIGGER_ID} className="h-10! w-full bg-card sm:max-w-md" aria-label="Asset to assess">
                      <SelectValue placeholder={!assets ? 'Loading assets…' : assets.length === 0 ? 'No registered assets' : 'Choose an asset to assess'} />
                    </SelectTrigger>
                    <SelectContent>
                      {(assets ?? []).map((asset) => (
                        <SelectItem key={asset.id} value={asset.id}>
                          {asset.name}
                          <span className="font-mono text-[11px] text-muted-foreground">{asset.assetKey ?? asset.hostname}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button onClick={run} disabled={!assetId || running || !!roleBlocked} className="h-10 px-4 sm:w-auto">
                    {running ? <Loader2 className="animate-spin" /> : <Play />}
                    {running ? 'Assessing…' : 'Run assessment'}
                  </Button>
                </div>

                <p className="text-xs text-muted-foreground">
                  {selected ? (
                    <>
                      Selected <span className="font-medium text-foreground">{selected.name}</span>
                      {(selected.assetKey ?? selected.hostname) && <> · <span className="font-mono">{selected.assetKey ?? selected.hostname}</span></>}
                      {selected.criticality && <> · {selected.criticality.toLowerCase()} criticality</>}
                    </>
                  ) : assets && assets.length === 0 ? (
                    <>Register an asset first. <Link to={ROUTES.assets} className="font-medium text-primary hover:underline">Open Assets</Link></>
                  ) : (
                    'Runs are limited to 10 per minute.'
                  )}
                </p>

                {roleBlocked && <p role="note" className="text-xs text-muted-foreground">{roleBlocked}</p>}

                {rateLimited && (
                  <p role="status" className="flex items-center gap-2 rounded-lg border border-medium/25 bg-medium/10 px-3 py-2 text-xs text-medium">
                    <Timer className="size-3.5 shrink-0" />
                    Assessment rate limit reached (10 runs per minute). Wait a minute, then run it again.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        <aside className="border-t border-border bg-muted/50 p-5 sm:p-6 lg:border-t-0 lg:border-l">
          <h3 className="text-[11px] font-semibold tracking-[0.08em] text-muted-foreground uppercase">Evidence used</h3>
          <ul className="mt-3 space-y-2">
            {EVIDENCE_SOURCES.map((source) => (
              <li key={source} className="flex items-start gap-2 text-[13px] text-foreground">
                <Check className="mt-0.5 size-3.5 shrink-0 text-low" />
                {source}
              </li>
            ))}
          </ul>
          <p className="mt-4 border-t border-border pt-3 text-xs leading-relaxed text-muted-foreground">
            Uses only evidence already in NETRA. No network scanning is performed, and no events, incidents or response actions are created.
          </p>
          {methodology && (
            <p className="mt-2 text-xs text-muted-foreground">
              Latest run used methodology <span className="font-mono text-foreground">{methodology}</span>
            </p>
          )}
        </aside>
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

function HistorySkeleton() {
  return (
    <div role="status" aria-label="Loading assessment history…" className="border-t border-border">
      {Array.from({ length: 5 }, (_, i) => (
        <div key={i} className={cn('grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-border/70 px-5 py-3.5 last:border-b-0', COLS)}>
          <div className="flex items-center gap-3">
            <Skeleton className="size-9 rounded-lg" />
            <div className="space-y-1.5">
              <Skeleton className="h-3.5 w-36" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
          <Skeleton className="h-8 w-24" />
          <Skeleton className="hidden h-5 w-32 lg:block" />
          <Skeleton className="hidden h-3.5 w-28 lg:block" />
          <span className="hidden lg:block" />
        </div>
      ))}
    </div>
  )
}

function AssessmentRow({ assessment: a, entryIndex, active, onOpen }: {
  assessment: BackendAssessmentSummary
  entryIndex: number
  active: boolean
  onOpen: () => void
}) {
  const tone = GRADE_TONE[a.grade]
  return (
    <li
      className="border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1"
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 35}ms` }}
    >
      <button
        type="button"
        onClick={onOpen}
        aria-label={`${a.asset?.name ?? a.assetKey}, grade ${a.grade}, score ${a.score} — open assessment`}
        className={cn(
          'group relative grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 px-5 py-3.5 text-left transition-colors outline-none hover:bg-muted/60 focus-visible:bg-primary/5',
          COLS,
          active && 'bg-primary/5 shadow-[inset_3px_0_0_var(--primary)]',
        )}
      >
        <div className="flex min-w-0 items-center gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-border bg-muted/60 text-muted-foreground">
            <Server className="size-4" />
          </span>
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold text-foreground">{a.asset?.name ?? a.assetKey}</div>
            <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
              {a.assetKey} · {a.methodologyVersion}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2.5 max-lg:col-start-2 max-lg:row-start-1">
          <GradeBadge grade={a.grade} />
          <div className="w-16">
            <div className="font-mono text-[13px] font-medium text-foreground tabular-nums">
              {a.score}<span className="text-muted-foreground">/100</span>
            </div>
            <MeterBar value={a.score} tone={tone} className="mt-1 h-1" />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 max-lg:col-span-2">
          {a.failed > 0 && <ToneBadge tone="critical" size="sm">{a.failed} failed</ToneBadge>}
          {a.warnings > 0 && <ToneBadge tone="medium" size="sm">{a.warnings} warnings</ToneBadge>}
          {a.failed === 0 && a.warnings === 0 && <ToneBadge tone="low" size="sm">No issues</ToneBadge>}
          {a.passed > 0 && <span className="text-[11px] text-muted-foreground">{a.passed} passed</span>}
        </div>
        <time dateTime={a.asOf} title={`${formatDateTime(a.asOf)} UTC`} className="text-xs leading-tight max-lg:col-span-2 max-lg:text-muted-foreground">
          <span className="text-foreground max-lg:text-muted-foreground">{formatDateTime(a.asOf)} UTC</span>
          <span className="text-muted-foreground lg:mt-0.5 lg:block"><span className="lg:hidden"> · </span>{timeAgo(a.asOf)}</span>
        </time>
        <ChevronRight className="size-4 text-muted-foreground/50 transition-all group-hover:translate-x-0.5 group-hover:text-primary max-lg:hidden" />
      </button>
    </li>
  )
}

function RequestError({ error, title, onRetry }: { error: Error; title: string; onRetry: () => void }) {
  const unauthorized = error instanceof HttpError && error.status === 401
  return (
    <div>
      <ErrorState
        title={unauthorized ? 'Authentication required' : title}
        message={unauthorized ? undefined : error.message}
        onRetry={unauthorized ? undefined : onRetry}
      />
      {unauthorized && (
        <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
      )}
    </div>
  )
}

function AssessmentUnavailable() {
  return (
    <PageContainer>
      <PageHeader icon={ClipboardCheck} eyebrow="Intelligence" title="Security Assessment" description={DESCRIPTION} />
      <Panel title="Security Assessment" description="Evidence-based asset assessment">
        <EmptyState
          icon={ServerOff}
          title="Security Assessment requires the NETRA API."
          description="Live assessment runs are unavailable in demo mode. Assessments are never simulated, because fabricated findings would be misleading. Run NETRA against the API to assess assets."
        />
      </Panel>
    </PageContainer>
  )
}
