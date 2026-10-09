import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronRight, ClipboardCheck, Play, ServerOff, Timer } from 'lucide-react'
import { toast } from 'sonner'
import type { AssessmentGrade, AssetInventoryItem, BackendAssessmentPage, BackendAssessmentSummary } from '@/api/types'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  Pagination,
  Panel,
  SelectFilter,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useQuery } from '@/hooks/useQuery'
import { GRADE_TONE } from '@/lib/assessment'
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

// Asset · Grade/score · Findings · Assessed
const COLS = 'lg:grid-cols-[minmax(0,1.6fr)_120px_minmax(0,1fr)_150px_16px]'

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
  // Unfiltered newest snapshot for the summary strip.
  const latest = useQuery('assessments-latest', () => assessmentService.list({ page: 1, pageSize: 1 }))

  const selectedId = params.get('assessment')
  const openAssessment = (id: string | null) => updateParams({ assessment: id })
  const filtered = assetFilter !== 'ALL' || gradeFilter !== 'ALL'
  const assetOptions = (assets.data ?? []).map((asset) => ({ value: asset.id, label: asset.name }))
  // A filter from a shared link can name an asset that is no longer registered; keep it selectable.
  if (assets.data && assetFilter !== 'ALL' && !assetOptions.some((option) => option.value === assetFilter)) {
    assetOptions.push({ value: assetFilter, label: 'Asset no longer registered' })
  }

  return (
    <PageContainer>
      <PageHeader eyebrow="Intelligence" title="Security Assessment" description={DESCRIPTION} />

      <MetricStrip metrics={summaryMetrics(latest.data, latest.error)} />

      <RunAssessmentPanel assets={assets.data} assetsError={assets.error} onRetryAssets={assets.reload} onAssessed={openAssessment} />

      <Panel
        title="Assessment history"
        description="Append-only snapshots, newest first · open one for findings, evidence and recommendations"
        flush
        actions={
          <div className="flex flex-wrap justify-end gap-2 max-sm:hidden">
            <SelectFilter
              label="Asset"
              value={assetFilter}
              onChange={setAssetFilter}
              options={[{ value: 'ALL', label: 'All assets' }, ...assetOptions]}
              className="max-w-56"
            />
            <SelectFilter
              label="Grade"
              value={gradeFilter}
              onChange={setGradeFilter}
              options={[{ value: 'ALL' as const, label: 'All' }, ...GRADES.map((grade) => ({ value: grade, label: grade }))]}
            />
          </div>
        }
      >
        <div className="flex flex-wrap gap-2 px-5 pb-3 sm:hidden">
          <SelectFilter
            label="Asset"
            value={assetFilter}
            onChange={setAssetFilter}
            options={[{ value: 'ALL', label: 'All assets' }, ...assetOptions]}
            className="w-full"
          />
          <SelectFilter
            label="Grade"
            value={gradeFilter}
            onChange={setGradeFilter}
            options={[{ value: 'ALL' as const, label: 'All' }, ...GRADES.map((grade) => ({ value: grade, label: grade }))]}
            className="w-full"
          />
        </div>

        {history.error ? (
          <RequestError error={history.error} title="Assessment history unavailable" onRetry={history.reload} />
        ) : !history.data ? (
          <LoadingState className="px-5 pt-1" count={5} label="Loading assessment history…" />
        ) : history.data.items.length === 0 ? (
          <EmptyState
            icon={ClipboardCheck}
            title={filtered ? 'No assessments match' : 'No assessments yet'}
            description={filtered ? 'Adjust the asset or grade filter.' : 'Choose an asset above and run its first assessment.'}
          />
        ) : (
          <>
            <div className={cn('hidden gap-4 border-y border-border px-5 py-2.5 text-[11px] font-medium text-muted-foreground lg:grid', COLS)}>
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

function summaryMetrics(data: BackendAssessmentPage | undefined, error: Error | undefined) {
  const newest = data?.items[0]
  const unavailable = error || !data
  return [
    { label: 'Assessments recorded', value: unavailable ? '—' : data.total, hint: 'stored snapshots across all assets' },
    {
      label: 'Latest grade',
      value: newest ? newest.grade : '—',
      valueClassName: newest ? toneStyles[GRADE_TONE[newest.grade]].text : undefined,
      hint: newest ? `${newest.score}/100 · ${newest.asset?.name ?? newest.assetKey}` : 'no assessment recorded',
    },
    {
      label: 'Last assessed',
      value: newest ? timeAgo(newest.asOf) : '—',
      hint: newest ? `${formatDateTime(newest.asOf)} UTC` : error ? 'history request failed' : 'no assessment recorded',
    },
    { label: 'Methodology', value: newest ? newest.methodologyVersion : '—', valueClassName: 'font-mono text-lg', hint: 'version used by the latest run' },
  ]
}

function RunAssessmentPanel({ assets, assetsError, onRetryAssets, onAssessed }: {
  assets: AssetInventoryItem[] | undefined
  assetsError: Error | undefined
  onRetryAssets: () => void
  onAssessed: (id: string) => void
}) {
  const [assetId, setAssetId] = useState<string>('')
  const [running, setRunning] = useState(false)
  const [rateLimited, setRateLimited] = useState(false)

  async function run() {
    if (!assetId) return
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
    <Panel title="Run assessment" description="Assess one registered asset against the current assessment methodology">
      {assetsError ? (
        <RequestError error={assetsError} title="Assets unavailable" onRetry={onRetryAssets} />
      ) : (
        <div className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Select value={assetId} onValueChange={setAssetId} disabled={!assets || assets.length === 0 || running}>
              <SelectTrigger className="h-9 w-full sm:w-80" aria-label="Asset to assess">
                <SelectValue placeholder={!assets ? 'Loading assets…' : assets.length === 0 ? 'No registered assets' : 'Choose an asset'} />
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
            <Button onClick={run} disabled={!assetId || running} className="sm:w-auto">
              <Play /> {running ? 'Assessing…' : 'Run assessment'}
            </Button>
          </div>
          {rateLimited && (
            <p role="status" className="flex items-center gap-2 rounded-md border border-medium/25 bg-medium/10 px-3 py-2 text-xs text-medium">
              <Timer className="size-3.5 shrink-0" />
              Assessment rate limit reached (10 runs per minute). Wait a minute, then run it again.
            </p>
          )}
          <p className="text-xs leading-relaxed text-muted-foreground">
            Uses only evidence already in NETRA: the asset record, its vulnerabilities and incidents, its security events
            from the last 7 days and active IP threat indicators. No network scanning is performed, and no events,
            incidents or response actions are created.
          </p>
        </div>
      )}
    </Panel>
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
          'group grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1.5 px-5 py-3 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6',
          COLS,
          active && 'bg-primary/6',
        )}
      >
        <div className="min-w-0">
          <div className="truncate text-[13px] font-medium">{a.asset?.name ?? a.assetKey}</div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
            {a.assetKey} · {a.methodologyVersion}
          </div>
        </div>
        <div className="flex items-center gap-2 max-lg:col-start-2 max-lg:row-start-1">
          <span className={cn('grid size-7 place-items-center rounded-md border text-sm font-semibold', toneStyles[tone].text, toneStyles[tone].soft, toneStyles[tone].border)}>
            {a.grade}
          </span>
          <span className="font-mono text-[13px] tabular-nums">{a.score}<span className="text-muted-foreground">/100</span></span>
        </div>
        <div className="flex flex-wrap gap-1 max-lg:col-span-2">
          {a.failed > 0 && <ToneBadge tone="critical" size="sm">{a.failed} failed</ToneBadge>}
          {a.warnings > 0 && <ToneBadge tone="medium" size="sm">{a.warnings} warnings</ToneBadge>}
          {a.failed === 0 && a.warnings === 0 && <ToneBadge tone="low" size="sm">No issues</ToneBadge>}
        </div>
        <time dateTime={a.asOf} title={`${formatDateTime(a.asOf)} UTC`} className="text-[11px] text-muted-foreground max-lg:col-span-2">
          {formatDateTime(a.asOf)} UTC · {timeAgo(a.asOf)}
        </time>
        <ChevronRight className="size-4 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground max-lg:hidden" />
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
      <PageHeader eyebrow="Intelligence" title="Security Assessment" description={DESCRIPTION} />
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
