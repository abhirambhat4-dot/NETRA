import { Link, useSearchParams } from 'react-router-dom'
import { ChevronRight, FileUp, ServerOff } from 'lucide-react'
import type { BackendImportBatchPage, BackendImportBatchSummary } from '@/api/types'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  Pagination,
  Panel,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { MAX_ROWS, MAX_UPLOAD_BYTES, describeImportOutcome, formatBytes } from '@/lib/datasetImport'
import { formatDateTime, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { importService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { ImportBatchDetailSheet } from './imports/ImportBatchDetailSheet'
import { UploadPanel } from './imports/UploadPanel'

const DESCRIPTION = 'Validate security dataset CSV files before they enter NETRA. Each upload is recorded as an import batch.'
const PAGE_SIZE = 10

// File · Result · Rows · Uploaded
const COLS = 'lg:grid-cols-[minmax(0,1.6fr)_170px_minmax(0,1fr)_150px_16px]'

export function DatasetImportPage() {
  return USE_MOCKS ? <ImportUnavailable /> : <LiveDatasetImportPage />
}

function LiveDatasetImportPage() {
  const [params, setParams] = useSearchParams()
  const pageParam = Number(params.get('page'))
  const page = Number.isInteger(pageParam) && pageParam > 1 ? pageParam : 1
  const selectedId = params.get('batch')
  const updateParams = (changes: Record<string, string | null>) => {
    // Start from the live URL so two quick changes do not overwrite each other.
    const next = new URLSearchParams(window.location.search)
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) next.delete(key)
      else next.set(key, value)
    }
    setParams(next, { replace: true })
  }
  const setPage = (value: number) => updateParams({ page: value > 1 ? String(value) : null })
  const openBatch = (id: string | null) => updateParams({ batch: id })

  const history = useQuery(`imports-${page}`, () => importService.list({ page, pageSize: PAGE_SIZE }))
  const latest = useQuery('imports-latest', () => importService.list({ page: 1, pageSize: 1 }))

  return (
    <PageContainer>
      <PageHeader icon={FileUp} eyebrow="Intake" title="Dataset Import" description={DESCRIPTION} />

      <MetricStrip metrics={summaryMetrics(latest.data, latest.error)} />

      <UploadPanel onOpenBatch={openBatch} />

      <Panel title="Import history" description="Your import batches, newest first · open one for its validation report" flush>
        {history.error ? (
          <RequestError error={history.error} onRetry={history.reload} />
        ) : !history.data ? (
          <LoadingState className="px-5 pt-1" count={4} label="Loading import history…" />
        ) : history.data.items.length === 0 ? (
          <EmptyState
            icon={FileUp}
            title={history.data.total > 0 ? 'No batches on this page' : 'No imports yet'}
            description={
              history.data.total > 0
                ? 'This page is past the end of your import history.'
                : 'Validate a CSV file above. Each upload, validated or rejected, is recorded here with its report.'
            }
            action={history.data.total > 0 ? <Button variant="outline" size="sm" onClick={() => setPage(1)}>First page</Button> : undefined}
          />
        ) : (
          <>
            <div className={cn('app-table-head hidden gap-4 border-y border-border px-5 py-2.5 lg:grid', COLS)}>
              <span>File</span>
              <span>Result</span>
              <span>Rows</span>
              <span>Uploaded</span>
              <span />
            </div>
            <ul className="max-lg:border-t max-lg:border-border">
              {history.data.items.map((item, index) => (
                <BatchRow key={item.id} batch={item} entryIndex={index} active={item.id === selectedId} onOpen={() => openBatch(item.id)} />
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

      <ImportBatchDetailSheet batchId={selectedId} onClose={() => openBatch(null)} />
    </PageContainer>
  )
}

function summaryMetrics(data: BackendImportBatchPage | undefined, error: Error | undefined) {
  const newest = data?.items[0]
  const outcome = newest ? describeImportOutcome(newest) : undefined
  return [
    { label: 'Import batches', value: error || !data ? '—' : data.total, hint: 'your recorded uploads' },
    {
      label: 'Latest result',
      value: outcome ? outcome.label : '—',
      valueClassName: outcome ? cn('text-lg', toneStyles[outcome.tone].text) : undefined,
      hint: newest ? newest.originalFilename : error ? 'history request failed' : 'no upload recorded',
    },
    {
      label: 'Last upload',
      value: newest ? timeAgo(newest.createdAt) : '—',
      hint: newest ? `${formatDateTime(newest.createdAt)} UTC` : 'no upload recorded',
    },
    {
      label: 'Upload limits',
      value: formatBytes(MAX_UPLOAD_BYTES),
      valueClassName: 'text-lg',
      hint: `${MAX_ROWS.toLocaleString('en-US')} data rows per file · default API limits`,
    },
  ]
}

function BatchRow({ batch: b, entryIndex, active, onOpen }: {
  batch: BackendImportBatchSummary
  entryIndex: number
  active: boolean
  onOpen: () => void
}) {
  const outcome = describeImportOutcome(b)
  return (
    <li
      className="border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1"
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 35}ms` }}
    >
      <button
        type="button"
        onClick={onOpen}
        aria-label={`${b.originalFilename}, ${outcome.label} — open import batch`}
        className={cn(
          'group grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1.5 px-5 py-3 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6',
          COLS,
          active && 'bg-primary/6',
        )}
      >
        <div className="min-w-0">
          <div className="truncate text-[13px] font-medium" title={b.originalFilename}>{b.originalFilename}</div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
            {b.datasetProfile} · v{b.profileVersion} · {formatBytes(b.fileSizeBytes)}
          </div>
        </div>
        <div className="max-lg:col-start-2 max-lg:row-start-1">
          <ToneBadge tone={outcome.tone} size="sm">{outcome.label}</ToneBadge>
        </div>
        <div className="text-[11px] text-muted-foreground max-lg:col-span-2">
          <span className="font-mono text-foreground/85">{b.acceptedRows.toLocaleString('en-US')}</span> of{' '}
          <span className="font-mono text-foreground/85">{b.totalRows.toLocaleString('en-US')}</span> accepted
          {b.errorTotal > 0 && <> · {b.errorTotal.toLocaleString('en-US')} issue{b.errorTotal === 1 ? '' : 's'}</>}
          {(b.eventsCreated ?? 0) > 0 && <> · {b.eventsCreated.toLocaleString('en-US')} stored as events</>}
        </div>
        <time dateTime={b.createdAt} title={`${formatDateTime(b.createdAt)} UTC`} className="text-[11px] text-muted-foreground max-lg:col-span-2">
          {formatDateTime(b.createdAt)} UTC · {timeAgo(b.createdAt)}
        </time>
        <ChevronRight className="size-4 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground max-lg:hidden" />
      </button>
    </li>
  )
}

function RequestError({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const unauthorized = error instanceof HttpError && error.status === 401
  return (
    <div>
      <ErrorState
        title={unauthorized ? 'Authentication required' : 'Import history unavailable'}
        message={unauthorized ? undefined : error.message}
        onRetry={unauthorized ? undefined : onRetry}
      />
      {unauthorized && (
        <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
      )}
    </div>
  )
}

function ImportUnavailable() {
  return (
    <PageContainer>
      <PageHeader icon={FileUp} eyebrow="Intake" title="Dataset Import" description={DESCRIPTION} />
      <Panel title="Dataset Import" description="Validation-only CSV uploads">
        <EmptyState
          icon={ServerOff}
          title="Dataset import requires the NETRA API."
          description="Uploads are unavailable in demo mode. Imports are never simulated, because a fabricated validation result would be misleading. Run NETRA against the API to validate files."
        />
      </Panel>
    </PageContainer>
  )
}
