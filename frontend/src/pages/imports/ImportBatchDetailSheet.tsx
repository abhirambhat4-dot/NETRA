import { Link } from 'react-router-dom'
import type { BackendImportBatchDetail, ImportIssue } from '@/api/types'
import { DetailSection, DetailSheet, ErrorState, KeyValueList, LoadingState, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { describeImportOutcome, formatBytes, issueLocation } from '@/lib/datasetImport'
import { formatDateTime, formatNumber } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { importService } from '@/services'
import { HttpError } from '@/services/http'

export function ImportBatchDetailSheet({ batchId, onClose }: { batchId: string | null; onClose: () => void }) {
  const detail = useQuery(`import-detail-${batchId ?? 'none'}`, () =>
    batchId ? importService.get(batchId) : Promise.resolve(undefined),
  )
  const batch = detail.data?.id === batchId ? detail.data : undefined
  const error = detail.error
  const status = error instanceof HttpError ? error.status : undefined

  return (
    <DetailSheet
      open={!!batchId}
      onOpenChange={(open) => !open && onClose()}
      eyebrow={batch ? `${batch.datasetProfile} · v${batch.profileVersion}` : batchId ?? undefined}
      title={batch ? batch.originalFilename : detail.loading ? 'Loading import batch' : 'Import batch'}
      description={batch ? `Validated ${formatDateTime(batch.completedAt ?? batch.createdAt)} UTC` : undefined}
    >
      {error ? (
        <div>
          <ErrorState
            title={status === 401 ? 'Authentication required' : status === 404 ? 'Import batch not found' : 'Import batch unavailable'}
            message={status === 401 || status === 404 ? undefined : error.message}
            onRetry={status === 401 || status === 404 ? undefined : detail.reload}
          />
          {status === 401 && (
            <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
          )}
        </div>
      ) : !batch ? (
        <LoadingState variant="inline" label="Loading import batch…" />
      ) : (
        <Body key={batch.id} batch={batch} />
      )}
    </DetailSheet>
  )
}

function Body({ batch: b }: { batch: BackendImportBatchDetail }) {
  const outcome = describeImportOutcome(b)
  return (
    <>
      <div className="space-y-2">
        <ToneBadge tone={outcome.tone}>{outcome.label}</ToneBadge>
        <p className="text-xs text-muted-foreground">{outcome.summary}</p>
      </div>

      <DetailSection title="Rows">
        <RowCounts batch={b} />
      </DetailSection>

      <DetailSection title="Batch">
        <KeyValueList
          columns={2}
          items={[
            { label: 'File', value: <span title={b.originalFilename}>{b.originalFilename}</span> },
            { label: 'File size', value: formatBytes(b.fileSizeBytes) },
            { label: 'Profile', value: `${b.datasetProfile} · v${b.profileVersion}`, mono: true },
            { label: 'Status', value: b.status, mono: true },
            { label: 'Uploaded', value: `${formatDateTime(b.createdAt)} UTC` },
            { label: 'Completed', value: b.completedAt ? `${formatDateTime(b.completedAt)} UTC` : '—' },
          ]}
        />
        <div className="mt-3 min-w-0">
          <div className="text-[11px] text-muted-foreground">SHA-256</div>
          <div className="mt-0.5 font-mono text-[11px] break-all text-foreground/90">{b.fileSha256}</div>
        </div>
      </DetailSection>

      <DetailSection title="Validation issues">
        {b.errorTotal === 0 ? (
          <p className="text-xs text-muted-foreground">No issues found.</p>
        ) : (
          <>
            {b.errorSampleTruncated && (
              <p className="mb-2.5 text-xs text-muted-foreground">
                Showing the first {b.errorSample.length} of {formatNumber(b.errorTotal)} issues. NETRA stores a capped sample.
              </p>
            )}
            <IssueList issues={b.errorSample} />
          </>
        )}
      </DetailSection>

      <p className="text-[11px] leading-relaxed text-muted-foreground">
        Validation only: no rows from this file were stored, and nothing was added to Security Events, Incidents or
        Assessments. Issues name a row, a column and a rule, never cell contents.
      </p>
    </>
  )
}

export function RowCounts({ batch }: { batch: BackendImportBatchDetail }) {
  const items = [
    { label: 'Data rows', value: batch.totalRows, className: '' },
    { label: 'Accepted', value: batch.acceptedRows, className: 'text-low' },
    { label: 'Rejected', value: batch.rejectedRows, className: batch.rejectedRows > 0 ? 'text-critical' : '' },
    { label: 'Issues', value: batch.errorTotal, className: batch.errorTotal > 0 ? 'text-medium' : '' },
  ]
  return (
    <dl className="surface-inset grid grid-cols-2 gap-px overflow-hidden rounded-lg sm:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className="px-3.5 py-2.5">
          <dt className="text-[11px] text-muted-foreground">{item.label}</dt>
          <dd className={`mt-0.5 font-mono text-sm tabular-nums ${item.className}`}>{item.value.toLocaleString('en-US')}</dd>
        </div>
      ))}
    </dl>
  )
}

export function IssueList({ issues }: { issues: ImportIssue[] }) {
  return (
    <ul className="surface-inset divide-y divide-border/70 rounded-lg text-xs">
      {issues.map((issue, index) => (
        <li key={index} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 px-3.5 py-2">
          <span className="font-medium text-foreground/85">{issueLocation(issue)}</span>
          <span className="text-muted-foreground">{issue.message}</span>
          <span className="ml-auto font-mono text-[10px] text-muted-foreground/80">{issue.rule}</span>
        </li>
      ))}
    </ul>
  )
}
