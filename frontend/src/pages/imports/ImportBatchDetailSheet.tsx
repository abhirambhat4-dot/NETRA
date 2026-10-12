import { Link } from 'react-router-dom'
import type { BackendImportBatchDetail, ImportIssue } from '@/api/types'
import { DetailSection, DetailSheet, ErrorState, KeyValueList, LoadingState, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import {
  delimiterLabel,
  describeCoverage,
  describeImportOutcome,
  describeStoredRows,
  formatBytes,
  issueLocation,
} from '@/lib/datasetImport'
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

      {b.normalization?.fieldMapping && (
        <DetailSection title="Field mapping">
          <KeyValueList
            columns={2}
            items={[
              { label: 'Record type', value: b.normalization.recordType ?? '—', mono: true },
              { label: 'Timestamp format', value: b.normalization.timestampFormat ?? '—', mono: true },
              { label: 'Offset for zoneless times', value: `UTC${b.normalization.utcOffset ?? '+00:00'}`, mono: true },
              {
                label: 'File format',
                value: `${b.normalization.encoding ?? '—'} · ${delimiterLabel(b.normalization.delimiter ?? ',')}`,
              },
              ...Object.entries(b.normalization.fieldMapping).map(([field, column]) => ({
                label: field,
                value: <span title={column}>{column}</span>,
              })),
              ...(b.normalization.defaultEventType
                ? [{ label: 'Default event type', value: b.normalization.defaultEventType }]
                : []),
            ]}
          />
          <p className="mt-2 text-[11px] text-muted-foreground">
            Recorded on every stored event, with all original columns by name, so each event can be traced to its source cells.
          </p>
        </DetailSection>
      )}

      {b.eventCoverage && describeCoverage(b.eventCoverage).length > 0 && (
        <DetailSection title="Assessment readiness">
          <ul className="space-y-1 text-xs leading-relaxed text-muted-foreground">
            {describeCoverage(b.eventCoverage).map((note) => <li key={note}>{note}</li>)}
          </ul>
        </DetailSection>
      )}

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
        {describeStoredRows(b) !== null
          ? `${describeStoredRows(b)} Each stored event records this batch and its file row.`
          : 'No rows from this file were stored.'}{' '}
        Rejected rows are never stored, and nothing was added to Incidents or Assessments. Issues name a row, a column
        and a rule, never cell contents.
      </p>
      {(b.eventsCreated ?? 0) > 0 && (
        <Button asChild variant="outline" size="sm">
          <Link to={`${ROUTES.events}?batch=${encodeURIComponent(b.id)}`}>
            View the {formatNumber(b.eventsCreated)} event{b.eventsCreated === 1 ? '' : 's'} this batch stored
          </Link>
        </Button>
      )}
    </>
  )
}

export function RowCounts({ batch }: { batch: BackendImportBatchDetail }) {
  const items = [
    { label: 'Data rows', value: batch.totalRows, className: '' },
    { label: 'Accepted', value: batch.acceptedRows, className: 'text-low' },
    { label: 'Rejected', value: batch.rejectedRows, className: batch.rejectedRows > 0 ? 'text-critical' : '' },
    { label: 'Issues', value: batch.errorTotal, className: batch.errorTotal > 0 ? 'text-medium' : '' },
    { label: 'Events stored', value: batch.eventsCreated ?? 0, className: '' },
    { label: 'Skipped (duplicates)', value: batch.duplicateRows ?? 0, className: '' },
  ]
  return (
    <dl className="surface-inset grid grid-cols-2 gap-px overflow-hidden rounded-lg sm:grid-cols-3">
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
