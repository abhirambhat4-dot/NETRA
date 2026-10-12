import type * as React from 'react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { CircleAlert, FileSearch, FileSpreadsheet, Loader2, Upload } from 'lucide-react'
import type { BackendImportBatchDetail, BackendImportPreview } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { Panel, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { permissionExplanation } from '@/lib/authorizationAccess'
import {
  IMPORT_PROFILES,
  MAX_ROWS,
  MAX_UPLOAD_BYTES,
  SECURITY_CSV_PROFILE,
  checkSelectedFile,
  describeCoverage,
  describeImportFailure,
  describeImportOutcome,
  draftToMapping,
  formatBytes,
  initialDraft,
  type ImportFailure,
  type MappingDraft,
} from '@/lib/datasetImport'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { importService } from '@/services'
import { HttpError } from '@/services/http'
import { IssueList, RowCounts } from './ImportBatchDetailSheet'
import { MappingReview } from './MappingReview'

const PREVIEW_ISSUES = 5

export function UploadPanel({ onOpenBatch }: { onOpenBatch: (id: string) => void }) {
  const [profile, setProfile] = useState(IMPORT_PROFILES[0].id)
  // The File stays in component state only; the page never reads its contents (the API previews it).
  const [file, setFile] = useState<File | null>(null)
  const [inputKey, setInputKey] = useState(0)
  const [busy, setBusy] = useState<'preview' | 'import' | null>(null)
  const [preview, setPreview] = useState<BackendImportPreview | null>(null)
  const [draft, setDraft] = useState<MappingDraft | null>(null)
  const [result, setResult] = useState<BackendImportBatchDetail | null>(null)
  const [failure, setFailure] = useState<ImportFailure | null>(null)
  const fileProblem = file ? checkSelectedFile(file) : null
  const profileMeta = IMPORT_PROFILES.find((option) => option.id === profile)
  const mapped = profile === SECURITY_CSV_PROFILE
  // Presentation only: the API enforces the role, and answers 403 for a role that is not recognised.
  const roleBlocked = permissionExplanation(useAuth().user, 'workflow', 'Importing dataset files')

  const resetReview = () => {
    setPreview(null)
    setDraft(null)
  }

  function chooseFile(event: React.ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] ?? null)
    setFailure(null)
    resetReview()
  }

  function chooseProfile(value: string) {
    setProfile(value)
    setFailure(null)
    resetReview()
  }

  function fail(cause: unknown) {
    setFailure(
      describeImportFailure(
        cause instanceof HttpError ? cause.status : null,
        cause instanceof Error ? cause.message : String(cause),
      ),
    )
  }

  async function runPreview(overrides?: { encoding: string; delimiter: string }) {
    if (!file || fileProblem || busy || roleBlocked) return
    setBusy('preview')
    setFailure(null)
    setResult(null)
    try {
      const next = await importService.preview(file, overrides)
      setPreview(next)
      setDraft(initialDraft(next))
    } catch (cause) {
      fail(cause)
    } finally {
      setBusy(null)
    }
  }

  async function runImport() {
    if (!file || fileProblem || busy || roleBlocked) return
    if (mapped && !draft) return
    setBusy('import')
    setFailure(null)
    setResult(null)
    try {
      const batch = await importService.upload(file, profile, mapped && draft ? draftToMapping(draft) : undefined)
      // Shown only once the API has recorded the batch.
      setResult(batch)
      setFile(null)
      resetReview()
      setInputKey((key) => key + 1)
    } catch (cause) {
      fail(cause)
    } finally {
      setBusy(null)
    }
  }

  function submit(event: React.FormEvent) {
    event.preventDefault()
    if (mapped) void runPreview()
    else void runImport()
  }

  const idleLabel = mapped ? (preview ? 'Preview again' : 'Preview and map columns') : failure ? 'Retry validation' : 'Validate file'
  const busyLabel = busy === 'preview' ? 'Reading the file…' : 'Uploading and validating…'
  const alreadyImported = preview?.alreadyImported
    ? 'These exact bytes were already imported with Security CSV; importing them again would be refused.'
    : null

  return (
    <Panel
      title="Import a security data file"
      description="Upload a CSV, review how NETRA reads it, then import. Each import is recorded as a batch with its validation report."
      actions={<ToneBadge tone="neutral" size="sm">Validated rows only</ToneBadge>}
    >
      <form onSubmit={submit} className="space-y-4" noValidate aria-busy={busy !== null}>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="min-w-0 space-y-1.5">
            <Label htmlFor="import-profile" className="text-[11px] text-foreground/80">Import type</Label>
            <Select value={profile} onValueChange={chooseProfile} disabled={busy !== null}>
              <SelectTrigger id="import-profile" className="h-9 w-full bg-card">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {IMPORT_PROFILES.map((option) => (
                  <SelectItem key={option.id} value={option.id}>{option.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">{profileMeta?.description}</p>
          </div>

          <div className="min-w-0 space-y-1.5">
            <Label htmlFor="import-file" className="text-[11px] text-foreground/80">CSV file</Label>
            <Input
              key={inputKey}
              id="import-file"
              type="file"
              accept=".csv,text/csv"
              disabled={busy !== null}
              aria-invalid={!!fileProblem}
              aria-describedby="import-file-hint"
              onChange={chooseFile}
              className="h-9 bg-card pt-1.5"
            />
            {fileProblem ? (
              <p id="import-file-hint" role="alert" className="text-[11px] text-critical">{fileProblem}</p>
            ) : (
              <p id="import-file-hint" className="text-[11px] text-muted-foreground">
                {file ? (
                  <span className="inline-flex max-w-full items-center gap-1.5">
                    <FileSpreadsheet className="size-3 shrink-0" />
                    <span className="truncate text-foreground/85" title={file.name}>{file.name}</span>
                    <span className="shrink-0 font-mono">{formatBytes(file.size)}</span>
                  </span>
                ) : (
                  `.csv only · up to ${formatBytes(MAX_UPLOAD_BYTES)} and ${MAX_ROWS.toLocaleString('en-US')} data rows`
                )}
              </p>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="max-w-2xl text-xs leading-relaxed text-muted-foreground">
            {mapped
              ? 'Comma, semicolon, tab or pipe delimited; UTF-8, UTF-16 or Windows-1252. The preview reads only the start of the file and stores nothing. Accepted rows are stored as Security Events; labels and severities from the file are kept for reference, never as detections.'
              : 'Every row is checked. With the CIC-IDS2017 profile, rows that pass are stored as Security Events tagged with this batch and their file row; the dataset label is kept as ground truth, not as a detection. Generic CSV is checked only. Full CIC-IDS2017 files exceed the upload limit; upload smaller CSV extracts.'}
          </p>
          <Button type="submit" variant={mapped && preview ? 'outline' : 'default'} disabled={!file || !!fileProblem || busy !== null || !!roleBlocked}>
            {busy !== null ? <Loader2 className="animate-spin" /> : mapped ? <FileSearch /> : <Upload />}
            {busy !== null ? busyLabel : idleLabel}
          </Button>
        </div>
        {roleBlocked && <p role="note" className="text-xs text-muted-foreground">{roleBlocked}</p>}
      </form>

      {mapped && preview?.recognizedProfile === 'cic-ids2017' && (
        <Notice tone="accent" title="Recognised CIC-IDS2017 file">
          <p className="text-foreground/80">
            The CIC-IDS2017 profile checks every one of the 85 columns and the dataset's timestamp conventions.
          </p>
          <Button size="sm" variant="outline" onClick={() => chooseProfile('cic-ids2017')}>Use the CIC-IDS2017 profile</Button>
        </Notice>
      )}
      {mapped && preview?.alreadyImported && (
        <Notice tone="medium" title="Already imported">
          <p className="text-foreground/80">{alreadyImported}</p>
          {preview.alreadyImportedBatchId && (
            <Button size="sm" variant="outline" onClick={() => onOpenBatch(preview.alreadyImportedBatchId!)}>Open existing batch</Button>
          )}
        </Notice>
      )}
      {mapped && preview && draft && (
        <MappingReview
          preview={preview}
          draft={draft}
          onChange={setDraft}
          onReread={(overrides) => void runPreview(overrides)}
          onImport={() => void runImport()}
          busy={busy}
          importBlocked={alreadyImported}
        />
      )}

      <section aria-live="polite" aria-label="Import result">
        {failure && <FailureNotice failure={failure} onOpenBatch={onOpenBatch} />}
        {result && <ResultSummary batch={result} onOpenBatch={onOpenBatch} />}
      </section>
    </Panel>
  )
}

function Notice({ tone, title, children }: { tone: 'accent' | 'medium'; title: string; children: React.ReactNode }) {
  return (
    <div
      role="note"
      className={cn(
        'mt-4 flex gap-2.5 rounded-md border px-3.5 py-2.5 text-xs',
        tone === 'medium' ? 'border-medium/25 bg-medium/10' : 'border-primary/25 bg-primary/8',
      )}
    >
      <CircleAlert className={cn('mt-0.5 size-3.5 shrink-0', tone === 'medium' ? 'text-medium' : 'text-primary')} />
      <div className="min-w-0 space-y-1.5">
        <p className={cn('font-medium', tone === 'medium' ? 'text-medium' : 'text-primary')}>{title}</p>
        {children}
      </div>
    </div>
  )
}

function FailureNotice({ failure, onOpenBatch }: { failure: ImportFailure; onOpenBatch: (id: string) => void }) {
  const warning = failure.kind === 'duplicate' || failure.kind === 'rateLimited'
  return (
    <div
      role="alert"
      className={cn(
        'mt-4 flex gap-2.5 rounded-md border px-3.5 py-2.5 text-xs',
        warning ? 'border-medium/25 bg-medium/10' : 'border-critical/30 bg-critical/10',
      )}
    >
      <CircleAlert className={cn('mt-0.5 size-3.5 shrink-0', warning ? 'text-medium' : 'text-critical')} />
      <div className="min-w-0 space-y-1.5">
        <p className={cn('font-medium', warning ? 'text-medium' : 'text-critical')}>{failure.title}</p>
        <p className="text-foreground/80">{failure.message}</p>
        {failure.kind === 'auth' && (
          <Button asChild size="sm" variant="outline"><Link to={ROUTES.login}>Sign in</Link></Button>
        )}
        {failure.existingBatchId && (
          <Button size="sm" variant="outline" onClick={() => onOpenBatch(failure.existingBatchId!)}>
            Open existing batch
          </Button>
        )}
      </div>
    </div>
  )
}

function ResultSummary({ batch, onOpenBatch }: { batch: BackendImportBatchDetail; onOpenBatch: (id: string) => void }) {
  const outcome = describeImportOutcome(batch)
  const preview = batch.errorSample.slice(0, PREVIEW_ISSUES)
  const coverage = batch.eventCoverage ? describeCoverage(batch.eventCoverage) : []
  return (
    <div className="mt-4 space-y-3 border-t border-border pt-4">
      <div className="flex flex-wrap items-center gap-2">
        <ToneBadge tone={outcome.tone}>{outcome.label}</ToneBadge>
        <span className="min-w-0 truncate text-xs text-foreground/85" title={batch.originalFilename}>{batch.originalFilename}</span>
        <span className="text-xs text-muted-foreground">· {outcome.summary}</span>
      </div>
      <RowCounts batch={batch} />
      {coverage.length > 0 && (
        <ul className="space-y-0.5 text-[11px] leading-relaxed text-muted-foreground" aria-label="What the stored events support">
          {coverage.map((note) => <li key={note}>{note}</li>)}
        </ul>
      )}
      {preview.length > 0 && <IssueList issues={preview} />}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] text-muted-foreground">
          Recorded as import batch <span className="font-mono">{batch.id.slice(0, 8)}</span>
          {batch.errorTotal > preview.length && ` · ${batch.errorTotal - preview.length} more issue${batch.errorTotal - preview.length === 1 ? '' : 's'} in the full report`}
        </p>
        <div className="flex flex-wrap gap-2">
          {(batch.eventsCreated ?? 0) > 0 && (
            <Button asChild size="sm" variant="outline">
              <Link to={`${ROUTES.events}?batch=${encodeURIComponent(batch.id)}`}>View imported events</Link>
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => onOpenBatch(batch.id)}>View full report</Button>
        </div>
      </div>
    </div>
  )
}
