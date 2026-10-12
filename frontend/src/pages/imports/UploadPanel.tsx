import type * as React from 'react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { CircleAlert, FileSpreadsheet, Loader2, Upload } from 'lucide-react'
import type { BackendImportBatchDetail } from '@/api/types'
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
  checkSelectedFile,
  describeImportFailure,
  describeImportOutcome,
  formatBytes,
  type ImportFailure,
} from '@/lib/datasetImport'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { importService } from '@/services'
import { HttpError } from '@/services/http'
import { IssueList, RowCounts } from './ImportBatchDetailSheet'

const PREVIEW_ISSUES = 5

export function UploadPanel({ onOpenBatch }: { onOpenBatch: (id: string) => void }) {
  const [profile, setProfile] = useState(IMPORT_PROFILES[0].id)
  // The File stays in component state only; its contents are never read or stored by the page.
  const [file, setFile] = useState<File | null>(null)
  const [inputKey, setInputKey] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<BackendImportBatchDetail | null>(null)
  const [failure, setFailure] = useState<ImportFailure | null>(null)
  const fileProblem = file ? checkSelectedFile(file) : null
  const profileMeta = IMPORT_PROFILES.find((option) => option.id === profile)
  // Presentation only: the API enforces the role, and answers 403 for a role that is not recognised.
  const roleBlocked = permissionExplanation(useAuth().user, 'workflow', 'Validating dataset files')

  function chooseFile(event: React.ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] ?? null)
    setFailure(null)
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!file || fileProblem || uploading || roleBlocked) return
    setUploading(true)
    setFailure(null)
    setResult(null)
    try {
      const batch = await importService.upload(file, profile)
      // Shown only once the API has recorded the batch.
      setResult(batch)
      setFile(null)
      setInputKey((key) => key + 1)
    } catch (cause) {
      setFailure(
        describeImportFailure(
          cause instanceof HttpError ? cause.status : null,
          cause instanceof Error ? cause.message : String(cause),
        ),
      )
    } finally {
      setUploading(false)
    }
  }

  return (
    <Panel
      title="Validate a dataset file"
      description="Upload a CSV to check it against a dataset profile. The outcome is recorded as an import batch."
      actions={<ToneBadge tone="neutral" size="sm">Validation only</ToneBadge>}
    >
      <form onSubmit={submit} className="space-y-4" noValidate aria-busy={uploading}>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="min-w-0 space-y-1.5">
            <Label htmlFor="import-profile" className="text-[11px] text-foreground/80">Dataset profile</Label>
            <Select value={profile} onValueChange={setProfile} disabled={uploading}>
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
              disabled={uploading}
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
            Rows are checked, not stored: nothing enters Security Events, Incidents or Assessments. Full CIC-IDS2017
            files exceed the upload limit; check them with the local profiler, or upload smaller CSV extracts.
          </p>
          <Button type="submit" disabled={!file || !!fileProblem || uploading || !!roleBlocked}>
            {uploading ? <Loader2 className="animate-spin" /> : <Upload />}
            {uploading ? 'Uploading and validating…' : failure ? 'Retry validation' : 'Validate file'}
          </Button>
        </div>
        {roleBlocked && <p role="note" className="text-xs text-muted-foreground">{roleBlocked}</p>}
      </form>

      <section aria-live="polite" aria-label="Validation result">
        {failure && <FailureNotice failure={failure} onOpenBatch={onOpenBatch} />}
        {result && <ResultSummary batch={result} onOpenBatch={onOpenBatch} />}
      </section>
    </Panel>
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
  return (
    <div className="mt-4 space-y-3 border-t border-border pt-4">
      <div className="flex flex-wrap items-center gap-2">
        <ToneBadge tone={outcome.tone}>{outcome.label}</ToneBadge>
        <span className="min-w-0 truncate text-xs text-foreground/85" title={batch.originalFilename}>{batch.originalFilename}</span>
        <span className="text-xs text-muted-foreground">· {outcome.summary}</span>
      </div>
      <RowCounts batch={batch} />
      {preview.length > 0 && <IssueList issues={preview} />}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] text-muted-foreground">
          Recorded as import batch <span className="font-mono">{batch.id.slice(0, 8)}</span>
          {batch.errorTotal > preview.length && ` · ${batch.errorTotal - preview.length} more issue${batch.errorTotal - preview.length === 1 ? '' : 's'} in the full report`}
        </p>
        <Button size="sm" variant="outline" onClick={() => onOpenBatch(batch.id)}>View full report</Button>
      </div>
    </div>
  )
}
