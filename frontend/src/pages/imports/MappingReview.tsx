import { CircleAlert, Loader2, Upload } from 'lucide-react'
import type { BackendImportPreview, CanonicalFieldName, ImportRecordType } from '@/api/types'
import { SegmentedControl, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  CONFIDENCE_META,
  delimiterLabel,
  draftProblems,
  mappableColumns,
  requiredFields,
  type MappingDraft,
} from '@/lib/datasetImport'
import { cn } from '@/lib/utils'

// Radix Select items need a non-empty value; this one stands for "no column".
const UNMAPPED = '__unmapped__'

interface MappingReviewProps {
  preview: BackendImportPreview
  draft: MappingDraft
  onChange: (draft: MappingDraft) => void
  /** Re-read the file with another encoding or delimiter; the server re-detects the columns. */
  onReread: (overrides: { encoding: string; delimiter: string }) => void
  onImport: () => void
  busy: 'preview' | 'import' | null
  importBlocked: string | null
}

/**
 * Preview of an uploaded CSV with the suggested field mapping. Only high-confidence suggestions are
 * preselected; the user confirms or corrects every field before anything is imported.
 */
export function MappingReview({ preview, draft, onChange, onReread, onImport, busy, importBlocked }: MappingReviewProps) {
  const columns = mappableColumns(preview)
  const required = new Set(requiredFields(preview, draft.recordType))
  const problems = draftProblems(draft, preview)
  const suggestions = new Map(preview.suggestions.map((item) => [item.field, item]))
  const mappedBy = new Map(Object.entries(draft.fields).filter(([, column]) => column).map(([field, column]) => [column, field]))
  const fieldLabel = new Map(preview.fields.map((field) => [field.name, field.label]))
  const recordType = preview.recordTypes.find((type) => type.name === draft.recordType)
  const disabled = busy !== null
  const setField = (name: CanonicalFieldName, column: string) =>
    onChange({ ...draft, fields: { ...draft.fields, [name]: column === UNMAPPED ? '' : column } })

  return (
    <div className="mt-4 space-y-5 border-t border-border pt-4" aria-busy={busy === 'preview'}>
      <div className="flex flex-wrap items-center gap-2">
        <ToneBadge tone={preview.needsReview ? 'medium' : 'low'}>
          {preview.needsReview ? 'Review the mapping' : 'Mapping detected'}
        </ToneBadge>
        <span className="min-w-0 truncate text-xs text-foreground/85" title={preview.originalFilename}>{preview.originalFilename}</span>
        <span className="text-xs text-muted-foreground">
          · {preview.columns.length} column{preview.columns.length === 1 ? '' : 's'} · first {preview.sampledRows} row
          {preview.sampledRows === 1 ? '' : 's'} sampled{preview.moreRows ? ' (more in the file)' : ''}
        </span>
      </div>

      {preview.warnings.length > 0 && (
        <ul className="space-y-1 rounded-md border border-medium/25 bg-medium/10 px-3.5 py-2.5 text-xs" aria-label="Preview warnings">
          {preview.warnings.map((warning) => (
            <li key={warning} className="flex gap-2 text-foreground/80">
              <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-medium" />
              <span>{warning}</span>
            </li>
          ))}
        </ul>
      )}

      <section className="grid gap-4 md:grid-cols-2" aria-label="File format">
        <div className="min-w-0 space-y-1.5">
          <Label htmlFor="map-encoding" className="text-[11px] text-foreground/80">Encoding</Label>
          <Select value={draft.encoding} disabled={disabled} onValueChange={(encoding) => onReread({ encoding, delimiter: draft.delimiter })}>
            <SelectTrigger id="map-encoding" className="h-9 w-full bg-card"><SelectValue /></SelectTrigger>
            <SelectContent>
              {preview.encodings.map((encoding) => <SelectItem key={encoding} value={encoding}>{encoding}</SelectItem>)}
            </SelectContent>
          </Select>
          <p className="text-[11px] text-muted-foreground">{preview.encodingConfident ? 'Detected from the file.' : 'Not UTF-8: check that characters look right.'}</p>
        </div>
        <div className="min-w-0 space-y-1.5">
          <Label htmlFor="map-delimiter" className="text-[11px] text-foreground/80">Delimiter</Label>
          <Select value={draft.delimiter} disabled={disabled} onValueChange={(delimiter) => onReread({ encoding: draft.encoding, delimiter })}>
            <SelectTrigger id="map-delimiter" className="h-9 w-full bg-card"><SelectValue /></SelectTrigger>
            <SelectContent>
              {preview.delimiters.map((option) => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}
            </SelectContent>
          </Select>
          <p className="text-[11px] text-muted-foreground">
            {preview.delimiterConfident ? `${delimiterLabel(preview.delimiter)}, detected from the file.` : 'Uncertain: check that the columns below split correctly.'}
          </p>
        </div>
      </section>

      <section className="space-y-2" aria-label="Record type">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-[13px] font-semibold">Record type</h3>
          <SegmentedControl<ImportRecordType>
            aria-label="Record type"
            value={draft.recordType}
            onChange={(value) => onChange({ ...draft, recordType: value })}
            options={preview.recordTypes.map((type) => ({ value: type.name, label: type.title }))}
          />
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">
          {recordType?.description} Required:{' '}
          <span className="text-foreground/85">{[...required].map((name) => fieldLabel.get(name) ?? name).join(', ')}</span>. Every other
          field is optional.
        </p>
      </section>

      <section aria-label="Field mapping">
        <h3 className="mb-2 text-[13px] font-semibold">Field mapping</h3>
        <ul className="surface-inset divide-y divide-border/70 rounded-lg">
          {preview.fields.map((field) => {
            const suggestion = suggestions.get(field.name)
            const chosen = draft.fields[field.name] ?? ''
            const meta = suggestion ? CONFIDENCE_META[suggestion.confidence] : null
            const hint =
              suggestion && !chosen && suggestion.confidence === 'low' && suggestion.column
                ? suggestion.column
                : null
            const isRequired = required.has(field.name)
            return (
              <li key={field.name} className="grid gap-x-4 gap-y-1.5 px-3.5 py-2.5 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Label htmlFor={`map-${field.name}`} className="text-xs font-medium text-foreground/90">{field.label}</Label>
                    {isRequired ? (
                      <ToneBadge tone="accent" size="sm">Required</ToneBadge>
                    ) : (
                      <span className="text-[10px] text-muted-foreground">optional</span>
                    )}
                    {meta && suggestion && suggestion.confidence !== 'none' && (
                      <ToneBadge tone={meta.tone} size="sm" title={suggestion.reason}>{meta.label}</ToneBadge>
                    )}
                  </div>
                  <p className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">{field.description}</p>
                  {suggestion?.confidence === 'ambiguous' && (
                    <p className="mt-0.5 text-[11px] text-medium">Several columns match: {suggestion.candidates.join(', ')}. Choose one.</p>
                  )}
                  {hint && (
                    <p className="mt-0.5 text-[11px] text-muted-foreground">
                      Possible match: <span className="text-foreground/85">{hint}</span> ({suggestion?.reason}).{' '}
                      <button type="button" className="text-primary underline-offset-2 hover:underline" disabled={disabled} onClick={() => setField(field.name, hint)}>
                        Use it
                      </button>
                    </p>
                  )}
                </div>
                <div className="min-w-0 space-y-1.5">
                  <Select value={chosen || UNMAPPED} disabled={disabled} onValueChange={(value) => setField(field.name, value)}>
                    <SelectTrigger id={`map-${field.name}`} className={cn('h-9 w-full bg-card', isRequired && !chosen && 'border-medium/50')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={UNMAPPED}>Not mapped</SelectItem>
                      {columns.map((column) => (
                        <SelectItem key={column} value={column}>
                          {column}
                          {mappedBy.has(column) && mappedBy.get(column) !== field.name ? ` · used for ${fieldLabel.get(mappedBy.get(column) as CanonicalFieldName)}` : ''}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {field.name === 'event_type' && !chosen && (
                    <Input
                      aria-label="Default event type"
                      placeholder={draft.recordType === 'network_flow' ? 'Default: network_flow' : 'Default event type, e.g. authentication'}
                      value={draft.defaultEventType}
                      maxLength={100}
                      disabled={disabled}
                      onChange={(event) => onChange({ ...draft, defaultEventType: event.target.value })}
                      className="h-9 bg-card"
                    />
                  )}
                  {field.name === 'occurred_at' && (
                    <div className="grid grid-cols-[minmax(0,1fr)_96px] gap-2">
                      <Select value={draft.timestampFormat || UNMAPPED} disabled={disabled} onValueChange={(value) => onChange({ ...draft, timestampFormat: value === UNMAPPED ? '' : value })}>
                        <SelectTrigger aria-label="Timestamp format" className={cn('h-9 w-full bg-card', !draft.timestampFormat && 'border-medium/50')}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={UNMAPPED}>Choose the timestamp format</SelectItem>
                          {preview.timestampFormats.map((format) => (
                            <SelectItem key={format.name} value={format.name}>
                              {format.label}
                              {preview.timestampFormatCandidates.includes(format.name) ? ' · matches sample' : ''}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Input
                        aria-label="UTC offset for timestamps without a zone"
                        title="UTC offset applied to timestamps that carry no zone"
                        value={draft.utcOffset}
                        disabled={disabled}
                        onChange={(event) => onChange({ ...draft, utcOffset: event.target.value.trim() })}
                        className="h-9 bg-card font-mono text-xs"
                      />
                    </div>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
        <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
          Unmapped columns are kept with each event, by their original names, for traceability. Severity and labels from the file
          are stored for reference only: imported events enter NETRA as INFO and are never treated as confirmed threats.
        </p>
      </section>

      <section aria-label="Sample rows">
        <h3 className="mb-2 text-[13px] font-semibold">Sample rows</h3>
        <div className="surface-inset max-h-72 overflow-auto rounded-lg">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-card">
              <tr className="border-b border-border">
                {preview.columns.map((column) => {
                  const field = mappedBy.get(column.name)
                  return (
                    <th key={column.index} scope="col" className="px-3 py-2 align-bottom font-medium whitespace-nowrap">
                      <div className={cn(field ? 'text-primary' : 'text-foreground/85')}>{column.name || `column ${column.index}`}</div>
                      <div className="font-normal text-muted-foreground">
                        {field ? `→ ${fieldLabel.get(field as CanonicalFieldName)}` : column.inferredKind}
                      </div>
                    </th>
                  )
                })}
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {preview.rows.map((row, rowIndex) => (
                <tr key={rowIndex}>
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex} className="max-w-56 truncate px-3 py-1.5 font-mono text-foreground/80" title={cell}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-1.5 text-[11px] text-muted-foreground">
          Shown as text. Cells starting with =, +, - or @ carry a leading apostrophe so spreadsheets never evaluate them.
        </p>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0 max-w-2xl text-xs">
          {problems.length > 0 ? (
            <ul className="space-y-0.5 text-medium" aria-label="Mapping problems">
              {problems.map((problem) => <li key={problem}>{problem}</li>)}
            </ul>
          ) : (
            <p className="text-muted-foreground">
              Every row is validated against this mapping. Valid rows are stored as security events tagged with the batch and their
              file row; rows that fail are reported and never stored.
            </p>
          )}
          {importBlocked && <p className="mt-1 text-muted-foreground">{importBlocked}</p>}
        </div>
        <Button type="button" onClick={onImport} disabled={problems.length > 0 || disabled || !!importBlocked}>
          {busy === 'import' ? <Loader2 className="animate-spin" /> : <Upload />}
          {busy === 'import' ? 'Importing…' : 'Import with this mapping'}
        </Button>
      </div>
    </div>
  )
}
