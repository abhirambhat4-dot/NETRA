import { Link } from 'react-router-dom'
import type { BackendAssessmentDetail, BackendAssessmentFinding } from '@/api/types'
import {
  DetailSection,
  DetailSheet,
  Disclosure,
  ErrorState,
  KeyValueList,
  LoadingState,
  SeverityBadge,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { GRADE_TONE, RESULT_LABEL, RESULT_TONE, groupFindingsByCategory } from '@/lib/assessment'
import { formatDateTime } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assessmentService } from '@/services'
import { HttpError } from '@/services/http'

const INPUT_LABEL: Record<string, [string, string]> = {
  vulnerabilities: ['vulnerability', 'vulnerabilities'],
  incidents: ['incident', 'incidents'],
  events: ['event in the 7-day window', 'events in the 7-day window'],
  threatIndicators: ['active IP indicator', 'active IP indicators'],
}

/** Known kinds in a fixed order (JSONB does not keep key order), then any others. */
function inputCountKeys(counts: Record<string, number>): string[] {
  const known = Object.keys(INPUT_LABEL).filter((key) => key in counts)
  return [...known, ...Object.keys(counts).filter((key) => !(key in INPUT_LABEL)).sort()]
}

function inputCountText(key: string, count: number): string {
  const [singular, plural] = INPUT_LABEL[key] ?? [key, key]
  return `${count} ${count === 1 ? singular : plural}`
}

export function AssessmentDetailSheet({ assessmentId, onClose }: { assessmentId: string | null; onClose: () => void }) {
  const detail = useQuery(`assessment-detail-${assessmentId ?? 'none'}`, () =>
    assessmentId ? assessmentService.get(assessmentId) : Promise.resolve(undefined),
  )
  const assessment = detail.data?.id === assessmentId ? detail.data : undefined
  const error = detail.error
  const status = error instanceof HttpError ? error.status : undefined

  return (
    <DetailSheet
      open={!!assessmentId}
      onOpenChange={(open) => !open && onClose()}
      eyebrow={assessment ? `${assessment.assetKey} · ${assessment.methodologyVersion}` : assessmentId ?? undefined}
      title={assessment ? `Assessment · ${assessment.asset?.name ?? assessment.assetKey}` : detail.loading ? 'Loading assessment' : 'Assessment details'}
      description={assessment ? `Evidence as of ${formatDateTime(assessment.asOf)} UTC` : undefined}
    >
      {error ? (
        <div>
          <ErrorState
            title={status === 401 ? 'Authentication required' : status === 404 ? 'Assessment not found' : 'Assessment unavailable'}
            message={status === 401 || status === 404 ? undefined : error.message}
            onRetry={status === 401 || status === 404 ? undefined : detail.reload}
          />
          {status === 401 && (
            <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
          )}
        </div>
      ) : !assessment ? (
        <LoadingState variant="inline" label="Loading assessment…" />
      ) : (
        <Body key={assessment.id} assessment={assessment} />
      )}
    </DetailSheet>
  )
}

function Body({ assessment: a }: { assessment: BackendAssessmentDetail }) {
  const groups = groupFindingsByCategory(a.findings)
  const tone = GRADE_TONE[a.grade]

  return (
    <>
      <div className="flex items-center gap-5">
        <div className={cn('grid size-18 shrink-0 place-items-center rounded-full border-2 text-center', toneStyles[tone].border, toneStyles[tone].soft)}>
          <div>
            <div className={cn('text-2xl leading-none font-semibold', toneStyles[tone].text)}>{a.grade}</div>
            <div className="mt-1 font-mono text-[10px] text-muted-foreground">{a.score}/100</div>
          </div>
        </div>
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap gap-1.5">
            <ToneBadge tone="critical" size="sm">{a.failed} failed</ToneBadge>
            <ToneBadge tone="medium" size="sm">{a.warnings} warnings</ToneBadge>
            <ToneBadge tone="info" size="sm">{a.informational} info</ToneBadge>
            <ToneBadge tone="low" size="sm">{a.passed} passed</ToneBadge>
          </div>
          <p className="text-xs text-muted-foreground">{a.summary}</p>
        </div>
      </div>

      <DetailSection title="Snapshot">
        <KeyValueList
          columns={2}
          items={[
            {
              label: 'Asset',
              value: a.assetId ? (
                <Link to={`${ROUTES.assets}?asset=${a.assetId}`} className="text-primary hover:underline">
                  {a.asset?.name ?? a.assetKey}
                </Link>
              ) : (
                `${a.assetKey} (asset no longer registered)`
              ),
            },
            { label: 'Asset key', value: a.assetKey, mono: true },
            { label: 'Evidence as of', value: `${formatDateTime(a.asOf)} UTC` },
            { label: 'Methodology', value: a.methodologyVersion, mono: true },
            { label: 'Requested by', value: <span title={a.requestedBy}>{a.requestedBy}</span> },
            { label: 'Snapshot stored', value: `${formatDateTime(a.createdAt)} UTC` },
          ]}
        />
        <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
          <span className="text-foreground/85">Evidence loaded · </span>
          {inputCountKeys(a.inputCounts).map((key) => inputCountText(key, a.inputCounts[key])).join(' · ')}
        </p>
      </DetailSection>

      {a.missingEvidence.length > 0 && (
        <DetailSection title="Evidence gaps">
          <ul className="surface-inset space-y-1.5 rounded-lg px-3.5 py-2.5 text-xs text-muted-foreground">
            {a.missingEvidence.map((line) => <li key={line}>{line}</li>)}
          </ul>
        </DetailSection>
      )}

      {groups.map((group) => (
        <DetailSection key={group.category} title={group.label}>
          <ul className="space-y-2.5">
            {group.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}
          </ul>
        </DetailSection>
      ))}
    </>
  )
}

function FindingCard({ finding: f }: { finding: BackendAssessmentFinding }) {
  const passed = f.result === 'PASS'
  const evidence = (
    <ul className="list-disc space-y-1 pl-4 text-xs leading-relaxed text-foreground/85 marker:text-muted-foreground/60">
      {f.evidence.map((line, index) => <li key={index} className="wrap-break-word">{line}</li>)}
    </ul>
  )
  // Totals count every matching record; the ID lists may be capped by the backend.
  const referenceTotal = f.vulnerabilityTotal + f.incidentTotal + f.eventTotal

  return (
    <li className="surface-inset rounded-lg px-3.5 py-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 text-[13px] font-medium">{f.title}</div>
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {f.severity && <SeverityBadge severity={f.severity} size="sm" />}
          <ToneBadge tone={RESULT_TONE[f.result]} size="sm">{RESULT_LABEL[f.result]}</ToneBadge>
          {f.deduction > 0 && <span className="font-mono text-[11px] text-muted-foreground">−{f.deduction}</span>}
        </div>
      </div>

      <div className="mt-2.5 space-y-2.5">
        {passed ? <Disclosure label="Evidence" hint={`${f.evidence.length}`}>{evidence}</Disclosure> : evidence}

        {f.recommendation && (
          <p className="rounded-md border border-primary/15 bg-primary/5 px-3 py-2 text-xs leading-relaxed">
            <span className="font-medium text-foreground">Recommendation · </span>
            <span className="text-foreground/85">{f.recommendation}</span>
          </p>
        )}

        {referenceTotal > 0 && (
          <Disclosure label="Referenced records" hint={exactCount(referenceTotal)}>
            <div className="space-y-2 text-[11px]">
              <ReferenceList label="Vulnerabilities" noun={['vulnerability', 'vulnerabilities']} ids={f.vulnerabilityIds} total={f.vulnerabilityTotal} />
              <ReferenceList label="Incidents" noun={['incident', 'incidents']} ids={f.incidentIds} total={f.incidentTotal} href={(id) => ROUTES.incident(id)} />
              <ReferenceList label="Events" noun={['event', 'events']} ids={f.eventIds} total={f.eventTotal} href={(id) => `${ROUTES.events}?event=${id}`} />
            </div>
          </Disclosure>
        )}
      </div>
    </li>
  )
}

/** Exact count with thousands separators ("5,000"), unlike the abbreviating formatNumber. */
function exactCount(n: number): string {
  return n.toLocaleString('en-US')
}

function ReferenceList({ label, noun, ids, total, href }: {
  label: string
  noun: [string, string]
  ids: string[]
  total: number
  href?: (id: string) => string
}) {
  if (!total) return null
  const capped = total > ids.length
  return (
    <div>
      <div className="mb-1 text-muted-foreground">
        {capped ? (
          <>
            Showing {exactCount(ids.length)} of {exactCount(total)} {total === 1 ? noun[0] : noun[1]}
            <span className="text-muted-foreground/70"> · most recent or most severe first</span>
          </>
        ) : (
          `${label} · ${exactCount(total)}`
        )}
      </div>
      <ul className="space-y-0.5 font-mono break-all">
        {ids.map((id) => (
          <li key={id}>
            {href ? <Link to={href(id)} className="text-primary hover:underline">{id}</Link> : <span className="text-foreground/85">{id}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}
