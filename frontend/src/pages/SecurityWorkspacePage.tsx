import type * as React from 'react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BrainCircuit,
  Briefcase,
  CircleCheck,
  ClipboardCheck,
  FileUp,
  Gauge,
  GitMerge,
  Info,
  RotateCw,
  ServerOff,
  ShieldCheck,
} from 'lucide-react'
import type { BackendAssessmentSummary, BackendImportBatchPage, BackendImportBatchSummary } from '@/api/types'
import { EmptyState, ErrorState, LoadingState, PageContainer, PageHeader, Panel, SectionHeader, SelectFilter, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import {
  ATTENTION_LIMIT,
  ATTENTION_LINKS,
  assessmentFindingAttention,
  datasetIssueAttention,
  demoExclusionNote,
  incidentAttention,
  isDemoAsset,
  isDemoIncident,
  responseQueue,
  severityMix,
  type ResponseStep,
} from '@/lib/attention'
import { formatDateTime, formatNumber, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { eventSourceMeta } from '@/lib/sources'
import {
  ASSESSMENT_PAGE_SIZE,
  DETAIL_CONCURRENCY,
  IMPORT_PAGE_SIZE,
  assessmentScope,
  countWithWindow,
  importScope,
  moreLabel,
  settleWithConcurrency,
  showingOf,
  type AssessmentScope,
} from '@/lib/workspaceStatus'
import { detectionSummary, ingestionSummary, inventorySummary, memorySummary, responseSummary } from '@/lib/workspaceSummary'
import { assessmentService, assetInventoryService, importService, incidentQueueService, memoryService, threatIntelInventoryService } from '@/services'
import { USE_MOCKS } from '@/services/http'
import { AttentionList, CapabilityCard, ListNotes, PanelError, StatusRow, type StatusItem } from './workspaces/shared'

const DESCRIPTION = 'Investigate prioritised incidents, move them through authorization and simulated containment, and review assessment findings and Cyber Memory.'
const ALL_DATASETS = 'ALL'
/** Rows per dashboard list; each list links to its full page. */
const LIST_LIMIT = 5

export function SecurityWorkspacePage() {
  return USE_MOCKS ? <SecurityWorkspaceUnavailable /> : <SecurityWorkspace />
}

/**
 * Findings are only in assessment details, so every assessment needing review is opened (a few at a
 * time). A failed detail is counted, not fatal: the others are still ranked.
 */
async function loadFindings(review: readonly BackendAssessmentSummary[]) {
  const settled = await settleWithConcurrency(review, DETAIL_CONCURRENCY, (assessment) => assessmentService.get(assessment.id))
  const loaded = settled.flatMap((result) => (result.status === 'fulfilled' ? [result.value] : []))
  const firstFailure = settled.find((result) => result.status === 'rejected')
  return {
    ids: review.map((assessment) => assessment.id).join(','),
    findings: assessmentFindingAttention(loaded),
    failed: settled.length - loaded.length,
    error: firstFailure?.status === 'rejected' ? (firstFailure.reason instanceof Error ? firstFailure.reason : new Error(String(firstFailure.reason))) : undefined,
  }
}

function SecurityWorkspace() {
  const imports = useQuery('workspace-imports', () => importService.list({ page: 1, pageSize: IMPORT_PAGE_SIZE }))
  // Summary counts come from the list alone, so a failed detail request cannot blank them.
  const summaries = useQuery('workspace-assessments', () => assessmentService.list({ page: 1, pageSize: ASSESSMENT_PAGE_SIZE }))
  const scope = summaries.data ? assessmentScope(summaries.data) : undefined
  const reviewIds = scope?.review.map((assessment) => assessment.id).join(',')
  const details = useQuery(`workspace-findings-${reviewIds ?? 'pending'}`, () => (scope ? loadFindings(scope.review) : Promise.resolve(null)))
  // useQuery keeps the previous result while a new key loads; only use findings for the current review set.
  const findings = details.data && details.data.ids === reviewIds ? details.data : undefined

  const [dataset, setDataset] = useState<string>(ALL_DATASETS)
  const batches = imports.data?.items ?? []
  const selected = batches.find((batch) => batch.id === dataset)
  // Asset coverage is only in a batch's detail, so it is loaded for the selected dataset alone.
  const detail = useQuery(`workspace-import-${selected?.id ?? 'none'}`, () =>
    selected ? importService.get(selected.id) : Promise.resolve(null),
  )
  const selectedDetail = selected && detail.data?.id === selected.id ? detail.data : undefined
  const datasetIssues = imports.data
    ? datasetIssueAttention(selected ? [selected] : batches, selectedDetail ? { [selectedDetail.id]: selectedDetail.eventCoverage } : {})
    : []
  const imported = imports.data ? importScope(imports.data) : undefined

  const findingsPanel = (
    <Panel
      title="Priority assessment findings"
      description="Assessment findings only: failed, then warning checks from each asset's latest assessment, in the assessment's own severity and point-deduction order. Incidents and threat intelligence are reviewed in their own sections."
      flush
    >
      {summaries.error ? (
        <PanelError error={summaries.error} title="Assessments unavailable" onRetry={summaries.reload} />
      ) : !scope ? (
        <LoadingState className="px-5 pt-1" count={ATTENTION_LIMIT} label="Loading assessments…" />
      ) : scope.latest.length === 0 ? (
        <EmptyState
          icon={ClipboardCheck}
          title="No assessments yet."
          description="Run a security assessment on an asset to see its failed and warning checks here."
          action={<Button asChild variant="outline" size="sm"><Link to={ROUTES.assessments}>Open Security Assessment</Link></Button>}
        />
      ) : scope.review.length === 0 ? (
        <EmptyState
          icon={CircleCheck}
          title="No failed or warning checks."
          description={scope.olderNotLoaded > 0
            ? `None in the newest ${formatNumber(ASSESSMENT_PAGE_SIZE)} assessments; ${formatNumber(scope.olderNotLoaded)} older ones were not read.`
            : "The latest assessment of each assessed asset has no failed or warning checks."}
        />
      ) : details.error ? (
        <PanelError error={details.error} title="Assessment findings unavailable" onRetry={details.reload} />
      ) : !findings ? (
        <LoadingState className="px-5 pt-1" count={ATTENTION_LIMIT} label="Loading assessment findings…" />
      ) : findings.failed === scope.review.length ? (
        <ErrorState
          title="Assessment findings unavailable"
          message={findings.error?.message}
          onRetry={details.reload}
        />
      ) : (
        <>
          <AttentionList items={findings.findings.slice(0, ATTENTION_LIMIT)} />
          <FindingsScope scope={scope} shown={Math.min(ATTENTION_LIMIT, findings.findings.length)} failed={findings.failed} onRetry={details.reload} />
        </>
      )}
    </Panel>
  )

  const datasetIssuesPanel = (
    <Panel
      title="Dataset import issues"
      description="Validation and asset-coverage issues in your uploads. Imported rows are stored as INFO; labels in a file are not NETRA detections."
      actions={
        batches.length > 0 && (
          <SelectFilter<string>
            label="Dataset"
            value={selected ? selected.id : ALL_DATASETS}
            onChange={setDataset}
            options={[
              { value: ALL_DATASETS, label: 'All datasets' },
              ...batches.map((batch) => ({ value: batch.id, label: `${batch.originalFilename} · ${formatDateTime(batch.createdAt)}` })),
            ]}
            className="max-w-64"
          />
        )
      }
      flush
    >
      {imports.error ? (
        <PanelError error={imports.error} title="Dataset imports unavailable" onRetry={imports.reload} />
      ) : !imports.data || !imported ? (
        <LoadingState className="px-5 pt-1" count={ATTENTION_LIMIT} label="Loading dataset imports…" />
      ) : batches.length === 0 ? (
        <EmptyState
          icon={FileUp}
          title="No datasets imported yet."
          description="Upload a dataset to check its validation and asset coverage here."
          action={<Button asChild variant="outline" size="sm"><Link to={ROUTES.imports}>Open Dataset Import</Link></Button>}
        />
      ) : selected && detail.error ? (
        <PanelError error={detail.error} title="Dataset details unavailable" onRetry={detail.reload} />
      ) : selected && !selectedDetail ? (
        <LoadingState className="px-5 pt-1" count={ATTENTION_LIMIT} label="Loading dataset details…" />
      ) : datasetIssues.length === 0 ? (
        <>
          <EmptyState
            icon={CircleCheck}
            title={selected ? 'No issues in this dataset.' : 'No import issues found.'}
            description={
              selected
                ? 'No rejected rows, and no stored events without a linked asset.'
                : imported.notChecked > 0
                  ? `No rejected uploads or rejected rows in your ${formatNumber(imported.loaded)} most recent imports. Select a dataset to also check its asset coverage.`
                  : 'No rejected uploads or rejected rows in your imports. Select a dataset to also check its asset coverage.'
            }
          />
          {!selected && <ImportWindowNote notChecked={imported.notChecked} loaded={imported.loaded} />}
        </>
      ) : (
        <>
          <AttentionList items={datasetIssues.slice(0, ATTENTION_LIMIT)} />
          <ScopeNotes
            notes={[
              moreLabel(Math.min(ATTENTION_LIMIT, datasetIssues.length), datasetIssues.length, ['issue', 'issues']),
              !selected && 'Select a dataset to also check which of its events are linked to an asset.',
            ]}
          />
          {!selected && <ImportWindowNote notChecked={imported.notChecked} loaded={imported.loaded} />}
        </>
      )}
    </Panel>
  )

  return (
    <PageContainer>
      <PageHeader icon={Briefcase} eyebrow="Investigation" title="Security Workspace" description={DESCRIPTION} />

      <WorkspaceOverview
        imports={imports}
        scope={scope}
        summariesError={summaries.error}
        reloadSummaries={summaries.reload}
        findingsPanel={findingsPanel}
        datasetIssuesPanel={datasetIssuesPanel}
        importStatus={
          <StatusRow
            label="Dataset and assessment coverage"
            items={statusItems(imports.data, imports.error, scope, summaries.error)}
            footer={scope && scope.olderNotLoaded > 0
              ? `+ Assessment counts cover only the newest ${formatNumber(ASSESSMENT_PAGE_SIZE)} of ${formatNumber(scope.total)} assessments; ${formatNumber(scope.olderNotLoaded)} older ones were not read.`
              : undefined}
          />
        }
      />
    </PageContainer>
  )
}

type Query<T> = { data: T | undefined; error: Error | undefined; reload: () => void }

/** Loading or error body for a capability card; undefined once the data is in. */
function cardState(queries: ReadonlyArray<Query<unknown>>, what: string) {
  const failed = queries.find((query) => query.error)
  if (failed) {
    return (
      <div className="flex flex-wrap items-center gap-2 text-[13px] text-muted-foreground" role="status">
        {what} unavailable{failed.error?.message ? `: ${failed.error.message}` : ''}.
        <Button variant="ghost" size="sm" className="h-7 px-2 text-[12px]" onClick={failed.reload}><RotateCw /> Retry</Button>
      </div>
    )
  }
  if (queries.some((query) => query.data === undefined)) return <LoadingState count={2} label={`Loading ${what.toLowerCase()}…`} />
  return undefined
}

/**
 * The six project capabilities, each summarised from its existing API, plus the detail lists that
 * lead into the existing workflows. Demo seed records (explicit markers only) are excluded and stated.
 */
function WorkspaceOverview({
  imports,
  scope,
  summariesError,
  reloadSummaries,
  findingsPanel,
  datasetIssuesPanel,
  importStatus,
}: {
  imports: Query<BackendImportBatchPage>
  scope: AssessmentScope | undefined
  summariesError: Error | undefined
  reloadSummaries: () => void
  /** Assessment findings, placed with the investigation panels. */
  findingsPanel: React.ReactNode
  /** Import issues and the import status strip, placed in the lower ingestion section. */
  datasetIssuesPanel: React.ReactNode
  importStatus: React.ReactNode
}) {
  const incidents = useQuery('workspace-incidents', () => incidentQueueService.listTolerant({ state: 'ALL' }))
  const prioritizedQuery = useQuery('workspace-prioritized-incidents', incidentQueueService.listPrioritized)
  const memory = useQuery('workspace-memory', memoryService.list)
  const assets = useQuery('workspace-assets', () => assetInventoryService.list())
  const indicators = useQuery('workspace-indicators', () => threatIntelInventoryService.list())
  const assessments: Query<AssessmentScope> = { data: scope, error: summariesError, reload: reloadSummaries }

  const allIncidents = incidents.data?.items ?? []
  const demoIncidentIds = new Set(allIncidents.filter(isDemoIncident).map((incident) => incident.id))
  const genuine = allIncidents.filter((incident) => !demoIncidentIds.has(incident.id))
  const incidentDemoNote = demoExclusionNote(demoIncidentIds.size, 0)
  const detection = detectionSummary(genuine)
  const response = responseSummary(genuine)
  const topSource = detection.bySource[0]

  const activeDemoIds = new Set((prioritizedQuery.data?.incidents ?? []).filter(isDemoIncident).map((incident) => incident.id))
  const prioritized = (prioritizedQuery.data?.prioritized ?? []).filter((entry) => !activeDemoIds.has(entry.incidentId))
  const activeMix = severityMix(prioritized)
  const scoredActive = prioritized.flatMap((entry) => (entry.riskScore === null ? [] : [entry.riskScore]))
  const rationale = prioritizedQuery.data ? incidentAttention(prioritized, prioritizedQuery.data.incidents) : []
  // Grouped from every genuine incident: CONTAINED is not an active state, so the active list would miss it.
  const queue = responseQueue(genuine, LIST_LIMIT)
  const waiting = (step: ResponseStep) => queue.find((group) => group.step === step)?.total ?? 0
  const investigationItems = investigationStatusItems({
    activeIncidents: prioritizedQuery.error ? 'error' : prioritizedQuery.data ? prioritized.length : undefined,
    queue: incidents.error ? 'error' : incidents.data ? { authorize: waiting('authorize'), contain: waiting('contain'), record: waiting('record') } : undefined,
    findings: summariesError ? 'error' : scope ? { total: scope.checkTotal, truncated: scope.olderNotLoaded > 0 } : undefined,
  })

  const ingestion = ingestionSummary(imports.data?.items ?? [])
  const importsTruncated = Boolean(imports.data && imports.data.total > imports.data.items.length)
  const lessons = memorySummary(memory.data ?? [], demoIncidentIds)
  const genuineAssets = (assets.data ?? []).filter((asset) => !isDemoAsset(asset))
  const demoAssets = (assets.data?.length ?? 0) - genuineAssets.length
  const inventory = inventorySummary(genuineAssets, indicators.data ?? [])

  return (
    <>
      <StatusRow label="Investigation status" items={investigationItems} />

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <Panel
          title="Response queue"
          description="Incidents waiting for their next response step, highest stored risk first. Each opens the incident to continue its workflow."
          actions={<Link to={ROUTES.incidents} className="text-[12px] font-medium text-primary hover:underline">All incidents</Link>}
          flush
        >
          {incidents.error ? (
            <PanelError error={incidents.error} title="Response queue unavailable" onRetry={incidents.reload} />
          ) : !incidents.data ? (
            <LoadingState className="px-5 pt-1" count={3} label="Loading response queue…" />
          ) : queue.every((group) => group.total === 0) ? (
            <>
              <EmptyState
                icon={CircleCheck}
                title="Nothing waiting for a response step."
                description="Incidents appear here once they are verified, authorized, or contained and not yet recorded in Cyber Memory."
              />
              <ListNotes centered notes={[incidentDemoNote]} />
            </>
          ) : (
            <>
              {queue.map((group) => (
                <section key={group.step} aria-label={group.title} className="border-t border-border first:border-t-0">
                  <h3 className="flex items-center justify-between px-5 pt-3 pb-2 text-[12px] font-semibold text-foreground">
                    {group.title}
                    <span className="font-mono text-[11px] font-medium text-muted-foreground tabular-nums">{formatNumber(group.total)}</span>
                  </h3>
                  {group.items.length > 0 ? (
                    <>
                      <AttentionList items={group.items} />
                      {group.total > group.items.length && (
                        <p className="px-5 pt-1 pb-2 text-[12px] text-muted-foreground">Showing {group.items.length} of {formatNumber(group.total)}.</p>
                      )}
                    </>
                  ) : (
                    <p className="px-5 pb-3 text-[12px] text-muted-foreground">None waiting.</p>
                  )}
                </section>
              ))}
              <ListNotes notes={[incidentDemoNote]} />
            </>
          )}
        </Panel>

        <Panel
          title="Risk and priority rationale"
          description="Active incidents in NETRA's priority order, with the risk factors and the engine's own reason for each position."
          actions={<Link to={ROUTES.incidents} className="text-[12px] font-medium text-primary hover:underline">All incidents</Link>}
          flush
        >
          {prioritizedQuery.error ? (
            <PanelError error={prioritizedQuery.error} title="Incident priority unavailable" onRetry={prioritizedQuery.reload} />
          ) : !prioritizedQuery.data ? (
            <LoadingState className="px-5 pt-1" count={3} label="Loading incident priority…" />
          ) : rationale.length === 0 ? (
            <EmptyState icon={CircleCheck} title="No active incidents to explain." description="Prioritised incidents and their rationale appear here while incidents are active." />
          ) : (
            <>
              <AttentionList items={rationale.slice(0, LIST_LIMIT)} showDetail />
              <ListNotes
                notes={[
                  rationale.length > LIST_LIMIT && `Showing ${LIST_LIMIT} of ${formatNumber(rationale.length)} active incidents`,
                  demoExclusionNote(activeDemoIds.size, 0),
                ]}
              />
            </>
          )}
        </Panel>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-2">
        {findingsPanel}

        <Panel
          title="Recent lessons"
          description="The newest Cyber Memory entries, each from a verified, simulated containment."
          actions={<Link to={ROUTES.cyberMemory} className="text-[12px] font-medium text-primary hover:underline">Cyber Memory</Link>}
          flush
        >
          {memory.error ? (
            <PanelError error={memory.error} title="Cyber Memory unavailable" onRetry={memory.reload} />
          ) : !memory.data || !incidents.data ? (
            <LoadingState className="px-5 pt-1" count={2} label="Loading lessons…" />
          ) : lessons.latest.length === 0 ? (
            <EmptyState icon={BrainCircuit} title="No lessons recorded yet." description="A lesson is written when an incident's simulated containment is verified and recorded to Cyber Memory." />
          ) : (
            <ul className="border-t border-border">
              {lessons.latest.slice(0, 3).map((entry) => (
                <li key={entry.id} className="border-b border-border/70 px-5 py-3 last:border-b-0">
                  <p className="line-clamp-2 text-[13px] leading-snug text-foreground">{entry.lessonsLearned}</p>
                  <p className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px] text-muted-foreground">
                    {entry.outcome && <span>{entry.outcome}</span>}
                    {entry.effectiveness && <span>· {entry.effectiveness.replaceAll('_', ' ').toLowerCase()}</span>}
                    <time dateTime={entry.recordedAt} title={`${formatDateTime(entry.recordedAt)} UTC`}>· {timeAgo(entry.recordedAt)}</time>
                    {entry.incidentId && (
                      <Link to={ATTENTION_LINKS.incident(entry.incidentId)} className="text-primary hover:underline">· Open incident</Link>
                    )}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <section aria-labelledby="workspace-capabilities" className="space-y-3">
        <SectionHeader
          title={<span id="workspace-capabilities">Capabilities</span>}
          description="What NETRA records for each stage of investigation and response, with its stated limits. Every figure comes from stored records."
        />
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <CapabilityCard
            index={1}
            icon={GitMerge}
            title="Detection & Evidence Correlation"
            body={cardState([incidents], 'Incidents')}
            facts={[
              { label: 'Incidents', value: formatNumber(detection.incidents) },
              { label: 'With correlated events', value: formatNumber(detection.withEvidence) },
              { label: 'Top detection source', value: topSource ? `${eventSourceMeta(topSource.source).short} · ${formatNumber(topSource.count)}` : 'None' },
              { label: 'Unsupported state', value: formatNumber(incidents.data?.unsupported ?? 0) },
            ]}
            note={
              <>
                Incidents come from NETRA detection sources and event correlation. Labels inside imported datasets are kept as data and are never counted as detections.
                {incidentDemoNote && ` ${incidentDemoNote}.`}
              </>
            }
            links={[{ label: 'Incidents', to: ROUTES.incidents }, { label: 'Security Events', to: ROUTES.events }]}
          />
          <CapabilityCard
            index={2}
            icon={Gauge}
            title="Explainable Risk Assessment"
            body={cardState([incidents, prioritizedQuery], 'Risk data')}
            facts={[
              { label: 'Incidents risk-scored', value: `${formatNumber(response.scored)} of ${formatNumber(detection.incidents)}` },
              { label: 'Highest active risk', value: scoredActive.length ? Math.round(Math.max(...scoredActive)) : 'Not scored' },
              { label: 'Active critical', value: formatNumber(activeMix.CRITICAL), tone: activeMix.CRITICAL > 0 ? 'critical' : undefined },
              { label: 'Active high', value: formatNumber(activeMix.HIGH), tone: activeMix.HIGH > 0 ? 'high' : undefined },
            ]}
            note="Scores and severities come from NETRA's risk engine, which returns its factors, reasons and missing evidence for each incident. Unscored incidents are shown as not calculated, never estimated."
            links={[{ label: 'Incidents', to: ROUTES.incidents }]}
          />
          <CapabilityCard
            index={3}
            icon={ShieldCheck}
            title="Decision & Controlled Response"
            body={cardState([incidents], 'Response data')}
            facts={[
              { label: 'Decisions recorded', value: formatNumber(response.decisions) },
              { label: 'Verified', value: formatNumber(response.stages.VERIFIED) },
              { label: 'Authorized', value: formatNumber(response.stages.AUTHORIZED) },
              { label: 'Contained', value: formatNumber(response.stages.CONTAINED) },
            ]}
            note="Recommendations need verification and human authorization before any response. Containment is simulated: no firewall, host or account is changed."
            links={[{ label: 'Incidents', to: ROUTES.incidents }]}
          />
          <CapabilityCard
            index={4}
            icon={BrainCircuit}
            title="Cyber Memory & Learning"
            body={cardState([memory, incidents], 'Cyber Memory')}
            facts={[
              { label: 'Lessons recorded', value: formatNumber(lessons.entries) },
              { label: 'Rated effective', value: formatNumber(lessons.effective) },
              { label: 'Incidents learned', value: formatNumber(response.stages.LEARNED) },
              { label: 'Latest lesson', value: lessons.latest[0] ? timeAgo(lessons.latest[0].recordedAt) : 'None' },
            ]}
            note={
              <>
                A lesson is recorded once a simulated containment is verified, and can be searched in Cyber Memory. Lessons are not fed back into detection, risk or decisions: NETRA does not learn autonomously.
                {lessons.demo > 0 && ` ${lessons.demo} demo ${lessons.demo === 1 ? 'entry' : 'entries'} excluded.`}
              </>
            }
            links={[{ label: 'Cyber Memory', to: ROUTES.cyberMemory }]}
          />
          <CapabilityCard
            index={5}
            icon={ClipboardCheck}
            title="Security Assessment"
            body={cardState([assets, indicators, assessments], 'Assessment data')}
            facts={[
              { label: 'Assets', value: formatNumber(inventory.assets) },
              { label: 'Assets assessed', value: scope ? countWithWindow(scope.latest.length, scope.olderNotLoaded > 0) : '—' },
              { label: 'Recorded vulnerabilities', value: formatNumber(inventory.vulnerabilities) },
              { label: 'Active threat indicators', value: formatNumber(inventory.activeIndicators) },
            ]}
            note={
              <>
                Each assessment is a per-asset snapshot of stored evidence; every finding names its check, evidence and recommendation. Assessments are not linked to a specific dataset.
                {demoAssets > 0 && ` ${formatNumber(demoAssets)} demo ${demoAssets === 1 ? 'asset' : 'assets'} excluded.`}
              </>
            }
            links={[
              { label: 'Security Assessment', to: ROUTES.assessments },
              { label: 'Assets', to: ROUTES.assets },
              { label: 'Threat Intelligence', to: ROUTES.threatIntelligence },
            ]}
          />
          <CapabilityCard
            index={6}
            icon={FileUp}
            title="Security Data Ingestion"
            body={cardState([imports], 'Imports')}
            facts={[
              { label: 'Imports', value: formatNumber(imports.data?.total ?? 0) },
              { label: 'Rows accepted', value: `${formatNumber(ingestion.acceptedRows)}${importsTruncated ? '+' : ''}` },
              { label: 'Rows rejected', value: `${formatNumber(ingestion.rejectedRows)}${importsTruncated ? '+' : ''}`, tone: ingestion.rejectedRows > 0 ? 'medium' : undefined },
              { label: 'Duplicates skipped', value: `${formatNumber(ingestion.duplicateRows)}${importsTruncated ? '+' : ''}` },
            ]}
            note={
              <>
                Files are previewed, field-mapped and validated before storage; duplicate rows are skipped and every batch keeps its file hash and rejection reasons.
                {importsTruncated && ` Row totals cover your newest ${formatNumber(imports.data?.items.length ?? 0)} imports.`}
              </>
            }
            links={[{ label: 'Dataset Import', to: ROUTES.imports }]}
          />
        </div>
      </section>

      <section aria-labelledby="workspace-ingestion" className="space-y-3">
        <SectionHeader
          title={<span id="workspace-ingestion">Data ingestion</span>}
          description="Uploaded datasets: validation, stored rows and asset coverage. Imported rows are records, not detections."
        />
        {importStatus}
        <div className="grid items-start gap-4 xl:grid-cols-2">
          {datasetIssuesPanel}

          <Panel
            title="Recent imports"
            description="Your latest dataset batches with their validation outcome and what was stored."
            actions={<Link to={ROUTES.imports} className="text-[12px] font-medium text-primary hover:underline">Dataset Import</Link>}
            flush
          >
            {imports.error ? (
              <PanelError error={imports.error} title="Dataset imports unavailable" onRetry={imports.reload} />
            ) : !imports.data ? (
              <LoadingState className="px-5 pt-1" count={3} label="Loading imports…" />
            ) : imports.data.items.length === 0 ? (
              <EmptyState icon={FileUp} title="No datasets imported yet." description="Imported batches, their row counts and rejection reasons appear here." />
            ) : (
              <>
                <RecentImports batches={imports.data.items.slice(0, LIST_LIMIT)} />
                <ListNotes notes={[moreLabel(Math.min(LIST_LIMIT, imports.data.items.length), imports.data.total, ['import', 'imports'])]} />
              </>
            )}
          </Panel>
        </div>
      </section>

        <Panel title="Known limits" description="What this workspace does not do yet, so its figures are read correctly.">
          <ul className="space-y-2.5 text-[13px] leading-relaxed text-muted-foreground">
            {KNOWN_LIMITS.map((limit) => (
              <li key={limit} className="flex gap-2.5">
                <Info className="mt-0.5 size-3.5 shrink-0 text-muted-foreground/70" aria-hidden />
                <span>{limit}</span>
              </li>
            ))}
          </ul>
        </Panel>
    </>
  )
}

const KNOWN_LIMITS = [
  'Containment is simulated: authorised actions are recorded and verified, but no network, host or account change is made.',
  'Cyber Memory stores lessons for search and review; they are not used to retrain detection or change risk scores.',
  'Assessments are per asset and are not linked to a dataset, so the dataset filter covers import and asset-coverage issues only.',
  'Labels inside imported datasets are stored as data, not as detections; imported rows are INFO events.',
  'Imported batches cannot be deleted from the interface.',
] as const

function RecentImports({ batches }: { batches: readonly BackendImportBatchSummary[] }) {
  return (
    <div className="overflow-x-auto border-t border-border">
      <table className="w-full min-w-136 text-left text-[12px]">
        <thead className="text-[11px] text-muted-foreground">
          <tr className="border-b border-border/70">
            <th scope="col" className="px-5 py-2 font-medium">Dataset</th>
            <th scope="col" className="px-2 py-2 font-medium">Status</th>
            <th scope="col" className="px-2 py-2 text-right font-medium">Accepted</th>
            <th scope="col" className="px-2 py-2 text-right font-medium">Rejected</th>
            <th scope="col" className="px-2 py-2 text-right font-medium">Duplicates</th>
            <th scope="col" className="px-5 py-2 text-right font-medium">Stored events</th>
          </tr>
        </thead>
        <tbody>
          {batches.map((batch) => (
            <tr key={batch.id} className="border-b border-border/70 last:border-b-0 hover:bg-foreground/2.5">
              <td className="max-w-56 px-5 py-2.5">
                <Link to={ATTENTION_LINKS.importBatch(batch.id)} className="block truncate font-medium text-foreground hover:text-primary hover:underline" title={batch.originalFilename}>
                  {batch.originalFilename}
                </Link>
                <span className="text-[11px] text-muted-foreground" title={`${formatDateTime(batch.createdAt)} UTC`}>{batch.datasetProfile} · {timeAgo(batch.createdAt)}</span>
              </td>
              <td className="px-2 py-2.5">
                <ToneBadge tone={batch.status === 'VALIDATED' ? 'low' : 'critical'} size="sm">{batch.status === 'VALIDATED' ? 'Validated' : 'Rejected'}</ToneBadge>
              </td>
              <td className="px-2 py-2.5 text-right font-mono tabular-nums">{formatNumber(batch.acceptedRows)} / {formatNumber(batch.totalRows)}</td>
              <td className="px-2 py-2.5 text-right font-mono tabular-nums">{formatNumber(batch.rejectedRows)}</td>
              <td className="px-2 py-2.5 text-right font-mono tabular-nums">{formatNumber(batch.duplicateRows)}</td>
              <td className="px-5 py-2.5 text-right font-mono tabular-nums">{formatNumber(batch.eventsCreated)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Concise, always-visible scope notes under a list; empty notes are dropped. */
function ScopeNotes({ notes }: { notes: Array<string | null | false | undefined> }) {
  const shown = notes.filter((note): note is string => Boolean(note))
  if (shown.length === 0) return null
  return (
    <ul className="space-y-1 px-5 pt-3 pb-2 text-[12px] leading-relaxed text-muted-foreground">
      {shown.map((note) => <li key={note}>{note}</li>)}
    </ul>
  )
}

function FindingsScope({ scope, shown, failed, onRetry }: { scope: AssessmentScope; shown: number; failed: number; onRetry: () => void }) {
  return (
    <>
      <ScopeNotes
        notes={[
          showingOf(shown, scope.checkTotal, 'failed or warning checks'),
          scope.olderNotLoaded > 0 &&
            `Only the newest ${formatNumber(ASSESSMENT_PAGE_SIZE)} of ${formatNumber(scope.total)} assessments were read; ${formatNumber(scope.olderNotLoaded)} older ones are not included.`,
        ]}
      />
      {failed > 0 && (
        <p role="status" className="flex flex-wrap items-center gap-x-2 gap-y-1 px-5 pb-2 text-[12px] text-medium">
          Findings from {formatNumber(failed)} of {formatNumber(scope.review.length)} assessments could not be loaded and are not ranked here.
          <Button variant="ghost" size="sm" className="h-7 px-2 text-[12px]" onClick={onRetry}><RotateCw /> Retry</Button>
        </p>
      )}
    </>
  )
}

function ImportWindowNote({ notChecked, loaded }: { notChecked: number; loaded: number }) {
  if (notChecked === 0) return null
  return (
    <p className="px-5 pb-2 text-[12px] leading-relaxed text-muted-foreground">
      Checking your {formatNumber(loaded)} most recent imports · {moreLabel(loaded, loaded + notChecked, ['import', 'imports'])} not checked.{' '}
      <Link to={ROUTES.imports} className="text-primary hover:underline">View all in Dataset Import</Link>
    </p>
  )
}

/** First status strip: investigation and response work. `'error'` = its source failed; undefined = still loading. */
function investigationStatusItems({
  activeIncidents,
  queue,
  findings,
}: {
  activeIncidents: number | 'error' | undefined
  queue: Record<ResponseStep, number> | 'error' | undefined
  findings: { total: number; truncated: boolean } | 'error' | undefined
}): StatusItem[] {
  const value = <T,>(source: T | 'error' | undefined, read: (data: T) => string) =>
    source === 'error' ? 'Unavailable' : source === undefined ? '—' : read(source)
  const step = (key: ResponseStep, label: string, hint: string): StatusItem => ({
    label,
    value: value(queue, (counts) => formatNumber(counts[key])),
    tone: queue && queue !== 'error' ? (queue[key] > 0 ? 'medium' : 'low') : undefined,
    hint,
  })
  return [
    { label: 'Active incidents', value: value(activeIncidents, formatNumber), hint: 'Incidents not yet contained; demo records excluded' },
    step('authorize', 'Awaiting authorization', 'Verified incidents that need an approved authorization'),
    step('contain', 'Awaiting containment', 'Authorized incidents whose simulated containment is not yet verified'),
    step('record', 'Awaiting Cyber Memory', 'Contained incidents not yet recorded as a lesson'),
    {
      label: 'Open assessment findings',
      value: value(findings, (found) => countWithWindow(found.total, found.truncated)),
      hint: "Failed or warning checks in each asset's latest assessment",
    },
  ]
}

function statusItems(
  imports: BackendImportBatchPage | undefined,
  importsError: Error | undefined,
  assessments: AssessmentScope | undefined,
  assessmentsError: Error | undefined,
): StatusItem[] {
  const pending = '—'
  const latestImport = imports?.items[0]
  const truncated = Boolean(assessments && assessments.olderNotLoaded > 0)
  return [
    {
      label: 'Your imports',
      value: importsError ? 'Unavailable' : imports ? formatNumber(imports.total) : pending,
      hint: 'Dataset batches you uploaded',
    },
    {
      label: 'Latest import',
      value: importsError ? 'Unavailable' : !imports ? pending : latestImport ? `${latestImport.status === 'VALIDATED' ? 'Validated' : 'Rejected'} · ${timeAgo(latestImport.createdAt)}` : 'None',
      tone: latestImport && !importsError ? (latestImport.status === 'VALIDATED' ? 'low' : 'critical') : undefined,
      hint: latestImport ? latestImport.originalFilename : undefined,
    },
    {
      label: 'Assets assessed',
      value: assessmentsError ? 'Unavailable' : assessments ? countWithWindow(assessments.latest.length, truncated) : pending,
      hint: 'Assets with at least one assessment',
    },
    {
      label: 'Needing review',
      value: assessmentsError ? 'Unavailable' : assessments ? countWithWindow(assessments.review.length, truncated) : pending,
      tone: assessments && !assessmentsError ? (assessments.review.length > 0 ? 'medium' : 'low') : undefined,
      hint: 'Assets whose latest assessment has failed or warning checks',
    },
  ]
}

function SecurityWorkspaceUnavailable() {
  return (
    <PageContainer>
      <PageHeader icon={Briefcase} eyebrow="Investigation" title="Security Workspace" description={DESCRIPTION} />
      <Panel title="Workspace status">
        <EmptyState
          icon={ServerOff}
          title="Security Workspace requires the NETRA API."
          description="Dataset imports and security assessments are never simulated in demo mode. Run NETRA against the API to use this view."
        />
      </Panel>
    </PageContainer>
  )
}
