import type * as React from 'react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, BrainCircuit, Loader2, Radar, ScanSearch, ShieldCheck, ShieldX, Sparkles } from 'lucide-react'
import type { LiveIncidentDetailsViewModel } from '@/api/types'
import { ErrorState, LifecycleStepper, LoadingState, PageContainer, Panel, SeverityBadge, SurfaceCard, type LifecycleStep } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { useAction } from '@/hooks/useAction'
import { useQuery } from '@/hooks/useQuery'
import { formatDateTime } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { liveIncidentDetailsService, liveIncidentWorkflowService } from '@/services'

const LIFECYCLE = ['DETECTED', 'UNDERSTOOD', 'PRIORITISED', 'VERIFIED', 'AUTHORIZED', 'CONTAINED', 'LEARNED'] as const

export function LiveIncidentDetails({ id }: { id: string }) {
  const detail = useQuery(`live-incident-${id}`, () => liveIncidentDetailsService.get(id))

  if (detail.error) {
    return (
      <PageContainer>
        <SurfaceCard>
          <ErrorState title={`Incident ${id} could not be loaded`} message={detail.error.message} onRetry={detail.reload} />
          <div className="flex justify-center pb-4">
            <Button variant="outline" asChild>
              <Link to={ROUTES.incidents}>
                <ArrowLeft /> Back to incidents
              </Link>
            </Button>
          </div>
        </SurfaceCard>
      </PageContainer>
    )
  }

  if (!detail.data || detail.data.incident.id !== id) {
    return (
      <PageContainer>
        <LoadingState variant="cards" count={3} />
        <SurfaceCard>
          <LoadingState count={8} />
        </SurfaceCard>
      </PageContainer>
    )
  }

  return <LiveIncidentDetailsContent detail={detail.data} />
}

function LiveIncidentDetailsContent({ detail }: { detail: LiveIncidentDetailsViewModel }) {
  const { busy, run } = useAction()
  const [rejectionReason, setRejectionReason] = useState('')
  const { incident } = detail
  const latestDecisionId = incident.latestDecision?.id
  const decision = incident.latestDecision ?? detail.decisions[detail.decisions.length - 1] ?? null
  const authorization = decision
    ? detail.authorizations.find((item) => item.decisionId === decision.id)
    : undefined
  const containment = authorization
    ? detail.containmentActions.find((item) => item.authorizationId === authorization.id)
    : undefined
  const hasMemory = detail.cyberMemories.length > 0
  const currentStage = LIFECYCLE.indexOf(incident.state)
  const lifecycle: LifecycleStep[] = LIFECYCLE.map((label, index) => ({
    key: label,
    label,
    state: index < currentStage ? 'done' : index === currentStage ? 'current' : 'upcoming',
    detail: index === currentStage ? 'Current API state' : undefined,
  }))

  return (
    <PageContainer className="gap-5 lg:gap-6">
      <SurfaceCard className="overflow-hidden p-0">
        <div className="flex flex-col gap-5 px-5 py-5 md:flex-row md:items-center md:px-6">
          <div className="min-w-0 flex-1">
            <Link to={ROUTES.incidents} className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              <ArrowLeft className="size-3.5" /> Incidents
            </Link>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-primary">{incident.incidentKey}</span>
              <SeverityBadge severity={incident.severity} />
              <span className="rounded-md border border-border px-2 py-1 font-mono text-[10px] text-muted-foreground">{incident.state}</span>
            </div>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-balance">{incident.title}</h1>
            <p className="mt-1.5 text-sm text-muted-foreground">{incident.description ?? 'Description: N/A'}</p>
          </div>
          <div className="shrink-0 text-center">
            <div className="metric text-3xl">{incident.riskScore ?? 'N/A'}</div>
            <div className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">Risk / 100</div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-px border-t border-border bg-border sm:grid-cols-3 xl:grid-cols-6">
          <Fact label="Incident ID" value={incident.id} mono />
          <Fact label="Detection source" value={incident.detectionSource} />
          <Fact label="Events" value={String(incident.eventCount)} />
          <Fact label="Created" value={formatDateTime(incident.createdAt)} />
          <Fact label="Updated" value={formatDateTime(incident.updatedAt)} />
          <Fact label="Recommended action" value={incident.recommendedAction ?? 'N/A'} />
        </div>
      </SurfaceCard>

      <Panel title="NETRA lifecycle" description="The current stage is backend-reported; missing stage timestamps are not inferred.">
        <LifecycleStepper steps={lifecycle} />
      </Panel>

      <Panel title="Workflow actions" description={`Actions are enabled from the backend-reported ${incident.state} state.`}>
        <div className="flex flex-wrap gap-2">
          {(incident.state === 'DETECTED' || incident.state === 'UNDERSTOOD') && (
            <Button
              variant="outline"
              disabled={busy !== null}
              onClick={() => run('enrich', () => liveIncidentWorkflowService.enrich(incident.id), 'Context enrichment completed')}
            >
              {busy === 'enrich' ? <Loader2 className="animate-spin" /> : <Sparkles />}
              Enrich context
            </Button>
          )}
          {(incident.state === 'DETECTED' || incident.state === 'UNDERSTOOD') && incident.eventCount > 0 && (
            <Button
              variant="outline"
              disabled={busy !== null}
              onClick={() => run('correlate', () => liveIncidentWorkflowService.correlate(incident.id), 'Correlation completed')}
            >
              {busy === 'correlate' ? <Loader2 className="animate-spin" /> : <Radar />}
              Correlate events
            </Button>
          )}
          {incident.state === 'UNDERSTOOD' && (
            <Button
              variant="outline"
              disabled={busy !== null}
              onClick={() => run('risk', () => liveIncidentWorkflowService.calculateRisk(incident.id), 'Risk calculation completed')}
            >
              {busy === 'risk' ? <Loader2 className="animate-spin" /> : <ScanSearch />}
              Calculate risk
            </Button>
          )}
          {incident.state === 'PRIORITISED' && detail.decisions.length === 0 && (
            <Button
              disabled={busy !== null}
              onClick={() => run('decision', () => liveIncidentWorkflowService.recommendDecision(incident.id), 'Decision recommendation created')}
            >
              {busy === 'decision' ? <Loader2 className="animate-spin" /> : <Sparkles />}
              Recommend decision
            </Button>
          )}
          {decision &&
            (incident.state === 'PRIORITISED' || incident.state === 'VERIFIED') &&
            !authorization && (
              <Button
                disabled={busy !== null}
                onClick={() => run('authorization', () => liveIncidentWorkflowService.requestAuthorization(decision.id), 'Authorization requested')}
              >
                {busy === 'authorization' ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
                Request authorization
              </Button>
            )}
          {authorization?.status === 'PENDING' && incident.state === 'VERIFIED' && (
            <Button
              disabled={busy !== null}
              onClick={() => run('approve', () => liveIncidentWorkflowService.approveAuthorization(authorization.id), 'Authorization approved')}
            >
              {busy === 'approve' ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
              Approve authorization
            </Button>
          )}
          {authorization?.status === 'PENDING' && (
            <div className="w-full max-w-xl space-y-2 border-t border-border pt-3">
              {incident.state !== 'VERIFIED' && (
                <p className="text-xs text-muted-foreground">
                  Approval requires VERIFIED, but the current API exposes no incident action to reach that state.
                </p>
              )}
              <label htmlFor="live-rejection-reason" className="text-xs font-medium">Reason for rejection</label>
              <Textarea
                id="live-rejection-reason"
                value={rejectionReason}
                onChange={(event) => setRejectionReason(event.target.value)}
                placeholder="Enter the operator's reason"
                className="min-h-20 text-[13px]"
              />
              <Button
                variant="destructive"
                disabled={busy !== null || rejectionReason.trim().length === 0}
                onClick={async () => {
                  const result = await run(
                    'reject',
                    () => liveIncidentWorkflowService.rejectAuthorization(authorization.id, rejectionReason),
                    'Authorization rejected',
                  )
                  if (result) setRejectionReason('')
                }}
              >
                {busy === 'reject' ? <Loader2 className="animate-spin" /> : <ShieldX />}
                Reject authorization
              </Button>
            </div>
          )}
          {incident.state === 'AUTHORIZED' && authorization?.status === 'APPROVED' && !containment && (
            <Button
              disabled={busy !== null}
              onClick={() => run('contain', () => liveIncidentWorkflowService.simulateContainment(authorization.id), 'Controlled containment simulation recorded')}
            >
              {busy === 'contain' ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
              Run controlled containment simulation
            </Button>
          )}
          {incident.state === 'AUTHORIZED' && containment?.executedAt && ['SUCCEEDED', 'FAILED'].includes(containment.status) && (
            <Button
              variant="outline"
              disabled={busy !== null}
              onClick={() => run('verify', () => liveIncidentWorkflowService.verifyContainment(containment.id), 'Containment verification recorded')}
            >
              {busy === 'verify' ? <Loader2 className="animate-spin" /> : <ScanSearch />}
              Verify containment result
            </Button>
          )}
          {incident.state === 'CONTAINED' && !hasMemory && (
            <Button
              disabled={busy !== null}
              onClick={() => run('memory', () => liveIncidentWorkflowService.createCyberMemory(incident.id), 'Cyber Memory created')}
            >
              {busy === 'memory' ? <Loader2 className="animate-spin" /> : <BrainCircuit />}
              Create Cyber Memory
            </Button>
          )}
          {incident.state === 'LEARNED' && <p className="text-sm text-muted-foreground">The incident has completed the backend workflow.</p>}
          {incident.state !== 'LEARNED' && ![
            incident.state === 'DETECTED' || incident.state === 'UNDERSTOOD',
            incident.state === 'UNDERSTOOD',
            incident.state === 'PRIORITISED' && detail.decisions.length === 0,
            Boolean(decision && (incident.state === 'PRIORITISED' || incident.state === 'VERIFIED') && !authorization),
            Boolean(authorization?.status === 'PENDING'),
            Boolean(incident.state === 'AUTHORIZED' && authorization?.status === 'APPROVED' && !containment),
            Boolean(incident.state === 'AUTHORIZED' && containment?.executedAt && ['SUCCEEDED', 'FAILED'].includes(containment.status)),
            Boolean(incident.state === 'CONTAINED' && !hasMemory),
          ].some(Boolean) && (
            <p className="text-sm text-muted-foreground">No workflow action is currently available for this backend-reported state.</p>
          )}
          {(incident.state === 'AUTHORIZED' || incident.state === 'CONTAINED') && (
            <p className="w-full border-t border-border pt-3 text-xs text-muted-foreground">
              Containment is a controlled simulation only. No host, firewall, or network changes are performed.
            </p>
          )}
        </div>
      </Panel>

      <div className="grid items-start gap-5 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-5 xl:col-span-8">
          <Panel title="Asset & assessment" description="Only fields supplied by the incident API are shown">
            {detail.asset ? (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <Fact label="Name" value={detail.asset.name} />
                <Fact label="Asset key" value={detail.asset.assetKey ?? 'N/A'} mono />
                <Fact label="Hostname" value={detail.asset.hostname ?? 'N/A'} mono />
                <Fact label="IP address" value={detail.asset.ipAddress ?? 'N/A'} mono />
                <Fact label="Type / environment" value={`${detail.asset.assetType} / ${detail.asset.environment}`} />
                <Fact label="Criticality / status" value={`${detail.asset.criticality} / ${detail.asset.status}`} />
                <Fact label="Exposure" value={detail.asset.exposure} />
                <Fact label="Owner" value={detail.asset.owner ?? 'N/A'} />
                <Fact label="Vulnerability details" value="Unavailable from this endpoint" />
              </div>
            ) : (
              <Unavailable message="No asset is associated with this incident." />
            )}
            <div className="mt-4 grid gap-3 border-t border-border pt-4 sm:grid-cols-2">
              <Fact label="Risk assessment" value="Unavailable from this endpoint" />
              <Fact label="MITRE ATT&CK technique" value="Unavailable from this endpoint" />
            </div>
          </Panel>

          <Panel title="Security events" description={`${detail.events.length} linked event${detail.events.length === 1 ? '' : 's'}`}>
            {detail.events.length ? (
              <div className="space-y-3">
                {detail.events.map((event) => (
                  <div key={event.id} className="border-b border-border py-3.5 first:pt-0 last:border-0 last:pb-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Link to={`${ROUTES.events}?event=${encodeURIComponent(event.eventUid)}`} className="text-sm font-medium hover:text-primary">
                        {event.eventType}
                      </Link>
                      <SeverityBadge severity={event.severity} size="sm" />
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{event.signature ?? 'Signature: N/A'}</p>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-4">
                      <Fact label="Event UID" value={event.eventUid} mono />
                      <Fact label="Occurred" value={formatDateTime(event.occurredAt)} />
                      <Fact label="Source" value={`${event.sourceIp ?? 'N/A'}:${event.sourcePort ?? 'N/A'}`} mono />
                      <Fact label="Destination" value={`${event.destinationIp ?? 'N/A'}:${event.destinationPort ?? 'N/A'}`} mono />
                      <Fact label="Protocol" value={event.protocol ?? 'N/A'} />
                      <Fact label="Detection source" value={event.detectionSource} />
                      <Fact label="Anomaly score" value={event.anomalyScore === null ? 'N/A' : String(event.anomalyScore)} />
                      <Fact label="Asset" value={event.asset?.name ?? 'N/A'} />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <Unavailable message="No linked events were returned." />
            )}
          </Panel>

          <Panel title="Incident timeline" description="Backend audit entries; unavailable stage and actor values remain marked">
            {detail.timeline.length ? (
              <ol className="space-y-0">
                {detail.timeline.map((entry) => (
                  <li key={entry.id} className="border-l border-border pb-5 pl-4 last:pb-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[13px] font-medium">{entry.title}</span>
                      <span className="font-mono text-[11px] text-muted-foreground">{formatDateTime(entry.timestamp)}</span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{entry.description}</p>
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      Source: {entry.source} · Stage: {entry.stage ?? 'N/A'} · Actor: {entry.actor ?? 'N/A'}
                      {entry.eventId ? ` · Event: ${entry.eventId}` : ''}
                    </p>
                  </li>
                ))}
              </ol>
            ) : (
              <Unavailable message="No timeline entries were returned." />
            )}
          </Panel>
        </div>

        <aside className="grid min-w-0 items-start gap-5 md:grid-cols-2 xl:sticky xl:top-20 xl:col-span-4 xl:flex xl:flex-col">
          <Panel title="Decisions" description="All decisions returned by the backend">
            {detail.decisions.length ? (
              <RecordList>
                {detail.decisions.map((decision) => (
                  <Record key={decision.id} id={decision.id} timestamp={decision.createdAt} label={decision.action}>
                    {latestDecisionId === decision.id && <p className="text-[10px] font-semibold text-primary">Latest decision</p>}
                    <p className="text-xs text-muted-foreground">{decision.rationale}</p>
                    <p className="text-[11px]">Risk: {decision.riskScore} · Confidence: {decision.confidence}</p>
                    <p className="text-[11px]">Recommendation: {decision.recommendation ?? 'N/A'}</p>
                  </Record>
                ))}
              </RecordList>
            ) : (
              <Unavailable message="No decisions were returned." />
            )}
            <p className="mt-3 border-t border-border pt-3 text-[11px] text-muted-foreground">Target, alternatives, authorization requirement, and decision status: unavailable.</p>
          </Panel>

          <Panel title="Authorizations" description="All authorization records; no OTP state is provided">
            {detail.authorizations.length ? (
              <RecordList>
                {detail.authorizations.map((authorization) => (
                  <Record key={authorization.id} id={authorization.id} timestamp={authorization.requestedAt} label={authorization.status}>
                    <p className="text-[11px]">Action: {authorization.requestedAction} · Requested by: {authorization.requestedBy}</p>
                    <p className="text-[11px]">Approved by: {authorization.approvedBy ?? 'N/A'} · Approved: {authorization.approvedAt ? formatDateTime(authorization.approvedAt) : 'N/A'}</p>
                    <p className="text-xs text-muted-foreground">Reason: {authorization.reason ?? 'N/A'}</p>
                  </Record>
                ))}
              </RecordList>
            ) : (
              <Unavailable message="No authorization records were returned." />
            )}
          </Panel>

          <Panel title="Containment actions" description="All actions returned by the backend">
            {detail.containmentActions.length ? (
              <RecordList>
                {detail.containmentActions.map((action) => (
                  <Record key={action.id} id={action.id} timestamp={action.createdAt} label={action.status}>
                    <p className="text-[11px]">{action.actionType} · Target: {action.target}</p>
                    <p className="text-[11px]">Executed: {action.executedAt ? formatDateTime(action.executedAt) : 'N/A'} · Verified: {action.verifiedAt ? formatDateTime(action.verifiedAt) : 'N/A'}</p>
                    <p className="text-xs text-muted-foreground">Result: {action.result ?? 'N/A'} · Error: {action.errorMessage ?? 'N/A'}</p>
                  </Record>
                ))}
              </RecordList>
            ) : (
              <Unavailable message="No containment actions were returned." />
            )}
          </Panel>

          <Panel title="Cyber Memory" description="References included in this incident response">
            {detail.cyberMemories.length ? (
              <RecordList>
                {detail.cyberMemories.map((memory) => (
                  <Record key={memory.id} id={memory.id} label={memory.outcome ?? 'Outcome: N/A'}>
                    <p className="text-xs leading-relaxed text-muted-foreground">{memory.lesson}</p>
                  </Record>
                ))}
              </RecordList>
            ) : (
              <Unavailable message="No Cyber Memory references were returned." />
            )}
            <p className="mt-3 border-t border-border pt-3 text-[11px] text-muted-foreground">Additional Cyber Memory metadata is unavailable in this response.</p>
          </Panel>
        </aside>
      </div>
    </PageContainer>
  )
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className={mono ? 'truncate font-mono text-xs text-foreground/90' : 'text-xs text-foreground/90'}>{value}</div>
    </div>
  )
}

function RecordList({ children }: { children: React.ReactNode }) {
  return <div className="space-y-3">{children}</div>
}

function Record({
  id,
  timestamp,
  label,
  children,
}: {
  id: string
  timestamp?: string
  label: string
  children: React.ReactNode
}) {
  return (
    <article className="rounded-lg border border-border p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-[10px] text-muted-foreground">{id}</span>
        <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-foreground/80">{label}</span>
      </div>
      {timestamp && <p className="mb-2 text-[10px] text-muted-foreground">{formatDateTime(timestamp)}</p>}
      <div className="space-y-1.5">{children}</div>
    </article>
  )
}

function Unavailable({ message }: { message: string }) {
  return <p className="rounded-lg border border-dashed border-border px-3.5 py-3 text-xs text-muted-foreground">{message}</p>
}