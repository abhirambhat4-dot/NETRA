import type * as React from 'react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import type { IncidentDetail } from '@/api/types'
import { DecisionTimeline } from '@/components/incidents/DecisionTimeline'
import { useGuideTone } from '@/components/guide'
import {
  Disclosure,
  ErrorState,
  LifecycleStepper,
  type LifecycleStep,
  LoadingState,
  PageContainer,
  Panel,
  RiskScore,
  SeverityBadge,
  StatusBadge,
  SurfaceCard,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { formatDateTime, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta } from '@/lib/sources'
import { incidentService, memoryService, threatIntelService } from '@/services'
import { USE_MOCKS } from '@/services/http'
import { AttackPanel } from './incident/AttackPanel'
import { AuthorizationPanel } from './incident/AuthorizationPanel'
import { ContainmentPanel } from './incident/ContainmentPanel'
import { DecisionPanel } from './incident/DecisionPanel'
import { MemoryPanel } from './incident/MemoryPanel'
import { RiskBreakdownPanel } from './incident/RiskBreakdownPanel'
import { LiveIncidentDetails } from './incident/LiveIncidentDetails'

const ACTIVE = new Set(['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING'])
/** Timeline entries shown before "Show full audit trail". */
const TIMELINE_PREVIEW = 3

/**
 * Incident investigation, ordered the way an analyst reasons:
 *   identity + risk + state + recommended action (first view)
 *   → lifecycle → why prioritised → attack & behaviour → audit trail,
 *   with decision → authorization → containment → memory alongside.
 */
export function IncidentDetailsPage() {
  const { id = '' } = useParams()
  if (!USE_MOCKS) return <LiveIncidentDetails id={id} />
  return <MockIncidentDetailsPage id={id} />
}

function MockIncidentDetailsPage({ id }: { id: string }) {
  const detail = useQuery(`incident-${id}`, () => incidentService.get(id))
  const indicators = useQuery('intel-indicators', threatIntelService.listIndicators)
  const memory = useQuery('memory-all', memoryService.list)

  const i = detail.data?.incident
  const live = i && ACTIVE.has(i.status)
  useGuideTone(!live ? 'normal' : i.severity === 'CRITICAL' ? 'critical' : i.severity === 'HIGH' ? 'warning' : 'normal')

  if (detail.error) {
    return (
      <SurfaceCard>
        <ErrorState title={`Incident ${id} not found`} message={detail.error.message} onRetry={detail.reload} />
        <div className="flex justify-center pb-8">
          <Button variant="outline" asChild>
            <Link to={ROUTES.incidents}>
              <ArrowLeft /> Back to incidents
            </Link>
          </Button>
        </div>
      </SurfaceCard>
    )
  }
  if (!detail.data) {
    return (
      <PageContainer>
        <LoadingState variant="cards" count={4} />
        <SurfaceCard>
          <LoadingState count={8} />
        </SurfaceCard>
      </PageContainer>
    )
  }

  const d = detail.data
  const incidentIndicators = (indicators.data ?? []).filter((x) => x.incidentIds.includes(d.incident.id))

  return (
    <PageContainer className="gap-5 lg:gap-6">
      <div className="motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-2 motion-safe:duration-500">
        <IncidentHeader detail={d} />
      </div>

      <SurfaceCard className="px-5 py-5 md:px-6">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[15px] font-semibold tracking-tight">Incident journey</h2>
          <span className="text-xs text-muted-foreground">Recorded lifecycle state · containment verification is tracked separately</span>
        </div>
        <LifecycleStepper steps={incidentJourney(d)} />
      </SurfaceCard>

      <TimelinePanel detail={d} />

      <ol aria-label="Evidence-led incident analysis and response" className="relative space-y-4 before:absolute before:top-4 before:bottom-8 before:left-3 before:w-px before:bg-border">
        <WorkflowReveal index={0}>
          <AttackPanel detail={d} indicators={incidentIndicators} />
        </WorkflowReveal>
        {d.riskAssessment && (
          <WorkflowReveal index={1}>
            <div className="rounded-xl" data-guide-target="risk-rationale">
              <RiskBreakdownPanel risk={d.riskAssessment} asset={d.asset} />
            </div>
          </WorkflowReveal>
        )}
        <WorkflowReveal index={2}>
          <DecisionPanel detail={d} />
        </WorkflowReveal>
        <WorkflowReveal index={3}>
          <AuthorizationPanel key={`${d.authorization?.id}-${d.authorization?.status}`} detail={d} />
        </WorkflowReveal>
        <WorkflowReveal index={4}>
          <ContainmentPanel detail={d} />
        </WorkflowReveal>
        <WorkflowReveal index={5}>
          <MemoryPanel detail={d} memory={memory.data ?? []} />
        </WorkflowReveal>
      </ol>
    </PageContainer>
  )
}

function WorkflowReveal({ index, children }: { index: number; children: React.ReactNode }) {
  return (
    <li
      className="relative pl-8 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-2 motion-safe:duration-500"
      style={{ animationDelay: `${index * 100}ms` }}
    >
      <span className="absolute top-4 left-0 grid size-6 place-items-center rounded-full border border-border bg-background font-mono text-[9px] text-muted-foreground">
        {String(index + 1).padStart(2, '0')}
      </span>
      {children}
    </li>
  )
}

function incidentJourney(d: IncidentDetail): LifecycleStep[] {
  const { incident, riskAssessment, decision, authorization, containmentAction } = d
  const monitorOnly = decision?.recommendedAction === 'MONITOR'
  const falsePositive = incident.status === 'FALSE_POSITIVE'
  const verified = falsePositive || authorization?.otpVerified === true
  const authorized = !decision?.requiresAuthorization
    ? 'skipped'
    : authorization?.status === 'APPROVED'
      ? 'done'
      : authorization?.status === 'REJECTED' || authorization?.status === 'EXPIRED'
        ? 'skipped'
        : 'upcoming'
  const contained = monitorOnly || falsePositive
    ? 'skipped'
    : containmentAction && ['EXECUTED', 'VERIFIED'].includes(containmentAction.status)
      ? 'done'
      : containmentAction && ['FAILED', 'ROLLED_BACK'].includes(containmentAction.status)
        ? 'skipped'
        : 'upcoming'
  const learned = incident.memoryEntryId ? 'done' : 'upcoming'

  const steps: LifecycleStep[] = [
    { key: 'detected', label: 'Detected', state: 'done', time: formatDateTime(incident.firstSeen) },
    { key: 'understood', label: 'Understood', state: d.events.length ? 'done' : 'upcoming', detail: `${incident.eventCount} correlated events` },
    { key: 'prioritised', label: 'Prioritised', state: riskAssessment ? 'done' : 'upcoming', detail: `Risk ${incident.riskScore}` },
    { key: 'verified', label: 'Verified', state: verified ? 'done' : 'upcoming', detail: authorization?.otpVerified ? 'Approver identity verified' : falsePositive ? 'Benign activity confirmed' : 'Review not recorded' },
    { key: 'authorized', label: 'Authorized', state: authorized, detail: authorization?.status?.toLowerCase().replace('_', ' ') ?? (monitorOnly ? 'Not required' : 'Awaiting approval') },
    { key: 'contained', label: 'Contained', state: contained, detail: containmentAction?.status.toLowerCase().replace('_', ' ') ?? (monitorOnly || falsePositive ? 'Not required' : 'No execution recorded') },
    { key: 'learned', label: 'Learned', state: learned, detail: incident.memoryEntryId ?? 'No memory record yet' },
  ]

  const current = steps.find((step) => step.state === 'upcoming')
  if (current) current.state = 'current'
  return steps
}

/** First view: who / how bad / where it stands / what to do. Metadata is one click away. */
function IncidentHeader({ detail: d }: { detail: IncidentDetail }) {
  const i = d.incident
  const src = detectionSourceMeta[i.detectionSource]

  return (
    <SurfaceCard className="overflow-hidden p-0">
      <div className="flex flex-col gap-6 px-5 py-5 md:flex-row md:items-center md:px-6">
        <div className="min-w-0 flex-1">
          <Link to={ROUTES.incidents} className="inline-flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-foreground">
            <ArrowLeft className="size-3.5" /> Incidents
          </Link>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-primary">{i.id}</span>
            <SeverityBadge severity={i.severity} />
            <StatusBadge status={i.status} />
            <ToneBadge tone="medium" size="sm">Demo enrichment</ToneBadge>
          </div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-balance md:text-[1.875rem]">{i.threatName}</h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Detected {timeAgo(i.firstSeen)} · last activity {timeAgo(i.lastSeen)}
          </p>

          <dl className="mt-4 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
            <Fact label="Affected asset">
              <Link to={`${ROUTES.assets}?asset=${d.asset.id}`} className="hover:text-primary">{d.asset.name}</Link>
              <span className="ml-1.5 text-[10px] text-muted-foreground">{d.asset.criticality.toLowerCase()}</span>
            </Fact>
            <Fact label="Correlated events">{i.eventCount.toLocaleString('en-US')}</Fact>
            <Fact label="Last activity">{timeAgo(i.lastSeen)}</Fact>
            <Fact label="Detection source">{src.short}</Fact>
          </dl>
        </div>
        <RiskScore score={i.riskScore} size="md" className="shrink-0 self-center" />
      </div>

      <div className="border-t border-border px-5 py-1.5 md:px-6">
        <Disclosure label="Incident metadata" hint="asset · IPs · detection · ATT&CK">
          <dl className="mb-3 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-3 xl:grid-cols-6">
            <Fact label="Affected asset">
              <Link to={`${ROUTES.assets}?asset=${d.asset.id}`} className="hover:text-primary">
                {d.asset.name}
              </Link>
            </Fact>
            <Fact label="Source IP" mono>
              {i.sourceIp}
            </Fact>
            <Fact label="Destination IP" mono>
              {i.destinationIp}
            </Fact>
            <Fact label="Detection time">{formatDateTime(i.firstSeen)} UTC</Fact>
            <Fact label="Detection source">
              <span className="inline-flex items-center gap-1.5">
                <src.icon className="size-3.5 text-muted-foreground" /> {src.short}
              </span>
            </Fact>
            <Fact label="MITRE ATT&CK" mono>
              {d.mitreTechnique ? `${d.mitreTechnique.id} · ${d.mitreTechnique.name}` : '—'}
            </Fact>
          </dl>
        </Disclosure>
      </div>
    </SurfaceCard>
  )
}

function TimelinePanel({ detail: d }: { detail: IncidentDetail }) {
  const [expanded, setExpanded] = useState(false)
  const entries = [...d.incident.timeline].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
  const hidden = entries.length - TIMELINE_PREVIEW
  const shown = expanded || hidden <= 0 ? entries : entries.slice(-TIMELINE_PREVIEW)

  return (
    <Panel
      title="Incident timeline"
      description="Every detection, decision and action — the audit trail NETRA remembers"
      actions={
        hidden > 0 && (
          <Button variant="ghost" size="sm" className="text-muted-foreground" aria-expanded={expanded} onClick={() => setExpanded((e) => !e)}>
            {expanded ? 'Show latest only' : `Show full audit trail (${entries.length})`}
          </Button>
        )
      }
    >
      {!expanded && hidden > 0 && (
        <p className="mb-4 text-[11px] text-muted-foreground">
          {hidden} earlier entr{hidden > 1 ? 'ies' : 'y'} hidden · latest {TIMELINE_PREVIEW} shown
        </p>
      )}
      <DecisionTimeline entries={shown} />
    </Panel>
  )
}

function Fact({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0 bg-surface px-4 py-3">
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className={mono ? 'mt-0.5 truncate font-mono text-xs text-foreground/90' : 'mt-0.5 truncate text-[13px] text-foreground/90'}>{children}</dd>
    </div>
  )
}
