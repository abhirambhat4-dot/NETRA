import type * as React from 'react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowDown, ArrowLeft, Sparkles } from 'lucide-react'
import type { IncidentDetail } from '@/api/types'
import { DecisionTimeline } from '@/components/incidents/DecisionTimeline'
import { useGuideTone } from '@/components/guide'
import {
  Disclosure,
  ErrorState,
  LifecycleStepper,
  LoadingState,
  PageContainer,
  Panel,
  RiskScore,
  SeverityBadge,
  StatusBadge,
  SurfaceCard,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { formatDateTime, timeAgo } from '@/lib/format'
import { buildLifecycle, recommendationHeadline } from '@/lib/incident'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta } from '@/lib/sources'
import { incidentService, memoryService, threatIntelService } from '@/services'
import { AttackPanel } from './incident/AttackPanel'
import { AuthorizationPanel } from './incident/AuthorizationPanel'
import { ContainmentPanel } from './incident/ContainmentPanel'
import { DecisionPanel } from './incident/DecisionPanel'
import { MemoryPanel } from './incident/MemoryPanel'
import { RiskBreakdownPanel } from './incident/RiskBreakdownPanel'

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
      <IncidentHeader detail={d} />

      <SurfaceCard className="px-5 py-5 md:px-6">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[15px] font-semibold tracking-tight">Decision lifecycle</h2>
          <span className="text-xs text-muted-foreground">Detect → Understand → Prioritise → Verify → Authorize → Contain → Learn</span>
        </div>
        <LifecycleStepper steps={buildLifecycle(d)} />
      </SurfaceCard>

      <div className="grid items-start gap-5 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-5 xl:col-span-8">
          {d.riskAssessment && (
            <div className="rounded-xl" data-guide-target="risk-rationale">
              <RiskBreakdownPanel risk={d.riskAssessment} asset={d.asset} />
            </div>
          )}
          <AttackPanel detail={d} indicators={incidentIndicators} />
          <TimelinePanel detail={d} />
        </div>

        <aside className="grid min-w-0 items-start gap-5 md:grid-cols-2 xl:sticky xl:top-20 xl:col-span-4 xl:flex xl:flex-col">
          <DecisionPanel detail={d} />
          <AuthorizationPanel key={`${d.authorization?.id}-${d.authorization?.status}`} detail={d} />
          <ContainmentPanel detail={d} />
          <MemoryPanel detail={d} memory={memory.data ?? []} />
        </aside>
      </div>
    </PageContainer>
  )
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
          </div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-balance md:text-[1.875rem]">{i.threatName}</h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Detected {timeAgo(i.firstSeen)} on <span className="text-foreground/90">{d.asset.name}</span> · last activity {timeAgo(i.lastSeen)}
          </p>

          {/* Recommended action */}
          <div className="mt-4 flex max-w-2xl flex-col gap-3 rounded-lg border border-primary/20 bg-primary/6 px-4 py-3 sm:flex-row sm:items-center">
            <Sparkles className="hidden size-4 shrink-0 text-primary sm:block" />
            <div className="min-w-0 flex-1">
              <div className="text-[10px] font-semibold tracking-[0.14em] text-primary uppercase">Recommended action</div>
              <div className="mt-0.5 text-[14px] leading-snug font-medium">{recommendationHeadline(d)}</div>
            </div>
            {d.decision && (
              <Button variant="outline" size="sm" asChild className="shrink-0 self-start sm:self-center">
                <a href="#decision">
                  Review decision <ArrowDown />
                </a>
              </Button>
            )}
          </div>
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
