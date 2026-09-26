import type * as React from 'react'
import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowRight, BrainCircuit } from 'lucide-react'
import type { Asset, CyberMemoryEntry, Incident, IncidentDetail } from '@/api/types'
import { DecisionTimeline, type TimelineItem } from '@/components/incidents/DecisionTimeline'
import { RiskTile } from '@/components/incidents/IncidentRow'
import {
  EmptyState,
  LifecycleStepper,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  Panel,
  StatusBadge,
  SurfaceCard,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { ACTION_LABEL, formatDateTime, timeAgo } from '@/lib/format'
import { buildLifecycle, decisionReasoning, recommendationHeadline } from '@/lib/incident'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { assetService, incidentService, memoryService } from '@/services'

export function CyberMemoryPage() {
  const [params, setParams] = useSearchParams()
  const memory = useQuery('memory-all', memoryService.list)
  const incidents = useQuery('memory-incidents', () => incidentService.list({ pageSize: 500 }))
  const assets = useQuery('memory-assets', assetService.list)

  const all = useMemo(
    () => [...(incidents.data?.items ?? [])].sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen)),
    [incidents.data],
  )
  const assetsById = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])
  const selectedId = params.get('incident') ?? all.find((i) => i.memoryEntryId && i.status === 'CONTAINED')?.id ?? all[0]?.id

  const entries = all.flatMap((i) => i.timeline)
  const humanDecisions = entries.filter((t) => t.actor !== 'NETRA').length
  const contained = all.filter((i) => i.containedAt)
  const mttc = contained.length
    ? Math.round(contained.reduce((s, i) => s + (Date.parse(i.containedAt!) - Date.parse(i.firstSeen)), 0) / contained.length / 60000)
    : 0

  const journal: TimelineItem[] = all
    .flatMap((i) =>
      i.timeline.map((t) => ({
        ...t,
        aside: (
          <Link to={ROUTES.incident(i.id)} className="font-mono text-[10px] text-primary hover:underline">
            {i.id}
          </Link>
        ),
      })),
    )
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(0, 10)

  return (
    <PageContainer>
      <PageHeader
        title="Cyber Memory"
        description="NETRA remembers what happened, why it was prioritised, what was decided, who authorized it, what action ran and what the result was."
      />

      <MetricStrip
        metrics={[
          { label: 'Memory records', value: memory.data?.length ?? '—', hint: 'lessons stored', valueClassName: 'text-violet' },
          { label: 'Decisions recorded', value: entries.length || '—', hint: `across ${all.length} incidents` },
          { label: 'Human authorizations', value: humanDecisions, hint: 'analyst / approver actions' },
          { label: 'Mean time to contain', value: mttc ? `${Math.floor(mttc / 60)}h ${mttc % 60}m` : '—', hint: `${contained.length} contained incidents` },
          { label: 'False positives learned', value: memory.data?.filter((m) => m.outcome === 'FALSE_POSITIVE').length ?? '—', hint: 'suppressed next time' },
        ]}
      />

      {/* Decision trail explorer */}
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Incidents" description="Select a decision trail" flush className="xl:col-span-4">
          {!incidents.data ? (
            <LoadingState className="px-5" count={8} />
          ) : (
            <ul className="border-t border-border">
              {all.map((i) => (
                <li key={i.id}>
                  <button
                    type="button"
                    onClick={() => setParams({ incident: i.id }, { replace: true })}
                    className={cn(
                      'relative flex w-full items-center gap-3 border-b border-border/70 px-5 py-2.5 text-left transition-colors hover:bg-foreground/2.5',
                      selectedId === i.id && 'bg-primary/7',
                    )}
                  >
                    {selectedId === i.id && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-linear-to-b from-primary to-violet" />}
                    <RiskTile score={i.riskScore} severity={i.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] font-medium">{i.threatName}</div>
                      <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                        <span className="font-mono">{i.id}</span>·<span>{timeAgo(i.lastSeen)}</span>
                        {i.memoryEntryId && <BrainCircuit className="size-3 text-violet" aria-label="In memory" />}
                      </div>
                    </div>
                    <StatusBadge status={i.status} size="sm" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div className="xl:col-span-8">
          {selectedId ? (
            <DecisionTrail id={selectedId} asset={assetsById} />
          ) : (
            <SurfaceCard>
              <EmptyState title="No incidents yet" />
            </SurfaceCard>
          )}
        </div>
      </div>

      {/* Knowledge records + journal */}
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Knowledge records" description="Lessons NETRA reuses when prioritising similar incidents" className="xl:col-span-7">
          {!memory.data ? (
            <LoadingState count={4} />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {memory.data.map((m) => (
                <MemoryRecord key={m.id} entry={m} asset={assetsById.get(m.assetId)} />
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Decision journal" description="Latest workflow entries across all incidents" className="xl:col-span-5">
          {journal.length ? <DecisionTimeline entries={journal} /> : <LoadingState count={6} />}
        </Panel>
      </div>
    </PageContainer>
  )
}

/** Full journey of one incident: lifecycle + the six things NETRA remembers + timeline. */
function DecisionTrail({ id, asset }: { id: string; asset: Map<string, Asset> }) {
  const detail = useQuery(`memory-trail-${id}`, () => incidentService.get(id))
  const d = detail.data
  if (!d || d.incident.id !== id) {
    return (
      <SurfaceCard>
        <LoadingState count={8} />
      </SurfaceCard>
    )
  }
  const i: Incident = d.incident
  return (
    <SurfaceCard className="p-0">
      <div className="flex flex-wrap items-center gap-4 border-b border-border px-5 py-4">
        <RiskTile score={i.riskScore} severity={i.severity} size="lg" />
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[11px] text-muted-foreground">
            {i.id} · {asset.get(i.assetId)?.name} · first seen {formatDateTime(i.firstSeen)}
          </div>
          <h2 className="mt-0.5 text-lg font-semibold tracking-tight">{i.threatName}</h2>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to={ROUTES.incident(i.id)}>
            Open incident <ArrowRight />
          </Link>
        </Button>
      </div>

      <div className="border-b border-border px-5 py-5">
        <LifecycleStepper steps={buildLifecycle(d)} />
      </div>

      <div className="grid gap-px bg-border sm:grid-cols-2 lg:grid-cols-3">
        {rememberedFacts(d).map((f) => (
          <div key={f.q} className="bg-surface px-5 py-3.5">
            <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">{f.q}</div>
            <div className="mt-1 text-[13px] leading-snug text-foreground/90">{f.a}</div>
          </div>
        ))}
      </div>

      <div className="border-t border-border px-5 py-5">
        <DecisionTimeline entries={[...i.timeline].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))} />
      </div>
    </SurfaceCard>
  )
}

function rememberedFacts(d: IncidentDetail): { q: string; a: React.ReactNode }[] {
  const auth = d.authorization
  const c = d.containmentAction
  return [
    { q: 'What happened', a: d.incident.description },
    { q: 'Why prioritised', a: `Risk ${d.incident.riskScore} — ${decisionReasoning(d)}` },
    { q: 'Decision', a: recommendationHeadline(d) },
    {
      q: 'Who authorized',
      a: auth
        ? auth.status === 'APPROVED'
          ? `${auth.approver} (OTP verified) · ${auth.respondedAt ? formatDateTime(auth.respondedAt) : ''}`
          : `${auth.status.replace('_', ' ').toLowerCase()} — requested by ${auth.requestedBy}`
        : d.decision?.requiresAuthorization
          ? 'Not yet requested'
          : 'Not required',
    },
    { q: 'Action taken', a: c ? `${ACTION_LABEL[c.actionType]} ${c.target} · ${c.status.replace('_', ' ').toLowerCase()}` : 'None yet' },
    {
      q: 'Result',
      a: c?.verificationResult ?? (d.incident.status === 'FALSE_POSITIVE' ? 'Confirmed benign — suppressed in future' : 'Pending'),
    },
  ]
}

function MemoryRecord({ entry: m, asset }: { entry: CyberMemoryEntry; asset?: Asset }) {
  return (
    <article className="surface-inset flex flex-col rounded-lg p-4 transition-colors hover:border-violet/25">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[11px] text-violet">{m.id}</span>
        <StatusBadge status={m.outcome} size="sm" />
      </div>
      <Link to={ROUTES.incident(m.incidentId)} className="mt-2 text-sm font-medium hover:text-primary">
        {m.threatName}
      </Link>
      <div className="mt-0.5 text-[11px] text-muted-foreground">
        <span className="font-mono">{m.incidentId}</span> · {asset?.name ?? m.assetId} · risk {m.riskScore} · {timeAgo(m.recordedAt)}
      </div>
      <p className="mt-2.5 flex-1 text-xs leading-relaxed text-foreground/80">{m.lessonsLearned}</p>
      <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-border pt-2.5">
        <span className="rounded border border-border px-1.5 text-[10px] text-foreground/80">{ACTION_LABEL[m.actionTaken]}</span>
        {m.tags.map((t) => (
          <span key={t} className="rounded bg-foreground/5 px-1.5 text-[10px] text-muted-foreground">
            #{t}
          </span>
        ))}
        {m.similarIncidentIds.map((id) => (
          <Link key={id} to={ROUTES.incident(id)} className="ml-auto font-mono text-[10px] text-primary hover:underline">
            ↻ {id}
          </Link>
        ))}
      </div>
    </article>
  )
}
