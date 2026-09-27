import type * as React from 'react'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import { ArrowRight, BrainCircuit, ChevronDown, CircleCheck, Scale, ShieldAlert, ShieldCheck, UserCheck, Zap } from 'lucide-react'
import type { Asset, CyberMemoryEntry, IncidentDetail } from '@/api/types'
import { DecisionTimeline, type TimelineItem } from '@/components/incidents/DecisionTimeline'
import { RiskTile } from '@/components/incidents/IncidentRow'
import {
  Disclosure,
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

const JOURNAL_PREVIEW = 5
const JOURNAL_MAX = 10

export function CyberMemoryPage() {
  const [params, setParams] = useSearchParams()
  const [journalOpen, setJournalOpen] = useState(false)
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
    .slice(0, JOURNAL_MAX)

  return (
    <PageContainer>
      <PageHeader
        eyebrow="Learn"
        title="Cyber Memory"
        description="What happened, what NETRA decided, who authorized it, what ran, how it ended — and the lesson carried into the next response."
      />

      <MetricStrip
        metrics={[
          {
            label: 'Memory records',
            value: memory.data?.length ?? '—',
            valueClassName: 'text-violet',
            hint: memory.data ? `${memory.data.filter((m) => m.outcome === 'FALSE_POSITIVE').length} false-positive lesson(s)` : 'lessons stored',
          },
          { label: 'Decisions recorded', value: entries.length || '—', hint: `across ${all.length} incidents` },
          { label: 'Human authorizations', value: humanDecisions, hint: 'analyst / approver actions' },
          { label: 'Mean time to contain', value: mttc ? `${Math.floor(mttc / 60)}h ${mttc % 60}m` : '—', hint: `${contained.length} contained incidents` },
        ]}
      />

      {/* Decision trail explorer */}
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Incidents" description="Select a decision trail" flush className="xl:col-span-4">
          {!incidents.data ? (
            <LoadingState className="px-5" count={8} />
          ) : (
            <ul className="max-h-144 overflow-y-auto border-t border-border max-xl:max-h-80">
              {all.map((i) => (
                <li key={i.id}>
                  <button
                    type="button"
                    aria-pressed={selectedId === i.id}
                    onClick={() => setParams({ incident: i.id }, { replace: true })}
                    className={cn(
                      'relative flex w-full items-center gap-3 border-b border-border/70 px-5 py-2.5 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6',
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

        <div className="rounded-xl xl:col-span-8" data-guide-target="memory-trail">
          {selectedId ? (
            <DecisionTrail id={selectedId} assets={assetsById} memory={memory.data ?? []} />
          ) : (
            <SurfaceCard>
              <EmptyState title="No incidents yet" />
            </SurfaceCard>
          )}
        </div>
      </div>

      {/* Knowledge records + journal */}
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Knowledge records" description="Lessons NETRA reuses when prioritising similar incidents · expand a record for details" flush className="xl:col-span-7">
          {!memory.data ? (
            <LoadingState className="px-5" count={4} />
          ) : (
            <ul className="border-t border-border">
              {memory.data.map((m) => (
                <MemoryRecord key={m.id} entry={m} asset={assetsById.get(m.assetId)} />
              ))}
            </ul>
          )}
        </Panel>
        <Panel
          title="Decision journal"
          description="Latest workflow entries across all incidents"
          className="xl:col-span-5"
          actions={
            journal.length > JOURNAL_PREVIEW && (
              <Button variant="ghost" size="sm" className="text-muted-foreground" aria-expanded={journalOpen} onClick={() => setJournalOpen((o) => !o)}>
                {journalOpen ? 'Show less' : `Show ${journal.length - JOURNAL_PREVIEW} more`}
              </Button>
            )
          }
        >
          {journal.length ? <DecisionTimeline entries={journalOpen ? journal : journal.slice(0, JOURNAL_PREVIEW)} /> : <LoadingState count={6} />}
        </Panel>
      </div>
    </PageContainer>
  )
}

// ---------------------------------------------------------------------------
// Intelligence trail

type NodeState = 'done' | 'current' | 'pending' | 'skipped'

interface TrailNode {
  key: string
  label: string
  icon: LucideIcon
  state: NodeState
  title: React.ReactNode
  detail?: React.ReactNode
  memory?: boolean
}

function trailFor(d: IncidentDetail, lesson?: CyberMemoryEntry): TrailNode[] {
  const i = d.incident
  const auth = d.authorization
  const c = d.containmentAction
  const fp = i.status === 'FALSE_POSITIVE'
  const needsAuth = !!d.decision?.requiresAuthorization

  const nodes: TrailNode[] = [
    {
      key: 'incident',
      label: 'Incident',
      icon: ShieldAlert,
      state: 'done',
      title: `${i.threatName} · risk ${i.riskScore}`,
      detail: i.description,
    },
    {
      key: 'decision',
      label: 'Decision',
      icon: Scale,
      state: d.decision ? 'done' : 'pending',
      title: recommendationHeadline(d),
      detail: d.riskAssessment ? decisionReasoning(d) : undefined,
    },
    {
      key: 'authorization',
      label: 'Authorization',
      icon: UserCheck,
      state: !needsAuth || fp ? 'skipped' : auth?.status === 'APPROVED' ? 'done' : 'pending',
      title: auth
        ? auth.status === 'APPROVED'
          ? `Approved by ${auth.approver} · OTP verified`
          : `${auth.status.replace('_', ' ').toLowerCase()} — requested by ${auth.requestedBy}`
        : needsAuth && !fp
          ? 'Not yet requested'
          : 'Not required',
      detail: auth?.respondedAt ? formatDateTime(auth.respondedAt) : auth?.comment ?? undefined,
    },
    {
      key: 'action',
      label: 'Action',
      icon: Zap,
      state: c ? (['EXECUTED', 'VERIFIED'].includes(c.status) ? 'done' : 'pending') : fp || !needsAuth ? 'skipped' : 'pending',
      title: c ? `${ACTION_LABEL[c.actionType]} ${c.target}` : fp ? 'No containment — benign activity' : 'None yet',
      detail: c ? `${c.status.replace('_', ' ').toLowerCase()}${c.executedAt ? ` · ${formatDateTime(c.executedAt)}` : ''}` : undefined,
    },
    {
      key: 'outcome',
      label: 'Outcome',
      icon: ShieldCheck,
      state: c?.verificationResult || fp ? 'done' : 'pending',
      title: c?.verificationResult ?? (fp ? 'Confirmed benign — suppressed in future' : 'Pending verification'),
    },
    {
      key: 'lesson',
      label: 'Lesson',
      icon: BrainCircuit,
      state: lesson ? 'done' : 'pending',
      title: lesson ? lesson.lessonsLearned : 'Recorded once the incident is closed',
      detail: lesson ? `${lesson.id} · ${timeAgo(lesson.recordedAt)}` : undefined,
      memory: true,
    },
  ]
  const firstPending = nodes.find((n) => n.state === 'pending')
  if (firstPending) firstPending.state = 'current'
  return nodes
}

/** One incident's journey as a connected trail; lifecycle and raw audit log on demand. */
function DecisionTrail({ id, assets, memory }: { id: string; assets: Map<string, Asset>; memory: CyberMemoryEntry[] }) {
  const detail = useQuery(`memory-trail-${id}`, () => incidentService.get(id))
  const d = detail.data
  if (!d || d.incident.id !== id) {
    return (
      <SurfaceCard>
        <LoadingState count={8} />
      </SurfaceCard>
    )
  }
  const i = d.incident
  const nodes = trailFor(d, memory.find((m) => m.incidentId === i.id))

  return (
    <SurfaceCard className="p-0">
      <div className="flex flex-wrap items-center gap-4 border-b border-border px-5 py-4">
        <RiskTile score={i.riskScore} severity={i.severity} size="lg" />
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[11px] text-muted-foreground">
            {i.id} · {assets.get(i.assetId)?.name} · first seen {formatDateTime(i.firstSeen)}
          </div>
          <h2 className="mt-0.5 text-lg font-semibold tracking-tight">{i.threatName}</h2>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to={ROUTES.incident(i.id)}>
            Open incident <ArrowRight />
          </Link>
        </Button>
      </div>

      <ol key={i.id} className="px-5 py-5">
        {nodes.map((n, idx) => (
          <TrailStep key={n.key} node={n} last={idx === nodes.length - 1} index={idx} />
        ))}
      </ol>

      <div className="border-t border-border px-5 py-2">
        <Disclosure label="Full audit trail" hint={`${i.timeline.length} entries · lifecycle`}>
          <div className="space-y-6 pb-3">
            <LifecycleStepper steps={buildLifecycle(d)} />
            <DecisionTimeline entries={[...i.timeline].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))} />
          </div>
        </Disclosure>
      </div>
    </SurfaceCard>
  )
}

function TrailStep({ node: n, last, index }: { node: TrailNode; last: boolean; index: number }) {
  const done = n.state === 'done'
  return (
    <li
      className="relative grid grid-cols-[32px_minmax(0,1fr)] gap-x-4 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-left-1 motion-safe:fill-mode-both"
      style={{ animationDelay: `${index * 60}ms` }}
    >
      <div className="relative flex justify-center">
        {!last && (
          <span
            aria-hidden
            className={cn('absolute top-8 -bottom-1 w-px', done ? (n.memory ? 'bg-violet/40' : 'bg-linear-to-b from-primary/50 to-primary/25') : 'bg-border')}
          />
        )}
        <span
          className={cn(
            'relative grid size-8 place-items-center rounded-lg border transition-colors',
            done && !n.memory && 'border-primary/35 bg-primary/12 text-primary',
            done && n.memory && 'border-violet/40 bg-violet/12 text-violet shadow-[0_0_16px_-4px_rgb(139_92_246/0.6)]',
            n.state === 'current' && 'border-medium/40 bg-medium/10 text-medium',
            n.state === 'pending' && 'border-border bg-surface text-muted-foreground',
            n.state === 'skipped' && 'border-dashed border-border bg-surface text-muted-foreground/60',
          )}
        >
          <n.icon className="size-4" />
        </span>
      </div>
      <div className={cn('min-w-0', !last && 'pb-5')}>
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'text-[10px] font-semibold tracking-[0.16em] uppercase',
              done ? (n.memory ? 'text-violet' : 'text-foreground/80') : n.state === 'current' ? 'text-medium' : 'text-muted-foreground/70',
            )}
          >
            {n.label}
          </span>
          {done && <CircleCheck className={cn('size-3', n.memory ? 'text-violet' : 'text-primary/80')} aria-label="complete" />}
          {n.state === 'current' && <span className="text-[10px] text-medium">in progress</span>}
          {n.state === 'skipped' && <span className="text-[10px] text-muted-foreground/70">not required</span>}
        </div>
        <p className={cn('mt-1 text-[13px] leading-snug', done || n.state === 'current' ? 'text-foreground/90' : 'text-muted-foreground')}>{n.title}</p>
        {n.detail && <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-muted-foreground">{n.detail}</p>}
      </div>
    </li>
  )
}

// ---------------------------------------------------------------------------

/** Collapsed: what was learned. Expanded: action, tags and related incidents. */
function MemoryRecord({ entry: m, asset }: { entry: CyberMemoryEntry; asset?: Asset }) {
  const [open, setOpen] = useState(false)
  return (
    <li className="border-b border-border/70 last:border-b-0">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="group flex w-full items-start gap-3 px-5 py-3.5 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6"
      >
        <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-md border border-violet/25 bg-violet/8 text-violet">
          <BrainCircuit className="size-3.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-[13px] font-medium">{m.threatName}</span>
            <span className="font-mono text-[11px] text-violet">{m.id}</span>
          </div>
          <p className={cn('mt-1 text-xs leading-relaxed text-foreground/80', !open && 'line-clamp-1')}>{m.lessonsLearned}</p>
        </div>
        <StatusBadge status={m.outcome} size="sm" className="mt-0.5" />
        <ChevronDown className={cn('mt-1 size-4 shrink-0 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>

      <div className="netra-disclosure-body" data-open={open}>
        <div inert={!open}>
          <div className="space-y-3 px-5 pb-4 pl-15">
            <div className="text-[11px] text-muted-foreground">
              <Link to={ROUTES.incident(m.incidentId)} className="font-mono text-foreground/85 hover:text-primary">
                {m.incidentId}
              </Link>{' '}
              · {asset?.name ?? m.assetId} · risk {m.riskScore} · recorded {timeAgo(m.recordedAt)}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="rounded border border-border px-1.5 text-[10px] text-foreground/80">{ACTION_LABEL[m.actionTaken]}</span>
              {m.mitreTechniqueId && <span className="rounded border border-primary/20 bg-primary/8 px-1.5 font-mono text-[10px] text-primary">{m.mitreTechniqueId}</span>}
              {m.tags.map((t) => (
                <span key={t} className="rounded bg-foreground/5 px-1.5 text-[10px] text-muted-foreground">
                  #{t}
                </span>
              ))}
            </div>
            {m.similarIncidentIds.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                Reused for
                {m.similarIncidentIds.map((id) => (
                  <Link key={id} to={ROUTES.incident(id)} className="font-mono text-primary hover:underline">
                    ↻ {id}
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </li>
  )
}
