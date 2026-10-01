import type * as React from 'react'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import { ArrowRight, BrainCircuit, ChevronDown, CircleCheck, Scale, ShieldAlert, ShieldCheck, UserCheck, Zap } from 'lucide-react'
import type { Asset, BackendMemoryEffectiveness, CyberMemoryEntry, IncidentDetail, MemoryOutcome } from '@/api/types'
import { DecisionTimeline, type TimelineItem } from '@/components/incidents/DecisionTimeline'
import { RiskTile } from '@/components/incidents/IncidentRow'
import {
  Disclosure,
  ErrorState,
  EmptyState,
  LifecycleStepper,
  LoadingState,
  MetricStrip,
  PageContainer,
  PageHeader,
  Panel,
  SearchInput,
  SelectFilter,
  StatusBadge,
  SurfaceCard,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { useCountUp } from '@/hooks/useCountUp'
import { ACTION_LABEL, formatDateTime, timeAgo } from '@/lib/format'
import { buildLifecycle, decisionReasoning, recommendationHeadline } from '@/lib/incident'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { assetService, incidentService, memoryService } from '@/services'
import { liveCyberMemoryService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'

const JOURNAL_PREVIEW = 5
const JOURNAL_MAX = 10
/** Mock outcomes are enums shown as badges; live outcomes are free-text results. */
const MEMORY_OUTCOMES: readonly string[] = ['CONTAINED', 'FALSE_POSITIVE', 'ESCALATED']

export function CyberMemoryPage() {
  return USE_MOCKS ? <MockCyberMemoryPage /> : <LiveCyberMemoryPage />
}

function LiveCyberMemoryPage() {
  const [search, setSearch] = useState('')
  const [effectiveness, setEffectiveness] = useState<BackendMemoryEffectiveness | 'ALL'>('ALL')
  const { data, error, reload } = useQuery(`live-cyber-memory-${search.trim()}-${effectiveness}`, () =>
    liveCyberMemoryService.listAll({
      search: search.trim() || undefined,
      effectiveness: effectiveness === 'ALL' ? undefined : effectiveness,
    }),
  )
  const filtered = data ?? []
  // Filtering is server-side, so an empty page only means "no data" when no filter is applied.
  const filtersActive = !!search.trim() || effectiveness !== 'ALL'
  const animatedCount = useCountUp(data?.length ?? 0, 650)
  return (
    <PageContainer>
      <PageHeader eyebrow="Learn" title="Cyber Memory" description="Backend records returned by the Cyber Memory API." actions={<ToneBadge tone="low" size="sm">Live API records</ToneBadge>} />
      <MetricStrip metrics={[{ label: 'Memory records', value: data ? Math.round(animatedCount) : '—', hint: 'lessons returned by the API' }]} />
      <Panel title="Knowledge records" description="Lessons and outcomes recorded by NETRA" flush>
        <LiveMemoryFilters
          search={search}
          onSearchChange={setSearch}
          effectiveness={effectiveness}
          onEffectivenessChange={setEffectiveness}
        />
        {error ? (
          <div>
            <ErrorState
              title={error instanceof HttpError && error.status === 401 ? 'Authentication required' : 'Cyber Memory unavailable'}
              message={error instanceof HttpError && error.status === 401 ? undefined : error.message}
              onRetry={error instanceof HttpError && error.status === 401 ? undefined : reload}
            />
            {error instanceof HttpError && error.status === 401 && (
              <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
            )}
          </div>
        ) : !data ? (
          <LoadingState className="px-5" count={4} />
        ) : filtered.length ? (
          <ul className="border-t border-border">
            {filtered.map((entry, index) => <MemoryRecord key={entry.id} entry={entry} entryIndex={index} />)}
          </ul>
        ) : (
          <EmptyState
            title={filtersActive ? 'No records match these filters' : 'No Cyber Memory records'}
            description={filtersActive ? 'Adjust the effectiveness filter or search terms.' : 'A memory record is created from a completed incident outcome; none are currently available.'}
          />
        )}
      </Panel>
    </PageContainer>
  )
}

function LiveMemoryFilters({
  search,
  onSearchChange,
  effectiveness,
  onEffectivenessChange,
}: {
  search: string
  onSearchChange: (value: string) => void
  effectiveness: BackendMemoryEffectiveness | 'ALL'
  onEffectivenessChange: (value: BackendMemoryEffectiveness | 'ALL') => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-y border-border px-5 py-3">
      <SearchInput
        value={search}
        onChange={onSearchChange}
        placeholder="Search lesson, outcome, incident…"
        className="w-full sm:w-80"
      />
      <SelectFilter
        label="Effectiveness"
        value={effectiveness}
        onChange={onEffectivenessChange}
        options={[
          { value: 'ALL', label: 'All effectiveness' },
          { value: 'EFFECTIVE', label: 'Effective' },
          { value: 'PARTIALLY_EFFECTIVE', label: 'Partially effective' },
          { value: 'INEFFECTIVE', label: 'Ineffective' },
          { value: 'UNKNOWN', label: 'Unknown' },
        ]}
      />
    </div>
  )
}

function MockCyberMemoryPage() {
  const [params, setParams] = useSearchParams()
  const [journalOpen, setJournalOpen] = useState(false)
  const [memorySearch, setMemorySearch] = useState('')
  const [memoryOutcome, setMemoryOutcome] = useState<MemoryOutcome | 'ALL'>('ALL')
  const memory = useQuery('memory-all', memoryService.list)
  const incidents = useQuery('memory-incidents', () => incidentService.list({ pageSize: 500 }))
  const assets = useQuery('memory-assets', assetService.list)

  const all = useMemo(
    () => [...(incidents.data?.items ?? [])].sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen)),
    [incidents.data],
  )
  const assetsById = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])
  const visibleMemory = filterMemoryEntries(memory.data ?? [], memorySearch, memoryOutcome)
  const selectedId = params.get('incident') ?? all.find((i) => i.memoryEntryId && i.status === 'CONTAINED')?.id ?? all[0]?.id

  const contained = all.filter((i) => i.containedAt)
  const mttc = contained.length
    ? Math.round(contained.reduce((s, i) => s + (Date.parse(i.containedAt!) - Date.parse(i.firstSeen)), 0) / contained.length / 60000)
    : 0
  const decisionsRecorded = all.filter((incident) => incident.decisionId !== null).length
  const authorizationsRecorded = all.filter((incident) => incident.authorizationId !== null).length
  const memoryAnimated = useCountUp(memory.data?.length ?? 0, 650)
  const decisionsAnimated = useCountUp(decisionsRecorded, 650)
  const authorizationsAnimated = useCountUp(authorizationsRecorded, 650)
  const containmentTimeAnimated = useCountUp(mttc, 850)

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
        actions={<ToneBadge tone="medium" size="sm">Demo enrichment</ToneBadge>}
      />

      <MetricStrip
        metrics={[
          {
            label: 'Memory records',
            value: memory.data ? Math.round(memoryAnimated) : '—',
            valueClassName: 'text-violet',
            hint: memory.data ? `${memory.data.filter((m) => m.outcome === 'FALSE_POSITIVE').length} false-positive lesson(s)` : 'lessons stored',
          },
          { label: 'Decisions recorded', value: incidents.data ? Math.round(decisionsAnimated) : '—', hint: `across ${all.length} incidents` },
          { label: 'Authorization records', value: incidents.data ? Math.round(authorizationsAnimated) : '—', hint: 'human approval gates recorded' },
          { label: 'Mean time to contain', value: contained.length ? `${Math.floor(containmentTimeAnimated / 60)}h ${Math.round(containmentTimeAnimated) % 60}m` : '—', hint: `${contained.length} contained incidents` },
        ]}
      />

      {/* Decision trail explorer */}
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Incidents" description="Select a decision trail" flush className="xl:col-span-4">
          {incidents.error ? (
            <ErrorState onRetry={incidents.reload} />
          ) : !incidents.data ? (
            <LoadingState className="px-5" count={8} />
          ) : all.length === 0 ? (
            <EmptyState title="No incidents yet" description="A decision trail appears here when incidents are available." />
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
        <Panel title="Knowledge records" description="Enriched mock lessons and outcomes · expand a record for details" flush className="xl:col-span-7">
          <MemoryFilters search={memorySearch} onSearchChange={setMemorySearch} outcome={memoryOutcome} onOutcomeChange={setMemoryOutcome} />
          {memory.error ? (
            <ErrorState onRetry={memory.reload} />
          ) : !memory.data ? (
            <LoadingState className="px-5" count={4} />
          ) : visibleMemory.length ? (
            <ul className="border-t border-border">
              {visibleMemory.map((m, index) => (
                <MemoryRecord key={m.id} entry={m} asset={m.assetId ? assetsById.get(m.assetId) : undefined} entryIndex={index} />
              ))}
            </ul>
          ) : (
              <EmptyState
                title={memory.data.length ? 'No records match these filters' : 'No Cyber Memory records'}
                description={memory.data.length ? 'Adjust the outcome filter or search terms.' : 'Memory is formed from recorded incident outcomes; no lessons are available yet.'}
              />
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
          {incidents.error ? (
            <ErrorState onRetry={incidents.reload} />
          ) : !incidents.data ? (
            <LoadingState count={6} />
          ) : journal.length ? (
            <DecisionTimeline entries={journalOpen ? journal : journal.slice(0, JOURNAL_PREVIEW)} />
          ) : (
            <EmptyState title="No workflow entries" description="Incident decisions and outcomes will appear in this journal when recorded." />
          )}
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
  if (detail.error) {
    return (
      <SurfaceCard>
        <ErrorState title="Decision trail unavailable" message={detail.error.message} onRetry={detail.reload} />
      </SurfaceCard>
    )
  }
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

function filterMemoryEntries(entries: CyberMemoryEntry[], search: string, outcome: MemoryOutcome | 'ALL') {
  const query = search.trim().toLowerCase()
  return entries.filter((entry) => {
    const matchesOutcome = outcome === 'ALL' || entry.outcome === outcome
    const matchesSearch = !query || [
      entry.id,
      entry.incidentId,
      entry.threatName,
      entry.lessonsLearned,
      entry.actionTaken,
      ...(entry.tags ?? []),
    ].some((value) => value?.toLowerCase().includes(query))
    return matchesOutcome && matchesSearch
  })
}

function MemoryFilters({
  search,
  onSearchChange,
  outcome,
  onOutcomeChange,
}: {
  search: string
  onSearchChange: (value: string) => void
  outcome: MemoryOutcome | 'ALL'
  onOutcomeChange: (value: MemoryOutcome | 'ALL') => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-y border-border px-5 py-3">
      <SearchInput value={search} onChange={onSearchChange} placeholder="Search lesson, incident, action, tag…" className="w-full sm:w-80" />
      <SelectFilter
        label="Outcome"
        value={outcome}
        onChange={onOutcomeChange}
        options={[
          { value: 'ALL', label: 'All outcomes' },
          { value: 'CONTAINED', label: 'Contained' },
          { value: 'FALSE_POSITIVE', label: 'False positive' },
          { value: 'ESCALATED', label: 'Escalated' },
        ]}
      />
    </div>
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
function MemoryRecord({ entry: m, asset, entryIndex = 0 }: { entry: CyberMemoryEntry; asset?: Asset; entryIndex?: number }) {
  const [open, setOpen] = useState(false)
  return (
    <li
      className="border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1"
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 40}ms` }}
    >
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
            <span className="text-[13px] font-medium">{m.threatName ?? 'Threat unavailable'}</span>
            <span className="font-mono text-[11px] text-violet">{m.id}</span>
          </div>
          <p className={cn('mt-1 text-xs leading-relaxed text-foreground/80', !open && 'line-clamp-1')}>{m.lessonsLearned}</p>
        </div>
        {m.outcome === 'CONTAINED' ? (
          <StatusBadge status="CONTAINED" size="sm" className="mt-0.5" />
        ) : m.outcome === 'FALSE_POSITIVE' ? (
          <StatusBadge status="FALSE_POSITIVE" size="sm" className="mt-0.5" />
        ) : m.outcome === 'ESCALATED' ? (
          <StatusBadge status="ESCALATED" size="sm" className="mt-0.5" />
        ) : (
          <span className="mt-0.5 shrink-0 rounded-md border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground capitalize">
            {m.effectiveness ? m.effectiveness.replaceAll('_', ' ').toLowerCase() : 'Outcome unavailable'}
          </span>
        )}
        <ChevronDown className={cn('mt-1 size-4 shrink-0 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>

      <div className="netra-disclosure-body" data-open={open}>
        <div inert={!open}>
          <div className="space-y-3 px-5 pb-4 pl-15">
            <div className="text-[11px] text-muted-foreground">
              {m.incidentId ? (
                <Link to={ROUTES.incident(m.incidentId)} className="font-mono text-foreground/85 hover:text-primary">
                  {m.incidentId}
                </Link>
              ) : 'Incident unavailable'}{' '}
              · {asset?.name ?? m.assetId ?? 'Asset unavailable'} · risk {m.riskScore ?? 'unavailable'} · recorded {timeAgo(m.recordedAt)}
            </div>
            {m.outcome && !MEMORY_OUTCOMES.includes(m.outcome) && (
              <p className="text-xs leading-relaxed text-foreground/80">
                <span className="text-muted-foreground">Outcome · </span>{m.outcome}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="rounded border border-border px-1.5 text-[10px] text-foreground/80">{m.actionTaken ? ACTION_LABEL[m.actionTaken as keyof typeof ACTION_LABEL] ?? m.actionTaken.replaceAll('_', ' ') : 'Action unavailable'}</span>
              {m.mitreTechniqueId && <span className="rounded border border-primary/20 bg-primary/8 px-1.5 font-mono text-[10px] text-primary">{m.mitreTechniqueId}</span>}
              {(m.tags ?? []).map((t) => (
                <span key={t} className="rounded bg-foreground/5 px-1.5 text-[10px] text-muted-foreground">
                  #{t}
                </span>
              ))}
            </div>
            {(m.similarIncidentIds ?? []).length > 0 && (
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                Reused for
                {(m.similarIncidentIds ?? []).map((id) => (
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
