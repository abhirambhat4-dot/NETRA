import { Link } from 'react-router-dom'
import { BrainCircuit } from 'lucide-react'
import type { CyberMemoryEntry, IncidentDetail } from '@/api/types'
import { Panel, StatusBadge } from '@/components/netra'
import { ACTION_LABEL, timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'

/** LEARN — this incident's memory record, or what NETRA recalled from the past. */
export function MemoryPanel({ detail: d, memory }: { detail: IncidentDetail; memory: CyberMemoryEntry[] }) {
  const own = memory.find((m) => m.incidentId === d.incident.id)
  const recalled = memory.filter(
    (m) =>
      m.incidentId !== d.incident.id &&
      ((m.similarIncidentIds ?? []).includes(d.incident.id) || (m.mitreTechniqueId && m.mitreTechniqueId === d.incident.mitreTechniqueId)),
  )

  return (
    <Panel
      title="Cyber Memory"
      description={own ? 'Incident outcome → lesson → future decision support' : 'Related lessons recalled from prior incidents'}
      actions={
        <Link to={ROUTES.cyberMemory} className="text-xs text-muted-foreground transition-colors hover:text-primary">
          Open →
        </Link>
      }
    >
      <div className="space-y-3">
        {own && <MemoryCard entry={own} highlight />}
        {recalled.map((m) => (
          <MemoryCard key={m.id} entry={m} />
        ))}
        {!own && recalled.length === 0 && (
          <div className="flex items-start gap-2.5 text-xs text-muted-foreground">
            <BrainCircuit className="mt-0.5 size-4 shrink-0" />
            No Cyber Memory record exists for this incident yet. A lesson remains pending until an outcome is recorded.
          </div>
        )}
      </div>
    </Panel>
  )
}

function MemoryCard({ entry: m, highlight }: { entry: CyberMemoryEntry; highlight?: boolean }) {
  return (
    <div className={highlight ? 'rounded-lg border border-violet/25 bg-violet/6 p-3.5' : 'surface-inset rounded-lg p-3.5'}>
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[11px] text-muted-foreground">
          {m.id} · {timeAgo(m.recordedAt)}
        </span>
        {m.outcome === 'CONTAINED' ? (
          <StatusBadge status="CONTAINED" size="sm" />
        ) : m.outcome === 'FALSE_POSITIVE' ? (
          <StatusBadge status="FALSE_POSITIVE" size="sm" />
        ) : m.outcome === 'ESCALATED' ? (
          <StatusBadge status="ESCALATED" size="sm" />
        ) : (
          <span className="rounded-md border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
            {m.outcome ?? m.effectiveness ?? 'Outcome unavailable'}
          </span>
        )}
      </div>
      {!highlight && m.incidentId && (
        <Link to={ROUTES.incident(m.incidentId)} className="mt-1.5 block text-[13px] font-medium hover:text-primary">
          {m.threatName} <span className="font-mono text-[11px] text-muted-foreground">{m.incidentId}</span>
        </Link>
      )}
      {highlight && <div className="mt-2 text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">Recorded lesson</div>}
      <p className="mt-1.5 text-xs leading-relaxed text-foreground/80">{m.lessonsLearned}</p>
      <div className="mt-2 text-[11px] text-muted-foreground">
        Action: <span className="text-foreground/85">{m.actionTaken ? ACTION_LABEL[m.actionTaken as keyof typeof ACTION_LABEL] ?? m.actionTaken.replaceAll('_', ' ') : 'Unavailable'}</span> · risk {m.riskScore ?? 'unavailable'}
      </div>
    </div>
  )
}
