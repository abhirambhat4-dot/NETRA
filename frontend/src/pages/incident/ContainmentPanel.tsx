import { CheckCircle2, Loader2, Play, ScanSearch } from 'lucide-react'
import type { IncidentDetail } from '@/api/types'
import { KeyValueList, LifecycleStepper, Panel, StatusBadge, type LifecycleStep } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useAction } from '@/hooks/useAction'
import { ACTION_LABEL, formatDateTime } from '@/lib/format'
import { containmentService } from '@/services'

/**
 * CONTAIN — execution and verification of the authorized action.
 * UI SIMULATION ONLY: no system or network change is made.
 */
export function ContainmentPanel({ detail: d }: { detail: IncidentDetail }) {
  const { busy, run } = useAction()
  const decision = d.decision
  const auth = d.authorization
  const c = d.containmentAction

  if (!decision || !decision.requiresAuthorization) {
    return (
      <Panel title="Containment" description="Response action">
        <p className="text-[13px] text-muted-foreground">No containment planned — this incident is handled by monitoring.</p>
      </Panel>
    )
  }

  const approved = auth?.status === 'APPROVED'
  const steps: LifecycleStep[] = [
    { key: 'auth', label: 'Authorized', state: approved ? 'done' : 'upcoming' },
    { key: 'req', label: 'Requested', state: c ? 'done' : 'upcoming' },
    { key: 'exec', label: 'Executed', state: c && ['EXECUTED', 'VERIFIED'].includes(c.status) ? 'done' : 'upcoming' },
    { key: 'verify', label: 'Verified', state: c?.status === 'VERIFIED' ? 'done' : 'upcoming' },
  ]
  const current = steps.find((s) => s.state === 'upcoming')
  if (current) current.state = 'current'

  return (
    <Panel
      title="Containment"
      description="Simulated response — no real network change"
      actions={c && <StatusBadge status={c.status} size="sm" />}
    >
      <div className="space-y-4">
        <LifecycleStepper steps={steps} orientation="horizontal" />

        <KeyValueList
          columns={2}
          items={[
            { label: 'Action', value: ACTION_LABEL[c?.actionType ?? decision.recommendedAction] },
            { label: 'Target', value: c?.target ?? decision.target, mono: true },
            { label: 'Authorization', value: auth ? `${auth.id} · ${auth.status.replace('_', ' ').toLowerCase()}` : 'Not requested', mono: !!auth },
            { label: 'Executed', value: c?.executedAt ? formatDateTime(c.executedAt) : '—' },
          ]}
        />

        {!c && (
          <p className="rounded-lg border border-dashed border-border px-3.5 py-2.5 text-xs text-muted-foreground">
            {approved ? 'Preparing containment…' : 'Containment unlocks once the action is authorized.'}
          </p>
        )}

        {c && (c.status === 'PENDING' || c.status === 'IN_PROGRESS') && (
          <Button
            className="w-full"
            disabled={busy !== null}
            onClick={() => run('exec', () => containmentService.execute(c.id), `${ACTION_LABEL[c.actionType]} executed (simulated)`)}
          >
            {busy === 'exec' ? <Loader2 className="animate-spin" /> : <Play />}
            {c.status === 'IN_PROGRESS' ? 'Confirm execution' : `Execute ${ACTION_LABEL[c.actionType].toLowerCase()}`}
          </Button>
        )}

        {c?.status === 'EXECUTED' && (
          <Button
            className="w-full"
            disabled={busy !== null}
            onClick={() => run('verify', () => containmentService.verify(c.id), 'Containment verified — stored in Cyber Memory')}
          >
            {busy === 'verify' ? <Loader2 className="animate-spin" /> : <ScanSearch />}
            Run verification
          </Button>
        )}

        {c?.status === 'VERIFIED' && (
          <div className="flex items-start gap-2.5 rounded-lg border border-low/20 bg-low/6 px-3.5 py-2.5 text-xs">
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-low" />
            <div>
              <div className="font-medium text-low">Verified {c.verifiedAt && `· ${formatDateTime(c.verifiedAt)}`}</div>
              <div className="mt-0.5 text-muted-foreground">{c.verificationResult}</div>
            </div>
          </div>
        )}
      </div>
    </Panel>
  )
}
