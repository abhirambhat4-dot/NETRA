import { Loader2, Play, ScanSearch } from 'lucide-react'
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
  const monitorOnly = decision?.recommendedAction === 'MONITOR'

  if (!decision || !decision.requiresAuthorization) {
    return <Panel title="Controlled response" description="Execution and independent verification are separate gates">
      <div className="grid gap-3 sm:grid-cols-2">
        <ResponseState title="Containment execution" state="Not required" detail={monitorOnly ? 'NETRA recommends monitoring; no containment action is planned.' : 'No containment recommendation is recorded.'} />
        <ResponseState title="Post-action verification" state="Not applicable" detail="There is no containment execution to verify." />
      </div>
    </Panel>
  }

  const approved = auth?.status === 'APPROVED'
  const executed = c?.status === 'EXECUTED' || c?.status === 'VERIFIED'
  const verificationFailed = c?.status === 'FAILED' || c?.status === 'ROLLED_BACK'
  const steps: LifecycleStep[] = [
    { key: 'auth', label: 'Authorized', state: approved ? 'done' : 'upcoming' },
    { key: 'exec', label: 'Executed', state: executed ? 'done' : verificationFailed || c?.status === 'IN_PROGRESS' || c?.status === 'PENDING' && approved ? 'current' : 'upcoming' },
    { key: 'verify', label: 'Verified', state: c?.status === 'VERIFIED' ? 'done' : verificationFailed ? 'skipped' : executed ? 'current' : 'upcoming' },
  ]
  const current = steps.find((s) => s.state === 'upcoming')
  if (current && !steps.some((step) => step.state === 'current')) current.state = 'current'

  return (
    <Panel
      title="Controlled response"
      description="Authorization gates execution; verification independently checks the result"
      actions={c && <StatusBadge status={c.status} size="sm" />}
    >
      <div className="space-y-4">
        <LifecycleStepper steps={steps} orientation="horizontal" />

        <KeyValueList columns={2} items={[
          { label: 'Recommended action', value: ACTION_LABEL[decision.recommendedAction] },
          { label: 'Target', value: decision.target, mono: true },
          { label: 'Authorization record', value: auth ? `${auth.id} · ${auth.status.replace('_', ' ').toLowerCase()}` : 'Not requested', mono: !!auth },
          { label: 'Containment record', value: c?.id ?? 'Not created', mono: !!c },
        ]} />

        <div className="grid gap-3 sm:grid-cols-2">
          <ResponseState
            title="Containment execution"
            state={c ? c.status.replace('_', ' ').toLowerCase() : approved ? 'Authorized · not executed' : 'Awaiting authorization'}
            detail={c?.executedAt ? `Execution recorded ${formatDateTime(c.executedAt)}` : c ? 'No execution timestamp was recorded.' : approved ? 'Approval is recorded, but no containment execution is recorded.' : 'No containment execution is recorded.'}
            tone={verificationFailed ? 'critical' : executed ? 'low' : 'neutral'}
          />
          <ResponseState
            title="Independent verification"
            state={c?.status === 'VERIFIED' ? 'Verified' : verificationFailed ? 'Not run' : executed ? 'Awaiting verification' : 'Pending execution'}
            detail={c?.status === 'VERIFIED'
              ? `${c.verifiedAt ? `Recorded ${formatDateTime(c.verifiedAt)} · ` : ''}${c.verificationResult ?? 'No result detail was recorded.'}`
              : verificationFailed
                ? 'The containment action did not complete successfully; no independent verification is recorded.'
                : 'Verification is a separate recorded step after containment execution.'}
            tone={c?.status === 'VERIFIED' ? 'low' : 'neutral'}
          />
        </div>

        {!c && (
          <p className="border-l-2 border-border pl-3 text-xs text-muted-foreground">
            {approved ? 'Authorization is recorded. No execution has occurred in the current mock state.' : 'A containment action remains locked until authorization is recorded.'}
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

      </div>
    </Panel>
  )
}

function ResponseState({ title, state, detail, tone = 'neutral' }: { title: string; state: string; detail: string; tone?: 'critical' | 'low' | 'neutral' }) {
  return (
    <section className="min-w-0 border-l border-border pl-3.5">
      <div className="text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">{title}</div>
      <div className={`mt-1 text-[13px] font-medium ${tone === 'critical' ? 'text-critical' : tone === 'low' ? 'text-low' : 'text-foreground/90'}`}>
        {state}
      </div>
      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{detail}</p>
    </section>
  )
}
