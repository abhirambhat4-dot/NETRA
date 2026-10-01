import type * as React from 'react'
import { useState } from 'react'
import { KeyRound, Loader2, ShieldCheck, ShieldX, UserCheck } from 'lucide-react'
import type { IncidentDetail } from '@/api/types'
import { KeyValueList, Panel, StatusBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp'
import { Textarea } from '@/components/ui/textarea'
import { useAction } from '@/hooks/useAction'
import { ACTION_LABEL, formatDateTime } from '@/lib/format'

import { DEMO_OTP_HINT, authorizationService } from '@/services'

/**
 * VERIFY — human-in-the-loop authorization.
 * UI SIMULATION: the OTP is a demo code; nothing is sent or enforced.
 */
export function AuthorizationPanel({ detail: d }: { detail: IncidentDetail }) {
  const { busy, run } = useAction()
  const [otp, setOtp] = useState('')
  const [rejecting, setRejecting] = useState(false)
  const [reason, setReason] = useState('')

  const decision = d.decision
  const auth = d.authorization
  const closed = d.incident.status === 'FALSE_POSITIVE' || d.incident.status === 'RESOLVED'

  const body = () => {
    if (!decision) return <Muted>No decision has been produced yet.</Muted>
    if (!decision.requiresAuthorization)
      return <Muted>Monitoring only — NETRA does not require authorization for passive actions.</Muted>
    if (closed && !auth) return <Muted>Incident closed without containment.</Muted>

    if (!auth || auth.status === 'REJECTED' || auth.status === 'EXPIRED') {
      return (
        <div className="space-y-3.5">
          {auth && (
            <div className="rounded-lg border border-critical/20 bg-critical/6 px-3.5 py-2.5 text-xs">
              <div className="font-medium text-critical">Previous request rejected</div>
              <div className="mt-0.5 text-muted-foreground">
                {auth.comment} · {auth.respondedAt && formatDateTime(auth.respondedAt)}
              </div>
            </div>
          )}
          <p className="text-[13px] text-foreground/85">
            <span className="font-medium">{ACTION_LABEL[decision.recommendedAction]}</span> on{' '}
            <span className="font-mono text-xs">{decision.target}</span> changes production systems and needs an approver.
          </p>
          <Button
            className="w-full"
            disabled={busy !== null}
            onClick={() => run('request', () => authorizationService.request(d.incident.id), 'Authorization requested — OTP sent to approver')}
          >
            {busy === 'request' ? <Loader2 className="animate-spin" /> : <UserCheck />}
            Request authorization
          </Button>
        </div>
      )
    }

    const facts = (
      <KeyValueList
        columns={2}
        items={[
          { label: 'Requested action', value: `${ACTION_LABEL[decision.recommendedAction]} ${decision.target}` },
          { label: 'Requested by', value: auth.requestedBy, mono: true },
          { label: 'Requested at', value: formatDateTime(auth.requestedAt) },
          { label: 'Approver', value: auth.approver ?? '—', mono: true },
        ]}
      />
    )

    if (auth.status === 'OTP_SENT' || auth.status === 'PENDING') {
      return (
        <div className="space-y-4">
          {facts}
          {!rejecting ? (
            <div className="surface-inset space-y-3 rounded-lg p-3.5">
              <div className="flex items-center gap-2 text-xs font-medium">
                <KeyRound className="size-3.5 text-primary" /> Approver verification
              </div>
              <InputOTP maxLength={6} value={otp} onChange={setOtp} aria-label="One-time password">
                <InputOTPGroup>
                  {Array.from({ length: 6 }, (_, i) => (
                    <InputOTPSlot key={i} index={i} className="size-9 font-mono" />
                  ))}
                </InputOTPGroup>
              </InputOTP>
              {DEMO_OTP_HINT && (
                <p className="text-[11px] text-muted-foreground">
                  Demo mode — use code <span className="font-mono text-foreground/85">{DEMO_OTP_HINT}</span>. Real OTP delivery arrives with the backend.
                </p>
              )}
              <div className="grid grid-cols-2 gap-2">
                <Button
                  disabled={otp.length !== 6 || busy !== null}
                  onClick={async () => {
                    const ok = await run('approve', () => authorizationService.verifyOtp(auth.id, otp), 'Authorization approved')
                    if (!ok) setOtp('')
                  }}
                >
                  {busy === 'approve' ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Approve
                </Button>
                <Button variant="outline" disabled={busy !== null} onClick={() => setRejecting(true)}>
                  <ShieldX /> Reject
                </Button>
              </div>
            </div>
          ) : (
            <div className="surface-inset space-y-3 rounded-lg p-3.5">
              <label htmlFor="reject-reason" className="text-xs font-medium">
                Reason for rejection
              </label>
              <Textarea
                id="reject-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="e.g. Source is an approved penetration test"
                className="min-h-20 text-[13px]"
              />
              <div className="grid grid-cols-2 gap-2">
                <Button variant="ghost" onClick={() => setRejecting(false)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  disabled={busy !== null || reason.trim().length < 3}
                  onClick={async () => {
                    await run('reject', () => authorizationService.reject(auth.id, reason.trim()), 'Authorization rejected')
                    setRejecting(false)
                  }}
                >
                  {busy === 'reject' && <Loader2 className="animate-spin" />} Confirm rejection
                </Button>
              </div>
            </div>
          )}
        </div>
      )
    }

    // APPROVED
    return (
      <div className="space-y-3.5">
        {facts}
        <div className="flex items-start gap-2.5 rounded-lg border border-low/20 bg-low/6 px-3.5 py-2.5 text-xs">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-low" />
          <div>
            <div className="font-medium text-low">Approved {auth.otpVerified && '· OTP verified'}</div>
            <div className="mt-0.5 text-muted-foreground">
              {auth.comment ?? 'Approver identity verified'} · {auth.respondedAt && formatDateTime(auth.respondedAt)}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <Panel
      title="Authorization gate"
      description="Human approval is required before any containment execution"
      actions={auth && <StatusBadge status={auth.status} size="sm" />}
    >
      {body()}
    </Panel>
  )
}

function Muted({ children }: { children: React.ReactNode }) {
  return <p className="text-[13px] text-muted-foreground">{children}</p>
}
