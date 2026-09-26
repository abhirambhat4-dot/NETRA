import type { ContainmentActionType, IncidentDetail, RiskFactorKey } from '@/api/types'
import type { LifecycleStep } from '@/components/netra/LifecycleStepper'
import { formatDateTime } from './format'

/**
 * Pure helpers that turn an IncidentDetail into the NETRA workflow view.
 * Shared by Incident Details and Cyber Memory.
 */

export const ACTION_PHRASE: Record<ContainmentActionType, string> = {
  BLOCK_IP: 'block source IP',
  ISOLATE_HOST: 'isolate the endpoint',
  DISABLE_ACCOUNT: 'disable the account',
  RATE_LIMIT: 'rate-limit the source',
  MONITOR: 'monitor',
}

/** "Require authorization to block source IP 192.168.1.25" */
export function recommendationHeadline(d: IncidentDetail): string {
  if (!d.decision) return 'No recommendation yet'
  const phrase = `${ACTION_PHRASE[d.decision.recommendedAction]} ${d.decision.target}`
  if (d.decision.recommendedAction === 'MONITOR') return `Monitor ${d.decision.target} — no containment required`
  return d.decision.requiresAuthorization ? `Require authorization to ${phrase}` : phrase
}

const FACTOR_PHRASE: Record<RiskFactorKey, (d: IncidentDetail) => string> = {
  ASSET_CRITICALITY: (d) => `${d.asset.criticality.toLowerCase()} asset`,
  VULNERABILITY_SEVERITY: (d) => `CVSS ${d.riskAssessment?.cvss.toFixed(1)} vulnerability`,
  ANOMALY_NOVELTY: () => 'highly abnormal behaviour',
  DETECTION_CONFIDENCE: () => 'high-confidence detection',
  ATTACK_TECHNIQUE: (d) => `known technique ${d.mitreTechnique?.id ?? ''}`.trim(),
  THREAT_INTELLIGENCE: () => 'threat-intelligence correlation',
}

/** "Critical asset + external exposure + high-confidence detection + …" from the strongest factors. */
export function decisionReasoning(d: IncidentDetail): string {
  if (!d.riskAssessment) return ''
  const strong = [...d.riskAssessment.factors]
    .filter((f) => f.value >= 0.75)
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 4)
    .map((f) => FACTOR_PHRASE[f.key](d))
  if (d.asset.exposure === 'EXTERNAL') strong.splice(1, 0, 'external exposure')
  const parts = strong.length ? strong : ['moderate combined risk across factors']
  const text = parts.join(' + ')
  return text.charAt(0).toUpperCase() + text.slice(1) + '.'
}

const at = (iso?: string | null) => (iso ? formatDateTime(iso) : undefined)

/** DETECTED → UNDERSTOOD → PRIORITISED → VERIFIED → AUTHORIZED → CONTAINED → LEARNED */
export function buildLifecycle(d: IncidentDetail): LifecycleStep[] {
  const { incident: i, authorization: auth, containmentAction: cnt, decision } = d
  const tl = (stage: string) => i.timeline.find((t) => t.stage === stage)?.timestamp
  const falsePositive = i.status === 'FALSE_POSITIVE'
  const monitorOnly = decision?.recommendedAction === 'MONITOR'

  const steps: LifecycleStep[] = [
    { key: 'detected', label: 'Detected', state: 'done', time: at(i.firstSeen) },
    { key: 'understood', label: 'Understood', state: 'done', time: at(tl('UNDERSTAND')), detail: `${i.eventCount} events` },
    { key: 'prioritised', label: 'Prioritised', state: d.riskAssessment ? 'done' : 'upcoming', time: at(d.riskAssessment?.assessedAt), detail: `Risk ${i.riskScore}` },
  ]

  if (falsePositive) {
    steps.push(
      { key: 'verified', label: 'Verified', state: 'done', detail: 'Benign activity' },
      { key: 'authorized', label: 'Authorized', state: 'skipped', detail: 'Not required' },
      { key: 'contained', label: 'Contained', state: 'skipped', detail: 'Not required' },
    )
  } else if (monitorOnly) {
    steps.push(
      { key: 'verified', label: 'Verified', state: 'upcoming', detail: 'Analyst review' },
      { key: 'authorized', label: 'Authorized', state: 'skipped', detail: 'Monitoring only' },
      { key: 'contained', label: 'Contained', state: 'skipped', detail: 'Monitoring only' },
    )
  } else {
    steps.push(
      { key: 'verified', label: 'Verified', state: auth ? 'done' : 'upcoming', time: at(auth?.requestedAt), detail: auth ? 'Authorization requested' : 'Needs approval' },
      {
        key: 'authorized',
        label: 'Authorized',
        state: auth?.status === 'APPROVED' ? 'done' : auth?.status === 'REJECTED' ? 'skipped' : 'upcoming',
        time: at(auth?.respondedAt),
        detail: auth?.status === 'REJECTED' ? 'Rejected' : auth?.status === 'OTP_SENT' ? 'OTP pending' : auth?.approver ? `by ${auth.approver}` : undefined,
      },
      {
        key: 'contained',
        label: 'Contained',
        state: cnt?.status === 'VERIFIED' ? 'done' : 'upcoming',
        time: at(cnt?.verifiedAt ?? cnt?.executedAt),
        detail: cnt ? cnt.status.replace('_', ' ').toLowerCase() : undefined,
      },
    )
  }

  steps.push({ key: 'learned', label: 'Learned', state: i.memoryEntryId ? 'done' : 'upcoming', detail: i.memoryEntryId ?? undefined })

  const current = steps.find((s) => s.state === 'upcoming')
  if (current) current.state = 'current'
  return steps
}
