// Incident verification (PRIORITISED -> VERIFIED), the step that makes authorization approval possible.
// Dependency-free so it runs under `node --test`.

/**
 * Only a PRIORITISED incident can be verified (decision_workflow.verify_incident), and only with a current
 * decision: decisions can be recommended only while PRIORITISED, and authorization needs one, so verifying
 * first would strand the incident. `decisionCount` counts the incident's CURRENT decisions (see
 * `currentDecisions`); superseded and rejected decisions do not count.
 */
export function canVerifyIncident(state: string, decisionCount: number): boolean {
  return state === 'PRIORITISED' && decisionCount > 0
}

type DecisionValidity = 'CURRENT' | 'SUPERSEDED' | 'REJECTED'

/** The decisions that can still be verified against and authorized, oldest first (as the API lists them). */
export function currentDecisions<T extends { validity: DecisionValidity }>(decisions: readonly T[]): T[] {
  return decisions.filter((decision) => decision.validity === 'CURRENT')
}

/** The incident's latest decision when it is CURRENT; null when superseded or rejected, so summaries never present
 * an unusable decision's action, recommendation or confidence as the incident's own. */
export function currentLatestDecision<T extends { validity?: DecisionValidity }>(decision: T | null | undefined): T | null {
  return decision?.validity === 'CURRENT' ? decision : null
}

/** How a decision is labelled in the incident's decision list. */
export function decisionValidityLabel(validity: DecisionValidity, decisionScore: number, incidentScore: number | null): string {
  if (validity === 'CURRENT') return 'Current decision'
  if (validity === 'REJECTED') return 'Rejected · every authorization request for it was rejected'
  return `Superseded · made for risk ${decisionScore}; the incident's risk is now ${incidentScore ?? 'unscored'}`
}

/** Why verification is not offered although the incident is PRIORITISED with decisions, or null. */
export function verificationBlockedReason(state: string, decisions: readonly { validity: DecisionValidity }[]): string | null {
  if (state !== 'PRIORITISED' || decisions.length === 0 || currentDecisions(decisions).length > 0) return null
  return 'Verification needs a current decision. The existing decisions were superseded by a risk re-evaluation or rejected; recommend a new decision for the current risk score first.'
}

/** POST target for the existing `/api/incidents/{id}/verify` endpoint (the HTTP client adds `/api`). */
export function verifyIncidentPath(incidentId: string): string {
  return `/incidents/${encodeURIComponent(incidentId)}/verify`
}

/** A 409 means the incident is no longer PRIORITISED, so the page reloads to show the backend's state. */
export function shouldRefreshAfterVerifyError(status: number | null): boolean {
  return status === 409
}
