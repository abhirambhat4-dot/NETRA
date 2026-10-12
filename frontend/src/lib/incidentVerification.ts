// Incident verification (PRIORITISED -> VERIFIED), the step that makes authorization approval possible.
// Dependency-free so it runs under `node --test`.

/**
 * Only a PRIORITISED incident can be verified (decision_workflow.verify_incident), and only once a
 * decision is stored: decisions can be recommended only while PRIORITISED, and authorization needs
 * one, so verifying first would strand the incident. `decisionCount` is the length of the incident
 * detail's `decisions` list, which the API builds from persisted decision records.
 */
export function canVerifyIncident(state: string, decisionCount: number): boolean {
  return state === 'PRIORITISED' && decisionCount > 0
}

/** POST target for the existing `/api/incidents/{id}/verify` endpoint (the HTTP client adds `/api`). */
export function verifyIncidentPath(incidentId: string): string {
  return `/incidents/${encodeURIComponent(incidentId)}/verify`
}

/** A 409 means the incident is no longer PRIORITISED, so the page reloads to show the backend's state. */
export function shouldRefreshAfterVerifyError(status: number | null): boolean {
  return status === 409
}
