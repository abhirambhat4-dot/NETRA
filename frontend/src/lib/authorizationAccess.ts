// Which authorization-workflow actions the signed-in user is offered, mirroring the backend role rules
// (backend/app/core/permissions.py). Presentation only: the API enforces every rule and stays
// authoritative. Dependency-free so it runs under `node --test`.

export type WorkflowPermission = 'workflow' | 'request' | 'resolve' | 'execute'

/**
 * workflow = incident lifecycle and intake writes (enrich, correlate, score, decide, verify, Cyber Memory);
 * request = request authorization; resolve = approve or reject; execute = run and verify containment.
 */
const ROLE_PERMISSIONS: Record<string, readonly WorkflowPermission[]> = {
  operator: ['workflow', 'request', 'execute'],
  approver: ['workflow', 'request', 'resolve', 'execute'],
  admin: ['workflow', 'request', 'resolve', 'execute'],
}

export interface SignedInUser {
  email: string
  role: string
}

/** Roles are matched exactly, as the backend does; an unknown role grants nothing. */
function permissionsFor(role: string | undefined): readonly WorkflowPermission[] | null {
  return role && Object.hasOwn(ROLE_PERMISSIONS, role) ? ROLE_PERMISSIONS[role] : null
}

export function rolePermits(user: SignedInUser | null, permission: WorkflowPermission): boolean {
  return permissionsFor(user?.role)?.includes(permission) ?? false
}

/** Actors are user emails; the backend compares them ignoring case and surrounding spaces. */
export function isSameActor(first: string | null | undefined, second: string | null | undefined): boolean {
  return (first ?? '').trim().toLowerCase() === (second ?? '').trim().toLowerCase()
}

function roleLabel(user: SignedInUser | null): string {
  if (!user?.role) return 'Your account has no role'
  if (!permissionsFor(user.role)) return `Your account role (${user.role}) is not recognised`
  return `You are signed in as ${user.role === 'operator' || user.role === 'admin' ? 'an' : 'a'} ${user.role}`
}

export const ROLE_REQUIRED_TO_RESOLVE = 'Approving or rejecting needs the approver or admin role.'
export const SELF_APPROVAL_BLOCKED =
  'You requested this authorization, so a different approver or admin must approve it.'

export interface ResolutionAccess {
  canApprove: boolean
  canReject: boolean
  /** Shown when Approve or Reject is withheld; null when both are offered. */
  explanation: string | null
}

/** Approve and Reject for a PENDING authorization requested by `requestedBy`. */
export function resolutionAccess(user: SignedInUser | null, requestedBy: string): ResolutionAccess {
  if (!rolePermits(user, 'resolve')) {
    return {
      canApprove: false,
      canReject: false,
      explanation: `${roleLabel(user)}. ${ROLE_REQUIRED_TO_RESOLVE} Ask an approver or admin to review this request.`,
    }
  }
  if (isSameActor(user?.email, requestedBy)) {
    // Rejecting your own request is allowed by the backend: it only withdraws the requested action.
    return { canApprove: false, canReject: true, explanation: SELF_APPROVAL_BLOCKED }
  }
  return { canApprove: true, canReject: true, explanation: null }
}

const ACTION_LABEL: Record<Exclude<WorkflowPermission, 'resolve'>, string> = {
  workflow: 'Advancing the incident workflow',
  request: 'Requesting authorization',
  execute: 'Running and verifying containment',
}

/**
 * Explanation when a workflow, request or containment action is withheld for the user's role; null when offered.
 * `action` names the specific action (for example "Running assessments") in place of the permission's default label.
 */
export function permissionExplanation(
  user: SignedInUser | null,
  permission: Exclude<WorkflowPermission, 'resolve'>,
  action: string = ACTION_LABEL[permission],
): string | null {
  if (rolePermits(user, permission)) return null
  return `${roleLabel(user)}. ${action} needs the operator, approver or admin role.`
}

/**
 * Message for an action the API refused with 403. The backend detail (a role or self-approval refusal)
 * is shown as returned; anything else gets a generic explanation. Returns null for other statuses.
 */
export function forbiddenActionMessage(status: number | null, detail: string | null | undefined): string | null {
  if (status !== 403) return null
  const reason = detail?.trim()
  return `NETRA refused this action: ${reason || 'your account is not permitted to perform it'}. ` +
    'Your access has been refreshed; contact an administrator if you need a different role.'
}
