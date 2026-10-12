import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ROLE_REQUIRED_TO_RESOLVE,
  SELF_APPROVAL_BLOCKED,
  forbiddenActionMessage,
  isSameActor,
  permissionExplanation,
  resolutionAccess,
  rolePermits,
} from '../src/lib/authorizationAccess.ts'

const REQUESTER = 'requester@example.com'
const operator = { email: 'operator@example.com', role: 'operator' }
const approver = { email: 'approver@example.com', role: 'approver' }
const admin = { email: 'admin@example.com', role: 'admin' }

// Same matrix as backend/app/core/permissions.py (workflow = OPERATE_WORKFLOW).
test('role permissions mirror the backend matrix', () => {
  assert.deepEqual(
    [operator, approver, admin].map((user) =>
      (['workflow', 'request', 'resolve', 'execute'] as const).map((p) => rolePermits(user, p)),
    ),
    [
      [true, true, false, true],
      [true, true, true, true],
      [true, true, true, true],
    ],
  )
})

test('unknown, mis-cased, inherited and missing roles grant nothing', () => {
  for (const role of ['viewer', 'Admin', 'APPROVER', '', 'constructor', '__proto__', 'toString']) {
    for (const permission of ['workflow', 'request', 'resolve', 'execute'] as const) {
      assert.equal(rolePermits({ email: 'x@example.com', role }, permission), false, `${role} ${permission}`)
    }
  }
  assert.equal(rolePermits(null, 'request'), false)
})

test('operator: Approve and Reject are withheld with a role explanation', () => {
  const access = resolutionAccess(operator, REQUESTER)

  assert.equal(access.canApprove, false)
  assert.equal(access.canReject, false)
  assert.ok(access.explanation?.startsWith('You are signed in as an operator.'))
  assert.ok(access.explanation?.includes(ROLE_REQUIRED_TO_RESOLVE))
})

test('operator who requested the authorization also cannot approve or reject it', () => {
  const access = resolutionAccess({ ...operator, email: REQUESTER }, REQUESTER)

  assert.deepEqual([access.canApprove, access.canReject], [false, false])
  assert.ok(access.explanation?.includes(ROLE_REQUIRED_TO_RESOLVE))
})

for (const user of [approver, admin]) {
  test(`${user.role}: a request made by someone else can be approved and rejected`, () => {
    assert.deepEqual(resolutionAccess(user, REQUESTER), { canApprove: true, canReject: true, explanation: null })
  })

  test(`${user.role}: their own request cannot be approved, only rejected`, () => {
    const access = resolutionAccess({ ...user, email: REQUESTER }, REQUESTER)

    assert.deepEqual(access, { canApprove: false, canReject: true, explanation: SELF_APPROVAL_BLOCKED })
  })
}

test('self-approval detection ignores case and surrounding spaces, as the backend does', () => {
  assert.equal(isSameActor(' Requester@Example.com ', REQUESTER), true)
  assert.equal(isSameActor('other@example.com', REQUESTER), false)
  assert.equal(resolutionAccess({ ...approver, email: 'REQUESTER@example.com' }, REQUESTER).canApprove, false)
})

test('signed-out or unknown-role users are offered no resolution and get an explanation', () => {
  const signedOut = resolutionAccess(null, REQUESTER)
  const viewer = resolutionAccess({ email: 'v@example.com', role: 'viewer' }, REQUESTER)

  assert.deepEqual([signedOut.canApprove, signedOut.canReject], [false, false])
  assert.ok(signedOut.explanation?.startsWith('Your account has no role.'))
  assert.ok(viewer.explanation?.startsWith('Your account role (viewer) is not recognised.'))
})

test('workflow, request and containment actions stay available to operators, approvers and admins', () => {
  for (const user of [operator, approver, admin]) {
    assert.equal(permissionExplanation(user, 'workflow'), null)
    assert.equal(permissionExplanation(user, 'request'), null)
    assert.equal(permissionExplanation(user, 'execute'), null)
  }
})

test('incident workflow steps (including verification) are explained, not offered, for an unknown role', () => {
  const viewer = { email: 'v@example.com', role: 'viewer' }

  assert.equal(
    permissionExplanation(viewer, 'workflow'),
    'Your account role (viewer) is not recognised. Advancing the incident workflow needs the operator, approver or admin role.',
  )
  assert.match(permissionExplanation(null, 'workflow') ?? '', /^Your account has no role\. Advancing the incident workflow/)
})

test('intake pages name their own action, and stay available to every recognised role', () => {
  const viewer = { email: 'v@example.com', role: 'viewer' }
  const actions = ['Validating dataset files', 'Running assessments', 'Submitting events', 'Creating incidents']

  for (const action of actions) {
    assert.equal(
      permissionExplanation(viewer, 'workflow', action),
      `Your account role (viewer) is not recognised. ${action} needs the operator, approver or admin role.`,
    )
    for (const user of [operator, approver, admin]) assert.equal(permissionExplanation(user, 'workflow', action), null)
  }
})

test('a 403 from a workflow step, such as verification, is shown with the backend reason', () => {
  const message = forbiddenActionMessage(403, 'Your role does not permit this action')

  assert.ok(message?.startsWith('NETRA refused this action: Your role does not permit this action.'))
})

test('request and containment actions are explained, not offered, for an unknown role', () => {
  const viewer = { email: 'v@example.com', role: 'viewer' }

  assert.match(permissionExplanation(viewer, 'request') ?? '', /Requesting authorization needs the operator, approver or admin role/)
  assert.match(permissionExplanation(viewer, 'execute') ?? '', /Running and verifying containment needs/)
})

test('a 403 shows the backend reason for a role refusal', () => {
  const message = forbiddenActionMessage(403, 'Your role does not permit this action')

  assert.ok(message?.startsWith('NETRA refused this action: Your role does not permit this action.'))
  assert.ok(message?.includes('Your access has been refreshed'))
})

test('a 403 shows the backend reason for a self-approval refusal', () => {
  const message = forbiddenActionMessage(403, 'An authorization cannot be approved by the user who requested it')

  assert.ok(message?.includes('cannot be approved by the user who requested it'))
})

test('a 403 without a usable detail gets a generic explanation', () => {
  assert.ok(forbiddenActionMessage(403, '   ')?.includes('your account is not permitted to perform it'))
  assert.ok(forbiddenActionMessage(403, null)?.includes('your account is not permitted to perform it'))
})

test('statuses other than 403 are left to the existing error handling', () => {
  for (const status of [400, 401, 404, 409, 422, 500, null]) {
    assert.equal(forbiddenActionMessage(status, 'detail'), null)
  }
})
