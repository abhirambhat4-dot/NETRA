import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { SLOW_RESTORE_MESSAGE, SLOW_RESTORE_MESSAGE_DELAY_MS, shouldDiscardStoredSession } from '../src/auth/sessionRestore.ts'
import { ApiUnreachableError } from '../src/services/httpRequest.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

/** Same shape as HttpError in src/services/http.ts (not importable here: it reads Vite's import.meta.env). */
class StatusError extends Error {
  readonly status: number
  constructor(status: number) {
    super(`Request failed (${status})`)
    this.status = status
  }
}

// --- Fix 1: safe session restoration --------------------------------------------------------------

test('a genuine 401 discards the stored session', () => {
  assert.equal(shouldDiscardStoredSession(new StatusError(401)), true)
  assert.equal(shouldDiscardStoredSession({ status: 401 }), true)
})

test('a temporarily unreachable API keeps the stored session (cold start, network drop, CORS)', () => {
  assert.equal(shouldDiscardStoredSession(new ApiUnreachableError('https://api.example')), false)
  assert.equal(shouldDiscardStoredSession(new TypeError('Failed to fetch')), false)
  assert.equal(shouldDiscardStoredSession(new DOMException('The operation timed out.', 'TimeoutError')), false)
  assert.equal(shouldDiscardStoredSession(new DOMException('Aborted', 'AbortError')), false)
})

test('server and gateway errors keep the stored session; they say nothing about the token', () => {
  for (const status of [500, 502, 503, 504, 429, 404, 403, 400]) {
    assert.equal(shouldDiscardStoredSession(new StatusError(status)), false, String(status))
  }
})

test('anything that is not a 401 error keeps the stored session', () => {
  for (const value of [null, undefined, 'error', 401, { status: '401' }, {}, new Error('x')]) {
    assert.equal(shouldDiscardStoredSession(value), false, String(value))
  }
})

test('session restore clears the token only through that check; a 401 still signs out everywhere', () => {
  const provider = source('../src/auth/AuthProvider.tsx')
  const restore = provider.slice(provider.indexOf('.me()'), provider.indexOf('.finally('))
  assert.match(restore, /\.catch\(\(error: unknown\) => \{\s+\/\/[^\n]*\n\s+\/\/[^\n]*\n\s+if \(shouldDiscardStoredSession\(error\)\) clearAuthToken\(\)/)
  assert.equal((restore.match(/clearAuthToken\(\)/g) ?? []).length, 1)
  // The load is still not signed in after any failure, so protected routes still require sign-in.
  assert.match(restore, /setToken\(null\)\s+setUser\(null\)/)
  // Unchanged: every 401 on any request clears the token and tells the app the session expired.
  const http = source('../src/services/http.ts')
  assert.match(http, /if \(res\.status === 401 && token\) \{[\s\S]*?clearAuthToken\(\)\s+window\.dispatchEvent\(new Event\(AUTH_EXPIRED_EVENT\)\)/)
  // Unchanged: sign-in and sign-out handling.
  assert.match(provider, /async function login\([\s\S]*?catch \(error\) \{\s+clearAuthToken\(\)\s+setToken\(null\)\s+setUser\(null\)\s+throw error/)
  assert.match(provider, /function logout\(\) \{\s+clearAuthToken\(\)/)
  assert.match(provider, /isAuthenticated: user !== null/)
})

// --- Fix 2: informative loading state -------------------------------------------------------------

test('a slow session restore explains the wait after a few seconds', () => {
  assert.equal(SLOW_RESTORE_MESSAGE, 'Waking the NETRA server — this can take up to a minute.')
  assert.ok(SLOW_RESTORE_MESSAGE_DELAY_MS >= 2000 && SLOW_RESTORE_MESSAGE_DELAY_MS <= 10000, String(SLOW_RESTORE_MESSAGE_DELAY_MS))
})

test('the loading screen keeps its spinner and status role, uses one cleared timer and makes no requests', () => {
  const guards = source('../src/auth/RouteGuards.tsx')
  const loading = guards.slice(guards.indexOf('function AuthLoading()'), guards.indexOf('export function RequireAuth'))
  assert.match(loading, /role="status" aria-label="Restoring session"/)
  assert.match(loading, /<Loader2 className="size-5 animate-spin text-primary" \/>/)
  assert.match(loading, /const id = window\.setTimeout\(\(\) => setSlow\(true\), SLOW_RESTORE_MESSAGE_DELAY_MS\)\s+return \(\) => window\.clearTimeout\(id\)\s+\}, \[\]\)/)
  assert.match(loading, /\{slow && <p[^>]*>\{SLOW_RESTORE_MESSAGE\}<\/p>\}/)
  assert.doesNotMatch(loading, /fetch\(|useAuth|authService|setInterval|navigate/)
  // Both guards still show it only while the session is being restored.
  assert.equal((guards.match(/if \(loading\) return <AuthLoading \/>/g) ?? []).length, 2)
})
