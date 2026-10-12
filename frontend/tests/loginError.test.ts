import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { loginFailureMessage } from '../src/pages/login/loginError.ts'
import { ApiUnreachableError } from '../src/services/httpRequest.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

/** Stand-in for services/http.ts HttpError, which needs Vite's import.meta.env to load. */
class HttpError extends Error {
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'HttpError'
    this.status = status
  }
}

test('an unreachable API is reported as such, not as a generic sign-in failure', () => {
  // Regression: the dev server called http://127.0.0.1:8000 while the API ran on :8001, and the
  // connection failure was shown as "Unable to sign in right now".
  const cause = new ApiUnreachableError('http://127.0.0.1:8000', { cause: new TypeError('Failed to fetch') })
  assert.equal(cause.name, 'ApiUnreachableError')
  assert.equal(cause.apiUrl, 'http://127.0.0.1:8000')
  assert.equal(
    loginFailureMessage(cause, { showApiAddress: true }),
    'Cannot reach the NETRA API at http://127.0.0.1:8000. Check that the backend is running, then try again.',
  )
  assert.equal(loginFailureMessage(cause), 'Cannot reach the NETRA API. Check that the backend is running, then try again.')
})

test('API error statuses get specific, user-safe messages', () => {
  assert.equal(loginFailureMessage(new HttpError('email: value is not a valid email address', 422)), 'Enter a valid email address and password.')
  assert.equal(loginFailureMessage(new HttpError('Too many', 429)), 'Too many sign-in attempts. Wait a moment, then try again.')
  assert.equal(loginFailureMessage(new HttpError('Internal Server Error', 500)), 'The NETRA API could not complete sign-in. Please try again shortly.')
  assert.equal(loginFailureMessage(new HttpError('Bad gateway', 502)), 'The NETRA API could not complete sign-in. Please try again shortly.')
})

test('unrecognised failures fall back to the page\'s generic message', () => {
  assert.equal(loginFailureMessage(new HttpError('Invalid email or password', 401)), null)
  assert.equal(loginFailureMessage(new HttpError('Not found', 404)), null)
  assert.equal(loginFailureMessage(new TypeError('x is undefined')), null)
  assert.equal(loginFailureMessage('boom'), null)
  assert.equal(loginFailureMessage(undefined), null)
})

test('the HTTP client turns a failed fetch into ApiUnreachableError and the login page uses it', () => {
  const http = source('../src/services/http.ts')
  assert.match(http, /throw new ApiUnreachableError\(BASE_URL, \{ cause \}\)/)
  assert.match(http, /cause\.name === 'AbortError'\) throw cause/)
  const login = source('../src/pages/LoginPage.tsx')
  assert.match(login, /cause instanceof HttpError && cause\.status === 401\s*\? INVALID_CREDENTIALS\s*: loginFailureMessage\(cause, \{ showApiAddress: import\.meta\.env\.DEV \}\) \?\? 'Unable to sign in right now\. Please try again\.'/)
})
