import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  DUPLICATE_ACCOUNT_MESSAGE,
  REGISTRATION_CLOSED_MESSAGE,
  REGISTRATION_FAILED_MESSAGE,
  registerFailureMessage,
} from '../src/pages/login/registerError.ts'

const source = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

test('a 403 explains that self-registration is closed and who can create the account', () => {
  assert.equal(registerFailureMessage(403), REGISTRATION_CLOSED_MESSAGE)
  assert.match(REGISTRATION_CLOSED_MESSAGE, /administrator/)
})

test('a 409 keeps the existing duplicate-account message', () => {
  assert.equal(registerFailureMessage(409), 'An account with this email already exists.')
  assert.equal(DUPLICATE_ACCOUNT_MESSAGE, 'An account with this email already exists.')
})

test('other failures, and no response at all, keep the existing generic message', () => {
  for (const status of [null, 400, 422, 429, 500, 503]) {
    assert.equal(registerFailureMessage(status), REGISTRATION_FAILED_MESSAGE)
  }
  assert.equal(REGISTRATION_FAILED_MESSAGE, 'Unable to create your account right now. Please check your details and try again.')
})

test('the registration page shows these messages for failed sign-ups', () => {
  const page = source('../src/pages/RegisterPage.tsx')

  assert.match(page, /registerFailureMessage\(cause instanceof HttpError \? cause\.status : null\)/)
})
