// Dependency-free so it runs under `node --test` (tests/sessionRestore.test.ts).

/**
 * Whether a failed session restore (GET /api/auth/me with the stored token) means the stored session is
 * genuinely invalid. The API answers 401 for a missing, malformed, expired or revoked token and for a
 * deactivated account, so only a 401 discards it. An unreachable API (a cold start, a network drop),
 * a timeout or a server error says nothing about the token: it is kept, and the next load tries again.
 */
export function shouldDiscardStoredSession(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { status?: unknown }).status === 401
}

/** How long session restoration may take before the loading screen explains the wait. */
export const SLOW_RESTORE_MESSAGE_DELAY_MS = 4000

export const SLOW_RESTORE_MESSAGE = 'Waking the NETRA server — this can take up to a minute.'
