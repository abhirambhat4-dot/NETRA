/**
 * User-facing text for a failed sign-in other than rejected credentials (LoginPage handles 401).
 * Import-free so tests/loginError.test.ts can load it with `node --test`; errors are recognised by
 * name and status rather than by class. Returns null for anything unrecognised, so the page keeps
 * its generic message. Never includes submitted values.
 */
export function loginFailureMessage(cause: unknown, opts: { showApiAddress?: boolean } = {}): string | null {
  if (!(cause instanceof Error)) return null

  if (cause.name === 'ApiUnreachableError') {
    const apiUrl = (cause as Error & { apiUrl?: unknown }).apiUrl
    const where = opts.showApiAddress && typeof apiUrl === 'string' && apiUrl ? ` at ${apiUrl}` : ''
    return `Cannot reach the NETRA API${where}. Check that the backend is running, then try again.`
  }

  const status = (cause as Error & { status?: unknown }).status
  if (typeof status !== 'number') return null
  if (status === 422) return 'Enter a valid email address and password.'
  if (status === 429) return 'Too many sign-in attempts. Wait a moment, then try again.'
  if (status >= 500) return 'The NETRA API could not complete sign-in. Please try again shortly.'
  return null
}
