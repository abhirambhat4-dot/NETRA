// Dependency-free so it runs under `node --test` (tests/postLoginRedirect.test.ts).

/** Default destination after sign-in: Command Home, the Live Tracking / Security Workspace choice. Equals ROUTES.commandHome. */
export const POST_LOGIN_DEFAULT = '/home'

/** Public or sign-in pages: never a destination to return to after signing in. */
const NO_RETURN = new Set(['/', '/login', '/register', '/forgot-password', '/reset-password'])

/**
 * Where to go after a successful sign-in. RequireAuth stores the protected route the user asked for as
 * `state.from` (a router location); it is used only when it is an in-app path. Anything else (missing,
 * malformed, protocol-relative, absolute URL, backslashes or control characters, or a public/sign-in page)
 * falls back to Command Home. LoginPage and RedirectAuthenticated both call this, so they always agree.
 */
export function postLoginPath(state: unknown): string {
  const from = typeof state === 'object' && state !== null ? (state as { from?: unknown }).from : undefined
  if (typeof from !== 'object' || from === null) return POST_LOGIN_DEFAULT
  const { pathname, search, hash } = from as { pathname?: unknown; search?: unknown; hash?: unknown }
  if (typeof pathname !== 'string' || !pathname.startsWith('/') || pathname.startsWith('//')) return POST_LOGIN_DEFAULT
  const rest = [search, hash].map((part) => (typeof part === 'string' ? part : ''))
  if ((rest[0] && !rest[0].startsWith('?')) || (rest[1] && !rest[1].startsWith('#'))) return POST_LOGIN_DEFAULT
  const target = pathname + rest[0] + rest[1]
  // No backslashes (some browsers read "/\evil" as "//evil"), whitespace or control characters.
  if (/[\\\s]/.test(target) || [...target].some((char) => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f)) {
    return POST_LOGIN_DEFAULT
  }
  // Must stay on this origin once resolved.
  let resolved: URL
  try {
    resolved = new URL(target, 'https://netra.invalid')
  } catch {
    return POST_LOGIN_DEFAULT
  }
  if (resolved.origin !== 'https://netra.invalid') return POST_LOGIN_DEFAULT
  const normalized = resolved.pathname.length > 1 ? resolved.pathname.replace(/\/+$/, '') : resolved.pathname
  if (NO_RETURN.has(normalized)) return POST_LOGIN_DEFAULT
  return resolved.pathname + resolved.search + resolved.hash
}
