import { ApiUnreachableError, buildRequestInit } from './httpRequest'

export { ApiUnreachableError }

/** Mock data is opt-in for local demos; production calls FastAPI by default. */
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === 'true'

/** The local FastAPI default applies to the dev server only; production builds must set VITE_API_BASE_URL. */
export const BASE_URL = (
  import.meta.env.VITE_API_BASE_URL?.trim() || (import.meta.env.DEV ? 'http://127.0.0.1:8000' : '')
).replace(/\/+$/, '')

/** Fired when the API rejects the stored token. */
export const AUTH_EXPIRED_EVENT = 'netra:auth-expired'

type Query = Record<string, string | number | boolean | undefined>

function buildUrl(path: string, query?: Query) {
  if (!BASE_URL) throw new Error('VITE_API_BASE_URL is not configured for this build.')
  const url = new URL(`${BASE_URL}/api${path}`)
  Object.entries(query ?? {}).forEach(([k, v]) => v !== undefined && url.searchParams.set(k, String(v)))
  return url.toString()
}

export class HttpError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'HttpError'
    this.status = status
  }
}

export function getAuthToken(): string | null {
  try {
    return localStorage.getItem('netra.token') ?? sessionStorage.getItem('netra.token')
  } catch {
    return null
  }
}

export function saveAuthToken(token: string, remember = true): void {
  // Production deployments should prefer a secure HttpOnly cookie/session to protect tokens from JavaScript-accessible XSS.
  localStorage.removeItem('netra.token')
  sessionStorage.removeItem('netra.token')
  ;(remember ? localStorage : sessionStorage).setItem('netra.token', token)
}

export function clearAuthToken(): void {
  localStorage.removeItem('netra.token')
  sessionStorage.removeItem('netra.token')
}

interface ValidationIssue {
  loc?: unknown[]
  msg?: unknown
}

/**
 * Readable text for a FastAPI error `detail`: a string as-is, or the list of validation issues
 * FastAPI returns for 422 responses as "field: message" pairs. Submitted input values are never echoed.
 */
export function errorMessage(detail: unknown): string | null {
  if (typeof detail === 'string') return detail || null
  if (!Array.isArray(detail)) return null
  const issues = detail.flatMap((item: ValidationIssue) => {
    if (!item || typeof item !== 'object' || typeof item.msg !== 'string') return []
    // Drop FastAPI's location prefix ("body", "query", "path", "header") so the field name leads.
    const loc = (item.loc ?? []).filter((part, index) => !(index === 0 && ['body', 'query', 'path', 'header'].includes(String(part))))
    return [loc.length ? `${loc.join('.')}: ${item.msg}` : item.msg]
  })
  return issues.length ? issues.join('; ') : null
}

async function request<T>(method: string, path: string, opts: { query?: Query; body?: unknown } = {}): Promise<T> {
  const token = getAuthToken()
  const url = buildUrl(path, opts.query)
  let res: Response
  try {
    res = await fetch(url, buildRequestInit(method, token, opts.body))
  } catch (cause) {
    // fetch rejects only when no response arrived; report that instead of a bare "Failed to fetch".
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiUnreachableError(BASE_URL, { cause })
  }
  if (!res.ok) {
    if (res.status === 401 && token) {
      // The stored session was rejected (expired or revoked): drop it so the route guards ask for sign-in.
      clearAuthToken()
      window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT))
    }
    const err = (await res.json().catch(() => null)) as { detail?: unknown } | null
    throw new HttpError(errorMessage(err?.detail) ?? `Request failed (${res.status})`, res.status)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const http = {
  get: <T>(path: string, query?: object) => request<T>('GET', path, { query: query as Query }),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, { body }),
  /** Multipart upload; the browser supplies the Content-Type and boundary. */
  postForm: <T>(path: string, form: FormData) => request<T>('POST', path, { body: form }),
}
