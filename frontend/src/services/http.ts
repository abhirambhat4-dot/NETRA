import type { ApiError } from '@/api/types'

/** true (default) → mock operational data; set VITE_USE_MOCKS=false to call FastAPI. */
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false'

export const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000').replace(/\/+$/, '')

type Query = Record<string, string | number | boolean | undefined>

function buildUrl(path: string, query?: Query) {
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

async function request<T>(method: string, path: string, opts: { query?: Query; body?: unknown } = {}): Promise<T> {
  const token = getAuthToken()
  const res = await fetch(buildUrl(path, opts.query), {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })
  if (!res.ok) {
    const err = (await res.json().catch(() => null)) as ApiError | null
    throw new HttpError(err?.detail ?? `Request failed (${res.status})`, res.status)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const http = {
  get: <T>(path: string, query?: object) => request<T>('GET', path, { query: query as Query }),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, { body }),
}
