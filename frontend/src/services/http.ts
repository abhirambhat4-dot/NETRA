import type { ApiError } from '@/api/types'

/** true (default) → mock data; set VITE_USE_MOCKS=false to call FastAPI. */
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false'

export const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1'

type Query = Record<string, string | number | boolean | undefined>

function buildUrl(path: string, query?: Query) {
  const url = new URL(BASE_URL + path)
  Object.entries(query ?? {}).forEach(([k, v]) => v !== undefined && url.searchParams.set(k, String(v)))
  return url.toString()
}

async function request<T>(method: string, path: string, opts: { query?: Query; body?: unknown } = {}): Promise<T> {
  const token = localStorage.getItem('netra.token')
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
    throw new Error(err?.detail ?? `Request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

export const http = {
  get: <T>(path: string, query?: object) => request<T>('GET', path, { query: query as Query }),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, { body }),
}
