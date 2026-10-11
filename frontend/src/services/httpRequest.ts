/**
 * No response arrived from the API at all: the server is not running, the configured address is
 * wrong, or the browser blocked the request (for example CORS). Distinct from `HttpError`, which
 * always carries a status the API returned.
 */
export class ApiUnreachableError extends Error {
  readonly apiUrl: string

  constructor(apiUrl: string, options?: { cause?: unknown }) {
    super(`Cannot reach the NETRA API at ${apiUrl}.`, options)
    this.name = 'ApiUnreachableError'
    this.apiUrl = apiUrl
  }
}

/**
 * Builds the fetch options for an API request. Kept free of Vite and browser globals so it can be
 * tested directly with `node --test`.
 *
 * JSON bodies are serialised with a JSON Content-Type. FormData bodies are passed through with no
 * Content-Type, so the browser sets `multipart/form-data` with its own boundary.
 */
export function buildRequestInit(method: string, token: string | null, body?: unknown): RequestInit {
  const isForm = typeof FormData !== 'undefined' && body instanceof FormData
  return {
    method,
    headers: {
      ...(isForm ? {} : { 'Content-Type': 'application/json' }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
  }
}
