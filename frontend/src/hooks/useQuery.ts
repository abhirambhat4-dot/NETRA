import { useCallback, useEffect, useState } from 'react'
import { DATA_CHANGED_EVENT } from '@/services'

interface QueryState<T> {
  data: T | undefined
  error: Error | undefined
  loading: boolean
  reload: () => void
}

/**
 * Minimal data-fetching hook for service calls.
 * `key` identifies the request — when it changes, the query re-runs.
 * Also refetches (keeping current data visible) after any service mutation.
 */
export function useQuery<T>(key: string, fetcher: () => Promise<T>): QueryState<T> {
  const [data, setData] = useState<T>()
  const [error, setError] = useState<Error>()
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(undefined)
    fetcher()
      .then((d) => !cancelled && setData(d))
      .catch((e: unknown) => !cancelled && setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
    // fetcher is intentionally excluded — `key` captures its inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, attempt])

  const reload = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    window.addEventListener(DATA_CHANGED_EVENT, reload)
    return () => window.removeEventListener(DATA_CHANGED_EVENT, reload)
  }, [reload])

  return { data, error, loading, reload }
}
