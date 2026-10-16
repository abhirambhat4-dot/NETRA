import { useEffect, useState, type ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { useAuth } from './AuthProvider'
import { postLoginPath } from './postLoginRedirect'
import { SLOW_RESTORE_MESSAGE, SLOW_RESTORE_MESSAGE_DELAY_MS } from './sessionRestore'
import { ROUTES } from '@/lib/navigation'

function AuthLoading() {
  // A sleeping API (a free-tier cold start) can hold the session check for up to a minute; after a few
  // seconds the wait is explained. One timer per mount, cleared on unmount; it makes no requests.
  const [slow, setSlow] = useState(false)
  useEffect(() => {
    const id = window.setTimeout(() => setSlow(true), SLOW_RESTORE_MESSAGE_DELAY_MS)
    return () => window.clearTimeout(id)
  }, [])

  return (
    <div className="grid min-h-svh place-items-center bg-background" role="status" aria-label="Restoring session">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="size-5 animate-spin text-primary" />
        {slow && <p className="max-w-xs px-4 text-center text-[13px] text-muted-foreground">{SLOW_RESTORE_MESSAGE}</p>}
      </div>
    </div>
  )
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated, loading } = useAuth()
  const location = useLocation()

  if (loading) return <AuthLoading />
  if (!isAuthenticated) return <Navigate to={ROUTES.login} replace state={{ from: location }} />
  return children
}

export function RedirectAuthenticated({ children }: { children: ReactNode }) {
  const { isAuthenticated, loading } = useAuth()
  const location = useLocation()
  if (loading) return <AuthLoading />
  // Same destination as LoginPage: right after sign-in this redirect races the page's own
  // navigate(), so both use postLoginPath (the safe protected route requested, else Command Home).
  if (isAuthenticated) return <Navigate to={postLoginPath(location.state)} replace />
  return children
}