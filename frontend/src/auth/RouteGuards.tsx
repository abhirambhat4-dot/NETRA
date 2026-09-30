import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { useAuth } from './AuthProvider'
import { ROUTES } from '@/lib/navigation'

function AuthLoading() {
  return (
    <div className="grid min-h-svh place-items-center bg-background" role="status" aria-label="Restoring session">
      <Loader2 className="size-5 animate-spin text-primary" />
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
  if (loading) return <AuthLoading />
  if (isAuthenticated) return <Navigate to={ROUTES.dashboard} replace />
  return children
}