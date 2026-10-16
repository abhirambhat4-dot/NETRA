import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { authService, type AuthUser, type RegisterRequest } from '@/services/auth'
import { AUTH_EXPIRED_EVENT, clearAuthToken, getAuthToken, saveAuthToken } from '@/services/http'
import { shouldDiscardStoredSession } from './sessionRestore'

interface AuthContextValue {
  user: AuthUser | null
  token: string | null
  isAuthenticated: boolean
  loading: boolean
  login: (email: string, password: string, remember?: boolean) => Promise<void>
  logout: () => void
  register: (request: RegisterRequest) => Promise<AuthUser>
  /** Re-reads the signed-in user (for example after a 403 suggests their role changed). */
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    const storedToken = getAuthToken()

    if (!storedToken) {
      setLoading(false)
      return () => {
        active = false
      }
    }

    setToken(storedToken)
    authService
      .me()
      .then((currentUser) => {
        if (active) setUser(currentUser)
      })
      .catch((error: unknown) => {
        // Only a rejected session (401) is discarded; an unreachable or failing API keeps the stored
        // token so the next load can restore it. Either way this load is not signed in.
        if (shouldDiscardStoredSession(error)) clearAuthToken()
        if (active) {
          setToken(null)
          setUser(null)
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    const expire = () => {
      setToken(null)
      setUser(null)
    }
    window.addEventListener(AUTH_EXPIRED_EVENT, expire)
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, expire)
  }, [])

  async function login(email: string, password: string, remember = true) {
    const result = await authService.login(email, password)
    saveAuthToken(result.access_token, remember)
    setToken(result.access_token)

    try {
      const currentUser = await authService.me()
      setUser(currentUser)
    } catch (error) {
      clearAuthToken()
      setToken(null)
      setUser(null)
      throw error
    }
  }

  function logout() {
    clearAuthToken()
    setToken(null)
    setUser(null)
  }

  async function register(request: RegisterRequest) {
    return authService.register(request)
  }

  async function refreshUser() {
    // A 401 here already signs the user out through AUTH_EXPIRED_EVENT; other failures keep the current user.
    try {
      setUser(await authService.me())
    } catch {
      // Keep the current user; the backend still enforces every permission.
    }
  }

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: user !== null, loading, login, logout, register, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}