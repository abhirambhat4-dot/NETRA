import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { authService, type AuthUser, type RegisterRequest } from '@/services/auth'
import { clearAuthToken, getAuthToken, saveAuthToken } from '@/services/http'

interface AuthContextValue {
  user: AuthUser | null
  token: string | null
  isAuthenticated: boolean
  loading: boolean
  login: (email: string, password: string, remember?: boolean) => Promise<void>
  logout: () => void
  register: (request: RegisterRequest) => Promise<AuthUser>
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
      .catch(() => {
        clearAuthToken()
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

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: user !== null, loading, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}