import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react'

interface AuthUser {
  username: string
  role: 'viewer' | 'analyst' | 'admin'
}

interface AuthState {
  user:        AuthUser | null
  accessToken: string | null
  isLoading:   boolean
}

interface AuthContextValue extends AuthState {
  login:    (username: string, password: string) => Promise<void>
  logout:   () => Promise<void>
  getToken: () => string | null
}

const AuthContext = createContext<AuthContextValue | null>(null)

const BASE         = import.meta.env.VITE_API_URL ?? 'http://localhost:8001'
export const AUTH_ENABLED = import.meta.env.VITE_AUTH_ENABLED === 'true'

const KEY_ACCESS  = 'nexussoc:access_token'
const KEY_REFRESH = 'nexussoc:refresh_token'
const KEY_USER    = 'nexussoc:user'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user:        null,
    accessToken: null,
    isLoading:   true,
  })

  // Restore session from localStorage on mount
  useEffect(() => {
    if (!AUTH_ENABLED) {
      setState({ user: { username: 'dev', role: 'admin' }, accessToken: null, isLoading: false })
      return
    }
    const token = localStorage.getItem(KEY_ACCESS)
    const raw   = localStorage.getItem(KEY_USER)
    if (token && raw) {
      try {
        setState({ user: JSON.parse(raw) as AuthUser, accessToken: token, isLoading: false })
        return
      } catch {
        // corrupted storage — clear and require login
      }
    }
    setState(s => ({ ...s, isLoading: false }))
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const res = await fetch(`${BASE}/auth/login`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }))
      throw new Error((err as { detail?: string }).detail ?? 'Login failed')
    }
    const data = await res.json() as {
      access_token: string; refresh_token: string; username: string; role: string
    }
    const user: AuthUser = { username: data.username, role: data.role as AuthUser['role'] }
    localStorage.setItem(KEY_ACCESS,  data.access_token)
    localStorage.setItem(KEY_REFRESH, data.refresh_token)
    localStorage.setItem(KEY_USER,    JSON.stringify(user))
    setState({ user, accessToken: data.access_token, isLoading: false })
  }, [])

  const logout = useCallback(async () => {
    const token = localStorage.getItem(KEY_ACCESS)
    if (token) {
      // Fire-and-forget — revoke on backend (best effort)
      fetch(`${BASE}/auth/logout`, {
        method:  'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {})
    }
    localStorage.removeItem(KEY_ACCESS)
    localStorage.removeItem(KEY_REFRESH)
    localStorage.removeItem(KEY_USER)
    setState({ user: null, accessToken: null, isLoading: false })
  }, [])

  const getToken = useCallback((): string | null => {
    if (!AUTH_ENABLED) return null
    return localStorage.getItem(KEY_ACCESS)
  }, [])

  return (
    <AuthContext.Provider value={{ ...state, login, logout, getToken }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
