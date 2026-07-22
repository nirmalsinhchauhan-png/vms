import { useEffect, useRef, useState, type ReactNode } from 'react'
import { apiJSON, configureApi } from '../lib/api'
import { AuthContext, type User } from './auth-context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const tokenRef = useRef<string | null>(null)

  useEffect(() => {
    configureApi({
      getToken: () => tokenRef.current,
      setToken: (t) => {
        tokenRef.current = t
      },
      onAuthFailure: () => {
        tokenRef.current = null
        setUser(null)
      },
    })
  }, [])

  useEffect(() => {
    // Silent refresh on mount: if the httpOnly refresh cookie is still
    // valid, this restores the session across a page reload with no
    // login prompt. /auth/refresh only returns a bare access token, so
    // /auth/me fills in who's actually logged in.
    let cancelled = false
    ;(async () => {
      try {
        const API_BASE = import.meta.env.VITE_API_BASE_URL
        const res = await fetch(`${API_BASE}/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
        })
        if (!res.ok) return
        const { access_token } = await res.json()
        tokenRef.current = access_token
        const me = await apiJSON<User>('/auth/me')
        if (!cancelled) setUser(me)
      } catch {
        // No valid session — stay logged out, not an error the user needs to see.
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  async function login(email: string, password: string) {
    const API_BASE = import.meta.env.VITE_API_BASE_URL
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: 'Login failed' }))
      throw new Error(body.error ?? 'Login failed')
    }
    const data = await res.json()
    tokenRef.current = data.access_token
    setUser(data.user)
  }

  async function logout() {
    try {
      await apiJSON('/auth/logout', { method: 'POST' })
    } finally {
      tokenRef.current = null
      setUser(null)
    }
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
  )
}
