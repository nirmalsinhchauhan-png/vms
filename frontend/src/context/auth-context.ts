import { createContext } from 'react'

export interface User {
  id: string
  email: string
  full_name: string
  role: string
}

export interface AuthContextValue {
  user: User | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
