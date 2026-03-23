import { createContext } from 'react'
import type { Operator } from '@/gen/specter/v1/operators_pb'

export interface AuthContextValue {
  loginWithToken: (username: string, token: string) => Promise<boolean>
  loginWithCert: (username: string, token: string) => Promise<boolean>
  loginWithOAuth: (accessToken: string) => Promise<boolean>
  logout: () => void
  operator: Operator | null
  isAuthenticated: boolean
  isAuthenticating: boolean
  error: string | null
}

export const AuthContext = createContext<AuthContextValue | null>(null)
