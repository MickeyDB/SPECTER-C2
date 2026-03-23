import { useEffect, useCallback } from 'react'
import { useAuthStore } from '@/store/authStore'
import type { AuthMethod } from '@/store/authStore'
import { specterClient } from '@/lib/client'
import { AuthContext } from './AuthContext'
import type { AuthContextValue } from './AuthContext'

interface AuthProviderProps {
  children: React.ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const store = useAuthStore()

  const loginWithToken = useCallback(async (username: string, token: string): Promise<boolean> => {
    store.setAuthenticating(true)
    try {
      const res = await specterClient.authenticate({ username, token })
      if (res.success && res.operator) {
        const method: AuthMethod = 'token'
        store.setAuthenticated(res.operator, res.authToken, method)
        return true
      }
      store.setError('Authentication failed: invalid credentials')
      return false
    } catch (err) {
      store.setError(err instanceof Error ? err.message : 'Authentication failed')
      return false
    }
  }, [store])

  const loginWithOAuth = useCallback(async (accessToken: string): Promise<boolean> => {
    store.setAuthenticating(true)
    try {
      const res = await specterClient.authenticate({
        username: '',
        token: accessToken,
      })
      if (res.success && res.operator) {
        store.setAuthenticated(res.operator, res.authToken, 'oauth2')
        return true
      }
      store.setError('OAuth authentication failed')
      return false
    } catch (err) {
      store.setError(err instanceof Error ? err.message : 'OAuth authentication failed')
      return false
    }
  }, [store])

  const logout = useCallback(() => {
    store.logout()
  }, [store])

  // Try to re-validate existing token on mount
  useEffect(() => {
    const token = store.authToken
    if (token && !store.operator) {
      specterClient.authenticate({ username: '', token })
        .then((res) => {
          if (res.success && res.operator) {
            store.setAuthenticated(res.operator, res.authToken, store.authMethod)
          } else {
            store.logout()
          }
        })
        .catch(() => store.logout())
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const value: AuthContextValue = {
    loginWithToken,
    loginWithOAuth,
    logout,
    operator: store.operator,
    isAuthenticated: store.isAuthenticated(),
    isAuthenticating: store.isAuthenticating,
    error: store.error,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
