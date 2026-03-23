import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Operator } from '@/gen/specter/v1/operators_pb'
import { OperatorRole } from '@/gen/specter/v1/operators_pb'

export type AuthMethod = 'mtls' | 'oauth2' | 'token' | null

export interface AuthState {
  /** Currently authenticated operator */
  operator: Operator | null
  /** Auth token for gRPC metadata */
  authToken: string | null
  /** How the user authenticated */
  authMethod: AuthMethod
  /** Whether auth is in progress */
  isAuthenticating: boolean
  /** Last auth error message */
  error: string | null

  // Actions
  setAuthenticated: (operator: Operator, token: string, method: AuthMethod) => void
  setAuthenticating: (val: boolean) => void
  setError: (error: string | null) => void
  logout: () => void
  isAuthenticated: () => boolean
  hasRole: (minRole: OperatorRole) => boolean
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      operator: null,
      authToken: null,
      authMethod: null,
      isAuthenticating: false,
      error: null,

      setAuthenticated: (operator, authToken, authMethod) =>
        set({ operator, authToken, authMethod, isAuthenticating: false, error: null }),

      setAuthenticating: (isAuthenticating) =>
        set({ isAuthenticating }),

      setError: (error) =>
        set({ error, isAuthenticating: false }),

      logout: () =>
        set({ operator: null, authToken: null, authMethod: null, error: null }),

      isAuthenticated: () => get().operator !== null && get().authToken !== null,

      hasRole: (minRole: OperatorRole) => {
        const op = get().operator
        if (!op) return false
        // Higher enum value = higher privilege (OBSERVER=1, OPERATOR=2, ADMIN=3)
        return op.role >= minRole
      },
    }),
    {
      name: 'specter-auth',
      partialize: (state) => ({
        authToken: state.authToken,
        authMethod: state.authMethod,
        // Operator is serialized without protobuf methods
        operator: state.operator
          ? { id: state.operator.id, username: state.operator.username, role: state.operator.role }
          : null,
      }),
    },
  ),
)
