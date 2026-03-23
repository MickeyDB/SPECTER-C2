import { Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import { OperatorRole } from '@/gen/specter/v1/operators_pb'

interface ProtectedRouteProps {
  children: React.ReactNode
  /** Minimum role required to access this route */
  minRole?: OperatorRole
}

/**
 * Route guard that redirects unauthenticated users to the login page.
 * Optionally enforces a minimum operator role for role-based access control.
 */
export function ProtectedRoute({ children, minRole }: ProtectedRouteProps) {
  const location = useLocation()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const hasRole = useAuthStore((s) => s.hasRole)

  if (!isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (minRole && !hasRole(minRole)) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-center">
          <h2 className="mb-2 text-lg font-medium text-specter-text">Access Denied</h2>
          <p className="text-sm text-specter-muted">
            You need at least {OperatorRole[minRole]} privileges to access this page.
          </p>
        </div>
      </div>
    )
  }

  return <>{children}</>
}
