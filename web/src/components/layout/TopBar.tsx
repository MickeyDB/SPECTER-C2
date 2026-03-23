import { useLocation } from 'react-router-dom'
import { Search, Bell, WifiOff } from 'lucide-react'
import { useOffline } from '@/hooks/useOffline'

const breadcrumbMap: Record<string, string> = {
  dashboard: 'Dashboard',
  sessions: 'Sessions',
  map: 'Session Map',
  tasks: 'Task Timeline',
  modules: 'Modules',
  profiles: 'Profile Editor',
  redirectors: 'Redirectors',
}

export function TopBar() {
  const location = useLocation()
  const { isOnline } = useOffline()
  const segments = location.pathname.split('/').filter(Boolean)
  const crumbs = segments.map((s) => breadcrumbMap[s] ?? s)

  return (
    <header className="flex items-center justify-between h-14 px-6 border-b border-specter-border bg-specter-surface">
      {/* Breadcrumbs */}
      <div className="flex items-center gap-2 text-sm">
        {crumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-2">
            {i > 0 && <span className="text-specter-border">/</span>}
            <span className={i === crumbs.length - 1 ? 'text-specter-text' : 'text-specter-muted'}>
              {crumb}
            </span>
          </span>
        ))}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-4">
        {!isOnline && (
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-500/20 text-amber-400 text-xs font-medium"
            data-testid="offline-indicator"
          >
            <WifiOff className="w-3.5 h-3.5" />
            Offline
          </div>
        )}
        <button className="p-2 rounded text-specter-muted hover:text-specter-text hover:bg-specter-border/50 transition-colors">
          <Search className="w-4 h-4" />
        </button>
        <button className="p-2 rounded text-specter-muted hover:text-specter-text hover:bg-specter-border/50 transition-colors">
          <Bell className="w-4 h-4" />
        </button>
      </div>
    </header>
  )
}
