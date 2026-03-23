import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Monitor,
  Network,
  ListTodo,
  Puzzle,
  FileCode,
  Hammer,
  Radio,
  FileText,
  ChevronLeft,
  ChevronRight,
  Ghost,
  Circle,
} from 'lucide-react'
import { useCollaborationStore } from '@/store/collaborationStore'
import { OperatorStatus } from '@/gen/specter/v1/collaboration_pb'

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/sessions', icon: Monitor, label: 'Sessions' },
  { to: '/map', icon: Network, label: 'Session Map' },
  { to: '/tasks', icon: ListTodo, label: 'Tasks' },
  { to: '/modules', icon: Puzzle, label: 'Modules' },
  { to: '/profiles', icon: FileCode, label: 'Profiles' },
  { to: '/builder', icon: Hammer, label: 'Builder' },
  { to: '/redirectors', icon: Radio, label: 'Redirectors' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside
      className={`flex flex-col bg-specter-surface border-r border-specter-border transition-all duration-200 ${
        collapsed ? 'w-16' : 'w-56'
      }`}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 h-14 border-b border-specter-border">
        <Ghost className="w-6 h-6 text-specter-accent shrink-0" />
        {!collapsed && (
          <span className="text-sm font-bold tracking-wider text-specter-text">
            SPECTER
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2 mx-2 rounded text-sm transition-colors ${
                isActive
                  ? 'bg-specter-accent/10 text-specter-accent'
                  : 'text-specter-muted hover:text-specter-text hover:bg-specter-border/50'
              }`
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {!collapsed && <span>{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Online operators */}
      <OperatorPresenceList collapsed={collapsed} />

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center h-10 border-t border-specter-border text-specter-muted hover:text-specter-text transition-colors"
      >
        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
      </button>
    </aside>
  )
}

function statusColor(status: OperatorStatus): string {
  switch (status) {
    case OperatorStatus.ONLINE:
      return 'text-green-400'
    case OperatorStatus.IDLE:
      return 'text-yellow-400'
    case OperatorStatus.OFFLINE:
      return 'text-gray-500'
    default:
      return 'text-gray-500'
  }
}

function OperatorPresenceList({ collapsed }: { collapsed: boolean }) {
  const operators = useCollaborationStore((s) => s.operators)

  if (operators.length === 0) return null

  return (
    <div className="border-t border-specter-border py-2 px-2">
      {!collapsed && (
        <div className="px-2 pb-1 text-xs text-specter-muted uppercase tracking-wider">
          Operators ({operators.length})
        </div>
      )}
      {operators.map((op) => (
        <div
          key={op.operatorId}
          className="flex items-center gap-2 px-2 py-1 rounded text-sm"
          title={
            collapsed
              ? `${op.username}${op.activeSessionId ? ` — ${op.activeSessionId}` : ''}`
              : undefined
          }
        >
          <Circle
            className={`w-2 h-2 shrink-0 fill-current ${statusColor(op.status)}`}
          />
          {!collapsed && (
            <>
              <span className="text-specter-text truncate">{op.username}</span>
              {op.activeSessionId && (
                <span className="text-xs text-specter-muted truncate ml-auto">
                  {op.activeSessionId.slice(0, 8)}
                </span>
              )}
            </>
          )}
        </div>
      ))}
    </div>
  )
}
