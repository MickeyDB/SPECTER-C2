import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard,
  Monitor,
  Network,
  ListTodo,
  Puzzle,
  FileCode,
  Headphones,
  Hammer,
  Radio,
  Target,
  Users,
  Bell,
  Cloud,
  FileText,
  ChevronLeft,
  ChevronRight,
  Ghost,
  Circle,
} from 'lucide-react'
import { useCollaborationStore } from '@/store/collaborationStore'
import { OperatorStatus } from '@/gen/specter/v1/collaboration_pb'

interface NavItem {
  to: string
  icon: LucideIcon
  label: string
}

interface NavSection {
  title: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    title: 'Operations',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/sessions', icon: Monitor, label: 'Sessions' },
      { to: '/map', icon: Network, label: 'Session Map' },
      { to: '/tasks', icon: ListTodo, label: 'Tasks' },
    ],
  },
  {
    title: 'Arsenal',
    items: [
      { to: '/modules', icon: Puzzle, label: 'Modules' },
      { to: '/profiles', icon: FileCode, label: 'Profiles' },
      { to: '/builder', icon: Hammer, label: 'Builder' },
    ],
  },
  {
    title: 'Infrastructure',
    items: [
      { to: '/listeners', icon: Headphones, label: 'Listeners' },
      { to: '/redirectors', icon: Radio, label: 'Redirectors' },
      { to: '/azure-deaddrop', icon: Cloud, label: 'Dead Drop' },
    ],
  },
  {
    title: 'Management',
    items: [
      { to: '/campaigns', icon: Target, label: 'Campaigns' },
      { to: '/operators', icon: Users, label: 'Operators' },
      { to: '/webhooks', icon: Bell, label: 'Webhooks' },
      { to: '/reports', icon: FileText, label: 'Reports' },
    ],
  },
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
      <nav className="flex-1 overflow-y-auto py-1">
        {navSections.map((section, sIdx) => (
          <div key={section.title}>
            {sIdx > 0 && <div className="mx-4 my-1 h-px bg-specter-border/50" />}
            {!collapsed && (
              <div className="px-4 pt-2 pb-1 text-[10px] font-medium uppercase tracking-wider text-specter-muted/60">
                {section.title}
              </div>
            )}
            {section.items.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-1.5 mx-2 rounded text-sm transition-colors ${
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
          </div>
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
        <div className="px-2 pb-1 text-[10px] font-medium uppercase tracking-wider text-specter-muted/60">
          Online ({operators.length})
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
