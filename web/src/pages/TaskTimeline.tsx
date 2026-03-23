import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  Clock,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Download,
  Filter,
  Search,
  CheckCircle,
  XCircle,
  Loader,
  Send,
  User,
  Monitor,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import { TaskStatus } from '@/gen/specter/v1/tasks_pb'
import type { Task } from '@/gen/specter/v1/tasks_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'

// ── Types ──────────────────────────────────────────────────────────────

type TaskCategory = 'recon' | 'lateral' | 'injection' | 'exfil' | 'persistence' | 'other'

interface TimelineEntry {
  task: Task
  sessionHostname: string
  sessionUsername: string
  category: TaskCategory
}

// ── Helpers ────────────────────────────────────────────────────────────

function categorizeTask(taskType: string): TaskCategory {
  const t = taskType.toLowerCase()
  if (['whoami', 'ipconfig', 'netstat', 'ps', 'ls', 'dir', 'env', 'sysinfo', 'arp', 'route', 'hostname'].some(k => t.includes(k))) return 'recon'
  if (['psexec', 'wmi', 'ssh', 'pivot', 'lateral', 'jump', 'dcom', 'winrm'].some(k => t.includes(k))) return 'lateral'
  if (['inject', 'shellcode', 'dll', 'load', 'spawn', 'execute-assembly', 'bof'].some(k => t.includes(k))) return 'injection'
  if (['download', 'exfil', 'upload', 'steal', 'dump', 'keylog', 'screenshot'].some(k => t.includes(k))) return 'exfil'
  if (['persist', 'registry', 'service', 'scheduled', 'startup'].some(k => t.includes(k))) return 'persistence'
  return 'other'
}

const categoryColors: Record<TaskCategory, string> = {
  recon: 'border-specter-info bg-specter-info/10 text-specter-info',
  lateral: 'border-status-stale bg-status-stale/10 text-status-stale',
  injection: 'border-specter-danger bg-specter-danger/10 text-specter-danger',
  exfil: 'border-purple-500 bg-purple-500/10 text-purple-400',
  persistence: 'border-teal-500 bg-teal-500/10 text-teal-400',
  other: 'border-specter-muted bg-specter-muted/10 text-specter-muted',
}

const categoryDotColors: Record<TaskCategory, string> = {
  recon: 'bg-specter-info',
  lateral: 'bg-status-stale',
  injection: 'bg-specter-danger',
  exfil: 'bg-purple-500',
  persistence: 'bg-teal-500',
  other: 'bg-specter-muted',
}

const statusConfig: Record<number, { label: string; icon: typeof CheckCircle; color: string }> = {
  [TaskStatus.QUEUED]: { label: 'Queued', icon: Clock, color: 'text-specter-muted' },
  [TaskStatus.DISPATCHED]: { label: 'Dispatched', icon: Send, color: 'text-specter-info' },
  [TaskStatus.COMPLETE]: { label: 'Complete', icon: CheckCircle, color: 'text-status-active' },
  [TaskStatus.FAILED]: { label: 'Failed', icon: XCircle, color: 'text-specter-danger' },
}

function formatTimestamp(seconds: bigint | undefined): string {
  if (seconds === undefined) return 'N/A'
  const d = new Date(Number(seconds) * 1000)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

function decodeResult(result: Uint8Array): string {
  if (!result || result.length === 0) return ''
  try {
    return new TextDecoder().decode(result)
  } catch {
    return `[${result.length} bytes]`
  }
}

function generateMarkdownExport(entries: TimelineEntry[]): string {
  const lines: string[] = [
    '# SPECTER Task Timeline Export',
    `Generated: ${new Date().toISOString()}`,
    '',
    '| Time | Operator | Target | Task | Category | Status | Result |',
    '|------|----------|--------|------|----------|--------|--------|',
  ]

  for (const e of entries) {
    const time = e.task.createdAt ? formatTimestamp(e.task.createdAt.seconds) : 'N/A'
    const status = statusConfig[e.task.status]?.label ?? 'Unknown'
    const result = decodeResult(e.task.result).slice(0, 100).replace(/\|/g, '\\|').replace(/\n/g, ' ')
    lines.push(
      `| ${time} | ${e.task.operatorId || 'N/A'} | ${e.sessionHostname}\\\\${e.sessionUsername} | ${e.task.taskType} | ${e.category} | ${status} | ${result || '-'} |`
    )
  }

  return lines.join('\n')
}

// ── Components ─────────────────────────────────────────────────────────

function TimelineEntryRow({
  entry,
  expanded,
  onToggle,
  onNavigateSession,
}: {
  entry: TimelineEntry
  expanded: boolean
  onToggle: () => void
  onNavigateSession: (sessionId: string) => void
}) {
  const { task, sessionHostname, sessionUsername, category } = entry
  const cfg = statusConfig[task.status] ?? statusConfig[TaskStatus.QUEUED]
  const StatusIcon = cfg.icon
  const result = decodeResult(task.result)

  return (
    <div className="group border-l-2 border-specter-border pl-6 relative">
      {/* Timeline dot */}
      <div className={`absolute -left-[5px] top-4 h-2 w-2 rounded-full ${categoryDotColors[category]}`} />

      <button
        onClick={onToggle}
        className="flex w-full items-start gap-3 rounded-lg px-3 py-3 text-left transition-colors hover:bg-specter-surface"
      >
        {/* Expand/collapse */}
        <div className="mt-0.5 shrink-0">
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5 text-specter-muted" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-specter-muted" />
          )}
        </div>

        {/* Main content */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase ${categoryColors[category]}`}>
              {category}
            </span>
            <span className="text-sm font-medium text-specter-text">{task.taskType}</span>
            <StatusIcon className={`h-3.5 w-3.5 ${cfg.color}`} />
            <span className={`text-xs ${cfg.color}`}>{cfg.label}</span>
          </div>

          <div className="mt-1 flex items-center gap-3 text-xs text-specter-muted">
            <span className="flex items-center gap-1">
              <User className="h-3 w-3" />
              {task.operatorId || 'system'}
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation()
                onNavigateSession(task.sessionId)
              }}
              className="flex items-center gap-1 hover:text-specter-text transition-colors"
            >
              <Monitor className="h-3 w-3" />
              {sessionHostname}\{sessionUsername}
            </button>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {task.createdAt ? formatRelativeTime(new Date(Number(task.createdAt.seconds) * 1000)) : 'N/A'}
            </span>
          </div>
        </div>

        {/* Timestamp */}
        <span className="shrink-0 text-xs text-specter-muted">
          {task.createdAt ? formatTimestamp(task.createdAt.seconds) : 'N/A'}
        </span>
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="ml-6 mb-3 mr-3 rounded-lg border border-specter-border bg-specter-surface p-3">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-specter-muted">Task ID:</span>{' '}
              <span className="text-specter-text font-mono">{task.id}</span>
            </div>
            <div>
              <span className="text-specter-muted">Session ID:</span>{' '}
              <span className="text-specter-text font-mono">{task.sessionId}</span>
            </div>
            <div>
              <span className="text-specter-muted">Created:</span>{' '}
              <span className="text-specter-text">
                {task.createdAt ? formatTimestamp(task.createdAt.seconds) : 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-specter-muted">Completed:</span>{' '}
              <span className="text-specter-text">
                {task.completedAt ? formatTimestamp(task.completedAt.seconds) : 'N/A'}
              </span>
            </div>
          </div>

          {result && (
            <div className="mt-3">
              <span className="text-xs text-specter-muted">Output:</span>
              <pre className="mt-1 max-h-60 overflow-auto rounded border border-specter-border bg-specter-bg p-2 text-xs text-specter-text font-mono whitespace-pre-wrap">
                {result}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function FilterBar({
  searchQuery,
  onSearchChange,
  statusFilter,
  onStatusChange,
  categoryFilter,
  onCategoryChange,
  operatorFilter,
  onOperatorChange,
  operators,
}: {
  searchQuery: string
  onSearchChange: (v: string) => void
  statusFilter: string
  onStatusChange: (v: string) => void
  categoryFilter: string
  onCategoryChange: (v: string) => void
  operatorFilter: string
  onOperatorChange: (v: string) => void
  operators: string[]
}) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {/* Search */}
      <div className="relative flex-1 min-w-[200px]">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search tasks..."
          className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
        />
      </div>

      {/* Status filter */}
      <div className="flex items-center gap-1.5">
        <Filter className="h-3.5 w-3.5 text-specter-muted" />
        <select
          value={statusFilter}
          onChange={(e) => onStatusChange(e.target.value)}
          className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
        >
          <option value="all">All Statuses</option>
          <option value="queued">Queued</option>
          <option value="dispatched">Dispatched</option>
          <option value="complete">Complete</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      {/* Category filter */}
      <select
        value={categoryFilter}
        onChange={(e) => onCategoryChange(e.target.value)}
        className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
      >
        <option value="all">All Categories</option>
        <option value="recon">Recon</option>
        <option value="lateral">Lateral</option>
        <option value="injection">Injection</option>
        <option value="exfil">Exfil</option>
        <option value="persistence">Persistence</option>
        <option value="other">Other</option>
      </select>

      {/* Operator filter */}
      <select
        value={operatorFilter}
        onChange={(e) => onOperatorChange(e.target.value)}
        className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
      >
        <option value="all">All Operators</option>
        {operators.map((op) => (
          <option key={op} value={op}>
            {op}
          </option>
        ))}
      </select>
    </div>
  )
}

// ── Task Timeline Page ────────────────────────────────────────────────

export function TaskTimeline() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [tasks, setTasks] = useState<Task[]>([])
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [expandedTasks, setExpandedTasks] = useState<Set<string>>(new Set())
  const refreshTimerRef = useRef<ReturnType<typeof setInterval>>(null)

  const searchQuery = searchParams.get('q') ?? ''
  const statusFilter = searchParams.get('status') ?? 'all'
  const categoryFilter = searchParams.get('category') ?? 'all'
  const operatorFilter = searchParams.get('operator') ?? 'all'

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const [tasksRes, sessionsRes] = await Promise.allSettled([
        specterClient.listTasks({ sessionId: '' }),
        specterClient.listSessions({}),
      ])

      if (tasksRes.status === 'fulfilled') {
        setTasks(tasksRes.value.tasks)
      }
      if (sessionsRes.status === 'fulfilled') {
        setSessions(sessionsRes.value.sessions)
      }

      if (tasksRes.status === 'rejected' && sessionsRes.status === 'rejected') {
        setError('Unable to connect to teamserver')
      }

      setLastRefresh(new Date())
    } catch {
      setError('Unable to connect to teamserver')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    refreshTimerRef.current = setInterval(fetchData, 15_000)
    return () => {
      if (refreshTimerRef.current) clearInterval(refreshTimerRef.current)
    }
  }, [fetchData])

  const sessionMap = useMemo(() => {
    const map = new Map<string, SessionInfo>()
    for (const s of sessions) map.set(s.id, s)
    return map
  }, [sessions])

  const entries: TimelineEntry[] = useMemo(() => {
    return tasks
      .map((task) => {
        const session = sessionMap.get(task.sessionId)
        return {
          task,
          sessionHostname: session?.hostname ?? 'Unknown',
          sessionUsername: session?.username ?? 'Unknown',
          category: categorizeTask(task.taskType),
        }
      })
      .sort((a, b) => {
        const aTime = a.task.createdAt ? Number(a.task.createdAt.seconds) : 0
        const bTime = b.task.createdAt ? Number(b.task.createdAt.seconds) : 0
        return bTime - aTime
      })
  }, [tasks, sessionMap])

  const operators = useMemo(() => {
    const ops = new Set<string>()
    for (const t of tasks) {
      if (t.operatorId) ops.add(t.operatorId)
    }
    return Array.from(ops).sort()
  }, [tasks])

  const filteredEntries = useMemo(() => {
    return entries.filter((e) => {
      // Status filter
      if (statusFilter !== 'all') {
        const statusMap: Record<string, TaskStatus> = {
          queued: TaskStatus.QUEUED,
          dispatched: TaskStatus.DISPATCHED,
          complete: TaskStatus.COMPLETE,
          failed: TaskStatus.FAILED,
        }
        if (e.task.status !== statusMap[statusFilter]) return false
      }

      // Category filter
      if (categoryFilter !== 'all' && e.category !== categoryFilter) return false

      // Operator filter
      if (operatorFilter !== 'all' && e.task.operatorId !== operatorFilter) return false

      // Search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        const searchable = [
          e.task.taskType,
          e.task.operatorId,
          e.task.id,
          e.sessionHostname,
          e.sessionUsername,
          e.task.sessionId,
        ]
          .join(' ')
          .toLowerCase()
        if (!searchable.includes(q)) return false
      }

      return true
    })
  }, [entries, statusFilter, categoryFilter, operatorFilter, searchQuery])

  const toggleExpanded = useCallback((taskId: string) => {
    setExpandedTasks((prev) => {
      const next = new Set(prev)
      if (next.has(taskId)) {
        next.delete(taskId)
      } else {
        next.add(taskId)
      }
      return next
    })
  }, [])

  const updateFilter = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        if (value === 'all' || value === '') {
          next.delete(key)
        } else {
          next.set(key, value)
        }
        return next
      })
    },
    [setSearchParams]
  )

  const handleExportMarkdown = useCallback(() => {
    const md = generateMarkdownExport(filteredEntries)
    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `specter-tasks-${new Date().toISOString().slice(0, 10)}.md`
    a.click()
    URL.revokeObjectURL(url)
  }, [filteredEntries])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Task Timeline</h1>
          <p className="text-xs text-specter-muted">
            Chronological view of all operator tasks
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {filteredEntries.length} of {entries.length} tasks
          </span>
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>
          <button
            onClick={handleExportMarkdown}
            className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text"
          >
            <Download className="h-3 w-3" />
            Export
          </button>
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-3 text-sm text-specter-danger">
          {error} — showing cached data
        </div>
      )}

      {/* Filters */}
      <FilterBar
        searchQuery={searchQuery}
        onSearchChange={(v) => updateFilter('q', v)}
        statusFilter={statusFilter}
        onStatusChange={(v) => updateFilter('status', v)}
        categoryFilter={categoryFilter}
        onCategoryChange={(v) => updateFilter('category', v)}
        operatorFilter={operatorFilter}
        onOperatorChange={(v) => updateFilter('operator', v)}
        operators={operators}
      />

      {/* Category Legend */}
      <div className="flex items-center gap-4 text-xs">
        {(['recon', 'lateral', 'injection', 'exfil', 'persistence', 'other'] as TaskCategory[]).map(
          (cat) => (
            <button
              key={cat}
              onClick={() => updateFilter('category', categoryFilter === cat ? 'all' : cat)}
              className={`flex items-center gap-1.5 transition-opacity ${
                categoryFilter !== 'all' && categoryFilter !== cat ? 'opacity-40' : ''
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${categoryDotColors[cat]}`} />
              <span className="capitalize text-specter-muted">{cat}</span>
            </button>
          )
        )}
      </div>

      {/* Timeline */}
      <div className="flex flex-col">
        {loading && tasks.length === 0 ? (
          <div className="flex items-center justify-center py-16">
            <Loader className="h-5 w-5 animate-spin text-specter-muted" />
          </div>
        ) : filteredEntries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-specter-muted">
            <Clock className="mb-2 h-8 w-8" />
            <p className="text-sm">No tasks found</p>
            {(searchQuery || statusFilter !== 'all' || categoryFilter !== 'all') && (
              <button
                onClick={() => setSearchParams({})}
                className="mt-2 text-xs text-specter-accent hover:underline"
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <div className="flex flex-col gap-1">
            {filteredEntries.map((entry) => (
              <TimelineEntryRow
                key={entry.task.id}
                entry={entry}
                expanded={expandedTasks.has(entry.task.id)}
                onToggle={() => toggleExpanded(entry.task.id)}
                onNavigateSession={(id) => navigate(`/sessions/${id}`)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
