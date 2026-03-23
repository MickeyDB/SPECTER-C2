import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  Search,
  ChevronUp,
  ChevronDown,
  RefreshCw,
  Terminal,
  Filter,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import { SessionStatus } from '@/gen/specter/v1/sessions_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'
import { useCollaborationStore } from '@/store/collaborationStore'

// ── Types ──────────────────────────────────────────────────────────────

type SortField =
  | 'hostname'
  | 'username'
  | 'pid'
  | 'osVersion'
  | 'integrityLevel'
  | 'externalIp'
  | 'lastCheckin'
  | 'firstSeen'
  | 'status'

type SortDirection = 'asc' | 'desc'

interface SortConfig {
  field: SortField
  direction: SortDirection
}

// ── Helpers ────────────────────────────────────────────────────────────

const statusLabel: Record<number, string> = {
  [SessionStatus.UNSPECIFIED]: 'Unknown',
  [SessionStatus.NEW]: 'New',
  [SessionStatus.ACTIVE]: 'Active',
  [SessionStatus.STALE]: 'Stale',
  [SessionStatus.DEAD]: 'Dead',
}

const statusDotColor: Record<number, string> = {
  [SessionStatus.UNSPECIFIED]: 'bg-specter-muted',
  [SessionStatus.NEW]: 'bg-status-new',
  [SessionStatus.ACTIVE]: 'bg-status-active',
  [SessionStatus.STALE]: 'bg-status-stale',
  [SessionStatus.DEAD]: 'bg-status-dead',
}

const statusFilterOptions = [
  { value: '', label: 'All' },
  { value: 'new', label: 'New' },
  { value: 'active', label: 'Active' },
  { value: 'stale', label: 'Stale' },
  { value: 'dead', label: 'Dead' },
]

const statusStringToEnum: Record<string, SessionStatus> = {
  new: SessionStatus.NEW,
  active: SessionStatus.ACTIVE,
  stale: SessionStatus.STALE,
  dead: SessionStatus.DEAD,
}

function formatTimestamp(ts?: { seconds: bigint; nanos: number }): string {
  if (!ts) return '—'
  const date = new Date(Number(ts.seconds) * 1000)
  const now = Date.now()
  const diff = now - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

function getTimestampMs(ts?: { seconds: bigint; nanos: number }): number {
  if (!ts) return 0
  return Number(ts.seconds) * 1000
}

function compareValues<T>(a: T, b: T, dir: SortDirection): number {
  if (a < b) return dir === 'asc' ? -1 : 1
  if (a > b) return dir === 'asc' ? 1 : -1
  return 0
}

// ── Column definitions ─────────────────────────────────────────────────

interface Column {
  key: SortField | 'actions'
  label: string
  width: string
  sortable: boolean
}

const columns: Column[] = [
  { key: 'status', label: 'Status', width: 'w-20', sortable: true },
  { key: 'hostname', label: 'Hostname', width: 'w-40', sortable: true },
  { key: 'username', label: 'Username', width: 'w-36', sortable: true },
  { key: 'pid', label: 'PID', width: 'w-20', sortable: true },
  { key: 'osVersion', label: 'OS', width: 'w-44', sortable: true },
  { key: 'integrityLevel', label: 'Integrity', width: 'w-24', sortable: true },
  { key: 'externalIp', label: 'IP', width: 'w-32', sortable: true },
  { key: 'lastCheckin', label: 'Last Check-in', width: 'w-28', sortable: true },
  { key: 'firstSeen', label: 'First Seen', width: 'w-28', sortable: true },
  { key: 'actions', label: '', width: 'w-16', sortable: false },
]

// ── Component ──────────────────────────────────────────────────────────

export function Sessions() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') ?? '')
  const [sort, setSort] = useState<SortConfig>({ field: 'lastCheckin', direction: 'desc' })

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await specterClient.listSessions({})
      setSessions(res.sessions)
    } catch {
      setError('Unable to fetch sessions')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSessions()
    const interval = setInterval(fetchSessions, 15_000)
    return () => clearInterval(interval)
  }, [fetchSessions])

  // Sync status filter with URL params
  useEffect(() => {
    const params = new URLSearchParams()
    if (statusFilter) params.set('status', statusFilter)
    setSearchParams(params, { replace: true })
  }, [statusFilter, setSearchParams])

  const handleSort = (field: SortField) => {
    setSort((prev) => ({
      field,
      direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc',
    }))
  }

  // Filter and sort
  const filteredSessions = useMemo(() => {
    let result = sessions

    // Status filter
    if (statusFilter && statusStringToEnum[statusFilter] !== undefined) {
      const target = statusStringToEnum[statusFilter]
      result = result.filter((s) => s.status === target)
    }

    // Search filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      result = result.filter(
        (s) =>
          s.hostname.toLowerCase().includes(q) ||
          s.username.toLowerCase().includes(q) ||
          s.externalIp.toLowerCase().includes(q) ||
          s.internalIp.toLowerCase().includes(q) ||
          s.processName.toLowerCase().includes(q) ||
          s.osVersion.toLowerCase().includes(q) ||
          s.id.toLowerCase().includes(q)
      )
    }

    // Sort
    result = [...result].sort((a, b) => {
      switch (sort.field) {
        case 'hostname':
          return compareValues(a.hostname.toLowerCase(), b.hostname.toLowerCase(), sort.direction)
        case 'username':
          return compareValues(a.username.toLowerCase(), b.username.toLowerCase(), sort.direction)
        case 'pid':
          return compareValues(a.pid, b.pid, sort.direction)
        case 'osVersion':
          return compareValues(a.osVersion.toLowerCase(), b.osVersion.toLowerCase(), sort.direction)
        case 'integrityLevel':
          return compareValues(a.integrityLevel.toLowerCase(), b.integrityLevel.toLowerCase(), sort.direction)
        case 'externalIp':
          return compareValues(a.externalIp, b.externalIp, sort.direction)
        case 'lastCheckin':
          return compareValues(getTimestampMs(a.lastCheckin), getTimestampMs(b.lastCheckin), sort.direction)
        case 'firstSeen':
          return compareValues(getTimestampMs(a.firstSeen), getTimestampMs(b.firstSeen), sort.direction)
        case 'status':
          return compareValues(a.status, b.status, sort.direction)
        default:
          return 0
      }
    })

    return result
  }, [sessions, statusFilter, searchQuery, sort])

  return (
    <div className="flex h-full flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Sessions</h1>
          <p className="text-xs text-specter-muted">
            {filteredSessions.length} of {sessions.length} sessions
          </p>
        </div>
        <button
          onClick={fetchSessions}
          disabled={loading}
          className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by hostname, username, IP, PID..."
            className="w-full rounded border border-specter-border bg-specter-surface py-2 pl-9 pr-3 text-xs text-specter-text placeholder:text-specter-muted/60 focus:border-specter-accent focus:outline-none"
          />
        </div>
        <div className="relative flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-specter-muted" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
          >
            {statusFilterOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-3 text-sm text-specter-danger">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="flex min-h-0 flex-1 flex-col rounded-lg border border-specter-border bg-specter-surface">
        {/* Table Header */}
        <div className="flex items-center border-b border-specter-border px-4 py-2.5">
          {columns.map((col) => (
            <div key={col.key} className={`${col.width} shrink-0 px-2`}>
              {col.sortable ? (
                <button
                  onClick={() => handleSort(col.key as SortField)}
                  className="flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-specter-muted transition-colors hover:text-specter-text"
                >
                  {col.label}
                  {sort.field === col.key && (
                    sort.direction === 'asc' ? (
                      <ChevronUp className="h-3 w-3" />
                    ) : (
                      <ChevronDown className="h-3 w-3" />
                    )
                  )}
                </button>
              ) : (
                <span className="text-xs font-medium uppercase tracking-wider text-specter-muted">
                  {col.label}
                </span>
              )}
            </div>
          ))}
        </div>

        {/* Table Body - Virtualized */}
        <SessionTableBody
          sessions={filteredSessions}
          onInteract={(id) => navigate(`/sessions/${id}`)}
        />
      </div>
    </div>
  )
}

// ── Virtualized Table Body ─────────────────────────────────────────────

function SessionTableBody({
  sessions,
  onInteract,
}: {
  sessions: SessionInfo[]
  onInteract: (id: string) => void
}) {
  const scrollRef = useRef<HTMLDivElement | null>(null)

  const virtualizer = useVirtualizer({
    count: sessions.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 40,
    overscan: 20,
  })

  if (sessions.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center py-12 text-sm text-specter-muted">
        No sessions found
      </div>
    )
  }

  return (
    <div ref={scrollRef} className="flex-1 overflow-auto">
      <div
        style={{ height: `${virtualizer.getTotalSize()}px`, width: '100%', position: 'relative' }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const session = sessions[virtualRow.index]
          return (
            <div
              key={session.id}
              data-testid="session-row"
              className="absolute left-0 flex w-full items-center border-b border-specter-border/50 px-4 transition-colors hover:bg-specter-border/20"
              style={{
                height: `${virtualRow.size}px`,
                transform: `translateY(${virtualRow.start}px)`,
              }}
            >
              {/* Status */}
              <div className="w-20 shrink-0 px-2">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${statusDotColor[session.status]}`} />
                  <span className="text-xs text-specter-muted">
                    {statusLabel[session.status]}
                  </span>
                </div>
              </div>

              {/* Hostname + active operator indicator */}
              <div className="w-40 shrink-0 truncate px-2 text-xs font-medium text-specter-text">
                {session.hostname}
                <SessionOperatorBadge sessionId={session.id} />
              </div>

              {/* Username */}
              <div className="w-36 shrink-0 truncate px-2 text-xs text-specter-text">
                {session.username}
              </div>

              {/* PID */}
              <div className="w-20 shrink-0 px-2 text-xs text-specter-muted">
                {session.pid}
              </div>

              {/* OS */}
              <div className="w-44 shrink-0 truncate px-2 text-xs text-specter-muted">
                {session.osVersion}
              </div>

              {/* Integrity */}
              <div className="w-24 shrink-0 px-2">
                <span
                  className={`text-xs ${
                    session.integrityLevel === 'System'
                      ? 'text-specter-danger'
                      : session.integrityLevel === 'High'
                        ? 'text-specter-warning'
                        : 'text-specter-muted'
                  }`}
                >
                  {session.integrityLevel}
                </span>
              </div>

              {/* IP */}
              <div className="w-32 shrink-0 truncate px-2 text-xs text-specter-muted">
                {session.externalIp}
              </div>

              {/* Last Check-in */}
              <div className="w-28 shrink-0 px-2 text-xs text-specter-muted">
                {formatTimestamp(session.lastCheckin)}
              </div>

              {/* First Seen */}
              <div className="w-28 shrink-0 px-2 text-xs text-specter-muted">
                {formatTimestamp(session.firstSeen)}
              </div>

              {/* Actions */}
              <div className="w-16 shrink-0 px-2">
                <button
                  onClick={() => onInteract(session.id)}
                  title="Interact"
                  className="rounded p-1 text-specter-muted transition-colors hover:bg-specter-accent/20 hover:text-specter-accent"
                >
                  <Terminal className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function SessionOperatorBadge({ sessionId }: { sessionId: string }) {
  const op = useCollaborationStore((s) => s.getOperatorForSession(sessionId))
  if (!op) return null
  return (
    <span className="ml-1 inline-flex items-center rounded bg-specter-accent/10 px-1 text-[10px] text-specter-accent">
      {op.username}
    </span>
  )
}
