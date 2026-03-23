import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import {
  Monitor,
  Activity,
  Skull,
  Zap,
  Radio,
  Clock,
  ArrowRight,
  RefreshCw,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import { SessionStatus } from '@/gen/specter/v1/sessions_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'
import type { RedirectorInfo } from '@/gen/specter/v1/azure_pb'

// ── Types ──────────────────────────────────────────────────────────────

interface SessionCounts {
  total: number
  active: number
  stale: number
  dead: number
  new: number
}

interface ActivityEvent {
  id: string
  type: 'session_new' | 'session_checkin' | 'session_dead' | 'task_complete' | 'task_failed'
  message: string
  timestamp: Date
}

interface CheckInDataPoint {
  time: string
  count: number
}

// ── Helpers ────────────────────────────────────────────────────────────

function countByStatus(sessions: SessionInfo[]): SessionCounts {
  const counts: SessionCounts = { total: 0, active: 0, stale: 0, dead: 0, new: 0 }
  counts.total = sessions.length
  for (const s of sessions) {
    switch (s.status) {
      case SessionStatus.ACTIVE:
        counts.active++
        break
      case SessionStatus.STALE:
        counts.stale++
        break
      case SessionStatus.DEAD:
        counts.dead++
        break
      case SessionStatus.NEW:
        counts.new++
        break
    }
  }
  return counts
}

function buildCheckInChart(sessions: SessionInfo[]): CheckInDataPoint[] {
  const now = Date.now()
  const buckets = new Map<string, number>()

  // Create 24 hour buckets
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now - i * 3600_000)
    const label = `${d.getHours().toString().padStart(2, '0')}:00`
    buckets.set(label, 0)
  }

  for (const s of sessions) {
    if (!s.lastCheckin) continue
    const ts = Number(s.lastCheckin.seconds) * 1000
    if (now - ts > 24 * 3600_000) continue
    const d = new Date(ts)
    const label = `${d.getHours().toString().padStart(2, '0')}:00`
    if (buckets.has(label)) {
      buckets.set(label, buckets.get(label)! + 1)
    }
  }

  return Array.from(buckets, ([time, count]) => ({ time, count }))
}

function deriveActivityEvents(sessions: SessionInfo[]): ActivityEvent[] {
  const events: ActivityEvent[] = []

  for (const s of sessions) {
    if (s.firstSeen) {
      events.push({
        id: `new-${s.id}`,
        type: 'session_new',
        message: `New session: ${s.hostname}\\${s.username} (${s.externalIp})`,
        timestamp: new Date(Number(s.firstSeen.seconds) * 1000),
      })
    }
    if (s.lastCheckin && s.status === SessionStatus.ACTIVE) {
      events.push({
        id: `checkin-${s.id}`,
        type: 'session_checkin',
        message: `Check-in: ${s.hostname}\\${s.username} [PID ${s.pid}]`,
        timestamp: new Date(Number(s.lastCheckin.seconds) * 1000),
      })
    }
    if (s.status === SessionStatus.DEAD) {
      events.push({
        id: `dead-${s.id}`,
        type: 'session_dead',
        message: `Session lost: ${s.hostname}\\${s.username}`,
        timestamp: new Date(
          Number((s.lastCheckin ?? s.firstSeen)?.seconds ?? 0) * 1000
        ),
      })
    }
  }

  events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
  return events.slice(0, 100)
}

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

const statusColorMap: Record<string, string> = {
  active: 'bg-status-active',
  stale: 'bg-status-stale',
  dead: 'bg-status-dead',
  new: 'bg-status-new',
}

const eventTypeStyles: Record<string, { color: string; icon: typeof Activity }> = {
  session_new: { color: 'text-status-new', icon: Zap },
  session_checkin: { color: 'text-status-active', icon: Activity },
  session_dead: { color: 'text-status-dead', icon: Skull },
  task_complete: { color: 'text-specter-accent', icon: Activity },
  task_failed: { color: 'text-specter-danger', icon: Skull },
}

// ── Components ─────────────────────────────────────────────────────────

function SessionOverviewCards({
  counts,
  onFilterClick,
}: {
  counts: SessionCounts
  onFilterClick: (status: string) => void
}) {
  const cards = [
    { label: 'Total', value: counts.total, key: 'total', icon: Monitor, color: 'text-specter-text' },
    { label: 'Active', value: counts.active, key: 'active', icon: Activity, color: 'text-status-active' },
    { label: 'Stale', value: counts.stale, key: 'stale', icon: Clock, color: 'text-status-stale' },
    { label: 'Dead', value: counts.dead, key: 'dead', icon: Skull, color: 'text-status-dead' },
    { label: 'New', value: counts.new, key: 'new', icon: Zap, color: 'text-status-new' },
  ]

  return (
    <div className="grid grid-cols-5 gap-4">
      {cards.map(({ label, value, key, icon: Icon, color }) => (
        <button
          key={key}
          onClick={() => onFilterClick(key)}
          className="flex flex-col gap-2 rounded-lg border border-specter-border bg-specter-surface p-4 text-left transition-colors hover:border-specter-muted"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-specter-muted">{label}</span>
            <Icon className={`h-4 w-4 ${color}`} />
          </div>
          <span className={`text-2xl font-bold ${color}`}>{value}</span>
          {key !== 'total' && (
            <div className="flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${statusColorMap[key]}`} />
              <span className="text-xs text-specter-muted">
                {counts.total > 0 ? Math.round((value / counts.total) * 100) : 0}%
              </span>
            </div>
          )}
        </button>
      ))}
    </div>
  )
}

function ActivityTimeline({ events }: { events: ActivityEvent[] }) {
  const listRef = useRef<HTMLDivElement>(null)

  return (
    <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface">
      <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
        <h3 className="text-sm font-medium text-specter-text">Activity Timeline</h3>
        <span className="text-xs text-specter-muted">{events.length} events</span>
      </div>
      <div ref={listRef} className="max-h-80 overflow-y-auto">
        {events.length === 0 ? (
          <div className="flex items-center justify-center py-8 text-sm text-specter-muted">
            No activity yet
          </div>
        ) : (
          <div className="divide-y divide-specter-border">
            {events.map((event) => {
              const style = eventTypeStyles[event.type] ?? eventTypeStyles.session_checkin
              const EventIcon = style.icon
              return (
                <div key={event.id} className="flex items-start gap-3 px-4 py-2.5">
                  <EventIcon className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${style.color}`} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs text-specter-text">{event.message}</p>
                  </div>
                  <span className="shrink-0 text-xs text-specter-muted">
                    {formatRelativeTime(event.timestamp)}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function RedirectorHealthWidget({ redirectors }: { redirectors: RedirectorInfo[] }) {
  return (
    <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface">
      <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
        <h3 className="text-sm font-medium text-specter-text">Redirectors</h3>
        <Radio className="h-4 w-4 text-specter-muted" />
      </div>
      <div className="max-h-64 overflow-y-auto">
        {redirectors.length === 0 ? (
          <div className="flex items-center justify-center py-8 text-sm text-specter-muted">
            No redirectors configured
          </div>
        ) : (
          <div className="divide-y divide-specter-border">
            {redirectors.map((r) => {
              const isHealthy = r.state === 'running' || r.state === 'healthy'
              return (
                <div key={r.id} className="flex items-center gap-3 px-4 py-2.5">
                  <span
                    className={`h-2 w-2 rounded-full ${isHealthy ? 'bg-status-active' : 'bg-status-dead'}`}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-medium text-specter-text">{r.name}</p>
                    <p className="truncate text-xs text-specter-muted">
                      {r.domain || r.provider || 'N/A'}
                    </p>
                  </div>
                  <span className={`text-xs ${isHealthy ? 'text-status-active' : 'text-status-dead'}`}>
                    {r.state || 'unknown'}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function CheckInChart({ data }: { data: CheckInDataPoint[] }) {
  return (
    <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface">
      <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
        <h3 className="text-sm font-medium text-specter-text">Check-in Frequency (24h)</h3>
      </div>
      <div className="p-4">
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
            <XAxis
              dataKey="time"
              stroke="#a1a1aa"
              tick={{ fontSize: 10, fill: '#a1a1aa' }}
              interval="preserveStartEnd"
            />
            <YAxis
              stroke="#a1a1aa"
              tick={{ fontSize: 10, fill: '#a1a1aa' }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#18181b',
                border: '1px solid #27272a',
                borderRadius: '6px',
                fontSize: '12px',
                color: '#f4f4f5',
              }}
            />
            <Line
              type="monotone"
              dataKey="count"
              stroke="#10b981"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 3, fill: '#10b981' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

// ── Dashboard Page ─────────────────────────────────────────────────────

export function Dashboard() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [redirectors, setRedirectors] = useState<RedirectorInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const [sessionsRes, redirectorsRes] = await Promise.allSettled([
        specterClient.listSessions({}),
        specterClient.listRedirectors({}),
      ])

      if (sessionsRes.status === 'fulfilled') {
        setSessions(sessionsRes.value.sessions)
      }
      if (redirectorsRes.status === 'fulfilled') {
        setRedirectors(redirectorsRes.value.redirectors)
      }

      // If both failed, show error
      if (sessionsRes.status === 'rejected' && redirectorsRes.status === 'rejected') {
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
    const interval = setInterval(fetchData, 15_000) // Refresh every 15s
    return () => clearInterval(interval)
  }, [fetchData])

  const counts = countByStatus(sessions)
  const events = deriveActivityEvents(sessions)
  const chartData = buildCheckInChart(sessions)

  const handleFilterClick = (status: string) => {
    if (status === 'total') {
      navigate('/sessions')
    } else {
      navigate(`/sessions?status=${status}`)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Dashboard</h1>
          <p className="text-xs text-specter-muted">
            Global overview of operations
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>
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

      {/* Session Overview Cards */}
      <SessionOverviewCards counts={counts} onFilterClick={handleFilterClick} />

      {/* Main Content Grid */}
      <div className="grid grid-cols-3 gap-6">
        {/* Left column: Activity + Chart */}
        <div className="col-span-2 flex flex-col gap-6">
          <CheckInChart data={chartData} />
          <ActivityTimeline events={events} />
        </div>

        {/* Right column: Redirector health */}
        <div className="flex flex-col gap-6">
          <RedirectorHealthWidget redirectors={redirectors} />

          {/* Quick Links */}
          <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface">
            <div className="border-b border-specter-border px-4 py-3">
              <h3 className="text-sm font-medium text-specter-text">Quick Actions</h3>
            </div>
            <div className="flex flex-col">
              {[
                { label: 'Sessions', to: '/sessions' },
                { label: 'Session Map', to: '/map' },
                { label: 'Task Timeline', to: '/tasks' },
                { label: 'Modules', to: '/modules' },
              ].map(({ label, to }) => (
                <button
                  key={to}
                  onClick={() => navigate(to)}
                  className="flex items-center justify-between px-4 py-2.5 text-xs text-specter-muted transition-colors hover:bg-specter-border/30 hover:text-specter-text"
                >
                  {label}
                  <ArrowRight className="h-3 w-3" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
