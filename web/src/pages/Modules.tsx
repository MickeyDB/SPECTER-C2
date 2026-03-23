import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search,
  RefreshCw,
  Grid3X3,
  List,
  Shield,
  Play,
  X,
  Loader,
  Package,
  Cpu,
  FileCode,
  Filter,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { ModuleInfo } from '@/gen/specter/v1/modules_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'
import { SessionStatus } from '@/gen/specter/v1/sessions_pb'
import { create } from '@bufbuild/protobuf'
import { LoadModuleRequestSchema } from '@/gen/specter/v1/modules_pb'

// ── Types ──────────────────────────────────────────────────────────────

interface DeployDialogState {
  module: ModuleInfo
  selectedSessions: string[]
  args: string
  deploying: boolean
  result: { success: boolean; message: string } | null
}

// ── Helpers ────────────────────────────────────────────────────────────

function inferOpsecRating(moduleType: string, name: string): number {
  const n = name.toLowerCase()
  if (n.includes('inject') || n.includes('shellcode')) return 1
  if (n.includes('dump') || n.includes('mimikatz') || n.includes('credential')) return 1
  if (n.includes('keylog') || n.includes('screenshot')) return 2
  if (n.includes('persist') || n.includes('registry') || n.includes('service')) return 2
  if (n.includes('psexec') || n.includes('wmi') || n.includes('lateral')) return 2
  if (n.includes('execute-assembly') || n.includes('bof')) return 3
  if (n.includes('enum') || n.includes('recon') || n.includes('ls') || n.includes('dir')) return 4
  if (moduleType.toLowerCase().includes('coff') || moduleType.toLowerCase().includes('bof')) return 4
  if (moduleType.toLowerCase().includes('pic')) return 3
  return 3
}

function formatBlobSize(size: bigint): string {
  const n = Number(size)
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

const moduleTypeIcon: Record<string, typeof Cpu> = {
  pic: Cpu,
  coff: FileCode,
  bof: FileCode,
}

// ── Components ─────────────────────────────────────────────────────────

function OpsecShields({ rating }: { rating: number }) {
  return (
    <div className="flex items-center gap-0.5" title={`OPSEC Rating: ${rating}/5`}>
      {[1, 2, 3, 4, 5].map((i) => (
        <Shield
          key={i}
          className={`h-3 w-3 ${i <= rating ? 'text-specter-accent fill-specter-accent/30' : 'text-specter-border'}`}
        />
      ))}
    </div>
  )
}

function ModuleCard({
  module,
  opsecRating,
  onDeploy,
}: {
  module: ModuleInfo
  opsecRating: number
  onDeploy: () => void
}) {
  const TypeIcon = moduleTypeIcon[module.moduleType.toLowerCase()] ?? Package

  return (
    <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface p-4 transition-colors hover:border-specter-muted">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <TypeIcon className="h-4 w-4 text-specter-muted" />
          <h3 className="text-sm font-medium text-specter-text">{module.name}</h3>
        </div>
        <span className="rounded border border-specter-border px-1.5 py-0.5 text-[10px] font-medium uppercase text-specter-muted">
          {module.moduleType || 'PIC'}
        </span>
      </div>

      <p className="mt-2 text-xs text-specter-muted line-clamp-2">
        {module.description || 'No description available'}
      </p>

      <div className="mt-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <OpsecShields rating={opsecRating} />
          <span className="text-[10px] text-specter-muted">v{module.version || '1.0'}</span>
          <span className="text-[10px] text-specter-muted">{formatBlobSize(module.blobSize)}</span>
        </div>
      </div>

      <button
        onClick={onDeploy}
        className="mt-3 flex items-center justify-center gap-1.5 rounded border border-specter-accent/30 bg-specter-accent/10 px-3 py-1.5 text-xs text-specter-accent transition-colors hover:bg-specter-accent/20"
      >
        <Play className="h-3 w-3" />
        Deploy
      </button>
    </div>
  )
}

function ModuleListRow({
  module,
  opsecRating,
  onDeploy,
}: {
  module: ModuleInfo
  opsecRating: number
  onDeploy: () => void
}) {
  const TypeIcon = moduleTypeIcon[module.moduleType.toLowerCase()] ?? Package

  return (
    <div className="flex items-center gap-4 border-b border-specter-border px-4 py-3 transition-colors hover:bg-specter-surface">
      <TypeIcon className="h-4 w-4 shrink-0 text-specter-muted" />
      <div className="min-w-0 flex-1">
        <span className="text-sm font-medium text-specter-text">{module.name}</span>
        <p className="truncate text-xs text-specter-muted">{module.description || 'No description'}</p>
      </div>
      <span className="shrink-0 rounded border border-specter-border px-1.5 py-0.5 text-[10px] font-medium uppercase text-specter-muted">
        {module.moduleType || 'PIC'}
      </span>
      <span className="shrink-0 text-[10px] text-specter-muted">v{module.version || '1.0'}</span>
      <span className="shrink-0 text-[10px] text-specter-muted">{formatBlobSize(module.blobSize)}</span>
      <OpsecShields rating={opsecRating} />
      <button
        onClick={onDeploy}
        className="shrink-0 flex items-center gap-1.5 rounded border border-specter-accent/30 bg-specter-accent/10 px-2.5 py-1 text-xs text-specter-accent transition-colors hover:bg-specter-accent/20"
      >
        <Play className="h-3 w-3" />
        Deploy
      </button>
    </div>
  )
}

function DeployDialog({
  state,
  sessions,
  onClose,
  onToggleSession,
  onArgsChange,
  onExecute,
}: {
  state: DeployDialogState
  sessions: SessionInfo[]
  onClose: () => void
  onToggleSession: (id: string) => void
  onArgsChange: (v: string) => void
  onExecute: () => void
}) {
  const activeSessions = sessions.filter(
    (s) => s.status === SessionStatus.ACTIVE || s.status === SessionStatus.NEW
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">
            Deploy: {state.module.name}
          </h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          {/* Session selector */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Target Sessions</label>
            <div className="mt-1.5 max-h-40 overflow-y-auto rounded border border-specter-border bg-specter-surface">
              {activeSessions.length === 0 ? (
                <div className="px-3 py-4 text-center text-xs text-specter-muted">
                  No active sessions available
                </div>
              ) : (
                activeSessions.map((s) => (
                  <label
                    key={s.id}
                    className="flex cursor-pointer items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-specter-border/30"
                  >
                    <input
                      type="checkbox"
                      checked={state.selectedSessions.includes(s.id)}
                      onChange={() => onToggleSession(s.id)}
                      className="rounded border-specter-border"
                    />
                    <span className="text-specter-text">
                      {s.hostname}\{s.username}
                    </span>
                    <span className="text-specter-muted">PID {s.pid}</span>
                  </label>
                ))
              )}
            </div>
            <span className="mt-1 text-[10px] text-specter-muted">
              {state.selectedSessions.length} session(s) selected
            </span>
          </div>

          {/* Arguments */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Arguments</label>
            <textarea
              value={state.args}
              onChange={(e) => onArgsChange(e.target.value)}
              placeholder="Enter module arguments..."
              rows={3}
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none font-mono"
            />
          </div>

          {/* Result */}
          {state.result && (
            <div
              className={`rounded border px-3 py-2 text-xs ${
                state.result.success
                  ? 'border-status-active/30 bg-status-active/10 text-status-active'
                  : 'border-specter-danger/30 bg-specter-danger/10 text-specter-danger'
              }`}
            >
              {state.result.message}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-specter-border px-4 py-3">
          <button
            onClick={onClose}
            className="rounded border border-specter-border px-3 py-1.5 text-xs text-specter-muted transition-colors hover:text-specter-text"
          >
            Cancel
          </button>
          <button
            onClick={onExecute}
            disabled={state.selectedSessions.length === 0 || state.deploying}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
          >
            {state.deploying ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <Play className="h-3 w-3" />
            )}
            Execute
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Modules Page ──────────────────────────────────────────────────────

export function Modules() {
  const [modules, setModules] = useState<ModuleInfo[]>([])
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [opsecFilter, setOpsecFilter] = useState('all')
  const [deployState, setDeployState] = useState<DeployDialogState | null>(null)

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const [modulesRes, sessionsRes] = await Promise.allSettled([
        specterClient.listModules({}),
        specterClient.listSessions({}),
      ])

      if (modulesRes.status === 'fulfilled') {
        setModules(modulesRes.value.modules)
      }
      if (sessionsRes.status === 'fulfilled') {
        setSessions(sessionsRes.value.sessions)
      }

      if (modulesRes.status === 'rejected' && sessionsRes.status === 'rejected') {
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
    const interval = setInterval(fetchData, 15_000)
    return () => clearInterval(interval)
  }, [fetchData])

  const moduleTypes = useMemo(() => {
    const types = new Set<string>()
    for (const m of modules) {
      if (m.moduleType) types.add(m.moduleType)
    }
    return Array.from(types).sort()
  }, [modules])

  const modulesWithRating = useMemo(() => {
    return modules.map((m) => ({
      module: m,
      opsecRating: inferOpsecRating(m.moduleType, m.name),
    }))
  }, [modules])

  const filteredModules = useMemo(() => {
    return modulesWithRating.filter(({ module, opsecRating }) => {
      // Type filter
      if (typeFilter !== 'all' && module.moduleType.toLowerCase() !== typeFilter.toLowerCase()) return false

      // OPSEC filter
      if (opsecFilter !== 'all' && opsecRating !== Number(opsecFilter)) return false

      // Search
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        const searchable = [module.name, module.description, module.moduleType, module.moduleId]
          .join(' ')
          .toLowerCase()
        if (!searchable.includes(q)) return false
      }

      return true
    })
  }, [modulesWithRating, typeFilter, opsecFilter, searchQuery])

  const handleDeploy = useCallback((module: ModuleInfo) => {
    setDeployState({
      module,
      selectedSessions: [],
      args: '',
      deploying: false,
      result: null,
    })
  }, [])

  const handleToggleSession = useCallback((sessionId: string) => {
    setDeployState((prev) => {
      if (!prev) return null
      const selected = prev.selectedSessions.includes(sessionId)
        ? prev.selectedSessions.filter((id) => id !== sessionId)
        : [...prev.selectedSessions, sessionId]
      return { ...prev, selectedSessions: selected, result: null }
    })
  }, [])

  const handleExecute = useCallback(async () => {
    if (!deployState) return

    setDeployState((prev) => (prev ? { ...prev, deploying: true, result: null } : null))

    try {
      const results: string[] = []
      for (const sessionId of deployState.selectedSessions) {
        const req = create(LoadModuleRequestSchema, {
          sessionId,
          moduleName: deployState.module.name,
          arguments: new TextEncoder().encode(deployState.args),
        })
        const res = await specterClient.loadModule(req)
        results.push(
          `${sessionId}: ${res.success ? 'OK' : 'FAILED'} - ${res.message || res.taskId}`
        )
      }

      setDeployState((prev) =>
        prev
          ? {
              ...prev,
              deploying: false,
              result: {
                success: true,
                message: `Deployed to ${deployState.selectedSessions.length} session(s)`,
              },
            }
          : null
      )
    } catch (err) {
      setDeployState((prev) =>
        prev
          ? {
              ...prev,
              deploying: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Deploy failed',
              },
            }
          : null
      )
    }
  }, [deployState])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Modules</h1>
          <p className="text-xs text-specter-muted">
            Browse and deploy available modules
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {filteredModules.length} of {modules.length} modules
          </span>
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>

          {/* View toggle */}
          <div className="flex rounded border border-specter-border">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-1.5 ${viewMode === 'grid' ? 'bg-specter-surface text-specter-text' : 'text-specter-muted'}`}
            >
              <Grid3X3 className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-1.5 ${viewMode === 'list' ? 'bg-specter-surface text-specter-text' : 'text-specter-muted'}`}
            >
              <List className="h-3.5 w-3.5" />
            </button>
          </div>

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
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search modules..."
            className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-specter-muted" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
          >
            <option value="all">All Types</option>
            {moduleTypes.map((t) => (
              <option key={t} value={t}>
                {t.toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        <select
          value={opsecFilter}
          onChange={(e) => setOpsecFilter(e.target.value)}
          className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
        >
          <option value="all">All OPSEC</option>
          {[1, 2, 3, 4, 5].map((r) => (
            <option key={r} value={r}>
              OPSEC {r}/5
            </option>
          ))}
        </select>
      </div>

      {/* Module List/Grid */}
      {loading && modules.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : filteredModules.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-specter-muted">
          <Package className="mb-2 h-8 w-8" />
          <p className="text-sm">No modules found</p>
          {(searchQuery || typeFilter !== 'all' || opsecFilter !== 'all') && (
            <button
              onClick={() => {
                setSearchQuery('')
                setTypeFilter('all')
                setOpsecFilter('all')
              }}
              className="mt-2 text-xs text-specter-accent hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-3 gap-4">
          {filteredModules.map(({ module, opsecRating }) => (
            <ModuleCard
              key={module.moduleId}
              module={module}
              opsecRating={opsecRating}
              onDeploy={() => handleDeploy(module)}
            />
          ))}
        </div>
      ) : (
        <div className="rounded-lg border border-specter-border">
          {filteredModules.map(({ module, opsecRating }) => (
            <ModuleListRow
              key={module.moduleId}
              module={module}
              opsecRating={opsecRating}
              onDeploy={() => handleDeploy(module)}
            />
          ))}
        </div>
      )}

      {/* Deploy Dialog */}
      {deployState && (
        <DeployDialog
          state={deployState}
          sessions={sessions}
          onClose={() => setDeployState(null)}
          onToggleSession={handleToggleSession}
          onArgsChange={(v) =>
            setDeployState((prev) => (prev ? { ...prev, args: v, result: null } : null))
          }
          onExecute={handleExecute}
        />
      )}
    </div>
  )
}
