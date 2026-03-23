import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search,
  RefreshCw,
  Loader,
  Plus,
  X,
  Play,
  Square,
  Radio,
  Trash2,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { Listener } from '@/gen/specter/v1/listeners_pb'
import {
  ListenerStatus,
  CreateListenerRequestSchema,
  StartListenerRequestSchema,
  StopListenerRequestSchema,
  DeleteListenerRequestSchema,
} from '@/gen/specter/v1/listeners_pb'
import { create } from '@bufbuild/protobuf'

// ── Helpers ────────────────────────────────────────────────────────────

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

function formatTimestamp(ts: Date | undefined): string {
  if (!ts) return '—'
  return ts.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function statusLabel(status: ListenerStatus): string {
  switch (status) {
    case ListenerStatus.RUNNING:
      return 'RUNNING'
    case ListenerStatus.STOPPED:
      return 'STOPPED'
    default:
      return 'UNKNOWN'
  }
}

function statusBadgeClasses(status: ListenerStatus): string {
  switch (status) {
    case ListenerStatus.RUNNING:
      return 'bg-status-active/10 border-status-active/30 text-status-active'
    case ListenerStatus.STOPPED:
      return 'bg-specter-muted/10 border-specter-muted/30 text-specter-muted'
    default:
      return 'bg-specter-muted/10 border-specter-muted/30 text-specter-muted'
  }
}

// ── Types ──────────────────────────────────────────────────────────────

interface CreateDialogState {
  name: string
  bindAddress: string
  port: number
  protocol: string
  creating: boolean
  error: string | null
}

const initialCreateState: CreateDialogState = {
  name: '',
  bindAddress: '0.0.0.0',
  port: 443,
  protocol: 'https',
  creating: false,
  error: null,
}

// ── Components ─────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: ListenerStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium ${statusBadgeClasses(status)}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          status === ListenerStatus.RUNNING ? 'bg-status-active animate-pulse' : 'bg-specter-muted'
        }`}
      />
      {statusLabel(status)}
    </span>
  )
}

function CreateListenerDialog({
  state,
  onClose,
  onUpdate,
  onCreate,
}: {
  state: CreateDialogState
  onClose: () => void
  onUpdate: (patch: Partial<CreateDialogState>) => void
  onCreate: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Create Listener</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          {/* Name */}
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Name</label>
            <input
              type="text"
              value={state.name}
              onChange={(e) => onUpdate({ name: e.target.value })}
              placeholder="https-listener-01"
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* Bind Address */}
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Bind Address</label>
            <input
              type="text"
              value={state.bindAddress}
              onChange={(e) => onUpdate({ bindAddress: e.target.value })}
              placeholder="0.0.0.0"
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* Port */}
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Port</label>
            <input
              type="number"
              value={state.port}
              onChange={(e) => onUpdate({ port: Number(e.target.value) })}
              min={1}
              max={65535}
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* Protocol */}
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Protocol</label>
            <select
              value={state.protocol}
              onChange={(e) => onUpdate({ protocol: e.target.value })}
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
            >
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="dns">DNS</option>
            </select>
          </div>

          {/* Error */}
          {state.error && (
            <div className="rounded border border-specter-danger/30 bg-specter-danger/10 px-3 py-2 text-xs text-specter-danger">
              {state.error}
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
            onClick={onCreate}
            disabled={!state.name.trim() || state.creating}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
          >
            {state.creating ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <Plus className="h-3 w-3" />
            )}
            Create
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Listeners Page ────────────────────────────────────────────────────

export function Listeners() {
  const [listeners, setListeners] = useState<Listener[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [searchQuery, setSearchQuery] = useState('')
  const [createDialog, setCreateDialog] = useState<CreateDialogState | null>(null)
  const [togglingIds, setTogglingIds] = useState<Set<string>>(new Set())

  const fetchListeners = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await specterClient.listListeners({})
      setListeners(res.listeners)
      setLastRefresh(new Date())
    } catch {
      setError('Unable to connect to teamserver')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchListeners()
    const interval = setInterval(fetchListeners, 10_000)
    return () => clearInterval(interval)
  }, [fetchListeners])

  const filteredListeners = useMemo(() => {
    if (!searchQuery) return listeners
    const q = searchQuery.toLowerCase()
    return listeners.filter((l) => {
      const searchable = [l.name, l.bindAddress, String(l.port), l.protocol, statusLabel(l.status)]
        .join(' ')
        .toLowerCase()
      return searchable.includes(q)
    })
  }, [listeners, searchQuery])

  const handleCreate = useCallback(async () => {
    if (!createDialog || !createDialog.name.trim()) return

    setCreateDialog((prev) => (prev ? { ...prev, creating: true, error: null } : null))

    try {
      const req = create(CreateListenerRequestSchema, {
        name: createDialog.name.trim(),
        bindAddress: createDialog.bindAddress,
        port: createDialog.port,
        protocol: createDialog.protocol,
      })
      const res = await specterClient.createListener(req)
      if (res.listener) {
        setListeners((prev) => [...prev, res.listener!])
      }
      setCreateDialog(null)
    } catch (err) {
      setCreateDialog((prev) =>
        prev
          ? {
              ...prev,
              creating: false,
              error: err instanceof Error ? err.message : 'Failed to create listener',
            }
          : null
      )
    }
  }, [createDialog])

  const handleToggle = useCallback(
    async (listener: Listener) => {
      const id = listener.id
      setTogglingIds((prev) => new Set(prev).add(id))

      try {
        if (listener.status === ListenerStatus.RUNNING) {
          const req = create(StopListenerRequestSchema, { id })
          const res = await specterClient.stopListener(req)
          if (res.listener) {
            setListeners((prev) => prev.map((l) => (l.id === id ? res.listener! : l)))
          }
        } else {
          const req = create(StartListenerRequestSchema, { id })
          const res = await specterClient.startListener(req)
          if (res.listener) {
            setListeners((prev) => prev.map((l) => (l.id === id ? res.listener! : l)))
          }
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to toggle listener')
        await fetchListeners()
      } finally {
        setTogglingIds((prev) => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
      }
    },
    [fetchListeners]
  )

  const handleDelete = useCallback(
    async (id: string) => {
      if (!confirm('Delete this listener? This cannot be undone.')) return
      try {
        const req = create(DeleteListenerRequestSchema, { id })
        await specterClient.deleteListener(req)
        setListeners((prev) => prev.filter((l) => l.id !== id))
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to delete listener')
      }
    },
    []
  )

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Listeners</h1>
          <p className="text-xs text-specter-muted">
            Manage C2 listener endpoints
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {filteredListeners.length} of {listeners.length} listeners
          </span>
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>

          <button
            onClick={fetchListeners}
            disabled={loading}
            className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          <button
            onClick={() => setCreateDialog({ ...initialCreateState })}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90"
          >
            <Plus className="h-3 w-3" />
            Create Listener
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-3 text-sm text-specter-danger">
          {error} — showing cached data
        </div>
      )}

      {/* Search */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search listeners..."
            className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
          />
        </div>
      </div>

      {/* Listeners Table */}
      {loading && listeners.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : filteredListeners.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-specter-muted">
          <Radio className="mb-2 h-8 w-8" />
          <p className="text-sm">No listeners found</p>
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="mt-2 text-xs text-specter-accent hover:underline"
            >
              Clear search
            </button>
          )}
        </div>
      ) : (
        <div className="rounded-lg border border-specter-border">
          {/* Table Header */}
          <div className="flex items-center gap-4 border-b border-specter-border bg-specter-surface px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-specter-muted">
            <span className="w-48">Name</span>
            <span className="w-36">Bind Address</span>
            <span className="w-20">Port</span>
            <span className="w-24">Protocol</span>
            <span className="w-24">Status</span>
            <span className="flex-1">Created</span>
            <span className="w-24 text-right">Actions</span>
          </div>

          {/* Table Rows */}
          {filteredListeners.map((listener) => {
            const isToggling = togglingIds.has(listener.id)
            const isRunning = listener.status === ListenerStatus.RUNNING

            return (
              <div
                key={listener.id}
                className="flex items-center gap-4 border-b border-specter-border px-4 py-3 transition-colors last:border-b-0 hover:bg-specter-surface"
              >
                {/* Name */}
                <div className="flex w-48 items-center gap-2">
                  <Radio className="h-3.5 w-3.5 shrink-0 text-specter-muted" />
                  <span className="truncate text-sm font-medium text-specter-text">
                    {listener.name}
                  </span>
                </div>

                {/* Bind Address */}
                <span className="w-36 truncate font-mono text-xs text-specter-muted">
                  {listener.bindAddress}
                </span>

                {/* Port */}
                <span className="w-20 font-mono text-xs text-specter-text">
                  {listener.port}
                </span>

                {/* Protocol */}
                <span className="w-24">
                  <span className="rounded border border-specter-border px-1.5 py-0.5 text-[10px] font-medium uppercase text-specter-muted">
                    {listener.protocol}
                  </span>
                </span>

                {/* Status */}
                <span className="w-24">
                  <StatusBadge status={listener.status} />
                </span>

                {/* Created */}
                <span className="flex-1 text-xs text-specter-muted">
                  {listener.createdAt ? formatTimestamp(new Date(Number(listener.createdAt.seconds) * 1000)) : '—'}
                </span>

                {/* Actions */}
                <div className="flex w-24 justify-end gap-1.5">
                  <button
                    onClick={() => handleToggle(listener)}
                    disabled={isToggling}
                    className={`flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs transition-colors disabled:opacity-50 ${
                      isRunning
                        ? 'border-specter-danger/30 text-specter-danger hover:bg-specter-danger/10'
                        : 'border-status-active/30 text-status-active hover:bg-status-active/10'
                    }`}
                  >
                    {isToggling ? (
                      <Loader className="h-3 w-3 animate-spin" />
                    ) : isRunning ? (
                      <Square className="h-3 w-3" />
                    ) : (
                      <Play className="h-3 w-3" />
                    )}
                    {isRunning ? 'Stop' : 'Start'}
                  </button>
                  <button
                    onClick={() => handleDelete(listener.id)}
                    disabled={isRunning}
                    className="flex items-center rounded border border-specter-border px-1.5 py-1 text-xs text-specter-muted transition-colors hover:border-specter-danger/30 hover:text-specter-danger disabled:opacity-30 disabled:cursor-not-allowed"
                    title={isRunning ? 'Stop listener before deleting' : 'Delete listener'}
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create Listener Dialog */}
      {createDialog && (
        <CreateListenerDialog
          state={createDialog}
          onClose={() => setCreateDialog(null)}
          onUpdate={(patch) =>
            setCreateDialog((prev) => (prev ? { ...prev, ...patch, error: null } : null))
          }
          onCreate={handleCreate}
        />
      )}
    </div>
  )
}
