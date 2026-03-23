import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import {
  Search,
  RefreshCw,
  Loader,
  Plus,
  X,
  Trash2,
  Webhook,
  Zap,
  CheckCircle,
  AlertCircle,
  Filter,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { WebhookInfo } from '@/gen/specter/v1/webhooks_pb'
import { WebhookFormat } from '@/gen/specter/v1/webhooks_pb'
import { create } from '@bufbuild/protobuf'
import {
  CreateWebhookRequestSchema,
  DeleteWebhookRequestSchema,
  TestWebhookRequestSchema,
} from '@/gen/specter/v1/webhooks_pb'

// ── Helpers ────────────────────────────────────────────────────────────

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

function truncateUrl(url: string, maxLen = 40): string {
  if (url.length <= maxLen) return url
  return url.slice(0, maxLen - 3) + '...'
}

function formatLabel(format: WebhookFormat): string {
  switch (format) {
    case WebhookFormat.GENERIC_JSON:
      return 'Generic JSON'
    case WebhookFormat.SLACK:
      return 'Slack'
    case WebhookFormat.SIEM_CEF:
      return 'SIEM CEF'
    default:
      return 'Unspecified'
  }
}

function formatBadgeClass(format: WebhookFormat): string {
  switch (format) {
    case WebhookFormat.GENERIC_JSON:
      return 'bg-blue-500/10 border-blue-500/30 text-blue-400'
    case WebhookFormat.SLACK:
      return 'bg-purple-500/10 border-purple-500/30 text-purple-400'
    case WebhookFormat.SIEM_CEF:
      return 'bg-orange-500/10 border-orange-500/30 text-orange-400'
    default:
      return 'bg-specter-muted/10 border-specter-muted/30 text-specter-muted'
  }
}

function parseEventFilters(eventFilters: string): string[] {
  try {
    const parsed = JSON.parse(eventFilters)
    if (Array.isArray(parsed)) return parsed
  } catch {
    // Fall back to line-separated parsing
  }
  return eventFilters
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
}

const EVENT_TYPES = [
  'session_new',
  'session_lost',
  'task_queued',
  'task_completed',
  'listener_started',
  'listener_stopped',
  'operator_login',
  'redirector_deployed',
  'redirector_burned',
]

// ── Types ──────────────────────────────────────────────────────────────

interface CreateFormState {
  name: string
  url: string
  secret: string
  format: WebhookFormat
  eventFilters: string
  enabled: boolean
  submitting: boolean
  result: { success: boolean; message: string } | null
}

interface ToastState {
  id: number
  message: string
  success: boolean
}

interface ConfirmState {
  webhookId: string
  webhookName: string
  deleting: boolean
}

// ── Components ─────────────────────────────────────────────────────────

function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, 4000)
    return () => clearTimeout(timer)
  }, [onDismiss])

  return (
    <div
      className={`flex items-center gap-2 rounded-lg border px-4 py-2.5 text-xs shadow-lg ${
        toast.success
          ? 'border-status-active/30 bg-status-active/10 text-status-active'
          : 'border-specter-danger/30 bg-specter-danger/10 text-specter-danger'
      }`}
    >
      {toast.success ? (
        <CheckCircle className="h-3.5 w-3.5 shrink-0" />
      ) : (
        <AlertCircle className="h-3.5 w-3.5 shrink-0" />
      )}
      <span>{toast.message}</span>
      <button onClick={onDismiss} className="ml-2 opacity-60 hover:opacity-100">
        <X className="h-3 w-3" />
      </button>
    </div>
  )
}

function ConfirmDialog({
  title,
  message,
  confirmLabel,
  loading: isLoading,
  onConfirm,
  onCancel,
}: {
  title: string
  message: string
  confirmLabel: string
  loading: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">{title}</h2>
          <button onClick={onCancel} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-4">
          <p className="text-xs text-specter-muted">{message}</p>
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-specter-border px-4 py-3">
          <button
            onClick={onCancel}
            className="rounded border border-specter-border px-3 py-1.5 text-xs text-specter-muted transition-colors hover:text-specter-text"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded bg-specter-danger px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-specter-danger/90 disabled:opacity-50"
          >
            {isLoading && <Loader className="h-3 w-3 animate-spin" />}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

function CreateWebhookDialog({
  state,
  onClose,
  onUpdate,
  onSubmit,
}: {
  state: CreateFormState
  onClose: () => void
  onUpdate: (patch: Partial<CreateFormState>) => void
  onSubmit: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Create Webhook</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          {/* Name */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Name</label>
            <input
              type="text"
              value={state.name}
              onChange={(e) => onUpdate({ name: e.target.value })}
              placeholder="e.g. Slack Alerts"
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* URL */}
          <div>
            <label className="text-xs font-medium text-specter-muted">URL</label>
            <input
              type="url"
              value={state.url}
              onChange={(e) => onUpdate({ url: e.target.value })}
              placeholder="https://hooks.example.com/webhook"
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none font-mono"
            />
          </div>

          {/* Secret */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Secret</label>
            <input
              type="password"
              value={state.secret}
              onChange={(e) => onUpdate({ secret: e.target.value })}
              placeholder="HMAC signing secret (optional)"
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none font-mono"
            />
          </div>

          {/* Format */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Format</label>
            <select
              value={state.format}
              onChange={(e) => onUpdate({ format: Number(e.target.value) as WebhookFormat })}
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
            >
              <option value={WebhookFormat.GENERIC_JSON}>Generic JSON</option>
              <option value={WebhookFormat.SLACK}>Slack</option>
              <option value={WebhookFormat.SIEM_CEF}>SIEM CEF</option>
            </select>
          </div>

          {/* Event Filters */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Event Filters</label>
            <textarea
              value={state.eventFilters}
              onChange={(e) => onUpdate({ eventFilters: e.target.value })}
              placeholder={EVENT_TYPES.join('\n')}
              rows={5}
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none font-mono"
            />
            <span className="mt-1 text-[10px] text-specter-muted">
              One event type per line. Leave empty to receive all events.
            </span>
          </div>

          {/* Enabled */}
          <label className="flex items-center gap-2 text-xs text-specter-text">
            <input
              type="checkbox"
              checked={state.enabled}
              onChange={(e) => onUpdate({ enabled: e.target.checked })}
              className="rounded border-specter-border"
            />
            Enabled
          </label>

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
            onClick={onSubmit}
            disabled={!state.name || !state.url || state.submitting}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
          >
            {state.submitting ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <Plus className="h-3 w-3" />
            )}
            Create Webhook
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Webhooks Page ─────────────────────────────────────────────────────

export function Webhooks() {
  const [webhooks, setWebhooks] = useState<WebhookInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [searchQuery, setSearchQuery] = useState('')
  const [formatFilter, setFormatFilter] = useState<string>('all')
  const [createForm, setCreateForm] = useState<CreateFormState | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<ConfirmState | null>(null)
  const [toasts, setToasts] = useState<ToastState[]>([])
  const [testingIds, setTestingIds] = useState<Set<string>>(new Set())

  const toastCounter = useRef(0)

  const addToast = useCallback((message: string, success: boolean) => {
    const id = ++toastCounter.current
    setToasts((prev) => [...prev, { id, message, success }])
  }, [])

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const res = await specterClient.listWebhooks({})
      setWebhooks(res.webhooks)
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

  const filteredWebhooks = useMemo(() => {
    return webhooks.filter((wh) => {
      // Format filter
      if (formatFilter !== 'all' && wh.format !== Number(formatFilter)) return false

      // Search
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        const searchable = [wh.name, wh.url, wh.id].join(' ').toLowerCase()
        if (!searchable.includes(q)) return false
      }

      return true
    })
  }, [webhooks, formatFilter, searchQuery])

  const handleCreate = useCallback(() => {
    setCreateForm({
      name: '',
      url: '',
      secret: '',
      format: WebhookFormat.GENERIC_JSON,
      eventFilters: '',
      enabled: true,
      submitting: false,
      result: null,
    })
  }, [])

  const handleCreateSubmit = useCallback(async () => {
    if (!createForm) return

    setCreateForm((prev) => (prev ? { ...prev, submitting: true, result: null } : null))

    try {
      const filters = createForm.eventFilters
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean)

      const req = create(CreateWebhookRequestSchema, {
        name: createForm.name,
        url: createForm.url,
        secret: createForm.secret,
        eventFilters: JSON.stringify(filters),
        format: createForm.format,
      })

      await specterClient.createWebhook(req)

      setCreateForm(null)
      addToast(`Webhook "${createForm.name}" created`, true)
      fetchData()
    } catch (err) {
      setCreateForm((prev) =>
        prev
          ? {
              ...prev,
              submitting: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Failed to create webhook',
              },
            }
          : null
      )
    }
  }, [createForm, addToast, fetchData])

  const handleTest = useCallback(
    async (webhook: WebhookInfo) => {
      setTestingIds((prev) => new Set(prev).add(webhook.id))

      try {
        const req = create(TestWebhookRequestSchema, { id: webhook.id })
        const res = await specterClient.testWebhook(req)

        if (res.success) {
          addToast(`Test to "${webhook.name}" succeeded: ${res.statusMessage || 'OK'}`, true)
        } else {
          addToast(
            `Test to "${webhook.name}" failed: ${res.statusMessage || 'Unknown error'}`,
            false
          )
        }
      } catch (err) {
        addToast(
          `Test to "${webhook.name}" failed: ${err instanceof Error ? err.message : 'Request error'}`,
          false
        )
      } finally {
        setTestingIds((prev) => {
          const next = new Set(prev)
          next.delete(webhook.id)
          return next
        })
      }
    },
    [addToast]
  )

  const handleDelete = useCallback(async () => {
    if (!confirmDelete) return

    setConfirmDelete((prev) => (prev ? { ...prev, deleting: true } : null))

    try {
      const req = create(DeleteWebhookRequestSchema, { id: confirmDelete.webhookId })
      await specterClient.deleteWebhook(req)

      addToast(`Webhook "${confirmDelete.webhookName}" deleted`, true)
      setConfirmDelete(null)
      fetchData()
    } catch (err) {
      addToast(
        `Failed to delete webhook: ${err instanceof Error ? err.message : 'Unknown error'}`,
        false
      )
      setConfirmDelete(null)
    }
  }, [confirmDelete, addToast, fetchData])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Webhooks</h1>
          <p className="text-xs text-specter-muted">
            Manage webhook integrations for event notifications
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {filteredWebhooks.length} of {webhooks.length} webhooks
          </span>
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>

          <button
            onClick={handleCreate}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90"
          >
            <Plus className="h-3 w-3" />
            Create Webhook
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
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[200px] flex-1">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search webhooks..."
            className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5 text-specter-muted" />
          <select
            value={formatFilter}
            onChange={(e) => setFormatFilter(e.target.value)}
            className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
          >
            <option value="all">All Formats</option>
            <option value={WebhookFormat.GENERIC_JSON}>Generic JSON</option>
            <option value={WebhookFormat.SLACK}>Slack</option>
            <option value={WebhookFormat.SIEM_CEF}>SIEM CEF</option>
          </select>
        </div>
      </div>

      {/* Table */}
      {loading && webhooks.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : filteredWebhooks.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-specter-muted">
          <Webhook className="mb-2 h-8 w-8" />
          <p className="text-sm">No webhooks found</p>
          {(searchQuery || formatFilter !== 'all') && (
            <button
              onClick={() => {
                setSearchQuery('')
                setFormatFilter('all')
              }}
              className="mt-2 text-xs text-specter-accent hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-specter-border">
          {/* Table Header */}
          <div className="grid grid-cols-[1fr_1.5fr_auto_auto_auto_auto_auto] items-center gap-4 border-b border-specter-border bg-specter-surface px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-specter-muted">
            <span>Name</span>
            <span>URL</span>
            <span>Format</span>
            <span>Enabled</span>
            <span>Filters</span>
            <span>Created</span>
            <span>Actions</span>
          </div>

          {/* Table Rows */}
          {filteredWebhooks.map((wh) => {
            const filters = parseEventFilters(wh.eventFilters)
            const isTesting = testingIds.has(wh.id)

            return (
              <div
                key={wh.id}
                className="grid grid-cols-[1fr_1.5fr_auto_auto_auto_auto_auto] items-center gap-4 border-b border-specter-border px-4 py-3 transition-colors last:border-b-0 hover:bg-specter-surface"
              >
                {/* Name */}
                <div className="flex items-center gap-2">
                  <Webhook className="h-3.5 w-3.5 shrink-0 text-specter-muted" />
                  <span className="truncate text-sm font-medium text-specter-text">{wh.name}</span>
                </div>

                {/* URL */}
                <span
                  className="truncate font-mono text-xs text-specter-muted"
                  title={wh.url}
                >
                  {truncateUrl(wh.url)}
                </span>

                {/* Format Badge */}
                <span
                  className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${formatBadgeClass(wh.format)}`}
                >
                  {formatLabel(wh.format)}
                </span>

                {/* Enabled */}
                <span
                  className={`text-xs font-medium ${
                    wh.enabled ? 'text-status-active' : 'text-specter-muted'
                  }`}
                >
                  {wh.enabled ? 'On' : 'Off'}
                </span>

                {/* Event Filters Count */}
                <span className="text-xs text-specter-muted">
                  {filters.length > 0 ? `${filters.length} event${filters.length > 1 ? 's' : ''}` : 'All'}
                </span>

                {/* Created */}
                <span className="whitespace-nowrap text-xs text-specter-muted">
                  {wh.createdAt ? formatDate(new Date(Number(wh.createdAt.seconds) * 1000)) : '—'}
                </span>

                {/* Actions */}
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => handleTest(wh)}
                    disabled={isTesting}
                    className="flex items-center gap-1 rounded border border-specter-border px-2 py-1 text-[10px] text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
                    title="Test Webhook"
                  >
                    {isTesting ? (
                      <Loader className="h-3 w-3 animate-spin" />
                    ) : (
                      <Zap className="h-3 w-3" />
                    )}
                    Test
                  </button>
                  <button
                    onClick={() =>
                      setConfirmDelete({
                        webhookId: wh.id,
                        webhookName: wh.name,
                        deleting: false,
                      })
                    }
                    className="flex items-center gap-1 rounded border border-specter-danger/30 px-2 py-1 text-[10px] text-specter-danger transition-colors hover:bg-specter-danger/10"
                    title="Delete Webhook"
                  >
                    <Trash2 className="h-3 w-3" />
                    Delete
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create Dialog */}
      {createForm && (
        <CreateWebhookDialog
          state={createForm}
          onClose={() => setCreateForm(null)}
          onUpdate={(patch) =>
            setCreateForm((prev) => (prev ? { ...prev, ...patch, result: null } : null))
          }
          onSubmit={handleCreateSubmit}
        />
      )}

      {/* Delete Confirm Dialog */}
      {confirmDelete && (
        <ConfirmDialog
          title="Delete Webhook"
          message={`Are you sure you want to delete "${confirmDelete.webhookName}"? This action cannot be undone.`}
          confirmLabel="Delete"
          loading={confirmDelete.deleting}
          onConfirm={handleDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      )}

      {/* Toasts */}
      {toasts.length > 0 && (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
          {toasts.map((t) => (
            <Toast key={t.id} toast={t} onDismiss={() => removeToast(t.id)} />
          ))}
        </div>
      )}
    </div>
  )
}
