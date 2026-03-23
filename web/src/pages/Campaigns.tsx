import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search,
  RefreshCw,
  Loader,
  Plus,
  X,
  Users,
  Monitor,
  Radio,
  Calendar,
  Trash2,
  UserPlus,
  FolderOpen,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type {
  CampaignInfo,
  CampaignOperator,
} from '@/gen/specter/v1/campaigns_pb'
import {
  CampaignAccessLevel,
  CreateCampaignRequestSchema,
  AddOperatorToCampaignRequestSchema,
  RemoveOperatorFromCampaignRequestSchema,
  AddSessionToCampaignRequestSchema,
  RemoveSessionFromCampaignRequestSchema,
} from '@/gen/specter/v1/campaigns_pb'
import { create } from '@bufbuild/protobuf'

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

function accessLevelLabel(level: CampaignAccessLevel): string {
  switch (level) {
    case CampaignAccessLevel.FULL:
      return 'FULL'
    case CampaignAccessLevel.READ_ONLY:
      return 'READ_ONLY'
    default:
      return 'UNSPECIFIED'
  }
}

function accessLevelBadgeClass(level: CampaignAccessLevel): string {
  switch (level) {
    case CampaignAccessLevel.FULL:
      return 'border-specter-accent/30 bg-specter-accent/10 text-specter-accent'
    case CampaignAccessLevel.READ_ONLY:
      return 'border-specter-muted/30 bg-specter-muted/10 text-specter-muted'
    default:
      return 'border-specter-border bg-specter-surface text-specter-muted'
  }
}

// ── Types ──────────────────────────────────────────────────────────────

interface ListenerOption {
  id: string
  name: string
}

interface OperatorOption {
  id: string
  username: string
}

interface SessionOption {
  id: string
  hostname: string
  username: string
}

interface CreateDialogState {
  name: string
  description: string
  listenerId: string
  creating: boolean
  result: { success: boolean; message: string } | null
}

interface AddOperatorDialogState {
  campaignId: string
  operatorId: string
  accessLevel: CampaignAccessLevel
  adding: boolean
  result: { success: boolean; message: string } | null
}

interface AddSessionDialogState {
  campaignId: string
  sessionId: string
  adding: boolean
  result: { success: boolean; message: string } | null
}

interface ConfirmRemoveState {
  type: 'operator' | 'session'
  campaignId: string
  targetId: string
  targetLabel: string
  loading: boolean
}

// ── Components ─────────────────────────────────────────────────────────

function CampaignCard({
  campaign,
  expanded,
  onToggle,
  onAddOperator,
  onRemoveOperator,
  onAddSession,
  onRemoveSession,
}: {
  campaign: CampaignInfo
  expanded: boolean
  onToggle: () => void
  onAddOperator: () => void
  onRemoveOperator: (operatorId: string, username: string) => void
  onAddSession: () => void
  onRemoveSession: (sessionId: string) => void
}) {
  return (
    <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface transition-colors hover:border-specter-muted">
      {/* Card Header */}
      <button
        onClick={onToggle}
        className="flex w-full items-start justify-between p-4 text-left"
      >
        <div className="flex items-center gap-2">
          <FolderOpen className="h-4 w-4 text-specter-muted" />
          <div>
            <h3 className="text-sm font-medium text-specter-text">{campaign.name}</h3>
            <p className="mt-0.5 text-xs text-specter-muted line-clamp-2">
              {campaign.description || 'No description'}
            </p>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 shrink-0 text-specter-muted" />
        ) : (
          <ChevronDown className="h-4 w-4 shrink-0 text-specter-muted" />
        )}
      </button>

      {/* Summary Stats */}
      <div className="flex items-center gap-4 border-t border-specter-border px-4 py-2.5">
        <div className="flex items-center gap-1.5 text-xs">
          <Users className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">
            {campaign.operators.length} operator(s)
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <Monitor className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">
            {campaign.sessionIds.length} session(s)
          </span>
        </div>
        {campaign.listenerId && (
          <div className="flex items-center gap-1.5 text-xs">
            <Radio className="h-3 w-3 text-specter-muted" />
            <span className="text-specter-muted truncate max-w-[120px]" title={campaign.listenerId}>
              {campaign.listenerId.slice(0, 8)}...
            </span>
          </div>
        )}
        {campaign.createdAt && (
          <div className="flex items-center gap-1.5 text-xs ml-auto">
            <Calendar className="h-3 w-3 text-specter-muted" />
            <span className="text-specter-muted">
              {formatDate(new Date(Number(campaign.createdAt.seconds) * 1000))}
            </span>
          </div>
        )}
      </div>

      {/* Expanded Detail */}
      {expanded && (
        <div className="flex flex-col gap-4 border-t border-specter-border p-4">
          {/* Operators Section */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-specter-text">Operators</span>
              <button
                onClick={onAddOperator}
                className="flex items-center gap-1 rounded border border-specter-accent/30 bg-specter-accent/10 px-2 py-1 text-[10px] text-specter-accent transition-colors hover:bg-specter-accent/20"
              >
                <UserPlus className="h-3 w-3" />
                Add Operator
              </button>
            </div>
            {campaign.operators.length === 0 ? (
              <div className="rounded border border-specter-border px-3 py-3 text-center text-xs text-specter-muted">
                No operators assigned
              </div>
            ) : (
              <div className="rounded border border-specter-border">
                {campaign.operators.map((op: CampaignOperator) => (
                  <div
                    key={op.operatorId}
                    className="flex items-center gap-3 border-b border-specter-border px-3 py-2 last:border-0"
                  >
                    <Users className="h-3 w-3 text-specter-muted" />
                    <span className="flex-1 text-xs text-specter-text">{op.username}</span>
                    <span
                      className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${accessLevelBadgeClass(op.accessLevel)}`}
                    >
                      {accessLevelLabel(op.accessLevel)}
                    </span>
                    <button
                      onClick={() => onRemoveOperator(op.operatorId, op.username)}
                      className="rounded p-1 text-specter-muted transition-colors hover:bg-specter-danger/10 hover:text-specter-danger"
                      title="Remove operator"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Sessions Section */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-specter-text">Sessions</span>
              <button
                onClick={onAddSession}
                className="flex items-center gap-1 rounded border border-specter-accent/30 bg-specter-accent/10 px-2 py-1 text-[10px] text-specter-accent transition-colors hover:bg-specter-accent/20"
              >
                <Plus className="h-3 w-3" />
                Add Session
              </button>
            </div>
            {campaign.sessionIds.length === 0 ? (
              <div className="rounded border border-specter-border px-3 py-3 text-center text-xs text-specter-muted">
                No sessions assigned
              </div>
            ) : (
              <div className="rounded border border-specter-border">
                {campaign.sessionIds.map((sid: string) => (
                  <div
                    key={sid}
                    className="flex items-center gap-3 border-b border-specter-border px-3 py-2 last:border-0"
                  >
                    <Monitor className="h-3 w-3 text-specter-muted" />
                    <span className="flex-1 font-mono text-xs text-specter-text">{sid}</span>
                    <button
                      onClick={() => onRemoveSession(sid)}
                      className="rounded p-1 text-specter-muted transition-colors hover:bg-specter-danger/10 hover:text-specter-danger"
                      title="Remove session"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Listener ID */}
          {campaign.listenerId && (
            <div>
              <span className="text-xs font-medium text-specter-text">Listener</span>
              <div className="mt-1 rounded border border-specter-border px-3 py-2">
                <div className="flex items-center gap-2 text-xs">
                  <Radio className="h-3 w-3 text-specter-muted" />
                  <span className="font-mono text-specter-text">{campaign.listenerId}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CreateCampaignDialog({
  state,
  listeners,
  onClose,
  onUpdate,
  onCreate,
}: {
  state: CreateDialogState
  listeners: ListenerOption[]
  onClose: () => void
  onUpdate: (patch: Partial<CreateDialogState>) => void
  onCreate: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Create Campaign</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Name</label>
            <input
              type="text"
              value={state.name}
              onChange={(e) => onUpdate({ name: e.target.value })}
              placeholder="Campaign name"
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Description</label>
            <textarea
              value={state.description}
              onChange={(e) => onUpdate({ description: e.target.value })}
              placeholder="Campaign description..."
              rows={3}
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Listener</label>
            <select
              value={state.listenerId}
              onChange={(e) => onUpdate({ listenerId: e.target.value })}
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
            >
              <option value="">Select a listener...</option>
              {listeners.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name} ({l.id.slice(0, 8)}...)
                </option>
              ))}
            </select>
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

function AddOperatorDialog({
  state,
  operators,
  onClose,
  onUpdate,
  onAdd,
}: {
  state: AddOperatorDialogState
  operators: OperatorOption[]
  onClose: () => void
  onUpdate: (patch: Partial<AddOperatorDialogState>) => void
  onAdd: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Add Operator</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Operator</label>
            <select
              value={state.operatorId}
              onChange={(e) => onUpdate({ operatorId: e.target.value })}
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
            >
              <option value="">Select an operator...</option>
              {operators.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.username}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Access Level</label>
            <select
              value={state.accessLevel}
              onChange={(e) =>
                onUpdate({ accessLevel: Number(e.target.value) as CampaignAccessLevel })
              }
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
            >
              <option value={CampaignAccessLevel.READ_ONLY}>READ_ONLY</option>
              <option value={CampaignAccessLevel.FULL}>FULL</option>
            </select>
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
            onClick={onAdd}
            disabled={!state.operatorId || state.adding}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
          >
            {state.adding ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <UserPlus className="h-3 w-3" />
            )}
            Add
          </button>
        </div>
      </div>
    </div>
  )
}

function AddSessionDialog({
  state,
  sessions,
  onClose,
  onUpdate,
  onAdd,
}: {
  state: AddSessionDialogState
  sessions: SessionOption[]
  onClose: () => void
  onUpdate: (patch: Partial<AddSessionDialogState>) => void
  onAdd: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Add Session</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-specter-muted">Session</label>
            <select
              value={state.sessionId}
              onChange={(e) => onUpdate({ sessionId: e.target.value })}
              className="w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
            >
              <option value="">Select a session...</option>
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.hostname}\{s.username} ({s.id.slice(0, 8)}...)
                </option>
              ))}
            </select>
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
            onClick={onAdd}
            disabled={!state.sessionId || state.adding}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
          >
            {state.adding ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <Plus className="h-3 w-3" />
            )}
            Add
          </button>
        </div>
      </div>
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

// ── Campaigns Page ────────────────────────────────────────────────────

export function Campaigns() {
  const [campaigns, setCampaigns] = useState<CampaignInfo[]>([])
  const [listeners, setListeners] = useState<ListenerOption[]>([])
  const [operators, setOperators] = useState<OperatorOption[]>([])
  const [sessions, setSessions] = useState<SessionOption[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [createDialog, setCreateDialog] = useState<CreateDialogState | null>(null)
  const [addOperatorDialog, setAddOperatorDialog] = useState<AddOperatorDialogState | null>(null)
  const [addSessionDialog, setAddSessionDialog] = useState<AddSessionDialogState | null>(null)
  const [confirmRemove, setConfirmRemove] = useState<ConfirmRemoveState | null>(null)

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const [campaignsRes, listenersRes, operatorsRes, sessionsRes] = await Promise.allSettled([
        specterClient.listCampaigns({}),
        specterClient.listListeners({}),
        specterClient.listOperators({}),
        specterClient.listSessions({}),
      ])

      if (campaignsRes.status === 'fulfilled') {
        setCampaigns(campaignsRes.value.campaigns)
      }
      if (listenersRes.status === 'fulfilled') {
        setListeners(
          listenersRes.value.listeners.map((l: { id: string; name: string }) => ({
            id: l.id,
            name: l.name,
          }))
        )
      }
      if (operatorsRes.status === 'fulfilled') {
        setOperators(
          operatorsRes.value.operators.map((o: { id: string; username: string }) => ({
            id: o.id,
            username: o.username,
          }))
        )
      }
      if (sessionsRes.status === 'fulfilled') {
        setSessions(
          sessionsRes.value.sessions.map(
            (s: { id: string; hostname: string; username: string }) => ({
              id: s.id,
              hostname: s.hostname,
              username: s.username,
            })
          )
        )
      }

      if (campaignsRes.status === 'rejected') {
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

  const filteredCampaigns = useMemo(() => {
    if (!searchQuery) return campaigns
    const q = searchQuery.toLowerCase()
    return campaigns.filter((c) =>
      [c.name, c.description, c.id, c.createdBy, c.listenerId]
        .join(' ')
        .toLowerCase()
        .includes(q)
    )
  }, [campaigns, searchQuery])

  // ── Create Campaign ───────────────────────────────────────────────

  const handleCreate = useCallback(async () => {
    if (!createDialog) return

    setCreateDialog((prev) => (prev ? { ...prev, creating: true, result: null } : null))

    try {
      const req = create(CreateCampaignRequestSchema, {
        name: createDialog.name,
        description: createDialog.description,
        listenerId: createDialog.listenerId || undefined,
      })
      await specterClient.createCampaign(req)

      setCreateDialog((prev) =>
        prev
          ? { ...prev, creating: false, result: { success: true, message: 'Campaign created successfully' } }
          : null
      )
      await fetchData()
    } catch (err) {
      setCreateDialog((prev) =>
        prev
          ? {
              ...prev,
              creating: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Create failed',
              },
            }
          : null
      )
    }
  }, [createDialog, fetchData])

  // ── Add Operator ──────────────────────────────────────────────────

  const handleAddOperator = useCallback(async () => {
    if (!addOperatorDialog) return

    setAddOperatorDialog((prev) => (prev ? { ...prev, adding: true, result: null } : null))

    try {
      const req = create(AddOperatorToCampaignRequestSchema, {
        campaignId: addOperatorDialog.campaignId,
        operatorId: addOperatorDialog.operatorId,
        accessLevel: addOperatorDialog.accessLevel,
      })
      await specterClient.addOperatorToCampaign(req)

      setAddOperatorDialog((prev) =>
        prev
          ? { ...prev, adding: false, result: { success: true, message: 'Operator added successfully' } }
          : null
      )
      await fetchData()
    } catch (err) {
      setAddOperatorDialog((prev) =>
        prev
          ? {
              ...prev,
              adding: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Failed to add operator',
              },
            }
          : null
      )
    }
  }, [addOperatorDialog, fetchData])

  // ── Add Session ───────────────────────────────────────────────────

  const handleAddSession = useCallback(async () => {
    if (!addSessionDialog) return

    setAddSessionDialog((prev) => (prev ? { ...prev, adding: true, result: null } : null))

    try {
      const req = create(AddSessionToCampaignRequestSchema, {
        campaignId: addSessionDialog.campaignId,
        sessionId: addSessionDialog.sessionId,
      })
      await specterClient.addSessionToCampaign(req)

      setAddSessionDialog((prev) =>
        prev
          ? { ...prev, adding: false, result: { success: true, message: 'Session added successfully' } }
          : null
      )
      await fetchData()
    } catch (err) {
      setAddSessionDialog((prev) =>
        prev
          ? {
              ...prev,
              adding: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Failed to add session',
              },
            }
          : null
      )
    }
  }, [addSessionDialog, fetchData])

  // ── Remove Operator / Session ─────────────────────────────────────

  const handleConfirmRemove = useCallback(async () => {
    if (!confirmRemove) return

    setConfirmRemove((prev) => (prev ? { ...prev, loading: true } : null))

    try {
      if (confirmRemove.type === 'operator') {
        const req = create(RemoveOperatorFromCampaignRequestSchema, {
          campaignId: confirmRemove.campaignId,
          operatorId: confirmRemove.targetId,
        })
        await specterClient.removeOperatorFromCampaign(req)
      } else {
        const req = create(RemoveSessionFromCampaignRequestSchema, {
          campaignId: confirmRemove.campaignId,
          sessionId: confirmRemove.targetId,
        })
        await specterClient.removeSessionFromCampaign(req)
      }

      setConfirmRemove(null)
      await fetchData()
    } catch {
      setConfirmRemove((prev) => (prev ? { ...prev, loading: false } : null))
    }
  }, [confirmRemove, fetchData])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Campaigns</h1>
          <p className="text-xs text-specter-muted">
            Manage campaigns, operators, and sessions
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {campaigns.length} campaign(s) &middot; Updated {formatRelativeTime(lastRefresh)}
          </span>
          <button
            onClick={() =>
              setCreateDialog({
                name: '',
                description: '',
                listenerId: '',
                creating: false,
                result: null,
              })
            }
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs font-medium text-specter-bg transition-colors hover:bg-specter-accent/90"
          >
            <Plus className="h-3 w-3" />
            Create Campaign
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

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search campaigns..."
          className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
        />
      </div>

      {/* Campaign Grid */}
      {loading && campaigns.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : filteredCampaigns.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-specter-muted">
          <FolderOpen className="mb-2 h-8 w-8" />
          <p className="text-sm">No campaigns found</p>
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
        <div className="grid grid-cols-3 gap-4">
          {filteredCampaigns.map((c) => (
            <CampaignCard
              key={c.id}
              campaign={c}
              expanded={expandedId === c.id}
              onToggle={() => setExpandedId((prev) => (prev === c.id ? null : c.id))}
              onAddOperator={() =>
                setAddOperatorDialog({
                  campaignId: c.id,
                  operatorId: '',
                  accessLevel: CampaignAccessLevel.READ_ONLY,
                  adding: false,
                  result: null,
                })
              }
              onRemoveOperator={(operatorId, username) =>
                setConfirmRemove({
                  type: 'operator',
                  campaignId: c.id,
                  targetId: operatorId,
                  targetLabel: username,
                  loading: false,
                })
              }
              onAddSession={() =>
                setAddSessionDialog({
                  campaignId: c.id,
                  sessionId: '',
                  adding: false,
                  result: null,
                })
              }
              onRemoveSession={(sessionId) =>
                setConfirmRemove({
                  type: 'session',
                  campaignId: c.id,
                  targetId: sessionId,
                  targetLabel: sessionId,
                  loading: false,
                })
              }
            />
          ))}
        </div>
      )}

      {/* Create Campaign Dialog */}
      {createDialog && (
        <CreateCampaignDialog
          state={createDialog}
          listeners={listeners}
          onClose={() => setCreateDialog(null)}
          onUpdate={(patch) => setCreateDialog((prev) => (prev ? { ...prev, ...patch } : null))}
          onCreate={handleCreate}
        />
      )}

      {/* Add Operator Dialog */}
      {addOperatorDialog && (
        <AddOperatorDialog
          state={addOperatorDialog}
          operators={operators}
          onClose={() => setAddOperatorDialog(null)}
          onUpdate={(patch) =>
            setAddOperatorDialog((prev) => (prev ? { ...prev, ...patch } : null))
          }
          onAdd={handleAddOperator}
        />
      )}

      {/* Add Session Dialog */}
      {addSessionDialog && (
        <AddSessionDialog
          state={addSessionDialog}
          sessions={sessions}
          onClose={() => setAddSessionDialog(null)}
          onUpdate={(patch) =>
            setAddSessionDialog((prev) => (prev ? { ...prev, ...patch } : null))
          }
          onAdd={handleAddSession}
        />
      )}

      {/* Confirm Remove Dialog */}
      {confirmRemove && (
        <ConfirmDialog
          title={`Remove ${confirmRemove.type === 'operator' ? 'Operator' : 'Session'}`}
          message={`Are you sure you want to remove ${confirmRemove.type === 'operator' ? 'operator' : 'session'} "${confirmRemove.targetLabel}" from this campaign? This action cannot be undone.`}
          confirmLabel="Remove"
          loading={confirmRemove.loading}
          onConfirm={handleConfirmRemove}
          onCancel={() => setConfirmRemove(null)}
        />
      )}
    </div>
  )
}
