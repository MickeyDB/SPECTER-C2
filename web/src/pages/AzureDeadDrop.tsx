import { useState, useCallback } from 'react'
import {
  RefreshCw,
  Loader,
  Plus,
  X,
  Cloud,
  Eye,
  EyeOff,
  Info,
  CheckCircle,
  XCircle,
  Key,
  Clock,
  Database,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { AzureListenerInfo, AzureContainerInfo } from '@/gen/specter/v1/azure_pb'
import { create } from '@bufbuild/protobuf'
import {
  CreateAzureListenerRequestSchema,
  ListAzureContainersRequestSchema,
} from '@/gen/specter/v1/azure_pb'

// ── Helpers ────────────────────────────────────────────────────────────

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

function formatTimestamp(ts: { seconds: bigint; nanos: number } | undefined): string {
  if (!ts) return 'N/A'
  const date = new Date(Number(ts.seconds) * 1000)
  return date.toLocaleString()
}

function generateEncryptionKeyHex(): string {
  const parts = [crypto.randomUUID(), crypto.randomUUID()]
  return parts.join('').replace(/-/g, '').slice(0, 64)
}

const statusColors: Record<string, string> = {
  running: 'text-status-active',
  active: 'text-status-active',
  listening: 'text-status-active',
  stopped: 'text-specter-muted',
  error: 'text-status-dead',
}

const statusBgColors: Record<string, string> = {
  running: 'bg-status-active/10 border-status-active/30',
  active: 'bg-status-active/10 border-status-active/30',
  listening: 'bg-status-active/10 border-status-active/30',
  stopped: 'bg-specter-muted/10 border-specter-muted/30',
  error: 'bg-status-dead/10 border-status-dead/30',
}

// ── Types ──────────────────────────────────────────────────────────────

interface CreateDialogState {
  name: string
  accountName: string
  accountSasToken: string
  pollIntervalSecs: string
  maxBlobAgeSecs: string
  encryptionKeyHex: string
  creating: boolean
  result: { success: boolean; message: string } | null
}

// ── Components ─────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase()
  const colorClass = statusColors[s] ?? 'text-specter-muted'
  const bgClass = statusBgColors[s] ?? 'bg-specter-muted/10 border-specter-muted/30'
  const Icon = s === 'running' || s === 'active' || s === 'listening' ? CheckCircle : XCircle

  return (
    <span className={`flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium ${bgClass} ${colorClass}`}>
      <Icon className="h-2.5 w-2.5" />
      {status}
    </span>
  )
}

function MaskedValue({ value }: { value: string }) {
  const [revealed, setRevealed] = useState(false)

  return (
    <div className="flex items-center gap-1.5">
      <span className="font-mono text-xs text-specter-text">
        {revealed ? value : value.slice(0, 8) + '\u2022'.repeat(12)}
      </span>
      <button
        onClick={() => setRevealed(!revealed)}
        className="text-specter-muted hover:text-specter-text"
        title={revealed ? 'Hide' : 'Reveal'}
      >
        {revealed ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
      </button>
    </div>
  )
}

function ListenerCard({
  listener,
  selected,
  onClick,
}: {
  listener: AzureListenerInfo
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`flex w-full flex-col rounded-lg border p-4 text-left transition-colors hover:border-specter-muted ${
        selected
          ? 'border-specter-accent bg-specter-accent/5'
          : 'border-specter-border bg-specter-surface'
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <Cloud className="h-4 w-4 text-specter-muted" />
          <h3 className="text-sm font-medium text-specter-text">{listener.name}</h3>
        </div>
        <StatusBadge status={listener.status || 'unknown'} />
      </div>

      {/* Details */}
      <div className="mt-3 flex flex-col gap-1.5">
        <div className="flex items-center gap-2 text-xs">
          <Database className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">Account:</span>
          <span className="text-specter-text">{listener.accountName}</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Clock className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">Poll:</span>
          <span className="text-specter-text">{Number(listener.pollIntervalSecs)}s</span>
          <span className="text-specter-muted">&middot;</span>
          <span className="text-specter-muted">Max Age:</span>
          <span className="text-specter-text">{Number(listener.maxBlobAgeSecs)}s</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Key className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">Key:</span>
          <MaskedValue value={listener.encryptionKeyHex} />
        </div>
      </div>
    </button>
  )
}

function ContainerTable({ containers }: { containers: AzureContainerInfo[] }) {
  if (containers.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-specter-muted">
        <Database className="mb-2 h-8 w-8" />
        <p className="text-sm">No containers for this listener</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-specter-border">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-specter-border bg-specter-surface">
            <th className="px-4 py-2.5 font-medium text-specter-muted">Session ID</th>
            <th className="px-4 py-2.5 font-medium text-specter-muted">Container Name</th>
            <th className="px-4 py-2.5 font-medium text-specter-muted">Provisioned</th>
            <th className="px-4 py-2.5 font-medium text-specter-muted">Cmd Seq</th>
            <th className="px-4 py-2.5 font-medium text-specter-muted">Result Seq</th>
            <th className="px-4 py-2.5 font-medium text-specter-muted">Created</th>
          </tr>
        </thead>
        <tbody>
          {containers.map((c) => (
            <tr
              key={c.sessionId}
              className="border-b border-specter-border transition-colors hover:bg-specter-surface"
            >
              <td className="px-4 py-2.5 font-mono text-specter-text">{c.sessionId}</td>
              <td className="px-4 py-2.5 text-specter-text">{c.containerName}</td>
              <td className="px-4 py-2.5">
                {c.provisioned ? (
                  <span className="inline-flex items-center gap-1 rounded border border-status-active/30 bg-status-active/10 px-1.5 py-0.5 text-[10px] font-medium text-status-active">
                    <CheckCircle className="h-2.5 w-2.5" />
                    Yes
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded border border-specter-muted/30 bg-specter-muted/10 px-1.5 py-0.5 text-[10px] font-medium text-specter-muted">
                    <XCircle className="h-2.5 w-2.5" />
                    No
                  </span>
                )}
              </td>
              <td className="px-4 py-2.5 font-mono text-specter-text">{c.nextCmdSeq}</td>
              <td className="px-4 py-2.5 font-mono text-specter-text">{c.nextResultSeq}</td>
              <td className="px-4 py-2.5 text-specter-muted">{formatTimestamp(c.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CreateListenerDialog({
  state,
  onClose,
  onChange,
  onCreate,
}: {
  state: CreateDialogState
  onClose: () => void
  onChange: (patch: Partial<CreateDialogState>) => void
  onCreate: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Create Azure Listener</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          {/* Name */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Listener Name</label>
            <input
              type="text"
              value={state.name}
              onChange={(e) => onChange({ name: e.target.value })}
              placeholder="azure-deaddrop-01"
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* Account Name */}
          <div>
            <label className="text-xs font-medium text-specter-muted">
              Azure Storage Account Name
            </label>
            <input
              type="text"
              value={state.accountName}
              onChange={(e) => onChange({ accountName: e.target.value })}
              placeholder="specterstorage01"
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* SAS Token */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Account SAS Token</label>
            <input
              type="password"
              value={state.accountSasToken}
              onChange={(e) => onChange({ accountSasToken: e.target.value })}
              placeholder="sv=2022-11-02&ss=b&srt=sco&sp=rwdlac..."
              className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs font-mono text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
            />
          </div>

          {/* Poll Interval + Max Blob Age */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-specter-muted">
                Poll Interval (seconds)
              </label>
              <input
                type="number"
                value={state.pollIntervalSecs}
                onChange={(e) => onChange({ pollIntervalSecs: e.target.value })}
                placeholder="30"
                min={1}
                className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-specter-muted">
                Max Blob Age (seconds)
              </label>
              <input
                type="number"
                value={state.maxBlobAgeSecs}
                onChange={(e) => onChange({ maxBlobAgeSecs: e.target.value })}
                placeholder="3600"
                min={1}
                className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
              />
            </div>
          </div>

          {/* Encryption Key */}
          <div>
            <label className="text-xs font-medium text-specter-muted">Encryption Key (Hex)</label>
            <div className="mt-1.5 flex gap-2">
              <input
                type="text"
                value={state.encryptionKeyHex}
                onChange={(e) => onChange({ encryptionKeyHex: e.target.value })}
                placeholder="64-char hex key"
                className="flex-1 rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs font-mono text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
              />
              <button
                onClick={() => onChange({ encryptionKeyHex: generateEncryptionKeyHex() })}
                className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text"
                title="Auto-generate key"
              >
                <Key className="h-3 w-3" />
                Generate
              </button>
            </div>
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
            disabled={!state.name || !state.accountName || !state.accountSasToken || state.creating}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
          >
            {state.creating ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <Plus className="h-3 w-3" />
            )}
            Create Listener
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Azure Dead Drop Page ──────────────────────────────────────────────

export function AzureDeadDrop() {
  const [listeners, setListeners] = useState<AzureListenerInfo[]>([])
  const [containers, setContainers] = useState<AzureContainerInfo[]>([])
  const [selectedListenerId, setSelectedListenerId] = useState<string | null>(null)
  const [loadingContainers, setLoadingContainers] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [createDialog, setCreateDialog] = useState<CreateDialogState | null>(null)

  const fetchContainers = useCallback(async (listenerId: string) => {
    try {
      setLoadingContainers(true)
      setError(null)

      const req = create(ListAzureContainersRequestSchema, { listenerId })
      const res = await specterClient.listAzureContainers(req)
      setContainers(res.containers)
      setLastRefresh(new Date())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch containers')
    } finally {
      setLoadingContainers(false)
    }
  }, [])

  const handleSelectListener = useCallback(
    (listener: AzureListenerInfo) => {
      setSelectedListenerId(listener.id)
      setContainers([])
      fetchContainers(listener.id)
    },
    [fetchContainers]
  )

  const handleRefreshContainers = useCallback(() => {
    if (selectedListenerId) {
      fetchContainers(selectedListenerId)
    }
  }, [selectedListenerId, fetchContainers])

  const openCreateDialog = useCallback(() => {
    setCreateDialog({
      name: '',
      accountName: '',
      accountSasToken: '',
      pollIntervalSecs: '30',
      maxBlobAgeSecs: '3600',
      encryptionKeyHex: '',
      creating: false,
      result: null,
    })
  }, [])

  const handleCreate = useCallback(async () => {
    if (!createDialog) return

    setCreateDialog((prev) => (prev ? { ...prev, creating: true, result: null } : null))

    try {
      const req = create(CreateAzureListenerRequestSchema, {
        name: createDialog.name,
        accountName: createDialog.accountName,
        accountSasToken: createDialog.accountSasToken,
        pollIntervalSecs: BigInt(parseInt(createDialog.pollIntervalSecs) || 30),
        maxBlobAgeSecs: BigInt(parseInt(createDialog.maxBlobAgeSecs) || 3600),
        encryptionKeyHex: createDialog.encryptionKeyHex,
      })
      const res = await specterClient.createAzureListener(req)

      if (res.listener) {
        setListeners((prev) => [...prev, res.listener!])
      }

      setCreateDialog((prev) =>
        prev
          ? {
              ...prev,
              creating: false,
              result: {
                success: true,
                message: `Listener "${createDialog.name}" created successfully`,
              },
            }
          : null
      )

      // Auto-close after success
      setTimeout(() => setCreateDialog(null), 1500)
    } catch (err) {
      setCreateDialog((prev) =>
        prev
          ? {
              ...prev,
              creating: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Failed to create listener',
              },
            }
          : null
      )
    }
  }, [createDialog])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Azure Dead Drop</h1>
          <p className="text-xs text-specter-muted">
            Manage Azure Blob Storage dead drop listeners and containers
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {listeners.length} listener{listeners.length !== 1 ? 's' : ''}
          </span>
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>
          <button
            onClick={openCreateDialog}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90"
          >
            <Plus className="h-3 w-3" />
            Create Azure Listener
          </button>
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-start gap-3 rounded-lg border border-specter-info/30 bg-specter-info/5 px-4 py-3">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-specter-info" />
        <p className="text-xs text-specter-info">
          Azure Blob Storage dead drop uses shared storage containers for asynchronous C2
          communication. Implants and teamserver exchange encrypted blobs without direct network
          connections.
        </p>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-3 text-sm text-specter-danger">
          {error}
        </div>
      )}

      {/* Listeners Section */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-specter-text">Azure Listeners</h2>
        {listeners.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-lg border border-specter-border bg-specter-surface py-12 text-specter-muted">
            <Cloud className="mb-2 h-8 w-8" />
            <p className="text-sm">No Azure listeners configured</p>
            <button
              onClick={openCreateDialog}
              className="mt-3 flex items-center gap-1.5 rounded border border-specter-accent/30 bg-specter-accent/10 px-3 py-1.5 text-xs text-specter-accent transition-colors hover:bg-specter-accent/20"
            >
              <Plus className="h-3 w-3" />
              Create your first listener
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-3 gap-4">
            {listeners.map((listener) => (
              <ListenerCard
                key={listener.id}
                listener={listener}
                selected={selectedListenerId === listener.id}
                onClick={() => handleSelectListener(listener)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Containers Section */}
      {selectedListenerId && (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-medium text-specter-text">
              Containers
              <span className="ml-2 text-xs font-normal text-specter-muted">
                Listener: {listeners.find((l) => l.id === selectedListenerId)?.name ?? selectedListenerId}
              </span>
            </h2>
            <button
              onClick={handleRefreshContainers}
              disabled={loadingContainers}
              className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
            >
              <RefreshCw className={`h-3 w-3 ${loadingContainers ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          {loadingContainers ? (
            <div className="flex items-center justify-center py-12">
              <Loader className="h-5 w-5 animate-spin text-specter-muted" />
            </div>
          ) : (
            <ContainerTable containers={containers} />
          )}
        </div>
      )}

      {/* Create Dialog */}
      {createDialog && (
        <CreateListenerDialog
          state={createDialog}
          onClose={() => setCreateDialog(null)}
          onChange={(patch) =>
            setCreateDialog((prev) => (prev ? { ...prev, ...patch, result: null } : null))
          }
          onCreate={handleCreate}
        />
      )}
    </div>
  )
}
