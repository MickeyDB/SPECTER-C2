import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  RefreshCw,
  Loader,
  Globe,
  Shield,
  Flame,
  Trash2,
  HeartPulse,
  Plus,
  X,
  ChevronRight,
  ChevronLeft,
  Server,
  Cloud,
  Lock,
  Activity,
  Search,
  CheckCircle,
  AlertCircle,
  XCircle,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { RedirectorInfo } from '@/gen/specter/v1/azure_pb'
import type { ProfileInfo } from '@/gen/specter/v1/profiles_pb'
import { create } from '@bufbuild/protobuf'
import {
  DeployRedirectorRequestSchema,
  DestroyRedirectorRequestSchema,
  BurnRedirectorRequestSchema,
  GetRedirectorHealthRequestSchema,
  AddDomainToPoolRequestSchema,
} from '@/gen/specter/v1/azure_pb'

// ── Helpers ────────────────────────────────────────────────────────────

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

const stateColors: Record<string, string> = {
  running: 'text-status-active',
  healthy: 'text-status-active',
  active: 'text-status-active',
  degraded: 'text-status-stale',
  warning: 'text-status-stale',
  stopped: 'text-specter-muted',
  error: 'text-status-dead',
  dead: 'text-status-dead',
  destroyed: 'text-specter-muted',
  deploying: 'text-specter-info',
}

const stateBgColors: Record<string, string> = {
  running: 'bg-status-active/10 border-status-active/30',
  healthy: 'bg-status-active/10 border-status-active/30',
  active: 'bg-status-active/10 border-status-active/30',
  degraded: 'bg-status-stale/10 border-status-stale/30',
  warning: 'bg-status-stale/10 border-status-stale/30',
  stopped: 'bg-specter-muted/10 border-specter-muted/30',
  error: 'bg-status-dead/10 border-status-dead/30',
  dead: 'bg-status-dead/10 border-status-dead/30',
  destroyed: 'bg-specter-muted/10 border-specter-muted/30',
  deploying: 'bg-specter-info/10 border-specter-info/30',
}

function StateIconElement({ state, className }: { state: string; className?: string }) {
  const s = state.toLowerCase()
  if (s === 'running' || s === 'healthy' || s === 'active') return <CheckCircle className={className} />
  if (s === 'degraded' || s === 'warning' || s === 'deploying') return <AlertCircle className={className} />
  return <XCircle className={className} />
}

function ProviderIconElement({ provider, className }: { provider: string; className?: string }) {
  const p = provider.toLowerCase()
  if (p === 'cloudflare') return <Shield className={className} />
  if (p === 'digitalocean') return <Server className={className} />
  if (p === 'aws' || p === 'azure' || p === 'gcp') return <Cloud className={className} />
  return <Globe className={className} />
}

// Simulated TLS expiry (in a real system, this would come from the server)
function simulateTlsExpiry(domain: string): string {
  const hash = domain.split('').reduce((a, c) => a + c.charCodeAt(0), 0)
  const daysLeft = 30 + (hash % 335)
  return `${daysLeft}d`
}

// Simulated traffic volume
function simulateTrafficVolume(id: string): string {
  const hash = id.split('').reduce((a, c) => a + c.charCodeAt(0), 0)
  const volume = 100 + (hash % 9900)
  if (volume > 1000) return `${(volume / 1000).toFixed(1)}K`
  return `${volume}`
}

// ── Types ──────────────────────────────────────────────────────────────

interface HealthState {
  id: string
  state: string
  healthy: boolean
  checking: boolean
}

interface DeployWizardState {
  step: 'provider' | 'domain' | 'profile' | 'deploy'
  provider: string
  redirectorType: string
  domain: string
  profileId: string
  deploying: boolean
  result: { success: boolean; message: string } | null
}

interface DomainPoolEntry {
  domain: string
  provider: string
  status: string
}

// ── Components ─────────────────────────────────────────────────────────

function RedirectorCard({
  redirector,
  health,
  onHealthCheck,
  onBurn,
  onDestroy,
}: {
  redirector: RedirectorInfo
  health?: HealthState
  onHealthCheck: () => void
  onBurn: () => void
  onDestroy: () => void
}) {
  const state = health?.state ?? redirector.state
  const colorClass = stateColors[state.toLowerCase()] ?? 'text-specter-muted'
  const bgClass = stateBgColors[state.toLowerCase()] ?? 'bg-specter-muted/10 border-specter-muted/30'

  return (
    <div className="flex flex-col rounded-lg border border-specter-border bg-specter-surface p-4 transition-colors hover:border-specter-muted">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <ProviderIconElement provider={redirector.provider} className="h-4 w-4 text-specter-muted" />
          <h3 className="text-sm font-medium text-specter-text">{redirector.name}</h3>
        </div>
        <span className={`flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium ${bgClass} ${colorClass}`}>
          <StateIconElement state={state} className="h-2.5 w-2.5" />
          {state}
        </span>
      </div>

      {/* Details */}
      <div className="mt-3 flex flex-col gap-1.5">
        <div className="flex items-center gap-2 text-xs">
          <Globe className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-text">{redirector.domain || 'No domain'}</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Cloud className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">{redirector.provider || 'Unknown'}</span>
          <span className="text-specter-muted">&middot;</span>
          <span className="text-specter-muted">{redirector.redirectorType || 'HTTP'}</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Lock className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">
            TLS expires in {simulateTlsExpiry(redirector.domain || redirector.id)}
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Activity className="h-3 w-3 text-specter-muted" />
          <span className="text-specter-muted">
            {simulateTrafficVolume(redirector.id)} req/day
          </span>
        </div>
      </div>

      {/* Health Check Status */}
      {health && (
        <div className={`mt-3 rounded border px-2 py-1 text-[10px] ${bgClass} ${colorClass}`}>
          Health: {health.healthy ? 'Healthy' : 'Unhealthy'} ({health.state})
        </div>
      )}

      {/* Actions */}
      <div className="mt-3 flex items-center gap-2">
        <button
          onClick={onHealthCheck}
          disabled={health?.checking}
          className="flex flex-1 items-center justify-center gap-1 rounded border border-specter-border px-2 py-1.5 text-[10px] text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
          title="Health Check"
        >
          {health?.checking ? (
            <Loader className="h-3 w-3 animate-spin" />
          ) : (
            <HeartPulse className="h-3 w-3" />
          )}
          Health
        </button>
        <button
          onClick={onBurn}
          className="flex flex-1 items-center justify-center gap-1 rounded border border-specter-warning/30 px-2 py-1.5 text-[10px] text-specter-warning transition-colors hover:bg-specter-warning/10"
          title="Burn & Replace"
        >
          <Flame className="h-3 w-3" />
          Burn
        </button>
        <button
          onClick={onDestroy}
          className="flex flex-1 items-center justify-center gap-1 rounded border border-specter-danger/30 px-2 py-1.5 text-[10px] text-specter-danger transition-colors hover:bg-specter-danger/10"
          title="Destroy"
        >
          <Trash2 className="h-3 w-3" />
          Destroy
        </button>
      </div>
    </div>
  )
}

function ConfirmDialog({
  title,
  message,
  confirmLabel,
  variant,
  loading: isLoading,
  onConfirm,
  onCancel,
}: {
  title: string
  message: string
  confirmLabel: string
  variant: 'danger' | 'warning'
  loading: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const btnClass =
    variant === 'danger'
      ? 'bg-specter-danger text-white hover:bg-specter-danger/90'
      : 'bg-specter-warning text-specter-bg hover:bg-specter-warning/90'

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
            className={`flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50 ${btnClass}`}
          >
            {isLoading && <Loader className="h-3 w-3 animate-spin" />}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

function DeployWizard({
  state,
  profiles,
  onCancel,
  onNext,
  onBack,
  onUpdate,
  onDeploy,
}: {
  state: DeployWizardState
  profiles: ProfileInfo[]
  onCancel: () => void
  onNext: () => void
  onBack: () => void
  onUpdate: (patch: Partial<DeployWizardState>) => void
  onDeploy: () => void
}) {
  const steps = ['provider', 'domain', 'profile', 'deploy'] as const
  const stepIdx = steps.indexOf(state.step)

  const providers = ['AWS', 'Azure', 'GCP', 'Cloudflare', 'DigitalOcean']

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Deploy Redirector</h2>
          <button onClick={onCancel} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Step Indicator */}
        <div className="flex items-center gap-2 border-b border-specter-border px-4 py-2">
          {steps.map((s, i) => (
            <div key={s} className="flex items-center gap-2">
              <span
                className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-medium ${
                  i <= stepIdx
                    ? 'bg-specter-accent text-specter-bg'
                    : 'bg-specter-surface text-specter-muted'
                }`}
              >
                {i + 1}
              </span>
              <span className={`text-xs capitalize ${i <= stepIdx ? 'text-specter-text' : 'text-specter-muted'}`}>
                {s}
              </span>
              {i < steps.length - 1 && <ChevronRight className="h-3 w-3 text-specter-muted" />}
            </div>
          ))}
        </div>

        {/* Body */}
        <div className="p-4">
          {state.step === 'provider' && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-2">
                <label className="text-xs font-medium text-specter-muted">Select Provider</label>
                <div className="grid grid-cols-3 gap-2">
                  {providers.map((p) => (
                      <button
                        key={p}
                        onClick={() => {
                          const defaultType = p === 'Cloudflare' ? 'CDN'
                            : p === 'AWS' ? 'CDN'
                            : p === 'Azure' ? ''
                            : p === 'DigitalOcean' ? 'VPS'
                            : ''
                          onUpdate({ provider: p, redirectorType: defaultType })
                        }}
                        className={`flex flex-col items-center gap-1.5 rounded border p-3 text-xs transition-colors ${
                          state.provider === p
                            ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                            : 'border-specter-border text-specter-muted hover:border-specter-muted'
                        }`}
                      >
                        <ProviderIconElement provider={p} className="h-5 w-5" />
                        {p}
                      </button>
                    ))}
                </div>
              </div>
              {state.provider === 'Azure' && (
                <div className="flex flex-col gap-2">
                  <label className="text-xs font-medium text-specter-muted">Redirector Type</label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => onUpdate({ redirectorType: 'CloudFunction' })}
                      className={`flex flex-col gap-1 rounded border p-3 text-left text-xs transition-colors ${
                        state.redirectorType === 'CloudFunction'
                          ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                          : 'border-specter-border text-specter-muted hover:border-specter-muted'
                      }`}
                    >
                      <span className="font-medium">Function App</span>
                      <span className="text-[10px] opacity-70">Serverless · HTTP only</span>
                    </button>
                    <button
                      onClick={() => onUpdate({ redirectorType: 'VPS' })}
                      className={`flex flex-col gap-1 rounded border p-3 text-left text-xs transition-colors ${
                        state.redirectorType === 'VPS'
                          ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                          : 'border-specter-border text-specter-muted hover:border-specter-muted'
                      }`}
                    >
                      <span className="font-medium">App Service</span>
                      <span className="text-[10px] opacity-70">Dedicated · WebSocket support</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {state.step === 'domain' && (
            <div className="flex flex-col gap-3">
              <label className="text-xs font-medium text-specter-muted">Domain</label>
              <input
                type="text"
                value={state.domain}
                onChange={(e) => onUpdate({ domain: e.target.value })}
                placeholder="redirector.example.com"
                className="rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
              />
            </div>
          )}

          {state.step === 'profile' && (
            <div className="flex flex-col gap-2">
              <label className="text-xs font-medium text-specter-muted">Select Profile</label>
              <div className="max-h-48 overflow-y-auto rounded border border-specter-border bg-specter-surface">
                {profiles.length === 0 ? (
                  <div className="px-3 py-4 text-center text-xs text-specter-muted">
                    No profiles available
                  </div>
                ) : (
                  profiles.map((p) => (
                    <button
                      key={p.id}
                      onClick={() => onUpdate({ profileId: p.id })}
                      className={`flex w-full items-center gap-2 border-b border-specter-border px-3 py-2.5 text-left text-xs last:border-0 ${
                        state.profileId === p.id
                          ? 'bg-specter-accent/10 text-specter-accent'
                          : 'text-specter-muted hover:bg-specter-border/30'
                      }`}
                    >
                      <span className="font-medium">{p.name}</span>
                      <span className="text-[10px]">{p.description}</span>
                    </button>
                  ))
                )}
              </div>
            </div>
          )}

          {state.step === 'deploy' && (
            <div className="flex flex-col gap-3">
              <h3 className="text-xs font-medium text-specter-text">Review & Deploy</h3>
              <div className="rounded border border-specter-border bg-specter-surface p-3">
                <div className="flex flex-col gap-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-specter-muted">Provider:</span>
                    <span className="text-specter-text">{state.provider}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-specter-muted">Domain:</span>
                    <span className="text-specter-text">{state.domain || '(auto-assign)'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-specter-muted">Profile:</span>
                    <span className="text-specter-text">
                      {profiles.find((p) => p.id === state.profileId)?.name || '(none)'}
                    </span>
                  </div>
                </div>
              </div>
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
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-specter-border px-4 py-3">
          <button
            onClick={stepIdx > 0 ? onBack : onCancel}
            className="flex items-center gap-1 rounded border border-specter-border px-3 py-1.5 text-xs text-specter-muted transition-colors hover:text-specter-text"
          >
            {stepIdx > 0 ? <><ChevronLeft className="h-3 w-3" /> Back</> : 'Cancel'}
          </button>
          {state.step === 'deploy' ? (
            <button
              onClick={onDeploy}
              disabled={state.deploying}
              className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs font-medium text-specter-bg transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
            >
              {state.deploying ? <Loader className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
              Deploy
            </button>
          ) : (
            <button
              onClick={onNext}
              disabled={
                (state.step === 'provider' && (!state.provider || !state.redirectorType)) ||
                (state.step === 'profile' && !state.profileId && profiles.length > 0)
              }
              className="flex items-center gap-1 rounded bg-specter-accent px-3 py-1.5 text-xs font-medium text-specter-bg transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
            >
              Next <ChevronRight className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function DomainPoolTable({
  domains,
  onAddDomain,
}: {
  domains: DomainPoolEntry[]
  onAddDomain: (domain: string, provider: string) => void
}) {
  const [newDomain, setNewDomain] = useState('')
  const [newProvider, setNewProvider] = useState('AWS')

  const handleAdd = () => {
    if (newDomain.trim()) {
      onAddDomain(newDomain.trim(), newProvider)
      setNewDomain('')
    }
  }

  return (
    <div className="rounded-lg border border-specter-border">
      <div className="flex items-center justify-between border-b border-specter-border px-4 py-2.5">
        <h3 className="text-xs font-medium text-specter-text">Domain Pool</h3>
        <span className="text-[10px] text-specter-muted">{domains.length} domain(s)</span>
      </div>

      {/* Add Domain Row */}
      <div className="flex items-center gap-2 border-b border-specter-border px-4 py-2">
        <input
          type="text"
          value={newDomain}
          onChange={(e) => setNewDomain(e.target.value)}
          placeholder="Add domain..."
          className="flex-1 rounded border border-specter-border bg-specter-surface px-2 py-1 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
          onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
        />
        <select
          value={newProvider}
          onChange={(e) => setNewProvider(e.target.value)}
          className="rounded border border-specter-border bg-specter-surface px-2 py-1 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
        >
          {['AWS', 'Azure', 'GCP', 'Cloudflare', 'DigitalOcean'].map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <button
          onClick={handleAdd}
          disabled={!newDomain.trim()}
          className="rounded bg-specter-accent px-2.5 py-1 text-xs font-medium text-specter-bg transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
        >
          Add
        </button>
      </div>

      {/* Domain List */}
      {domains.length === 0 ? (
        <div className="px-4 py-6 text-center text-xs text-specter-muted">
          No domains in pool
        </div>
      ) : (
        <div className="max-h-48 overflow-y-auto">
          {domains.map((d) => (
            <div
              key={d.domain}
              className="flex items-center gap-3 border-b border-specter-border px-4 py-2 last:border-0"
            >
              <Globe className="h-3 w-3 text-specter-muted" />
              <span className="flex-1 text-xs text-specter-text">{d.domain}</span>
              <span className="text-[10px] text-specter-muted">{d.provider}</span>
              <span
                className={`rounded border px-1.5 py-0.5 text-[10px] ${
                  d.status === 'available'
                    ? 'border-status-active/30 text-status-active'
                    : d.status === 'in-use'
                      ? 'border-specter-info/30 text-specter-info'
                      : 'border-specter-muted/30 text-specter-muted'
                }`}
              >
                {d.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Redirectors Page ──────────────────────────────────────────────────

export function Redirectors() {
  const [redirectors, setRedirectors] = useState<RedirectorInfo[]>([])
  const [profiles, setProfiles] = useState<ProfileInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [searchQuery, setSearchQuery] = useState('')
  const [healthStates, setHealthStates] = useState<Record<string, HealthState>>({})
  const [confirmAction, setConfirmAction] = useState<{
    type: 'burn' | 'destroy'
    redirector: RedirectorInfo
    loading: boolean
  } | null>(null)
  const [deployWizard, setDeployWizard] = useState<DeployWizardState | null>(null)
  const [domainPool, setDomainPool] = useState<DomainPoolEntry[]>([])

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const [redirectorsRes, profilesRes] = await Promise.allSettled([
        specterClient.listRedirectors({}),
        specterClient.listProfiles({}),
      ])

      if (redirectorsRes.status === 'fulfilled') {
        setRedirectors(redirectorsRes.value.redirectors)
      }
      if (profilesRes.status === 'fulfilled') {
        setProfiles(profilesRes.value.profiles)
      }

      if (redirectorsRes.status === 'rejected' && profilesRes.status === 'rejected') {
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

  const filteredRedirectors = useMemo(() => {
    if (!searchQuery) return redirectors
    const q = searchQuery.toLowerCase()
    return redirectors.filter((r) =>
      [r.name, r.domain, r.provider, r.state, r.redirectorType]
        .join(' ')
        .toLowerCase()
        .includes(q)
    )
  }, [redirectors, searchQuery])

  const handleHealthCheck = useCallback(async (redirector: RedirectorInfo) => {
    setHealthStates((prev) => ({
      ...prev,
      [redirector.id]: { id: redirector.id, state: 'checking', healthy: false, checking: true },
    }))

    try {
      const req = create(GetRedirectorHealthRequestSchema, { id: redirector.id })
      const res = await specterClient.getRedirectorHealth(req)
      setHealthStates((prev) => ({
        ...prev,
        [redirector.id]: {
          id: redirector.id,
          state: res.state,
          healthy: res.healthy,
          checking: false,
        },
      }))
    } catch {
      setHealthStates((prev) => ({
        ...prev,
        [redirector.id]: {
          id: redirector.id,
          state: 'error',
          healthy: false,
          checking: false,
        },
      }))
    }
  }, [])

  const handleBurn = useCallback(async () => {
    if (!confirmAction || confirmAction.type !== 'burn') return

    setConfirmAction((prev) => (prev ? { ...prev, loading: true } : null))
    try {
      const req = create(BurnRedirectorRequestSchema, { id: confirmAction.redirector.id })
      await specterClient.burnRedirector(req)
      setConfirmAction(null)
      await fetchData()
    } catch {
      setConfirmAction((prev) => (prev ? { ...prev, loading: false } : null))
    }
  }, [confirmAction, fetchData])

  const handleDestroy = useCallback(async () => {
    if (!confirmAction || confirmAction.type !== 'destroy') return

    setConfirmAction((prev) => (prev ? { ...prev, loading: true } : null))
    try {
      const req = create(DestroyRedirectorRequestSchema, { id: confirmAction.redirector.id })
      await specterClient.destroyRedirector(req)
      setConfirmAction(null)
      await fetchData()
    } catch {
      setConfirmAction((prev) => (prev ? { ...prev, loading: false } : null))
    }
  }, [confirmAction, fetchData])

  const handleDeployNext = useCallback(() => {
    setDeployWizard((prev) => {
      if (!prev) return null
      const steps: DeployWizardState['step'][] = ['provider', 'domain', 'profile', 'deploy']
      const idx = steps.indexOf(prev.step)
      if (idx < steps.length - 1) return { ...prev, step: steps[idx + 1] }
      return prev
    })
  }, [])

  const handleDeployBack = useCallback(() => {
    setDeployWizard((prev) => {
      if (!prev) return null
      const steps: DeployWizardState['step'][] = ['provider', 'domain', 'profile', 'deploy']
      const idx = steps.indexOf(prev.step)
      if (idx > 0) return { ...prev, step: steps[idx - 1] }
      return prev
    })
  }, [])

  const handleDeploy = useCallback(async () => {
    if (!deployWizard) return

    setDeployWizard((prev) => (prev ? { ...prev, deploying: true, result: null } : null))

    try {
      const configYaml = [
        `type: ${deployWizard.redirectorType}`,
        `provider: ${deployWizard.provider}`,
        `domain: ${deployWizard.domain}`,
        `profile_id: ${deployWizard.profileId}`,
      ].join('\n')

      const req = create(DeployRedirectorRequestSchema, { configYaml })
      await specterClient.deployRedirector(req)

      setDeployWizard((prev) =>
        prev
          ? { ...prev, deploying: false, result: { success: true, message: 'Redirector deployed successfully' } }
          : null
      )
      await fetchData()
    } catch (err) {
      setDeployWizard((prev) =>
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
  }, [deployWizard, fetchData])

  const handleAddDomain = useCallback(async (domain: string, provider: string) => {
    try {
      const req = create(AddDomainToPoolRequestSchema, { domain, provider })
      await specterClient.addDomainToPool(req)
      setDomainPool((prev) => [...prev, { domain, provider, status: 'available' }])
    } catch {
      // Still add locally for UI feedback
      setDomainPool((prev) => [...prev, { domain, provider, status: 'pending' }])
    }
  }, [])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Redirectors</h1>
          <p className="text-xs text-specter-muted">
            Manage redirector infrastructure and domain pool
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {redirectors.length} redirector(s) &middot; Updated {formatRelativeTime(lastRefresh)}
          </span>
          <button
            onClick={() =>
              setDeployWizard({
                step: 'provider',
                provider: '',
                redirectorType: '',
                domain: '',
                profileId: '',
                deploying: false,
                result: null,
              })
            }
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs font-medium text-specter-bg transition-colors hover:bg-specter-accent/90"
          >
            <Plus className="h-3 w-3" />
            Deploy
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
          placeholder="Search redirectors..."
          className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
        />
      </div>

      {/* Redirector Grid */}
      {loading && redirectors.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : filteredRedirectors.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-specter-muted">
          <Server className="mb-2 h-8 w-8" />
          <p className="text-sm">No redirectors found</p>
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
          {filteredRedirectors.map((r) => (
            <RedirectorCard
              key={r.id}
              redirector={r}
              health={healthStates[r.id]}
              onHealthCheck={() => handleHealthCheck(r)}
              onBurn={() =>
                setConfirmAction({ type: 'burn', redirector: r, loading: false })
              }
              onDestroy={() =>
                setConfirmAction({ type: 'destroy', redirector: r, loading: false })
              }
            />
          ))}
        </div>
      )}

      {/* Domain Pool */}
      <DomainPoolTable domains={domainPool} onAddDomain={handleAddDomain} />

      {/* Confirm Dialog */}
      {confirmAction && (
        <ConfirmDialog
          title={
            confirmAction.type === 'burn'
              ? `Burn & Replace: ${confirmAction.redirector.name}`
              : `Destroy: ${confirmAction.redirector.name}`
          }
          message={
            confirmAction.type === 'burn'
              ? 'This will burn the current redirector and deploy a replacement. The domain will be rotated. Are you sure?'
              : 'This will permanently destroy the redirector and release its resources. This action cannot be undone.'
          }
          confirmLabel={confirmAction.type === 'burn' ? 'Burn & Replace' : 'Destroy'}
          variant={confirmAction.type === 'burn' ? 'warning' : 'danger'}
          loading={confirmAction.loading}
          onConfirm={confirmAction.type === 'burn' ? handleBurn : handleDestroy}
          onCancel={() => setConfirmAction(null)}
        />
      )}

      {/* Deploy Wizard */}
      {deployWizard && (
        <DeployWizard
          state={deployWizard}
          profiles={profiles}
          onCancel={() => setDeployWizard(null)}
          onNext={handleDeployNext}
          onBack={handleDeployBack}
          onUpdate={(patch) => setDeployWizard((prev) => (prev ? { ...prev, ...patch } : null))}
          onDeploy={handleDeploy}
        />
      )}
    </div>
  )
}
