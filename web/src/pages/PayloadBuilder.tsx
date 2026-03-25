import { useState, useEffect, useCallback } from 'react'
import {
  Loader,
  Download,
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle,
  Shield,
  RefreshCw,
  X,
  Copy,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import { create } from '@bufbuild/protobuf'
import {
  GeneratePayloadRequestSchema,
  ChannelEndpointSchema,
  SleepSettingsSchema,
  ObfuscationConfigSchema,
} from '@/gen/specter/v1/builder_pb'
import type {
  FormatDescription,
  GeneratePayloadResponse,
  YaraWarning,
} from '@/gen/specter/v1/builder_pb'
import type { ProfileInfo } from '@/gen/specter/v1/profiles_pb'
import type { RedirectorInfo } from '@/gen/specter/v1/azure_pb'

// ── Helpers ──────────────────────────────────────────────────────────────

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function downloadBlob(data: Uint8Array, filename: string) {
  const blob = new Blob([new Uint8Array(data)], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

const FORMAT_EXTENSIONS: Record<string, string> = {
  raw: '.bin',
  dll: '.dll',
  service_exe: '.exe',
  dotnet: '.exe',
  ps1_stager: '.ps1',
  hta_stager: '.hta',
}

const CHANNEL_KINDS = ['https', 'http', 'dns', 'smb', 'wss', 'ws']

// ── Types ────────────────────────────────────────────────────────────────

interface ChannelEntry {
  id: number
  kind: string
  address: string
}

// ── Components ───────────────────────────────────────────────────────────

function YaraWarnings({ warnings }: { warnings: YaraWarning[] }) {
  if (warnings.length === 0) return null

  return (
    <div className="rounded border border-specter-warning/30 bg-specter-warning/10 p-3">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-specter-warning">
        <AlertTriangle className="h-3.5 w-3.5" />
        YARA Detection Warnings ({warnings.length})
      </div>
      <div className="space-y-1">
        {warnings.map((w, i) => (
          <div key={i} className="flex items-center gap-2 text-xs text-specter-warning/80">
            <span className="font-mono">{w.ruleName}</span>
            {w.namespace && (
              <span className="text-specter-muted">({w.namespace})</span>
            )}
            {w.tags.length > 0 && (
              <div className="flex gap-1">
                {w.tags.map((t) => (
                  <span
                    key={t}
                    className="rounded bg-specter-warning/20 px-1 py-0.5 text-[10px]"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function BuildResult({
  result,
  onClose,
}: {
  result: GeneratePayloadResponse
  onClose: () => void
}) {
  const ext = FORMAT_EXTENSIONS[result.format] ?? '.bin'
  const filename = `specter-${result.buildId.slice(0, 8)}${ext}`
  const [copied, setCopied] = useState(false)

  const handleCopyPubkey = useCallback(() => {
    navigator.clipboard.writeText(hexEncode(result.implantPubkey))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [result.implantPubkey])

  if (!result.success) {
    return (
      <div className="rounded-lg border border-specter-danger/30 bg-specter-danger/10 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-specter-danger">
            <AlertTriangle className="h-4 w-4" />
            Build Failed
          </div>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="mt-2 text-xs text-specter-danger/80">{result.error}</p>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-status-active/30 bg-status-active/10 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-status-active">
          <CheckCircle className="h-4 w-4" />
          Payload Generated
        </div>
        <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="mt-3 grid grid-cols-3 gap-4 text-xs">
        <div>
          <span className="text-specter-muted">Build ID</span>
          <div className="mt-0.5 font-mono text-specter-text">{result.buildId.slice(0, 12)}...</div>
        </div>
        <div>
          <span className="text-specter-muted">Format</span>
          <div className="mt-0.5 text-specter-text">{result.format}</div>
        </div>
        <div>
          <span className="text-specter-muted">Size</span>
          <div className="mt-0.5 text-specter-text">{formatBytes(result.payload.length)}</div>
        </div>
      </div>

      {result.implantPubkey.length > 0 && (
        <div className="mt-3">
          <span className="text-xs text-specter-muted">Implant Public Key (X25519)</span>
          <div className="mt-0.5 flex items-center gap-2">
            <code className="flex-1 truncate rounded bg-specter-bg px-2 py-1 font-mono text-[11px] text-specter-accent">
              {hexEncode(result.implantPubkey)}
            </code>
            <button
              onClick={handleCopyPubkey}
              className="shrink-0 rounded p-1 text-specter-muted hover:text-specter-text"
              title="Copy public key"
            >
              {copied ? <CheckCircle className="h-3.5 w-3.5 text-status-active" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      )}

      <YaraWarnings warnings={result.yaraWarnings} />

      <button
        onClick={() => downloadBlob(result.payload, filename)}
        className="mt-4 flex w-full items-center justify-center gap-2 rounded bg-specter-accent px-4 py-2 text-sm font-medium text-specter-bg transition-colors hover:bg-specter-accent/90"
      >
        <Download className="h-4 w-4" />
        Download {filename} ({formatBytes(result.payload.length)})
      </button>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────

export function PayloadBuilder() {
  // Data
  const [formats, setFormats] = useState<FormatDescription[]>([])
  const [profiles, setProfiles] = useState<ProfileInfo[]>([])
  const [redirectors, setRedirectors] = useState<RedirectorInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Form state
  const [selectedFormat, setSelectedFormat] = useState('raw')
  const [selectedProfile, setSelectedProfile] = useState('')
  const [selectedListener, setSelectedListener] = useState('')
  const [listeners, setListeners] = useState<{ id: string; name: string; port: number; protocol: string }[]>([])
  const [channels, setChannels] = useState<ChannelEntry[]>([
    { id: 1, kind: 'https', address: '' },
  ])
  const [sleepInterval, setSleepInterval] = useState(60)
  const [sleepJitter, setSleepJitter] = useState(10)
  const [killDate, setKillDate] = useState('')
  const [proxyTarget, setProxyTarget] = useState('')
  const [serviceName, setServiceName] = useState('')
  const [stagerUrl, setStagerUrl] = useState('')

  // Obfuscation
  const [stringEncryption, setStringEncryption] = useState(false)
  const [apiHashRandomization, setApiHashRandomization] = useState(false)
  const [junkCodeInsertion, setJunkCodeInsertion] = useState(false)
  const [junkDensity, setJunkDensity] = useState(8)
  const [controlFlowFlattening, setControlFlowFlattening] = useState(false)
  const [xorEncryption, setXorEncryption] = useState(false)

  // Evasion
  const [moduleOverloading, setModuleOverloading] = useState(true)
  const [pdataRegistration, setPdataRegistration] = useState(false)
  const [ntcontinueEntry, setNtcontinueEntry] = useState(false)

  // Development / Debug
  const [debugMode, setDebugMode] = useState(false)
  const [skipAntiAnalysis, setSkipAntiAnalysis] = useState(false)

  // Build state
  const [building, setBuilding] = useState(false)
  const [buildResult, setBuildResult] = useState<GeneratePayloadResponse | null>(null)

  let nextChannelId = channels.length > 0 ? Math.max(...channels.map((c) => c.id)) + 1 : 1

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const [fmtRes, profRes, redirRes, listRes] = await Promise.allSettled([
        specterClient.listFormats({}),
        specterClient.listProfiles({}),
        specterClient.listRedirectors({}),
        specterClient.listListeners({}),
      ])
      if (fmtRes.status === 'fulfilled') setFormats(fmtRes.value.formats)
      if (profRes.status === 'fulfilled') {
        setProfiles(profRes.value.profiles)
        if (profRes.value.profiles.length > 0 && !selectedProfile) {
          setSelectedProfile(profRes.value.profiles[0].name)
        }
      }
      if (redirRes.status === 'fulfilled') {
        setRedirectors(redirRes.value.redirectors.filter((r) => r.state === 'Active'))
      }
      if (listRes.status === 'fulfilled') {
        const items = listRes.value.listeners.map((l: any) => ({
          id: l.id, name: l.name, port: l.port, protocol: l.protocol,
        }))
        setListeners(items)
        if (items.length > 0 && !selectedListener) {
          setSelectedListener(items[0].id)
        }
      }
      if (fmtRes.status === 'rejected' && profRes.status === 'rejected') {
        setError('Unable to connect to teamserver')
      }
    } catch {
      setError('Unable to connect to teamserver')
    } finally {
      setLoading(false)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const addChannel = useCallback(() => {
    setChannels((prev) => [
      ...prev,
      { id: nextChannelId, kind: 'https', address: '' },
    ])
  }, [nextChannelId])

  const removeChannel = useCallback((id: number) => {
    setChannels((prev) => prev.filter((c) => c.id !== id))
  }, [])

  const updateChannel = useCallback(
    (id: number, field: 'kind' | 'address', value: string) => {
      setChannels((prev) =>
        prev.map((c) => (c.id === id ? { ...c, [field]: value } : c))
      )
    },
    []
  )

  const handleGenerate = useCallback(async () => {
    const validChannels = channels.filter((c) => c.address.trim())
    if (validChannels.length === 0) {
      setError('At least one channel endpoint is required')
      return
    }
    if (!selectedProfile) {
      setError('Select a C2 profile')
      return
    }
    if (!selectedListener) {
      setError('Select a listener to bind the payload to')
      return
    }

    setBuilding(true)
    setError(null)
    setBuildResult(null)

    try {
      const channelEndpoints = validChannels.map((c) =>
        create(ChannelEndpointSchema, { kind: c.kind, address: c.address })
      )

      const sleep = create(SleepSettingsSchema, {
        intervalSecs: BigInt(sleepInterval),
        jitterPercent: sleepJitter,
      })

      const obfuscation = create(ObfuscationConfigSchema, {
        stringEncryption,
        apiHashRandomization,
        junkCodeInsertion,
        junkDensity,
        controlFlowFlattening,
        xorEncryption,
      })

      let killDateUnix = BigInt(0)
      if (killDate) {
        const ts = new Date(killDate).getTime()
        if (!isNaN(ts)) killDateUnix = BigInt(Math.floor(ts / 1000))
      }

      const req = create(GeneratePayloadRequestSchema, {
        format: selectedFormat,
        profileName: selectedProfile,
        channels: channelEndpoints,
        sleep,
        killDate: killDateUnix,
        obfuscation,
        proxyTarget,
        serviceName,
        stagerUrl,
        listenerId: selectedListener,
        evasion: {
          moduleOverloading,
          pdataRegistration,
          ntcontinueEntry,
        },
        debugMode,
        skipAntiAnalysis,
      })

      const res = await specterClient.generatePayload(req)
      setBuildResult(res)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Payload generation failed')
    } finally {
      setBuilding(false)
    }
  }, [
    channels,
    selectedFormat,
    selectedProfile,
    sleepInterval,
    sleepJitter,
    killDate,
    stringEncryption,
    apiHashRandomization,
    junkCodeInsertion,
    junkDensity,
    controlFlowFlattening,
    xorEncryption,
    moduleOverloading,
    pdataRegistration,
    ntcontinueEntry,
    debugMode,
    skipAntiAnalysis,
    proxyTarget,
    serviceName,
    stagerUrl,
  ])

  const selectedFormatInfo = formats.find((f) => f.name === selectedFormat)
  const showProxyTarget = selectedFormat === 'dll'
  const showServiceName = selectedFormat === 'service_exe'
  const showStagerUrl = selectedFormat === 'ps1_stager' || selectedFormat === 'hta_stager'

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Payload Builder</h1>
          <p className="text-xs text-specter-muted">
            Generate implant payloads with embedded configuration
          </p>
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

      {/* Error */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-3 text-sm text-specter-danger">
          <span>{error}</span>
          <button onClick={() => setError(null)}>
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Build Result */}
      {buildResult && (
        <BuildResult result={buildResult} onClose={() => setBuildResult(null)} />
      )}

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-6">
          {/* Left Column: Core Config */}
          <div className="flex flex-col gap-5">
            {/* Output Format */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <h2 className="mb-3 text-xs font-medium text-specter-text">Output Format</h2>
              <div className="grid grid-cols-3 gap-2">
                {formats.map((fmt) => (
                  <button
                    key={fmt.name}
                    onClick={() => setSelectedFormat(fmt.name)}
                    className={`rounded border p-2.5 text-left transition-colors ${
                      selectedFormat === fmt.name
                        ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                        : 'border-specter-border text-specter-muted hover:border-specter-muted hover:text-specter-text'
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium">{fmt.name}</span>
                      {fmt.opsecWarning && (
                        <AlertTriangle className="h-3 w-3 text-specter-warning" />
                      )}
                    </div>
                    <div className="mt-0.5 text-[10px] opacity-70">{fmt.extension}</div>
                  </button>
                ))}
                {formats.length === 0 && (
                  <>
                    {['raw', 'dll', 'service_exe', 'dotnet', 'ps1_stager', 'hta_stager'].map((name) => (
                      <button
                        key={name}
                        onClick={() => setSelectedFormat(name)}
                        className={`rounded border p-2.5 text-left transition-colors ${
                          selectedFormat === name
                            ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                            : 'border-specter-border text-specter-muted hover:border-specter-muted hover:text-specter-text'
                        }`}
                      >
                        <div className="text-xs font-medium">{name}</div>
                        <div className="mt-0.5 text-[10px] opacity-70">{FORMAT_EXTENSIONS[name]}</div>
                      </button>
                    ))}
                  </>
                )}
              </div>
              {selectedFormatInfo?.description && (
                <p className="mt-2 text-[10px] text-specter-muted">{selectedFormatInfo.description}</p>
              )}
              {selectedFormatInfo?.opsecWarning && (
                <div className="mt-2 flex items-center gap-1 text-[10px] text-specter-warning">
                  <AlertTriangle className="h-3 w-3" />
                  OPSEC warning: this format may be more easily detected
                </div>
              )}
            </section>

            {/* C2 Profile */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <h2 className="mb-3 text-xs font-medium text-specter-text">C2 Profile</h2>
              {profiles.length === 0 ? (
                <p className="text-xs text-specter-muted">
                  No profiles available. Create one in the Profile Editor first.
                </p>
              ) : (
                <select
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                >
                  {profiles.map((p) => (
                    <option key={p.id} value={p.name}>
                      {p.name}{p.description ? ` — ${p.description}` : ''}
                    </option>
                  ))}
                </select>
              )}
            </section>

            {/* Listener */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <h2 className="mb-3 text-xs font-medium text-specter-text">Listener</h2>
              {listeners.length === 0 ? (
                <p className="text-xs text-specter-muted">
                  No listeners available. Create one in the Listeners page first.
                </p>
              ) : (
                <select
                  value={selectedListener}
                  onChange={(e) => setSelectedListener(e.target.value)}
                  className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                >
                  {listeners.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} — {l.protocol}://0.0.0.0:{l.port}
                    </option>
                  ))}
                </select>
              )}
              <p className="mt-1.5 text-[10px] text-specter-muted">
                Payload will be cryptographically bound to this listener's keypair.
              </p>
            </section>

            {/* Callback Channels */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-xs font-medium text-specter-text">Callback Channels</h2>
                <div className="flex gap-1">
                  {redirectors.length > 0 && (
                    <select
                      onChange={(e) => {
                        const redir = redirectors.find((r) => r.id === e.target.value)
                        if (redir) {
                          const domain = redir.domain.includes('://') ? redir.domain : `https://${redir.domain}`
                          // Use the default hostname from the redirector; user can edit the path
                          const address = domain.endsWith('/') ? domain : domain
                          setChannels((prev) => [
                            ...prev,
                            { id: Math.max(0, ...prev.map((c) => c.id)) + 1, kind: 'https', address },
                          ])
                        }
                        e.target.value = ''
                      }}
                      className="rounded border border-specter-border bg-specter-bg px-2 py-1 text-[10px] text-specter-muted focus:border-specter-accent focus:outline-none"
                      defaultValue=""
                    >
                      <option value="" disabled>
                        + From Redirector
                      </option>
                      {redirectors.map((r) => (
                        <option key={r.id} value={r.id}>
                          {r.name} ({r.domain})
                        </option>
                      ))}
                    </select>
                  )}
                  <button
                    onClick={addChannel}
                    className="flex items-center gap-1 rounded border border-specter-border px-2 py-1 text-[10px] text-specter-muted transition-colors hover:text-specter-text"
                  >
                    <Plus className="h-3 w-3" />
                    Custom
                  </button>
                </div>
              </div>
              <div className="space-y-2">
                {channels.map((ch, idx) => (
                  <div key={ch.id} className="flex items-center gap-2">
                    <span className="w-4 text-center text-[10px] text-specter-muted">
                      {idx === 0 ? 'P' : 'F'}
                    </span>
                    <select
                      value={ch.kind}
                      onChange={(e) => updateChannel(ch.id, 'kind', e.target.value)}
                      className="rounded border border-specter-border bg-specter-bg px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                    >
                      {CHANNEL_KINDS.map((k) => (
                        <option key={k} value={k}>
                          {k.toUpperCase()}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={ch.address}
                      onChange={(e) => updateChannel(ch.id, 'address', e.target.value)}
                      placeholder={`${ch.kind}://c2.example.com/api/checkin`}
                      className="flex-1 rounded border border-specter-border bg-specter-bg px-2 py-1.5 text-xs text-specter-text placeholder:text-specter-muted/50 focus:border-specter-accent focus:outline-none font-mono"
                    />
                    {channels.length > 1 && (
                      <button
                        onClick={() => removeChannel(ch.id)}
                        className="rounded p-1 text-specter-muted hover:text-specter-danger"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[10px] text-specter-muted">
                P = Primary channel, F = Fallback. Implant rotates to fallback on failure.
              </p>
            </section>

            {/* Format-specific options */}
            {showProxyTarget && (
              <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
                <h2 className="mb-3 text-xs font-medium text-specter-text">DLL Sideload Target</h2>
                <input
                  type="text"
                  value={proxyTarget}
                  onChange={(e) => setProxyTarget(e.target.value)}
                  placeholder="e.g. version.dll"
                  className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted/50 focus:border-specter-accent focus:outline-none font-mono"
                />
                <p className="mt-1.5 text-[10px] text-specter-muted">
                  Target DLL whose exports will be proxied for sideloading.
                </p>
              </section>
            )}

            {showServiceName && (
              <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
                <h2 className="mb-3 text-xs font-medium text-specter-text">Service Name</h2>
                <input
                  type="text"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  placeholder="e.g. SpecterSvc"
                  className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted/50 focus:border-specter-accent focus:outline-none font-mono"
                />
              </section>
            )}

            {showStagerUrl && (
              <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
                <h2 className="mb-3 text-xs font-medium text-specter-text">Stager Download URL</h2>
                <input
                  type="text"
                  value={stagerUrl}
                  onChange={(e) => setStagerUrl(e.target.value)}
                  placeholder="https://cdn.example.com/update.bin"
                  className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted/50 focus:border-specter-accent focus:outline-none font-mono"
                />
                <p className="mt-1.5 text-[10px] text-specter-muted">
                  URL where the stager will download the full payload from.
                </p>
              </section>
            )}
          </div>

          {/* Right Column: Sleep, Obfuscation, Generate */}
          <div className="flex flex-col gap-5">
            {/* Sleep Configuration */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <h2 className="mb-3 text-xs font-medium text-specter-text">Sleep Configuration</h2>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="mb-1 block text-[10px] text-specter-muted">
                    Interval (seconds)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={86400}
                    value={sleepInterval}
                    onChange={(e) => setSleepInterval(Number(e.target.value) || 60)}
                    className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[10px] text-specter-muted">
                    Jitter (0-100%)
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={sleepJitter}
                    onChange={(e) => setSleepJitter(Number(e.target.value) || 0)}
                    className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                  />
                </div>
              </div>
              <div className="mt-2 text-[10px] text-specter-muted">
                Check-in range: {Math.round(sleepInterval * (1 - sleepJitter / 100))}s
                {' — '}
                {Math.round(sleepInterval * (1 + sleepJitter / 100))}s
              </div>
            </section>

            {/* Kill Date */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <h2 className="mb-3 text-xs font-medium text-specter-text">Kill Date</h2>
              <input
                type="date"
                value={killDate}
                onChange={(e) => setKillDate(e.target.value)}
                className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
              />
              <p className="mt-1.5 text-[10px] text-specter-muted">
                Implant self-terminates after this date. Leave empty for no kill date.
              </p>
            </section>

            {/* Obfuscation */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <div className="mb-3 flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-specter-accent" />
                <h2 className="text-xs font-medium text-specter-text">Obfuscation</h2>
              </div>
              <div className="space-y-3">
                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={stringEncryption}
                    onChange={(e) => setStringEncryption(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">String Encryption</div>
                    <div className="text-[10px] text-specter-muted">
                      Re-encrypt embedded strings with a fresh XOR key
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={apiHashRandomization}
                    onChange={(e) => setApiHashRandomization(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">API Hash Randomization</div>
                    <div className="text-[10px] text-specter-muted">
                      Randomize hash salt and recompute API hash constants
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={junkCodeInsertion}
                    onChange={(e) => setJunkCodeInsertion(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">Junk Code Insertion</div>
                    <div className="text-[10px] text-specter-muted">
                      Insert NOP-equivalent sequences between functions
                    </div>
                  </div>
                </label>

                {junkCodeInsertion && (
                  <div className="ml-7">
                    <label className="mb-1 block text-[10px] text-specter-muted">
                      Junk Density (2-64 bytes)
                    </label>
                    <input
                      type="number"
                      min={2}
                      max={64}
                      value={junkDensity}
                      onChange={(e) => setJunkDensity(Number(e.target.value) || 8)}
                      className="w-24 rounded border border-specter-border bg-specter-bg px-2 py-1.5 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                    />
                  </div>
                )}

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={controlFlowFlattening}
                    onChange={(e) => setControlFlowFlattening(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">Control Flow Flattening</div>
                    <div className="text-[10px] text-specter-warning">
                      Heavy transform — increases payload size significantly
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={xorEncryption}
                    onChange={(e) => setXorEncryption(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">XOR Encryption</div>
                    <div className="text-[10px] text-specter-muted">
                      Encrypt blob with per-build 128-byte key + decryption stub
                    </div>
                  </div>
                </label>
              </div>
            </section>

            {/* Runtime Evasion */}
            <section className="rounded-lg border border-specter-border bg-specter-surface p-4">
              <div className="mb-3 flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-specter-accent" />
                <h2 className="text-xs font-medium text-specter-text">Runtime Evasion</h2>
              </div>
              <div className="space-y-3">
                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={moduleOverloading}
                    onChange={(e) => setModuleOverloading(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">Module Overloading</div>
                    <div className="text-[10px] text-specter-muted">
                      Load into file-backed section (NtCreateSection) — defeats memory scanners
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={pdataRegistration}
                    onChange={(e) => setPdataRegistration(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">.pdata Registration</div>
                    <div className="text-[10px] text-specter-muted">
                      Register exception handling data (RtlAddFunctionTable) — hides injected code
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={ntcontinueEntry}
                    onChange={(e) => setNtcontinueEntry(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">NtContinue Entry</div>
                    <div className="text-[10px] text-specter-muted">
                      Clean initial call stack via synthetic thread context transfer
                    </div>
                  </div>
                </label>
              </div>
            </section>

            {/* Development / Debug */}
            <section className="rounded-lg border border-specter-warning/30 bg-specter-warning/5 p-4">
              <div className="mb-3 flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5 text-specter-warning" />
                <h2 className="text-xs font-medium text-specter-text">Development</h2>
              </div>
              <div className="space-y-3">
                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={debugMode}
                    onChange={(e) => setDebugMode(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">Debug Mode</div>
                    <div className="text-[10px] text-specter-warning">
                      DebugView traces, simple 5s sleep — OPSEC unsafe for production
                    </div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={skipAntiAnalysis}
                    onChange={(e) => setSkipAntiAnalysis(e.target.checked)}
                    className="rounded border-specter-border"
                  />
                  <div>
                    <div className="text-xs text-specter-text">Skip VM/Sandbox Checks</div>
                    <div className="text-[10px] text-specter-warning">
                      Disable anti-analysis checks — use for testing in VMs
                    </div>
                  </div>
                </label>
              </div>
            </section>

            {/* Generate Button */}
            <button
              onClick={handleGenerate}
              disabled={building || !selectedProfile || channels.every((c) => !c.address.trim())}
              className="flex items-center justify-center gap-2 rounded-lg bg-specter-accent px-6 py-3 text-sm font-medium text-specter-bg transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
            >
              {building ? (
                <>
                  <Loader className="h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  Generate Payload
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
