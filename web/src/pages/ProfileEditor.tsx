import { useState, useEffect, useCallback, useMemo } from 'react'
import Editor from '@monaco-editor/react'
import {
  Save,
  RefreshCw,
  Loader,
  FileText,
  Plus,
  Clock,
  Hash,
  ArrowLeftRight,
  ChevronRight,
  AlertCircle,
  CheckCircle,
  X,
  Trash2,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { ProfileInfo } from '@/gen/specter/v1/profiles_pb'
import { create } from '@bufbuild/protobuf'
import { CreateProfileRequestSchema } from '@/gen/specter/v1/profiles_pb'

// ── Helpers ────────────────────────────────────────────────────────────

function formatTimestamp(ts?: { seconds: bigint; nanos: number }): string {
  if (!ts) return 'N/A'
  const date = new Date(Number(ts.seconds) * 1000)
  return date.toLocaleString()
}

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

const DEFAULT_PROFILE_YAML = `# SPECTER C2 Profile Configuration
name: "default"
description: "Default HTTP profile"

http:
  # HTTP GET request configuration (beacon check-in)
  get:
    uri: "/api/v1/status"
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      Accept: "application/json"
      Accept-Language: "en-US,en;q=0.9"

  # HTTP POST request configuration (task results)
  post:
    uri: "/api/v1/submit"
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      Content-Type: "application/octet-stream"

timing:
  sleep: 60          # Beacon interval in seconds
  jitter: 25         # Jitter percentage (0-50)
  kill_date: ""      # Optional kill date (YYYY-MM-DD)

tls:
  verify: false
  ja3_randomize: true
`

interface ValidationError {
  line: number
  message: string
}

function validateYaml(content: string): ValidationError[] {
  const errors: ValidationError[] = []
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    // Check for tabs (YAML should use spaces)
    if (line.includes('\t')) {
      errors.push({ line: i + 1, message: 'Tabs not allowed in YAML, use spaces' })
    }
    // Check for trailing whitespace on non-empty lines with content
    if (line.length > 0 && line.trimEnd() !== line && line.trim().length > 0) {
      // Only flag truly problematic trailing whitespace
    }
  }

  // Check for basic YAML structure
  if (content.trim().length === 0) {
    errors.push({ line: 1, message: 'Profile content cannot be empty' })
  }

  return errors
}

// Well-known TLS numeric IDs for JA3 computation
const CIPHER_IDS: Record<string, string> = {
  'TLS_AES_128_GCM_SHA256': '4865',
  'TLS_AES_256_GCM_SHA384': '4866',
  'TLS_CHACHA20_POLY1305_SHA256': '4867',
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': '49199',
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': '49200',
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': '49195',
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': '49196',
  'TLS_RSA_WITH_AES_128_GCM_SHA256': '156',
  'TLS_RSA_WITH_AES_256_GCM_SHA384': '157',
}
const CURVE_IDS: Record<string, string> = {
  'x25519': '29', 'secp256r1': '23', 'secp384r1': '24', 'secp521r1': '25',
}
const EXT_IDS: Record<string, string> = {
  'server_name': '0', 'status_request': '5', 'supported_groups': '10',
  'ec_point_formats': '11', 'signature_algorithms': '13',
  'application_layer_protocol_negotiation': '16', 'signed_certificate_timestamp': '18',
  'extended_master_secret': '23', 'session_ticket': '35',
  'supported_versions': '43', 'psk_key_exchange_modes': '45', 'key_share': '51',
}

function parseTlsFromYaml(content: string) {
  const ciphers: string[] = []
  const curves: string[] = []
  const extensions: string[] = []
  const alpn: string[] = []
  let targetJa3 = ''
  let inSection = ''

  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === 'cipher_suites:') { inSection = 'ciphers'; continue }
    if (trimmed === 'curves:') { inSection = 'curves'; continue }
    if (trimmed === 'extensions:') { inSection = 'extensions'; continue }
    if (trimmed === 'alpn:') { inSection = 'alpn'; continue }
    if (trimmed.startsWith('target_ja3:')) { targetJa3 = trimmed.split(':')[1]?.trim().replace(/['"]/g, '') || ''; continue }
    if (trimmed.startsWith('- ') && inSection) {
      const val = trimmed.slice(2).trim().replace(/['"]/g, '')
      if (inSection === 'ciphers') ciphers.push(val)
      else if (inSection === 'curves') curves.push(val)
      else if (inSection === 'extensions') extensions.push(val)
      else if (inSection === 'alpn') alpn.push(val)
    } else if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('-')) {
      // Non-list line — exit current section unless it's a sub-key
      const indent = line.length - line.trimStart().length
      if (indent <= 4) inSection = ''
    }
  }
  return { ciphers, curves, extensions, alpn, targetJa3 }
}

// Simple MD5 for JA3 (browser-compatible, no crypto import needed)
function simpleMd5(str: string): string {
  // Use a basic hash that produces a 32-char hex string
  // For a real implementation, use SubtleCrypto — this is a display approximation
  let h1 = 0x811c9dc5, h2 = 0x1000193, h3 = 0xcbf29ce4, h4 = 0x84222325
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i)
    h1 = Math.imul(h1 ^ c, 0x01000193)
    h2 = Math.imul(h2 ^ c, 0x100001b3)
    h3 = Math.imul(h3 ^ c, 0x1000193)
    h4 = Math.imul(h4 ^ c, 0x100001b3)
  }
  return [h1, h2, h3, h4].map(h => (h >>> 0).toString(16).padStart(8, '0')).join('')
}

function computeJa3Hash(content: string): { ja3: string; ja3Raw: string; ja4: string } {
  const tls = parseTlsFromYaml(content)

  // If target_ja3 is set, use it directly
  if (tls.targetJa3) {
    return { ja3: tls.targetJa3, ja3Raw: '(using target_ja3 override)', ja4: '—' }
  }

  // JA3 = md5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
  const version = '771' // TLS 1.2
  const cipherIds = tls.ciphers.map(c => CIPHER_IDS[c] || '0').join('-') || '4865-4866-4867'
  const extIds = tls.extensions.map(e => EXT_IDS[e] || '0').join('-') || '0-10-11-13-16-23-43-45-51'
  const curveIds = tls.curves.map(c => CURVE_IDS[c] || '0').join('-') || '29-23'
  const ecPoints = '0' // uncompressed

  const ja3Raw = `${version},${cipherIds},${extIds},${curveIds},${ecPoints}`
  const ja3 = simpleMd5(ja3Raw)

  // JA4 approximation: t{TLS version}{SNI}{cipher count}{ext count}_{cipher hash}_{ext hash}
  const proto = tls.alpn.includes('h2') ? 'h2' : 'h1'
  const sni = 'd' // domain (not IP)
  const cCount = tls.ciphers.length.toString().padStart(2, '0') || '03'
  const eCount = tls.extensions.length.toString().padStart(2, '0') || '09'
  const cipherHash = simpleMd5(cipherIds).slice(0, 12)
  const extHash = simpleMd5(extIds + curveIds).slice(0, 12)
  const ja4 = `t13${sni}${proto}${cCount}${eCount}_${cipherHash}_${extHash}`

  return { ja3, ja3Raw, ja4 }
}

interface HttpPreview {
  method: string
  uri: string
  headers: Record<string, string>
}

function parsePreview(content: string): { get: HttpPreview; post: HttpPreview } {
  const result = {
    get: { method: 'GET', uri: '/api/v1/status', headers: {} as Record<string, string> },
    post: { method: 'POST', uri: '/api/v1/submit', headers: {} as Record<string, string> },
  }

  const lines = content.split('\n')
  let section: 'none' | 'get' | 'post' = 'none'
  let inHeaders = false

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed === 'get:') { section = 'get'; inHeaders = false }
    else if (trimmed === 'post:') { section = 'post'; inHeaders = false }
    else if (trimmed === 'headers:' && section !== 'none') { inHeaders = true }
    else if (trimmed.startsWith('uri:') && section !== 'none') {
      const val = trimmed.replace('uri:', '').trim().replace(/^["']|["']$/g, '')
      result[section].uri = val || result[section].uri
      inHeaders = false
    } else if (inHeaders && section !== 'none' && trimmed.includes(':')) {
      const idx = trimmed.indexOf(':')
      const key = trimmed.slice(0, idx).trim()
      const val = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, '')
      if (key && val && !key.startsWith('#')) {
        result[section].headers[key] = val
      }
    } else if (trimmed.length > 0 && !trimmed.startsWith('#') && !trimmed.startsWith('-') && section !== 'none') {
      // Check if indentation decreased → exit headers
      const indent = line.length - line.trimStart().length
      if (indent <= 4) inHeaders = false
    }
  }

  return result
}

function parseTimingFromYaml(content: string): { sleep: number; jitter: number; distribution: string } {
  const result = { sleep: 60, jitter: 25, distribution: 'uniform' }
  const lines = content.split('\n')
  for (const line of lines) {
    const trimmed = line.trim()
    // Support both schema names
    const sleepMatch = trimmed.match(/^(?:sleep|callback_interval):\s*(\d+)/)
    if (sleepMatch) result.sleep = parseInt(sleepMatch[1], 10)
    const jitterMatch = trimmed.match(/^(?:jitter|jitter_percent):\s*(\d+)/)
    if (jitterMatch) result.jitter = parseInt(jitterMatch[1], 10)
    const distMatch = trimmed.match(/^jitter_distribution:\s*(\w+)/)
    if (distMatch) result.distribution = distMatch[1].toLowerCase()
  }
  return result
}

// ── Components ─────────────────────────────────────────────────────────

function ProfileList({
  profiles,
  selectedId,
  onSelect,
  onCreate,
  onDelete,
}: {
  profiles: ProfileInfo[]
  selectedId: string | null
  onSelect: (id: string) => void
  onCreate: () => void
  onDelete: (id: string) => void
}) {
  return (
    <div className="flex flex-col border-r border-specter-border">
      <div className="flex items-center justify-between border-b border-specter-border px-3 py-2">
        <span className="text-xs font-medium text-specter-muted">Profiles</span>
        <button
          onClick={onCreate}
          className="rounded p-1 text-specter-muted transition-colors hover:bg-specter-surface hover:text-specter-text"
          title="New Profile"
        >
          <Plus className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {profiles.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-specter-muted">
            No profiles yet
          </div>
        ) : (
          profiles.map((p) => (
            <div
              key={p.id}
              className={`flex w-full items-center gap-2 border-b border-specter-border px-3 py-2.5 transition-colors ${
                selectedId === p.id
                  ? 'bg-specter-surface text-specter-text'
                  : 'text-specter-muted hover:bg-specter-surface/50'
              }`}
            >
              <button
                onClick={() => onSelect(p.id)}
                className="flex min-w-0 flex-1 items-center gap-2 text-left"
              >
                <FileText className="h-3.5 w-3.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-xs font-medium">{p.name}</div>
                  <div className="truncate text-[10px] text-specter-muted">
                    {p.description || 'No description'}
                  </div>
                </div>
                <ChevronRight className="h-3 w-3 shrink-0 opacity-50" />
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onDelete(p.id)
                }}
                className="shrink-0 rounded p-1 text-specter-muted transition-colors hover:bg-specter-danger/10 hover:text-specter-danger"
                title="Delete profile"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function HttpPreviewPanel({ content }: { content: string }) {
  const preview = useMemo(() => parsePreview(content), [content])
  const timing = useMemo(() => parseTimingFromYaml(content), [content])
  const ja3 = useMemo(() => computeJa3Hash(content), [content])

  return (
    <div className="flex flex-col gap-4 overflow-y-auto p-4">
      {/* GET Request Preview */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-specter-text">
          <ArrowLeftRight className="h-3 w-3" />
          GET Request (Check-in)
        </h3>
        <div className="rounded border border-specter-border bg-specter-bg p-3 font-mono text-[11px]">
          <div className="text-specter-accent">
            GET {preview.get.uri} HTTP/1.1
          </div>
          {Object.entries(preview.get.headers).map(([k, v]) => (
            <div key={k} className="text-specter-muted">
              <span className="text-specter-text">{k}:</span> {v}
            </div>
          ))}
        </div>
      </div>

      {/* POST Request Preview */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-specter-text">
          <ArrowLeftRight className="h-3 w-3" />
          POST Request (Task Results)
        </h3>
        <div className="rounded border border-specter-border bg-specter-bg p-3 font-mono text-[11px]">
          <div className="text-specter-accent">
            POST {preview.post.uri} HTTP/1.1
          </div>
          {Object.entries(preview.post.headers).map(([k, v]) => (
            <div key={k} className="text-specter-muted">
              <span className="text-specter-text">{k}:</span> {v}
            </div>
          ))}
        </div>
      </div>

      {/* Timing Histogram */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-specter-text">
          <Clock className="h-3 w-3" />
          Timing Distribution
        </h3>
        <div className="rounded border border-specter-border bg-specter-bg p-3">
          <div className="mb-2 flex items-center justify-between text-[10px] text-specter-muted">
            <span>Sleep: {timing.sleep}s</span>
            <span>Jitter: {timing.jitter}%</span>
          </div>
          <TimingHistogram sleep={timing.sleep} jitter={timing.jitter} distribution={timing.distribution} />
          <div className="mt-1 flex justify-between text-[10px] text-specter-muted">
            <span>{Math.round(timing.sleep * (1 - timing.jitter / 100))}s</span>
            <span>{Math.round(timing.sleep * (1 + timing.jitter / 100))}s</span>
          </div>
        </div>
      </div>

      {/* JA3 / JA4 Fingerprints */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-specter-text">
          <Hash className="h-3 w-3" />
          TLS Fingerprints
        </h3>
        <div className="space-y-2 rounded border border-specter-border bg-specter-bg p-3">
          <div>
            <div className="mb-0.5 text-[10px] text-specter-muted">JA3</div>
            <code className="break-all font-mono text-[11px] text-specter-accent">
              {ja3.ja3}
            </code>
          </div>
          <div>
            <div className="mb-0.5 text-[10px] text-specter-muted">JA4</div>
            <code className="break-all font-mono text-[11px] text-specter-accent">
              {ja3.ja4}
            </code>
          </div>
          <div>
            <div className="mb-0.5 text-[10px] text-specter-muted">JA3 raw string</div>
            <code className="break-all font-mono text-[10px] text-specter-muted">
              {ja3.ja3Raw}
            </code>
          </div>
        </div>
      </div>
    </div>
  )
}

function TimingHistogram({ sleep, jitter, distribution = 'uniform' }: { sleep: number; jitter: number; distribution?: string }) {
  const bars = useMemo(() => {
    const min = sleep * (1 - jitter / 100)
    const max = sleep * (1 + jitter / 100)
    const range = max - min
    const bucketCount = 20
    const buckets = new Array(bucketCount).fill(0)
    const n = 2000

    for (let i = 0; i < n; i++) {
      const u = i / n
      let val: number
      switch (distribution) {
        case 'gaussian': {
          // Box-Muller approximation centered at sleep with stddev = range/6
          const u1 = (i + 1) / (n + 1)
          const u2 = ((i * 7 + 3) % n + 1) / (n + 1)
          const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2)
          val = sleep + z * (range / 6)
          break
        }
        case 'pareto': {
          // Pareto-like: heavy tail toward longer intervals
          const alpha = 3
          val = min + range * (1 - Math.pow(1 - u, 1 / alpha))
          break
        }
        default:
          // Uniform
          val = min + range * u
      }
      val = Math.max(min, Math.min(max, val))
      const idx = Math.min(bucketCount - 1, Math.floor(((val - min) / range) * bucketCount))
      buckets[idx]++
    }

    const maxVal = Math.max(...buckets)
    return buckets.map((v) => (maxVal > 0 ? v / maxVal : 0))
  }, [sleep, jitter, distribution])

  return (
    <div className="flex h-12 items-end gap-px">
      {bars.map((h, i) => (
        <div
          key={i}
          className="flex-1 rounded-t bg-specter-accent/60"
          style={{ height: `${Math.max(2, h * 100)}%` }}
        />
      ))}
    </div>
  )
}

// ── ProfileEditor Page ─────────────────────────────────────────────────

export function ProfileEditor() {
  const [profiles, setProfiles] = useState<ProfileInfo[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [editorContent, setEditorContent] = useState(DEFAULT_PROFILE_YAML)
  const [profileName, setProfileName] = useState('new-profile')
  const [profileDesc, setProfileDesc] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saveResult, setSaveResult] = useState<{ success: boolean; message: string } | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [isNew, setIsNew] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<{ id: string; name: string } | null>(null)
  const [deleting, setDeleting] = useState(false)

  const validationErrors = useMemo(() => validateYaml(editorContent), [editorContent])

  const fetchProfiles = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await specterClient.listProfiles({})
      setProfiles(res.profiles)
      setLastRefresh(new Date())
    } catch {
      setError('Unable to connect to teamserver')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchProfiles()
  }, [fetchProfiles])

  const handleSelectProfile = useCallback(
    async (id: string) => {
      try {
        const res = await specterClient.getProfile({ id })
        if (res.profile) {
          setSelectedId(id)
          setEditorContent(res.profile.yamlContent || DEFAULT_PROFILE_YAML)
          setProfileName(res.profile.name)
          setProfileDesc(res.profile.description)
          setIsNew(false)
          setSaveResult(null)
        }
      } catch {
        setError('Failed to load profile')
      }
    },
    []
  )

  const handleNewProfile = useCallback(() => {
    setSelectedId(null)
    setEditorContent(DEFAULT_PROFILE_YAML)
    setProfileName('new-profile')
    setProfileDesc('')
    setIsNew(true)
    setSaveResult(null)
  }, [])

  const handleSave = useCallback(async () => {
    if (validationErrors.length > 0) {
      setSaveResult({ success: false, message: 'Fix validation errors before saving' })
      return
    }

    setSaving(true)
    setSaveResult(null)

    try {
      const req = create(CreateProfileRequestSchema, {
        name: profileName,
        description: profileDesc,
        yamlContent: editorContent,
      })
      const res = await specterClient.createProfile(req)
      if (res.profile) {
        setSelectedId(res.profile.id)
        setIsNew(false)
        setSaveResult({ success: true, message: 'Profile saved successfully' })
        await fetchProfiles()
      }
    } catch (err) {
      setSaveResult({
        success: false,
        message: err instanceof Error ? err.message : 'Failed to save profile',
      })
    } finally {
      setSaving(false)
    }
  }, [profileName, profileDesc, editorContent, validationErrors, fetchProfiles])

  const handleDeleteRequest = useCallback(
    (id: string) => {
      const profile = profiles.find((p) => p.id === id)
      setDeleteConfirm({ id, name: profile?.name || id })
    },
    [profiles]
  )

  const handleDeleteConfirm = useCallback(async () => {
    if (!deleteConfirm) return
    setDeleting(true)
    try {
      await specterClient.deleteProfile({ id: deleteConfirm.id })
      if (selectedId === deleteConfirm.id) {
        setSelectedId(null)
        setEditorContent(DEFAULT_PROFILE_YAML)
        setProfileName('new-profile')
        setProfileDesc('')
        setIsNew(false)
      }
      setDeleteConfirm(null)
      await fetchProfiles()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete profile')
    } finally {
      setDeleting(false)
    }
  }, [deleteConfirm, selectedId, fetchProfiles])

  return (
    <div className="flex h-full flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Profile Editor</h1>
          <p className="text-xs text-specter-muted">
            Create and edit C2 communication profiles
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {profiles.length} profile(s) &middot; Updated {formatRelativeTime(lastRefresh)}
          </span>
          <button
            onClick={fetchProfiles}
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
          {error}
        </div>
      )}

      {/* Main Layout: Sidebar + Editor + Preview */}
      <div className="flex flex-1 overflow-hidden rounded-lg border border-specter-border">
        {/* Profile List Sidebar */}
        <div className="w-56 shrink-0">
          <ProfileList
            profiles={profiles}
            selectedId={selectedId}
            onSelect={handleSelectProfile}
            onCreate={handleNewProfile}
            onDelete={handleDeleteRequest}
          />
        </div>

        {/* Editor Panel */}
        <div className="flex flex-1 flex-col">
          {/* Editor Toolbar */}
          <div className="flex items-center justify-between border-b border-specter-border px-3 py-2">
            <div className="flex items-center gap-3">
              <input
                type="text"
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                placeholder="Profile name"
                className="rounded border border-specter-border bg-specter-surface px-2 py-1 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
              />
              <input
                type="text"
                value={profileDesc}
                onChange={(e) => setProfileDesc(e.target.value)}
                placeholder="Description"
                className="w-48 rounded border border-specter-border bg-specter-surface px-2 py-1 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
              />
              {selectedId && !isNew && (
                <span className="text-[10px] text-specter-muted">
                  Last saved: {formatTimestamp(profiles.find((p) => p.id === selectedId)?.updatedAt)}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {validationErrors.length > 0 && (
                <span className="flex items-center gap-1 text-[10px] text-specter-warning">
                  <AlertCircle className="h-3 w-3" />
                  {validationErrors.length} issue(s)
                </span>
              )}
              {validationErrors.length === 0 && editorContent.trim().length > 0 && (
                <span className="flex items-center gap-1 text-[10px] text-status-active">
                  <CheckCircle className="h-3 w-3" />
                  Valid
                </span>
              )}
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs font-medium text-specter-bg transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
              >
                {saving ? (
                  <Loader className="h-3 w-3 animate-spin" />
                ) : (
                  <Save className="h-3 w-3" />
                )}
                Save
              </button>
            </div>
          </div>

          {/* Save Result Banner */}
          {saveResult && (
            <div
              className={`flex items-center justify-between border-b px-3 py-1.5 text-xs ${
                saveResult.success
                  ? 'border-status-active/30 bg-status-active/10 text-status-active'
                  : 'border-specter-danger/30 bg-specter-danger/10 text-specter-danger'
              }`}
            >
              <span>{saveResult.message}</span>
              <button onClick={() => setSaveResult(null)}>
                <X className="h-3 w-3" />
              </button>
            </div>
          )}

          {/* Split View: Editor + Preview */}
          <div className="flex flex-1 overflow-hidden">
            {/* Monaco Editor (50%) */}
            <div className="flex-1 border-r border-specter-border" data-testid="editor-panel">
              <Editor
                height="100%"
                defaultLanguage="yaml"
                value={editorContent}
                onChange={(value) => setEditorContent(value ?? '')}
                theme="vs-dark"
                options={{
                  minimap: { enabled: false },
                  fontSize: 12,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  tabSize: 2,
                  insertSpaces: true,
                  renderWhitespace: 'selection',
                  padding: { top: 8 },
                }}
              />
            </div>

            {/* Live Preview (50%) */}
            <div className="flex-1" data-testid="preview-panel">
              <div className="border-b border-specter-border px-3 py-2">
                <span className="text-xs font-medium text-specter-muted">Live Preview</span>
              </div>
              <HttpPreviewPanel content={editorContent} />
            </div>
          </div>
        </div>
      </div>

      {/* Delete Confirmation Dialog */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-sm rounded-lg border border-specter-border bg-specter-bg shadow-xl">
            <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
              <h2 className="text-sm font-medium text-specter-text">Delete Profile</h2>
              <button onClick={() => setDeleteConfirm(null)} className="text-specter-muted hover:text-specter-text">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-4">
              <p className="text-xs text-specter-muted">
                Are you sure you want to delete the profile &ldquo;{deleteConfirm.name}&rdquo;? This action cannot be undone.
              </p>
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-specter-border px-4 py-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="rounded border border-specter-border px-3 py-1.5 text-xs text-specter-muted transition-colors hover:text-specter-text"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteConfirm}
                disabled={deleting}
                className="flex items-center gap-1.5 rounded bg-specter-danger px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-specter-danger/90 disabled:opacity-50"
              >
                {deleting && <Loader className="h-3 w-3 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
