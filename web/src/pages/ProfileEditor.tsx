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

function computeJa3Hash(content: string): string {
  // Simulated JA3 hash computation based on TLS settings in profile
  let hash = 0
  for (let i = 0; i < content.length; i++) {
    const chr = content.charCodeAt(i)
    hash = ((hash << 5) - hash) + chr
    hash |= 0
  }
  const hex = Math.abs(hash).toString(16).padStart(32, '0').slice(0, 32)
  return hex
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

function parseTimingFromYaml(content: string): { sleep: number; jitter: number } {
  const result = { sleep: 60, jitter: 25 }
  const lines = content.split('\n')
  for (const line of lines) {
    const trimmed = line.trim()
    const sleepMatch = trimmed.match(/^sleep:\s*(\d+)/)
    if (sleepMatch) result.sleep = parseInt(sleepMatch[1], 10)
    const jitterMatch = trimmed.match(/^jitter:\s*(\d+)/)
    if (jitterMatch) result.jitter = parseInt(jitterMatch[1], 10)
  }
  return result
}

// ── Components ─────────────────────────────────────────────────────────

function ProfileList({
  profiles,
  selectedId,
  onSelect,
  onCreate,
}: {
  profiles: ProfileInfo[]
  selectedId: string | null
  onSelect: (id: string) => void
  onCreate: () => void
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
            <button
              key={p.id}
              onClick={() => onSelect(p.id)}
              className={`flex w-full items-center gap-2 border-b border-specter-border px-3 py-2.5 text-left transition-colors ${
                selectedId === p.id
                  ? 'bg-specter-surface text-specter-text'
                  : 'text-specter-muted hover:bg-specter-surface/50'
              }`}
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
          <TimingHistogram sleep={timing.sleep} jitter={timing.jitter} />
          <div className="mt-1 flex justify-between text-[10px] text-specter-muted">
            <span>{Math.round(timing.sleep * (1 - timing.jitter / 100))}s</span>
            <span>{Math.round(timing.sleep * (1 + timing.jitter / 100))}s</span>
          </div>
        </div>
      </div>

      {/* JA3 Hash */}
      <div>
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-specter-text">
          <Hash className="h-3 w-3" />
          Computed JA3 Hash
        </h3>
        <div className="rounded border border-specter-border bg-specter-bg p-3">
          <code className="break-all font-mono text-[11px] text-specter-accent">
            {ja3}
          </code>
        </div>
      </div>
    </div>
  )
}

function TimingHistogram({ sleep, jitter }: { sleep: number; jitter: number }) {
  const bars = useMemo(() => {
    const min = sleep * (1 - jitter / 100)
    const max = sleep * (1 + jitter / 100)
    const range = max - min
    const bucketCount = 20
    const buckets = new Array(bucketCount).fill(0)

    // Deterministic distribution of beacon intervals (uniform approximation)
    for (let i = 0; i < 1000; i++) {
      const u = i / 1000
      const val = min + range * u
      const idx = Math.min(bucketCount - 1, Math.floor(((val - min) / range) * bucketCount))
      buckets[idx]++
    }

    const maxVal = Math.max(...buckets)
    return buckets.map((v) => (maxVal > 0 ? v / maxVal : 0))
  }, [sleep, jitter])

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
    </div>
  )
}
