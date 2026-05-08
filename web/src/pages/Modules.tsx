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
  args: Record<string, string | number | boolean>
  deploying: boolean
  result: { success: boolean; message: string } | null
}

type ModuleArgKind = 'string' | 'int32' | 'bool' | 'bytes_hex'

interface ModuleArgField {
  key: string
  label: string
  kind: ModuleArgKind
  required?: boolean
  placeholder?: string
  defaultValue?: string | number | boolean
  min?: number
  max?: number
}

interface ModuleSubcommand {
  value: string
  label: string
  fields: ModuleArgField[]
}

interface ModuleArgSchema {
  moduleName: string
  subcommands: ModuleSubcommand[]
}

type EncodedModuleArg =
  | { type: 'string'; value: string }
  | { type: 'int32'; value: number }
  | { type: 'bytes'; value: Uint8Array }

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

const MODULE_ARG_SCHEMAS: Record<string, ModuleArgSchema> = {
  socks5: {
    moduleName: 'socks5',
    subcommands: [
      {
        value: 'start',
        label: 'Start relay',
        fields: [
          { key: 'throttle_ms', label: 'Throttle', kind: 'int32', defaultValue: 250, min: 10, max: 5000 },
          { key: 'channel_url', label: 'WebSocket channel URL', kind: 'string', placeholder: 'wss://redirector.example/api/socks/<session>/ws' },
        ],
      },
      { value: 'status', label: 'Request status', fields: [] },
      { value: 'stop', label: 'Stop relay', fields: [] },
    ],
  },
  token: {
    moduleName: 'token',
    subcommands: [
      { value: 'list', label: 'List process tokens', fields: [] },
      { value: 'revert', label: 'Revert token', fields: [] },
      {
        value: 'steal',
        label: 'Steal by PID',
        fields: [{ key: 'pid', label: 'PID', kind: 'int32', required: true, min: 1 }],
      },
      {
        value: 'make',
        label: 'Make network token',
        fields: [
          { key: 'domain', label: 'Domain', kind: 'string', required: true, placeholder: '.' },
          { key: 'user', label: 'Username', kind: 'string', required: true },
          { key: 'pass', label: 'Password', kind: 'string', required: true },
        ],
      },
    ],
  },
  lateral: {
    moduleName: 'lateral',
    subcommands: [
      {
        value: 'wmi',
        label: 'WMI process create',
        fields: [
          { key: 'target', label: 'Target host', kind: 'string', required: true },
          { key: 'command', label: 'Command', kind: 'string', required: true },
        ],
      },
      {
        value: 'scm',
        label: 'SCM service create',
        fields: [
          { key: 'target', label: 'Target host', kind: 'string', required: true },
          { key: 'payload_path', label: 'Payload path', kind: 'string', required: true, placeholder: 'C:\\Windows\\Temp\\svc.exe' },
        ],
      },
      {
        value: 'dcom',
        label: 'DCOM launch',
        fields: [
          { key: 'target', label: 'Target host', kind: 'string', required: true },
          { key: 'payload', label: 'Payload', kind: 'string', required: true },
        ],
      },
      {
        value: 'schtask',
        label: 'Scheduled task',
        fields: [
          { key: 'target', label: 'Target host', kind: 'string', required: true },
          { key: 'payload_path', label: 'Payload path', kind: 'string', required: true, placeholder: 'C:\\Windows\\Temp\\task.exe' },
        ],
      },
    ],
  },
  inject: {
    moduleName: 'inject',
    subcommands: [
      {
        value: 'createthread',
        label: 'CreateThread',
        fields: [
          { key: 'pid', label: 'PID', kind: 'int32', required: true, min: 1 },
          { key: 'shellcode', label: 'Shellcode hex', kind: 'bytes_hex', required: true },
        ],
      },
      {
        value: 'apc',
        label: 'APC queue',
        fields: [
          { key: 'pid', label: 'PID', kind: 'int32', required: true, min: 1 },
          { key: 'tid', label: 'TID', kind: 'int32', required: true, min: 1 },
          { key: 'shellcode', label: 'Shellcode hex', kind: 'bytes_hex', required: true },
        ],
      },
      {
        value: 'hijack',
        label: 'Thread hijack',
        fields: [
          { key: 'pid', label: 'PID', kind: 'int32', required: true, min: 1 },
          { key: 'tid', label: 'TID', kind: 'int32', required: true, min: 1 },
          { key: 'shellcode', label: 'Shellcode hex', kind: 'bytes_hex', required: true },
        ],
      },
      {
        value: 'stomp',
        label: 'Module stomp',
        fields: [
          { key: 'pid', label: 'PID', kind: 'int32', required: true, min: 1 },
          { key: 'dll_name', label: 'DLL name', kind: 'string', required: true, placeholder: 'amsi.dll' },
          { key: 'shellcode', label: 'Shellcode hex', kind: 'bytes_hex', required: true },
        ],
      },
    ],
  },
  exfil: {
    moduleName: 'exfil',
    subcommands: [
      {
        value: 'file',
        label: 'Single file',
        fields: [
          { key: 'path', label: 'Remote path', kind: 'string', required: true },
          { key: 'chunk_size', label: 'Chunk size', kind: 'int32', defaultValue: 65536, min: 1024 },
          { key: 'throttle_ms', label: 'Throttle', kind: 'int32', defaultValue: 100, min: 0 },
        ],
      },
      {
        value: 'directory',
        label: 'Directory match',
        fields: [
          { key: 'dir', label: 'Directory', kind: 'string', required: true },
          { key: 'pattern', label: 'Pattern', kind: 'string', required: true, defaultValue: '*' },
          { key: 'recursive', label: 'Recursive', kind: 'bool', defaultValue: false },
          { key: 'chunk_size', label: 'Chunk size', kind: 'int32', defaultValue: 65536, min: 1024 },
          { key: 'throttle_ms', label: 'Throttle', kind: 'int32', defaultValue: 100, min: 0 },
        ],
      },
    ],
  },
  collect: {
    moduleName: 'collect',
    subcommands: [
      {
        value: 'keylog',
        label: 'Keylog',
        fields: [{ key: 'duration_sec', label: 'Duration', kind: 'int32', defaultValue: 60, min: 1, max: 3600 }],
      },
      {
        value: 'screenshot',
        label: 'Screenshot',
        fields: [
          { key: 'interval_sec', label: 'Interval', kind: 'int32', defaultValue: 5, min: 1 },
          { key: 'count', label: 'Count', kind: 'int32', defaultValue: 1, min: 1, max: 100 },
        ],
      },
    ],
  },
  smoke: {
    moduleName: 'smoke',
    subcommands: [{ value: 'run', label: 'Run smoke check', fields: [] }],
  },
}

function schemaForModule(moduleName: string): ModuleArgSchema | null {
  const name = moduleName.toLowerCase()
  if (MODULE_ARG_SCHEMAS[name]) return MODULE_ARG_SCHEMAS[name]
  if (name === 'keylog' || name === 'screenshot') return MODULE_ARG_SCHEMAS.collect
  return null
}

function initialArgsForModule(moduleName: string): Record<string, string | number | boolean> {
  const schema = schemaForModule(moduleName)
  if (!schema) return {}
  const name = moduleName.toLowerCase()
  const preferredSubcommand = name === 'screenshot' || name === 'keylog' ? name : schema.subcommands[0].value
  const subcommand =
    schema.subcommands.find((item) => item.value === preferredSubcommand) ?? schema.subcommands[0]
  const args: Record<string, string | number | boolean> = { subcommand: subcommand.value }
  for (const field of subcommand.fields) {
    args[field.key] = field.defaultValue ?? (field.kind === 'bool' ? false : field.kind === 'int32' ? 0 : '')
  }
  return args
}

function hexToBytes(input: string): Uint8Array {
  const hex = input.replace(/[\s:,-]/g, '')
  if (!hex) return new Uint8Array()
  if (hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) {
    throw new Error('Hex data must contain complete byte pairs')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function encodeModuleArgs(args: EncodedModuleArg[]): Uint8Array {
  const chunks: Uint8Array[] = []
  const header = new Uint8Array(4)
  new DataView(header.buffer).setUint32(0, args.length, true)
  chunks.push(header)

  for (const arg of args) {
    const data =
      arg.type === 'string'
        ? new Uint8Array([...new TextEncoder().encode(arg.value), 0])
        : arg.type === 'int32'
          ? (() => {
              const bytes = new Uint8Array(4)
              new DataView(bytes.buffer).setUint32(0, arg.value >>> 0, true)
              return bytes
            })()
          : arg.value
    const meta = new Uint8Array(8)
    const view = new DataView(meta.buffer)
    view.setUint32(0, arg.type === 'string' ? 0 : arg.type === 'int32' ? 1 : 2, true)
    view.setUint32(4, data.length, true)
    chunks.push(meta, data)
  }

  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

function buildModuleArgs(moduleName: string, values: Record<string, string | number | boolean>): Uint8Array {
  const schema = schemaForModule(moduleName)
  if (!schema) throw new Error(`No argument schema registered for module '${moduleName}'`)

  const subcommandValue = String(values.subcommand ?? schema.subcommands[0].value)
  const subcommand = schema.subcommands.find((item) => item.value === subcommandValue)
  if (!subcommand) throw new Error(`Unsupported ${schema.moduleName} action '${subcommandValue}'`)

  const args: EncodedModuleArg[] = [{ type: 'string', value: subcommand.value }]
  for (const field of subcommand.fields) {
    const raw = values[field.key] ?? field.defaultValue ?? ''
    if (field.required && (raw === '' || raw === 0 || raw === false)) {
      throw new Error(`${field.label} is required`)
    }

    if (field.kind === 'string') {
      args.push({ type: 'string', value: String(raw) })
    } else if (field.kind === 'int32') {
      const value = Number(raw)
      if (!Number.isInteger(value) || value < 0) throw new Error(`${field.label} must be a positive integer`)
      if (field.min !== undefined && value < field.min) throw new Error(`${field.label} must be at least ${field.min}`)
      if (field.max !== undefined && value > field.max) throw new Error(`${field.label} must be at most ${field.max}`)
      args.push({ type: 'int32', value })
    } else if (field.kind === 'bool') {
      args.push({ type: 'int32', value: raw === true ? 1 : 0 })
    } else {
      const bytes = hexToBytes(String(raw))
      if (field.required && bytes.length === 0) throw new Error(`${field.label} is required`)
      args.push({ type: 'bytes', value: bytes })
    }
  }

  const dcomMethod = schema.moduleName === 'lateral' && subcommand.value === 'dcom'
    ? String(values.method ?? 'mmc')
    : null
  if (dcomMethod) {
    args.push({ type: 'string', value: dcomMethod })
  }

  return encodeModuleArgs(args)
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
  onArgsChange: (key: string, value: string | number | boolean) => void
  onExecute: () => void
}) {
  const activeSessions = sessions.filter(
    (s) => s.status === SessionStatus.ACTIVE || s.status === SessionStatus.NEW
  )
  const schema = schemaForModule(state.module.name)
  const subcommandValue = String(state.args.subcommand ?? schema?.subcommands[0]?.value ?? '')
  const subcommand = schema?.subcommands.find((item) => item.value === subcommandValue)

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

          {/* Module-specific arguments */}
          {schema ? (
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-specter-muted">Action</label>
                <select
                  value={subcommandValue}
                  onChange={(e) => {
                    const next = schema.subcommands.find((item) => item.value === e.target.value)
                    onArgsChange('subcommand', e.target.value)
                    if (next) {
                      next.fields.forEach((field) => {
                        onArgsChange(field.key, field.defaultValue ?? (field.kind === 'bool' ? false : field.kind === 'int32' ? 0 : ''))
                      })
                    }
                  }}
                  className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                >
                  {schema.subcommands.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </div>

              {subcommand?.fields.map((field) => (
                <div key={field.key}>
                  <label className="text-xs font-medium text-specter-muted">{field.label}</label>
                  {field.kind === 'bool' ? (
                    <label className="mt-1.5 flex items-center gap-2 rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text">
                      <input
                        type="checkbox"
                        checked={Boolean(state.args[field.key])}
                        onChange={(e) => onArgsChange(field.key, e.target.checked)}
                      />
                      Enabled
                    </label>
                  ) : field.kind === 'bytes_hex' ? (
                    <textarea
                      value={String(state.args[field.key] ?? '')}
                      onChange={(e) => onArgsChange(field.key, e.target.value)}
                      rows={3}
                      placeholder="Hex bytes, for example: 90 90 cc"
                      className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 font-mono text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
                    />
                  ) : (
                    <input
                      type={field.kind === 'int32' ? 'number' : field.key === 'pass' ? 'password' : 'text'}
                      value={String(state.args[field.key] ?? field.defaultValue ?? '')}
                      min={field.min}
                      max={field.max}
                      placeholder={field.placeholder}
                      onChange={(e) => onArgsChange(field.key, field.kind === 'int32' ? Number(e.target.value) : e.target.value)}
                      className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
                    />
                  )}
                </div>
              ))}

              {schema.moduleName === 'lateral' && subcommandValue === 'dcom' && (
                <div>
                  <label className="text-xs font-medium text-specter-muted">DCOM method</label>
                  <select
                    value={String(state.args.method ?? 'mmc')}
                    onChange={(e) => onArgsChange('method', e.target.value)}
                    className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                  >
                    <option value="mmc">MMC20.Application</option>
                    <option value="shell">ShellWindows</option>
                    <option value="windows">ShellBrowserWindow</option>
                  </select>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded border border-specter-danger/30 bg-specter-danger/10 px-3 py-2 text-xs text-specter-danger">
              No argument schema is registered for this module. Deployment is disabled until the module exposes a typed argument schema.
            </div>
          )}

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
            disabled={!schema || state.selectedSessions.length === 0 || state.deploying}
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
      args: initialArgsForModule(module.name),
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

  const handleArgChange = useCallback((key: string, value: string | number | boolean) => {
    setDeployState((prev) => (prev ? { ...prev, args: { ...prev.args, [key]: value }, result: null } : null))
  }, [])

  const handleExecute = useCallback(async () => {
    if (!deployState) return

    setDeployState((prev) => (prev ? { ...prev, deploying: true, result: null } : null))

    try {
      const results: string[] = []
      const encodedArgs = buildModuleArgs(deployState.module.name, deployState.args)
      for (const sessionId of deployState.selectedSessions) {
        const req = create(LoadModuleRequestSchema, {
          sessionId,
          moduleName: deployState.module.name,
          arguments: encodedArgs,
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
          onArgsChange={handleArgChange}
          onExecute={handleExecute}
        />
      )}
    </div>
  )
}
