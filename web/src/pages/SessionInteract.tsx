import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Terminal as XTerminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import {
  PanelRightClose,
  PanelRightOpen,
  Moon,
  Skull,
  Upload,
  Download,
  X,
  Plus,
  Monitor,
  Activity,
  Clock,
  Shield,
  Cpu,
  Globe,
  Network,
  Hash,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import { SessionStatus } from '@/gen/specter/v1/sessions_pb'
import { TaskPriority, TaskStatus } from '@/gen/specter/v1/tasks_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'
import type { Task } from '@/gen/specter/v1/tasks_pb'
import '@xterm/xterm/css/xterm.css'

// ── Types ──────────────────────────────────────────────────────────────

interface TabState {
  sessionId: string
  hostname: string
  commandHistory: string[]
  historyIndex: number
  currentInput: string
}

// ── Helpers ────────────────────────────────────────────────────────────

const statusLabel: Record<number, string> = {
  [SessionStatus.UNSPECIFIED]: 'Unknown',
  [SessionStatus.NEW]: 'New',
  [SessionStatus.ACTIVE]: 'Active',
  [SessionStatus.STALE]: 'Stale',
  [SessionStatus.DEAD]: 'Dead',
}

const statusColor: Record<number, string> = {
  [SessionStatus.UNSPECIFIED]: 'text-specter-muted',
  [SessionStatus.NEW]: 'text-status-new',
  [SessionStatus.ACTIVE]: 'text-status-active',
  [SessionStatus.STALE]: 'text-status-stale',
  [SessionStatus.DEAD]: 'text-status-dead',
}

const statusDotColor: Record<number, string> = {
  [SessionStatus.UNSPECIFIED]: 'bg-specter-muted',
  [SessionStatus.NEW]: 'bg-status-new',
  [SessionStatus.ACTIVE]: 'bg-status-active',
  [SessionStatus.STALE]: 'bg-status-stale',
  [SessionStatus.DEAD]: 'bg-status-dead',
}

const taskStatusLabel: Record<number, string> = {
  [TaskStatus.UNSPECIFIED]: 'Unknown',
  [TaskStatus.QUEUED]: 'Queued',
  [TaskStatus.DISPATCHED]: 'Dispatched',
  [TaskStatus.COMPLETE]: 'Complete',
  [TaskStatus.FAILED]: 'Failed',
}

function formatTimestamp(ts?: { seconds: bigint; nanos: number }): string {
  if (!ts) return '—'
  const date = new Date(Number(ts.seconds) * 1000)
  return date.toLocaleString()
}

function formatRelativeTime(ts?: { seconds: bigint; nanos: number }): string {
  if (!ts) return '—'
  const diff = Date.now() - Number(ts.seconds) * 1000
  if (diff < 60_000) return 'just now'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`
  return `${Math.floor(diff / 86400_000)}d ago`
}

// Known commands for tab completion
const KNOWN_COMMANDS = [
  'help', 'sleep', 'kill', 'upload', 'download', 'shell', 'powershell',
  'execute-assembly', 'inject', 'ps', 'ls', 'cd', 'pwd', 'cat', 'mkdir',
  'rm', 'cp', 'mv', 'whoami', 'env', 'netstat', 'ifconfig', 'arp',
  'screenshot', 'keylog', 'hashdump', 'mimikatz', 'token', 'pivot',
  'socks', 'portfwd', 'exit', 'tasks', 'clear',
]

// ── Terminal Hook ──────────────────────────────────────────────────────

function useXterm(
  containerRef: React.RefObject<HTMLDivElement | null>,
  onCommand: (cmd: string) => void,
  tabState: TabState,
  setTabState: (update: (prev: TabState) => TabState) => void,
) {
  const termRef = useRef<XTerminal | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const term = new XTerminal({
      cursorBlink: true,
      cursorStyle: 'bar',
      fontSize: 13,
      fontFamily: "'Cascadia Code', 'Fira Code', Consolas, monospace",
      theme: {
        background: '#09090b',
        foreground: '#f4f4f5',
        cursor: '#10b981',
        selectionBackground: '#27272a',
        black: '#09090b',
        red: '#ef4444',
        green: '#10b981',
        yellow: '#f59e0b',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#f4f4f5',
        brightBlack: '#71717a',
        brightRed: '#f87171',
        brightGreen: '#34d399',
        brightYellow: '#fbbf24',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#ffffff',
      },
      scrollback: 10000,
      allowProposedApi: true,
    })

    const fitAddon = new FitAddon()
    const webLinksAddon = new WebLinksAddon()
    term.loadAddon(fitAddon)
    term.loadAddon(webLinksAddon)
    term.open(container)

    // Small delay for container to be sized
    requestAnimationFrame(() => {
      try { fitAddon.fit() } catch { /* container not ready */ }
    })

    termRef.current = term
    fitAddonRef.current = fitAddon

    // Write initial prompt
    term.writeln('\x1b[32m╔══════════════════════════════════════════╗\x1b[0m')
    term.writeln('\x1b[32m║\x1b[0m  SPECTER C2 — Session Console            \x1b[32m║\x1b[0m')
    term.writeln('\x1b[32m╚══════════════════════════════════════════╝\x1b[0m')
    term.writeln('')
    writePrompt(term)

    let currentLine = ''

    term.onKey(({ key, domEvent }) => {
      const ev = domEvent

      if (ev.key === 'Enter') {
        term.writeln('')
        const cmd = currentLine.trim()
        if (cmd) {
          setTabState((prev) => ({
            ...prev,
            commandHistory: [...prev.commandHistory, cmd],
            historyIndex: prev.commandHistory.length + 1,
            currentInput: '',
          }))

          if (cmd === 'clear') {
            term.clear()
          } else {
            onCommand(cmd)
          }
        }
        currentLine = ''
        writePrompt(term)
      } else if (ev.key === 'Backspace') {
        if (currentLine.length > 0) {
          currentLine = currentLine.slice(0, -1)
          term.write('\b \b')
        }
      } else if (ev.key === 'ArrowUp') {
        const history = tabState.commandHistory
        const idx = tabState.historyIndex - 1
        if (idx >= 0 && idx < history.length) {
          // Clear current line
          while (currentLine.length > 0) {
            term.write('\b \b')
            currentLine = currentLine.slice(0, -1)
          }
          currentLine = history[idx]
          term.write(currentLine)
          setTabState((prev) => ({ ...prev, historyIndex: idx }))
        }
      } else if (ev.key === 'ArrowDown') {
        const history = tabState.commandHistory
        const idx = tabState.historyIndex + 1
        // Clear current line
        while (currentLine.length > 0) {
          term.write('\b \b')
          currentLine = currentLine.slice(0, -1)
        }
        if (idx < history.length) {
          currentLine = history[idx]
          term.write(currentLine)
          setTabState((prev) => ({ ...prev, historyIndex: idx }))
        } else {
          setTabState((prev) => ({ ...prev, historyIndex: history.length }))
        }
      } else if (ev.key === 'Tab') {
        ev.preventDefault()
        const matches = KNOWN_COMMANDS.filter((c) => c.startsWith(currentLine))
        if (matches.length === 1) {
          const completion = matches[0].slice(currentLine.length)
          currentLine += completion
          term.write(completion)
        } else if (matches.length > 1) {
          term.writeln('')
          term.writeln(`\x1b[33m${matches.join('  ')}\x1b[0m`)
          writePrompt(term)
          term.write(currentLine)
        }
      } else if (!ev.ctrlKey && !ev.altKey && !ev.metaKey && key.length === 1) {
        currentLine += key
        term.write(key)
      }
    })

    const resizeObserver = new ResizeObserver(() => {
      try { fitAddon.fit() } catch { /* ignore */ }
    })
    resizeObserver.observe(container)

    return () => {
      resizeObserver.disconnect()
      term.dispose()
      termRef.current = null
      fitAddonRef.current = null
    }
  }, [containerRef, onCommand, tabState.commandHistory, tabState.historyIndex, setTabState])

  return termRef
}

function writePrompt(term: XTerminal) {
  term.write('\x1b[32mspecter>\x1b[0m ')
}

// ── Sidebar Component ──────────────────────────────────────────────────

function SessionSidebar({
  session,
  tasks,
  collapsed,
  onToggle,
  onAction,
}: {
  session: SessionInfo | null
  tasks: Task[]
  collapsed: boolean
  onToggle: () => void
  onAction: (action: string) => void
}) {
  if (collapsed) {
    return (
      <div className="flex w-10 flex-col items-center border-l border-specter-border bg-specter-surface pt-3">
        <button
          onClick={onToggle}
          className="rounded p-1 text-specter-muted transition-colors hover:text-specter-text"
          title="Expand sidebar"
        >
          <PanelRightOpen className="h-4 w-4" />
        </button>
      </div>
    )
  }

  return (
    <div className="flex w-80 flex-col border-l border-specter-border bg-specter-surface" data-testid="session-sidebar">
      {/* Sidebar Header */}
      <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
        <h3 className="text-sm font-medium text-specter-text">Session Details</h3>
        <button
          onClick={onToggle}
          className="rounded p-1 text-specter-muted transition-colors hover:text-specter-text"
          title="Collapse sidebar"
        >
          <PanelRightClose className="h-4 w-4" />
        </button>
      </div>

      {session ? (
        <div className="flex-1 overflow-y-auto">
          {/* Session Info */}
          <div className="space-y-3 border-b border-specter-border p-4">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${statusDotColor[session.status]}`} />
              <span className={`text-sm font-medium ${statusColor[session.status]}`}>
                {statusLabel[session.status]}
              </span>
            </div>

            <div className="space-y-2">
              <MetadataRow icon={Monitor} label="Hostname" value={session.hostname} />
              <MetadataRow icon={Activity} label="Username" value={session.username} />
              <MetadataRow icon={Hash} label="PID" value={String(session.pid)} />
              <MetadataRow icon={Cpu} label="Process" value={session.processName} />
              <MetadataRow icon={Shield} label="Integrity" value={session.integrityLevel} />
              <MetadataRow icon={Globe} label="External IP" value={session.externalIp} />
              <MetadataRow icon={Network} label="Internal IP" value={session.internalIp} />
              <MetadataRow icon={Monitor} label="OS" value={session.osVersion} />
              <MetadataRow icon={Clock} label="Last Check-in" value={formatRelativeTime(session.lastCheckin)} />
              <MetadataRow icon={Clock} label="First Seen" value={formatTimestamp(session.firstSeen)} />
            </div>
          </div>

          {/* Quick Actions */}
          <div className="border-b border-specter-border p-4">
            <h4 className="mb-3 text-xs font-medium uppercase tracking-wider text-specter-muted">
              Quick Actions
            </h4>
            <div className="grid grid-cols-2 gap-2">
              <ActionButton icon={Moon} label="Sleep" onClick={() => onAction('sleep')} />
              <ActionButton icon={Skull} label="Kill" onClick={() => onAction('kill')} variant="danger" />
              <ActionButton icon={Upload} label="Upload" onClick={() => onAction('upload')} />
              <ActionButton icon={Download} label="Download" onClick={() => onAction('download')} />
            </div>
          </div>

          {/* Recent Tasks */}
          <div className="p-4">
            <h4 className="mb-3 text-xs font-medium uppercase tracking-wider text-specter-muted">
              Recent Tasks ({tasks.length})
            </h4>
            {tasks.length === 0 ? (
              <p className="text-xs text-specter-muted">No tasks yet</p>
            ) : (
              <div className="space-y-2">
                {tasks.slice(0, 10).map((task) => (
                  <div
                    key={task.id}
                    className="rounded border border-specter-border/50 p-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-specter-text">{task.taskType}</span>
                      <span
                        className={`${
                          task.status === TaskStatus.COMPLETE
                            ? 'text-status-active'
                            : task.status === TaskStatus.FAILED
                              ? 'text-specter-danger'
                              : 'text-specter-muted'
                        }`}
                      >
                        {taskStatusLabel[task.status]}
                      </span>
                    </div>
                    <span className="text-specter-muted">
                      {formatRelativeTime(task.createdAt)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex flex-1 items-center justify-center text-sm text-specter-muted">
          Loading session...
        </div>
      )}
    </div>
  )
}

function MetadataRow({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Monitor
  label: string
  value: string
}) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-3 w-3 shrink-0 text-specter-muted" />
      <div className="min-w-0">
        <p className="text-xs text-specter-muted">{label}</p>
        <p className="truncate text-xs text-specter-text">{value || '—'}</p>
      </div>
    </div>
  )
}

function ActionButton({
  icon: Icon,
  label,
  onClick,
  variant = 'default',
}: {
  icon: typeof Moon
  label: string
  onClick: () => void
  variant?: 'default' | 'danger'
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs transition-colors ${
        variant === 'danger'
          ? 'border-specter-danger/30 text-specter-danger hover:bg-specter-danger/10'
          : 'border-specter-border text-specter-muted hover:border-specter-muted hover:text-specter-text'
      }`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  )
}

// ── Main Page Component ────────────────────────────────────────────────

export function SessionInteract() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const terminalRef = useRef<HTMLDivElement>(null)

  const [session, setSession] = useState<SessionInfo | null>(null)
  const [tasks, setTasks] = useState<Task[]>([])
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [tabs, setTabs] = useState<TabState[]>(() =>
    id
      ? [{
          sessionId: id,
          hostname: '...',
          commandHistory: [],
          historyIndex: 0,
          currentInput: '',
        }]
      : []
  )
  const [activeTabIndex, setActiveTabIndex] = useState(0)
  const [error, setError] = useState<string | null>(null)

  // Fetch session info
  const fetchSession = useCallback(async () => {
    if (!id) return
    try {
      const res = await specterClient.getSession({ id })
      if (res.session) {
        setSession(res.session)
        setTabs((prev) =>
          prev.map((t) =>
            t.sessionId === id ? { ...t, hostname: res.session!.hostname } : t
          )
        )
      }
    } catch {
      setError('Unable to fetch session details')
    }
  }, [id])

  // Fetch tasks for the session
  const fetchTasks = useCallback(async () => {
    if (!id) return
    try {
      const res = await specterClient.listTasks({ sessionId: id })
      setTasks(res.tasks)
    } catch {
      // silently fail for tasks
    }
  }, [id])

  useEffect(() => {
    const refresh = () => {
      fetchSession()
      fetchTasks()
    }
    refresh()
    const interval = setInterval(refresh, 10_000)
    return () => clearInterval(interval)
  }, [fetchSession, fetchTasks])

  // Handle command execution
  const handleCommand = useCallback(
    async (cmd: string) => {
      if (!id) return

      const parts = cmd.split(/\s+/)
      const command = parts[0]
      const args = parts.slice(1).join(' ')

      // Handle local commands
      if (command === 'help') {
        // Help is handled in terminal output, not via gRPC
        return
      }
      if (command === 'exit') {
        navigate('/sessions')
        return
      }

      try {
        const encoder = new TextEncoder()
        await specterClient.queueTask({
          sessionId: id,
          taskType: command,
          arguments: encoder.encode(args),
          priority: TaskPriority.NORMAL,
          operatorId: '',
        })
        // Refresh tasks after queuing
        fetchTasks()
      } catch {
        // Error queuing will be shown in terminal
      }
    },
    [id, navigate, fetchTasks]
  )

  // Handle sidebar quick actions
  const handleAction = useCallback(
    (action: string) => {
      handleCommand(action)
    },
    [handleCommand]
  )

  const activeTab = tabs[activeTabIndex]

  const setActiveTabState = useCallback(
    (update: (prev: TabState) => TabState) => {
      setTabs((prev) =>
        prev.map((t, i) => (i === activeTabIndex ? update(t) : t))
      )
    },
    [activeTabIndex]
  )

  // xterm hook
  useXterm(terminalRef, handleCommand, activeTab ?? {
    sessionId: '',
    hostname: '',
    commandHistory: [],
    historyIndex: 0,
    currentInput: '',
  }, setActiveTabState)

  const addTab = () => {
    if (!id) return
    const newTab: TabState = {
      sessionId: id,
      hostname: session?.hostname ?? '...',
      commandHistory: [],
      historyIndex: 0,
      currentInput: '',
    }
    setTabs((prev) => [...prev, newTab])
    setActiveTabIndex(tabs.length)
  }

  const closeTab = (index: number) => {
    if (tabs.length <= 1) return
    setTabs((prev) => prev.filter((_, i) => i !== index))
    if (activeTabIndex >= index && activeTabIndex > 0) {
      setActiveTabIndex(activeTabIndex - 1)
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Error */}
      {error && (
        <div className="mx-4 mt-2 rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-2 text-sm text-specter-danger">
          {error}
        </div>
      )}

      {/* Tab Bar */}
      <div className="flex items-center border-b border-specter-border bg-specter-surface">
        <div className="flex flex-1 items-center overflow-x-auto">
          {tabs.map((tab, i) => (
            <div
              key={`${tab.sessionId}-${i}`}
              className={`group flex items-center gap-2 border-r border-specter-border px-4 py-2 text-xs ${
                i === activeTabIndex
                  ? 'bg-specter-bg text-specter-text'
                  : 'text-specter-muted hover:bg-specter-border/20 hover:text-specter-text'
              }`}
            >
              <button
                onClick={() => setActiveTabIndex(i)}
                className="flex items-center gap-2"
              >
                <span className={`h-1.5 w-1.5 rounded-full ${
                  session ? statusDotColor[session.status] : 'bg-specter-muted'
                }`} />
                <span className="max-w-[120px] truncate">{tab.hostname}</span>
              </button>
              {tabs.length > 1 && (
                <button
                  onClick={() => closeTab(i)}
                  className="rounded p-0.5 opacity-0 transition-opacity group-hover:opacity-100 hover:bg-specter-border"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          ))}
        </div>
        <button
          onClick={addTab}
          className="border-l border-specter-border px-3 py-2 text-specter-muted transition-colors hover:text-specter-text"
          title="New tab"
        >
          <Plus className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Main Content: Terminal + Sidebar */}
      <div className="flex min-h-0 flex-1">
        {/* Terminal Area (70% height is handled by flex) */}
        <div className="flex-1 overflow-hidden p-2" data-testid="terminal-container">
          <div
            ref={terminalRef}
            className="h-full w-full"
            data-testid="xterm-container"
          />
        </div>

        {/* Sidebar (30% width, collapsible) */}
        <SessionSidebar
          session={session}
          tasks={tasks}
          collapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed((p) => !p)}
          onAction={handleAction}
        />
      </div>
    </div>
  )
}
