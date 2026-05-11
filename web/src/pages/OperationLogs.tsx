import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertCircle, CheckCircle2, ClipboardList, RefreshCw, Search, XCircle } from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { OperationLog } from '@/gen/specter/v1/operation_logs_pb'

const sourceOptions = ['', 'module', 'socks', 'terraform', 'redirector']
const levelStyles: Record<string, string> = {
  error: 'text-specter-danger border-specter-danger bg-specter-danger/10',
  warn: 'text-status-stale border-status-stale bg-status-stale/10',
  warning: 'text-status-stale border-status-stale bg-status-stale/10',
  info: 'text-status-active border-status-active bg-status-active/10',
  debug: 'text-specter-muted border-specter-border bg-specter-surface',
}

function formatTimestamp(log: OperationLog): string {
  const seconds = log.createdAt?.seconds
  if (seconds === undefined) return 'N/A'
  return new Date(Number(seconds) * 1000).toLocaleString()
}

function levelIcon(level: string) {
  if (level === 'error') return XCircle
  if (level === 'warn' || level === 'warning') return AlertCircle
  return CheckCircle2
}

export function OperationLogs() {
  const [logs, setLogs] = useState<OperationLog[]>([])
  const [source, setSource] = useState('')
  const [target, setTarget] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const filteredTarget = useMemo(() => target.trim(), [target])

  const loadLogs = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await specterClient.listOperationLogs({
        source,
        targetId: filteredTarget,
        limit: 300,
      })
      setLogs(response.logs)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to fetch operation logs')
    } finally {
      setLoading(false)
    }
  }, [source, filteredTarget])

  useEffect(() => {
    void loadLogs()
    const timer = window.setInterval(() => void loadLogs(), 5000)
    return () => window.clearInterval(timer)
  }, [loadLogs])

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-specter-text">
            <ClipboardList className="h-5 w-5 text-specter-accent" />
            <h1 className="text-lg font-semibold">Operation Logs</h1>
          </div>
          <p className="mt-1 text-sm text-specter-muted">
            Module output, SOCKS lifecycle, redirector deployment, and Terraform command logs.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadLogs()}
          className="inline-flex items-center gap-2 rounded border border-specter-border px-3 py-2 text-sm text-specter-text hover:bg-specter-surface"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-3 border-y border-specter-border py-3">
        <label className="flex items-center gap-2 text-sm text-specter-muted">
          Source
          <select
            value={source}
            onChange={(event) => setSource(event.target.value)}
            className="rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-specter-text"
          >
            {sourceOptions.map((option) => (
              <option key={option || 'all'} value={option}>
                {option || 'all'}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-72 items-center gap-2 text-sm text-specter-muted">
          <Search className="h-4 w-4" />
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="target id"
            className="w-full rounded border border-specter-border bg-specter-surface px-2 py-1.5 text-specter-text placeholder:text-specter-muted/70"
          />
        </label>
      </div>

      {error && (
        <div className="rounded border border-specter-danger bg-specter-danger/10 px-3 py-2 text-sm text-specter-danger">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded border border-specter-border">
        <table className="w-full table-fixed text-left text-sm">
          <thead className="border-b border-specter-border bg-specter-surface text-xs uppercase text-specter-muted">
            <tr>
              <th className="w-44 px-3 py-2">Time</th>
              <th className="w-28 px-3 py-2">Level</th>
              <th className="w-32 px-3 py-2">Source</th>
              <th className="w-52 px-3 py-2">Target</th>
              <th className="px-3 py-2">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-specter-border">
            {logs.map((log) => {
              const style = levelStyles[log.level] ?? levelStyles.info
              const Icon = levelIcon(log.level)
              const isExpanded = expanded === log.id
              return (
                <tr key={log.id} className="align-top hover:bg-specter-surface/60">
                  <td className="px-3 py-2 font-mono text-xs text-specter-muted">{formatTimestamp(log)}</td>
                  <td className="px-3 py-2">
                    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs ${style}`}>
                      <Icon className="h-3 w-3" />
                      {log.level || 'info'}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-specter-text">{log.source}</td>
                  <td className="px-3 py-2 font-mono text-xs text-specter-muted">
                    {log.targetType ? `${log.targetType}:` : ''}
                    {log.targetId || '-'}
                  </td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => setExpanded(isExpanded ? null : log.id)}
                      className="w-full text-left text-specter-text hover:text-specter-accent"
                    >
                      {log.message}
                    </button>
                    {isExpanded && log.details && (
                      <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap rounded border border-specter-border bg-specter-bg p-3 font-mono text-xs text-specter-muted">
                        {log.details}
                      </pre>
                    )}
                  </td>
                </tr>
              )
            })}
            {logs.length === 0 && !loading && (
              <tr>
                <td colSpan={5} className="px-3 py-10 text-center text-sm text-specter-muted">
                  No operation logs found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
