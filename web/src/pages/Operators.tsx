import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search,
  RefreshCw,
  Loader,
  Users,
  ShieldCheck,
  KeyRound,
  Plus,
  X,
  Copy,
  Download,
  Ban,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import type { Operator } from '@/gen/specter/v1/operators_pb'
import { OperatorRole } from '@/gen/specter/v1/operators_pb'
import type { CertificateInfo } from '@/gen/specter/v1/certificates_pb'
import {
  IssueOperatorCertificateRequestSchema,
  RevokeOperatorCertificateRequestSchema,
} from '@/gen/specter/v1/certificates_pb'
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
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function formatDateTime(date: Date): string {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function timestampToDate(ts?: { seconds: bigint; nanos: number }): Date | null {
  if (!ts) return null
  return new Date(Number(ts.seconds) * 1000 + ts.nanos / 1_000_000)
}

function roleLabel(role: OperatorRole): string {
  switch (role) {
    case OperatorRole.ADMIN:
      return 'ADMIN'
    case OperatorRole.OPERATOR:
      return 'OPERATOR'
    case OperatorRole.OBSERVER:
      return 'OBSERVER'
    default:
      return 'UNSPECIFIED'
  }
}

function roleBadgeClasses(role: OperatorRole): string {
  switch (role) {
    case OperatorRole.ADMIN:
      return 'bg-specter-accent/10 border-specter-accent/30 text-specter-accent'
    case OperatorRole.OPERATOR:
      return 'bg-specter-info/10 border-specter-info/30 text-specter-info'
    case OperatorRole.OBSERVER:
      return 'bg-specter-muted/10 border-specter-muted/30 text-specter-muted'
    default:
      return 'bg-specter-muted/10 border-specter-muted/30 text-specter-muted'
  }
}

// ── Types ──────────────────────────────────────────────────────────────

interface IssueCertDialogState {
  username: string
  role: string
  validityDays: number
  issuing: boolean
  result: null | {
    success: boolean
    message: string
    certPem?: string
    keyPem?: string
    caCertPem?: string
    serial?: string
  }
}

interface RevokeConfirmState {
  serial: string
  subjectCn: string
  revoking: boolean
}

// ── Components ─────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: OperatorRole }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${roleBadgeClasses(role)}`}
    >
      {roleLabel(role)}
    </span>
  )
}

function CertStatusBadge({ revoked }: { revoked: boolean }) {
  if (revoked) {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-specter-danger/30 bg-specter-danger/10 px-1.5 py-0.5 text-[10px] font-medium text-specter-danger">
        <Ban className="h-2.5 w-2.5" />
        Revoked
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-status-active/30 bg-status-active/10 px-1.5 py-0.5 text-[10px] font-medium text-status-active">
      <CheckCircle className="h-2.5 w-2.5" />
      Active
    </span>
  )
}

function IssueCertDialog({
  state,
  onClose,
  onFieldChange,
  onIssue,
}: {
  state: IssueCertDialogState
  onClose: () => void
  onFieldChange: (field: keyof IssueCertDialogState, value: string | number) => void
  onIssue: () => void
}) {
  const handleCopy = useCallback((text: string) => {
    navigator.clipboard.writeText(text)
  }, [])

  const handleDownload = useCallback((content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }, [])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Issue Operator Certificate</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex flex-col gap-4 p-4">
          {!state.result?.success ? (
            <>
              {/* Username */}
              <div>
                <label className="text-xs font-medium text-specter-muted">Username</label>
                <input
                  type="text"
                  value={state.username}
                  onChange={(e) => onFieldChange('username', e.target.value)}
                  placeholder="operator-name"
                  className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none font-mono"
                />
              </div>

              {/* Role */}
              <div>
                <label className="text-xs font-medium text-specter-muted">Role</label>
                <select
                  value={state.role}
                  onChange={(e) => onFieldChange('role', e.target.value)}
                  className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none"
                >
                  <option value="ADMIN">Admin</option>
                  <option value="OPERATOR">Operator</option>
                  <option value="OBSERVER">Observer</option>
                </select>
              </div>

              {/* Validity Days */}
              <div>
                <label className="text-xs font-medium text-specter-muted">Validity (days)</label>
                <input
                  type="number"
                  value={state.validityDays}
                  onChange={(e) => onFieldChange('validityDays', parseInt(e.target.value) || 0)}
                  min={1}
                  max={3650}
                  className="mt-1.5 w-full rounded border border-specter-border bg-specter-surface px-3 py-2 text-xs text-specter-text focus:border-specter-accent focus:outline-none font-mono"
                />
              </div>

              {/* Error */}
              {state.result && !state.result.success && (
                <div className="rounded border border-specter-danger/30 bg-specter-danger/10 px-3 py-2 text-xs text-specter-danger">
                  {state.result.message}
                </div>
              )}
            </>
          ) : (
            <>
              {/* Success: Show PEM content */}
              <div className="rounded border border-status-active/30 bg-status-active/10 px-3 py-2 text-xs text-status-active">
                Certificate issued successfully (Serial: {state.result.serial})
              </div>

              {/* Client Certificate */}
              <div>
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-specter-muted">Client Certificate</label>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => handleCopy(state.result!.certPem!)}
                      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-specter-muted hover:text-specter-text"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() =>
                        handleDownload(state.result!.certPem!, `${state.username}-cert.pem`)
                      }
                      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-specter-muted hover:text-specter-text"
                      title="Download"
                    >
                      <Download className="h-3 w-3" />
                    </button>
                  </div>
                </div>
                <pre className="mt-1 max-h-24 overflow-auto rounded border border-specter-border bg-specter-surface px-3 py-2 text-[10px] text-specter-text font-mono select-all">
                  {state.result.certPem}
                </pre>
              </div>

              {/* Private Key */}
              <div>
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-specter-muted">Private Key</label>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => handleCopy(state.result!.keyPem!)}
                      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-specter-muted hover:text-specter-text"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() =>
                        handleDownload(state.result!.keyPem!, `${state.username}-key.pem`)
                      }
                      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-specter-muted hover:text-specter-text"
                      title="Download"
                    >
                      <Download className="h-3 w-3" />
                    </button>
                  </div>
                </div>
                <pre className="mt-1 max-h-24 overflow-auto rounded border border-specter-border bg-specter-surface px-3 py-2 text-[10px] text-specter-text font-mono select-all">
                  {state.result.keyPem}
                </pre>
              </div>

              {/* CA Certificate */}
              <div>
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-specter-muted">CA Certificate</label>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => handleCopy(state.result!.caCertPem!)}
                      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-specter-muted hover:text-specter-text"
                      title="Copy to clipboard"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() => handleDownload(state.result!.caCertPem!, 'ca-cert.pem')}
                      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-specter-muted hover:text-specter-text"
                      title="Download"
                    >
                      <Download className="h-3 w-3" />
                    </button>
                  </div>
                </div>
                <pre className="mt-1 max-h-24 overflow-auto rounded border border-specter-border bg-specter-surface px-3 py-2 text-[10px] text-specter-text font-mono select-all">
                  {state.result.caCertPem}
                </pre>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-specter-border px-4 py-3">
          <button
            onClick={onClose}
            className="rounded border border-specter-border px-3 py-1.5 text-xs text-specter-muted transition-colors hover:text-specter-text"
          >
            {state.result?.success ? 'Close' : 'Cancel'}
          </button>
          {!state.result?.success && (
            <button
              onClick={onIssue}
              disabled={!state.username.trim() || state.issuing}
              className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
            >
              {state.issuing ? (
                <Loader className="h-3 w-3 animate-spin" />
              ) : (
                <KeyRound className="h-3 w-3" />
              )}
              Issue Certificate
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function RevokeConfirmDialog({
  state,
  onClose,
  onConfirm,
}: {
  state: RevokeConfirmState
  onClose: () => void
  onConfirm: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg border border-specter-border bg-specter-bg shadow-xl">
        <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
          <h2 className="text-sm font-medium text-specter-text">Revoke Certificate</h2>
          <button onClick={onClose} className="text-specter-muted hover:text-specter-text">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex flex-col gap-3 p-4">
          <div className="flex items-center gap-2 rounded border border-specter-danger/30 bg-specter-danger/10 px-3 py-2 text-xs text-specter-danger">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>This action cannot be undone. The operator will lose access immediately.</span>
          </div>
          <div className="text-xs text-specter-muted">
            Certificate: <span className="font-mono text-specter-text">{state.subjectCn}</span>
          </div>
          <div className="text-xs text-specter-muted">
            Serial: <span className="font-mono text-specter-text">{state.serial}</span>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-specter-border px-4 py-3">
          <button
            onClick={onClose}
            className="rounded border border-specter-border px-3 py-1.5 text-xs text-specter-muted transition-colors hover:text-specter-text"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={state.revoking}
            className="flex items-center gap-1.5 rounded bg-specter-danger px-3 py-1.5 text-xs text-white font-medium transition-colors hover:bg-specter-danger/90 disabled:opacity-50"
          >
            {state.revoking ? (
              <Loader className="h-3 w-3 animate-spin" />
            ) : (
              <Ban className="h-3 w-3" />
            )}
            Revoke
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Operators Page ────────────────────────────────────────────────────

export function Operators() {
  const [operators, setOperators] = useState<Operator[]>([])
  const [certificates, setCertificates] = useState<CertificateInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [searchQuery, setSearchQuery] = useState('')
  const [issueCertState, setIssueCertState] = useState<IssueCertDialogState | null>(null)
  const [revokeState, setRevokeState] = useState<RevokeConfirmState | null>(null)

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const [operatorsRes, certsRes] = await Promise.allSettled([
        specterClient.listOperators({}),
        specterClient.listOperatorCertificates({}),
      ])

      if (operatorsRes.status === 'fulfilled') {
        setOperators(operatorsRes.value.operators)
      }
      if (certsRes.status === 'fulfilled') {
        setCertificates(certsRes.value.certificates)
      }

      if (operatorsRes.status === 'rejected' && certsRes.status === 'rejected') {
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

  // ── Filtered data ─────────────────────────────────────────────────

  const filteredOperators = useMemo(() => {
    if (!searchQuery) return operators
    const q = searchQuery.toLowerCase()
    return operators.filter((op) => {
      const searchable = [op.username, roleLabel(op.role), op.id].join(' ').toLowerCase()
      return searchable.includes(q)
    })
  }, [operators, searchQuery])

  const filteredCertificates = useMemo(() => {
    if (!searchQuery) return certificates
    const q = searchQuery.toLowerCase()
    return certificates.filter((cert) => {
      const searchable = [cert.serial, cert.subjectCn, cert.subjectOu].join(' ').toLowerCase()
      return searchable.includes(q)
    })
  }, [certificates, searchQuery])

  // ── Issue Certificate ─────────────────────────────────────────────

  const handleOpenIssueCert = useCallback(() => {
    setIssueCertState({
      username: '',
      role: 'OPERATOR',
      validityDays: 365,
      issuing: false,
      result: null,
    })
  }, [])

  const handleIssueCertFieldChange = useCallback(
    (field: keyof IssueCertDialogState, value: string | number) => {
      setIssueCertState((prev) => (prev ? { ...prev, [field]: value, result: null } : null))
    },
    []
  )

  const handleIssueCert = useCallback(async () => {
    if (!issueCertState) return

    setIssueCertState((prev) => (prev ? { ...prev, issuing: true, result: null } : null))

    try {
      const req = create(IssueOperatorCertificateRequestSchema, {
        username: issueCertState.username,
        role: issueCertState.role,
        validityDays: issueCertState.validityDays,
      })
      const res = await specterClient.issueOperatorCertificate(req)

      setIssueCertState((prev) =>
        prev
          ? {
              ...prev,
              issuing: false,
              result: {
                success: true,
                message: 'Certificate issued successfully',
                certPem: res.certPem,
                keyPem: res.keyPem,
                caCertPem: res.caCertPem,
                serial: res.serial,
              },
            }
          : null
      )

      // Refresh data to show new certificate
      fetchData()
    } catch (err) {
      setIssueCertState((prev) =>
        prev
          ? {
              ...prev,
              issuing: false,
              result: {
                success: false,
                message: err instanceof Error ? err.message : 'Failed to issue certificate',
              },
            }
          : null
      )
    }
  }, [issueCertState, fetchData])

  // ── Revoke Certificate ────────────────────────────────────────────

  const handleOpenRevoke = useCallback((cert: CertificateInfo) => {
    setRevokeState({
      serial: cert.serial,
      subjectCn: cert.subjectCn,
      revoking: false,
    })
  }, [])

  const handleRevoke = useCallback(async () => {
    if (!revokeState) return

    setRevokeState((prev) => (prev ? { ...prev, revoking: true } : null))

    try {
      const req = create(RevokeOperatorCertificateRequestSchema, {
        serial: revokeState.serial,
      })
      await specterClient.revokeOperatorCertificate(req)
      setRevokeState(null)
      fetchData()
    } catch {
      setRevokeState((prev) => (prev ? { ...prev, revoking: false } : null))
    }
  }, [revokeState, fetchData])

  // ── Render ────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Operators</h1>
          <p className="text-xs text-specter-muted">
            Manage operator accounts and mTLS certificates
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-specter-muted">
            {operators.length} operator{operators.length !== 1 ? 's' : ''} &middot;{' '}
            {certificates.length} cert{certificates.length !== 1 ? 's' : ''}
          </span>
          <span className="text-xs text-specter-muted">
            Updated {formatRelativeTime(lastRefresh)}
          </span>

          <button
            onClick={handleOpenIssueCert}
            className="flex items-center gap-1.5 rounded bg-specter-accent px-3 py-1.5 text-xs text-specter-bg font-medium transition-colors hover:bg-specter-accent/90"
          >
            <Plus className="h-3 w-3" />
            Issue Certificate
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
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-specter-muted" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search operators and certificates..."
          className="w-full rounded border border-specter-border bg-specter-surface py-1.5 pl-8 pr-3 text-xs text-specter-text placeholder:text-specter-muted focus:border-specter-accent focus:outline-none"
        />
      </div>

      {/* Loading */}
      {loading && operators.length === 0 && certificates.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader className="h-5 w-5 animate-spin text-specter-muted" />
        </div>
      ) : (
        <>
          {/* Operators Table */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Users className="h-4 w-4 text-specter-muted" />
              <h2 className="text-sm font-medium text-specter-text">Operators</h2>
              <span className="text-xs text-specter-muted">({filteredOperators.length})</span>
            </div>

            {filteredOperators.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-lg border border-specter-border py-10 text-specter-muted">
                <Users className="mb-2 h-8 w-8" />
                <p className="text-sm">No operators found</p>
              </div>
            ) : (
              <div className="overflow-hidden rounded-lg border border-specter-border">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-specter-border bg-specter-surface">
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Username
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Role
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Created
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Last Login
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredOperators.map((op) => {
                      const createdAt = timestampToDate(op.createdAt)
                      const lastLogin = timestampToDate(op.lastLogin)

                      return (
                        <tr
                          key={op.id}
                          className="border-b border-specter-border transition-colors hover:bg-specter-surface last:border-b-0"
                        >
                          <td className="px-4 py-2.5">
                            <span className="text-xs font-medium text-specter-text font-mono">
                              {op.username}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <RoleBadge role={op.role} />
                          </td>
                          <td className="px-4 py-2.5">
                            <span className="text-xs text-specter-muted">
                              {createdAt ? formatDate(createdAt) : '—'}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className="text-xs text-specter-muted">
                              {lastLogin ? formatRelativeTime(lastLogin) : 'Never'}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Certificates Table */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ShieldCheck className="h-4 w-4 text-specter-muted" />
              <h2 className="text-sm font-medium text-specter-text">Certificates</h2>
              <span className="text-xs text-specter-muted">({filteredCertificates.length})</span>
            </div>

            {filteredCertificates.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-lg border border-specter-border py-10 text-specter-muted">
                <KeyRound className="mb-2 h-8 w-8" />
                <p className="text-sm">No certificates found</p>
              </div>
            ) : (
              <div className="overflow-hidden rounded-lg border border-specter-border">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-specter-border bg-specter-surface">
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Serial
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        CN
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        OU / Role
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Issued
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Expires
                      </th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Status
                      </th>
                      <th className="px-4 py-2 text-right text-[10px] font-medium uppercase tracking-wider text-specter-muted">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredCertificates.map((cert) => {
                      const issuedAt = timestampToDate(cert.issuedAt)
                      const expiresAt = timestampToDate(cert.expiresAt)
                      const isExpired = expiresAt ? expiresAt.getTime() < Date.now() : false

                      return (
                        <tr
                          key={cert.serial}
                          className="border-b border-specter-border transition-colors hover:bg-specter-surface last:border-b-0"
                        >
                          <td className="px-4 py-2.5">
                            <span className="text-xs text-specter-text font-mono">
                              {cert.serial.length > 16
                                ? `${cert.serial.slice(0, 8)}...${cert.serial.slice(-8)}`
                                : cert.serial}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className="text-xs font-medium text-specter-text">
                              {cert.subjectCn}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className="text-xs text-specter-muted">{cert.subjectOu || '—'}</span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className="text-xs text-specter-muted">
                              {issuedAt ? formatDateTime(issuedAt) : '—'}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span
                              className={`text-xs ${isExpired && !cert.revoked ? 'text-specter-danger' : 'text-specter-muted'}`}
                            >
                              {expiresAt ? formatDateTime(expiresAt) : '—'}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <CertStatusBadge revoked={cert.revoked} />
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            {!cert.revoked && (
                              <button
                                onClick={() => handleOpenRevoke(cert)}
                                className="inline-flex items-center gap-1 rounded border border-specter-danger/30 bg-specter-danger/10 px-2 py-1 text-[10px] font-medium text-specter-danger transition-colors hover:bg-specter-danger/20"
                              >
                                <Ban className="h-2.5 w-2.5" />
                                Revoke
                              </button>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {/* Issue Certificate Dialog */}
      {issueCertState && (
        <IssueCertDialog
          state={issueCertState}
          onClose={() => setIssueCertState(null)}
          onFieldChange={handleIssueCertFieldChange}
          onIssue={handleIssueCert}
        />
      )}

      {/* Revoke Confirmation Dialog */}
      {revokeState && (
        <RevokeConfirmDialog
          state={revokeState}
          onClose={() => setRevokeState(null)}
          onConfirm={handleRevoke}
        />
      )}
    </div>
  )
}
