import { useState, useEffect, useCallback } from 'react'
import {
  FileText,
  Download,
  RefreshCw,
  Plus,
  Eye,
  Clock,
  User,
  ChevronDown,
  X,
} from 'lucide-react'
import { specterClient } from '@/lib/client'
import { create } from '@bufbuild/protobuf'
import {
  GenerateReportRequestSchema,
  ReportFormatProto,
  ReportIncludeSectionsSchema,
} from '@/gen/specter/v1/reports_pb'
import type { ReportInfo } from '@/gen/specter/v1/reports_pb'
import type { CampaignInfo } from '@/gen/specter/v1/campaigns_pb'

// ── Helpers ────────────────────────────────────────────────────────────

function formatTimestamp(seconds: bigint | undefined): string {
  if (seconds === undefined) return 'N/A'
  const d = new Date(Number(seconds) * 1000)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

// ── Report Preview Modal ──────────────────────────────────────────────

function ReportPreviewModal({
  report,
  onClose,
}: {
  report: ReportInfo
  onClose: () => void
}) {
  function handleDownload() {
    const ext = report.format === 'json' ? 'json' : 'md'
    const blob = new Blob([report.content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `specter-report-${report.campaignName.replace(/\s+/g, '-')}-${report.id.slice(0, 8)}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-specter-surface border border-specter-border rounded-lg w-[90vw] max-w-5xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-specter-border">
          <div>
            <h2 className="text-lg font-semibold text-specter-text">
              Report: {report.campaignName}
            </h2>
            <p className="text-xs text-specter-muted mt-0.5">
              {report.format.toUpperCase()} &middot; Created{' '}
              {formatTimestamp(report.createdAt?.seconds)} by {report.createdBy}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded bg-specter-accent/10 text-specter-accent hover:bg-specter-accent/20 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Download .{report.format === 'json' ? 'json' : 'md'}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded text-specter-muted hover:text-specter-text hover:bg-specter-border/50 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          <pre className="whitespace-pre-wrap text-sm text-specter-text font-mono leading-relaxed">
            {report.content}
          </pre>
        </div>
      </div>
    </div>
  )
}

// ── Generate Report Wizard ────────────────────────────────────────────

function GenerateWizard({
  campaigns,
  onGenerate,
  onCancel,
  generating,
}: {
  campaigns: CampaignInfo[]
  onGenerate: (req: {
    campaignId: string
    format: ReportFormatProto
    timeline: boolean
    iocList: boolean
    findings: boolean
    recommendations: boolean
    operatorFilter: string
  }) => void
  onCancel: () => void
  generating: boolean
}) {
  const [campaignId, setCampaignId] = useState('')
  const [format, setFormat] = useState<ReportFormatProto>(
    ReportFormatProto.REPORT_FORMAT_MARKDOWN
  )
  const [timeline, setTimeline] = useState(true)
  const [iocList, setIocList] = useState(true)
  const [findings, setFindings] = useState(true)
  const [recommendations, setRecommendations] = useState(true)
  const [operatorFilter, setOperatorFilter] = useState('')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-specter-surface border border-specter-border rounded-lg w-[480px] max-h-[80vh] overflow-auto">
        <div className="px-6 py-4 border-b border-specter-border">
          <h2 className="text-lg font-semibold text-specter-text">
            Generate Report
          </h2>
          <p className="text-xs text-specter-muted mt-1">
            Create an engagement report from campaign data
          </p>
        </div>

        <div className="px-6 py-4 space-y-4">
          {/* Campaign */}
          <div>
            <label className="block text-xs font-medium text-specter-muted mb-1">
              Campaign
            </label>
            <div className="relative">
              <select
                value={campaignId}
                onChange={(e) => setCampaignId(e.target.value)}
                className="w-full bg-specter-bg border border-specter-border rounded px-3 py-2 text-sm text-specter-text appearance-none cursor-pointer"
              >
                <option value="">Select a campaign...</option>
                {campaigns.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-2.5 w-4 h-4 text-specter-muted pointer-events-none" />
            </div>
          </div>

          {/* Format */}
          <div>
            <label className="block text-xs font-medium text-specter-muted mb-1">
              Output Format
            </label>
            <div className="flex gap-2">
              <button
                onClick={() =>
                  setFormat(ReportFormatProto.REPORT_FORMAT_MARKDOWN)
                }
                className={`flex-1 px-3 py-2 rounded text-sm border transition-colors ${
                  format === ReportFormatProto.REPORT_FORMAT_MARKDOWN
                    ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                    : 'border-specter-border text-specter-muted hover:text-specter-text'
                }`}
              >
                Markdown
              </button>
              <button
                onClick={() =>
                  setFormat(ReportFormatProto.REPORT_FORMAT_JSON)
                }
                className={`flex-1 px-3 py-2 rounded text-sm border transition-colors ${
                  format === ReportFormatProto.REPORT_FORMAT_JSON
                    ? 'border-specter-accent bg-specter-accent/10 text-specter-accent'
                    : 'border-specter-border text-specter-muted hover:text-specter-text'
                }`}
              >
                JSON
              </button>
            </div>
          </div>

          {/* Sections */}
          <div>
            <label className="block text-xs font-medium text-specter-muted mb-2">
              Include Sections
            </label>
            <div className="space-y-2">
              {[
                { label: 'Timeline of Actions', checked: timeline, set: setTimeline },
                { label: 'IOC List', checked: iocList, set: setIocList },
                { label: 'Findings', checked: findings, set: setFindings },
                { label: 'Recommendations', checked: recommendations, set: setRecommendations },
              ].map(({ label, checked, set }) => (
                <label
                  key={label}
                  className="flex items-center gap-2 text-sm text-specter-text cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) => set(e.target.checked)}
                    className="accent-specter-accent"
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>

          {/* Operator filter */}
          <div>
            <label className="block text-xs font-medium text-specter-muted mb-1">
              Operator Filter (optional)
            </label>
            <input
              type="text"
              value={operatorFilter}
              onChange={(e) => setOperatorFilter(e.target.value)}
              placeholder="Filter by operator ID..."
              className="w-full bg-specter-bg border border-specter-border rounded px-3 py-2 text-sm text-specter-text placeholder:text-specter-muted/50"
            />
          </div>
        </div>

        {/* Actions */}
        <div className="px-6 py-4 border-t border-specter-border flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm rounded border border-specter-border text-specter-muted hover:text-specter-text transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() =>
              onGenerate({
                campaignId,
                format,
                timeline,
                iocList,
                findings,
                recommendations,
                operatorFilter,
              })
            }
            disabled={!campaignId || generating}
            className="px-4 py-2 text-sm rounded bg-specter-accent text-white hover:bg-specter-accent/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
          >
            {generating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileText className="w-3.5 h-3.5" />
                Generate
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Reports Page ─────────────────────────────────────────────────

export function Reports() {
  const [reports, setReports] = useState<ReportInfo[]>([])
  const [campaigns, setCampaigns] = useState<CampaignInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [showWizard, setShowWizard] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [previewReport, setPreviewReport] = useState<ReportInfo | null>(null)
  const [error, setError] = useState<string | null>(null)

  const fetchReports = useCallback(async () => {
    try {
      const res = await specterClient.listReports({})
      setReports(res.reports)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch reports'
      setError(msg)
    }
  }, [])

  const fetchCampaigns = useCallback(async () => {
    try {
      const res = await specterClient.listCampaigns({})
      setCampaigns(res.campaigns)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch campaigns'
      setError(msg)
    }
  }, [])

  useEffect(() => {
    Promise.all([fetchReports(), fetchCampaigns()]).finally(() =>
      setLoading(false)
    )
  }, [fetchReports, fetchCampaigns])

  async function handleGenerate(req: {
    campaignId: string
    format: ReportFormatProto
    timeline: boolean
    iocList: boolean
    findings: boolean
    recommendations: boolean
    operatorFilter: string
  }) {
    setGenerating(true)
    setError(null)
    try {
      const sections = create(ReportIncludeSectionsSchema, {
        timeline: req.timeline,
        iocList: req.iocList,
        findings: req.findings,
        recommendations: req.recommendations,
      })

      const request = create(GenerateReportRequestSchema, {
        campaignId: req.campaignId,
        format: req.format,
        includeSections: sections,
        operatorFilter: req.operatorFilter,
      })

      const res = await specterClient.generateReport(request)
      if (res.report) {
        setReports((prev) => [res.report!, ...prev])
        setShowWizard(false)
        setPreviewReport(res.report)
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to generate report'
      setError(msg)
    } finally {
      setGenerating(false)
    }
  }

  async function handlePreview(reportId: string) {
    try {
      const res = await specterClient.getReport({ id: reportId })
      if (res.report) {
        setPreviewReport(res.report)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch report'
      setError(msg)
    }
  }

  function handleDownload(report: ReportInfo) {
    const ext = report.format === 'json' ? 'json' : 'md'
    const blob = new Blob([report.content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `specter-report-${report.campaignName.replace(/\s+/g, '-')}-${report.id.slice(0, 8)}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <RefreshCw className="w-5 h-5 animate-spin text-specter-muted" />
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 p-6 gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-specter-text">Reports</h1>
          <p className="text-sm text-specter-muted mt-0.5">
            Generate and manage engagement reports
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setLoading(true)
              fetchReports().finally(() => setLoading(false))
            }}
            className="p-2 rounded border border-specter-border text-specter-muted hover:text-specter-text transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-1.5 px-4 py-2 text-sm rounded bg-specter-accent text-white hover:bg-specter-accent/80 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Generate Report
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="px-4 py-3 rounded bg-specter-danger/10 border border-specter-danger/30 text-specter-danger text-sm">
          {error}
        </div>
      )}

      {/* Reports List */}
      {reports.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-specter-muted">
          <FileText className="w-12 h-12 mb-3 opacity-30" />
          <p className="text-sm">No reports generated yet</p>
          <p className="text-xs mt-1">
            Click "Generate Report" to create your first engagement report
          </p>
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-specter-bg">
              <tr className="border-b border-specter-border text-left text-xs text-specter-muted">
                <th className="px-4 py-2 font-medium">Campaign</th>
                <th className="px-4 py-2 font-medium">Format</th>
                <th className="px-4 py-2 font-medium">Created</th>
                <th className="px-4 py-2 font-medium">Created By</th>
                <th className="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr
                  key={report.id}
                  className="border-b border-specter-border/50 hover:bg-specter-surface/50 transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <FileText className="w-4 h-4 text-specter-accent shrink-0" />
                      <span className="text-specter-text font-medium">
                        {report.campaignName}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-xs bg-specter-border/50 text-specter-muted">
                      {report.format.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-specter-muted">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5" />
                      {formatTimestamp(report.createdAt?.seconds)}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-specter-muted">
                    <div className="flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5" />
                      {report.createdBy}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => handlePreview(report.id)}
                        className="p-1.5 rounded text-specter-muted hover:text-specter-text hover:bg-specter-border/50 transition-colors"
                        title="Preview"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDownload(report)}
                        className="p-1.5 rounded text-specter-muted hover:text-specter-text hover:bg-specter-border/50 transition-colors"
                        title="Download"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals */}
      {showWizard && (
        <GenerateWizard
          campaigns={campaigns}
          onGenerate={handleGenerate}
          onCancel={() => setShowWizard(false)}
          generating={generating}
        />
      )}

      {previewReport && (
        <ReportPreviewModal
          report={previewReport}
          onClose={() => setPreviewReport(null)}
        />
      )}
    </div>
  )
}
