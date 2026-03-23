import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import * as d3 from 'd3'
import { RefreshCw, X } from 'lucide-react'
import { specterClient } from '@/lib/client'
import { SessionStatus } from '@/gen/specter/v1/sessions_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'
import { SessionNodeSVG, NODE_WIDTH, NODE_HEIGHT } from '@/components/graph/SessionNode'
import type { SessionNodeData } from '@/components/graph/SessionNode'
import { PivotEdgeSVG, ArrowMarkerDefs } from '@/components/graph/PivotEdge'
import type { PivotEdgeData } from '@/components/graph/PivotEdge'
import { GraphControls } from '@/components/graph/GraphControls'

// ── Helpers ────────────────────────────────────────────────────────────

function getSubnet(ip: string): string {
  const parts = ip.split('.')
  if (parts.length === 4) return parts.slice(0, 3).join('.')
  return ip
}

function buildGraphData(
  sessions: SessionInfo[]
): { nodes: SessionNodeData[]; edges: PivotEdgeData[] } {
  // Build nodes first so edges can reference them
  const nodes: SessionNodeData[] = sessions.map((s) => ({
    id: s.id,
    hostname: s.hostname,
    username: s.username,
    status: s.status,
    pivotCount: 0,
    internalIp: s.internalIp,
    externalIp: s.externalIp,
    pid: s.pid,
    osVersion: s.osVersion,
    integrityLevel: s.integrityLevel,
    processName: s.processName,
  }))

  const nodeMap = new Map<string, SessionNodeData>()
  for (const n of nodes) nodeMap.set(n.id, n)

  const edgeSet = new Set<string>()
  const edges: PivotEdgeData[] = []

  // Subnet edges
  const subnetMap = new Map<string, SessionInfo[]>()
  for (const s of sessions) {
    if (s.internalIp) {
      const subnet = getSubnet(s.internalIp)
      const group = subnetMap.get(subnet) ?? []
      group.push(s)
      subnetMap.set(subnet, group)
    }
  }

  for (const [, group] of subnetMap) {
    if (group.length < 2) continue
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const a = group[i]
        const b = group[j]
        const edgeId = [a.id, b.id].sort().join('::')
        if (edgeSet.has(edgeId)) continue
        edgeSet.add(edgeId)

        const srcNode = nodeMap.get(a.id)
        const tgtNode = nodeMap.get(b.id)
        if (!srcNode || !tgtNode) continue

        srcNode.pivotCount++
        tgtNode.pivotCount++
        edges.push({
          id: edgeId,
          source: srcNode,
          target: tgtNode,
          linkType: 'subnet',
          active: a.status !== SessionStatus.DEAD && b.status !== SessionStatus.DEAD,
        })
      }
    }
  }

  // External IP (channel) edges
  const extIpMap = new Map<string, SessionInfo[]>()
  for (const s of sessions) {
    if (s.externalIp) {
      const group = extIpMap.get(s.externalIp) ?? []
      group.push(s)
      extIpMap.set(s.externalIp, group)
    }
  }

  for (const [, group] of extIpMap) {
    if (group.length < 2) continue
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const a = group[i]
        const b = group[j]
        const edgeId = [a.id, b.id].sort().join('::')
        if (edgeSet.has(edgeId)) continue
        edgeSet.add(edgeId)

        const srcNode = nodeMap.get(a.id)
        const tgtNode = nodeMap.get(b.id)
        if (!srcNode || !tgtNode) continue

        srcNode.pivotCount++
        tgtNode.pivotCount++
        edges.push({
          id: edgeId,
          source: srcNode,
          target: tgtNode,
          linkType: 'channel',
          active: a.status !== SessionStatus.DEAD && b.status !== SessionStatus.DEAD,
        })
      }
    }
  }

  return { nodes, edges }
}

const STATUS_LABEL: Record<number, string> = {
  0: 'Unknown',
  1: 'New',
  2: 'Active',
  3: 'Stale',
  4: 'Dead',
}

const STATUS_DOT_CLASS: Record<number, string> = {
  1: 'bg-status-new',
  2: 'bg-status-active',
  3: 'bg-status-stale',
  4: 'bg-status-dead',
}

// ── SessionMap Page ───────────────────────────────────────────────────

export function SessionMap() {
  const navigate = useNavigate()
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const simulationRef = useRef<d3.Simulation<SessionNodeData, PivotEdgeData> | null>(null)
  const transformRef = useRef<d3.ZoomTransform>(d3.zoomIdentity)

  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedNode, setSelectedNode] = useState<SessionNodeData | null>(null)
  const [, setTick] = useState(0) // force re-render on simulation tick

  const { nodes, edges } = useMemo(() => buildGraphData(sessions), [sessions])

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await specterClient.listSessions({})
      setSessions(res.sessions)
    } catch {
      setError('Unable to connect to teamserver')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSessions()
    const interval = setInterval(fetchSessions, 15_000)
    return () => clearInterval(interval)
  }, [fetchSessions])

  // D3 force simulation
  useEffect(() => {
    if (nodes.length === 0) return

    const sim = d3
      .forceSimulation<SessionNodeData>(nodes)
      .force(
        'link',
        d3
          .forceLink<SessionNodeData, PivotEdgeData>(edges)
          .id((d) => d.id)
          .distance(200)
      )
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(0, 0))
      .force('collision', d3.forceCollide(NODE_WIDTH / 2 + 20))
      .alphaDecay(0.02)
      .on('tick', () => {
        setTick((t) => t + 1)
      })

    simulationRef.current = sim

    return () => {
      sim.stop()
    }
  }, [nodes, edges])

  // D3 zoom behavior
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        transformRef.current = event.transform
        setTick((t) => t + 1)
      })

    d3.select(svg).call(zoom)

    return () => {
      d3.select(svg).on('.zoom', null)
    }
  }, [])

  // ── Drag handler ──────────────────────────────────────────────────
  const dragState = useRef<{
    node: SessionNodeData
    startX: number
    startY: number
    offsetX: number
    offsetY: number
  } | null>(null)

  const handleNodeMouseDown = useCallback(
    (node: SessionNodeData, e: React.MouseEvent) => {
      e.stopPropagation()
      const t = transformRef.current
      dragState.current = {
        node,
        startX: e.clientX,
        startY: e.clientY,
        offsetX: (node.x ?? 0) * t.k + t.x,
        offsetY: (node.y ?? 0) * t.k + t.y,
      }

      node.fx = node.x
      node.fy = node.y
      simulationRef.current?.alphaTarget(0.3).restart()

      const handleMouseMove = (ev: MouseEvent) => {
        if (!dragState.current) return
        const t = transformRef.current
        const dx = ev.clientX - dragState.current.startX
        const dy = ev.clientY - dragState.current.startY
        dragState.current.node.fx =
          (dragState.current.offsetX + dx - t.x) / t.k
        dragState.current.node.fy =
          (dragState.current.offsetY + dy - t.y) / t.k
      }

      const handleMouseUp = () => {
        if (dragState.current) {
          const n = dragState.current.node
          if (!n.pinned) {
            n.fx = null
            n.fy = null
          }
          dragState.current = null
          simulationRef.current?.alphaTarget(0)
        }
        window.removeEventListener('mousemove', handleMouseMove)
        window.removeEventListener('mouseup', handleMouseUp)
      }

      window.addEventListener('mousemove', handleMouseMove)
      window.addEventListener('mouseup', handleMouseUp)
    },
    []
  )

  const handleNodeClick = useCallback(
    (node: SessionNodeData, e: React.MouseEvent) => {
      e.stopPropagation()
      setSelectedNode((prev) => (prev?.id === node.id ? null : node))
    },
    []
  )

  const handleNodeDoubleClick = useCallback(
    (node: SessionNodeData, e: React.MouseEvent) => {
      e.stopPropagation()
      navigate(`/sessions/${node.id}`)
    },
    [navigate]
  )

  const handlePinToggle = useCallback((node: SessionNodeData) => {
    node.pinned = !node.pinned
    if (node.pinned) {
      node.fx = node.x
      node.fy = node.y
    } else {
      node.fx = null
      node.fy = null
    }
    setTick((t) => t + 1)
  }, [])

  // ── Controls ──────────────────────────────────────────────────────
  const handleZoomIn = useCallback(() => {
    const svg = svgRef.current
    if (!svg) return
    d3.select(svg).transition().duration(300).call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      1.5
    )
  }, [])

  const handleZoomOut = useCallback(() => {
    const svg = svgRef.current
    if (!svg) return
    d3.select(svg).transition().duration(300).call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      0.67
    )
  }, [])

  const handleFitView = useCallback(() => {
    const svg = svgRef.current
    if (!svg || nodes.length === 0) return

    const padding = 60
    const bbox = {
      minX: Math.min(...nodes.map((n) => (n.x ?? 0) - NODE_WIDTH / 2)),
      maxX: Math.max(...nodes.map((n) => (n.x ?? 0) + NODE_WIDTH / 2)),
      minY: Math.min(...nodes.map((n) => (n.y ?? 0) - NODE_HEIGHT / 2)),
      maxY: Math.max(...nodes.map((n) => (n.y ?? 0) + NODE_HEIGHT / 2)),
    }

    const svgRect = svg.getBoundingClientRect()
    const w = bbox.maxX - bbox.minX + padding * 2
    const h = bbox.maxY - bbox.minY + padding * 2
    const scale = Math.min(svgRect.width / w, svgRect.height / h, 2)
    const cx = (bbox.minX + bbox.maxX) / 2
    const cy = (bbox.minY + bbox.maxY) / 2

    const transform = d3.zoomIdentity
      .translate(svgRect.width / 2, svgRect.height / 2)
      .scale(scale)
      .translate(-cx, -cy)

    d3.select(svg)
      .transition()
      .duration(500)
      .call(d3.zoom<SVGSVGElement, unknown>().transform as any, transform) // eslint-disable-line @typescript-eslint/no-explicit-any
  }, [nodes])

  const handleUnpinAll = useCallback(() => {
    for (const n of nodes) {
      n.pinned = false
      n.fx = null
      n.fy = null
    }
    simulationRef.current?.alpha(0.5).restart()
  }, [nodes])

  const handleExportSVG = useCallback(() => {
    const svg = svgRef.current
    if (!svg) return
    const clone = svg.cloneNode(true) as SVGSVGElement
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
    const blob = new Blob([clone.outerHTML], { type: 'image/svg+xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'session-map.svg'
    a.click()
    URL.revokeObjectURL(url)
  }, [])

  const handleExportPNG = useCallback(() => {
    const svg = svgRef.current
    if (!svg) return
    const clone = svg.cloneNode(true) as SVGSVGElement
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
    const svgData = new XMLSerializer().serializeToString(clone)
    const canvas = document.createElement('canvas')
    const rect = svg.getBoundingClientRect()
    canvas.width = rect.width * 2
    canvas.height = rect.height * 2
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.scale(2, 2)
    const img = new Image()
    img.onload = () => {
      ctx.fillStyle = '#09090b'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.drawImage(img, 0, 0, rect.width, rect.height)
      const a = document.createElement('a')
      a.href = canvas.toDataURL('image/png')
      a.download = 'session-map.png'
      a.click()
    }
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)))
  }, [])

  const t = transformRef.current

  return (
    <div className="flex h-full flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-specter-text">Session Map</h1>
          <p className="text-xs text-specter-muted">
            Interactive network graph — click to inspect, double-click to interact, drag to rearrange
          </p>
        </div>
        <button
          onClick={fetchSessions}
          disabled={loading}
          className="flex items-center gap-1.5 rounded border border-specter-border bg-specter-surface px-3 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text disabled:opacity-50"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-lg border border-specter-danger/30 bg-specter-danger/10 px-4 py-3 text-sm text-specter-danger">
          {error}
        </div>
      )}

      {/* Graph Container */}
      <div
        ref={containerRef}
        className="relative flex-1 overflow-hidden rounded-lg border border-specter-border bg-specter-surface"
      >
        {sessions.length === 0 && !loading ? (
          <div className="flex h-full items-center justify-center text-sm text-specter-muted">
            No sessions available
          </div>
        ) : (
          <>
            <svg
              ref={svgRef}
              className="h-full w-full"
              data-testid="session-map-svg"
            >
              <ArrowMarkerDefs />
              <g transform={`translate(${t.x}, ${t.y}) scale(${t.k})`}>
                {/* Edges */}
                {edges.map((edge) => (
                  <PivotEdgeSVG key={edge.id} edge={edge} />
                ))}
                {/* Nodes */}
                {nodes.map((node) => (
                  <SessionNodeSVG
                    key={node.id}
                    node={node}
                    onMouseDown={(e) => handleNodeMouseDown(node, e)}
                    onClick={(e) => handleNodeClick(node, e)}
                    onDoubleClick={(e) => handleNodeDoubleClick(node, e)}
                  />
                ))}
              </g>
            </svg>

            <GraphControls
              onZoomIn={handleZoomIn}
              onZoomOut={handleZoomOut}
              onFitView={handleFitView}
              onExportSVG={handleExportSVG}
              onExportPNG={handleExportPNG}
              onUnpinAll={handleUnpinAll}
              sessionCount={nodes.length}
              edgeCount={edges.length}
            />
          </>
        )}

        {/* Details Popup */}
        {selectedNode && (
          <div
            className="absolute right-4 top-4 w-72 rounded-lg border border-specter-border bg-specter-surface shadow-xl"
            data-testid="node-details-popup"
          >
            <div className="flex items-center justify-between border-b border-specter-border px-4 py-3">
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${STATUS_DOT_CLASS[selectedNode.status] ?? 'bg-specter-muted'}`}
                />
                <h3 className="text-sm font-medium text-specter-text">
                  {selectedNode.hostname}
                </h3>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-specter-muted hover:text-specter-text"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
            <div className="space-y-2 px-4 py-3 text-xs">
              <DetailRow label="Status" value={STATUS_LABEL[selectedNode.status] ?? 'Unknown'} />
              <DetailRow label="Username" value={selectedNode.username} />
              <DetailRow label="PID" value={String(selectedNode.pid)} />
              <DetailRow label="Process" value={selectedNode.processName} />
              <DetailRow label="OS" value={selectedNode.osVersion} />
              <DetailRow label="Integrity" value={selectedNode.integrityLevel} />
              <DetailRow label="Internal IP" value={selectedNode.internalIp || 'N/A'} />
              <DetailRow label="External IP" value={selectedNode.externalIp || 'N/A'} />
              <DetailRow label="Pivots" value={String(selectedNode.pivotCount)} />
            </div>
            <div className="border-t border-specter-border px-4 py-2.5">
              <div className="flex gap-2">
                <button
                  onClick={() => handlePinToggle(selectedNode)}
                  className="flex-1 rounded border border-specter-border px-2 py-1.5 text-xs text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text"
                >
                  {selectedNode.pinned ? 'Unpin' : 'Pin'}
                </button>
                <button
                  onClick={() => navigate(`/sessions/${selectedNode.id}`)}
                  className="flex-1 rounded bg-specter-accent px-2 py-1.5 text-xs font-medium text-white transition-colors hover:bg-specter-accent/80"
                >
                  Interact
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-specter-muted">{label}</span>
      <span className="text-specter-text">{value}</span>
    </div>
  )
}
