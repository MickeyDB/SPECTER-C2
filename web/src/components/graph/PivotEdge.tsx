import type { SessionNodeData } from './SessionNode'

export interface PivotEdgeData {
  id: string
  source: SessionNodeData
  target: SessionNodeData
  linkType: string
  active: boolean
}

export function PivotEdgeSVG({ edge }: { edge: PivotEdgeData }) {
  const sx = edge.source.x ?? 0
  const sy = edge.source.y ?? 0
  const tx = edge.target.x ?? 0
  const ty = edge.target.y ?? 0

  const color = edge.active ? '#10b981' : '#ef4444'
  const midX = (sx + tx) / 2
  const midY = (sy + ty) / 2

  return (
    <g data-testid={`pivot-edge-${edge.id}`}>
      <line
        x1={sx}
        y1={sy}
        x2={tx}
        y2={ty}
        stroke={color}
        strokeWidth={1.5}
        strokeDasharray={edge.active ? undefined : '6 3'}
        strokeOpacity={0.6}
        markerEnd={`url(#arrow-${edge.active ? 'active' : 'dead'})`}
      />
      {/* Link type label */}
      <rect
        x={midX - 20}
        y={midY - 8}
        width={40}
        height={14}
        rx={3}
        fill="#18181b"
        stroke="#27272a"
        strokeWidth={0.5}
      />
      <text
        x={midX}
        y={midY + 3}
        textAnchor="middle"
        fill="#a1a1aa"
        fontSize={8}
        fontFamily="monospace"
      >
        {edge.linkType.length > 6 ? edge.linkType.slice(0, 5) + '.' : edge.linkType}
      </text>
    </g>
  )
}

export function ArrowMarkerDefs() {
  return (
    <defs>
      <marker
        id="arrow-active"
        viewBox="0 0 10 10"
        refX={10}
        refY={5}
        markerWidth={8}
        markerHeight={8}
        orient="auto-start-reverse"
      >
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" fillOpacity={0.6} />
      </marker>
      <marker
        id="arrow-dead"
        viewBox="0 0 10 10"
        refX={10}
        refY={5}
        markerWidth={8}
        markerHeight={8}
        orient="auto-start-reverse"
      >
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" fillOpacity={0.6} />
      </marker>
    </defs>
  )
}
