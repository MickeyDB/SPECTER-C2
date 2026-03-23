import type { SessionStatus } from '@/gen/specter/v1/sessions_pb'

export interface SessionNodeData {
  id: string
  hostname: string
  username: string
  status: SessionStatus
  pivotCount: number
  internalIp: string
  externalIp: string
  pid: number
  osVersion: string
  integrityLevel: string
  processName: string
  x?: number
  y?: number
  fx?: number | null
  fy?: number | null
  pinned?: boolean
}

const STATUS_COLORS: Record<number, { fill: string; stroke: string; text: string }> = {
  1: { fill: '#1e3a5f', stroke: '#3b82f6', text: '#93c5fd' }, // NEW - blue
  2: { fill: '#064e3b', stroke: '#10b981', text: '#6ee7b7' }, // ACTIVE - emerald
  3: { fill: '#451a03', stroke: '#f59e0b', text: '#fcd34d' }, // STALE - amber
  4: { fill: '#450a0a', stroke: '#ef4444', text: '#fca5a5' }, // DEAD - red
}

const DEFAULT_COLORS = { fill: '#27272a', stroke: '#52525b', text: '#a1a1aa' }

export const NODE_WIDTH = 160
export const NODE_HEIGHT = 50

export function SessionNodeSVG({
  node,
  onMouseDown,
  onClick,
  onDoubleClick,
}: {
  node: SessionNodeData
  onMouseDown?: (e: React.MouseEvent) => void
  onClick?: (e: React.MouseEvent) => void
  onDoubleClick?: (e: React.MouseEvent) => void
}) {
  const colors = STATUS_COLORS[node.status] ?? DEFAULT_COLORS
  const baseSize = NODE_WIDTH + Math.min(node.pivotCount * 10, 40)
  const w = baseSize
  const h = NODE_HEIGHT

  return (
    <g
      transform={`translate(${(node.x ?? 0) - w / 2}, ${(node.y ?? 0) - h / 2})`}
      onMouseDown={onMouseDown}
      onClick={onClick}
      onDoubleClick={onDoubleClick}
      style={{ cursor: 'pointer' }}
      data-testid={`session-node-${node.id}`}
    >
      {/* Background rect */}
      <rect
        width={w}
        height={h}
        rx={8}
        ry={8}
        fill={colors.fill}
        stroke={colors.stroke}
        strokeWidth={node.pinned ? 2.5 : 1.5}
        strokeDasharray={node.pinned ? '4 2' : undefined}
      />
      {/* Status dot */}
      <circle cx={14} cy={h / 2} r={4} fill={colors.stroke} />
      {/* Hostname */}
      <text
        x={26}
        y={h / 2 - 6}
        fill={colors.text}
        fontSize={11}
        fontFamily="monospace"
        fontWeight={600}
      >
        {node.hostname.length > 16 ? node.hostname.slice(0, 14) + '..' : node.hostname}
      </text>
      {/* Username */}
      <text
        x={26}
        y={h / 2 + 10}
        fill="#a1a1aa"
        fontSize={9}
        fontFamily="monospace"
      >
        {node.username.length > 18 ? node.username.slice(0, 16) + '..' : node.username}
      </text>
      {/* Pivot count badge */}
      {node.pivotCount > 0 && (
        <g transform={`translate(${w - 20}, 4)`}>
          <rect width={16} height={14} rx={3} fill={colors.stroke} opacity={0.8} />
          <text
            x={8}
            y={11}
            fill="#fff"
            fontSize={8}
            fontFamily="monospace"
            textAnchor="middle"
          >
            {node.pivotCount}
          </text>
        </g>
      )}
    </g>
  )
}
