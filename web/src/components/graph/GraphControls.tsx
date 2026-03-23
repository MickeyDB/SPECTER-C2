import { ZoomIn, ZoomOut, Maximize, Download, Pin, RotateCcw } from 'lucide-react'

interface GraphControlsProps {
  onZoomIn: () => void
  onZoomOut: () => void
  onFitView: () => void
  onExportSVG: () => void
  onExportPNG: () => void
  onUnpinAll: () => void
  sessionCount: number
  edgeCount: number
}

function ControlButton({
  onClick,
  title,
  children,
}: {
  onClick: () => void
  title: string
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="flex h-8 w-8 items-center justify-center rounded border border-specter-border bg-specter-surface text-specter-muted transition-colors hover:border-specter-muted hover:text-specter-text"
    >
      {children}
    </button>
  )
}

export function GraphControls({
  onZoomIn,
  onZoomOut,
  onFitView,
  onExportSVG,
  onExportPNG,
  onUnpinAll,
  sessionCount,
  edgeCount,
}: GraphControlsProps) {
  return (
    <div className="absolute bottom-4 left-4 flex flex-col gap-2" data-testid="graph-controls">
      <div className="flex gap-1">
        <ControlButton onClick={onZoomIn} title="Zoom in">
          <ZoomIn className="h-3.5 w-3.5" />
        </ControlButton>
        <ControlButton onClick={onZoomOut} title="Zoom out">
          <ZoomOut className="h-3.5 w-3.5" />
        </ControlButton>
        <ControlButton onClick={onFitView} title="Fit to view">
          <Maximize className="h-3.5 w-3.5" />
        </ControlButton>
        <ControlButton onClick={onUnpinAll} title="Unpin all nodes">
          <RotateCcw className="h-3.5 w-3.5" />
        </ControlButton>
      </div>
      <div className="flex gap-1">
        <ControlButton onClick={onExportSVG} title="Export SVG">
          <Download className="h-3.5 w-3.5" />
        </ControlButton>
        <ControlButton onClick={onExportPNG} title="Export PNG">
          <Pin className="h-3.5 w-3.5" />
        </ControlButton>
      </div>
      <div className="rounded border border-specter-border bg-specter-surface px-2 py-1 text-xs text-specter-muted">
        {sessionCount} nodes · {edgeCount} edges
      </div>
    </div>
  )
}
