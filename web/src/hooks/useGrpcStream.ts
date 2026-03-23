import { useEffect, useRef, useCallback, useState } from 'react'
import { specterClient } from '@/lib/client'
import type { Event } from '@/gen/specter/v1/specter_service_pb'

export interface UseGrpcStreamOptions {
  /** Whether the stream should be active */
  enabled?: boolean
  /** Callback for each event received */
  onEvent?: (event: Event) => void
  /** Callback when the stream encounters an error */
  onError?: (error: Error) => void
  /** Callback when the stream is connected */
  onConnect?: () => void
  /** Auto-reconnect delay in ms (0 to disable) */
  reconnectDelay?: number
}

export interface UseGrpcStreamResult {
  /** Whether the stream is currently connected */
  connected: boolean
  /** Last error encountered */
  error: Error | null
  /** Manually disconnect the stream */
  disconnect: () => void
  /** Manually reconnect the stream */
  reconnect: () => void
}

/**
 * Hook for subscribing to the gRPC SubscribeEvents server-streaming RPC.
 * Automatically reconnects on disconnection.
 */
export function useGrpcStream(options: UseGrpcStreamOptions = {}): UseGrpcStreamResult {
  const {
    enabled = true,
    onEvent,
    onError,
    onConnect,
    reconnectDelay = 5000,
  } = options

  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const cleanup = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    setConnected(false)
  }, [])

  const connect = useCallback(async () => {
    cleanup()

    if (!enabled) return

    const controller = new AbortController()
    abortRef.current = controller

    try {
      const stream = specterClient.subscribeEvents(
        {},
        { signal: controller.signal },
      )

      setConnected(true)
      setError(null)
      onConnect?.()

      for await (const event of stream) {
        if (controller.signal.aborted) break
        onEvent?.(event)
      }
    } catch (err) {
      if (controller.signal.aborted) return // Expected on disconnect

      const streamError = err instanceof Error ? err : new Error('Stream disconnected')
      setError(streamError)
      onError?.(streamError)
    } finally {
      setConnected(false)

      // Auto-reconnect if enabled and not manually aborted
      if (!controller.signal.aborted && enabled && reconnectDelay > 0) {
        reconnectTimeoutRef.current = setTimeout(connect, reconnectDelay)
      }
    }
  }, [enabled, onEvent, onError, onConnect, reconnectDelay, cleanup])

  useEffect(() => {
    if (enabled) connect()
    return cleanup
  }, [enabled, connect, cleanup])

  const disconnect = useCallback(() => {
    cleanup()
  }, [cleanup])

  const reconnect = useCallback(() => {
    cleanup()
    connect()
  }, [cleanup, connect])

  return { connected, error, disconnect, reconnect }
}
