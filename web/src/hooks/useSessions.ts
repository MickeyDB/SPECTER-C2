import { useEffect, useCallback } from 'react'
import { useSessionStore } from '@/store/sessionStore'
import { useGrpcStream } from './useGrpcStream'
import type { Event } from '@/gen/specter/v1/specter_service_pb'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'

export interface UseSessionsOptions {
  /** Auto-refresh interval in ms (0 to disable polling) */
  pollInterval?: number
  /** Whether to subscribe to real-time events */
  realtime?: boolean
}

/**
 * Hook that provides sessions data with auto-refresh and optional real-time updates.
 * Combines polling with gRPC streaming for reliable session state.
 */
export function useSessions(options: UseSessionsOptions = {}) {
  const { pollInterval = 15_000, realtime = true } = options

  const sessions = useSessionStore((s) => s.sessions)
  const loading = useSessionStore((s) => s.loading)
  const error = useSessionStore((s) => s.error)
  const fetchSessions = useSessionStore((s) => s.fetchSessions)
  const updateSession = useSessionStore((s) => s.updateSession)
  const counts = useSessionStore((s) => s.counts)

  // Initial fetch
  useEffect(() => {
    fetchSessions()
  }, [fetchSessions])

  // Polling
  useEffect(() => {
    if (pollInterval <= 0) return
    const interval = setInterval(fetchSessions, pollInterval)
    return () => clearInterval(interval)
  }, [fetchSessions, pollInterval])

  // Real-time updates via gRPC stream
  const handleEvent = useCallback(
    (event: Event) => {
      if (event.event.case === 'sessionEvent' && event.event.value?.session) {
        updateSession(event.event.value.session as SessionInfo)
      }
    },
    [updateSession],
  )

  const { connected } = useGrpcStream({
    enabled: realtime,
    onEvent: handleEvent,
  })

  const refresh = useCallback(() => {
    fetchSessions()
  }, [fetchSessions])

  return {
    sessions,
    loading,
    error,
    refresh,
    counts: counts(),
    connected,
  }
}
