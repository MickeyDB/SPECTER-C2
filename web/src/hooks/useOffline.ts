import { useState, useEffect, useCallback, useRef } from 'react'
import { useUiStore } from '@/store/uiStore'

export interface OfflineState {
  /** Whether the browser is currently online */
  isOnline: boolean
  /** Number of tasks queued while offline (from last sync) */
  queuedTaskCount: number
}

/**
 * Hook that tracks online/offline state, listens for service worker
 * sync messages, and fires toast notifications on connection changes.
 */
export function useOffline(): OfflineState {
  const [isOnline, setIsOnline] = useState(navigator.onLine)
  const [queuedTaskCount, setQueuedTaskCount] = useState(0)
  const addNotification = useUiStore((s) => s.addNotification)
  const wasOnlineRef = useRef(navigator.onLine)

  const handleOnline = useCallback(() => {
    setIsOnline(true)

    // Only notify if we were previously offline
    if (!wasOnlineRef.current) {
      // Trigger SW sync
      navigator.serviceWorker?.ready.then((registration) => {
        registration.active?.postMessage({ type: 'SYNC_TASKS' })
      })

      addNotification({
        type: 'success',
        title: 'Connection Restored',
        message: queuedTaskCount > 0
          ? `${queuedTaskCount} queued task${queuedTaskCount === 1 ? '' : 's'} sent.`
          : 'Teamserver connection is back online.',
      })
    }

    wasOnlineRef.current = true
  }, [addNotification, queuedTaskCount])

  const handleOffline = useCallback(() => {
    setIsOnline(false)
    wasOnlineRef.current = false

    addNotification({
      type: 'warning',
      title: 'Connection Lost',
      message: 'Tasks will be queued and sent when connection is restored.',
    })
  }, [addNotification])

  // Listen for SW sync completion messages
  const handleSwMessage = useCallback(
    (event: MessageEvent) => {
      if (event.data?.type === 'SYNC_COMPLETE') {
        const { total, synced } = event.data as { total: number; synced: number }
        setQueuedTaskCount(0)

        if (total > 0) {
          addNotification({
            type: synced === total ? 'success' : 'warning',
            title: 'Task Sync Complete',
            message: `${synced}/${total} queued task${total === 1 ? '' : 's'} synced.`,
          })
        }
      }
    },
    [addNotification],
  )

  useEffect(() => {
    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)
    navigator.serviceWorker?.addEventListener('message', handleSwMessage)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
      navigator.serviceWorker?.removeEventListener('message', handleSwMessage)
    }
  }, [handleOnline, handleOffline, handleSwMessage])

  return { isOnline, queuedTaskCount }
}
