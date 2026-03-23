import { useCallback } from 'react'
import { useUiStore } from '@/store/uiStore'
import type { Notification } from '@/store/uiStore'
import { useGrpcStream } from './useGrpcStream'
import type { Event } from '@/gen/specter/v1/specter_service_pb'

export interface UseNotificationsOptions {
  /** Whether to subscribe to real-time events for auto-notifications */
  realtime?: boolean
}

/**
 * Hook for managing operator notifications.
 * Can auto-generate notifications from gRPC event stream.
 */
export function useNotifications(options: UseNotificationsOptions = {}) {
  const { realtime = false } = options

  const notifications = useUiStore((s) => s.notifications)
  const addNotification = useUiStore((s) => s.addNotification)
  const markNotificationRead = useUiStore((s) => s.markNotificationRead)
  const markAllRead = useUiStore((s) => s.markAllRead)
  const clearNotifications = useUiStore((s) => s.clearNotifications)
  const removeNotification = useUiStore((s) => s.removeNotification)
  const unreadCount = useUiStore((s) => s.unreadCount)

  const notify = useCallback(
    (type: Notification['type'], title: string, message?: string) => {
      addNotification({ type, title, message })
    },
    [addNotification],
  )

  // Auto-generate notifications from gRPC events
  const handleEvent = useCallback(
    (event: Event) => {
      if (event.event.case === 'sessionEvent') {
        const sessionEvent = event.event.value
        const hostname = sessionEvent?.session?.hostname ?? 'Unknown'
        const eventType = sessionEvent?.eventType ?? 'update'

        if (eventType === 'new' || eventType === 'created') {
          addNotification({
            type: 'info',
            title: 'New Session',
            message: `${hostname} checked in`,
          })
        } else if (eventType === 'dead' || eventType === 'lost') {
          addNotification({
            type: 'warning',
            title: 'Session Lost',
            message: `${hostname} is no longer responding`,
          })
        }
      } else if (event.event.case === 'taskEvent') {
        const taskEvent = event.event.value
        const taskType = taskEvent?.task?.taskType ?? 'unknown'
        const eventType = taskEvent?.eventType ?? 'update'

        if (eventType === 'completed') {
          addNotification({
            type: 'success',
            title: 'Task Complete',
            message: `${taskType} finished successfully`,
          })
        } else if (eventType === 'failed') {
          addNotification({
            type: 'error',
            title: 'Task Failed',
            message: `${taskType} execution failed`,
          })
        }
      }
    },
    [addNotification],
  )

  useGrpcStream({
    enabled: realtime,
    onEvent: handleEvent,
  })

  return {
    notifications,
    unreadCount: unreadCount(),
    notify,
    markRead: markNotificationRead,
    markAllRead,
    clear: clearNotifications,
    remove: removeNotification,
  }
}
