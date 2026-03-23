import { useEffect, useCallback } from 'react'
import { useTaskStore } from '@/store/taskStore'
import { useGrpcStream } from './useGrpcStream'
import type { Event } from '@/gen/specter/v1/specter_service_pb'
import type { Task } from '@/gen/specter/v1/tasks_pb'

export interface UseTaskResultsOptions {
  /** Session ID to filter tasks by */
  sessionId?: string
  /** Auto-refresh interval in ms (0 to disable) */
  pollInterval?: number
  /** Whether to subscribe to real-time events */
  realtime?: boolean
}

/**
 * Hook that provides task data with auto-refresh and optional real-time updates.
 */
export function useTaskResults(options: UseTaskResultsOptions = {}) {
  const { sessionId, pollInterval = 10_000, realtime = true } = options

  const tasksBySession = useTaskStore((s) => s.tasksBySession)
  const loading = useTaskStore((s) => s.loading)
  const error = useTaskStore((s) => s.error)
  const fetchTasks = useTaskStore((s) => s.fetchTasks)
  const updateTask = useTaskStore((s) => s.updateTask)
  const queueTask = useTaskStore((s) => s.queueTask)

  const tasks = sessionId ? (tasksBySession[sessionId] ?? []) : Object.values(tasksBySession).flat()

  // Initial fetch
  useEffect(() => {
    if (sessionId) fetchTasks(sessionId)
  }, [sessionId, fetchTasks])

  // Polling
  useEffect(() => {
    if (!sessionId || pollInterval <= 0) return
    const interval = setInterval(() => fetchTasks(sessionId), pollInterval)
    return () => clearInterval(interval)
  }, [sessionId, fetchTasks, pollInterval])

  // Real-time updates
  const handleEvent = useCallback(
    (event: Event) => {
      if (event.event.case === 'taskEvent' && event.event.value?.task) {
        const task = event.event.value.task as Task
        if (!sessionId || task.sessionId === sessionId) {
          updateTask(task)
        }
      }
    },
    [sessionId, updateTask],
  )

  const { connected } = useGrpcStream({
    enabled: realtime,
    onEvent: handleEvent,
  })

  const refresh = useCallback(() => {
    if (sessionId) fetchTasks(sessionId)
  }, [sessionId, fetchTasks])

  const submitTask = useCallback(
    async (taskType: string, args: string, operatorId = '') => {
      if (!sessionId) return null
      return queueTask(sessionId, taskType, args, operatorId)
    },
    [sessionId, queueTask],
  )

  return {
    tasks,
    loading,
    error,
    refresh,
    submitTask,
    connected,
  }
}
