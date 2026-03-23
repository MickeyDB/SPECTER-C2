import { create } from 'zustand'
import type { Task } from '@/gen/specter/v1/tasks_pb'
import { TaskStatus, TaskPriority } from '@/gen/specter/v1/tasks_pb'
import { specterClient } from '@/lib/client'

export interface TaskState {
  /** Tasks indexed by session ID */
  tasksBySession: Record<string, Task[]>
  /** All tasks (flattened) */
  allTasks: Task[]
  /** Loading state */
  loading: boolean
  /** Error message */
  error: string | null

  // Actions
  fetchTasks: (sessionId: string) => Promise<void>
  fetchAllTasks: () => Promise<void>
  queueTask: (sessionId: string, taskType: string, args: string, operatorId: string) => Promise<string | null>
  updateTask: (task: Task) => void
  getTaskResult: (taskId: string) => Promise<Task | null>

  // Getters
  getBySession: (sessionId: string) => Task[]
  getByStatus: (status: TaskStatus) => Task[]
}

export const useTaskStore = create<TaskState>()((set, get) => ({
  tasksBySession: {},
  allTasks: [],
  loading: false,
  error: null,

  fetchTasks: async (sessionId: string) => {
    set({ loading: true, error: null })
    try {
      const res = await specterClient.listTasks({ sessionId })
      set((state) => ({
        tasksBySession: { ...state.tasksBySession, [sessionId]: res.tasks },
        loading: false,
      }))
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch tasks', loading: false })
    }
  },

  fetchAllTasks: async () => {
    set({ loading: true, error: null })
    try {
      // Fetch tasks for all known sessions by fetching with empty session ID
      const res = await specterClient.listTasks({ sessionId: '' })
      set({ allTasks: res.tasks, loading: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch tasks', loading: false })
    }
  },

  queueTask: async (sessionId, taskType, args, operatorId) => {
    try {
      const encoder = new TextEncoder()
      const res = await specterClient.queueTask({
        sessionId,
        taskType,
        arguments: encoder.encode(args),
        priority: TaskPriority.NORMAL,
        operatorId,
      })
      // Add the new task to the store
      if (res.task) {
        set((state) => {
          const existing = state.tasksBySession[sessionId] ?? []
          return {
            tasksBySession: {
              ...state.tasksBySession,
              [sessionId]: [res.task!, ...existing],
            },
          }
        })
      }
      return res.taskId
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to queue task' })
      return null
    }
  },

  updateTask: (task) =>
    set((state) => {
      const sessionTasks = state.tasksBySession[task.sessionId] ?? []
      const idx = sessionTasks.findIndex((t) => t.id === task.id)
      const updated = idx >= 0
        ? sessionTasks.map((t) => (t.id === task.id ? task : t))
        : [task, ...sessionTasks]
      return {
        tasksBySession: { ...state.tasksBySession, [task.sessionId]: updated },
      }
    }),

  getTaskResult: async (taskId: string) => {
    try {
      const res = await specterClient.getTaskResult({ taskId })
      return res.task ?? null
    } catch {
      return null
    }
  },

  getBySession: (sessionId) => get().tasksBySession[sessionId] ?? [],

  getByStatus: (status) =>
    Object.values(get().tasksBySession)
      .flat()
      .filter((t) => t.status === status),
}))
