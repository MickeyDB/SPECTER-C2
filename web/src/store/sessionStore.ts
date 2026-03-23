import { create } from 'zustand'
import type { SessionInfo } from '@/gen/specter/v1/sessions_pb'
import { SessionStatus } from '@/gen/specter/v1/sessions_pb'
import { specterClient } from '@/lib/client'

export interface SessionState {
  /** All sessions */
  sessions: SessionInfo[]
  /** Currently selected session (for interact page) */
  selectedSession: SessionInfo | null
  /** Loading state */
  loading: boolean
  /** Error message */
  error: string | null
  /** Last fetch timestamp */
  lastFetched: number | null

  // Actions
  fetchSessions: () => Promise<void>
  fetchSession: (id: string) => Promise<void>
  setSelectedSession: (session: SessionInfo | null) => void
  updateSession: (session: SessionInfo) => void
  removeSession: (id: string) => void

  // Computed-like getters
  getByStatus: (status: SessionStatus) => SessionInfo[]
  getById: (id: string) => SessionInfo | undefined
  counts: () => { total: number; active: number; stale: number; dead: number; new_: number }
}

export const useSessionStore = create<SessionState>()((set, get) => ({
  sessions: [],
  selectedSession: null,
  loading: false,
  error: null,
  lastFetched: null,

  fetchSessions: async () => {
    set({ loading: true, error: null })
    try {
      const res = await specterClient.listSessions({})
      set({ sessions: res.sessions, loading: false, lastFetched: Date.now() })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch sessions', loading: false })
    }
  },

  fetchSession: async (id: string) => {
    try {
      const res = await specterClient.getSession({ id })
      if (res.session) {
        set({ selectedSession: res.session })
        // Also update in the sessions array
        set((state) => ({
          sessions: state.sessions.map((s) => (s.id === id ? res.session! : s)),
        }))
      }
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to fetch session' })
    }
  },

  setSelectedSession: (session) => set({ selectedSession: session }),

  updateSession: (session) =>
    set((state) => {
      const idx = state.sessions.findIndex((s) => s.id === session.id)
      if (idx >= 0) {
        const sessions = [...state.sessions]
        sessions[idx] = session
        return { sessions }
      }
      return { sessions: [...state.sessions, session] }
    }),

  removeSession: (id) =>
    set((state) => ({
      sessions: state.sessions.filter((s) => s.id !== id),
      selectedSession: state.selectedSession?.id === id ? null : state.selectedSession,
    })),

  getByStatus: (status) => get().sessions.filter((s) => s.status === status),

  getById: (id) => get().sessions.find((s) => s.id === id),

  counts: () => {
    const sessions = get().sessions
    return {
      total: sessions.length,
      active: sessions.filter((s) => s.status === SessionStatus.ACTIVE).length,
      stale: sessions.filter((s) => s.status === SessionStatus.STALE).length,
      dead: sessions.filter((s) => s.status === SessionStatus.DEAD).length,
      new_: sessions.filter((s) => s.status === SessionStatus.NEW).length,
    }
  },
}))
