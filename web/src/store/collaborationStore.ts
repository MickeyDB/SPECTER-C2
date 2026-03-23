import { create } from 'zustand'
import type {
  PresenceInfo,
  ChatMessage,
} from '@/gen/specter/v1/collaboration_pb'
import { OperatorStatus } from '@/gen/specter/v1/collaboration_pb'

export interface CollaborationState {
  /** Connected operators with presence info */
  operators: PresenceInfo[]
  /** Chat messages (global channel) */
  chatMessages: ChatMessage[]
  /** Whether the chat widget is open */
  chatOpen: boolean
  /** Unread message count (since last close) */
  unreadCount: number

  // Actions
  setOperators: (operators: PresenceInfo[]) => void
  updateOperator: (presence: PresenceInfo) => void
  removeOperator: (operatorId: string) => void
  addChatMessage: (message: ChatMessage) => void
  setChatMessages: (messages: ChatMessage[]) => void
  toggleChat: () => void
  setChatOpen: (open: boolean) => void
  resetUnread: () => void

  // Computed-like
  onlineCount: () => number
  getOperatorForSession: (sessionId: string) => PresenceInfo | undefined
}

export const useCollaborationStore = create<CollaborationState>()((set, get) => ({
  operators: [],
  chatMessages: [],
  chatOpen: false,
  unreadCount: 0,

  setOperators: (operators) => set({ operators }),

  updateOperator: (presence) =>
    set((state) => {
      const idx = state.operators.findIndex(
        (op) => op.operatorId === presence.operatorId,
      )
      if (presence.status === OperatorStatus.OFFLINE) {
        return {
          operators: state.operators.filter(
            (op) => op.operatorId !== presence.operatorId,
          ),
        }
      }
      if (idx >= 0) {
        const operators = [...state.operators]
        operators[idx] = presence
        return { operators }
      }
      return { operators: [...state.operators, presence] }
    }),

  removeOperator: (operatorId) =>
    set((state) => ({
      operators: state.operators.filter((op) => op.operatorId !== operatorId),
    })),

  addChatMessage: (message) =>
    set((state) => ({
      chatMessages: [...state.chatMessages, message],
      unreadCount: state.chatOpen ? state.unreadCount : state.unreadCount + 1,
    })),

  setChatMessages: (messages) => set({ chatMessages: messages }),

  toggleChat: () =>
    set((state) => ({
      chatOpen: !state.chatOpen,
      unreadCount: !state.chatOpen ? 0 : state.unreadCount,
    })),

  setChatOpen: (open) =>
    set({ chatOpen: open, unreadCount: open ? 0 : get().unreadCount }),

  resetUnread: () => set({ unreadCount: 0 }),

  onlineCount: () =>
    get().operators.filter(
      (op) =>
        op.status === OperatorStatus.ONLINE ||
        op.status === OperatorStatus.IDLE,
    ).length,

  getOperatorForSession: (sessionId) =>
    get().operators.find((op) => op.activeSessionId === sessionId),
}))
