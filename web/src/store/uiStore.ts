import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
  timestamp: number
  read: boolean
}

export interface UiState {
  /** Sidebar collapsed state */
  sidebarCollapsed: boolean
  /** Notifications list */
  notifications: Notification[]
  /** Whether notification panel is open */
  notificationPanelOpen: boolean
  /** Command palette open state */
  commandPaletteOpen: boolean
  /** Active page for breadcrumb tracking */
  activePage: string

  // Actions
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void

  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void
  markNotificationRead: (id: string) => void
  markAllRead: () => void
  clearNotifications: () => void
  removeNotification: (id: string) => void

  toggleNotificationPanel: () => void
  setNotificationPanelOpen: (open: boolean) => void
  toggleCommandPalette: () => void
  setActivePage: (page: string) => void

  // Getters
  unreadCount: () => number
}

let notifCounter = 0

export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      sidebarCollapsed: false,
      notifications: [],
      notificationPanelOpen: false,
      commandPaletteOpen: false,
      activePage: 'dashboard',

      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

      addNotification: (notif) => {
        const id = `notif-${Date.now()}-${++notifCounter}`
        set((state) => ({
          notifications: [
            { ...notif, id, timestamp: Date.now(), read: false },
            ...state.notifications,
          ].slice(0, 100), // Keep last 100
        }))
      },

      markNotificationRead: (id) =>
        set((state) => ({
          notifications: state.notifications.map((n) =>
            n.id === id ? { ...n, read: true } : n,
          ),
        })),

      markAllRead: () =>
        set((state) => ({
          notifications: state.notifications.map((n) => ({ ...n, read: true })),
        })),

      clearNotifications: () => set({ notifications: [] }),

      removeNotification: (id) =>
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        })),

      toggleNotificationPanel: () =>
        set((state) => ({ notificationPanelOpen: !state.notificationPanelOpen })),

      setNotificationPanelOpen: (open) => set({ notificationPanelOpen: open }),
      toggleCommandPalette: () =>
        set((state) => ({ commandPaletteOpen: !state.commandPaletteOpen })),
      setActivePage: (page) => set({ activePage: page }),

      unreadCount: () => get().notifications.filter((n) => !n.read).length,
    }),
    {
      name: 'specter-ui',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
      }),
    },
  ),
)
