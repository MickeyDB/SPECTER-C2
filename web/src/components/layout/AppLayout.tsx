import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { ChatWidget } from '@/components/ChatWidget'
import { usePresence } from '@/hooks/usePresence'

export function AppLayout() {
  // Subscribe to presence + chat events from the event stream
  usePresence()

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-specter-bg">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
      <ChatWidget />
    </div>
  )
}
