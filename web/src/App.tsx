import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from '@/auth/AuthProvider'
import { ProtectedRoute } from '@/auth/ProtectedRoute'
import { LoginPage } from '@/auth/LoginPage'
import { AppLayout } from '@/components/layout/AppLayout'
import { Dashboard } from '@/pages/Dashboard'
import { Sessions } from '@/pages/Sessions'
import { SessionInteract } from '@/pages/SessionInteract'
import { SessionMap } from '@/pages/SessionMap'
import { TaskTimeline } from '@/pages/TaskTimeline'
import { Modules } from '@/pages/Modules'
import { ProfileEditor } from '@/pages/ProfileEditor'
import { Listeners } from '@/pages/Listeners'
import { Redirectors } from '@/pages/Redirectors'
import { PayloadBuilder } from '@/pages/PayloadBuilder'
import { Operators } from '@/pages/Operators'
import { Campaigns } from '@/pages/Campaigns'
import { Webhooks } from '@/pages/Webhooks'
import { AzureDeadDrop } from '@/pages/AzureDeadDrop'
import { Reports } from '@/pages/Reports'

export default function App() {
  return (
    <BrowserRouter basename="/ui">
      <AuthProvider>
        <Routes>
          <Route path="login" element={<LoginPage />} />
          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="sessions" element={<Sessions />} />
            <Route path="sessions/:id" element={<SessionInteract />} />
            <Route path="map" element={<SessionMap />} />
            <Route path="tasks" element={<TaskTimeline />} />
            <Route path="modules" element={<Modules />} />
            <Route path="profiles" element={<ProfileEditor />} />
            <Route path="listeners" element={<Listeners />} />
            <Route path="builder" element={<PayloadBuilder />} />
            <Route path="redirectors" element={<Redirectors />} />
            <Route path="operators" element={<Operators />} />
            <Route path="campaigns" element={<Campaigns />} />
            <Route path="webhooks" element={<Webhooks />} />
            <Route path="azure-deaddrop" element={<AzureDeadDrop />} />
            <Route path="reports" element={<Reports />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
