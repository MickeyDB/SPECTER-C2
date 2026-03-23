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
import { Redirectors } from '@/pages/Redirectors'
import { PayloadBuilder } from '@/pages/PayloadBuilder'
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
            <Route path="builder" element={<PayloadBuilder />} />
            <Route path="redirectors" element={<Redirectors />} />
            <Route path="reports" element={<Reports />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
