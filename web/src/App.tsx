import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from '@/auth/AuthProvider'
import { ProtectedRoute } from '@/auth/ProtectedRoute'
import { LoginPage } from '@/auth/LoginPage'
import { AppLayout } from '@/components/layout/AppLayout'

const Dashboard = lazy(() => import('@/pages/Dashboard').then(({ Dashboard }) => ({ default: Dashboard })))
const Sessions = lazy(() => import('@/pages/Sessions').then(({ Sessions }) => ({ default: Sessions })))
const SessionInteract = lazy(() =>
  import('@/pages/SessionInteract').then(({ SessionInteract }) => ({ default: SessionInteract })),
)
const SessionMap = lazy(() => import('@/pages/SessionMap').then(({ SessionMap }) => ({ default: SessionMap })))
const TaskTimeline = lazy(() =>
  import('@/pages/TaskTimeline').then(({ TaskTimeline }) => ({ default: TaskTimeline })),
)
const Modules = lazy(() => import('@/pages/Modules').then(({ Modules }) => ({ default: Modules })))
const ProfileEditor = lazy(() =>
  import('@/pages/ProfileEditor').then(({ ProfileEditor }) => ({ default: ProfileEditor })),
)
const Listeners = lazy(() => import('@/pages/Listeners').then(({ Listeners }) => ({ default: Listeners })))
const Redirectors = lazy(() => import('@/pages/Redirectors').then(({ Redirectors }) => ({ default: Redirectors })))
const PayloadBuilder = lazy(() =>
  import('@/pages/PayloadBuilder').then(({ PayloadBuilder }) => ({ default: PayloadBuilder })),
)
const Operators = lazy(() => import('@/pages/Operators').then(({ Operators }) => ({ default: Operators })))
const Campaigns = lazy(() => import('@/pages/Campaigns').then(({ Campaigns }) => ({ default: Campaigns })))
const Webhooks = lazy(() => import('@/pages/Webhooks').then(({ Webhooks }) => ({ default: Webhooks })))
const AzureDeadDrop = lazy(() =>
  import('@/pages/AzureDeadDrop').then(({ AzureDeadDrop }) => ({ default: AzureDeadDrop })),
)
const Reports = lazy(() => import('@/pages/Reports').then(({ Reports }) => ({ default: Reports })))
const OperationLogs = lazy(() =>
  import('@/pages/OperationLogs').then(({ OperationLogs }) => ({ default: OperationLogs })),
)

function RouteFallback() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-specter-bg text-xs text-specter-muted">
      Loading...
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter basename="/ui">
      <AuthProvider>
        <Suspense fallback={<RouteFallback />}>
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
              <Route path="logs" element={<OperationLogs />} />
            </Route>
          </Routes>
        </Suspense>
      </AuthProvider>
    </BrowserRouter>
  )
}
