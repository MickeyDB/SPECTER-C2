import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

// Register service worker for offline support
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/ui/sw.js')
      .then((registration) => {
        // Sync queued tasks when back online
        window.addEventListener('online', () => {
          registration.active?.postMessage({ type: 'SYNC_TASKS' })
        })
      })
      .catch(() => {
        // SW registration failed — app works without it
      })
  })
}
