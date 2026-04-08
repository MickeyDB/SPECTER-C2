import { useState, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Shield, Key, Globe } from 'lucide-react'
import { useAuth } from './useAuth'
import { attemptMtlsAuth } from './mtls'

export function LoginPage() {
  const { loginWithToken, loginWithCert, isAuthenticating, error } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/dashboard'

  const [username, setUsername] = useState('')
  const [token, setToken] = useState('')
  const [mtlsStatus, setMtlsStatus] = useState<'idle' | 'checking' | 'failed'>('idle')

  const handleTokenLogin = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !token.trim()) return
    const ok = await loginWithToken(username, token)
    if (ok) navigate(from, { replace: true })
  }, [username, token, loginWithToken, navigate, from])

  const handleMtlsLogin = useCallback(async () => {
    setMtlsStatus('checking')
    const baseUrl = import.meta.env.DEV ? '' : window.location.origin
    const result = await attemptMtlsAuth(baseUrl)
    if (result.success && result.token && result.username) {
      // mTLS succeeded — store the token directly (no password-based gRPC auth needed)
      const success = await loginWithCert(result.username, result.token)
      if (success) {
        navigate(from, { replace: true })
        return
      }
    }
    setMtlsStatus('failed')
  }, [loginWithToken, navigate, from])

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-specter-bg px-4">
      <div className="w-full max-w-md space-y-8 p-8">
        {/* Header */}
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg border border-specter-border bg-specter-surface">
            <Shield className="h-6 w-6 text-specter-accent" />
          </div>
          <h1 className="text-2xl font-bold text-specter-text">SPECTER</h1>
          <p className="mt-1 text-sm text-specter-muted">Authenticate to access the C2 console</p>
        </div>

        {/* mTLS Auth */}
        <div className="rounded-lg border border-specter-border bg-specter-surface p-4">
          <div className="mb-3 flex items-center gap-2">
            <Key className="h-4 w-4 text-specter-accent" />
            <h3 className="text-sm font-medium text-specter-text">Certificate Authentication</h3>
          </div>
          <p className="mb-3 text-xs text-specter-muted">
            Use your operator client certificate for mutual TLS authentication.
          </p>
          <button
            onClick={handleMtlsLogin}
            disabled={mtlsStatus === 'checking'}
            className="w-full rounded border border-specter-accent/30 bg-specter-accent/10 px-4 py-2 text-sm text-specter-accent transition-colors hover:bg-specter-accent/20 disabled:opacity-50"
          >
            {mtlsStatus === 'checking' ? 'Checking certificate...' : 'Authenticate with Certificate'}
          </button>
          {mtlsStatus === 'failed' && (
            <p className="mt-2 text-xs text-specter-danger">
              Certificate authentication failed. Ensure your client certificate is installed.
            </p>
          )}
        </div>

        {/* Divider */}
        <div className="flex items-center gap-3">
          <div className="h-px flex-1 bg-specter-border" />
          <span className="text-xs text-specter-muted">or</span>
          <div className="h-px flex-1 bg-specter-border" />
        </div>

        {/* Token Auth */}
        <form onSubmit={handleTokenLogin} className="rounded-lg border border-specter-border bg-specter-surface p-4">
          <div className="mb-3 flex items-center gap-2">
            <Globe className="h-4 w-4 text-specter-info" />
            <h3 className="text-sm font-medium text-specter-text">Token Authentication</h3>
          </div>
          <div className="space-y-3">
            <div>
              <label htmlFor="username" className="mb-1 block text-xs text-specter-muted">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-sm text-specter-text placeholder:text-specter-muted/50 focus:border-specter-accent focus:outline-none"
                placeholder="operator"
                autoComplete="username"
              />
            </div>
            <div>
              <label htmlFor="token" className="mb-1 block text-xs text-specter-muted">
                Authentication Token
              </label>
              <input
                id="token"
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                className="w-full rounded border border-specter-border bg-specter-bg px-3 py-2 text-sm text-specter-text placeholder:text-specter-muted/50 focus:border-specter-accent focus:outline-none"
                placeholder="••••••••••••"
                autoComplete="current-password"
              />
            </div>
            <button
              type="submit"
              disabled={isAuthenticating || !username.trim() || !token.trim()}
              className="w-full rounded bg-specter-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-specter-accent/90 disabled:opacity-50"
            >
              {isAuthenticating ? 'Authenticating...' : 'Sign In'}
            </button>
          </div>
        </form>

        {/* Error */}
        {error && (
          <div className="rounded border border-specter-danger/30 bg-specter-danger/10 px-4 py-2 text-sm text-specter-danger">
            {error}
          </div>
        )}
      </div>
    </div>
  )
}
