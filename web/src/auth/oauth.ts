/**
 * OAuth2/OIDC authentication with PKCE (Proof Key for Code Exchange).
 *
 * This provides a fallback authentication mechanism when mTLS is not
 * available (e.g., browser without client certs configured).
 */

/** Generate a cryptographically random string for PKCE */
function generateRandomString(length: number): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(36).padStart(2, '0')).join('').slice(0, length)
}

/** Generate PKCE code verifier (43-128 chars, RFC 7636) */
export function generateCodeVerifier(): string {
  return generateRandomString(64)
}

/** Generate PKCE code challenge from verifier (S256 method) */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

export interface OAuthConfig {
  /** Authorization endpoint URL */
  authorizationUrl: string
  /** Token endpoint URL */
  tokenUrl: string
  /** Client ID */
  clientId: string
  /** Redirect URI (typically /ui/auth/callback) */
  redirectUri: string
  /** Scopes to request */
  scopes: string[]
}

export interface OAuthTokens {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  tokenType: string
  idToken?: string
}

const PKCE_VERIFIER_KEY = 'specter_pkce_verifier'
const OAUTH_STATE_KEY = 'specter_oauth_state'

/**
 * Initiate OAuth2 PKCE authorization flow.
 * Redirects the browser to the authorization server.
 */
export async function startOAuthFlow(config: OAuthConfig): Promise<void> {
  const verifier = generateCodeVerifier()
  const challenge = await generateCodeChallenge(verifier)
  const state = generateRandomString(32)

  // Store verifier and state for the callback
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier)
  sessionStorage.setItem(OAUTH_STATE_KEY, state)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })

  window.location.href = `${config.authorizationUrl}?${params.toString()}`
}

/**
 * Handle the OAuth2 callback. Exchanges the authorization code for tokens.
 * Returns null if the callback is invalid (state mismatch, missing code, etc).
 */
export async function handleOAuthCallback(
  config: OAuthConfig,
  callbackUrl: string,
): Promise<OAuthTokens | null> {
  const url = new URL(callbackUrl)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const error = url.searchParams.get('error')

  if (error) {
    console.error('OAuth error:', error, url.searchParams.get('error_description'))
    return null
  }

  if (!code || !state) return null

  // Verify state
  const savedState = sessionStorage.getItem(OAUTH_STATE_KEY)
  if (state !== savedState) {
    console.error('OAuth state mismatch')
    return null
  }

  // Get stored verifier
  const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY)
  if (!verifier) {
    console.error('Missing PKCE verifier')
    return null
  }

  // Clean up session storage
  sessionStorage.removeItem(PKCE_VERIFIER_KEY)
  sessionStorage.removeItem(OAUTH_STATE_KEY)

  // Exchange code for tokens
  try {
    const res = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.redirectUri,
        client_id: config.clientId,
        code_verifier: verifier,
      }),
    })

    if (!res.ok) return null

    const data = await res.json()
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in,
      tokenType: data.token_type,
      idToken: data.id_token,
    }
  } catch {
    return null
  }
}

/**
 * Refresh an expired access token using the refresh token.
 */
export async function refreshAccessToken(
  config: OAuthConfig,
  refreshToken: string,
): Promise<OAuthTokens | null> {
  try {
    const res = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: config.clientId,
      }),
    })

    if (!res.ok) return null

    const data = await res.json()
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? refreshToken,
      expiresIn: data.expires_in,
      tokenType: data.token_type,
      idToken: data.id_token,
    }
  } catch {
    return null
  }
}
