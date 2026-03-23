/**
 * mTLS authentication via browser client certificates.
 *
 * When the teamserver requires client certificates (mTLS), the browser
 * automatically presents a cert selection dialog. This module detects
 * whether a client cert is available and extracts operator identity.
 */

export interface MtlsCertInfo {
  /** Certificate subject CN — maps to operator username */
  commonName: string
  /** Certificate issuer (should be SPECTER CA) */
  issuer: string
  /** Expiry date */
  notAfter: Date
}

/**
 * Attempt mTLS authentication by calling the teamserver's authenticate
 * endpoint. The browser handles cert selection automatically when the
 * server requests a client certificate during TLS handshake.
 *
 * Returns true if the server accepted the client cert (HTTP 200).
 * Returns false if auth failed or no cert was presented.
 */
export interface MtlsAuthResult {
  success: boolean
  token?: string
  username?: string
}

export async function attemptMtlsAuth(baseUrl: string): Promise<MtlsAuthResult> {
  try {
    const res = await fetch(`${baseUrl}/auth/mtls`, {
      method: 'POST',
      credentials: 'include',
    })
    if (!res.ok) return { success: false }
    const data = await res.json()
    return { success: true, token: data.token, username: data.username }
  } catch {
    return { success: false }
  }
}

/**
 * Check if the current connection uses a client certificate.
 * This is a best-effort detection — browsers don't expose cert details
 * to JavaScript directly. We rely on the server echoing back cert info.
 */
export async function getMtlsCertInfo(baseUrl: string): Promise<MtlsCertInfo | null> {
  try {
    const res = await fetch(`${baseUrl}/auth/mtls/info`, {
      credentials: 'include',
    })
    if (!res.ok) return null
    const data = await res.json()
    return {
      commonName: data.common_name ?? '',
      issuer: data.issuer ?? '',
      notAfter: new Date(data.not_after ?? 0),
    }
  } catch {
    return null
  }
}
