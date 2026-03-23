import { createGrpcWebTransport } from '@connectrpc/connect-web'
import type { Interceptor } from '@connectrpc/connect'
import { useAuthStore } from '@/store/authStore'

/**
 * Interceptor that attaches the bearer token from the auth store
 * to every outgoing gRPC-Web request.
 */
const authInterceptor: Interceptor = (next) => async (req) => {
  const token = useAuthStore.getState().authToken
  if (token) {
    req.header.set('Authorization', `Bearer ${token}`)
  }
  return next(req)
}

/**
 * gRPC-Web transport for communicating with the SPECTER teamserver.
 * In development, Vite proxies /specter.v1 to the teamserver.
 * In production, the teamserver serves the UI at /ui/ and handles gRPC-Web directly.
 *
 * Uses gRPC-Web protocol (not Connect) to match the server's tonic-web layer.
 */
export const transport = createGrpcWebTransport({
  baseUrl: import.meta.env.DEV ? '' : window.location.origin,
  interceptors: [authInterceptor],
})
