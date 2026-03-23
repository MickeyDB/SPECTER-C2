import { createGrpcWebTransport } from '@connectrpc/connect-web'

/**
 * gRPC-Web transport for communicating with the SPECTER teamserver.
 * In development, Vite proxies /specter.v1 to the teamserver.
 * In production, the teamserver serves the UI at /ui/ and handles gRPC-Web directly.
 *
 * Uses gRPC-Web protocol (not Connect) to match the server's tonic-web layer.
 */
export const transport = createGrpcWebTransport({
  baseUrl: import.meta.env.DEV ? '' : window.location.origin,
})
