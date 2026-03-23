/**
 * SPECTER C2 Lambda@Edge — Viewer Request Filter
 *
 * Inspects CloudFront viewer requests against the C2 profile.
 * Matching requests pass through to the origin (teamserver).
 * Non-matching requests receive a decoy 404 response.
 *
 * Profile ID: ${profile_id}
 */

'use strict';

const URI_REGEX   = new RegExp("${uri_pattern}");
const HDR_NAME    = "${header_name}".toLowerCase();
const HDR_REGEX   = new RegExp("${header_pattern}");
const DECOY_BODY  = `${decoy_response}`;

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const uri     = request.uri;

  // Check URI pattern
  if (!URI_REGEX.test(uri)) {
    return decoyResponse();
  }

  // Check required header
  const headers = request.headers;
  const hdrValues = headers[HDR_NAME];
  if (!hdrValues || hdrValues.length === 0 || !HDR_REGEX.test(hdrValues[0].value)) {
    return decoyResponse();
  }

  // Allow request through to origin
  return request;
};

function decoyResponse() {
  return {
    status: '404',
    statusDescription: 'Not Found',
    headers: {
      'content-type': [{
        key: 'Content-Type',
        value: 'text/html; charset=utf-8',
      }],
      'cache-control': [{
        key: 'Cache-Control',
        value: 'no-store',
      }],
    },
    body: DECOY_BODY,
  };
}
