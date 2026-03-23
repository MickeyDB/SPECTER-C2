use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::SqlitePool;
use thiserror::Error;
use tokio::sync::broadcast;

use super::SpecterEvent;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("webhook not found: {0}")]
    NotFound(String),

    #[error("HTTP error: {0}")]
    Http(String),
}

/// Webhook payload format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookFormat {
    GenericJSON,
    Slack,
    SiemCef,
}

impl WebhookFormat {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "Slack" => Self::Slack,
            "SIEM-CEF" | "SiemCef" => Self::SiemCef,
            _ => Self::GenericJSON,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GenericJSON => "GenericJSON",
            Self::Slack => "Slack",
            Self::SiemCef => "SIEM-CEF",
        }
    }

    pub fn from_proto(v: i32) -> Self {
        match v {
            2 => Self::Slack,
            3 => Self::SiemCef,
            _ => Self::GenericJSON,
        }
    }

    pub fn to_proto(&self) -> i32 {
        match self {
            Self::GenericJSON => 1,
            Self::Slack => 2,
            Self::SiemCef => 3,
        }
    }
}

/// A configured webhook endpoint.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub secret: String,
    pub event_filters: Vec<String>,
    pub format: WebhookFormat,
    pub enabled: bool,
    pub created_at: i64,
}

/// Row type for sqlx deserialization.
#[derive(sqlx::FromRow)]
struct WebhookRow {
    id: String,
    name: String,
    url: String,
    secret: String,
    event_filters: String,
    format: String,
    enabled: i32,
    created_at: i64,
}

impl From<WebhookRow> for WebhookConfig {
    fn from(row: WebhookRow) -> Self {
        let filters: Vec<String> = serde_json::from_str(&row.event_filters).unwrap_or_default();
        Self {
            id: row.id,
            name: row.name,
            url: row.url,
            secret: row.secret,
            event_filters: filters,
            format: WebhookFormat::from_str(&row.format),
            enabled: row.enabled != 0,
            created_at: row.created_at,
        }
    }
}

/// Manages webhook endpoints, subscribes to the event bus, and delivers payloads.
pub struct WebhookManager {
    pool: SqlitePool,
    http_client: reqwest::Client,
}

impl WebhookManager {
    pub fn new(pool: SqlitePool) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { pool, http_client }
    }

    /// Create a new webhook endpoint.
    pub async fn create_webhook(
        &self,
        name: &str,
        url: &str,
        secret: &str,
        event_filters: &[String],
        format: WebhookFormat,
    ) -> Result<WebhookConfig, WebhookError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let filters_json = serde_json::to_string(event_filters).unwrap_or_else(|_| "[]".into());

        sqlx::query(
            "INSERT INTO webhooks (id, name, url, secret, event_filters, format, enabled, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(url)
        .bind(secret)
        .bind(&filters_json)
        .bind(format.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(WebhookConfig {
            id,
            name: name.to_string(),
            url: url.to_string(),
            secret: secret.to_string(),
            event_filters: event_filters.to_vec(),
            format,
            enabled: true,
            created_at: now,
        })
    }

    /// List all webhooks.
    pub async fn list_webhooks(&self) -> Result<Vec<WebhookConfig>, WebhookError> {
        let rows = sqlx::query_as::<_, WebhookRow>(
            "SELECT id, name, url, secret, event_filters, format, enabled, created_at FROM webhooks",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Delete a webhook by ID.
    pub async fn delete_webhook(&self, id: &str) -> Result<(), WebhookError> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(WebhookError::NotFound(id.to_string()));
        }
        Ok(())
    }

    /// Get a single webhook by ID.
    pub async fn get_webhook(&self, id: &str) -> Result<WebhookConfig, WebhookError> {
        let row = sqlx::query_as::<_, WebhookRow>(
            "SELECT id, name, url, secret, event_filters, format, enabled, created_at FROM webhooks WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| WebhookError::NotFound(id.to_string()))?;

        Ok(row.into())
    }

    /// Send a test event to a specific webhook.
    pub async fn test_webhook(&self, id: &str) -> Result<String, WebhookError> {
        let webhook = self.get_webhook(id).await?;
        let test_payload = serde_json::json!({
            "event_type": "test",
            "message": "SPECTER webhook test event",
            "timestamp": Utc::now().to_rfc3339(),
        });

        let body = format_payload(&webhook, &test_payload);
        self.deliver(&webhook, &body).await
    }

    /// Start the background event forwarding loop. Subscribes to the event bus
    /// and delivers matching events to all enabled webhooks.
    pub fn start_forwarding(self: &Arc<Self>, mut event_rx: broadcast::Receiver<SpecterEvent>) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        let event_type = event_type_name(&event);
                        let payload = event_to_json(&event);

                        // Load current webhook configs from DB each time
                        // (ensures config changes are picked up without restart)
                        let webhooks = match manager.list_webhooks().await {
                            Ok(w) => w,
                            Err(e) => {
                                tracing::error!("Failed to load webhooks: {e}");
                                continue;
                            }
                        };

                        for webhook in &webhooks {
                            if !webhook.enabled {
                                continue;
                            }

                            // Check event filters (empty = all events)
                            if !webhook.event_filters.is_empty()
                                && !webhook.event_filters.iter().any(|f| f == &event_type)
                            {
                                continue;
                            }

                            let body = format_payload(webhook, &payload);
                            let manager = Arc::clone(&manager);
                            let webhook = webhook.clone();
                            tokio::spawn(async move {
                                if let Err(e) = manager.deliver_with_retry(&webhook, &body).await {
                                    tracing::warn!(
                                        "Webhook delivery failed for '{}': {e}",
                                        webhook.name
                                    );
                                }
                            });
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Webhook subscriber lagged, skipped {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    /// Deliver a payload to a webhook with 3 retries and exponential backoff.
    async fn deliver_with_retry(
        &self,
        webhook: &WebhookConfig,
        body: &str,
    ) -> Result<String, WebhookError> {
        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                let delay = Duration::from_millis(500 * 2u64.pow(attempt));
                tokio::time::sleep(delay).await;
            }
            match self.deliver(webhook, body).await {
                Ok(status) => return Ok(status),
                Err(e) => {
                    tracing::debug!("Webhook '{}' attempt {}: {e}", webhook.name, attempt + 1);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| WebhookError::Http("unknown error".into())))
    }

    /// Deliver a single HTTP POST to the webhook endpoint.
    async fn deliver(&self, webhook: &WebhookConfig, body: &str) -> Result<String, WebhookError> {
        let mut request = self
            .http_client
            .post(&webhook.url)
            .header("Content-Type", content_type_for_format(webhook.format))
            .header("User-Agent", "SPECTER-Webhook/1.0")
            .body(body.to_string());

        // Sign with HMAC-SHA256 if secret is provided
        if !webhook.secret.is_empty() {
            let signature = compute_hmac(&webhook.secret, body);
            request = request.header("X-Signature", signature);
        }

        let response = request
            .send()
            .await
            .map_err(|e| WebhookError::Http(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            Ok(format!("{status}"))
        } else {
            Err(WebhookError::Http(format!("HTTP {status}")))
        }
    }
}

/// Compute HMAC-SHA256 signature for a payload.
fn compute_hmac(secret: &str, payload: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Get the content type header for a webhook format.
fn content_type_for_format(format: WebhookFormat) -> &'static str {
    match format {
        WebhookFormat::GenericJSON | WebhookFormat::Slack => "application/json",
        WebhookFormat::SiemCef => "text/plain",
    }
}

/// Format an event payload according to the webhook's format.
fn format_payload(webhook: &WebhookConfig, payload: &serde_json::Value) -> String {
    match webhook.format {
        WebhookFormat::GenericJSON => {
            serde_json::to_string(payload).unwrap_or_else(|_| "{}".into())
        }
        WebhookFormat::Slack => {
            let event_type = payload
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let details = payload
                .get("details")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let message = payload
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or(&details);

            let slack_payload = serde_json::json!({
                "text": format!("*[SPECTER]* `{event_type}` — {message}"),
                "username": "SPECTER C2",
            });
            serde_json::to_string(&slack_payload).unwrap_or_else(|_| "{}".into())
        }
        WebhookFormat::SiemCef => {
            let event_type = payload
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let timestamp = payload
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let severity = match event_type {
                "session_new" | "session_lost" => "7",
                "task_failed" => "5",
                _ => "3",
            };

            format!(
                "CEF:0|SPECTER|C2|1.0|{event_type}|{event_type}|{severity}|rt={timestamp} msg={}",
                payload
                    .get("details")
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            )
        }
    }
}

/// Convert a SpecterEvent variant to an event type name string.
fn event_type_name(event: &SpecterEvent) -> String {
    match event {
        SpecterEvent::SessionNew(_) => "session_new".into(),
        SpecterEvent::SessionCheckin(_) => "session_checkin".into(),
        SpecterEvent::SessionLost(_) => "session_lost".into(),
        SpecterEvent::TaskQueued(_) => "task_queued".into(),
        SpecterEvent::TaskComplete(_) => "task_complete".into(),
        SpecterEvent::TaskFailed(_) => "task_failed".into(),
        SpecterEvent::PresenceUpdate(_) => "presence_update".into(),
        SpecterEvent::ChatMessage(_) => "chat_message".into(),
        SpecterEvent::Generic { .. } => "generic".into(),
    }
}

/// Convert a SpecterEvent to a JSON payload for webhook delivery.
fn event_to_json(event: &SpecterEvent) -> serde_json::Value {
    match event {
        SpecterEvent::SessionNew(e)
        | SpecterEvent::SessionCheckin(e)
        | SpecterEvent::SessionLost(e) => {
            let session_info = e.session.as_ref().map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "hostname": s.hostname,
                    "username": s.username,
                    "pid": s.pid,
                    "os_version": s.os_version,
                    "status": s.status,
                })
            });
            serde_json::json!({
                "event_type": event_type_name(event),
                "timestamp": Utc::now().to_rfc3339(),
                "details": session_info,
            })
        }
        SpecterEvent::TaskQueued(e)
        | SpecterEvent::TaskComplete(e)
        | SpecterEvent::TaskFailed(e) => {
            let task_info = e.task.as_ref().map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "session_id": t.session_id,
                    "task_type": t.task_type,
                    "status": t.status,
                })
            });
            serde_json::json!({
                "event_type": event_type_name(event),
                "timestamp": Utc::now().to_rfc3339(),
                "details": task_info,
            })
        }
        SpecterEvent::PresenceUpdate(ref p) => {
            let presence = p.presence.as_ref().map(|pr| {
                serde_json::json!({
                    "operator_id": pr.operator_id,
                    "username": pr.username,
                    "status": pr.status,
                    "active_session_id": pr.active_session_id,
                })
            });
            serde_json::json!({
                "event_type": event_type_name(event),
                "timestamp": Utc::now().to_rfc3339(),
                "details": presence,
            })
        }
        SpecterEvent::ChatMessage(ref m) => {
            serde_json::json!({
                "event_type": "chat_message",
                "timestamp": Utc::now().to_rfc3339(),
                "details": {
                    "id": m.id,
                    "sender_id": m.sender_id,
                    "sender_username": m.sender_username,
                    "content": m.content,
                    "channel": m.channel,
                },
            })
        }
        SpecterEvent::Generic { ref message } => {
            serde_json::json!({
                "event_type": "generic",
                "timestamp": Utc::now().to_rfc3339(),
                "details": { "message": message },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        crate::db::migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_create_and_list_webhooks() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        let wh = manager
            .create_webhook(
                "test-hook",
                "https://example.com/hook",
                "secret123",
                &["session_new".into(), "task_complete".into()],
                WebhookFormat::GenericJSON,
            )
            .await
            .unwrap();

        assert_eq!(wh.name, "test-hook");
        assert_eq!(wh.url, "https://example.com/hook");
        assert!(wh.enabled);
        assert_eq!(wh.event_filters.len(), 2);

        let all = manager.list_webhooks().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, wh.id);
    }

    #[tokio::test]
    async fn test_delete_webhook() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        let wh = manager
            .create_webhook(
                "del-me",
                "https://example.com/hook",
                "",
                &[],
                WebhookFormat::Slack,
            )
            .await
            .unwrap();

        manager.delete_webhook(&wh.id).await.unwrap();
        let all = manager.list_webhooks().await.unwrap();
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_webhook() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        let result = manager.delete_webhook("nonexistent").await;
        assert!(result.is_err());
        match result {
            Err(WebhookError::NotFound(id)) => assert_eq!(id, "nonexistent"),
            _ => panic!("expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_get_webhook() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        let wh = manager
            .create_webhook(
                "get-me",
                "https://example.com/hook",
                "mysecret",
                &[],
                WebhookFormat::SiemCef,
            )
            .await
            .unwrap();

        let fetched = manager.get_webhook(&wh.id).await.unwrap();
        assert_eq!(fetched.name, "get-me");
        assert_eq!(fetched.format, WebhookFormat::SiemCef);
    }

    #[tokio::test]
    async fn test_get_nonexistent_webhook() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        let result = manager.get_webhook("nonexistent").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_hmac_signature() {
        let sig = compute_hmac("secret", "payload");
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 64); // SHA-256 = 32 bytes = 64 hex chars

        // Same input should produce same output
        let sig2 = compute_hmac("secret", "payload");
        assert_eq!(sig, sig2);

        // Different secret should produce different output
        let sig3 = compute_hmac("other-secret", "payload");
        assert_ne!(sig, sig3);
    }

    #[test]
    fn test_format_payload_generic_json() {
        let webhook = WebhookConfig {
            id: "test".into(),
            name: "test".into(),
            url: "https://example.com".into(),
            secret: String::new(),
            event_filters: vec![],
            format: WebhookFormat::GenericJSON,
            enabled: true,
            created_at: 0,
        };

        let payload = serde_json::json!({"event_type": "session_new", "details": "test"});
        let body = format_payload(&webhook, &payload);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["event_type"], "session_new");
    }

    #[test]
    fn test_format_payload_slack() {
        let webhook = WebhookConfig {
            id: "test".into(),
            name: "test".into(),
            url: "https://hooks.slack.com/services/test".into(),
            secret: String::new(),
            event_filters: vec![],
            format: WebhookFormat::Slack,
            enabled: true,
            created_at: 0,
        };

        let payload = serde_json::json!({"event_type": "session_new", "message": "new session"});
        let body = format_payload(&webhook, &payload);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["text"].as_str().unwrap().contains("session_new"));
        assert_eq!(parsed["username"], "SPECTER C2");
    }

    #[test]
    fn test_format_payload_siem_cef() {
        let webhook = WebhookConfig {
            id: "test".into(),
            name: "test".into(),
            url: "https://siem.example.com".into(),
            secret: String::new(),
            event_filters: vec![],
            format: WebhookFormat::SiemCef,
            enabled: true,
            created_at: 0,
        };

        let payload =
            serde_json::json!({"event_type": "session_new", "timestamp": "2026-03-20T00:00:00Z"});
        let body = format_payload(&webhook, &payload);
        assert!(body.starts_with("CEF:0|SPECTER|"));
        assert!(body.contains("session_new"));
    }

    #[test]
    fn test_event_type_name() {
        use specter_common::proto::specter::v1::SessionEvent;

        let event = SpecterEvent::SessionNew(SessionEvent {
            event_type: String::new(),
            session: None,
            timestamp: None,
        });
        assert_eq!(event_type_name(&event), "session_new");

        let event = SpecterEvent::SessionLost(SessionEvent {
            event_type: String::new(),
            session: None,
            timestamp: None,
        });
        assert_eq!(event_type_name(&event), "session_lost");
    }

    #[test]
    fn test_webhook_format_roundtrip() {
        assert_eq!(
            WebhookFormat::from_str("GenericJSON"),
            WebhookFormat::GenericJSON
        );
        assert_eq!(WebhookFormat::from_str("Slack"), WebhookFormat::Slack);
        assert_eq!(WebhookFormat::from_str("SIEM-CEF"), WebhookFormat::SiemCef);
        assert_eq!(
            WebhookFormat::from_str("unknown"),
            WebhookFormat::GenericJSON
        );

        assert_eq!(WebhookFormat::GenericJSON.as_str(), "GenericJSON");
        assert_eq!(WebhookFormat::Slack.as_str(), "Slack");
        assert_eq!(WebhookFormat::SiemCef.as_str(), "SIEM-CEF");
    }

    #[test]
    fn test_webhook_format_proto_roundtrip() {
        assert_eq!(WebhookFormat::from_proto(1), WebhookFormat::GenericJSON);
        assert_eq!(WebhookFormat::from_proto(2), WebhookFormat::Slack);
        assert_eq!(WebhookFormat::from_proto(3), WebhookFormat::SiemCef);
        assert_eq!(WebhookFormat::from_proto(99), WebhookFormat::GenericJSON);

        assert_eq!(WebhookFormat::GenericJSON.to_proto(), 1);
        assert_eq!(WebhookFormat::Slack.to_proto(), 2);
        assert_eq!(WebhookFormat::SiemCef.to_proto(), 3);
    }

    #[tokio::test]
    async fn test_create_webhook_with_all_formats() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        for format in [
            WebhookFormat::GenericJSON,
            WebhookFormat::Slack,
            WebhookFormat::SiemCef,
        ] {
            let wh = manager
                .create_webhook(
                    &format!("hook-{}", format.as_str()),
                    "https://example.com/hook",
                    "",
                    &[],
                    format,
                )
                .await
                .unwrap();
            assert_eq!(wh.format, format);
        }

        let all = manager.list_webhooks().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_webhook_event_filters_persisted() {
        let pool = setup_test_db().await;
        let manager = WebhookManager::new(pool);

        let filters = vec![
            "session_new".to_string(),
            "session_lost".to_string(),
            "task_failed".to_string(),
        ];

        let wh = manager
            .create_webhook(
                "filtered",
                "https://example.com/hook",
                "",
                &filters,
                WebhookFormat::GenericJSON,
            )
            .await
            .unwrap();

        let fetched = manager.get_webhook(&wh.id).await.unwrap();
        assert_eq!(fetched.event_filters, filters);
    }
}
