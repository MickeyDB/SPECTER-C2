use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error(
        "chain integrity violation at sequence {sequence}: expected hash {expected}, got {actual}"
    )]
    ChainIntegrity {
        sequence: i64,
        expected: String,
        actual: String,
    },
}

/// Actions that can be recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    SessionInteract,
    TaskQueue,
    TaskComplete,
    ModuleLoad,
    ListenerCreate,
    ListenerStart,
    ListenerStop,
    OperatorCreate,
    OperatorAuth,
    CertIssue,
    CertRevoke,
    CertRotate,
    ProfileCreate,
    ProfileCompile,
    WebhookCreate,
    WebhookDelete,
    WebhookTest,
    CampaignCreate,
    CampaignUpdate,
    PayloadGenerate,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SessionInteract => "SESSION_INTERACT",
            Self::TaskQueue => "TASK_QUEUE",
            Self::TaskComplete => "TASK_COMPLETE",
            Self::ModuleLoad => "MODULE_LOAD",
            Self::ListenerCreate => "LISTENER_CREATE",
            Self::ListenerStart => "LISTENER_START",
            Self::ListenerStop => "LISTENER_STOP",
            Self::OperatorCreate => "OPERATOR_CREATE",
            Self::OperatorAuth => "OPERATOR_AUTH",
            Self::CertIssue => "CERT_ISSUE",
            Self::CertRevoke => "CERT_REVOKE",
            Self::CertRotate => "CERT_ROTATE",
            Self::ProfileCreate => "PROFILE_CREATE",
            Self::ProfileCompile => "PROFILE_COMPILE",
            Self::WebhookCreate => "WEBHOOK_CREATE",
            Self::WebhookDelete => "WEBHOOK_DELETE",
            Self::WebhookTest => "WEBHOOK_TEST",
            Self::CampaignCreate => "CAMPAIGN_CREATE",
            Self::CampaignUpdate => "CAMPAIGN_UPDATE",
            Self::PayloadGenerate => "PAYLOAD_GENERATE",
        };
        write!(f, "{s}")
    }
}

impl AuditAction {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SESSION_INTERACT" => Some(Self::SessionInteract),
            "TASK_QUEUE" => Some(Self::TaskQueue),
            "TASK_COMPLETE" => Some(Self::TaskComplete),
            "MODULE_LOAD" => Some(Self::ModuleLoad),
            "LISTENER_CREATE" => Some(Self::ListenerCreate),
            "LISTENER_START" => Some(Self::ListenerStart),
            "LISTENER_STOP" => Some(Self::ListenerStop),
            "OPERATOR_CREATE" => Some(Self::OperatorCreate),
            "OPERATOR_AUTH" => Some(Self::OperatorAuth),
            "CERT_ISSUE" => Some(Self::CertIssue),
            "CERT_REVOKE" => Some(Self::CertRevoke),
            "CERT_ROTATE" => Some(Self::CertRotate),
            "PROFILE_CREATE" => Some(Self::ProfileCreate),
            "PROFILE_COMPILE" => Some(Self::ProfileCompile),
            "WEBHOOK_CREATE" => Some(Self::WebhookCreate),
            "WEBHOOK_DELETE" => Some(Self::WebhookDelete),
            "WEBHOOK_TEST" => Some(Self::WebhookTest),
            "CAMPAIGN_CREATE" => Some(Self::CampaignCreate),
            "CAMPAIGN_UPDATE" => Some(Self::CampaignUpdate),
            "PAYLOAD_GENERATE" => Some(Self::PayloadGenerate),
            _ => None,
        }
    }
}

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: String,
    pub sequence_number: i64,
    pub operator_id: String,
    pub action: String,
    pub target: String,
    pub details: String,
    pub timestamp: i64,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Filter criteria for querying audit entries.
#[derive(Debug, Default)]
pub struct AuditFilter {
    pub operator_id: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
}

/// Export format for audit data.
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Immutable tamper-evident hash-chained audit log.
pub struct AuditLog {
    pool: SqlitePool,
}

impl AuditLog {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Compute the SHA-256 hash for an audit entry.
    fn compute_hash(
        sequence: i64,
        timestamp: i64,
        operator: &str,
        action: &str,
        target: &str,
        details: &str,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(operator.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(details.as_bytes());
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Append a new entry to the audit log. Atomically fetches the previous
    /// entry's hash, computes the new hash, and inserts.
    /// Append an audit entry, logging a warning if it fails.
    ///
    /// Callers that discard the result with `let _ = ...` should use this
    /// method instead of [`append`] to ensure failures are visible.
    pub async fn log_append(
        &self,
        operator_id: &str,
        action: AuditAction,
        target: &str,
        details: &serde_json::Value,
    ) {
        if let Err(e) = self.append(operator_id, action, target, details).await {
            tracing::warn!(
                %action,
                %target,
                "Audit log append failed: {e}"
            );
        }
    }

    pub async fn append(
        &self,
        operator_id: &str,
        action: AuditAction,
        target: &str,
        details: &serde_json::Value,
    ) -> Result<String, AuditError> {
        let id = uuid::Uuid::new_v4().to_string();
        let action_str = action.to_string();
        let details_str = details.to_string();
        let timestamp = chrono::Utc::now().timestamp_millis();

        // Use a transaction for atomicity (gap-free sequence).
        let mut tx = self.pool.begin().await?;

        // Get the last entry's sequence_number and entry_hash.
        let last: Option<(i64, String)> = sqlx::query_as(
            "SELECT sequence_number, entry_hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let (prev_seq, prev_hash) = match last {
            Some((seq, hash)) => (seq, hash),
            None => (0, String::new()),
        };

        let sequence = prev_seq + 1;
        let entry_hash = Self::compute_hash(
            sequence,
            timestamp,
            operator_id,
            &action_str,
            target,
            &details_str,
            &prev_hash,
        );

        sqlx::query(
            "INSERT INTO audit_log (id, sequence_number, operator_id, action, target, details, timestamp, prev_hash, entry_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(sequence)
        .bind(operator_id)
        .bind(&action_str)
        .bind(target)
        .bind(&details_str)
        .bind(timestamp)
        .bind(&prev_hash)
        .bind(&entry_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Walk the full chain and recompute hashes to detect tampering.
    /// Returns Ok(entry_count) if chain is valid.
    pub async fn verify_chain(&self) -> Result<i64, AuditError> {
        let entries: Vec<AuditEntry> = sqlx::query_as::<_, AuditEntryRow>(
            "SELECT id, sequence_number, operator_id, action, target, details, timestamp, prev_hash, entry_hash
             FROM audit_log ORDER BY sequence_number ASC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        let mut expected_prev_hash = String::new();

        for entry in &entries {
            // Check prev_hash matches what we expect
            if entry.prev_hash != expected_prev_hash {
                return Err(AuditError::ChainIntegrity {
                    sequence: entry.sequence_number,
                    expected: expected_prev_hash,
                    actual: entry.prev_hash.clone(),
                });
            }

            // Recompute and verify entry_hash
            let computed = Self::compute_hash(
                entry.sequence_number,
                entry.timestamp,
                &entry.operator_id,
                &entry.action,
                &entry.target,
                &entry.details,
                &entry.prev_hash,
            );

            if entry.entry_hash != computed {
                return Err(AuditError::ChainIntegrity {
                    sequence: entry.sequence_number,
                    expected: computed,
                    actual: entry.entry_hash.clone(),
                });
            }

            expected_prev_hash = entry.entry_hash.clone();
        }

        Ok(entries.len() as i64)
    }

    /// Query audit entries with optional filters.
    pub async fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        let mut sql = String::from(
            "SELECT id, sequence_number, operator_id, action, target, details, timestamp, prev_hash, entry_hash
             FROM audit_log WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();

        if let Some(ref op) = filter.operator_id {
            sql.push_str(&format!(" AND operator_id = ${}", binds.len() + 1));
            binds.push(op.clone());
        }
        if let Some(ref action) = filter.action {
            sql.push_str(&format!(" AND action = ${}", binds.len() + 1));
            binds.push(action.clone());
        }
        if let Some(ref target) = filter.target {
            sql.push_str(&format!(" AND target = ${}", binds.len() + 1));
            binds.push(target.clone());
        }

        // For time ranges we need to handle differently since they're i64, not String.
        // We'll build the query dynamically with SQLite-compatible placeholders.
        // Since sqlx doesn't support truly dynamic bind lists easily, use a simpler approach.
        let entries = self.query_with_filter(filter).await?;
        let _ = (sql, binds); // suppress unused warnings

        Ok(entries)
    }

    /// Internal filtered query implementation.
    async fn query_with_filter(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        // Build query parts
        let mut conditions = Vec::new();

        if filter.operator_id.is_some() {
            conditions.push("operator_id = ?");
        }
        if filter.action.is_some() {
            conditions.push("action = ?");
        }
        if filter.target.is_some() {
            conditions.push("target = ?");
        }
        if filter.time_start.is_some() {
            conditions.push("timestamp >= ?");
        }
        if filter.time_end.is_some() {
            conditions.push("timestamp <= ?");
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, sequence_number, operator_id, action, target, details, timestamp, prev_hash, entry_hash
             FROM audit_log{} ORDER BY sequence_number ASC",
            where_clause
        );

        let mut query = sqlx::query_as::<_, AuditEntryRow>(&sql);

        if let Some(ref op) = filter.operator_id {
            query = query.bind(op);
        }
        if let Some(ref action) = filter.action {
            query = query.bind(action);
        }
        if let Some(ref target) = filter.target {
            query = query.bind(target);
        }
        if let Some(ts) = filter.time_start {
            query = query.bind(ts);
        }
        if let Some(ts) = filter.time_end {
            query = query.bind(ts);
        }

        let rows = query.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Export audit entries matching a filter in the specified format.
    pub async fn export(
        &self,
        filter: &AuditFilter,
        format: ExportFormat,
    ) -> Result<String, AuditError> {
        let entries = self.query(filter).await?;
        match format {
            ExportFormat::Json => {
                let json_entries: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "id": e.id,
                            "sequence_number": e.sequence_number,
                            "operator_id": e.operator_id,
                            "action": e.action,
                            "target": e.target,
                            "details": e.details,
                            "timestamp": e.timestamp,
                            "prev_hash": e.prev_hash,
                            "entry_hash": e.entry_hash,
                        })
                    })
                    .collect();
                Ok(
                    serde_json::to_string_pretty(&json_entries)
                        .unwrap_or_else(|_| "[]".to_string()),
                )
            }
            ExportFormat::Csv => {
                let mut csv = String::from(
                    "id,sequence_number,operator_id,action,target,details,timestamp,prev_hash,entry_hash\n",
                );
                for e in &entries {
                    // Escape fields that might contain commas/quotes
                    csv.push_str(&format!(
                        "{},{},{},{},\"{}\",\"{}\",{},{},{}\n",
                        e.id,
                        e.sequence_number,
                        e.operator_id,
                        e.action,
                        e.target.replace('"', "\"\""),
                        e.details.replace('"', "\"\""),
                        e.timestamp,
                        e.prev_hash,
                        e.entry_hash,
                    ));
                }
                Ok(csv)
            }
        }
    }
}

/// Row type for sqlx deserialization.
#[derive(sqlx::FromRow)]
struct AuditEntryRow {
    id: String,
    sequence_number: i64,
    operator_id: String,
    action: String,
    target: String,
    details: String,
    timestamp: i64,
    prev_hash: String,
    entry_hash: String,
}

impl From<AuditEntryRow> for AuditEntry {
    fn from(row: AuditEntryRow) -> Self {
        Self {
            id: row.id,
            sequence_number: row.sequence_number,
            operator_id: row.operator_id,
            action: row.action,
            target: row.target,
            details: row.details,
            timestamp: row.timestamp,
            prev_hash: row.prev_hash,
            entry_hash: row.entry_hash,
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
    async fn test_append_and_verify_chain() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        // Append several entries
        let id1 = audit
            .append(
                "op1",
                AuditAction::ListenerCreate,
                "listener-1",
                &serde_json::json!({"port": 8080}),
            )
            .await
            .unwrap();
        assert!(!id1.is_empty());

        let id2 = audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                "session-abc",
                &serde_json::json!({"task": "whoami"}),
            )
            .await
            .unwrap();
        assert_ne!(id1, id2);

        let id3 = audit
            .append(
                "op2",
                AuditAction::TaskComplete,
                "session-abc",
                &serde_json::json!({"result": "admin"}),
            )
            .await
            .unwrap();
        assert_ne!(id2, id3);

        // Verify chain integrity
        let count = audit.verify_chain().await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_chain_detects_hash_tampering() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool.clone());

        audit
            .append(
                "op1",
                AuditAction::ListenerCreate,
                "listener-1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                "session-1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        // Tamper with the first entry's hash
        sqlx::query("UPDATE audit_log SET entry_hash = 'tampered' WHERE sequence_number = 1")
            .execute(&pool)
            .await
            .unwrap();

        let result = audit.verify_chain().await;
        assert!(result.is_err());
        match result {
            Err(AuditError::ChainIntegrity { sequence, .. }) => {
                assert_eq!(sequence, 1);
            }
            _ => panic!("expected ChainIntegrity error"),
        }
    }

    #[tokio::test]
    async fn test_chain_detects_prev_hash_tampering() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool.clone());

        audit
            .append(
                "op1",
                AuditAction::OperatorCreate,
                "user-a",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                "session-1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        // Tamper with the second entry's prev_hash
        sqlx::query("UPDATE audit_log SET prev_hash = 'wrong' WHERE sequence_number = 2")
            .execute(&pool)
            .await
            .unwrap();

        let result = audit.verify_chain().await;
        assert!(result.is_err());
        match result {
            Err(AuditError::ChainIntegrity { sequence, .. }) => {
                assert_eq!(sequence, 2);
            }
            _ => panic!("expected ChainIntegrity error"),
        }
    }

    #[tokio::test]
    async fn test_sequence_is_monotonic_gap_free() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        for i in 0..5 {
            audit
                .append(
                    "op1",
                    AuditAction::TaskQueue,
                    &format!("target-{i}"),
                    &serde_json::json!({}),
                )
                .await
                .unwrap();
        }

        let entries = audit.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries.len(), 5);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence_number, (i + 1) as i64);
        }
    }

    #[tokio::test]
    async fn test_query_filter_by_operator() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        audit
            .append(
                "alice",
                AuditAction::TaskQueue,
                "s1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        audit
            .append("bob", AuditAction::TaskQueue, "s2", &serde_json::json!({}))
            .await
            .unwrap();
        audit
            .append(
                "alice",
                AuditAction::TaskComplete,
                "s1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        let filter = AuditFilter {
            operator_id: Some("alice".to_string()),
            ..Default::default()
        };
        let entries = audit.query(&filter).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.operator_id == "alice"));
    }

    #[tokio::test]
    async fn test_query_filter_by_action() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        audit
            .append("op1", AuditAction::TaskQueue, "s1", &serde_json::json!({}))
            .await
            .unwrap();
        audit
            .append(
                "op1",
                AuditAction::ListenerCreate,
                "l1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        let filter = AuditFilter {
            action: Some("LISTENER_CREATE".to_string()),
            ..Default::default()
        };
        let entries = audit.query(&filter).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "LISTENER_CREATE");
    }

    #[tokio::test]
    async fn test_query_filter_by_target() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                "session-abc",
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                "session-xyz",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        let filter = AuditFilter {
            target: Some("session-abc".to_string()),
            ..Default::default()
        };
        let entries = audit.query(&filter).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].target, "session-abc");
    }

    #[tokio::test]
    async fn test_export_json() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                "s1",
                &serde_json::json!({"cmd": "whoami"}),
            )
            .await
            .unwrap();

        let json = audit
            .export(&AuditFilter::default(), ExportFormat::Json)
            .await
            .unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["operator_id"], "op1");
        assert_eq!(parsed[0]["action"], "TASK_QUEUE");
    }

    #[tokio::test]
    async fn test_export_csv() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        audit
            .append("op1", AuditAction::TaskQueue, "s1", &serde_json::json!({}))
            .await
            .unwrap();
        audit
            .append(
                "op2",
                AuditAction::ListenerCreate,
                "l1",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        let csv = audit
            .export(&AuditFilter::default(), ExportFormat::Csv)
            .await
            .unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 entries
        assert!(lines[0].starts_with("id,sequence_number,"));
    }

    #[tokio::test]
    async fn test_empty_chain_verifies() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        let count = audit.verify_chain().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_first_entry_has_empty_prev_hash() {
        let pool = setup_test_db().await;
        let audit = AuditLog::new(pool);

        audit
            .append(
                "op1",
                AuditAction::OperatorCreate,
                "admin",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        let entries = audit.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].prev_hash, "");
        assert!(!entries[0].entry_hash.is_empty());
        assert_eq!(entries[0].sequence_number, 1);
    }
}
