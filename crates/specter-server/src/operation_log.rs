use std::sync::Arc;

use chrono::Utc;
use specter_common::proto::specter::v1::OperationLog;
use sqlx::{Row, SqlitePool};

use crate::event::{EventBus, SpecterEvent};

const MAX_DETAILS_BYTES: usize = 64 * 1024;

pub fn trim_details(details: impl AsRef<str>) -> String {
    let details = details.as_ref();
    if details.len() <= MAX_DETAILS_BYTES {
        return details.to_string();
    }

    let mut end = MAX_DETAILS_BYTES;
    while !details.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n...[truncated: {} bytes omitted]",
        &details[..end],
        details.len().saturating_sub(end)
    )
}

pub async fn record_operation_log(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    level: &str,
    source: &str,
    target_type: &str,
    target_id: &str,
    message: impl AsRef<str>,
    details: impl AsRef<str>,
) -> Result<OperationLog, sqlx::Error> {
    let now = Utc::now().timestamp();
    let log = OperationLog {
        id: uuid::Uuid::new_v4().to_string(),
        level: level.to_ascii_lowercase(),
        source: source.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        message: message.as_ref().to_string(),
        details: trim_details(details),
        created_at: Some(prost_types::Timestamp {
            seconds: now,
            nanos: 0,
        }),
    };

    sqlx::query(
        "INSERT INTO operation_logs (id, level, source, target_type, target_id, message, details, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&log.id)
    .bind(&log.level)
    .bind(&log.source)
    .bind(&log.target_type)
    .bind(&log.target_id)
    .bind(&log.message)
    .bind(&log.details)
    .bind(now)
    .execute(pool)
    .await?;

    event_bus.publish(SpecterEvent::OperationLog(log.clone()));
    Ok(log)
}

#[derive(Clone)]
pub struct OperationLogStore {
    pool: SqlitePool,
    event_bus: Arc<EventBus>,
}

impl OperationLogStore {
    pub fn new(pool: SqlitePool, event_bus: Arc<EventBus>) -> Self {
        Self { pool, event_bus }
    }

    pub async fn record(
        &self,
        level: &str,
        source: &str,
        target_type: &str,
        target_id: &str,
        message: impl AsRef<str>,
        details: impl AsRef<str>,
    ) -> Result<OperationLog, sqlx::Error> {
        record_operation_log(
            &self.pool,
            &self.event_bus,
            level,
            source,
            target_type,
            target_id,
            message,
            details,
        )
        .await
    }

    pub async fn list(
        &self,
        source: &str,
        target_type: &str,
        target_id: &str,
        limit: i64,
    ) -> Result<Vec<OperationLog>, sqlx::Error> {
        let limit = limit.clamp(1, 1000);
        let source_filter = source.trim();
        let target_type_filter = target_type.trim();
        let target_id_filter = target_id.trim();

        let rows = sqlx::query(
            "SELECT id, level, source, target_type, target_id, message, details, created_at
             FROM operation_logs
             WHERE (?1 = '' OR source = ?1)
               AND (?2 = '' OR target_type = ?2)
               AND (?3 = '' OR target_id = ?3)
             ORDER BY created_at DESC
             LIMIT ?4",
        )
        .bind(source_filter)
        .bind(target_type_filter)
        .bind(target_id_filter)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let created_at: i64 = row.get("created_at");
                OperationLog {
                    id: row.get("id"),
                    level: row.get("level"),
                    source: row.get("source"),
                    target_type: row.get("target_type"),
                    target_id: row.get("target_id"),
                    message: row.get("message"),
                    details: row.get("details"),
                    created_at: Some(prost_types::Timestamp {
                        seconds: created_at,
                        nanos: 0,
                    }),
                }
            })
            .collect())
    }
}
