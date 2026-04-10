use std::sync::Arc;

use chrono::Utc;
use prost_types::Timestamp;
use specter_common::proto::specter::v1::{SessionEvent, SessionInfo, SessionStatus};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::event::{EventBus, SpecterEvent};

pub struct SessionManager {
    pool: SqlitePool,
    event_bus: Arc<EventBus>,
}

impl SessionManager {
    pub fn new(pool: SqlitePool, event_bus: Arc<EventBus>) -> Self {
        Self { pool, event_bus }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_session(
        &self,
        hostname: String,
        username: String,
        pid: u32,
        os_version: String,
        integrity_level: String,
        process_name: String,
        internal_ip: String,
        external_ip: String,
    ) -> Result<String, sqlx::Error> {
        self.register_session_with_pubkey(
            hostname,
            username,
            pid,
            os_version,
            integrity_level,
            process_name,
            internal_ip,
            external_ip,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_session_with_pubkey(
        &self,
        hostname: String,
        username: String,
        pid: u32,
        os_version: String,
        integrity_level: String,
        process_name: String,
        internal_ip: String,
        external_ip: String,
        implant_pubkey: Option<Vec<u8>>,
    ) -> Result<String, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO sessions (id, hostname, username, pid, os_version, integrity_level, \
             process_name, internal_ip, external_ip, last_checkin, first_seen, status, implant_pubkey) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW', ?)",
        )
        .bind(&id)
        .bind(&hostname)
        .bind(&username)
        .bind(pid as i64)
        .bind(&os_version)
        .bind(&integrity_level)
        .bind(&process_name)
        .bind(&internal_ip)
        .bind(&external_ip)
        .bind(now)
        .bind(now)
        .bind(&implant_pubkey)
        .execute(&self.pool)
        .await?;

        if let Ok(Some(session)) = self.get_session(&id).await {
            self.event_bus
                .publish(SpecterEvent::SessionNew(SessionEvent {
                    event_type: "session_new".to_string(),
                    session: Some(session),
                    timestamp: Some(ts(now)),
                }));
        }

        Ok(id)
    }

    pub async fn update_checkin(&self, session_id: &str) -> Result<(), sqlx::Error> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE sessions SET last_checkin = ?, status = 'ACTIVE' WHERE id = ? AND deleted = 0",
        )
        .bind(now)
        .bind(session_id)
        .execute(&self.pool)
        .await?;

        if let Ok(Some(session)) = self.get_session(session_id).await {
            self.event_bus
                .publish(SpecterEvent::SessionCheckin(SessionEvent {
                    event_type: "session_checkin".to_string(),
                    session: Some(session),
                    timestamp: Some(ts(now)),
                }));
        }

        Ok(())
    }

    /// Update sleep interval and jitter for a session (called when a sleep task completes).
    pub async fn update_sleep_config(
        &self,
        session_id: &str,
        interval: u32,
        jitter: u32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE sessions SET sleep_interval = ?1, sleep_jitter = ?2 WHERE id = ?3 AND deleted = 0",
        )
        .bind(interval as i64)
        .bind(jitter as i64)
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_session(&self, id: &str) -> Result<Option<SessionInfo>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, hostname, username, pid, os_version, integrity_level, process_name, \
             internal_ip, external_ip, last_checkin, first_seen, status, active_channel \
             FROM sessions WHERE id = ? AND deleted = 0",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| row_to_session(&r)))
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, hostname, username, pid, os_version, integrity_level, process_name, \
             internal_ip, external_ip, last_checkin, first_seen, status, active_channel \
             FROM sessions WHERE deleted = 0",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_session).collect())
    }

    #[allow(dead_code)]
    pub async fn remove_session(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sessions SET deleted = 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Find a session by its implant public key.
    pub async fn find_by_pubkey(&self, pubkey: &[u8]) -> Result<Option<String>, sqlx::Error> {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM sessions WHERE implant_pubkey = ? AND deleted = 0")
                .bind(pubkey)
                .fetch_optional(&self.pool)
                .await?;

        Ok(existing.map(|(id,)| id))
    }

    /// Get the implant public key for a session.
    pub async fn get_implant_pubkey(
        &self,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        let row: Option<(Option<Vec<u8>>,)> =
            sqlx::query_as("SELECT implant_pubkey FROM sessions WHERE id = ? AND deleted = 0")
                .bind(session_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.and_then(|(pk,)| pk))
    }

    /// Register or update a session, storing the implant public key.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_or_update_with_pubkey(
        &self,
        hostname: &str,
        username: &str,
        pid: u32,
        os_version: &str,
        integrity_level: &str,
        process_name: &str,
        internal_ip: &str,
        external_ip: &str,
        implant_pubkey: &[u8],
    ) -> Result<String, sqlx::Error> {
        // First try to find by pubkey (more reliable for binary protocol)
        if let Some(id) = self.find_by_pubkey(implant_pubkey).await? {
            self.update_checkin(&id).await?;
            return Ok(id);
        }

        self.register_session_with_pubkey(
            hostname.to_string(),
            username.to_string(),
            pid,
            os_version.to_string(),
            integrity_level.to_string(),
            process_name.to_string(),
            internal_ip.to_string(),
            external_ip.to_string(),
            Some(implant_pubkey.to_vec()),
        )
        .await
    }

    /// Find an existing session by hostname+username+pid, or create a new one.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_or_update(
        &self,
        hostname: &str,
        username: &str,
        pid: u32,
        os_version: &str,
        integrity_level: &str,
        process_name: &str,
        internal_ip: &str,
        external_ip: &str,
    ) -> Result<String, sqlx::Error> {
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM sessions WHERE hostname = ? AND username = ? AND pid = ? AND deleted = 0",
        )
        .bind(hostname)
        .bind(username)
        .bind(pid as i64)
        .fetch_optional(&self.pool)
        .await?;

        match existing {
            Some((id,)) => {
                self.update_checkin(&id).await?;
                Ok(id)
            }
            None => {
                self.register_session(
                    hostname.to_string(),
                    username.to_string(),
                    pid,
                    os_version.to_string(),
                    integrity_level.to_string(),
                    process_name.to_string(),
                    internal_ip.to_string(),
                    external_ip.to_string(),
                )
                .await
            }
        }
    }

    /// Recompute session statuses based on last check-in time.
    pub async fn update_statuses(&self, default_interval: i64) -> Result<(), sqlx::Error> {
        let now = Utc::now().timestamp();

        let rows = sqlx::query("SELECT id, last_checkin, status FROM sessions WHERE deleted = 0")
            .fetch_all(&self.pool)
            .await?;

        for row in &rows {
            let id: &str = row.get("id");
            let last_checkin: i64 = row.get("last_checkin");
            let old_status: &str = row.get("status");
            let elapsed = now - last_checkin;

            let new_status = if elapsed < default_interval * 3 {
                "ACTIVE"
            } else if elapsed < default_interval * 10 {
                "STALE"
            } else {
                "DEAD"
            };

            if new_status != old_status {
                sqlx::query("UPDATE sessions SET status = ? WHERE id = ?")
                    .bind(new_status)
                    .bind(id)
                    .execute(&self.pool)
                    .await?;

                if new_status == "DEAD" && old_status != "DEAD" {
                    if let Ok(Some(session)) = self.get_session(id).await {
                        self.event_bus
                            .publish(SpecterEvent::SessionLost(SessionEvent {
                                event_type: "session_lost".to_string(),
                                session: Some(session),
                                timestamp: Some(ts(now)),
                            }));
                    }
                }
            }
        }

        Ok(())
    }

    /// Spawn a background task that recomputes session statuses every `interval_secs`.
    pub fn start_status_updater(
        self: &Arc<Self>,
        interval_secs: u64,
        default_checkin_interval: i64,
    ) {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                tick.tick().await;
                if let Err(e) = mgr.update_statuses(default_checkin_interval).await {
                    tracing::error!("Failed to update session statuses: {e}");
                }
            }
        });
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn ts(epoch_secs: i64) -> Timestamp {
    Timestamp {
        seconds: epoch_secs,
        nanos: 0,
    }
}

fn str_to_status(s: &str) -> i32 {
    match s {
        "NEW" => SessionStatus::New.into(),
        "ACTIVE" => SessionStatus::Active.into(),
        "STALE" => SessionStatus::Stale.into(),
        "DEAD" => SessionStatus::Dead.into(),
        _ => SessionStatus::Unspecified.into(),
    }
}

fn row_to_session(row: &SqliteRow) -> SessionInfo {
    let last_checkin: i64 = row.get("last_checkin");
    let first_seen: i64 = row.get("first_seen");
    let status_str: &str = row.get("status");
    let pid: i64 = row.get("pid");

    let sleep_interval: i64 = row.try_get("sleep_interval").unwrap_or(60);
    let sleep_jitter: i64 = row.try_get("sleep_jitter").unwrap_or(10);

    SessionInfo {
        id: row.get("id"),
        hostname: row.get("hostname"),
        username: row.get("username"),
        pid: pid as u32,
        os_version: row.get("os_version"),
        integrity_level: row.get("integrity_level"),
        process_name: row.get("process_name"),
        internal_ip: row.get("internal_ip"),
        external_ip: row.get("external_ip"),
        last_checkin: Some(ts(last_checkin)),
        first_seen: Some(ts(first_seen)),
        status: str_to_status(status_str),
        active_channel: row.get("active_channel"),
        sleep_interval: sleep_interval as u32,
        sleep_jitter: sleep_jitter as u32,
    }
}
