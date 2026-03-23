use std::sync::Arc;

use chrono::Utc;
use prost_types::Timestamp;
use specter_common::proto::specter::v1::{Task, TaskEvent, TaskPriority, TaskStatus};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::event::{EventBus, SpecterEvent};

pub struct TaskDispatcher {
    pool: SqlitePool,
    event_bus: Arc<EventBus>,
}

impl TaskDispatcher {
    pub fn new(pool: SqlitePool, event_bus: Arc<EventBus>) -> Self {
        Self { pool, event_bus }
    }

    pub async fn queue_task(
        &self,
        session_id: &str,
        task_type: &str,
        arguments: &[u8],
        priority: TaskPriority,
        operator_id: &str,
    ) -> Result<String, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let priority_str = priority_to_str(priority);

        sqlx::query(
            "INSERT INTO tasks (id, session_id, task_type, arguments, priority, status, \
             created_at, operator_id) VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?)",
        )
        .bind(&id)
        .bind(session_id)
        .bind(task_type)
        .bind(arguments)
        .bind(priority_str)
        .bind(now)
        .bind(operator_id)
        .execute(&self.pool)
        .await?;

        if let Ok(Some(task)) = self.get_task(&id).await {
            self.event_bus.publish(SpecterEvent::TaskQueued(TaskEvent {
                event_type: "task_queued".to_string(),
                task: Some(task),
                timestamp: Some(ts(now)),
            }));
        }

        Ok(id)
    }

    /// Return queued tasks for a session, ordered by priority DESC then created_at ASC.
    pub async fn get_pending_tasks(&self, session_id: &str) -> Result<Vec<Task>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, session_id, task_type, arguments, priority, status, created_at, \
             completed_at, operator_id, result FROM tasks \
             WHERE session_id = ? AND status = 'QUEUED' \
             ORDER BY \
               CASE priority \
                 WHEN 'HIGH' THEN 0 \
                 WHEN 'NORMAL' THEN 1 \
                 WHEN 'LOW' THEN 2 \
                 ELSE 3 \
               END, \
               created_at ASC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_task).collect())
    }

    pub async fn mark_dispatched(&self, task_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE tasks SET status = 'DISPATCHED' WHERE id = ?")
            .bind(task_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn complete_task(
        &self,
        task_id: &str,
        result: &[u8],
        success: bool,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now().timestamp();
        let status = if success { "COMPLETE" } else { "FAILED" };

        sqlx::query("UPDATE tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?")
            .bind(status)
            .bind(result)
            .bind(now)
            .bind(task_id)
            .execute(&self.pool)
            .await?;

        if let Ok(Some(task)) = self.get_task(task_id).await {
            let event = if success {
                SpecterEvent::TaskComplete(TaskEvent {
                    event_type: "task_complete".to_string(),
                    task: Some(task),
                    timestamp: Some(ts(now)),
                })
            } else {
                SpecterEvent::TaskFailed(TaskEvent {
                    event_type: "task_failed".to_string(),
                    task: Some(task),
                    timestamp: Some(ts(now)),
                })
            };
            self.event_bus.publish(event);
        }

        Ok(())
    }

    pub async fn get_task(&self, task_id: &str) -> Result<Option<Task>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, session_id, task_type, arguments, priority, status, created_at, \
             completed_at, operator_id, result FROM tasks WHERE id = ?",
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_task))
    }

    pub async fn list_tasks(&self, session_id: &str) -> Result<Vec<Task>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, session_id, task_type, arguments, priority, status, created_at, \
             completed_at, operator_id, result FROM tasks WHERE session_id = ? \
             ORDER BY created_at DESC",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_task).collect())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn ts(epoch_secs: i64) -> Timestamp {
    Timestamp {
        seconds: epoch_secs,
        nanos: 0,
    }
}

fn priority_to_str(p: TaskPriority) -> &'static str {
    match p {
        TaskPriority::High => "HIGH",
        TaskPriority::Normal => "NORMAL",
        TaskPriority::Low => "LOW",
        TaskPriority::Unspecified => "NORMAL",
    }
}

fn str_to_priority(s: &str) -> i32 {
    match s {
        "HIGH" => TaskPriority::High.into(),
        "NORMAL" => TaskPriority::Normal.into(),
        "LOW" => TaskPriority::Low.into(),
        _ => TaskPriority::Unspecified.into(),
    }
}

fn str_to_task_status(s: &str) -> i32 {
    match s {
        "QUEUED" => TaskStatus::Queued.into(),
        "DISPATCHED" => TaskStatus::Dispatched.into(),
        "COMPLETE" => TaskStatus::Complete.into(),
        "FAILED" => TaskStatus::Failed.into(),
        _ => TaskStatus::Unspecified.into(),
    }
}

fn row_to_task(row: &SqliteRow) -> Task {
    let created_at: i64 = row.get("created_at");
    let completed_at: Option<i64> = row.get("completed_at");
    let arguments: Option<Vec<u8>> = row.get("arguments");
    let result: Option<Vec<u8>> = row.get("result");

    Task {
        id: row.get("id"),
        session_id: row.get("session_id"),
        task_type: row.get("task_type"),
        arguments: arguments.unwrap_or_default(),
        priority: str_to_priority(row.get("priority")),
        status: str_to_task_status(row.get("status")),
        created_at: Some(ts(created_at)),
        completed_at: completed_at.map(ts),
        operator_id: row.get("operator_id"),
        result: result.unwrap_or_default(),
    }
}
