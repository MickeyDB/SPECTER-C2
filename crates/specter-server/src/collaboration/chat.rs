use std::sync::Arc;

use sqlx::SqlitePool;

use specter_common::proto::specter::v1::ChatMessage;

use crate::event::{EventBus, SpecterEvent};

/// Manages chat messages with SQLite persistence and event broadcast.
pub struct ChatService {
    pool: SqlitePool,
    event_bus: Arc<EventBus>,
}

impl ChatService {
    pub fn new(pool: SqlitePool, event_bus: Arc<EventBus>) -> Self {
        Self { pool, event_bus }
    }

    /// Send a chat message, persist to DB, and broadcast via event bus.
    pub async fn send_message(
        &self,
        sender_id: &str,
        sender_username: &str,
        content: &str,
        channel: &str,
    ) -> Result<ChatMessage, ChatError> {
        if content.trim().is_empty() {
            return Err(ChatError::EmptyMessage);
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let timestamp_secs = now.timestamp();
        let channel = if channel.is_empty() {
            "global"
        } else {
            channel
        };

        sqlx::query(
            "INSERT INTO chat_messages (id, sender_id, sender_username, content, channel, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(sender_id)
        .bind(sender_username)
        .bind(content)
        .bind(channel)
        .bind(timestamp_secs)
        .execute(&self.pool)
        .await
        .map_err(ChatError::Database)?;

        let msg = ChatMessage {
            id,
            sender_id: sender_id.to_string(),
            sender_username: sender_username.to_string(),
            content: content.to_string(),
            channel: channel.to_string(),
            timestamp: Some(prost_types::Timestamp {
                seconds: timestamp_secs,
                nanos: 0,
            }),
        };

        self.event_bus
            .publish(SpecterEvent::ChatMessage(msg.clone()));

        Ok(msg)
    }

    /// Get chat history for a channel, optionally since a given timestamp, with a limit.
    pub async fn get_messages(
        &self,
        channel: &str,
        since: Option<i64>,
        limit: i32,
    ) -> Result<Vec<ChatMessage>, ChatError> {
        let limit = if limit <= 0 || limit > 500 {
            100
        } else {
            limit
        };
        let since = since.unwrap_or(0);
        let channel = if channel.is_empty() {
            "global"
        } else {
            channel
        };

        let rows = sqlx::query_as::<_, ChatRow>(
            "SELECT id, sender_id, sender_username, content, channel, timestamp
             FROM chat_messages
             WHERE channel = ? AND timestamp >= ?
             ORDER BY timestamp ASC
             LIMIT ?",
        )
        .bind(channel)
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(ChatError::Database)?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ChatRow {
    id: String,
    sender_id: String,
    sender_username: String,
    content: String,
    channel: String,
    timestamp: i64,
}

impl From<ChatRow> for ChatMessage {
    fn from(r: ChatRow) -> Self {
        ChatMessage {
            id: r.id,
            sender_id: r.sender_id,
            sender_username: r.sender_username,
            content: r.content,
            channel: r.channel,
            timestamp: Some(prost_types::Timestamp {
                seconds: r.timestamp,
                nanos: 0,
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Message content cannot be empty")]
    EmptyMessage,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE chat_messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                sender_username TEXT NOT NULL,
                content TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT 'global',
                timestamp INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn test_send_and_get_messages() {
        let pool = setup_test_db().await;
        let bus = Arc::new(EventBus::new(64));
        let chat = ChatService::new(pool, bus);

        let msg = chat
            .send_message("op1", "alice", "Hello team!", "global")
            .await
            .unwrap();
        assert_eq!(msg.sender_username, "alice");
        assert_eq!(msg.content, "Hello team!");
        assert_eq!(msg.channel, "global");

        let msgs = chat.get_messages("global", None, 50).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "Hello team!");
    }

    #[tokio::test]
    async fn test_empty_message_rejected() {
        let pool = setup_test_db().await;
        let bus = Arc::new(EventBus::new(64));
        let chat = ChatService::new(pool, bus);

        let result = chat.send_message("op1", "alice", "  ", "global").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChatError::EmptyMessage));
    }

    #[tokio::test]
    async fn test_channel_isolation() {
        let pool = setup_test_db().await;
        let bus = Arc::new(EventBus::new(64));
        let chat = ChatService::new(pool, bus);

        chat.send_message("op1", "alice", "global msg", "global")
            .await
            .unwrap();
        chat.send_message("op1", "alice", "session msg", "session-123")
            .await
            .unwrap();

        let global = chat.get_messages("global", None, 50).await.unwrap();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].content, "global msg");

        let session = chat.get_messages("session-123", None, 50).await.unwrap();
        assert_eq!(session.len(), 1);
        assert_eq!(session[0].content, "session msg");
    }

    #[tokio::test]
    async fn test_chat_events_published() {
        let pool = setup_test_db().await;
        let bus = Arc::new(EventBus::new(64));
        let mut rx = bus.subscribe();
        let chat = ChatService::new(pool, Arc::clone(&bus));

        chat.send_message("op1", "alice", "test", "global")
            .await
            .unwrap();

        let event = rx.try_recv().unwrap();
        match event {
            SpecterEvent::ChatMessage(msg) => {
                assert_eq!(msg.content, "test");
                assert_eq!(msg.sender_username, "alice");
            }
            _ => panic!("Expected ChatMessage event"),
        }
    }

    #[tokio::test]
    async fn test_get_messages_since() {
        let pool = setup_test_db().await;
        let bus = Arc::new(EventBus::new(64));
        let chat = ChatService::new(pool, bus);

        chat.send_message("op1", "alice", "old msg", "global")
            .await
            .unwrap();

        // Messages with current timestamp should all be returned when since=0
        let msgs = chat.get_messages("global", Some(0), 50).await.unwrap();
        assert_eq!(msgs.len(), 1);

        // Future since should return nothing
        let future = chrono::Utc::now().timestamp() + 3600;
        let msgs = chat.get_messages("global", Some(future), 50).await.unwrap();
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn test_default_channel() {
        let pool = setup_test_db().await;
        let bus = Arc::new(EventBus::new(64));
        let chat = ChatService::new(pool, bus);

        // Empty channel should default to "global"
        let msg = chat.send_message("op1", "alice", "hi", "").await.unwrap();
        assert_eq!(msg.channel, "global");

        let msgs = chat.get_messages("", None, 50).await.unwrap();
        assert_eq!(msgs.len(), 1);
    }
}
