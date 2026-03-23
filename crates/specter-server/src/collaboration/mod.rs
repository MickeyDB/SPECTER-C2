pub mod chat;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use specter_common::proto::specter::v1::{OperatorStatus, PresenceInfo, PresenceUpdate};

use crate::event::{EventBus, SpecterEvent};

/// Tracks connected operators and their active sessions.
pub struct PresenceManager {
    /// operator_id → PresenceInfo
    state: RwLock<HashMap<String, PresenceInfo>>,
    event_bus: Arc<EventBus>,
}

impl PresenceManager {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            event_bus,
        }
    }

    /// Register an operator as connected.
    pub async fn operator_connected(&self, operator_id: &str, username: &str) {
        let now = chrono::Utc::now();
        let presence = PresenceInfo {
            operator_id: operator_id.to_string(),
            username: username.to_string(),
            status: OperatorStatus::Online.into(),
            active_session_id: String::new(),
            last_activity: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: 0,
            }),
        };

        self.state
            .write()
            .await
            .insert(operator_id.to_string(), presence.clone());

        let update = PresenceUpdate {
            event_type: "connected".to_string(),
            presence: Some(presence),
            timestamp: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: 0,
            }),
        };
        self.event_bus.publish(SpecterEvent::PresenceUpdate(update));
    }

    /// Mark an operator as disconnected.
    pub async fn operator_disconnected(&self, operator_id: &str) {
        let now = chrono::Utc::now();
        let presence = {
            let mut state = self.state.write().await;
            if let Some(mut p) = state.remove(operator_id) {
                p.status = OperatorStatus::Offline.into();
                p.last_activity = Some(prost_types::Timestamp {
                    seconds: now.timestamp(),
                    nanos: 0,
                });
                Some(p)
            } else {
                None
            }
        };

        if let Some(presence) = presence {
            let update = PresenceUpdate {
                event_type: "disconnected".to_string(),
                presence: Some(presence),
                timestamp: Some(prost_types::Timestamp {
                    seconds: now.timestamp(),
                    nanos: 0,
                }),
            };
            self.event_bus.publish(SpecterEvent::PresenceUpdate(update));
        }
    }

    /// Update the operator's active session and refresh last_activity.
    pub async fn update_active_session(&self, operator_id: &str, session_id: &str) {
        let now = chrono::Utc::now();
        let mut state = self.state.write().await;
        if let Some(p) = state.get_mut(operator_id) {
            p.active_session_id = session_id.to_string();
            p.status = OperatorStatus::Online.into();
            p.last_activity = Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: 0,
            });

            let update = PresenceUpdate {
                event_type: "active_session".to_string(),
                presence: Some(p.clone()),
                timestamp: Some(prost_types::Timestamp {
                    seconds: now.timestamp(),
                    nanos: 0,
                }),
            };
            self.event_bus.publish(SpecterEvent::PresenceUpdate(update));
        }
    }

    /// Get all currently active operators.
    pub async fn get_active_operators(&self) -> Vec<PresenceInfo> {
        self.state.read().await.values().cloned().collect()
    }

    /// Get the count of currently connected operators.
    pub async fn active_count(&self) -> usize {
        self.state.read().await.len()
    }

    /// Mark idle operators (no activity for `idle_seconds`) as IDLE.
    pub async fn mark_idle(&self, idle_seconds: i64) {
        let now = chrono::Utc::now().timestamp();
        let mut state = self.state.write().await;
        for p in state.values_mut() {
            if p.status == OperatorStatus::Online as i32 {
                if let Some(ref ts) = p.last_activity {
                    if now - ts.seconds > idle_seconds {
                        p.status = OperatorStatus::Idle.into();
                        let update = PresenceUpdate {
                            event_type: "idle".to_string(),
                            presence: Some(p.clone()),
                            timestamp: Some(prost_types::Timestamp {
                                seconds: now,
                                nanos: 0,
                            }),
                        };
                        self.event_bus.publish(SpecterEvent::PresenceUpdate(update));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_presence_connect_disconnect() {
        let bus = Arc::new(EventBus::new(64));
        let pm = PresenceManager::new(bus);

        pm.operator_connected("op1", "alice").await;
        assert_eq!(pm.active_count().await, 1);

        let ops = pm.get_active_operators().await;
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].username, "alice");
        assert_eq!(ops[0].status, OperatorStatus::Online as i32);

        pm.operator_disconnected("op1").await;
        assert_eq!(pm.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_presence_active_session() {
        let bus = Arc::new(EventBus::new(64));
        let pm = PresenceManager::new(bus);

        pm.operator_connected("op1", "alice").await;
        pm.update_active_session("op1", "session-abc").await;

        let ops = pm.get_active_operators().await;
        assert_eq!(ops[0].active_session_id, "session-abc");
    }

    #[tokio::test]
    async fn test_presence_multiple_operators() {
        let bus = Arc::new(EventBus::new(64));
        let pm = PresenceManager::new(bus);

        pm.operator_connected("op1", "alice").await;
        pm.operator_connected("op2", "bob").await;
        assert_eq!(pm.active_count().await, 2);

        pm.operator_disconnected("op1").await;
        assert_eq!(pm.active_count().await, 1);

        let ops = pm.get_active_operators().await;
        assert_eq!(ops[0].username, "bob");
    }

    #[tokio::test]
    async fn test_disconnect_unknown_operator() {
        let bus = Arc::new(EventBus::new(64));
        let pm = PresenceManager::new(bus);

        // Should not panic
        pm.operator_disconnected("nonexistent").await;
        assert_eq!(pm.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_presence_events_published() {
        let bus = Arc::new(EventBus::new(64));
        let mut rx = bus.subscribe();
        let pm = PresenceManager::new(Arc::clone(&bus));

        pm.operator_connected("op1", "alice").await;

        let event = rx.try_recv().unwrap();
        match event {
            SpecterEvent::PresenceUpdate(update) => {
                assert_eq!(update.event_type, "connected");
                assert_eq!(update.presence.unwrap().username, "alice");
            }
            _ => panic!("Expected PresenceUpdate event"),
        }
    }
}
