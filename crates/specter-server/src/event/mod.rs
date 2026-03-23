pub mod webhooks;

use specter_common::proto::specter::v1::{ChatMessage, PresenceUpdate, SessionEvent, TaskEvent};
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
pub enum SpecterEvent {
    SessionNew(SessionEvent),
    SessionCheckin(SessionEvent),
    SessionLost(SessionEvent),
    TaskQueued(TaskEvent),
    TaskComplete(TaskEvent),
    TaskFailed(TaskEvent),
    PresenceUpdate(PresenceUpdate),
    ChatMessage(ChatMessage),
    Generic { message: String },
}

pub struct EventBus {
    sender: broadcast::Sender<SpecterEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: SpecterEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SpecterEvent> {
        self.sender.subscribe()
    }
}
