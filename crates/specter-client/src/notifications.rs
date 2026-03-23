//! Desktop notifications via terminal bell.
//!
//! Configurable notification level. Triggers a terminal bell ('\x07') for:
//! - New session callback
//! - Session lost / marked dead
//! - High-priority task completion (configurable)

/// Notification priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Default)]
pub enum NotifyLevel {
    /// No notifications.
    Off,
    /// Only critical events (new session, session lost).
    Critical,
    /// Critical + task completion.
    #[default]
    Normal,
    /// All events including task queued.
    Verbose,
}


impl NotifyLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Critical => "CRIT",
            Self::Normal => "NORM",
            Self::Verbose => "VERB",
        }
    }

    /// Cycle to next level.
    pub fn cycle(self) -> Self {
        match self {
            Self::Off => Self::Critical,
            Self::Critical => Self::Normal,
            Self::Normal => Self::Verbose,
            Self::Verbose => Self::Off,
        }
    }
}

/// The kind of event that may trigger a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyEvent {
    NewSession,
    SessionLost,
    TaskComplete,
    TaskFailed,
    TaskQueued,
}

impl NotifyEvent {
    /// The minimum notify level required for this event to fire.
    fn min_level(self) -> NotifyLevel {
        match self {
            Self::NewSession | Self::SessionLost => NotifyLevel::Critical,
            Self::TaskComplete | Self::TaskFailed => NotifyLevel::Normal,
            Self::TaskQueued => NotifyLevel::Verbose,
        }
    }
}

/// Check if a notification should fire and ring the terminal bell if so.
pub fn notify(event: NotifyEvent, level: NotifyLevel) -> bool {
    if level >= event.min_level() && level != NotifyLevel::Off {
        ring_bell();
        true
    } else {
        false
    }
}

/// Ring the terminal bell (BEL character).
fn ring_bell() {
    // Print BEL character to stdout
    print!("\x07");
}

/// Alert ticker state for status bar — scrolling recent events.
#[derive(Debug, Default)]
pub struct AlertTicker {
    pub alerts: Vec<AlertEntry>,
    pub max_alerts: usize,
}

/// A single alert entry.
#[derive(Debug, Clone)]
pub struct AlertEntry {
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event: NotifyEvent,
}

impl AlertTicker {
    pub fn new() -> Self {
        Self {
            alerts: Vec::new(),
            max_alerts: 20,
        }
    }

    /// Push a new alert, trimming old ones.
    pub fn push(&mut self, event: NotifyEvent, message: String) {
        self.alerts.push(AlertEntry {
            message,
            timestamp: chrono::Utc::now(),
            event,
        });
        if self.alerts.len() > self.max_alerts {
            self.alerts.remove(0);
        }
    }

    /// Get the most recent alert message for the status bar ticker.
    pub fn latest(&self) -> Option<&AlertEntry> {
        self.alerts.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_level_default() {
        assert_eq!(NotifyLevel::default(), NotifyLevel::Normal);
    }

    #[test]
    fn test_notify_level_cycle() {
        assert_eq!(NotifyLevel::Off.cycle(), NotifyLevel::Critical);
        assert_eq!(NotifyLevel::Critical.cycle(), NotifyLevel::Normal);
        assert_eq!(NotifyLevel::Normal.cycle(), NotifyLevel::Verbose);
        assert_eq!(NotifyLevel::Verbose.cycle(), NotifyLevel::Off);
    }

    #[test]
    fn test_notify_level_labels() {
        assert_eq!(NotifyLevel::Off.label(), "OFF");
        assert_eq!(NotifyLevel::Critical.label(), "CRIT");
        assert_eq!(NotifyLevel::Normal.label(), "NORM");
        assert_eq!(NotifyLevel::Verbose.label(), "VERB");
    }

    #[test]
    fn test_notify_fires_correctly() {
        // Critical events fire at Critical level
        assert!(notify(NotifyEvent::NewSession, NotifyLevel::Critical));
        assert!(notify(NotifyEvent::SessionLost, NotifyLevel::Critical));
        // Task events don't fire at Critical level
        assert!(!notify(NotifyEvent::TaskComplete, NotifyLevel::Critical));
        // Task events fire at Normal
        assert!(notify(NotifyEvent::TaskComplete, NotifyLevel::Normal));
        assert!(notify(NotifyEvent::TaskFailed, NotifyLevel::Normal));
        // TaskQueued only fires at Verbose
        assert!(!notify(NotifyEvent::TaskQueued, NotifyLevel::Normal));
        assert!(notify(NotifyEvent::TaskQueued, NotifyLevel::Verbose));
        // Nothing fires at Off
        assert!(!notify(NotifyEvent::NewSession, NotifyLevel::Off));
    }

    #[test]
    fn test_alert_ticker() {
        let mut ticker = AlertTicker::new();
        assert!(ticker.latest().is_none());

        ticker.push(NotifyEvent::NewSession, "New session: host-1".into());
        assert_eq!(ticker.latest().unwrap().message, "New session: host-1");
        assert_eq!(ticker.alerts.len(), 1);

        ticker.push(NotifyEvent::TaskComplete, "Task 1 complete".into());
        assert_eq!(ticker.latest().unwrap().message, "Task 1 complete");
        assert_eq!(ticker.alerts.len(), 2);
    }

    #[test]
    fn test_alert_ticker_max_size() {
        let mut ticker = AlertTicker {
            alerts: Vec::new(),
            max_alerts: 3,
        };
        ticker.push(NotifyEvent::NewSession, "a".into());
        ticker.push(NotifyEvent::NewSession, "b".into());
        ticker.push(NotifyEvent::NewSession, "c".into());
        ticker.push(NotifyEvent::NewSession, "d".into());
        assert_eq!(ticker.alerts.len(), 3);
        assert_eq!(ticker.alerts[0].message, "b");
    }
}
