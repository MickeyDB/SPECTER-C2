use chrono::{DateTime, Utc};
use specter_common::proto::specter::v1::SessionInfo;

use crate::commands::completion::CompletionState;
use crate::commands::history::{PersistentHistory, ReverseSearchState};
use crate::commands::CommandRegistry;
use crate::input::{CheatsheetState, CommandPrompt, InputMode, SearchState};
use crate::notifications::{AlertTicker, NotifyLevel};
use crate::ui::output_format::PaginationState;
use crate::ui::palette::PaletteState;
use crate::ui::session_graph::{PivotLink, SessionGraphState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePanel {
    SessionList,
    MainPanel,
    ContextPanel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextTab {
    Info,
    Process,
    Tasks,
    Network,
}

impl ContextTab {
    pub const ALL: [ContextTab; 4] = [
        ContextTab::Info,
        ContextTab::Process,
        ContextTab::Tasks,
        ContextTab::Network,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Process => "Process",
            Self::Tasks => "Tasks",
            Self::Network => "Network",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::Info => Self::Process,
            Self::Process => Self::Tasks,
            Self::Tasks => Self::Network,
            Self::Network => Self::Network,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Info => Self::Info,
            Self::Process => Self::Info,
            Self::Tasks => Self::Process,
            Self::Network => Self::Tasks,
        }
    }
}

/// A recorded task for the Tasks tab in the context panel.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TaskRecord {
    pub id: u64,
    pub task_type: String,
    pub status: TaskRecordStatus,
    pub submitted: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub operator: String,
    pub output: Option<String>,
    pub session_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TaskRecordStatus {
    Pending,
    Running,
    Complete,
    Failed,
}

impl TaskRecordStatus {
    pub fn icon(self) -> &'static str {
        match self {
            Self::Pending => "⏳",
            Self::Running => "▶",
            Self::Complete => "✓",
            Self::Failed => "✗",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineKind {
    Input,
    Output,
    Error,
    System,
    TaskQueued,
    TaskComplete,
    TaskFailed,
}

#[derive(Debug, Clone)]
pub struct ConsoleLine {
    pub timestamp: DateTime<Utc>,
    pub kind: LineKind,
    pub content: String,
    pub session_id: Option<String>,
}

impl ConsoleLine {
    pub fn new(kind: LineKind, content: String) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
            content,
            session_id: None,
        }
    }

    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

#[allow(dead_code)]
pub struct App {
    pub sessions: Vec<SessionInfo>,
    pub selected_index: usize,
    pub connection_status: ConnectionStatus,
    pub active_panel: ActivePanel,
    pub server_addr: String,
    pub should_quit: bool,

    // Modal input state
    pub input_mode: InputMode,
    pub command_prompt: CommandPrompt,
    pub search_state: SearchState,
    pub cheatsheet: CheatsheetState,

    // Console state
    pub console_input: String,
    pub console_cursor: usize,
    pub console_output: Vec<ConsoleLine>,
    pub console_scroll: usize,
    pub console_focused: bool,
    pub console_history: Vec<String>,
    pub history_index: Option<usize>,
    pub command_registry: CommandRegistry,
    /// The session ID currently being interacted with in the console.
    pub active_session_id: Option<String>,

    // Command palette
    pub palette: PaletteState,

    // Context panel tabs
    pub context_tab: ContextTab,
    pub task_records: Vec<TaskRecord>,
    pub task_scroll: usize,
    pub next_task_id: u64,

    // Tab completion
    pub completion: CompletionState,

    // Persistent history
    pub persistent_history: PersistentHistory,

    // Reverse search (Ctrl-R)
    pub reverse_search: ReverseSearchState,

    // Session graph overlay (Ctrl-G)
    pub session_graph: SessionGraphState,
    pub pivot_links: Vec<PivotLink>,

    // Output pagination
    pub pagination: PaginationState,

    // Notifications
    pub notify_level: NotifyLevel,
    pub alert_ticker: AlertTicker,

    // Status bar enhancements
    pub show_utc_time: bool,
    pub connected_operators: u32,

    // Collaboration: operator presence
    pub operator_presence: Vec<OperatorPresenceEntry>,

    // Collaboration: chat panel
    pub chat_visible: bool,
    pub chat_messages: Vec<ChatEntry>,
    pub chat_input: String,
    pub chat_cursor: usize,
    pub chat_scroll: usize,
}

/// Lightweight presence entry for display in the TUI.
#[derive(Debug, Clone)]
pub struct OperatorPresenceEntry {
    pub username: String,
    pub active_session: String,
    pub status: OperatorPresenceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorPresenceStatus {
    Online,
    Idle,
    Offline,
}

impl OperatorPresenceEntry {
    pub fn display(&self) -> String {
        if self.active_session.is_empty() {
            match self.status {
                OperatorPresenceStatus::Online => self.username.clone(),
                OperatorPresenceStatus::Idle => format!("{} (idle)", self.username),
                OperatorPresenceStatus::Offline => format!("{} (offline)", self.username),
            }
        } else {
            // Show first 8 chars of session ID
            let short_session = if self.active_session.len() > 8 {
                &self.active_session[..8]
            } else {
                &self.active_session
            };
            format!("{} ({})", self.username, short_session)
        }
    }
}

/// Chat message entry for the TUI chat panel.
#[derive(Debug, Clone)]
pub struct ChatEntry {
    pub sender: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl App {
    pub fn new(server_addr: String) -> Self {
        Self {
            sessions: Vec::new(),
            selected_index: 0,
            connection_status: ConnectionStatus::Disconnected,
            active_panel: ActivePanel::SessionList,
            server_addr,
            should_quit: false,
            input_mode: InputMode::default(),
            command_prompt: CommandPrompt::default(),
            search_state: SearchState::default(),
            cheatsheet: CheatsheetState::default(),
            console_input: String::new(),
            console_cursor: 0,
            console_output: Vec::new(),
            console_scroll: 0,
            console_focused: false,
            console_history: Vec::new(),
            history_index: None,
            command_registry: CommandRegistry::new(),
            active_session_id: None,
            palette: PaletteState::default(),
            context_tab: ContextTab::Info,
            task_records: Vec::new(),
            task_scroll: 0,
            next_task_id: 1,
            completion: CompletionState::default(),
            persistent_history: PersistentHistory::new(),
            reverse_search: ReverseSearchState::default(),
            session_graph: SessionGraphState::default(),
            pivot_links: Vec::new(),
            pagination: PaginationState::default(),
            notify_level: NotifyLevel::default(),
            alert_ticker: AlertTicker::new(),
            show_utc_time: true,
            connected_operators: 1,
            operator_presence: Vec::new(),
            chat_visible: false,
            chat_messages: Vec::new(),
            chat_input: String::new(),
            chat_cursor: 0,
            chat_scroll: 0,
        }
    }

    /// Record a new task for the Tasks tab.
    #[allow(dead_code)]
    pub fn record_task(&mut self, task_type: String, session_id: String) -> u64 {
        let id = self.next_task_id;
        self.next_task_id += 1;
        self.task_records.push(TaskRecord {
            id,
            task_type,
            status: TaskRecordStatus::Pending,
            submitted: Utc::now(),
            completed: None,
            operator: "operator".to_string(),
            output: None,
            session_id,
        });
        id
    }

    pub fn next_session(&mut self) {
        if !self.sessions.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.sessions.len();
        }
    }

    pub fn prev_session(&mut self) {
        if !self.sessions.is_empty() {
            self.selected_index = self
                .selected_index
                .checked_sub(1)
                .unwrap_or(self.sessions.len() - 1);
        }
    }

    pub fn first_session(&mut self) {
        self.selected_index = 0;
    }

    pub fn last_session(&mut self) {
        if !self.sessions.is_empty() {
            self.selected_index = self.sessions.len() - 1;
        }
    }

    pub fn selected_session(&self) -> Option<&SessionInfo> {
        self.sessions.get(self.selected_index)
    }

    pub fn update_sessions(&mut self, sessions: Vec<SessionInfo>) {
        self.sessions = sessions;
        if self.selected_index >= self.sessions.len() {
            self.selected_index = self.sessions.len().saturating_sub(1);
        }
    }

    pub fn cycle_panel(&mut self) {
        self.active_panel = match self.active_panel {
            ActivePanel::SessionList => ActivePanel::MainPanel,
            ActivePanel::MainPanel => ActivePanel::ContextPanel,
            ActivePanel::ContextPanel => ActivePanel::SessionList,
        };
    }

    // ── Console methods ─────────────────────────────────────────────

    pub fn console_insert_char(&mut self, ch: char) {
        self.console_input.insert(self.console_cursor, ch);
        self.console_cursor += ch.len_utf8();
    }

    pub fn console_delete_char(&mut self) {
        if self.console_cursor < self.console_input.len() {
            self.console_input.remove(self.console_cursor);
        }
    }

    pub fn console_backspace(&mut self) {
        if self.console_cursor > 0 {
            self.console_cursor -= 1;
            self.console_input.remove(self.console_cursor);
        }
    }

    pub fn console_move_left(&mut self) {
        self.console_cursor = self.console_cursor.saturating_sub(1);
    }

    pub fn console_move_right(&mut self) {
        if self.console_cursor < self.console_input.len() {
            self.console_cursor += 1;
        }
    }

    pub fn console_home(&mut self) {
        self.console_cursor = 0;
    }

    pub fn console_end(&mut self) {
        self.console_cursor = self.console_input.len();
    }

    pub fn console_word_left(&mut self) {
        if self.console_cursor == 0 {
            return;
        }
        let bytes = self.console_input.as_bytes();
        let mut pos = self.console_cursor - 1;
        // Skip whitespace
        while pos > 0 && bytes[pos] == b' ' {
            pos -= 1;
        }
        // Skip word characters
        while pos > 0 && bytes[pos - 1] != b' ' {
            pos -= 1;
        }
        self.console_cursor = pos;
    }

    pub fn console_word_right(&mut self) {
        let len = self.console_input.len();
        if self.console_cursor >= len {
            return;
        }
        let bytes = self.console_input.as_bytes();
        let mut pos = self.console_cursor;
        // Skip current word
        while pos < len && bytes[pos] != b' ' {
            pos += 1;
        }
        // Skip whitespace
        while pos < len && bytes[pos] == b' ' {
            pos += 1;
        }
        self.console_cursor = pos;
    }

    pub fn console_submit(&mut self) -> Option<String> {
        let input = self.console_input.trim().to_string();
        if input.is_empty() {
            return None;
        }
        // Add to in-memory history
        if self.console_history.last().map(|s| s.as_str()) != Some(&input) {
            self.console_history.push(input.clone());
        }
        // Persist to disk
        self.persistent_history.push(&input);
        // Close completion popup if open
        self.completion.close();
        self.history_index = None;
        self.console_input.clear();
        self.console_cursor = 0;
        self.console_scroll = 0;
        Some(input)
    }

    pub fn console_history_up(&mut self) {
        if self.console_history.is_empty() {
            return;
        }
        let idx = match self.history_index {
            None => self.console_history.len() - 1,
            Some(0) => return,
            Some(i) => i - 1,
        };
        self.history_index = Some(idx);
        self.console_input = self.console_history[idx].clone();
        self.console_cursor = self.console_input.len();
    }

    pub fn console_history_down(&mut self) {
        match self.history_index {
            None => (),
            Some(i) => {
                if i + 1 >= self.console_history.len() {
                    self.history_index = None;
                    self.console_input.clear();
                    self.console_cursor = 0;
                } else {
                    self.history_index = Some(i + 1);
                    self.console_input = self.console_history[i + 1].clone();
                    self.console_cursor = self.console_input.len();
                }
            }
        }
    }

    pub fn console_scroll_up(&mut self, lines: usize) {
        let max_scroll = self.console_output.len().saturating_sub(1);
        self.console_scroll = (self.console_scroll + lines).min(max_scroll);
    }

    pub fn console_scroll_down(&mut self, lines: usize) {
        self.console_scroll = self.console_scroll.saturating_sub(lines);
    }

    pub fn console_append(&mut self, line: ConsoleLine) {
        self.console_output.push(line);
        // Auto-scroll to bottom when not manually scrolled
        if self.console_scroll == 0 {
            // Already at bottom, nothing to do
        }
    }

    pub fn console_clear(&mut self) {
        self.console_output.clear();
        self.console_scroll = 0;
    }

    /// Enter console interaction mode for the currently selected session.
    pub fn enter_console(&mut self) {
        if let Some(session) = self.selected_session() {
            let session_id = session.id.clone();
            let hostname = session.hostname.clone();
            self.active_session_id = Some(session_id.clone());
            self.console_focused = true;
            self.input_mode = InputMode::Insert;
            self.active_panel = ActivePanel::MainPanel;
            self.console_append(ConsoleLine::new(
                LineKind::System,
                format!(
                    "Interacting with session {} ({})",
                    &session_id[..8.min(session_id.len())],
                    hostname
                ),
            ));
        }
    }

    /// Leave console interaction mode.
    pub fn exit_console(&mut self) {
        self.console_focused = false;
        self.input_mode = InputMode::Normal;
        self.active_session_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use specter_common::proto::specter::v1::SessionStatus;

    fn make_session(id: &str, hostname: &str) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            hostname: hostname.to_string(),
            username: "testuser".to_string(),
            pid: 1234,
            os_version: String::new(),
            integrity_level: String::new(),
            process_name: String::new(),
            internal_ip: String::new(),
            external_ip: String::new(),
            last_checkin: None,
            first_seen: None,
            status: SessionStatus::Active.into(),
            active_channel: String::new(),
        }
    }

    #[test]
    fn test_next_session_wraps() {
        let mut app = App::new("test".to_string());
        app.update_sessions(vec![
            make_session("1", "host-a"),
            make_session("2", "host-b"),
        ]);
        assert_eq!(app.selected_index, 0);
        app.next_session();
        assert_eq!(app.selected_index, 1);
        app.next_session();
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn test_prev_session_wraps() {
        let mut app = App::new("test".to_string());
        app.update_sessions(vec![
            make_session("1", "host-a"),
            make_session("2", "host-b"),
        ]);
        assert_eq!(app.selected_index, 0);
        app.prev_session();
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn test_first_last_session() {
        let mut app = App::new("test".to_string());
        app.update_sessions(vec![
            make_session("1", "a"),
            make_session("2", "b"),
            make_session("3", "c"),
        ]);
        app.last_session();
        assert_eq!(app.selected_index, 2);
        app.first_session();
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn test_selected_session() {
        let mut app = App::new("test".to_string());
        assert!(app.selected_session().is_none());
        app.update_sessions(vec![make_session("1", "host-a")]);
        assert_eq!(app.selected_session().unwrap().id, "1");
    }

    #[test]
    fn test_update_sessions_clamps_index() {
        let mut app = App::new("test".to_string());
        app.update_sessions(vec![
            make_session("1", "a"),
            make_session("2", "b"),
            make_session("3", "c"),
        ]);
        app.selected_index = 2;
        app.update_sessions(vec![make_session("1", "a")]);
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn test_cycle_panel() {
        let mut app = App::new("test".to_string());
        assert_eq!(app.active_panel, ActivePanel::SessionList);
        app.cycle_panel();
        assert_eq!(app.active_panel, ActivePanel::MainPanel);
        app.cycle_panel();
        assert_eq!(app.active_panel, ActivePanel::ContextPanel);
        app.cycle_panel();
        assert_eq!(app.active_panel, ActivePanel::SessionList);
    }

    #[test]
    fn test_navigation_on_empty() {
        let mut app = App::new("test".to_string());
        app.next_session();
        assert_eq!(app.selected_index, 0);
        app.prev_session();
        assert_eq!(app.selected_index, 0);
        app.last_session();
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn test_console_insert_and_cursor() {
        let mut app = App::new("test".to_string());
        app.console_insert_char('h');
        app.console_insert_char('i');
        assert_eq!(app.console_input, "hi");
        assert_eq!(app.console_cursor, 2);
        app.console_move_left();
        assert_eq!(app.console_cursor, 1);
        app.console_insert_char('X');
        assert_eq!(app.console_input, "hXi");
    }

    #[test]
    fn test_console_backspace_delete() {
        let mut app = App::new("test".to_string());
        app.console_input = "abc".to_string();
        app.console_cursor = 2;
        app.console_backspace();
        assert_eq!(app.console_input, "ac");
        assert_eq!(app.console_cursor, 1);
        app.console_delete_char();
        assert_eq!(app.console_input, "a");
    }

    #[test]
    fn test_console_home_end() {
        let mut app = App::new("test".to_string());
        app.console_input = "hello".to_string();
        app.console_cursor = 3;
        app.console_home();
        assert_eq!(app.console_cursor, 0);
        app.console_end();
        assert_eq!(app.console_cursor, 5);
    }

    #[test]
    fn test_console_word_jump() {
        let mut app = App::new("test".to_string());
        app.console_input = "hello world foo".to_string();
        app.console_cursor = 0;
        app.console_word_right();
        assert_eq!(app.console_cursor, 6);
        app.console_word_right();
        assert_eq!(app.console_cursor, 12);
        app.console_word_left();
        assert_eq!(app.console_cursor, 6);
    }

    #[test]
    fn test_console_submit_and_history() {
        let mut app = App::new("test".to_string());
        app.console_input = "whoami".to_string();
        app.console_cursor = 6;
        let result = app.console_submit();
        assert_eq!(result, Some("whoami".to_string()));
        assert!(app.console_input.is_empty());
        assert_eq!(app.console_cursor, 0);
        assert_eq!(app.console_history, vec!["whoami"]);

        // Empty submit returns None
        assert!(app.console_submit().is_none());
    }

    #[test]
    fn test_console_history_navigation() {
        let mut app = App::new("test".to_string());
        app.console_history = vec!["cmd1".to_string(), "cmd2".to_string(), "cmd3".to_string()];

        app.console_history_up();
        assert_eq!(app.console_input, "cmd3");
        app.console_history_up();
        assert_eq!(app.console_input, "cmd2");
        app.console_history_down();
        assert_eq!(app.console_input, "cmd3");
        app.console_history_down();
        assert!(app.console_input.is_empty());
    }

    #[test]
    fn test_console_scroll() {
        let mut app = App::new("test".to_string());
        for i in 0..20 {
            app.console_append(ConsoleLine::new(LineKind::Output, format!("line {i}")));
        }
        assert_eq!(app.console_scroll, 0);
        app.console_scroll_up(5);
        assert_eq!(app.console_scroll, 5);
        app.console_scroll_down(3);
        assert_eq!(app.console_scroll, 2);
        app.console_scroll_down(10);
        assert_eq!(app.console_scroll, 0);
    }

    #[test]
    fn test_enter_exit_console() {
        let mut app = App::new("test".to_string());
        app.update_sessions(vec![make_session("abcdef12", "target-host")]);
        app.enter_console();
        assert!(app.console_focused);
        assert_eq!(app.active_session_id, Some("abcdef12".to_string()));
        assert_eq!(app.active_panel, ActivePanel::MainPanel);
        assert_eq!(app.console_output.len(), 1);

        app.exit_console();
        assert!(!app.console_focused);
        assert!(app.active_session_id.is_none());
    }
}
