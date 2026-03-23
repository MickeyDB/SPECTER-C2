//! Modal input system — Vim-style keybinding modes for the TUI.
//!
//! Modes:
//! - **Normal**: Session navigation, panel switching, quick actions.
//! - **Command**: `:` prompt for ex-style commands.
//! - **Search**: `/` prompt for fuzzy session search.
//! - **Insert**: Console input for interacting with a session.

use std::fmt;

/// The four Vim-style input modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum InputMode {
    /// Default mode — navigate sessions, switch panels, trigger actions.
    #[default]
    Normal,
    /// `:` command prompt — type a command, Enter executes, Escape cancels.
    Command,
    /// `/` search prompt — fuzzy match sessions, n/N next/prev, Escape cancels.
    Search,
    /// Console input — interact with the active session (type commands, view output).
    Insert,
}


impl fmt::Display for InputMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "NORMAL"),
            Self::Command => write!(f, "COMMAND"),
            Self::Search => write!(f, "SEARCH"),
            Self::Insert => write!(f, "INSERT"),
        }
    }
}

/// State for the `:` command prompt (Command mode).
#[derive(Debug, Default)]
pub struct CommandPrompt {
    pub input: String,
    pub cursor: usize,
}

impl CommandPrompt {
    pub fn clear(&mut self) {
        self.input.clear();
        self.cursor = 0;
    }

    pub fn insert_char(&mut self, ch: char) {
        self.input.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.input.remove(self.cursor);
        }
    }

    pub fn delete_char(&mut self) {
        if self.cursor < self.input.len() {
            self.input.remove(self.cursor);
        }
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.input.len() {
            self.cursor += 1;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.input.len();
    }

    /// Take the input, clearing the prompt. Returns the trimmed string.
    pub fn take(&mut self) -> String {
        let val = self.input.trim().to_string();
        self.clear();
        val
    }
}

/// State for the `/` search prompt (Search mode).
#[derive(Debug, Default)]
pub struct SearchState {
    pub query: String,
    pub cursor: usize,
    /// Indices into the session list that match the current query.
    pub matches: Vec<usize>,
    /// Current position within `matches`.
    pub match_index: usize,
}

impl SearchState {
    pub fn clear(&mut self) {
        self.query.clear();
        self.cursor = 0;
        self.matches.clear();
        self.match_index = 0;
    }

    pub fn insert_char(&mut self, ch: char) {
        self.query.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.query.remove(self.cursor);
        }
    }

    pub fn delete_char(&mut self) {
        if self.cursor < self.query.len() {
            self.query.remove(self.cursor);
        }
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.query.len() {
            self.cursor += 1;
        }
    }

    /// Advance to the next match (wraps around).
    pub fn next_match(&mut self) {
        if !self.matches.is_empty() {
            self.match_index = (self.match_index + 1) % self.matches.len();
        }
    }

    /// Go to the previous match (wraps around).
    pub fn prev_match(&mut self) {
        if !self.matches.is_empty() {
            self.match_index = self
                .match_index
                .checked_sub(1)
                .unwrap_or(self.matches.len() - 1);
        }
    }

    /// Get the currently selected session index, if any.
    pub fn current_match(&self) -> Option<usize> {
        self.matches.get(self.match_index).copied()
    }

    /// Update matches by fuzzy-matching against session fields.
    /// Each entry is (session_index). Matches hostname, username, IP, or ID prefix.
    pub fn update_matches(&mut self, sessions: &[specter_common::proto::specter::v1::SessionInfo]) {
        self.matches.clear();
        if self.query.is_empty() {
            self.match_index = 0;
            return;
        }

        let query_lower = self.query.to_lowercase();
        for (i, session) in sessions.iter().enumerate() {
            if session.hostname.to_lowercase().contains(&query_lower)
                || session.username.to_lowercase().contains(&query_lower)
                || session.internal_ip.to_lowercase().contains(&query_lower)
                || session.external_ip.to_lowercase().contains(&query_lower)
                || session.id.to_lowercase().starts_with(&query_lower)
            {
                self.matches.push(i);
            }
        }

        // Clamp match_index
        if self.match_index >= self.matches.len() {
            self.match_index = 0;
        }
    }
}

/// Whether to show the keybinding cheatsheet overlay.
#[derive(Debug, Default)]
pub struct CheatsheetState {
    pub visible: bool,
}

impl CheatsheetState {
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_mode_display() {
        assert_eq!(InputMode::Normal.to_string(), "NORMAL");
        assert_eq!(InputMode::Command.to_string(), "COMMAND");
        assert_eq!(InputMode::Search.to_string(), "SEARCH");
        assert_eq!(InputMode::Insert.to_string(), "INSERT");
    }

    #[test]
    fn test_input_mode_default() {
        assert_eq!(InputMode::default(), InputMode::Normal);
    }

    #[test]
    fn test_command_prompt_insert_and_cursor() {
        let mut prompt = CommandPrompt::default();
        prompt.insert_char('h');
        prompt.insert_char('e');
        prompt.insert_char('l');
        assert_eq!(prompt.input, "hel");
        assert_eq!(prompt.cursor, 3);
        prompt.move_left();
        assert_eq!(prompt.cursor, 2);
        prompt.insert_char('X');
        assert_eq!(prompt.input, "heXl");
    }

    #[test]
    fn test_command_prompt_backspace_delete() {
        let mut prompt = CommandPrompt::default();
        prompt.input = "abc".to_string();
        prompt.cursor = 2;
        prompt.backspace();
        assert_eq!(prompt.input, "ac");
        assert_eq!(prompt.cursor, 1);
        prompt.delete_char();
        assert_eq!(prompt.input, "a");
    }

    #[test]
    fn test_command_prompt_home_end() {
        let mut prompt = CommandPrompt::default();
        prompt.input = "hello".to_string();
        prompt.cursor = 3;
        prompt.home();
        assert_eq!(prompt.cursor, 0);
        prompt.end();
        assert_eq!(prompt.cursor, 5);
    }

    #[test]
    fn test_command_prompt_take() {
        let mut prompt = CommandPrompt::default();
        prompt.input = "  help shell  ".to_string();
        prompt.cursor = 14;
        let val = prompt.take();
        assert_eq!(val, "help shell");
        assert!(prompt.input.is_empty());
        assert_eq!(prompt.cursor, 0);
    }

    #[test]
    fn test_search_state_matches() {
        let mut state = SearchState::default();
        state.query = "host".to_string();

        let sessions = vec![
            specter_common::proto::specter::v1::SessionInfo {
                id: "abc123".into(),
                hostname: "my-host-1".into(),
                username: "admin".into(),
                pid: 1,
                internal_ip: "10.0.0.1".into(),
                ..Default::default()
            },
            specter_common::proto::specter::v1::SessionInfo {
                id: "def456".into(),
                hostname: "server-2".into(),
                username: "root".into(),
                pid: 2,
                internal_ip: "10.0.0.2".into(),
                ..Default::default()
            },
            specter_common::proto::specter::v1::SessionInfo {
                id: "ghi789".into(),
                hostname: "host-3".into(),
                username: "user".into(),
                pid: 3,
                internal_ip: "10.0.0.3".into(),
                ..Default::default()
            },
        ];

        state.update_matches(&sessions);
        assert_eq!(state.matches, vec![0, 2]); // "my-host-1" and "host-3"
        assert_eq!(state.current_match(), Some(0));

        state.next_match();
        assert_eq!(state.current_match(), Some(2));

        state.next_match();
        assert_eq!(state.current_match(), Some(0)); // wraps

        state.prev_match();
        assert_eq!(state.current_match(), Some(2));
    }

    #[test]
    fn test_search_state_empty_query() {
        let mut state = SearchState::default();
        let sessions = vec![specter_common::proto::specter::v1::SessionInfo {
            id: "abc".into(),
            hostname: "host".into(),
            ..Default::default()
        }];
        state.update_matches(&sessions);
        assert!(state.matches.is_empty());
        assert_eq!(state.current_match(), None);
    }

    #[test]
    fn test_search_state_no_matches() {
        let mut state = SearchState::default();
        state.query = "zzzzz".to_string();
        let sessions = vec![specter_common::proto::specter::v1::SessionInfo {
            id: "abc".into(),
            hostname: "host".into(),
            ..Default::default()
        }];
        state.update_matches(&sessions);
        assert!(state.matches.is_empty());
    }

    #[test]
    fn test_search_next_prev_empty() {
        let mut state = SearchState::default();
        // Should not panic on empty
        state.next_match();
        state.prev_match();
        assert_eq!(state.current_match(), None);
    }

    #[test]
    fn test_cheatsheet_toggle() {
        let mut cs = CheatsheetState::default();
        assert!(!cs.visible);
        cs.toggle();
        assert!(cs.visible);
        cs.toggle();
        assert!(!cs.visible);
    }
}
