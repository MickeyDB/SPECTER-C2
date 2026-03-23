//! Persistent command history stored at `~/.specter/history`.
//!
//! Supports up to 1000 entries and Ctrl-R reverse incremental search.

use std::fs;
use std::path::PathBuf;

const MAX_HISTORY: usize = 1000;
const HISTORY_DIR: &str = ".specter";
const HISTORY_FILE: &str = "history";

/// Persistent command history backed by a file on disk.
#[derive(Debug)]
pub struct PersistentHistory {
    /// All history entries (oldest first).
    entries: Vec<String>,
    /// Path to the history file.
    path: Option<PathBuf>,
}

impl Default for PersistentHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl PersistentHistory {
    pub fn new() -> Self {
        let path = Self::history_path();
        let entries = path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|content| {
                content
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect()
            })
            .unwrap_or_default();

        Self { entries, path }
    }

    /// Create an in-memory-only history (for testing).
    pub fn in_memory() -> Self {
        Self {
            entries: Vec::new(),
            path: None,
        }
    }

    fn history_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(HISTORY_DIR).join(HISTORY_FILE))
    }

    /// Add a command to history and persist.
    pub fn push(&mut self, cmd: &str) {
        let cmd = cmd.trim().to_string();
        if cmd.is_empty() {
            return;
        }
        // Dedup consecutive entries
        if self.entries.last().map(|s| s.as_str()) == Some(&cmd) {
            return;
        }
        self.entries.push(cmd);
        // Trim to max
        if self.entries.len() > MAX_HISTORY {
            let drain_count = self.entries.len() - MAX_HISTORY;
            self.entries.drain(..drain_count);
        }
        self.save();
    }

    /// Get all entries (oldest first).
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Search backwards from the end for entries containing `query`.
    /// Returns matching entries in reverse order (most recent first).
    pub fn reverse_search(&self, query: &str) -> Vec<(usize, &str)> {
        if query.is_empty() {
            return Vec::new();
        }
        let lower_query = query.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, entry)| entry.to_lowercase().contains(&lower_query))
            .map(|(i, entry)| (i, entry.as_str()))
            .collect()
    }

    /// Save the history to disk.
    fn save(&self) {
        if let Some(ref path) = self.path {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let content = self.entries.join("\n");
            let _ = fs::write(path, content);
        }
    }

    /// Load history entries into the in-memory console_history vec.
    pub fn load_into(&self, console_history: &mut Vec<String>) {
        console_history.clear();
        console_history.extend(self.entries.iter().cloned());
    }
}

/// State for Ctrl-R reverse search overlay.
#[derive(Debug, Default)]
pub struct ReverseSearchState {
    /// Whether reverse search is active.
    pub active: bool,
    /// The current search query.
    pub query: String,
    /// Cursor position in the query.
    pub cursor: usize,
    /// Index into matches (0 = most recent match).
    pub match_index: usize,
    /// The matching entry text (for display).
    pub current_match: Option<String>,
}

impl ReverseSearchState {
    pub fn open(&mut self) {
        self.active = true;
        self.query.clear();
        self.cursor = 0;
        self.match_index = 0;
        self.current_match = None;
    }

    pub fn close(&mut self) {
        self.active = false;
        self.query.clear();
        self.cursor = 0;
        self.match_index = 0;
        self.current_match = None;
    }

    pub fn insert_char(&mut self, ch: char) {
        self.query.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
        self.match_index = 0; // reset to most recent
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.query.remove(self.cursor);
            self.match_index = 0;
        }
    }

    /// Update the current match based on the history and query.
    pub fn update(&mut self, history: &PersistentHistory) {
        let matches = history.reverse_search(&self.query);
        self.current_match = matches
            .get(self.match_index)
            .map(|(_, entry)| entry.to_string());
    }

    /// Move to the next (older) match.
    pub fn next_match(&mut self, history: &PersistentHistory) {
        let matches = history.reverse_search(&self.query);
        if !matches.is_empty() {
            self.match_index = (self.match_index + 1).min(matches.len() - 1);
            self.current_match = matches
                .get(self.match_index)
                .map(|(_, entry)| entry.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_entries() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("whoami");
        hist.push("ps");
        hist.push("ls");
        assert_eq!(hist.len(), 3);
        assert_eq!(hist.entries(), &["whoami", "ps", "ls"]);
    }

    #[test]
    fn test_dedup_consecutive() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("whoami");
        hist.push("whoami");
        hist.push("ps");
        hist.push("ps");
        assert_eq!(hist.len(), 2);
        assert_eq!(hist.entries(), &["whoami", "ps"]);
    }

    #[test]
    fn test_empty_not_added() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("");
        hist.push("   ");
        assert!(hist.is_empty());
    }

    #[test]
    fn test_max_entries() {
        let mut hist = PersistentHistory::in_memory();
        for i in 0..1050 {
            hist.push(&format!("cmd-{i}"));
        }
        assert_eq!(hist.len(), MAX_HISTORY);
        // Oldest entries should have been drained
        assert_eq!(hist.entries()[0], "cmd-50");
        assert_eq!(hist.entries()[MAX_HISTORY - 1], "cmd-1049");
    }

    #[test]
    fn test_reverse_search() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("shell whoami");
        hist.push("ps");
        hist.push("shell ipconfig");
        hist.push("ls");

        let results = hist.reverse_search("shell");
        assert_eq!(results.len(), 2);
        // Most recent first
        assert_eq!(results[0].1, "shell ipconfig");
        assert_eq!(results[1].1, "shell whoami");
    }

    #[test]
    fn test_reverse_search_empty_query() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("cmd1");
        let results = hist.reverse_search("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_reverse_search_no_match() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("cmd1");
        let results = hist.reverse_search("zzz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_load_into() {
        let mut hist = PersistentHistory::in_memory();
        hist.push("a");
        hist.push("b");
        let mut buf = Vec::new();
        hist.load_into(&mut buf);
        assert_eq!(buf, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_reverse_search_state() {
        let mut state = ReverseSearchState::default();
        assert!(!state.active);
        state.open();
        assert!(state.active);
        state.insert_char('s');
        state.insert_char('h');
        assert_eq!(state.query, "sh");

        let mut hist = PersistentHistory::in_memory();
        hist.push("shell whoami");
        hist.push("ps");
        hist.push("shell ipconfig");

        state.update(&hist);
        assert_eq!(state.current_match, Some("shell ipconfig".to_string()));

        state.next_match(&hist);
        assert_eq!(state.current_match, Some("shell whoami".to_string()));

        state.close();
        assert!(!state.active);
        assert!(state.query.is_empty());
    }
}
