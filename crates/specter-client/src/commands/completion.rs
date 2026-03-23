//! Context-aware tab completion for the console input.
//!
//! Completion rules:
//! - Empty input → all command names
//! - `upload ` → local file paths
//! - `download ` → cached remote paths (placeholder)
//! - `use ` → session IDs / hostnames
//! - `sleep ` → common intervals
//! - Partial command name → matching command names

use specter_common::proto::specter::v1::SessionInfo;

use super::CommandRegistry;

/// Visible completion state shown as a popup above the input line.
#[derive(Debug, Default)]
pub struct CompletionState {
    /// The list of completions available for the current input context.
    pub items: Vec<String>,
    /// Currently selected index (wraps around).
    pub selected: usize,
    /// Whether the completion popup is visible.
    pub visible: bool,
    /// The prefix that was completed (before cursor).
    pub prefix: String,
}

impl CompletionState {
    pub fn close(&mut self) {
        self.items.clear();
        self.selected = 0;
        self.visible = false;
        self.prefix.clear();
    }

    pub fn select_next(&mut self) {
        if !self.items.is_empty() {
            self.selected = (self.selected + 1) % self.items.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.items.is_empty() {
            self.selected = self.selected.checked_sub(1).unwrap_or(self.items.len() - 1);
        }
    }

    pub fn selected_item(&self) -> Option<&str> {
        self.items.get(self.selected).map(|s| s.as_str())
    }
}

/// Maximum number of completion items to display.
const MAX_COMPLETIONS: usize = 5;

/// Common sleep intervals suggested for the `sleep` command.
const SLEEP_INTERVALS: &[&str] = &["1", "5", "10", "30", "60", "300", "600", "3600"];

/// Generate completions for the given input and cursor position.
///
/// Returns the list of completion strings and the prefix that should be replaced.
pub fn generate_completions(
    input: &str,
    registry: &CommandRegistry,
    sessions: &[SessionInfo],
) -> CompletionState {
    let trimmed = input.trim_start();

    // If input is empty or has no space, complete command names
    if !trimmed.contains(' ') {
        let prefix = trimmed.to_lowercase();
        let mut items: Vec<String> = registry
            .names()
            .into_iter()
            .filter(|name| name.starts_with(&prefix))
            .map(|s| s.to_string())
            .collect();
        items.truncate(MAX_COMPLETIONS);

        if items.is_empty() || (items.len() == 1 && items[0] == prefix) {
            return CompletionState::default();
        }

        return CompletionState {
            items,
            selected: 0,
            visible: true,
            prefix: prefix.to_string(),
        };
    }

    // Input has a space — complete based on the command
    let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let arg_text = parts.get(1).copied().unwrap_or("");

    match cmd.as_str() {
        "use" => {
            let lower = arg_text.to_lowercase();
            let mut items: Vec<String> = sessions
                .iter()
                .filter_map(|s| {
                    let id_prefix = if s.id.len() > 8 { &s.id[..8] } else { &s.id };
                    if s.hostname.to_lowercase().starts_with(&lower)
                        || id_prefix.to_lowercase().starts_with(&lower)
                    {
                        Some(s.hostname.clone())
                    } else {
                        None
                    }
                })
                .collect();
            items.truncate(MAX_COMPLETIONS);

            if items.is_empty() {
                return CompletionState::default();
            }

            CompletionState {
                items,
                selected: 0,
                visible: true,
                prefix: arg_text.to_string(),
            }
        }
        "sleep" => {
            let mut items: Vec<String> = SLEEP_INTERVALS
                .iter()
                .filter(|i| i.starts_with(arg_text))
                .map(|s| s.to_string())
                .collect();
            items.truncate(MAX_COMPLETIONS);

            if items.is_empty() {
                return CompletionState::default();
            }

            CompletionState {
                items,
                selected: 0,
                visible: true,
                prefix: arg_text.to_string(),
            }
        }
        "upload" => {
            // File path completion — list files in the directory prefix
            complete_local_paths(arg_text)
        }
        "download" => {
            // Remote path completion is a placeholder (would need server-side cache)
            CompletionState::default()
        }
        _ => CompletionState::default(),
    }
}

/// Apply the selected completion to the console input.
///
/// Returns the new input string and cursor position.
pub fn apply_completion(input: &str, completion: &CompletionState) -> Option<(String, usize)> {
    let selected = completion.selected_item()?;

    let trimmed = input.trim_start();
    if !trimmed.contains(' ') {
        // Completing a command name — replace the whole input
        let new_input = format!("{} ", selected);
        let cursor = new_input.len();
        Some((new_input, cursor))
    } else {
        // Completing an argument — replace from after the first space
        let space_idx = input.find(' ')?;
        let new_input = format!("{} {}", &input[..space_idx], selected);
        let cursor = new_input.len();
        Some((new_input, cursor))
    }
}

/// Attempt to complete local file paths for upload commands.
fn complete_local_paths(prefix: &str) -> CompletionState {
    use std::path::Path;

    let path = Path::new(prefix);
    let (dir, file_prefix) = if prefix.ends_with('/') || prefix.ends_with('\\') {
        (prefix, "")
    } else {
        match path.parent() {
            Some(parent) => {
                let parent_str = if parent.as_os_str().is_empty() {
                    "."
                } else {
                    parent.to_str().unwrap_or(".")
                };
                let file = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                (parent_str, file)
            }
            None => (".", prefix),
        }
    };

    let Ok(entries) = std::fs::read_dir(dir) else {
        return CompletionState::default();
    };

    let lower_prefix = file_prefix.to_lowercase();
    let mut items: Vec<String> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_str()?.to_string();
            if name.to_lowercase().starts_with(&lower_prefix) {
                let full = if dir == "." {
                    name
                } else {
                    format!("{}/{}", dir.trim_end_matches(['/', '\\']), name)
                };
                Some(full)
            } else {
                None
            }
        })
        .collect();

    items.sort();
    items.truncate(MAX_COMPLETIONS);

    if items.is_empty() {
        return CompletionState::default();
    }

    CompletionState {
        items,
        selected: 0,
        visible: true,
        prefix: prefix.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> CommandRegistry {
        CommandRegistry::new()
    }

    fn make_sessions() -> Vec<SessionInfo> {
        vec![
            SessionInfo {
                id: "abc12345-long-id".to_string(),
                hostname: "target-alpha".to_string(),
                username: "admin".to_string(),
                pid: 1,
                ..Default::default()
            },
            SessionInfo {
                id: "def67890-long-id".to_string(),
                hostname: "target-beta".to_string(),
                username: "root".to_string(),
                pid: 2,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_complete_empty_input() {
        let reg = make_registry();
        let sessions = make_sessions();
        let state = generate_completions("", &reg, &sessions);
        // Empty input should show all commands (truncated to 5)
        assert!(state.visible);
        assert!(!state.items.is_empty());
        assert!(state.items.len() <= 5);
    }

    #[test]
    fn test_complete_partial_command() {
        let reg = make_registry();
        let sessions = make_sessions();
        let state = generate_completions("sh", &reg, &sessions);
        assert!(state.visible);
        assert!(state.items.contains(&"shell".to_string()));
    }

    #[test]
    fn test_complete_exact_command_no_popup() {
        let reg = make_registry();
        let sessions = make_sessions();
        // Typing the exact command name should not show completions
        let state = generate_completions("whoami", &reg, &sessions);
        assert!(!state.visible);
    }

    #[test]
    fn test_complete_use_sessions() {
        let reg = make_registry();
        let sessions = make_sessions();
        let state = generate_completions("use target", &reg, &sessions);
        assert!(state.visible);
        assert_eq!(state.items.len(), 2);
        assert!(state.items.contains(&"target-alpha".to_string()));
        assert!(state.items.contains(&"target-beta".to_string()));
    }

    #[test]
    fn test_complete_use_specific() {
        let reg = make_registry();
        let sessions = make_sessions();
        let state = generate_completions("use target-a", &reg, &sessions);
        assert!(state.visible);
        assert_eq!(state.items, vec!["target-alpha".to_string()]);
    }

    #[test]
    fn test_complete_sleep_intervals() {
        let reg = make_registry();
        let sessions = make_sessions();
        let state = generate_completions("sleep 3", &reg, &sessions);
        assert!(state.visible);
        assert!(state.items.contains(&"30".to_string()));
        assert!(state.items.contains(&"300".to_string()));
        assert!(state.items.contains(&"3600".to_string()));
    }

    #[test]
    fn test_complete_unknown_command_no_completions() {
        let reg = make_registry();
        let sessions = make_sessions();
        let state = generate_completions("whoami arg", &reg, &sessions);
        assert!(!state.visible);
    }

    #[test]
    fn test_apply_completion_command() {
        let state = CompletionState {
            items: vec!["shell".to_string()],
            selected: 0,
            visible: true,
            prefix: "sh".to_string(),
        };
        let (new_input, cursor) = apply_completion("sh", &state).unwrap();
        assert_eq!(new_input, "shell ");
        assert_eq!(cursor, 6);
    }

    #[test]
    fn test_apply_completion_argument() {
        let state = CompletionState {
            items: vec!["target-alpha".to_string()],
            selected: 0,
            visible: true,
            prefix: "target-a".to_string(),
        };
        let (new_input, cursor) = apply_completion("use target-a", &state).unwrap();
        assert_eq!(new_input, "use target-alpha");
        assert_eq!(cursor, 16);
    }

    #[test]
    fn test_completion_state_cycle() {
        let mut state = CompletionState {
            items: vec!["a".into(), "b".into(), "c".into()],
            selected: 0,
            visible: true,
            prefix: String::new(),
        };
        assert_eq!(state.selected_item(), Some("a"));
        state.select_next();
        assert_eq!(state.selected_item(), Some("b"));
        state.select_next();
        assert_eq!(state.selected_item(), Some("c"));
        state.select_next();
        assert_eq!(state.selected_item(), Some("a")); // wraps
        state.select_prev();
        assert_eq!(state.selected_item(), Some("c")); // wraps back
    }

    #[test]
    fn test_completion_close() {
        let mut state = CompletionState {
            items: vec!["a".into()],
            selected: 0,
            visible: true,
            prefix: "a".into(),
        };
        state.close();
        assert!(!state.visible);
        assert!(state.items.is_empty());
    }
}
