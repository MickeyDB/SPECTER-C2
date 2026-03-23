//! Integration tests for context-aware tab completion and history search.

use specter_client::commands::completion::{
    apply_completion, generate_completions, CompletionState,
};
use specter_client::commands::history::{PersistentHistory, ReverseSearchState};
use specter_client::commands::CommandRegistry;

use specter_common::proto::specter::v1::SessionInfo;

fn make_registry() -> CommandRegistry {
    CommandRegistry::new()
}

fn make_sessions() -> Vec<SessionInfo> {
    vec![
        SessionInfo {
            id: "abc12345-0000-0000-0000-000000000001".to_string(),
            hostname: "target-alpha".to_string(),
            username: "admin".to_string(),
            pid: 1234,
            ..Default::default()
        },
        SessionInfo {
            id: "def67890-0000-0000-0000-000000000002".to_string(),
            hostname: "target-beta".to_string(),
            username: "root".to_string(),
            pid: 5678,
            ..Default::default()
        },
        SessionInfo {
            id: "aaa11111-0000-0000-0000-000000000003".to_string(),
            hostname: "dc01.corp.local".to_string(),
            username: "SYSTEM".to_string(),
            pid: 4,
            ..Default::default()
        },
    ]
}

// ── Command name completion ─────────────────────────────────────────────────

#[test]
fn empty_input_shows_all_commands_truncated() {
    let state = generate_completions("", &make_registry(), &make_sessions());
    assert!(state.visible);
    assert!(!state.items.is_empty());
    assert!(state.items.len() <= 5);
}

#[test]
fn partial_command_shows_matches() {
    let state = generate_completions("sh", &make_registry(), &make_sessions());
    assert!(state.visible);
    assert!(state.items.contains(&"shell".to_string()));
}

#[test]
fn partial_s_shows_multiple_matches() {
    let state = generate_completions("s", &make_registry(), &make_sessions());
    assert!(state.visible);
    // "sessions", "shell", "sleep" all start with "s"
    assert!(state.items.len() >= 3);
}

#[test]
fn exact_command_hides_popup() {
    let state = generate_completions("whoami", &make_registry(), &make_sessions());
    assert!(!state.visible);
}

#[test]
fn no_matching_command_hides_popup() {
    let state = generate_completions("zzz", &make_registry(), &make_sessions());
    assert!(!state.visible);
}

// ── Session completion (use command) ────────────────────────────────────────

#[test]
fn use_completes_all_sessions() {
    let state = generate_completions("use ", &make_registry(), &make_sessions());
    assert!(state.visible);
    assert_eq!(state.items.len(), 3);
}

#[test]
fn use_filters_by_hostname_prefix() {
    let state = generate_completions("use target-a", &make_registry(), &make_sessions());
    assert!(state.visible);
    assert_eq!(state.items, vec!["target-alpha".to_string()]);
}

#[test]
fn use_filters_by_id_prefix() {
    let state = generate_completions("use abc", &make_registry(), &make_sessions());
    assert!(state.visible);
    assert!(state.items.contains(&"target-alpha".to_string()));
}

#[test]
fn use_no_matching_session_hides_popup() {
    let state = generate_completions("use zzz", &make_registry(), &make_sessions());
    assert!(!state.visible);
}

#[test]
fn use_empty_sessions_hides_popup() {
    let state = generate_completions("use ", &make_registry(), &[]);
    assert!(!state.visible);
}

// ── Sleep interval completion ───────────────────────────────────────────────

#[test]
fn sleep_shows_all_intervals() {
    let state = generate_completions("sleep ", &make_registry(), &make_sessions());
    assert!(state.visible);
    // All 8 intervals start with "" so all match, but truncated to 5
    assert!(state.items.len() <= 5);
}

#[test]
fn sleep_filters_by_prefix() {
    let state = generate_completions("sleep 3", &make_registry(), &make_sessions());
    assert!(state.visible);
    assert!(state.items.contains(&"30".to_string()));
    assert!(state.items.contains(&"300".to_string()));
    assert!(state.items.contains(&"3600".to_string()));
    assert!(!state.items.contains(&"1".to_string()));
}

#[test]
fn sleep_exact_value_no_match_if_no_prefix() {
    let state = generate_completions("sleep 999", &make_registry(), &make_sessions());
    assert!(!state.visible);
}

// ── Other command completion ────────────────────────────────────────────────

#[test]
fn download_returns_no_completions() {
    let state = generate_completions("download ", &make_registry(), &make_sessions());
    assert!(!state.visible);
}

#[test]
fn unknown_command_arg_returns_no_completions() {
    let state = generate_completions("whoami foo", &make_registry(), &make_sessions());
    assert!(!state.visible);
}

// ── CompletionState cycling ─────────────────────────────────────────────────

#[test]
fn cycle_next_wraps_around() {
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
    assert_eq!(state.selected_item(), Some("a")); // wrapped
}

#[test]
fn cycle_prev_wraps_around() {
    let mut state = CompletionState {
        items: vec!["a".into(), "b".into(), "c".into()],
        selected: 0,
        visible: true,
        prefix: String::new(),
    };
    state.select_prev();
    assert_eq!(state.selected_item(), Some("c")); // wrapped backward
}

#[test]
fn cycle_on_empty_items_is_safe() {
    let mut state = CompletionState::default();
    state.select_next(); // should not panic
    state.select_prev();
    assert_eq!(state.selected_item(), None);
}

#[test]
fn close_clears_state() {
    let mut state = CompletionState {
        items: vec!["a".into(), "b".into()],
        selected: 1,
        visible: true,
        prefix: "test".into(),
    };
    state.close();
    assert!(!state.visible);
    assert!(state.items.is_empty());
    assert_eq!(state.selected, 0);
    assert!(state.prefix.is_empty());
}

// ── Apply completion ────────────────────────────────────────────────────────

#[test]
fn apply_command_completion_adds_trailing_space() {
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
fn apply_argument_completion_replaces_arg() {
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
fn apply_with_no_selection_returns_none() {
    let state = CompletionState::default();
    assert!(apply_completion("test", &state).is_none());
}

#[test]
fn apply_second_item_selected() {
    let mut state = CompletionState {
        items: vec![
            "sessions".to_string(),
            "shell".to_string(),
            "sleep".to_string(),
        ],
        selected: 0,
        visible: true,
        prefix: "s".to_string(),
    };
    state.select_next(); // now selected = 1 (shell)
    let (new_input, _) = apply_completion("s", &state).unwrap();
    assert_eq!(new_input, "shell ");
}

// ── Persistent history ──────────────────────────────────────────────────────

#[test]
fn history_push_and_retrieve() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("whoami");
    hist.push("ps");
    hist.push("ls");
    assert_eq!(hist.len(), 3);
    assert_eq!(hist.entries(), &["whoami", "ps", "ls"]);
}

#[test]
fn history_deduplicates_consecutive() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("whoami");
    hist.push("whoami");
    hist.push("ps");
    hist.push("ps");
    hist.push("whoami"); // not consecutive with previous whoami
    assert_eq!(hist.len(), 3);
    assert_eq!(hist.entries(), &["whoami", "ps", "whoami"]);
}

#[test]
fn history_ignores_empty_and_whitespace() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("");
    hist.push("   ");
    hist.push("\t");
    assert!(hist.is_empty());
}

#[test]
fn history_trims_input() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("  whoami  ");
    assert_eq!(hist.entries(), &["whoami"]);
}

#[test]
fn history_max_entries_enforced() {
    let mut hist = PersistentHistory::in_memory();
    for i in 0..1050 {
        hist.push(&format!("cmd-{i}"));
    }
    assert_eq!(hist.len(), 1000);
    assert_eq!(hist.entries()[0], "cmd-50");
    assert_eq!(hist.entries()[999], "cmd-1049");
}

#[test]
fn history_load_into_buffer() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("a");
    hist.push("b");
    hist.push("c");
    let mut buf = vec!["old".to_string()];
    hist.load_into(&mut buf);
    assert_eq!(buf, vec!["a", "b", "c"]);
}

// ── Reverse search ──────────────────────────────────────────────────────────

#[test]
fn reverse_search_finds_matching_entries() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("shell whoami");
    hist.push("ps");
    hist.push("shell ipconfig");
    hist.push("ls");

    let results = hist.reverse_search("shell");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].1, "shell ipconfig"); // most recent first
    assert_eq!(results[1].1, "shell whoami");
}

#[test]
fn reverse_search_case_insensitive() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("Shell Whoami");
    hist.push("SHELL IPCONFIG");

    let results = hist.reverse_search("shell");
    assert_eq!(results.len(), 2);
}

#[test]
fn reverse_search_empty_query_returns_empty() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("cmd");
    assert!(hist.reverse_search("").is_empty());
}

#[test]
fn reverse_search_no_match_returns_empty() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("whoami");
    assert!(hist.reverse_search("zzz").is_empty());
}

#[test]
fn reverse_search_partial_match() {
    let mut hist = PersistentHistory::in_memory();
    hist.push("shell ipconfig /all");
    hist.push("download file.txt");

    let results = hist.reverse_search("ip");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, "shell ipconfig /all");
}

// ── ReverseSearchState ──────────────────────────────────────────────────────

#[test]
fn reverse_search_state_lifecycle() {
    let mut state = ReverseSearchState::default();
    assert!(!state.active);

    state.open();
    assert!(state.active);
    assert!(state.query.is_empty());

    state.insert_char('s');
    state.insert_char('h');
    assert_eq!(state.query, "sh");
    assert_eq!(state.cursor, 2);

    let mut hist = PersistentHistory::in_memory();
    hist.push("shell whoami");
    hist.push("ps");
    hist.push("shell ipconfig");

    state.update(&hist);
    assert_eq!(state.current_match, Some("shell ipconfig".to_string()));

    state.next_match(&hist);
    assert_eq!(state.current_match, Some("shell whoami".to_string()));

    // Next match beyond end stays at last
    state.next_match(&hist);
    assert_eq!(state.current_match, Some("shell whoami".to_string()));

    state.close();
    assert!(!state.active);
    assert!(state.query.is_empty());
    assert!(state.current_match.is_none());
}

#[test]
fn reverse_search_state_backspace() {
    let mut state = ReverseSearchState::default();
    state.open();
    state.insert_char('a');
    state.insert_char('b');
    assert_eq!(state.query, "ab");

    state.backspace();
    assert_eq!(state.query, "a");
    assert_eq!(state.cursor, 1);

    state.backspace();
    assert_eq!(state.query, "");
    assert_eq!(state.cursor, 0);

    // Backspace on empty is safe
    state.backspace();
    assert_eq!(state.cursor, 0);
}

#[test]
fn reverse_search_state_insert_resets_match_index() {
    let mut state = ReverseSearchState::default();
    state.open();
    state.insert_char('s');
    state.match_index = 5; // simulate navigating to older match
    state.insert_char('h'); // new char should reset
    assert_eq!(state.match_index, 0);
}

#[test]
fn reverse_search_state_no_matches() {
    let mut state = ReverseSearchState::default();
    state.open();
    state.insert_char('z');

    let hist = PersistentHistory::in_memory();
    state.update(&hist);
    assert!(state.current_match.is_none());

    state.next_match(&hist);
    assert!(state.current_match.is_none());
}
