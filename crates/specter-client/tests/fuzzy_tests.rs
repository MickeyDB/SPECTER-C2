//! Integration tests for fuzzy search matching and ranking.

use specter_client::search::fuzzy::{fuzzy_match, fuzzy_search};

// ── Basic matching ──────────────────────────────────────────────────────────

#[test]
fn exact_match_returns_all_positions_sequential() {
    let (score, positions) = fuzzy_match("shell", "shell").unwrap();
    assert_eq!(positions, vec![0, 1, 2, 3, 4]);
    assert!(score > 0);
}

#[test]
fn prefix_match() {
    let (_, positions) = fuzzy_match("hel", "hello world").unwrap();
    assert_eq!(positions, vec![0, 1, 2]);
}

#[test]
fn suffix_match() {
    let result = fuzzy_match("rld", "hello world");
    assert!(result.is_some());
    let (_, positions) = result.unwrap();
    assert_eq!(*positions.last().unwrap(), 10); // 'd' at index 10
}

#[test]
fn sparse_character_match() {
    let (_, positions) = fuzzy_match("hlo", "hello").unwrap();
    // h(0), l(2 or 3), o(4)
    assert_eq!(positions[0], 0);
    assert_eq!(*positions.last().unwrap(), 4);
}

#[test]
fn no_match_returns_none() {
    assert!(fuzzy_match("xyz", "hello").is_none());
    assert!(fuzzy_match("abc", "def").is_none());
}

#[test]
fn pattern_longer_than_haystack_returns_none() {
    assert!(fuzzy_match("toolongpattern", "hi").is_none());
}

#[test]
fn empty_pattern_matches_anything() {
    let (score, positions) = fuzzy_match("", "anything").unwrap();
    assert_eq!(score, 0);
    assert!(positions.is_empty());
}

#[test]
fn empty_haystack_with_nonempty_pattern_returns_none() {
    assert!(fuzzy_match("a", "").is_none());
}

#[test]
fn single_character_match() {
    let (_, positions) = fuzzy_match("s", "shell").unwrap();
    assert_eq!(positions, vec![0]);
}

#[test]
fn case_insensitive_matching() {
    assert!(fuzzy_match("HELLO", "hello world").is_some());
    assert!(fuzzy_match("hello", "HELLO WORLD").is_some());
    assert!(fuzzy_match("HeLlO", "hElLo").is_some());
}

// ── Scoring and ranking ─────────────────────────────────────────────────────

#[test]
fn consecutive_matches_score_higher_than_spread() {
    let (score_consec, _) = fuzzy_match("abc", "abc").unwrap();
    let (score_spread, _) = fuzzy_match("abc", "a_b_c").unwrap();
    assert!(
        score_consec > score_spread,
        "consecutive ({score_consec}) should beat spread ({score_spread})"
    );
}

#[test]
fn word_boundary_match_scores_higher() {
    // "sh" at start of "shell" vs middle of "crash"
    let (score_start, _) = fuzzy_match("sh", "shell").unwrap();
    let (score_mid, _) = fuzzy_match("sh", "crash").unwrap();
    assert!(
        score_start > score_mid,
        "word-start ({score_start}) should beat mid-word ({score_mid})"
    );
}

#[test]
fn separator_boundary_bonus() {
    // "u" after separator in "file-upload" vs middle of "result"
    let (score_sep, _) = fuzzy_match("u", "file-upload").unwrap();
    let (score_mid, _) = fuzzy_match("u", "result").unwrap();
    assert!(
        score_sep > score_mid,
        "separator boundary ({score_sep}) should beat mid-word ({score_mid})"
    );
}

#[test]
fn earlier_position_scores_higher() {
    // "a" at position 0 vs position 5
    let (score_early, _) = fuzzy_match("a", "apple").unwrap();
    let (score_late, _) = fuzzy_match("a", "zzzzza").unwrap();
    assert!(
        score_early > score_late,
        "earlier match ({score_early}) should beat later ({score_late})"
    );
}

#[test]
fn camel_case_boundary_bonus() {
    // "gn" matching at camelCase boundary in "getName" vs spread in "beginning"
    let result_camel = fuzzy_match("gn", "getName");
    let result_spread = fuzzy_match("gn", "beginning");
    assert!(result_camel.is_some());
    assert!(result_spread.is_some());
    let (score_camel, _) = result_camel.unwrap();
    let (score_spread, _) = result_spread.unwrap();
    assert!(
        score_camel > score_spread,
        "camelCase boundary ({score_camel}) should beat spread ({score_spread})"
    );
}

// ── fuzzy_search function ───────────────────────────────────────────────────

#[test]
fn search_returns_only_matching_items() {
    let items = vec![(0, "shell"), (1, "upload"), (2, "download"), (3, "sleep")];
    let results = fuzzy_search("sh", &items);
    let indices: Vec<usize> = results.iter().map(|r| r.index).collect();
    assert!(indices.contains(&0)); // shell
    assert!(!indices.contains(&1)); // upload - no match
    assert!(!indices.contains(&2)); // download - no match
}

#[test]
fn search_results_sorted_by_score_descending() {
    let items = vec![(0, "download"), (1, "upload"), (2, "shell"), (3, "sleep")];
    let results = fuzzy_search("sl", &items);
    // "sleep" starts with "sl" → higher score than "shell" where s..l is spread
    assert!(!results.is_empty());
    let first = &results[0];
    assert_eq!(first.index, 3, "sleep should rank first for 'sl'");
}

#[test]
fn search_empty_pattern_returns_all_with_zero_score() {
    let items = vec![(0, "a"), (1, "b"), (2, "c")];
    let results = fuzzy_search("", &items);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert_eq!(r.score, 0);
        assert!(r.positions.is_empty());
    }
}

#[test]
fn search_no_matches_returns_empty() {
    let items = vec![(0, "hello"), (1, "world")];
    let results = fuzzy_search("xyz", &items);
    assert!(results.is_empty());
}

#[test]
fn search_preserves_original_indices() {
    let items = vec![(10, "shell"), (20, "sleep"), (30, "upload")];
    let results = fuzzy_search("sl", &items);
    for r in &results {
        assert!(
            r.index == 10 || r.index == 20,
            "unexpected index {}",
            r.index
        );
    }
}

#[test]
fn search_with_single_item() {
    let items = vec![(0, "test")];
    let results = fuzzy_search("t", &items);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].index, 0);
}

// ── Edge cases ──────────────────────────────────────────────────────────────

#[test]
fn match_with_all_separators() {
    // Pattern chars appearing after various separators
    let result = fuzzy_match("abc", "x-a.b_c");
    assert!(result.is_some());
}

#[test]
fn repeated_characters_in_pattern() {
    let result = fuzzy_match("ll", "hello");
    assert!(result.is_some());
    let (_, positions) = result.unwrap();
    assert_eq!(positions.len(), 2);
}

#[test]
fn unicode_characters() {
    // Should handle basic unicode without panicking
    let result = fuzzy_match("a", "café");
    assert!(result.is_some());
}

#[test]
fn very_long_haystack() {
    let long_hay = "a".repeat(500) + "xyz";
    let result = fuzzy_match("xyz", &long_hay);
    assert!(result.is_some());
}

#[test]
fn pattern_equals_haystack_exactly() {
    let (score, positions) = fuzzy_match("test", "test").unwrap();
    assert_eq!(positions.len(), 4);
    assert!(score > 0);
}

#[test]
fn search_ranking_prefers_command_names() {
    // Simulate command palette: searching for "s" should rank "shell" and "sleep" and "sessions"
    let items = vec![
        (0, "cd"),
        (1, "clear"),
        (2, "download"),
        (3, "exit"),
        (4, "help"),
        (5, "jobs"),
        (6, "kill"),
        (7, "ls"),
        (8, "ps"),
        (9, "pwd"),
        (10, "sessions"),
        (11, "shell"),
        (12, "sleep"),
        (13, "upload"),
        (14, "use"),
        (15, "whoami"),
    ];
    let results = fuzzy_search("s", &items);
    // All items containing 's' should match; items starting with 's' should rank highest
    let top_indices: Vec<usize> = results.iter().take(3).map(|r| r.index).collect();
    // sessions, shell, sleep all start with 's'
    assert!(
        top_indices.contains(&10) || top_indices.contains(&11) || top_indices.contains(&12),
        "top results should include commands starting with 's': {:?}",
        top_indices
    );
}
