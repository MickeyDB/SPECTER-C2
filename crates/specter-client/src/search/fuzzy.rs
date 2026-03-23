//! Character-by-character fuzzy matching with scoring.
//!
//! Scores are computed based on:
//! - Consecutive character matches (bonus)
//! - Word boundary matches (bonus)
//! - Start-of-string matches (bonus)
//! - Earlier match positions score higher

/// A single fuzzy match result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzyMatch {
    /// Index of the matched item in the source list.
    pub index: usize,
    /// Score (higher is better).
    pub score: i32,
    /// Byte positions in the haystack where pattern chars matched.
    pub positions: Vec<usize>,
}

/// Perform fuzzy matching of `pattern` against `haystack`.
///
/// Returns `None` if not all pattern characters are found in order.
/// Returns `Some(score, positions)` on match.
pub fn fuzzy_match(pattern: &str, haystack: &str) -> Option<(i32, Vec<usize>)> {
    if pattern.is_empty() {
        return Some((0, Vec::new()));
    }

    let pattern_lower: Vec<char> = pattern.to_lowercase().chars().collect();
    let haystack_chars: Vec<char> = haystack.chars().collect();
    let haystack_lower: Vec<char> = haystack.to_lowercase().chars().collect();

    if pattern_lower.len() > haystack_lower.len() {
        return None;
    }

    // Find the best match using a greedy-with-backtrack approach.
    // Try starting from each possible position of the first char.
    let mut best_score = None;
    let mut best_positions = Vec::new();

    for start in 0..haystack_lower.len() {
        if haystack_lower[start] != pattern_lower[0] {
            continue;
        }
        if let Some((score, positions)) =
            try_match_from(&pattern_lower, &haystack_chars, &haystack_lower, start)
        {
            if best_score.is_none() || score > best_score.unwrap() {
                best_score = Some(score);
                best_positions = positions;
            }
        }
    }

    best_score.map(|score| (score, best_positions))
}

fn try_match_from(
    pattern: &[char],
    haystack: &[char],
    haystack_lower: &[char],
    start: usize,
) -> Option<(i32, Vec<usize>)> {
    let mut positions = Vec::with_capacity(pattern.len());
    let mut pi = 0;
    let mut hi = start;

    while pi < pattern.len() && hi < haystack_lower.len() {
        if haystack_lower[hi] == pattern[pi] {
            positions.push(hi);
            pi += 1;
        }
        hi += 1;
    }

    if pi < pattern.len() {
        return None;
    }

    let score = compute_score(&positions, haystack, haystack_lower);
    Some((score, positions))
}

fn compute_score(positions: &[usize], haystack: &[char], haystack_lower: &[char]) -> i32 {
    let mut score: i32 = 0;

    for (i, &pos) in positions.iter().enumerate() {
        // Base: each matched char is worth 1 point
        score += 1;

        // Bonus: consecutive match (previous match was pos-1)
        if i > 0 && positions[i - 1] == pos - 1 {
            score += 8;
        }

        // Bonus: word boundary (start of string, or previous char is separator)
        if pos == 0 {
            score += 10;
        } else {
            let prev = haystack_lower[pos - 1];
            if is_separator(prev) {
                score += 5;
            } else if prev.is_lowercase() && haystack[pos].is_uppercase() {
                // camelCase boundary
                score += 4;
            }
        }

        // Note: exact case match bonus is not applied because the pattern
        // is lowercased during matching. The other bonuses (consecutive,
        // word boundary, camelCase) provide sufficient ranking.
    }

    // Penalty: later start position
    if let Some(&first) = positions.first() {
        score -= first as i32;
    }

    // Bonus: tighter grouping (less spread)
    if positions.len() > 1 {
        let spread = positions.last().unwrap() - positions.first().unwrap();
        let min_spread = positions.len() - 1;
        let extra_spread = spread - min_spread;
        score -= extra_spread as i32;
    }

    score
}

fn is_separator(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '_' | '/' | '\\' | '.' | ':' | '@')
}

/// Fuzzy-match a pattern against a list of items, returning sorted results.
///
/// Each item has a `label` (what to match against) and an `index` (original position).
/// Results are sorted by score descending.
pub fn fuzzy_search(pattern: &str, items: &[(usize, &str)]) -> Vec<FuzzyMatch> {
    if pattern.is_empty() {
        return items
            .iter()
            
            .map(|&(index, _)| FuzzyMatch {
                index,
                score: 0,
                positions: Vec::new(),
            })
            .collect();
    }

    let mut results: Vec<FuzzyMatch> = items
        .iter()
        .filter_map(|&(index, label)| {
            fuzzy_match(pattern, label).map(|(score, positions)| FuzzyMatch {
                index,
                score,
                positions,
            })
        })
        .collect();

    results.sort_by(|a, b| b.score.cmp(&a.score));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let (score, positions) = fuzzy_match("hello", "hello").unwrap();
        assert_eq!(positions, vec![0, 1, 2, 3, 4]);
        assert!(score > 0);
    }

    #[test]
    fn test_prefix_match() {
        let result = fuzzy_match("hel", "hello world");
        assert!(result.is_some());
        let (_, positions) = result.unwrap();
        assert_eq!(positions, vec![0, 1, 2]);
    }

    #[test]
    fn test_sparse_match() {
        let result = fuzzy_match("hlo", "hello");
        assert!(result.is_some());
        let (_, positions) = result.unwrap();
        assert_eq!(positions, vec![0, 2, 4]);
    }

    #[test]
    fn test_no_match() {
        assert!(fuzzy_match("xyz", "hello").is_none());
    }

    #[test]
    fn test_case_insensitive() {
        let result = fuzzy_match("HELLO", "hello world");
        assert!(result.is_some());
    }

    #[test]
    fn test_empty_pattern() {
        let result = fuzzy_match("", "anything");
        assert!(result.is_some());
        let (score, positions) = result.unwrap();
        assert_eq!(score, 0);
        assert!(positions.is_empty());
    }

    #[test]
    fn test_pattern_longer_than_haystack() {
        assert!(fuzzy_match("toolong", "hi").is_none());
    }

    #[test]
    fn test_word_boundary_bonus() {
        // "sh" should score higher on "shell" than on "crash"
        let (score_shell, _) = fuzzy_match("sh", "shell").unwrap();
        let (score_crash, _) = fuzzy_match("sh", "crash").unwrap();
        assert!(score_shell > score_crash);
    }

    #[test]
    fn test_consecutive_bonus() {
        // "abc" consecutive in "abc" should score higher than spread in "a_b_c"
        let (score_consec, _) = fuzzy_match("abc", "abc").unwrap();
        let (score_spread, _) = fuzzy_match("abc", "a_b_c").unwrap();
        assert!(score_consec > score_spread);
    }

    #[test]
    fn test_fuzzy_search_sorted() {
        let items = vec![(0, "download"), (1, "upload"), (2, "shell"), (3, "sleep")];
        let results = fuzzy_search("sl", &items);
        // "shell" and "sleep" should match; "sleep" has "sl" at start
        assert!(results.iter().any(|r| r.index == 3)); // sleep
        assert!(results.iter().any(|r| r.index == 2)); // shell
                                                       // "sleep" should rank higher (starts with "sl")
        let sleep_pos = results.iter().position(|r| r.index == 3).unwrap();
        let shell_pos = results.iter().position(|r| r.index == 2).unwrap();
        assert!(sleep_pos < shell_pos);
    }

    #[test]
    fn test_fuzzy_search_empty_pattern() {
        let items = vec![(0, "a"), (1, "b")];
        let results = fuzzy_search("", &items);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_separator_bonus() {
        // "u" after separator should score higher
        let (score1, _) = fuzzy_match("u", "file-upload").unwrap();
        let (score2, _) = fuzzy_match("u", "result").unwrap();
        assert!(score1 > score2);
    }
}
