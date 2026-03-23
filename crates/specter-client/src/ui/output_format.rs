//! Rich output formatting for the console.
//!
//! - JSON pretty-printing with syntax highlighting
//! - Hex dump for binary output
//! - Large output pagination with `-- More --` prompt
#![allow(dead_code)]
//! - Table formatting for structured output (process lists, file listings)

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Detect the format of output content and return formatted lines.
pub fn format_output(content: &str) -> Vec<Line<'_>> {
    if looks_like_json(content) {
        format_json(content)
    } else if looks_like_hex(content) {
        // Already hex-formatted, just style it
        format_hex_styled(content)
    } else if looks_like_table(content) {
        format_table(content)
    } else {
        vec![Line::from(Span::styled(
            content,
            Style::default().fg(Color::White),
        ))]
    }
}

/// Format raw bytes as a hex dump.
/// Format: `OFFSET | HH HH HH ... | ASCII`
pub fn hex_dump(data: &[u8]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let bytes_per_line = 16;

    for (chunk_idx, chunk) in data.chunks(bytes_per_line).enumerate() {
        let offset = chunk_idx * bytes_per_line;
        let mut spans = Vec::new();

        // Address
        spans.push(Span::styled(
            format!("{offset:08x}  "),
            Style::default().fg(Color::DarkGray),
        ));

        // Hex bytes
        let mut hex_part = String::new();
        for (i, byte) in chunk.iter().enumerate() {
            hex_part.push_str(&format!("{byte:02x} "));
            if i == 7 {
                hex_part.push(' ');
            }
        }
        // Pad if less than 16 bytes
        let expected_len = bytes_per_line * 3 + 1; // "xx " * 16 + extra space at 8
        while hex_part.len() < expected_len {
            hex_part.push(' ');
        }
        spans.push(Span::styled(hex_part, Style::default().fg(Color::Yellow)));

        // Separator
        spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));

        // ASCII
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        spans.push(Span::styled(ascii, Style::default().fg(Color::Green)));

        lines.push(Line::from(spans));
    }

    lines
}

/// Pretty-print JSON with syntax highlighting.
/// Keys: cyan, strings: green, numbers: yellow, booleans: magenta, null: red.
pub fn format_json(content: &str) -> Vec<Line<'_>> {
    // Try to parse and re-format; if that fails, return as-is
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);
    match parsed {
        Ok(value) => {
            let pretty =
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| content.to_string());
            pretty
                .lines()
                .map(highlight_json_line)
                .collect()
        }
        Err(_) => vec![Line::from(Span::styled(
            content,
            Style::default().fg(Color::White),
        ))],
    }
}

/// Apply JSON syntax highlighting to a single line.
fn highlight_json_line(line: &str) -> Line<'static> {
    let owned = line.to_string();
    let trimmed = owned.trim();
    let indent_len = owned.len() - owned.trim_start().len();
    let indent = " ".repeat(indent_len);

    let mut spans = vec![Span::styled(indent, Style::default())];

    if trimmed.is_empty() {
        return Line::from(spans);
    }

    // Simple token-based highlighting
    let mut chars = trimmed.chars().peekable();
    let mut current = String::new();

    while let Some(&ch) = chars.peek() {
        match ch {
            '"' => {
                if !current.is_empty() {
                    spans.push(classify_span(&current));
                    current.clear();
                }
                // Read the whole string
                let mut s = String::new();
                s.push(chars.next().unwrap()); // opening "
                let mut escaped = false;
                for ch in chars.by_ref() {
                    s.push(ch);
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        break;
                    }
                }

                // Check if this is a key (followed by ':')
                let remaining: String = chars.clone().collect();
                let remaining_trimmed = remaining.trim_start();
                if remaining_trimmed.starts_with(':') {
                    spans.push(Span::styled(s, Style::default().fg(Color::Cyan)));
                } else {
                    spans.push(Span::styled(s, Style::default().fg(Color::Green)));
                }
            }
            '{' | '}' | '[' | ']' | ':' | ',' => {
                if !current.is_empty() {
                    spans.push(classify_span(&current));
                    current.clear();
                }
                spans.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(Color::White),
                ));
                chars.next();
            }
            ' ' => {
                if !current.is_empty() {
                    spans.push(classify_span(&current));
                    current.clear();
                }
                spans.push(Span::styled(" ", Style::default()));
                chars.next();
            }
            _ => {
                current.push(chars.next().unwrap());
            }
        }
    }

    if !current.is_empty() {
        spans.push(classify_span(&current));
    }

    Line::from(spans)
}

/// Classify a non-string JSON token by type.
fn classify_span(token: &str) -> Span<'static> {
    let trimmed = token.trim();
    if trimmed == "true" || trimmed == "false" {
        Span::styled(token.to_string(), Style::default().fg(Color::Magenta))
    } else if trimmed == "null" {
        Span::styled(
            token.to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::DIM),
        )
    } else if trimmed.parse::<f64>().is_ok() {
        Span::styled(token.to_string(), Style::default().fg(Color::Yellow))
    } else {
        Span::styled(token.to_string(), Style::default().fg(Color::White))
    }
}

/// Style pre-formatted hex dump content.
fn format_hex_styled(content: &str) -> Vec<Line<'_>> {
    content
        .lines()
        .map(|line| {
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Yellow),
            ))
        })
        .collect()
}

/// Format tabular data with aligned columns.
pub fn format_table(content: &str) -> Vec<Line<'static>> {
    let rows: Vec<Vec<String>> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| line.split_whitespace().map(|s| s.to_string()).collect())
        .collect();

    if rows.is_empty() {
        return vec![Line::from(Span::styled(
            content.to_string(),
            Style::default().fg(Color::White),
        ))];
    }

    // Calculate column widths
    let col_count = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut widths = vec![0usize; col_count];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut lines = Vec::new();
    for (row_idx, row) in rows.iter().enumerate() {
        let mut spans = Vec::new();
        for (i, cell) in row.iter().enumerate() {
            let width = widths.get(i).copied().unwrap_or(cell.len());
            let style = if row_idx == 0 {
                // Header row
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            spans.push(Span::styled(format!("{:<width$}  ", cell), style));
        }
        lines.push(Line::from(spans));

        // Separator after header
        if row_idx == 0 {
            let total_width: usize = widths.iter().sum::<usize>() + (col_count * 2);
            lines.push(Line::from(Span::styled(
                "─".repeat(total_width),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    lines
}

/// Pagination state for large outputs.
#[derive(Debug, Default)]
pub struct PaginationState {
    pub active: bool,
    pub content_lines: Vec<String>,
    pub current_offset: usize,
    pub page_size: usize,
}

impl PaginationState {
    /// Start paginating a large output.
    pub fn start(&mut self, content: String, page_size: usize) {
        self.content_lines = content.lines().map(|l| l.to_string()).collect();
        self.current_offset = 0;
        self.page_size = page_size;
        self.active = !self.content_lines.is_empty();
    }

    /// Get the current page of lines.
    pub fn current_page(&self) -> &[String] {
        let end = (self.current_offset + self.page_size).min(self.content_lines.len());
        &self.content_lines[self.current_offset..end]
    }

    /// Advance to the next page. Returns false if we've reached the end.
    pub fn next_page(&mut self) -> bool {
        let next = self.current_offset + self.page_size;
        if next < self.content_lines.len() {
            self.current_offset = next;
            true
        } else {
            self.active = false;
            false
        }
    }

    /// Whether there are more pages.
    pub fn has_more(&self) -> bool {
        self.current_offset + self.page_size < self.content_lines.len()
    }

    /// Close pagination.
    pub fn close(&mut self) {
        self.active = false;
        self.content_lines.clear();
        self.current_offset = 0;
    }

    /// Total number of pages.
    pub fn total_pages(&self) -> usize {
        if self.page_size == 0 {
            return 0;
        }
        self.content_lines.len().div_ceil(self.page_size)
    }

    /// Current page number (1-based).
    pub fn current_page_num(&self) -> usize {
        if self.page_size == 0 {
            return 0;
        }
        self.current_offset / self.page_size + 1
    }
}

/// The pagination threshold (lines) — outputs longer than this trigger pagination.
pub const PAGINATION_THRESHOLD: usize = 100;

// ── Detection heuristics ─────────────────────────────────────────────

fn looks_like_json(content: &str) -> bool {
    let trimmed = content.trim();
    (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
}

fn looks_like_hex(content: &str) -> bool {
    // Check if the first line matches hex dump format: 8 hex chars followed by spaces and hex bytes
    content
        .lines()
        .next()
        .map(|line| {
            let trimmed = line.trim();
            trimmed.len() > 10
                && trimmed[..8].chars().all(|c| c.is_ascii_hexdigit())
                && trimmed.as_bytes().get(8) == Some(&b' ')
        })
        .unwrap_or(false)
}

fn looks_like_table(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return false;
    }

    // Check if most lines have a consistent number of whitespace-separated columns
    let col_counts: Vec<usize> = lines.iter().map(|l| l.split_whitespace().count()).collect();
    let first = col_counts[0];

    // At least 2 columns, and most rows have the same count
    first >= 2 && col_counts.iter().filter(|&&c| c == first).count() * 2 >= col_counts.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump_basic() {
        let data = b"Hello, World!";
        let lines = hex_dump(data);
        assert_eq!(lines.len(), 1);
        let text: String = lines[0]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(text.contains("00000000"));
        assert!(text.contains("Hello, World!"));
    }

    #[test]
    fn test_hex_dump_multiline() {
        let data = vec![0u8; 32];
        let lines = hex_dump(&data);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_hex_dump_non_printable() {
        let data = vec![0x00, 0x01, 0xff, 0x41]; // NUL, SOH, 0xFF, 'A'
        let lines = hex_dump(&data);
        let text: String = lines[0]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(text.contains("...A"));
    }

    #[test]
    fn test_format_json_valid() {
        let json = r#"{"key": "value", "num": 42, "ok": true}"#;
        let lines = format_json(json);
        assert!(lines.len() > 1); // Pretty-printed = multiple lines
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(text.contains("key"));
        assert!(text.contains("value"));
    }

    #[test]
    fn test_format_json_invalid() {
        let content = "not json at all";
        let lines = format_json(content);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_format_table_basic() {
        let content = "PID  NAME  STATUS\n123  bash  running\n456  vim   running\n";
        let lines = format_table(content);
        // Header + separator + 2 data rows
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_looks_like_json() {
        assert!(looks_like_json(r#"{"key": "val"}"#));
        assert!(looks_like_json(r#"[1, 2, 3]"#));
        assert!(!looks_like_json("hello world"));
        assert!(!looks_like_json(""));
    }

    #[test]
    fn test_looks_like_hex() {
        assert!(looks_like_hex("00000000  48 65 6c 6c  | Hell"));
        assert!(!looks_like_hex("hello world"));
    }

    #[test]
    fn test_looks_like_table() {
        assert!(looks_like_table("A B C\n1 2 3\n4 5 6\n"));
        assert!(!looks_like_table("just a single line"));
        assert!(!looks_like_table("one\ntwo\nthree\n"));
    }

    #[test]
    fn test_pagination_basic() {
        let mut state = PaginationState::default();
        let content = (0..50)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        state.start(content, 20);

        assert!(state.active);
        assert_eq!(state.total_pages(), 3);
        assert_eq!(state.current_page_num(), 1);
        assert_eq!(state.current_page().len(), 20);
        assert!(state.has_more());

        assert!(state.next_page());
        assert_eq!(state.current_page_num(), 2);

        assert!(state.next_page());
        assert_eq!(state.current_page_num(), 3);
        assert_eq!(state.current_page().len(), 10);
        assert!(!state.has_more());

        assert!(!state.next_page());
        assert!(!state.active);
    }

    #[test]
    fn test_pagination_close() {
        let mut state = PaginationState::default();
        state.start("a\nb\nc".to_string(), 2);
        assert!(state.active);
        state.close();
        assert!(!state.active);
        assert!(state.content_lines.is_empty());
    }

    #[test]
    fn test_classify_span_types() {
        let bool_span = classify_span("true");
        assert_eq!(bool_span.style.fg, Some(Color::Magenta));

        let null_span = classify_span("null");
        assert_eq!(null_span.style.fg, Some(Color::Red));

        let num_span = classify_span("42");
        assert_eq!(num_span.style.fg, Some(Color::Yellow));

        let other_span = classify_span("random");
        assert_eq!(other_span.style.fg, Some(Color::White));
    }

    #[test]
    fn test_format_output_auto_detect() {
        // JSON
        let json_lines = format_output(r#"{"a": 1}"#);
        assert!(json_lines.len() >= 1);

        // Plain text
        let plain_lines = format_output("hello world");
        assert_eq!(plain_lines.len(), 1);
    }
}
