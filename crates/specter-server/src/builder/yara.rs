//! YARA scanning for pre-delivery payload validation.
//!
//! Scans every generated payload against YARA rules before delivery. Uses
//! the `yr` (yara-x) or `yara` CLI tool if available on PATH, falling back
//! to a built-in pattern matcher for basic string rules.
//!
//! Matches are returned as warnings so the operator can decide whether to
//! proceed, regenerate with different obfuscation, or abort.

use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("rules directory not found: {0}")]
    RulesDirNotFound(PathBuf),
    #[error("failed to read rule file {path}: {source}")]
    RuleRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("YARA compile error: {0}")]
    Compile(String),
    #[error("YARA scan error: {0}")]
    Scan(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A single YARA rule match against a payload.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Name of the rule that matched.
    pub rule_name: String,
    /// Namespace / source file of the rule.
    pub namespace: String,
    /// Tags associated with the rule.
    pub tags: Vec<String>,
}

/// Scan a payload blob against all YARA rules in the given directory.
///
/// Returns a list of matches. An empty list means the payload is clean.
/// Any `.yar` or `.yara` files in `rules_dir` (non-recursive) are loaded.
///
/// Strategy:
/// 1. Try `yr scan` (yara-x CLI)
/// 2. Try `yara` (classic YARA CLI)
/// 3. Fall back to built-in pattern scanner
pub fn scan_payload(blob: &[u8], rules_dir: &Path) -> Result<Vec<YaraMatch>, YaraError> {
    if !rules_dir.exists() {
        return Err(YaraError::RulesDirNotFound(rules_dir.to_path_buf()));
    }

    let rule_files = collect_rule_files(rules_dir)?;
    if rule_files.is_empty() {
        return Ok(Vec::new());
    }

    // Write payload to a temp file for CLI scanning
    let tmp_dir = std::env::temp_dir();
    let payload_path = tmp_dir.join(format!("specter_yara_scan_{}.bin", std::process::id()));
    std::fs::write(&payload_path, blob)?;

    let result = scan_with_cli(&rule_files, &payload_path).or_else(|_| {
        tracing::debug!("CLI YARA scanner not available, using built-in pattern matcher");
        scan_with_builtin(blob, &rule_files)
    });

    // Clean up temp file
    let _ = std::fs::remove_file(&payload_path);

    result
}

/// Attempt to scan using `yr scan` (yara-x CLI) or `yara` (classic).
fn scan_with_cli(rule_files: &[PathBuf], payload_path: &Path) -> Result<Vec<YaraMatch>, YaraError> {
    // Try yr (yara-x) first, then yara
    for cmd_name in &["yr", "yara"] {
        let args = if *cmd_name == "yr" {
            // yr scan <rules_path> <target>
            let mut a = vec!["scan".to_string()];
            for rf in rule_files {
                a.push(rf.to_string_lossy().into_owned());
            }
            a.push(payload_path.to_string_lossy().into_owned());
            a
        } else {
            // yara <rules_file> <target>
            // Classic yara only takes one rules file, so concatenate
            let mut a = Vec::new();
            for rf in rule_files {
                a.push(rf.to_string_lossy().into_owned());
            }
            a.push(payload_path.to_string_lossy().into_owned());
            a
        };

        match Command::new(cmd_name).args(&args).output() {
            Ok(output) if output.status.success() || output.status.code() == Some(0) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Ok(parse_yara_output(&stdout));
            }
            Ok(output) => {
                // Non-zero exit but ran — could mean matches found (yara exits 0 even with matches)
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    return Ok(parse_yara_output(&stdout));
                }
                // Actual error
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::debug!("{cmd_name} failed: {stderr}");
                continue;
            }
            Err(_) => continue, // binary not found
        }
    }

    Err(YaraError::Scan("no YARA CLI tool available".into()))
}

/// Parse YARA CLI output. Format: `rule_name [tags] target_path`
fn parse_yara_output(output: &str) -> Vec<YaraMatch> {
    let mut matches = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "RuleName target_path" or "RuleName [tag1,tag2] target_path"
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if let Some(&rule_name) = parts.first() {
            matches.push(YaraMatch {
                rule_name: rule_name.to_string(),
                namespace: String::new(),
                tags: Vec::new(),
            });
        }
    }
    matches
}

/// Built-in pattern scanner: parses basic YARA string rules and performs
/// byte-level matching. Supports `$name = "literal"` and `$name = { hex }`
/// patterns with `condition: any of them` or `condition: $specific`.
///
/// This is intentionally simplified — for production use, install `yr` or `yara`.
fn scan_with_builtin(blob: &[u8], rule_files: &[PathBuf]) -> Result<Vec<YaraMatch>, YaraError> {
    let mut matches = Vec::new();

    for path in rule_files {
        let source = std::fs::read_to_string(path).map_err(|e| YaraError::RuleRead {
            path: path.clone(),
            source: e,
        })?;

        let namespace = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default")
            .to_string();

        let parsed = parse_yara_rules(&source);
        for rule in &parsed {
            if rule_matches(blob, rule) {
                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    namespace: namespace.clone(),
                    tags: rule.tags.clone(),
                });
            }
        }
    }

    Ok(matches)
}

// ---------------------------------------------------------------------------
// Built-in YARA rule parser (simplified)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ParsedRule {
    name: String,
    tags: Vec<String>,
    strings: Vec<PatternEntry>,
    condition: RuleCondition,
}

#[derive(Debug)]
struct PatternEntry {
    id: String,
    pattern: Vec<u8>,
}

#[derive(Debug)]
enum RuleCondition {
    AnyOfThem,
    AllOfThem,
    Specific(Vec<String>),
    AlwaysTrue,
}

/// Minimal YARA rule parser supporting `rule Name { strings: ... condition: ... }`.
fn parse_yara_rules(source: &str) -> Vec<ParsedRule> {
    let mut rules = Vec::new();
    let _chars = source.chars().peekable();
    let source_bytes = source.as_bytes();
    let mut pos = 0;

    while pos < source.len() {
        // Skip to next "rule" keyword
        if let Some(idx) = source[pos..].find("rule ") {
            pos += idx;
        } else {
            break;
        }

        // Skip comment blocks before parsing
        let before = &source[..pos];
        if before
            .rfind("/*")
            .map(|s| before[s..].contains("*/"))
            .unwrap_or(true)
        {
            // Not inside a block comment
        }

        pos += 5; // skip "rule "

        // Parse rule name
        let name_start = pos;
        while pos < source.len()
            && (source_bytes[pos].is_ascii_alphanumeric() || source_bytes[pos] == b'_')
        {
            pos += 1;
        }
        let name = source[name_start..pos].trim().to_string();
        if name.is_empty() {
            continue;
        }

        // Skip to opening brace
        let mut tags = Vec::new();
        while pos < source.len() && source_bytes[pos] != b'{' {
            // Check for tags after ':'
            if source_bytes[pos] == b':' {
                pos += 1;
                // Read tags until '{'
                while pos < source.len() && source_bytes[pos] != b'{' {
                    let tag_start = pos;
                    while pos < source.len()
                        && source_bytes[pos] != b'{'
                        && !source_bytes[pos].is_ascii_whitespace()
                    {
                        pos += 1;
                    }
                    let tag = source[tag_start..pos].trim().to_string();
                    if !tag.is_empty() {
                        tags.push(tag);
                    }
                    while pos < source.len() && source_bytes[pos].is_ascii_whitespace() {
                        pos += 1;
                    }
                }
            } else {
                pos += 1;
            }
        }
        if pos >= source.len() {
            break;
        }
        pos += 1; // skip '{'

        // Find matching closing brace (accounting for nesting)
        let body_start = pos;
        let mut depth = 1;
        while pos < source.len() && depth > 0 {
            match source_bytes[pos] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            if depth > 0 {
                pos += 1;
            }
        }
        let body = &source[body_start..pos];
        if pos < source.len() {
            pos += 1; // skip '}'
        }

        // Parse strings section
        let strings = parse_strings_section(body);

        // Parse condition section
        let condition = parse_condition_section(body);

        rules.push(ParsedRule {
            name,
            tags,
            strings,
            condition,
        });
    }

    rules
}

fn parse_strings_section(body: &str) -> Vec<PatternEntry> {
    let mut entries = Vec::new();

    let strings_section = if let Some(idx) = body.find("strings:") {
        let start = idx + 8;
        let end = body[start..]
            .find("condition:")
            .map(|i| start + i)
            .unwrap_or(body.len());
        &body[start..end]
    } else {
        return entries;
    };

    for line in strings_section.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        // Parse: $name = "literal" or $name = { hex bytes }
        if let Some(eq_pos) = line.find('=') {
            let id = line[..eq_pos].trim().to_string();
            let value_part = line[eq_pos + 1..].trim();

            if let Some(pattern) = parse_string_value(value_part) {
                entries.push(PatternEntry { id, pattern });
            }
        }
    }

    entries
}

fn parse_string_value(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();

    // Strip trailing modifiers like "ascii", "wide", "nocase"
    // Quoted string literal
    if let Some(rest) = value.strip_prefix('"') {
        // Find the closing quote
        if let Some(end_quote) = rest.find('"') {
            let literal = &rest[..end_quote];
            // Handle basic escape sequences
            let mut bytes = Vec::new();
            let mut chars = literal.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some('n') => bytes.push(b'\n'),
                        Some('r') => bytes.push(b'\r'),
                        Some('t') => bytes.push(b'\t'),
                        Some('\\') => bytes.push(b'\\'),
                        Some('"') => bytes.push(b'"'),
                        Some('x') => {
                            let h: String = chars.by_ref().take(2).collect();
                            if let Ok(b) = u8::from_str_radix(&h, 16) {
                                bytes.push(b);
                            }
                        }
                        Some(other) => {
                            bytes.push(b'\\');
                            let mut buf = [0u8; 4];
                            bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                        }
                        None => bytes.push(b'\\'),
                    }
                } else {
                    let mut buf = [0u8; 4];
                    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
            return Some(bytes);
        }
    }

    // Hex string: { AA BB CC ... }
    if value.starts_with('{') {
        if let Some(end) = value.find('}') {
            let hex_str = &value[1..end];
            let hex_clean: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hex_clean.len().is_multiple_of(2) {
                let bytes: Result<Vec<u8>, _> = (0..hex_clean.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16))
                    .collect();
                if let Ok(b) = bytes {
                    return Some(b);
                }
            }
        }
    }

    None
}

fn parse_condition_section(body: &str) -> RuleCondition {
    let condition_str = if let Some(idx) = body.find("condition:") {
        body[idx + 10..].trim()
    } else {
        return RuleCondition::AlwaysTrue;
    };

    let cond = condition_str.trim().trim_end_matches('}').trim();

    if cond == "true" {
        RuleCondition::AlwaysTrue
    } else if cond.contains("any of them") {
        RuleCondition::AnyOfThem
    } else if cond.contains("all of them") {
        RuleCondition::AllOfThem
    } else if cond.starts_with('$') {
        // Simple: condition references specific string variables
        let vars: Vec<String> = cond
            .split(|c: char| !c.is_alphanumeric() && c != '$' && c != '_')
            .filter(|s| s.starts_with('$'))
            .map(|s| s.to_string())
            .collect();
        if vars.is_empty() {
            RuleCondition::AnyOfThem
        } else {
            RuleCondition::Specific(vars)
        }
    } else {
        // For complex conditions (filesize, etc.), treat as "any of them"
        RuleCondition::AnyOfThem
    }
}

fn rule_matches(blob: &[u8], rule: &ParsedRule) -> bool {
    if rule.strings.is_empty() {
        return matches!(rule.condition, RuleCondition::AlwaysTrue);
    }

    match &rule.condition {
        RuleCondition::AlwaysTrue => true,
        RuleCondition::AnyOfThem => rule.strings.iter().any(|s| pattern_found(blob, &s.pattern)),
        RuleCondition::AllOfThem => rule.strings.iter().all(|s| pattern_found(blob, &s.pattern)),
        RuleCondition::Specific(vars) => vars.iter().any(|var| {
            rule.strings
                .iter()
                .any(|s| s.id == *var && pattern_found(blob, &s.pattern))
        }),
    }
}

fn pattern_found(blob: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || pattern.len() > blob.len() {
        return false;
    }
    blob.windows(pattern.len()).any(|w| w == pattern)
}

/// Collect `.yar` and `.yara` files from a directory (non-recursive).
fn collect_rule_files(dir: &Path) -> Result<Vec<PathBuf>, YaraError> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| YaraError::RuleRead {
        path: dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| YaraError::RuleRead {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "yar" || ext == "yara" {
                    files.push(path);
                }
            }
        }
    }

    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_rule(dir: &Path, filename: &str, content: &str) {
        let path = dir.join(filename);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn test_scan_no_rules_dir() {
        let result = scan_payload(&[0x90; 64], Path::new("/nonexistent/yara/rules"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_empty_rules_dir() {
        let dir = TempDir::new().unwrap();
        let matches = scan_payload(&[0x90; 64], dir.path()).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_no_match() {
        let dir = TempDir::new().unwrap();
        write_rule(
            dir.path(),
            "test_rule.yar",
            r#"
rule DetectMalware {
    strings:
        $magic = "EVIL_MARKER_BYTES"
    condition:
        any of them
}
"#,
        );

        let payload = vec![0x90; 256];
        let matches = scan_payload(&payload, dir.path()).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_with_match() {
        let dir = TempDir::new().unwrap();
        write_rule(
            dir.path(),
            "test_detect.yar",
            r#"
rule DetectTestMarker {
    strings:
        $marker = "SPECTER_TEST_PAYLOAD"
    condition:
        $marker
}
"#,
        );

        let mut payload = vec![0x90; 64];
        payload.extend_from_slice(b"SPECTER_TEST_PAYLOAD");
        payload.extend_from_slice(&[0x90; 64]);

        let matches = scan_payload(&payload, dir.path()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "DetectTestMarker");
    }

    #[test]
    fn test_scan_multiple_rules() {
        let dir = TempDir::new().unwrap();
        write_rule(
            dir.path(),
            "rule_a.yar",
            r#"
rule RuleA {
    strings:
        $a = "MARKER_A"
    condition:
        $a
}
"#,
        );
        write_rule(
            dir.path(),
            "rule_b.yar",
            r#"
rule RuleB {
    strings:
        $b = "MARKER_B"
    condition:
        $b
}
"#,
        );

        let mut payload = vec![0x00; 32];
        payload.extend_from_slice(b"MARKER_A");
        payload.extend_from_slice(b"MARKER_B");

        let matches = scan_payload(&payload, dir.path()).unwrap();
        assert_eq!(matches.len(), 2);

        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(names.contains(&"RuleA"));
        assert!(names.contains(&"RuleB"));
    }

    #[test]
    fn test_scan_ignores_non_yara_files() {
        let dir = TempDir::new().unwrap();
        write_rule(dir.path(), "notes.txt", "This is not a YARA rule file");
        write_rule(dir.path(), "config.json", "{}");

        let matches = scan_payload(&[0x90; 64], dir.path()).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_collect_rule_files() {
        let dir = TempDir::new().unwrap();
        write_rule(dir.path(), "a.yar", "rule A { condition: true }");
        write_rule(dir.path(), "b.yara", "rule B { condition: true }");
        write_rule(dir.path(), "c.txt", "not a rule");

        let files = collect_rule_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_builtin_scanner_any_of_them() {
        let dir = TempDir::new().unwrap();
        write_rule(
            dir.path(),
            "multi.yar",
            r#"
rule MultiString {
    strings:
        $a = "ALPHA"
        $b = "BETA"
    condition:
        any of them
}
"#,
        );

        let files = collect_rule_files(dir.path()).unwrap();

        // Only ALPHA present → should match
        let mut payload = vec![0x00; 16];
        payload.extend_from_slice(b"ALPHA");
        let matches = scan_with_builtin(&payload, &files).unwrap();
        assert_eq!(matches.len(), 1);

        // Neither present → no match
        let payload = vec![0x00; 64];
        let matches = scan_with_builtin(&payload, &files).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_builtin_scanner_all_of_them() {
        let dir = TempDir::new().unwrap();
        write_rule(
            dir.path(),
            "all.yar",
            r#"
rule AllRequired {
    strings:
        $a = "ALPHA"
        $b = "BETA"
    condition:
        all of them
}
"#,
        );

        let files = collect_rule_files(dir.path()).unwrap();

        // Only one present → no match
        let mut payload = vec![0x00; 16];
        payload.extend_from_slice(b"ALPHA");
        let matches = scan_with_builtin(&payload, &files).unwrap();
        assert!(matches.is_empty());

        // Both present → match
        let mut payload = vec![0x00; 16];
        payload.extend_from_slice(b"ALPHA");
        payload.extend_from_slice(b"BETA");
        let matches = scan_with_builtin(&payload, &files).unwrap();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_builtin_scanner_hex_pattern() {
        let dir = TempDir::new().unwrap();
        write_rule(
            dir.path(),
            "hex.yar",
            r#"
rule HexPattern {
    strings:
        $hex = { 4D 5A 90 00 }
    condition:
        $hex
}
"#,
        );

        let files = collect_rule_files(dir.path()).unwrap();

        let payload = vec![0x4D, 0x5A, 0x90, 0x00, 0x00, 0x00];
        let matches = scan_with_builtin(&payload, &files).unwrap();
        assert_eq!(matches.len(), 1);

        let payload = vec![0x00; 64];
        let matches = scan_with_builtin(&payload, &files).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_string_value_quoted() {
        let result = parse_string_value(r#""hello world""#);
        assert_eq!(result.unwrap(), b"hello world");
    }

    #[test]
    fn test_parse_string_value_hex() {
        let result = parse_string_value("{ 41 42 43 }");
        assert_eq!(result.unwrap(), b"ABC");
    }

    #[test]
    fn test_parse_string_value_escape() {
        let result = parse_string_value(r#""line\x00null""#);
        assert_eq!(result.unwrap(), b"line\x00null");
    }

    #[test]
    fn test_condition_true_rule() {
        let dir = TempDir::new().unwrap();
        write_rule(dir.path(), "always.yar", "rule Always { condition: true }");

        let files = collect_rule_files(dir.path()).unwrap();
        let matches = scan_with_builtin(&[0x00; 16], &files).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "Always");
    }
}
