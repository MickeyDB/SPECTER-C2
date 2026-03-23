pub mod completion;
pub mod history;

use std::collections::HashMap;

/// A parsed command with its name and arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub name: String,
    pub args: Vec<String>,
}

/// Metadata about a registered command.
#[derive(Debug, Clone)]
pub struct CommandInfo {
    pub name: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
    /// The task_type string sent to the teamserver, or None for local-only commands.
    pub task_type: Option<&'static str>,
    /// Minimum required arguments.
    pub min_args: usize,
}

/// Registry of all built-in commands.
pub struct CommandRegistry {
    commands: HashMap<&'static str, CommandInfo>,
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRegistry {
    pub fn new() -> Self {
        let mut commands = HashMap::new();

        let defs: Vec<CommandInfo> = vec![
            CommandInfo {
                name: "shell",
                usage: "shell <command>",
                description: "Execute a shell command on the target",
                task_type: Some("shell"),
                min_args: 1,
            },
            CommandInfo {
                name: "upload",
                usage: "upload <local_path> <remote_path>",
                description: "Upload a file to the target",
                task_type: Some("upload"),
                min_args: 2,
            },
            CommandInfo {
                name: "download",
                usage: "download <remote_path>",
                description: "Download a file from the target",
                task_type: Some("download"),
                min_args: 1,
            },
            CommandInfo {
                name: "ps",
                usage: "ps",
                description: "List running processes on the target",
                task_type: Some("ps"),
                min_args: 0,
            },
            CommandInfo {
                name: "ls",
                usage: "ls [path]",
                description: "List directory contents on the target",
                task_type: Some("ls"),
                min_args: 0,
            },
            CommandInfo {
                name: "pwd",
                usage: "pwd",
                description: "Print working directory on the target",
                task_type: Some("pwd"),
                min_args: 0,
            },
            CommandInfo {
                name: "cd",
                usage: "cd <path>",
                description: "Change directory on the target",
                task_type: Some("cd"),
                min_args: 1,
            },
            CommandInfo {
                name: "whoami",
                usage: "whoami",
                description: "Print current user on the target",
                task_type: Some("whoami"),
                min_args: 0,
            },
            CommandInfo {
                name: "sleep",
                usage: "sleep <seconds> [jitter%]",
                description: "Set implant sleep interval",
                task_type: Some("sleep"),
                min_args: 1,
            },
            CommandInfo {
                name: "kill",
                usage: "kill",
                description: "Terminate the implant",
                task_type: Some("kill"),
                min_args: 0,
            },
            CommandInfo {
                name: "exit",
                usage: "exit",
                description: "Disconnect from current session (local)",
                task_type: None,
                min_args: 0,
            },
            CommandInfo {
                name: "help",
                usage: "help [command]",
                description: "Show help for commands",
                task_type: None,
                min_args: 0,
            },
            CommandInfo {
                name: "sessions",
                usage: "sessions",
                description: "List all active sessions (local)",
                task_type: None,
                min_args: 0,
            },
            CommandInfo {
                name: "use",
                usage: "use <session_id>",
                description: "Switch to a session by ID or hostname",
                task_type: None,
                min_args: 1,
            },
            CommandInfo {
                name: "jobs",
                usage: "jobs",
                description: "List pending/running tasks (local)",
                task_type: None,
                min_args: 0,
            },
            CommandInfo {
                name: "clear",
                usage: "clear",
                description: "Clear the console output",
                task_type: None,
                min_args: 0,
            },
            // ── Module commands ──────────────────────────────
            CommandInfo {
                name: "socks",
                usage: "socks <start|stop|status>",
                description: "SOCKS5 reverse proxy — start, stop, or check status",
                task_type: Some("module_load"),
                min_args: 1,
            },
            CommandInfo {
                name: "token",
                usage: "token <steal|make|revert|list> [args...]",
                description: "Token manipulation — steal/make/revert/list",
                task_type: Some("module_load"),
                min_args: 1,
            },
            CommandInfo {
                name: "lateral",
                usage: "lateral <wmi|scm|dcom|schtask> <target> [payload] [method]",
                description: "Lateral movement via WMI/SCM/DCOM/ScheduledTask",
                task_type: Some("module_load"),
                min_args: 2,
            },
            CommandInfo {
                name: "inject",
                usage: "inject <createthread|apc|hijack|stomp> <pid> [args...]",
                description: "Process injection — CreateThread/APC/hijack/stomp",
                task_type: Some("module_load"),
                min_args: 2,
            },
            CommandInfo {
                name: "keylog",
                usage: "keylog <duration_seconds>",
                description: "Start keylogger for specified duration",
                task_type: Some("module_load"),
                min_args: 1,
            },
            CommandInfo {
                name: "screenshot",
                usage: "screenshot [interval_seconds] [count]",
                description: "Capture screenshots from target",
                task_type: Some("module_load"),
                min_args: 0,
            },
            CommandInfo {
                name: "modules",
                usage: "modules [list]",
                description: "List available modules (local)",
                task_type: None,
                min_args: 0,
            },
            CommandInfo {
                name: "report",
                usage: "report generate <campaign_id> [--format md|json]",
                description: "Generate engagement report for a campaign",
                task_type: None,
                min_args: 1,
            },
        ];

        for info in defs {
            commands.insert(info.name, info);
        }

        Self { commands }
    }

    pub fn get(&self, name: &str) -> Option<&CommandInfo> {
        self.commands.get(name)
    }

    pub fn all(&self) -> Vec<&CommandInfo> {
        let mut cmds: Vec<_> = self.commands.values().collect();
        cmds.sort_by_key(|c| c.name);
        cmds
    }

    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self.commands.keys().copied().collect();
        names.sort();
        names
    }
}

/// Parse a raw input string into a `ParsedCommand`.
///
/// Handles quoted arguments (double quotes) and whitespace trimming.
pub fn parse_command(input: &str) -> Option<ParsedCommand> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars = trimmed.chars().peekable();

    for ch in chars {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        return None;
    }

    let name = args.remove(0).to_lowercase();
    Some(ParsedCommand { name, args })
}

/// Validate a parsed command against the registry. Returns Ok(()) or an error message.
pub fn validate_command(cmd: &ParsedCommand, registry: &CommandRegistry) -> Result<(), String> {
    let info = registry.get(&cmd.name).ok_or_else(|| {
        format!(
            "Unknown command: '{}'. Type 'help' for available commands.",
            cmd.name
        )
    })?;

    // For 'shell', join all args into one so min_args=1 means "at least something"
    if cmd.name == "shell" {
        if cmd.args.is_empty() {
            return Err(format!("Usage: {}", info.usage));
        }
        return Ok(());
    }

    if cmd.args.len() < info.min_args {
        return Err(format!("Usage: {}", info.usage));
    }

    Ok(())
}

/// Map a TUI command name to the corresponding implant module name.
/// Returns None for non-module commands.
pub fn module_name_for_command(cmd_name: &str) -> Option<&'static str> {
    match cmd_name {
        "socks" => Some("socks5"),
        "token" => Some("token"),
        "lateral" => Some("lateral"),
        "inject" => Some("inject"),
        "keylog" => Some("collect"),
        "screenshot" => Some("collect"),
        _ => None,
    }
}

/// Build the task arguments bytes from a parsed command.
/// For `shell`, joins all args with spaces.
/// For module commands, prepends the module name followed by the subcommand/args.
/// For others, joins with newline separators.
pub fn build_task_args(cmd: &ParsedCommand) -> Vec<u8> {
    if cmd.name == "shell" {
        cmd.args.join(" ").into_bytes()
    } else if let Some(module_name) = module_name_for_command(&cmd.name) {
        // Module args format: module_name\nsubcommand\narg1\narg2...
        // For keylog/screenshot, prepend the subcommand automatically
        let mut parts = vec![module_name.to_string()];
        match cmd.name.as_str() {
            "keylog" => {
                parts.push("keylog".to_string());
                parts.extend(cmd.args.iter().cloned());
            }
            "screenshot" => {
                parts.push("screenshot".to_string());
                parts.extend(cmd.args.iter().cloned());
            }
            _ => {
                parts.extend(cmd.args.iter().cloned());
            }
        }
        parts.join("\n").into_bytes()
    } else {
        cmd.args.join("\n").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        assert!(parse_command("").is_none());
        assert!(parse_command("   ").is_none());
    }

    #[test]
    fn test_parse_simple() {
        let cmd = parse_command("whoami").unwrap();
        assert_eq!(cmd.name, "whoami");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn test_parse_with_args() {
        let cmd = parse_command("shell ipconfig /all").unwrap();
        assert_eq!(cmd.name, "shell");
        assert_eq!(cmd.args, vec!["ipconfig", "/all"]);
    }

    #[test]
    fn test_parse_quoted_args() {
        let cmd = parse_command(r#"upload "C:\my file.txt" "C:\dest""#).unwrap();
        assert_eq!(cmd.name, "upload");
        assert_eq!(cmd.args, vec![r"C:\my file.txt", r"C:\dest"]);
    }

    #[test]
    fn test_parse_case_insensitive() {
        let cmd = parse_command("SHELL test").unwrap();
        assert_eq!(cmd.name, "shell");
    }

    #[test]
    fn test_validate_known_command() {
        let registry = CommandRegistry::new();
        let cmd = ParsedCommand {
            name: "whoami".to_string(),
            args: vec![],
        };
        assert!(validate_command(&cmd, &registry).is_ok());
    }

    #[test]
    fn test_validate_unknown_command() {
        let registry = CommandRegistry::new();
        let cmd = ParsedCommand {
            name: "foobar".to_string(),
            args: vec![],
        };
        assert!(validate_command(&cmd, &registry).is_err());
    }

    #[test]
    fn test_validate_missing_args() {
        let registry = CommandRegistry::new();
        let cmd = ParsedCommand {
            name: "cd".to_string(),
            args: vec![],
        };
        let err = validate_command(&cmd, &registry).unwrap_err();
        assert!(err.contains("Usage:"));
    }

    #[test]
    fn test_validate_shell_needs_args() {
        let registry = CommandRegistry::new();
        let cmd = ParsedCommand {
            name: "shell".to_string(),
            args: vec![],
        };
        assert!(validate_command(&cmd, &registry).is_err());

        let cmd2 = ParsedCommand {
            name: "shell".to_string(),
            args: vec!["whoami".to_string()],
        };
        assert!(validate_command(&cmd2, &registry).is_ok());
    }

    #[test]
    fn test_registry_all_commands() {
        let registry = CommandRegistry::new();
        let names = registry.names();
        assert!(names.contains(&"shell"));
        assert!(names.contains(&"help"));
        assert!(names.contains(&"clear"));
        assert_eq!(names.len(), 24);
    }

    #[test]
    fn test_build_task_args_shell() {
        let cmd = ParsedCommand {
            name: "shell".to_string(),
            args: vec!["ipconfig".to_string(), "/all".to_string()],
        };
        assert_eq!(build_task_args(&cmd), b"ipconfig /all");
    }

    #[test]
    fn test_build_task_args_upload() {
        let cmd = ParsedCommand {
            name: "upload".to_string(),
            args: vec!["local.txt".to_string(), "remote.txt".to_string()],
        };
        assert_eq!(build_task_args(&cmd), b"local.txt\nremote.txt");
    }
}
