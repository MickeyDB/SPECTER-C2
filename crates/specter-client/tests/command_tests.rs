//! Integration tests for command parsing, validation, and task argument building.

use specter_client::commands::{
    build_task_args, parse_command, validate_command, CommandRegistry, ParsedCommand,
};

// ── Registry tests ──────────────────────────────────────────────────────────

#[test]
fn registry_contains_all_16_commands() {
    let reg = CommandRegistry::new();
    let names = reg.names();
    assert_eq!(names.len(), 24);
    let expected = [
        "cd",
        "clear",
        "download",
        "exit",
        "help",
        "inject",
        "jobs",
        "keylog",
        "kill",
        "lateral",
        "ls",
        "modules",
        "ps",
        "pwd",
        "report",
        "screenshot",
        "sessions",
        "shell",
        "sleep",
        "socks",
        "token",
        "upload",
        "use",
        "whoami",
    ];
    for name in &expected {
        assert!(names.contains(name), "missing command: {name}");
    }
}

#[test]
fn registry_names_are_sorted() {
    let reg = CommandRegistry::new();
    let names = reg.names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn registry_all_returns_sorted() {
    let reg = CommandRegistry::new();
    let all = reg.all();
    let names: Vec<&str> = all.iter().map(|c| c.name).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn registry_get_existing_command() {
    let reg = CommandRegistry::new();
    let info = reg.get("shell").expect("shell should exist");
    assert_eq!(info.name, "shell");
    assert_eq!(info.task_type, Some("shell"));
    assert_eq!(info.min_args, 1);
}

#[test]
fn registry_get_missing_command_returns_none() {
    let reg = CommandRegistry::new();
    assert!(reg.get("nonexistent").is_none());
}

#[test]
fn local_commands_have_no_task_type() {
    let reg = CommandRegistry::new();
    let local_cmds = ["exit", "help", "sessions", "use", "jobs", "clear"];
    for name in &local_cmds {
        let info = reg.get(name).unwrap();
        assert!(
            info.task_type.is_none(),
            "{name} should be a local command (task_type=None)"
        );
    }
}

#[test]
fn remote_commands_have_task_type() {
    let reg = CommandRegistry::new();
    let remote_cmds = [
        "shell", "upload", "download", "ps", "ls", "pwd", "cd", "whoami", "sleep", "kill",
    ];
    for name in &remote_cmds {
        let info = reg.get(name).unwrap();
        assert!(
            info.task_type.is_some(),
            "{name} should be a remote command (task_type=Some)"
        );
    }
}

#[test]
fn all_commands_have_usage_and_description() {
    let reg = CommandRegistry::new();
    for info in reg.all() {
        assert!(!info.usage.is_empty(), "{} has empty usage", info.name);
        assert!(
            !info.description.is_empty(),
            "{} has empty description",
            info.name
        );
    }
}

// ── Parsing tests ───────────────────────────────────────────────────────────

#[test]
fn parse_empty_and_whitespace() {
    assert!(parse_command("").is_none());
    assert!(parse_command("   ").is_none());
    assert!(parse_command("\t").is_none());
    assert!(parse_command("\n").is_none());
}

#[test]
fn parse_single_command() {
    let cmd = parse_command("whoami").unwrap();
    assert_eq!(cmd.name, "whoami");
    assert!(cmd.args.is_empty());
}

#[test]
fn parse_command_with_single_arg() {
    let cmd = parse_command("cd /tmp").unwrap();
    assert_eq!(cmd.name, "cd");
    assert_eq!(cmd.args, vec!["/tmp"]);
}

#[test]
fn parse_command_with_multiple_args() {
    let cmd = parse_command("shell ipconfig /all").unwrap();
    assert_eq!(cmd.name, "shell");
    assert_eq!(cmd.args, vec!["ipconfig", "/all"]);
}

#[test]
fn parse_handles_extra_whitespace() {
    let cmd = parse_command("   shell    arg1    arg2   ").unwrap();
    assert_eq!(cmd.name, "shell");
    assert_eq!(cmd.args, vec!["arg1", "arg2"]);
}

#[test]
fn parse_command_name_is_lowercased() {
    let cmd = parse_command("SHELL test").unwrap();
    assert_eq!(cmd.name, "shell");

    let cmd2 = parse_command("WhoAmI").unwrap();
    assert_eq!(cmd2.name, "whoami");
}

#[test]
fn parse_quoted_args_preserves_spaces() {
    let cmd = parse_command(r#"upload "C:\my file.txt" "C:\dest dir""#).unwrap();
    assert_eq!(cmd.name, "upload");
    assert_eq!(cmd.args.len(), 2);
    assert_eq!(cmd.args[0], r"C:\my file.txt");
    assert_eq!(cmd.args[1], r"C:\dest dir");
}

#[test]
fn parse_mixed_quoted_and_unquoted_args() {
    let cmd = parse_command(r#"shell echo "hello world""#).unwrap();
    assert_eq!(cmd.name, "shell");
    assert_eq!(cmd.args, vec!["echo", "hello world"]);
}

#[test]
fn parse_empty_quoted_arg() {
    let cmd = parse_command(r#"shell """#).unwrap();
    assert_eq!(cmd.name, "shell");
    // Empty quotes produce no arg (empty string not pushed since current is empty after quotes toggle)
    // Actually: quotes toggle in_quotes, but between the two quotes nothing is added to current
    // so current remains empty. After loop, current is empty so not pushed.
    assert!(cmd.args.is_empty());
}

// ── Validation tests ────────────────────────────────────────────────────────

#[test]
fn validate_zero_arg_commands() {
    let reg = CommandRegistry::new();
    let zero_arg = [
        "ps", "ls", "pwd", "whoami", "kill", "exit", "help", "sessions", "jobs", "clear",
    ];
    for name in &zero_arg {
        let cmd = ParsedCommand {
            name: name.to_string(),
            args: vec![],
        };
        assert!(
            validate_command(&cmd, &reg).is_ok(),
            "{name} should accept 0 args"
        );
    }
}

#[test]
fn validate_cd_requires_path() {
    let reg = CommandRegistry::new();
    let cmd = ParsedCommand {
        name: "cd".to_string(),
        args: vec![],
    };
    let err = validate_command(&cmd, &reg).unwrap_err();
    assert!(err.contains("Usage:"));
    assert!(err.contains("cd"));
}

#[test]
fn validate_cd_with_path_ok() {
    let reg = CommandRegistry::new();
    let cmd = ParsedCommand {
        name: "cd".to_string(),
        args: vec!["/tmp".to_string()],
    };
    assert!(validate_command(&cmd, &reg).is_ok());
}

#[test]
fn validate_upload_requires_two_args() {
    let reg = CommandRegistry::new();
    // 0 args
    let cmd0 = ParsedCommand {
        name: "upload".to_string(),
        args: vec![],
    };
    assert!(validate_command(&cmd0, &reg).is_err());

    // 1 arg
    let cmd1 = ParsedCommand {
        name: "upload".to_string(),
        args: vec!["file.txt".to_string()],
    };
    assert!(validate_command(&cmd1, &reg).is_err());

    // 2 args OK
    let cmd2 = ParsedCommand {
        name: "upload".to_string(),
        args: vec!["local.txt".to_string(), "remote.txt".to_string()],
    };
    assert!(validate_command(&cmd2, &reg).is_ok());
}

#[test]
fn validate_download_requires_one_arg() {
    let reg = CommandRegistry::new();
    let cmd0 = ParsedCommand {
        name: "download".to_string(),
        args: vec![],
    };
    assert!(validate_command(&cmd0, &reg).is_err());

    let cmd1 = ParsedCommand {
        name: "download".to_string(),
        args: vec!["remote.txt".to_string()],
    };
    assert!(validate_command(&cmd1, &reg).is_ok());
}

#[test]
fn validate_shell_requires_at_least_one_arg() {
    let reg = CommandRegistry::new();
    let empty = ParsedCommand {
        name: "shell".to_string(),
        args: vec![],
    };
    assert!(validate_command(&empty, &reg).is_err());

    let with_args = ParsedCommand {
        name: "shell".to_string(),
        args: vec!["whoami".to_string()],
    };
    assert!(validate_command(&with_args, &reg).is_ok());

    // Multiple args also OK
    let multi = ParsedCommand {
        name: "shell".to_string(),
        args: vec!["ipconfig".to_string(), "/all".to_string()],
    };
    assert!(validate_command(&multi, &reg).is_ok());
}

#[test]
fn validate_sleep_requires_interval() {
    let reg = CommandRegistry::new();
    let cmd0 = ParsedCommand {
        name: "sleep".to_string(),
        args: vec![],
    };
    assert!(validate_command(&cmd0, &reg).is_err());

    let cmd1 = ParsedCommand {
        name: "sleep".to_string(),
        args: vec!["30".to_string()],
    };
    assert!(validate_command(&cmd1, &reg).is_ok());

    // With jitter
    let cmd2 = ParsedCommand {
        name: "sleep".to_string(),
        args: vec!["30".to_string(), "20".to_string()],
    };
    assert!(validate_command(&cmd2, &reg).is_ok());
}

#[test]
fn validate_use_requires_session_id() {
    let reg = CommandRegistry::new();
    let cmd = ParsedCommand {
        name: "use".to_string(),
        args: vec![],
    };
    assert!(validate_command(&cmd, &reg).is_err());

    let cmd2 = ParsedCommand {
        name: "use".to_string(),
        args: vec!["abc123".to_string()],
    };
    assert!(validate_command(&cmd2, &reg).is_ok());
}

#[test]
fn validate_unknown_command_gives_helpful_error() {
    let reg = CommandRegistry::new();
    let cmd = ParsedCommand {
        name: "foobar".to_string(),
        args: vec![],
    };
    let err = validate_command(&cmd, &reg).unwrap_err();
    assert!(err.contains("Unknown command"));
    assert!(err.contains("foobar"));
    assert!(err.contains("help"));
}

#[test]
fn validate_error_includes_usage() {
    let reg = CommandRegistry::new();
    let cmd = ParsedCommand {
        name: "upload".to_string(),
        args: vec![],
    };
    let err = validate_command(&cmd, &reg).unwrap_err();
    assert!(err.starts_with("Usage:"));
}

// ── Task argument building ──────────────────────────────────────────────────

#[test]
fn build_args_shell_joins_with_spaces() {
    let cmd = ParsedCommand {
        name: "shell".to_string(),
        args: vec!["ipconfig".to_string(), "/all".to_string()],
    };
    assert_eq!(build_task_args(&cmd), b"ipconfig /all");
}

#[test]
fn build_args_non_shell_joins_with_newlines() {
    let cmd = ParsedCommand {
        name: "upload".to_string(),
        args: vec!["local.txt".to_string(), "remote.txt".to_string()],
    };
    assert_eq!(build_task_args(&cmd), b"local.txt\nremote.txt");
}

#[test]
fn build_args_single_arg() {
    let cmd = ParsedCommand {
        name: "cd".to_string(),
        args: vec!["/tmp".to_string()],
    };
    assert_eq!(build_task_args(&cmd), b"/tmp");
}

#[test]
fn build_args_empty_args() {
    let cmd = ParsedCommand {
        name: "ps".to_string(),
        args: vec![],
    };
    assert_eq!(build_task_args(&cmd), b"");
}

// ── Round-trip: parse → validate → build ────────────────────────────────────

#[test]
fn round_trip_shell_command() {
    let reg = CommandRegistry::new();
    let cmd = parse_command("shell net user /domain").unwrap();
    assert!(validate_command(&cmd, &reg).is_ok());
    let args = build_task_args(&cmd);
    assert_eq!(args, b"net user /domain");
}

#[test]
fn round_trip_upload_quoted_paths() {
    let reg = CommandRegistry::new();
    let cmd = parse_command(r#"upload "C:\my file.txt" "C:\dest""#).unwrap();
    assert!(validate_command(&cmd, &reg).is_ok());
    let args = build_task_args(&cmd);
    assert_eq!(args, b"C:\\my file.txt\nC:\\dest");
}

#[test]
fn round_trip_sleep_with_jitter() {
    let reg = CommandRegistry::new();
    let cmd = parse_command("sleep 60 25").unwrap();
    assert!(validate_command(&cmd, &reg).is_ok());
    let args = build_task_args(&cmd);
    assert_eq!(args, b"60\n25");
}

// ── Help text tests ─────────────────────────────────────────────────────────

#[test]
fn help_command_usage_contains_command_name() {
    let reg = CommandRegistry::new();
    for info in reg.all() {
        assert!(
            info.usage.contains(info.name),
            "Usage for '{}' should contain command name: {}",
            info.name,
            info.usage,
        );
    }
}

#[test]
fn help_command_is_local_only() {
    let reg = CommandRegistry::new();
    let help = reg.get("help").unwrap();
    assert!(help.task_type.is_none());
    assert_eq!(help.min_args, 0);
}
