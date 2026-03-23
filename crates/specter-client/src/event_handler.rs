use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{ActivePanel, App, ConsoleLine, LineKind};
use crate::commands::completion::{apply_completion, generate_completions};
use crate::commands::{build_task_args, parse_command, validate_command};
use crate::input::InputMode;
use crate::ui::palette::{build_palette_items, PaletteCategory};

pub enum EventResult {
    Continue,
    Quit,
    /// A task should be queued via gRPC with (session_id, task_type, args).
    QueueTask {
        session_id: String,
        task_type: String,
        args: Vec<u8>,
    },
    /// Generate a report for a campaign.
    GenerateReport {
        campaign_id: String,
        format: String,
    },
    /// Send a chat message via gRPC.
    SendChatMessage {
        content: String,
        channel: String,
    },
}

/// Top-level key event handler — routes through the modal input system.
pub fn handle_key_event(key: KeyEvent, app: &mut App) -> EventResult {
    // Ctrl-C always quits regardless of mode
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return EventResult::Quit;
    }

    // If session graph overlay is open, handle its keys
    if app.session_graph.visible {
        return handle_session_graph_keys(key, app);
    }

    // If palette is open, route all keys to palette handler
    if app.palette.visible {
        return handle_palette_mode(key, app);
    }

    // Ctrl-G toggles session graph overlay from any mode
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') {
        app.session_graph.toggle();
        return EventResult::Continue;
    }

    // Ctrl-T toggles chat panel from any mode
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('t') {
        app.chat_visible = !app.chat_visible;
        return EventResult::Continue;
    }

    // If chat panel is visible, route keystrokes to chat input handler
    if app.chat_visible {
        return handle_chat_input(key, app);
    }

    // Ctrl-P opens command palette from any mode except Search (where it means prev match)
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && key.code == KeyCode::Char('p')
        && app.input_mode != InputMode::Search
    {
        let items = build_palette_items(app);
        app.palette.open(items);
        return EventResult::Continue;
    }

    match app.input_mode {
        InputMode::Normal => handle_normal_mode(key, app),
        InputMode::Insert => handle_insert_mode(key, app),
        InputMode::Command => handle_command_mode(key, app),
        InputMode::Search => handle_search_mode(key, app),
    }
}

// ── Normal mode ─────────────────────────────────────────────────────

fn handle_normal_mode(key: KeyEvent, app: &mut App) -> EventResult {
    match key.code {
        KeyCode::Char('q') => EventResult::Quit,

        // Navigation
        KeyCode::Char('j') | KeyCode::Down => {
            app.next_session();
            EventResult::Continue
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.prev_session();
            EventResult::Continue
        }
        KeyCode::Char('g') => {
            app.first_session();
            EventResult::Continue
        }
        KeyCode::Char('G') => {
            app.last_session();
            EventResult::Continue
        }

        // Panel switching
        KeyCode::Tab => {
            app.cycle_panel();
            EventResult::Continue
        }
        KeyCode::Char('1') => {
            app.active_panel = ActivePanel::SessionList;
            EventResult::Continue
        }
        KeyCode::Char('2') => {
            app.active_panel = ActivePanel::MainPanel;
            EventResult::Continue
        }
        KeyCode::Char('3') => {
            app.active_panel = ActivePanel::ContextPanel;
            EventResult::Continue
        }

        // Enter Insert mode (console interaction)
        KeyCode::Enter | KeyCode::Char('i') => {
            app.enter_console();
            EventResult::Continue
        }

        // `:` → Command mode
        KeyCode::Char(':') => {
            app.input_mode = InputMode::Command;
            app.command_prompt.clear();
            EventResult::Continue
        }

        // `/` → Search mode
        KeyCode::Char('/') => {
            app.input_mode = InputMode::Search;
            app.search_state.clear();
            EventResult::Continue
        }

        // `?` → Toggle keybinding cheatsheet
        KeyCode::Char('?') => {
            app.cheatsheet.toggle();
            EventResult::Continue
        }

        // `h`/`l` → navigate context panel tabs when focused
        KeyCode::Char('h') if app.active_panel == ActivePanel::ContextPanel => {
            app.context_tab = app.context_tab.prev();
            EventResult::Continue
        }
        KeyCode::Char('l') if app.active_panel == ActivePanel::ContextPanel => {
            app.context_tab = app.context_tab.next();
            EventResult::Continue
        }

        // `d` → Mark selected session dead (visual indicator)
        KeyCode::Char('d') => {
            // Mark as dead is a visual hint; actual status comes from server.
            // Append a console note for the operator.
            if let Some(session) = app.selected_session() {
                let msg = format!(
                    "Session {} marked dead by operator",
                    &session.id[..8.min(session.id.len())]
                );
                app.console_append(ConsoleLine::new(LineKind::System, msg));
            }
            EventResult::Continue
        }

        // `r` → Refresh (visual feedback; actual refresh is on the 2s poll)
        KeyCode::Char('r') => {
            app.console_append(ConsoleLine::new(
                LineKind::System,
                "Refreshing sessions...".to_string(),
            ));
            EventResult::Continue
        }

        // `t` → Toggle UTC/local time in status bar
        KeyCode::Char('t') => {
            app.show_utc_time = !app.show_utc_time;
            EventResult::Continue
        }

        // Ctrl-L → Redraw (no-op, terminal redraws each loop)
        _ if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') => {
            EventResult::Continue
        }

        _ => EventResult::Continue,
    }
}

// ── Insert mode (console) ───────────────────────────────────────────

fn handle_insert_mode(key: KeyEvent, app: &mut App) -> EventResult {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    // Handle reverse search (Ctrl-R) sub-mode
    if app.reverse_search.active {
        return handle_reverse_search_input(key, app);
    }

    match key.code {
        KeyCode::Esc => {
            app.completion.close();
            app.exit_console();
            EventResult::Continue
        }
        KeyCode::Enter => {
            if app.completion.visible {
                // Apply selected completion
                if let Some((new_input, cursor)) =
                    apply_completion(&app.console_input, &app.completion)
                {
                    app.console_input = new_input;
                    app.console_cursor = cursor;
                }
                app.completion.close();
                EventResult::Continue
            } else {
                handle_console_submit(app)
            }
        }

        // Tab / Shift-Tab → cycle completions
        KeyCode::Tab if !shift => {
            if app.completion.visible {
                app.completion.select_next();
            } else {
                app.completion =
                    generate_completions(&app.console_input, &app.command_registry, &app.sessions);
            }
            EventResult::Continue
        }
        KeyCode::BackTab => {
            if app.completion.visible {
                app.completion.select_prev();
            } else {
                app.completion =
                    generate_completions(&app.console_input, &app.command_registry, &app.sessions);
            }
            EventResult::Continue
        }

        // Ctrl-R → reverse search
        KeyCode::Char('r') if ctrl => {
            app.completion.close();
            app.reverse_search.open();
            EventResult::Continue
        }

        KeyCode::Char('u') if ctrl => {
            app.completion.close();
            app.console_scroll_up(10);
            EventResult::Continue
        }
        KeyCode::Char('d') if ctrl => {
            app.completion.close();
            app.console_scroll_down(10);
            EventResult::Continue
        }
        KeyCode::Left if ctrl => {
            app.completion.close();
            app.console_word_left();
            EventResult::Continue
        }
        KeyCode::Right if ctrl => {
            app.completion.close();
            app.console_word_right();
            EventResult::Continue
        }
        KeyCode::Backspace => {
            app.console_backspace();
            app.completion.close();
            EventResult::Continue
        }
        KeyCode::Delete => {
            app.console_delete_char();
            app.completion.close();
            EventResult::Continue
        }
        KeyCode::Left => {
            app.console_move_left();
            app.completion.close();
            EventResult::Continue
        }
        KeyCode::Right => {
            app.console_move_right();
            app.completion.close();
            EventResult::Continue
        }
        KeyCode::Home => {
            app.console_home();
            app.completion.close();
            EventResult::Continue
        }
        KeyCode::End => {
            app.console_end();
            app.completion.close();
            EventResult::Continue
        }
        KeyCode::Up => {
            app.completion.close();
            app.console_history_up();
            EventResult::Continue
        }
        KeyCode::Down => {
            app.completion.close();
            app.console_history_down();
            EventResult::Continue
        }
        KeyCode::PageUp => {
            app.completion.close();
            app.console_scroll_up(20);
            EventResult::Continue
        }
        KeyCode::PageDown => {
            app.completion.close();
            app.console_scroll_down(20);
            EventResult::Continue
        }
        KeyCode::Char(ch) => {
            app.console_insert_char(ch);
            app.completion.close();
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

/// Handle key events while Ctrl-R reverse search is active.
fn handle_reverse_search_input(key: KeyEvent, app: &mut App) -> EventResult {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    match key.code {
        KeyCode::Esc => {
            app.reverse_search.close();
            EventResult::Continue
        }
        KeyCode::Enter => {
            // Accept the match into console input
            if let Some(matched) = app.reverse_search.current_match.clone() {
                app.console_input = matched;
                app.console_cursor = app.console_input.len();
            }
            app.reverse_search.close();
            EventResult::Continue
        }
        // Ctrl-R again → go to next (older) match
        KeyCode::Char('r') if ctrl => {
            app.reverse_search.next_match(&app.persistent_history);
            EventResult::Continue
        }
        KeyCode::Backspace => {
            app.reverse_search.backspace();
            app.reverse_search.update(&app.persistent_history);
            EventResult::Continue
        }
        KeyCode::Char(ch) => {
            app.reverse_search.insert_char(ch);
            app.reverse_search.update(&app.persistent_history);
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

// ── Command mode (`:` prompt) ───────────────────────────────────────

fn handle_command_mode(key: KeyEvent, app: &mut App) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            app.command_prompt.clear();
            EventResult::Continue
        }
        KeyCode::Enter => {
            let input = app.command_prompt.take();
            app.input_mode = InputMode::Normal;
            execute_command_mode_input(app, &input)
        }
        KeyCode::Backspace => {
            app.command_prompt.backspace();
            EventResult::Continue
        }
        KeyCode::Delete => {
            app.command_prompt.delete_char();
            EventResult::Continue
        }
        KeyCode::Left => {
            app.command_prompt.move_left();
            EventResult::Continue
        }
        KeyCode::Right => {
            app.command_prompt.move_right();
            EventResult::Continue
        }
        KeyCode::Home => {
            app.command_prompt.home();
            EventResult::Continue
        }
        KeyCode::End => {
            app.command_prompt.end();
            EventResult::Continue
        }
        KeyCode::Char(ch) => {
            app.command_prompt.insert_char(ch);
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

/// Execute a command typed at the `:` prompt.
fn execute_command_mode_input(app: &mut App, input: &str) -> EventResult {
    if input.is_empty() {
        return EventResult::Continue;
    }

    match input {
        "q" | "quit" => EventResult::Quit,
        "w" | "write" => {
            app.console_append(ConsoleLine::new(
                LineKind::System,
                "No writable state to save.".to_string(),
            ));
            EventResult::Continue
        }
        "wq" => EventResult::Quit,
        "sessions" => {
            handle_sessions_list(app);
            EventResult::Continue
        }
        "clear" => {
            app.console_clear();
            EventResult::Continue
        }
        "help" => {
            handle_help(app, &[]);
            EventResult::Continue
        }
        _ => {
            // Try to parse as "use <session>" or "help <cmd>"
            if let Some(rest) = input.strip_prefix("use ") {
                handle_use_session(app, &[rest.to_string()]);
                EventResult::Continue
            } else if let Some(rest) = input.strip_prefix("help ") {
                handle_help(app, &[rest.to_string()]);
                EventResult::Continue
            } else {
                app.console_append(ConsoleLine::new(
                    LineKind::Error,
                    format!("Unknown command: ':{input}'"),
                ));
                EventResult::Continue
            }
        }
    }
}

// ── Search mode (`/` prompt) ────────────────────────────────────────

fn handle_search_mode(key: KeyEvent, app: &mut App) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            app.search_state.clear();
            EventResult::Continue
        }
        KeyCode::Enter => {
            // Select current match and go back to Normal
            if let Some(idx) = app.search_state.current_match() {
                app.selected_index = idx;
            }
            app.input_mode = InputMode::Normal;
            app.search_state.clear();
            EventResult::Continue
        }
        KeyCode::Backspace => {
            app.search_state.backspace();
            app.search_state.update_matches(&app.sessions);
            if let Some(idx) = app.search_state.current_match() {
                app.selected_index = idx;
            }
            EventResult::Continue
        }
        KeyCode::Delete => {
            app.search_state.delete_char();
            app.search_state.update_matches(&app.sessions);
            if let Some(idx) = app.search_state.current_match() {
                app.selected_index = idx;
            }
            EventResult::Continue
        }
        KeyCode::Left => {
            app.search_state.move_left();
            EventResult::Continue
        }
        KeyCode::Right => {
            app.search_state.move_right();
            EventResult::Continue
        }
        // Ctrl-N or Tab → next match
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.search_state.next_match();
            if let Some(idx) = app.search_state.current_match() {
                app.selected_index = idx;
            }
            EventResult::Continue
        }
        // Ctrl-P → previous match
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.search_state.prev_match();
            if let Some(idx) = app.search_state.current_match() {
                app.selected_index = idx;
            }
            EventResult::Continue
        }
        KeyCode::Char(ch) => {
            app.search_state.insert_char(ch);
            app.search_state.update_matches(&app.sessions);
            if let Some(idx) = app.search_state.current_match() {
                app.selected_index = idx;
            }
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

// ── Palette mode (command palette overlay) ───────────────────────────

fn handle_palette_mode(key: KeyEvent, app: &mut App) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.palette.close();
            EventResult::Continue
        }
        KeyCode::Enter => {
            if let Some(item) = app.palette.selected_item().cloned() {
                app.palette.close();
                execute_palette_selection(app, &item)
            } else {
                app.palette.close();
                EventResult::Continue
            }
        }
        KeyCode::Up => {
            app.palette.select_prev();
            EventResult::Continue
        }
        KeyCode::Down => {
            app.palette.select_next();
            EventResult::Continue
        }
        KeyCode::Backspace => {
            app.palette.backspace();
            EventResult::Continue
        }
        KeyCode::Delete => {
            app.palette.delete_char();
            EventResult::Continue
        }
        KeyCode::Left => {
            app.palette.move_left();
            EventResult::Continue
        }
        KeyCode::Right => {
            app.palette.move_right();
            EventResult::Continue
        }
        KeyCode::Char(ch) => {
            app.palette.insert_char(ch);
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

fn execute_palette_selection(app: &mut App, item: &crate::ui::palette::PaletteItem) -> EventResult {
    match item.category {
        PaletteCategory::Command => {
            // Insert the command into the console input and switch to insert mode
            app.console_input = item.action.clone();
            app.console_cursor = app.console_input.len();
            if !app.console_focused {
                app.enter_console();
            }
            app.input_mode = InputMode::Insert;
            EventResult::Continue
        }
        PaletteCategory::Session => {
            // Switch to the selected session
            handle_use_session(app, &[item.action.clone()]);
            EventResult::Continue
        }
        PaletteCategory::RecentTask => {
            // Insert the recent command into console and switch to insert mode
            app.console_input = item.action.clone();
            app.console_cursor = app.console_input.len();
            if !app.console_focused {
                if app.active_session_id.is_some() {
                    app.console_focused = true;
                    app.active_panel = ActivePanel::MainPanel;
                } else {
                    app.enter_console();
                }
            }
            app.input_mode = InputMode::Insert;
            EventResult::Continue
        }
    }
}

// ── Console submit (shared by Insert mode) ──────────────────────────

fn handle_console_submit(app: &mut App) -> EventResult {
    let input = match app.console_submit() {
        Some(input) => input,
        None => return EventResult::Continue,
    };

    // Echo the input to console output
    let echo_line = if let Some(ref sid) = app.active_session_id {
        ConsoleLine::new(LineKind::Input, input.clone()).with_session(sid.clone())
    } else {
        ConsoleLine::new(LineKind::Input, input.clone())
    };
    app.console_append(echo_line);

    // Parse the command
    let parsed = match parse_command(&input) {
        Some(cmd) => cmd,
        None => return EventResult::Continue,
    };

    // Handle local-only commands
    match parsed.name.as_str() {
        "clear" => {
            app.console_clear();
            return EventResult::Continue;
        }
        "exit" => {
            app.exit_console();
            return EventResult::Continue;
        }
        "help" => {
            handle_help(app, &parsed.args);
            return EventResult::Continue;
        }
        "sessions" => {
            handle_sessions_list(app);
            return EventResult::Continue;
        }
        "use" => {
            handle_use_session(app, &parsed.args);
            return EventResult::Continue;
        }
        "jobs" => {
            app.console_append(ConsoleLine::new(
                LineKind::System,
                "Job tracking not yet implemented.".to_string(),
            ));
            return EventResult::Continue;
        }
        "modules" => {
            handle_modules_list(app);
            return EventResult::Continue;
        }
        "report" => {
            return handle_report_command(app, &parsed.args);
        }
        _ => {}
    }

    // Validate the command
    if let Err(err) = validate_command(&parsed, &app.command_registry) {
        app.console_append(ConsoleLine::new(LineKind::Error, err));
        return EventResult::Continue;
    }

    // Check we have an active session for remote commands
    let session_id = match &app.active_session_id {
        Some(id) => id.clone(),
        None => {
            app.console_append(ConsoleLine::new(
                LineKind::Error,
                "No active session. Use 'use <session_id>' or press Enter on a session first."
                    .to_string(),
            ));
            return EventResult::Continue;
        }
    };

    // Get the task type from the registry
    let task_type = match app.command_registry.get(&parsed.name) {
        Some(info) => match info.task_type {
            Some(tt) => tt.to_string(),
            None => return EventResult::Continue,
        },
        None => return EventResult::Continue,
    };

    let args = build_task_args(&parsed);

    // Show "queued" message
    app.console_append(
        ConsoleLine::new(
            LineKind::TaskQueued,
            format!("Task queued: {} {}", parsed.name, parsed.args.join(" ")),
        )
        .with_session(session_id.clone()),
    );

    EventResult::QueueTask {
        session_id,
        task_type,
        args,
    }
}

// ── Helper commands (shared across modes) ───────────────────────────

fn handle_help(app: &mut App, args: &[String]) {
    if let Some(cmd_name) = args.first() {
        if let Some(info) = app.command_registry.get(cmd_name.as_str()) {
            let line = format!("{} — {}", info.usage, info.description);
            app.console_append(ConsoleLine::new(LineKind::System, line));
        } else {
            app.console_append(ConsoleLine::new(
                LineKind::Error,
                format!("Unknown command: '{cmd_name}'"),
            ));
        }
    } else {
        let lines: Vec<String> = app
            .command_registry
            .all()
            .iter()
            .map(|info| format!("  {:12} {}", info.name, info.description))
            .collect();
        app.console_append(ConsoleLine::new(
            LineKind::System,
            "Available commands:".to_string(),
        ));
        for line in lines {
            app.console_append(ConsoleLine::new(LineKind::System, line));
        }
    }
}

fn handle_sessions_list(app: &mut App) {
    if app.sessions.is_empty() {
        app.console_append(ConsoleLine::new(
            LineKind::System,
            "No active sessions.".to_string(),
        ));
        return;
    }

    let lines: Vec<String> = app
        .sessions
        .iter()
        .map(|session| {
            let short_id = if session.id.len() > 8 {
                &session.id[..8]
            } else {
                &session.id
            };
            format!(
                "{:<10} {:<20} {:<15} {:<8}",
                short_id, session.hostname, session.username, session.pid
            )
        })
        .collect();

    app.console_append(ConsoleLine::new(
        LineKind::System,
        format!("{:<10} {:<20} {:<15} {:<8}", "ID", "Hostname", "User", "PID"),
    ));
    for line in lines {
        app.console_append(ConsoleLine::new(LineKind::Output, line));
    }
}

fn handle_modules_list(app: &mut App) {
    let modules = [
        ("socks5", "SOCKS5 reverse proxy"),
        ("token", "Token manipulation (steal/make/revert/list)"),
        ("lateral", "Lateral movement (wmi/scm/dcom/schtask)"),
        ("inject", "Process injection (createthread/apc/hijack/stomp)"),
        ("exfil", "Exfiltration (file/directory)"),
        ("collect", "Collection (keylog/screenshot)"),
    ];

    app.console_append(ConsoleLine::new(
        LineKind::System,
        format!("{:<12} {}", "Module", "Description"),
    ));
    for (name, desc) in &modules {
        app.console_append(ConsoleLine::new(
            LineKind::Output,
            format!("{:<12} {}", name, desc),
        ));
    }
}

fn handle_report_command(app: &mut App, args: &[String]) -> EventResult {
    if args.is_empty() {
        app.console_append(ConsoleLine::new(
            LineKind::Error,
            "Usage: report generate <campaign_id> [--format md|json]".to_string(),
        ));
        return EventResult::Continue;
    }

    match args[0].as_str() {
        "generate" => {
            if args.len() < 2 {
                app.console_append(ConsoleLine::new(
                    LineKind::Error,
                    "Usage: report generate <campaign_id> [--format md|json]".to_string(),
                ));
                return EventResult::Continue;
            }

            let campaign_id = args[1].clone();

            // Parse optional --format flag
            let mut format = "md".to_string();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--format" && i + 1 < args.len() {
                    format = args[i + 1].to_lowercase();
                    i += 2;
                } else {
                    i += 1;
                }
            }

            app.console_append(ConsoleLine::new(
                LineKind::System,
                format!(
                    "Generating {} report for campaign {}...",
                    format.to_uppercase(),
                    campaign_id
                ),
            ));

            EventResult::GenerateReport {
                campaign_id,
                format,
            }
        }
        _ => {
            app.console_append(ConsoleLine::new(
                LineKind::Error,
                format!("Unknown report subcommand: '{}'. Use 'report generate <campaign_id>'", args[0]),
            ));
            EventResult::Continue
        }
    }
}

// ── Session graph overlay ─────────────────────────────────────────

/// Handle keyboard input when the chat panel is visible.
/// Escape closes the chat panel, Enter sends the message, other keys edit the input.
fn handle_chat_input(key: KeyEvent, app: &mut App) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.chat_visible = false;
            EventResult::Continue
        }
        KeyCode::Enter => {
            let content = app.chat_input.trim().to_string();
            if content.is_empty() {
                return EventResult::Continue;
            }
            app.chat_input.clear();
            app.chat_cursor = 0;
            EventResult::SendChatMessage {
                content,
                channel: "global".to_string(),
            }
        }
        KeyCode::Backspace => {
            if app.chat_cursor > 0 {
                app.chat_cursor -= 1;
                app.chat_input.remove(app.chat_cursor);
            }
            EventResult::Continue
        }
        KeyCode::Delete => {
            if app.chat_cursor < app.chat_input.len() {
                app.chat_input.remove(app.chat_cursor);
            }
            EventResult::Continue
        }
        KeyCode::Left => {
            app.chat_cursor = app.chat_cursor.saturating_sub(1);
            EventResult::Continue
        }
        KeyCode::Right => {
            if app.chat_cursor < app.chat_input.len() {
                app.chat_cursor += 1;
            }
            EventResult::Continue
        }
        KeyCode::Home => {
            app.chat_cursor = 0;
            EventResult::Continue
        }
        KeyCode::End => {
            app.chat_cursor = app.chat_input.len();
            EventResult::Continue
        }
        KeyCode::Char(ch) => {
            app.chat_input.insert(app.chat_cursor, ch);
            app.chat_cursor += ch.len_utf8();
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

fn handle_session_graph_keys(key: KeyEvent, app: &mut App) -> EventResult {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.session_graph.toggle();
            EventResult::Continue
        }
        _ if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') => {
            app.session_graph.toggle();
            EventResult::Continue
        }
        KeyCode::PageUp | KeyCode::Char('k') | KeyCode::Up => {
            app.session_graph.scroll_up(3);
            EventResult::Continue
        }
        KeyCode::PageDown | KeyCode::Char('j') | KeyCode::Down => {
            app.session_graph.scroll_down(3);
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

fn handle_use_session(app: &mut App, args: &[String]) {
    let target = match args.first() {
        Some(t) => t,
        None => {
            app.console_append(ConsoleLine::new(
                LineKind::Error,
                "Usage: use <session_id or hostname>".to_string(),
            ));
            return;
        }
    };

    // Match by ID prefix or hostname
    let matched = app.sessions.iter().find(|s| {
        s.id.starts_with(target.as_str()) || s.hostname.eq_ignore_ascii_case(target.as_str())
    });

    match matched {
        Some(session) => {
            let session_id = session.id.clone();
            let hostname = session.hostname.clone();
            app.active_session_id = Some(session_id.clone());
            app.console_append(ConsoleLine::new(
                LineKind::System,
                format!(
                    "Switched to session {} ({})",
                    &session_id[..8.min(session_id.len())],
                    hostname
                ),
            ));
        }
        None => {
            app.console_append(ConsoleLine::new(
                LineKind::Error,
                format!("No session matching '{target}'"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{ActivePanel, App};
    use crate::input::InputMode;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use specter_common::proto::specter::v1::{SessionInfo, SessionStatus};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn make_session(id: &str) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            hostname: "host".to_string(),
            username: "user".to_string(),
            pid: 1,
            os_version: String::new(),
            integrity_level: String::new(),
            process_name: String::new(),
            internal_ip: String::new(),
            external_ip: String::new(),
            last_checkin: None,
            first_seen: None,
            status: SessionStatus::Active.into(),
            active_channel: String::new(),
        }
    }

    fn make_session_with_host(id: &str, hostname: &str) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            hostname: hostname.to_string(),
            username: "user".to_string(),
            pid: 1,
            ..Default::default()
        }
    }

    // ── Normal mode tests ───────────────────────────────────────────

    #[test]
    fn test_quit_keys() {
        let mut app = App::new("test".into());
        assert!(matches!(
            handle_key_event(press(KeyCode::Char('q')), &mut app),
            EventResult::Quit
        ));
    }

    #[test]
    fn test_ctrl_c_quits() {
        let mut app = App::new("test".into());
        assert!(matches!(
            handle_key_event(ctrl(KeyCode::Char('c')), &mut app),
            EventResult::Quit
        ));
    }

    #[test]
    fn test_navigation() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![
            make_session("1"),
            make_session("2"),
            make_session("3"),
        ]);
        handle_key_event(press(KeyCode::Char('j')), &mut app);
        assert_eq!(app.selected_index, 1);
        handle_key_event(press(KeyCode::Char('k')), &mut app);
        assert_eq!(app.selected_index, 0);
        handle_key_event(press(KeyCode::Char('G')), &mut app);
        assert_eq!(app.selected_index, 2);
        handle_key_event(press(KeyCode::Char('g')), &mut app);
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn test_tab_cycles_panels() {
        let mut app = App::new("test".into());
        assert_eq!(app.active_panel, ActivePanel::SessionList);
        handle_key_event(press(KeyCode::Tab), &mut app);
        assert_eq!(app.active_panel, ActivePanel::MainPanel);
        handle_key_event(press(KeyCode::Tab), &mut app);
        assert_eq!(app.active_panel, ActivePanel::ContextPanel);
    }

    #[test]
    fn test_number_keys_jump_panels() {
        let mut app = App::new("test".into());
        handle_key_event(press(KeyCode::Char('2')), &mut app);
        assert_eq!(app.active_panel, ActivePanel::MainPanel);
        handle_key_event(press(KeyCode::Char('3')), &mut app);
        assert_eq!(app.active_panel, ActivePanel::ContextPanel);
        handle_key_event(press(KeyCode::Char('1')), &mut app);
        assert_eq!(app.active_panel, ActivePanel::SessionList);
    }

    #[test]
    fn test_enter_activates_console() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![make_session("session123")]);
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(app.console_focused);
        assert_eq!(app.input_mode, InputMode::Insert);
        assert_eq!(app.active_session_id, Some("session123".to_string()));
    }

    #[test]
    fn test_i_enters_insert_mode() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![make_session("session123")]);
        handle_key_event(press(KeyCode::Char('i')), &mut app);
        assert_eq!(app.input_mode, InputMode::Insert);
        assert!(app.console_focused);
    }

    #[test]
    fn test_colon_enters_command_mode() {
        let mut app = App::new("test".into());
        handle_key_event(press(KeyCode::Char(':')), &mut app);
        assert_eq!(app.input_mode, InputMode::Command);
    }

    #[test]
    fn test_slash_enters_search_mode() {
        let mut app = App::new("test".into());
        handle_key_event(press(KeyCode::Char('/')), &mut app);
        assert_eq!(app.input_mode, InputMode::Search);
    }

    #[test]
    fn test_question_mark_toggles_cheatsheet() {
        let mut app = App::new("test".into());
        assert!(!app.cheatsheet.visible);
        handle_key_event(press(KeyCode::Char('?')), &mut app);
        assert!(app.cheatsheet.visible);
        handle_key_event(press(KeyCode::Char('?')), &mut app);
        assert!(!app.cheatsheet.visible);
    }

    // ── Insert mode tests ───────────────────────────────────────────

    #[test]
    fn test_console_typing() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());

        handle_key_event(press(KeyCode::Char('l')), &mut app);
        handle_key_event(press(KeyCode::Char('s')), &mut app);
        assert_eq!(app.console_input, "ls");
    }

    #[test]
    fn test_console_escape() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert!(!app.console_focused);
        assert_eq!(app.input_mode, InputMode::Normal);
    }

    #[test]
    fn test_console_submit_local_clear() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        app.console_append(ConsoleLine::new(LineKind::Output, "old".to_string()));
        assert_eq!(app.console_output.len(), 1);

        app.console_input = "clear".to_string();
        app.console_cursor = 5;
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(app.console_output.is_empty());
    }

    #[test]
    fn test_console_submit_remote_command() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("session-abc".to_string());

        app.console_input = "whoami".to_string();
        app.console_cursor = 6;
        let result = handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(matches!(
            result,
            EventResult::QueueTask {
                ref session_id,
                ref task_type,
                ..
            } if session_id == "session-abc" && task_type == "whoami"
        ));
    }

    #[test]
    fn test_console_help() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());

        app.console_input = "help".to_string();
        app.console_cursor = 4;
        handle_key_event(press(KeyCode::Enter), &mut app);
        // Should have echoed the input + "Available commands:" + all command entries
        assert!(app.console_output.len() > 2);
    }

    #[test]
    fn test_ctrl_c_quits_in_console() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        assert!(matches!(
            handle_key_event(ctrl(KeyCode::Char('c')), &mut app),
            EventResult::Quit
        ));
    }

    // ── Command mode tests ──────────────────────────────────────────

    #[test]
    fn test_command_mode_quit() {
        let mut app = App::new("test".into());
        app.input_mode = InputMode::Command;
        // Type "q" then Enter
        handle_key_event(press(KeyCode::Char('q')), &mut app);
        let result = handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(matches!(result, EventResult::Quit));
    }

    #[test]
    fn test_command_mode_escape() {
        let mut app = App::new("test".into());
        app.input_mode = InputMode::Command;
        handle_key_event(press(KeyCode::Char('h')), &mut app);
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(app.command_prompt.input.is_empty());
    }

    #[test]
    fn test_command_mode_unknown_command() {
        let mut app = App::new("test".into());
        app.input_mode = InputMode::Command;
        for ch in "badcmd".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert_eq!(app.input_mode, InputMode::Normal);
        // Should have appended an error line
        assert!(app
            .console_output
            .iter()
            .any(|l| l.content.contains("Unknown command")));
    }

    #[test]
    fn test_command_mode_sessions() {
        let mut app = App::new("test".into());
        app.input_mode = InputMode::Command;
        for ch in "sessions".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(app
            .console_output
            .iter()
            .any(|l| l.content.contains("No active sessions")));
    }

    // ── Search mode tests ───────────────────────────────────────────

    #[test]
    fn test_search_mode_finds_session() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![
            make_session_with_host("aaa111", "alpha-host"),
            make_session_with_host("bbb222", "beta-host"),
            make_session_with_host("ccc333", "charlie-host"),
        ]);

        // Enter search mode
        handle_key_event(press(KeyCode::Char('/')), &mut app);
        assert_eq!(app.input_mode, InputMode::Search);

        // Type "beta"
        for ch in "beta".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        assert_eq!(app.selected_index, 1); // beta-host is index 1

        // Press Enter to confirm
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn test_search_mode_escape_cancels() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![
            make_session_with_host("aaa111", "alpha-host"),
            make_session_with_host("bbb222", "beta-host"),
        ]);

        handle_key_event(press(KeyCode::Char('/')), &mut app);
        for ch in "beta".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(app.search_state.query.is_empty());
    }

    #[test]
    fn test_search_mode_next_prev_match() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![
            make_session_with_host("aaa111", "host-alpha"),
            make_session_with_host("bbb222", "server-beta"),
            make_session_with_host("ccc333", "host-charlie"),
        ]);

        handle_key_event(press(KeyCode::Char('/')), &mut app);
        // Type "host" — matches indices 0, 2
        for ch in "host".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        assert_eq!(app.selected_index, 0); // first match

        // Ctrl-N → next match
        handle_key_event(ctrl(KeyCode::Char('n')), &mut app);
        assert_eq!(app.selected_index, 2); // second match

        // Ctrl-P → prev match
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        assert_eq!(app.selected_index, 0);
    }

    // ── Palette mode tests ─────────────────────────────────────────

    #[test]
    fn test_ctrl_p_opens_palette() {
        let mut app = App::new("test".into());
        assert!(!app.palette.visible);
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        assert!(app.palette.visible);
        // Should have command items at minimum
        assert!(!app.palette.items.is_empty());
    }

    #[test]
    fn test_palette_escape_closes() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        assert!(app.palette.visible);
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert!(!app.palette.visible);
    }

    #[test]
    fn test_palette_typing_filters() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        let total_items = app.palette.filtered_indices.len();

        // Type "sh" to filter
        handle_key_event(press(KeyCode::Char('s')), &mut app);
        handle_key_event(press(KeyCode::Char('h')), &mut app);
        assert!(app.palette.filtered_indices.len() <= total_items);
        // "shell" should be in filtered results
        let has_shell = app.palette.filtered_indices.iter().any(|&idx| {
            app.palette.items[idx].label == "shell"
        });
        assert!(has_shell);
    }

    #[test]
    fn test_palette_navigation() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        assert_eq!(app.palette.selected, 0);
        handle_key_event(press(KeyCode::Down), &mut app);
        assert_eq!(app.palette.selected, 1);
        handle_key_event(press(KeyCode::Up), &mut app);
        assert_eq!(app.palette.selected, 0);
    }

    #[test]
    fn test_palette_select_command() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![make_session("session-1")]);
        app.enter_console();

        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        // Find "whoami" and select it
        for ch in "whoami".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(!app.palette.visible);
        assert_eq!(app.console_input, "whoami");
        assert_eq!(app.input_mode, InputMode::Insert);
    }

    #[test]
    fn test_palette_select_session() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![
            make_session_with_host("abc123", "target-host"),
            make_session_with_host("def456", "other-host"),
        ]);

        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        // Filter for the session
        for ch in "target".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(!app.palette.visible);
        assert_eq!(app.active_session_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_palette_backspace() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        handle_key_event(press(KeyCode::Char('x')), &mut app);
        handle_key_event(press(KeyCode::Char('y')), &mut app);
        assert_eq!(app.palette.query, "xy");
        handle_key_event(press(KeyCode::Backspace), &mut app);
        assert_eq!(app.palette.query, "x");
    }

    #[test]
    fn test_palette_includes_recent_tasks() {
        let mut app = App::new("test".into());
        app.console_history = vec!["whoami".to_string(), "ps".to_string()];
        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        // Should have recent task items
        let has_recent = app.palette.items.iter().any(|item| {
            item.category == crate::ui::palette::PaletteCategory::RecentTask
        });
        assert!(has_recent);
    }

    #[test]
    fn test_ctrl_p_in_insert_mode_opens_palette() {
        let mut app = App::new("test".into());
        app.update_sessions(vec![make_session("s1")]);
        app.enter_console();
        assert_eq!(app.input_mode, InputMode::Insert);

        handle_key_event(ctrl(KeyCode::Char('p')), &mut app);
        assert!(app.palette.visible);
    }

    // ── Context panel tab tests ──────────────────────────────────────

    #[test]
    fn test_h_l_navigates_context_tabs() {
        let mut app = App::new("test".into());
        app.active_panel = ActivePanel::ContextPanel;
        assert_eq!(app.context_tab, crate::app::ContextTab::Info);

        handle_key_event(press(KeyCode::Char('l')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Process);

        handle_key_event(press(KeyCode::Char('l')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Tasks);

        handle_key_event(press(KeyCode::Char('l')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Network);

        handle_key_event(press(KeyCode::Char('h')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Tasks);

        handle_key_event(press(KeyCode::Char('h')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Process);

        handle_key_event(press(KeyCode::Char('h')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Info);
    }

    #[test]
    fn test_h_l_only_when_context_panel_focused() {
        let mut app = App::new("test".into());
        app.active_panel = ActivePanel::SessionList;
        // 'l' should NOT change context tab when not focused on context panel
        // (in SessionList it's unhandled, falls through to Continue)
        handle_key_event(press(KeyCode::Char('l')), &mut app);
        assert_eq!(app.context_tab, crate::app::ContextTab::Info);
    }

    // ── Tab completion tests ─────────────────────────────────────────

    #[test]
    fn test_tab_opens_completion() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        app.console_input = "sh".to_string();
        app.console_cursor = 2;

        handle_key_event(press(KeyCode::Tab), &mut app);
        assert!(app.completion.visible);
        assert!(app.completion.items.contains(&"shell".to_string()));
    }

    #[test]
    fn test_tab_cycles_completions() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        app.console_input = "".to_string();
        app.console_cursor = 0;

        // Open completions
        handle_key_event(press(KeyCode::Tab), &mut app);
        assert!(app.completion.visible);
        let first = app.completion.selected;
        assert_eq!(first, 0);

        // Tab again cycles
        handle_key_event(press(KeyCode::Tab), &mut app);
        assert_eq!(app.completion.selected, 1);
    }

    #[test]
    fn test_enter_applies_completion() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        app.console_input = "sh".to_string();
        app.console_cursor = 2;

        // Open completions
        handle_key_event(press(KeyCode::Tab), &mut app);
        assert!(app.completion.visible);

        // Enter applies the completion
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(!app.completion.visible);
        assert_eq!(app.console_input, "shell ");
    }

    #[test]
    fn test_typing_closes_completion() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        app.console_input = "sh".to_string();
        app.console_cursor = 2;

        handle_key_event(press(KeyCode::Tab), &mut app);
        assert!(app.completion.visible);

        // Typing closes the popup
        handle_key_event(press(KeyCode::Char('e')), &mut app);
        assert!(!app.completion.visible);
    }

    // ── Reverse search tests ─────────────────────────────────────────

    #[test]
    fn test_ctrl_r_opens_reverse_search() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());

        handle_key_event(ctrl(KeyCode::Char('r')), &mut app);
        assert!(app.reverse_search.active);
    }

    #[test]
    fn test_reverse_search_typing_and_accept() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        // Add some persistent history
        app.persistent_history.push("shell whoami");
        app.persistent_history.push("ps");
        app.persistent_history.push("shell ipconfig");

        // Open reverse search
        handle_key_event(ctrl(KeyCode::Char('r')), &mut app);
        assert!(app.reverse_search.active);

        // Type "shell"
        for ch in "shell".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        assert_eq!(
            app.reverse_search.current_match,
            Some("shell ipconfig".to_string())
        );

        // Accept with Enter
        handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(!app.reverse_search.active);
        assert_eq!(app.console_input, "shell ipconfig");
    }

    #[test]
    fn test_reverse_search_escape_cancels() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());

        handle_key_event(ctrl(KeyCode::Char('r')), &mut app);
        handle_key_event(press(KeyCode::Char('x')), &mut app);
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert!(!app.reverse_search.active);
        assert!(app.console_input.is_empty());
    }

    #[test]
    fn test_reverse_search_ctrl_r_cycles() {
        let mut app = App::new("test".into());
        app.console_focused = true;
        app.input_mode = InputMode::Insert;
        app.active_session_id = Some("s1".to_string());
        app.persistent_history.push("shell whoami");
        app.persistent_history.push("shell ipconfig");

        handle_key_event(ctrl(KeyCode::Char('r')), &mut app);
        for ch in "shell".chars() {
            handle_key_event(press(KeyCode::Char(ch)), &mut app);
        }
        assert_eq!(
            app.reverse_search.current_match,
            Some("shell ipconfig".to_string())
        );

        // Ctrl-R again → older match
        handle_key_event(ctrl(KeyCode::Char('r')), &mut app);
        assert_eq!(
            app.reverse_search.current_match,
            Some("shell whoami".to_string())
        );
    }

    // ── Session graph tests ─────────────────────────────────────────

    #[test]
    fn test_ctrl_g_toggles_session_graph() {
        let mut app = App::new("test".into());
        assert!(!app.session_graph.visible);
        handle_key_event(ctrl(KeyCode::Char('g')), &mut app);
        assert!(app.session_graph.visible);
        // Ctrl-G again closes it
        handle_key_event(ctrl(KeyCode::Char('g')), &mut app);
        assert!(!app.session_graph.visible);
    }

    #[test]
    fn test_session_graph_escape_closes() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('g')), &mut app);
        assert!(app.session_graph.visible);
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert!(!app.session_graph.visible);
    }

    #[test]
    fn test_session_graph_scroll() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('g')), &mut app);
        assert!(app.session_graph.visible);
        handle_key_event(press(KeyCode::Char('j')), &mut app);
        // Scroll down doesn't go below 0
        assert_eq!(app.session_graph.scroll, 0);
        handle_key_event(press(KeyCode::Char('k')), &mut app);
        assert_eq!(app.session_graph.scroll, 3);
    }

    #[test]
    fn test_session_graph_q_closes() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('g')), &mut app);
        assert!(app.session_graph.visible);
        handle_key_event(press(KeyCode::Char('q')), &mut app);
        assert!(!app.session_graph.visible);
    }

    // ── Status bar feature tests ────────────────────────────────────

    #[test]
    fn test_t_toggles_utc_time() {
        let mut app = App::new("test".into());
        assert!(app.show_utc_time);
        handle_key_event(press(KeyCode::Char('t')), &mut app);
        assert!(!app.show_utc_time);
        handle_key_event(press(KeyCode::Char('t')), &mut app);
        assert!(app.show_utc_time);
    }

    // ── Chat panel tests ────────────────────────────────────────────

    #[test]
    fn test_ctrl_t_toggles_chat() {
        let mut app = App::new("test".into());
        assert!(!app.chat_visible);
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);
        assert!(app.chat_visible);
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);
        assert!(!app.chat_visible);
    }

    #[test]
    fn test_chat_typing() {
        let mut app = App::new("test".into());
        // Open chat
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);
        assert!(app.chat_visible);

        // Type into chat
        handle_key_event(press(KeyCode::Char('h')), &mut app);
        handle_key_event(press(KeyCode::Char('i')), &mut app);
        assert_eq!(app.chat_input, "hi");
        assert_eq!(app.chat_cursor, 2);
    }

    #[test]
    fn test_chat_send_returns_event() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);

        // Type a message
        handle_key_event(press(KeyCode::Char('h')), &mut app);
        handle_key_event(press(KeyCode::Char('i')), &mut app);

        // Send with Enter
        let result = handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(matches!(result, EventResult::SendChatMessage { .. }));
        if let EventResult::SendChatMessage { content, channel } = result {
            assert_eq!(content, "hi");
            assert_eq!(channel, "global");
        }
        // Input should be cleared after send
        assert!(app.chat_input.is_empty());
    }

    #[test]
    fn test_chat_esc_closes() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);
        assert!(app.chat_visible);
        handle_key_event(press(KeyCode::Esc), &mut app);
        assert!(!app.chat_visible);
    }

    #[test]
    fn test_chat_empty_send_ignored() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);
        let result = handle_key_event(press(KeyCode::Enter), &mut app);
        assert!(matches!(result, EventResult::Continue));
    }

    #[test]
    fn test_chat_backspace() {
        let mut app = App::new("test".into());
        handle_key_event(ctrl(KeyCode::Char('t')), &mut app);
        handle_key_event(press(KeyCode::Char('a')), &mut app);
        handle_key_event(press(KeyCode::Char('b')), &mut app);
        handle_key_event(press(KeyCode::Backspace), &mut app);
        assert_eq!(app.chat_input, "a");
    }
}
