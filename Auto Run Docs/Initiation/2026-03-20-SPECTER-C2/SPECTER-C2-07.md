# Phase 07: TUI Client Advanced Features

This phase transforms the basic TUI from Phase 01 into a fully-featured operator interface. It adds the interaction console (command input with history and tab-completion), real-time task submission and output streaming, Vim-style modal keybindings (Normal/Command/Search/Insert modes), the command palette (Ctrl-P fuzzy search), a session graph view (ASCII art showing pivot relationships), rich output formatting (JSON pretty-printing, hex dumps, pagination), and desktop notifications. By the end, the TUI is a fast, keyboard-driven, information-dense operator console.

## Context

The TUI client (`crates/specter-client/`) from Phase 01 has session listing, panel layout, and basic keyboard navigation. This phase adds the remaining features: interaction console, tasking, Vim navigation, command palette, session graph, task history, tab completion, and notifications. The TUI connects to the teamserver via gRPC.

TUI source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-client\`
Search existing code in `src/ui/` and `src/event_handler.rs` to understand the current architecture before adding new widgets.

## Tasks

- [x] Implement the interaction console in the center panel:
  - Create `src/ui/console.rs` — interactive command console widget:
    - Command input line at bottom with `specter>` prompt, cursor tracking, insert/delete/backspace/home/end/word-jump (Ctrl-Left/Right)
    - Command history (Vec<String>) with up/down navigation, Ctrl-R reverse search
    - Scrollable output area above input — timestamps, source session, task type, content
    - ANSI color code rendering (map ANSI escapes to ratatui styles)
    - Auto-scroll to bottom, manual scroll with PgUp/PgDn, Ctrl-U/Ctrl-D for half-page
  - Create `src/commands/mod.rs` — command parser and registry:
    - `parse_command(input) -> ParsedCommand`, HashMap<String, CommandHandler> registry
    - Built-in commands: `shell`, `upload`, `download`, `ps`, `ls`, `pwd`, `cd`, `whoami`, `sleep`, `kill`, `exit`, `help`, `sessions`, `use`, `jobs`, `clear`
    - Each command validates args, creates QueueTaskRequest, sends via gRPC
  - Wire console to gRPC: queue tasks on submit, subscribe to task completion events, append formatted output

- [x] Implement Vim-style modal keybindings:
  - Create `src/input/mod.rs` — modal input system:
    - Mode enum: Normal, Command, Search, Insert
    - Normal mode: j/k/g/G navigation, Enter selects session + enters Insert, Tab cycles panels, `?` toggles keybinding cheatsheet, `d` marks session dead, `r` refreshes, `1`/`2`/`3` jumps to panel, Ctrl-L redraws
    - `:` → Command mode (command prompt), `/` → Search mode (search bar), `i`/Enter → Insert mode (console input), Escape → Normal mode
    - Command mode: type command at `:` prompt, Enter executes, Tab autocompletes, Escape cancels
    - Search mode: fuzzy match against session hostnames/usernames/IPs, `n`/`N` next/prev match, Enter selects, Escape cancels
  - Update `src/event_handler.rs` to route all key events through modal system
  - Display current mode in status bar
  <!-- Completed: Created src/input/mod.rs with InputMode enum (Normal/Command/Search/Insert), CommandPrompt, SearchState, and CheatsheetState. Rewrote event_handler.rs to route all keys through modal dispatch. Updated status bar with bold mode indicator and command/search prompt display. All 61 specter-client tests pass (167 workspace total). -->

- [x] Implement command palette and fuzzy search:
  - Create `src/ui/palette.rs` — command palette overlay:
    - Triggered by Ctrl-P in any mode, centered floating overlay (60% width, 50% height)
    - Search input with fuzzy filtering, scrollable results list
    - Categories: Commands, Sessions, Modules, Recent Tasks
    - Enter selects, Escape closes
  - Create `src/search/fuzzy.rs` — character-by-character fuzzy match with scoring (consecutive matches, word boundaries, start position), returns sorted results with highlighted positions
  - Searchable items: commands, sessions, modules (from teamserver), recent task history (last 50)
  <!-- Completed: Created src/search/fuzzy.rs with character-by-character fuzzy matching (consecutive bonus, word boundary bonus, start position bonus, spread penalty), fuzzy_search() for sorted results. Created src/ui/palette.rs with PaletteState, PaletteItem (3 categories: Command/Session/RecentTask), centered overlay rendering with Clear widget, category-colored labels, and selection highlighting. Added PaletteState to App, Ctrl-P opens palette from any mode (except Search where it means prev match), palette Enter selects items (commands fill console input, sessions switch active session, recent tasks fill console). All 82 specter-client tests pass (188 workspace total). -->

- [x] Implement context panel tabs and tab completion:
  - Update `src/ui/context_panel.rs` with tab system: [Info] [Process] [Tasks] [Network]
    - Navigate tabs with `h`/`l` when focused
    - Info tab: full session details (hostname, user, domain, PID, process, OS, arch, integrity, IPs, channel, timestamps, session ID)
    - Process tab: process tree with box-drawing characters, implant process highlighted green
    - Tasks tab: scrollable task history (ID, Type, Status icon, Submitted, Completed, Operator), Enter shows full output in console
    - Network tab: placeholder for connection data
  - Create `src/commands/completion.rs` — context-aware tab completion:
    - Empty input: all commands; `upload `: local file paths; `download `: cached remote paths; `use `: session IDs/hostnames; `sleep `: common intervals
    - Tab cycles forward, Shift-Tab backward, popup above input (max 5 items)
  - Create `src/commands/history.rs` — persistent history at `~/.specter/history` (max 1000 entries), Ctrl-R reverse search
  <!-- Completed: Added ContextTab enum (Info/Process/Tasks/Network) with h/l navigation when context panel focused. Rewrote context_panel.rs with tab bar and 4 tab renderers (Info shows full session details, Process shows tree with implant highlighted green, Tasks shows scrollable history with status icons, Network shows placeholder). Created commands/completion.rs with context-aware tab completion (command names, session IDs/hostnames for `use`, sleep intervals, local file paths for `upload`), Tab/Shift-Tab cycling, popup above input (max 5 items). Created commands/history.rs with persistent history at ~/.specter/history (max 1000 entries, dedup), ReverseSearchState for Ctrl-R. Updated console.rs with completion popup overlay and reverse search display. All 115 specter-client tests pass (221 workspace total). -->

- [x] Implement session graph view and rich output formatting:
  - Create `src/ui/session_graph.rs` — ASCII session graph toggled with Ctrl-G:
    - Nodes = sessions, edges = pivot links (SMB/lateral movement parent-child)
    - Box-drawing characters, color-coded by status, track pivot relationships in app state
  - Create `src/ui/output_format.rs` — rich output:
    - JSON pretty-printing with syntax highlighting (keys cyan, strings green, numbers yellow, booleans magenta)
    - Hex dump for binary output (address | hex bytes | ASCII)
    - Large output pagination with `-- More --` prompt
    - Table formatting for structured output (process lists, file listings): auto-detect columnar data, align columns
  - Desktop notifications: terminal bell on new session, session lost, high-priority task complete (configurable level)
  - Update status bar: alert ticker (scrolling recent events), connected operators count, UTC/local time toggle (`t`)
  <!-- Completed: Created src/ui/session_graph.rs with SessionGraphState, PivotLink, ASCII box-drawing graph (nodes=sessions, edges=pivot links), Ctrl-G toggle overlay with scroll support, color-coded by status, legend. Created src/ui/output_format.rs with format_output() auto-detection, format_json() with syntax highlighting (keys cyan, strings green, numbers yellow, booleans magenta), hex_dump() (address|hex|ASCII), format_table() with aligned columns and header, PaginationState with page navigation. Created src/notifications.rs with NotifyLevel (Off/Critical/Normal/Verbose), NotifyEvent, terminal bell, AlertTicker for status bar. Updated status_bar.rs with operator count, UTC/local time toggle (t key), notify level display, alert ticker (recent events <30s). Added Ctrl-G and t keybindings to event_handler.rs, session graph key handler (Esc/q/j/k/PgUp/PgDn). All 148 specter-client tests pass (254 workspace total). -->

- [x] Write tests for command parsing, fuzzy search, and completion:
  - `crates/specter-client/tests/command_tests.rs` — all built-in commands, argument validation, help text
  - `crates/specter-client/tests/fuzzy_tests.rs` — various inputs and rankings, edge cases
  - `crates/specter-client/tests/completion_tests.rs` — context-aware completion, history search
  - Run `cargo test -p specter-client`
  <!-- Completed: Added src/lib.rs to expose commands/search/input/notifications modules for integration testing. Created 3 integration test files: command_tests.rs (36 tests covering registry, parsing, validation for all 16 commands, task arg building, round-trip tests, help text), fuzzy_tests.rs (27 tests covering matching, scoring bonuses, ranking, edge cases including unicode/long strings/camelCase), completion_tests.rs (38 tests covering command/session/sleep completion, CompletionState cycling, apply_completion, PersistentHistory, reverse search). All 101 new integration tests + 209 existing tests pass (310 workspace total). -->
