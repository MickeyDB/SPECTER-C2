# Phase 07: TUI Client Advanced Features

This phase transforms the basic TUI client from Phase 01 into a fully-featured operator interface. It adds the interaction console (command input with tab-completion, history, and syntax highlighting), real-time task submission and output streaming, Vim-style modal keybindings (normal mode, command mode, search mode), the command palette (Ctrl-P fuzzy search), the session graph view (ASCII art showing pivot relationships), rich output handling (JSON pretty-printing, hex dumps, pagination), and desktop notifications. By the end of this phase, the TUI is a fast, keyboard-driven, information-dense operator console that rivals professional terminal applications.

## Context

The TUI client (`crates/specter-client/`) was created in Phase 01 with basic session listing, panel layout, and keyboard navigation. This phase adds the remaining features defined in the spec: interaction console, tasking, Vim navigation, command palette, session graph, task history, tab completion, and notifications. The TUI connects to the teamserver via gRPC (SpecterService).

TUI source: `/Users/mdebaets/Documents/SPECTER/crates/specter-client/`

## Tasks

- [ ] Implement the interaction console in the center panel:
  - Create `src/ui/console.rs` — the interactive command console widget:
    - Command input line at the bottom of the center panel with a `specter>` prompt
    - Input buffer with cursor position tracking (insert, delete, backspace, home, end, word-jump with Ctrl-Left/Right)
    - Command history (Vec<String>) with up/down arrow navigation
    - Ctrl-R reverse search through history (like bash)
    - Output display area above the input line — scrollable, paginated
    - Output rendering: each output entry has a timestamp, source session, task type, and content
    - ANSI color code support (render ANSI escape sequences as ratatui styles)
    - Auto-scroll to bottom on new output, with ability to scroll up (PgUp/PgDn, Ctrl-U/Ctrl-D for half-page)
  - Create `src/commands/mod.rs` — command parser and registry:
    - `parse_command(input: &str) -> ParsedCommand` — split input into command name + arguments
    - Command registry: HashMap<String, CommandHandler>
    - Built-in commands:
      - `shell <command>` — queue shell execution task on selected session
      - `upload <local_path> <remote_path>` — queue file upload task
      - `download <remote_path>` — queue file download task
      - `ps` — queue process listing task
      - `ls [path]` — queue directory listing task
      - `pwd` — queue current directory task
      - `cd <path>` — queue directory change task
      - `whoami` — queue identity task
      - `sleep <seconds> [jitter%]` — update implant sleep interval
      - `kill` — send kill command to implant
      - `exit` — disconnect from session (not kill implant)
      - `help [command]` — show help for all commands or a specific command
      - `sessions` — switch focus back to session list
      - `use <session_id>` — switch to a different session
      - `jobs` — list active tasks for current session
      - `clear` — clear console output
    - Each command: validates arguments, creates a QueueTaskRequest, sends via gRPC
  - Wire console to the gRPC client:
    - On command submission: queue task via `queue_task()` RPC
    - Subscribe to task completion events via `SubscribeEvents` stream
    - When a task completes: append formatted output to the console

- [ ] Implement Vim-style modal keybindings:
  - Create `src/input/mod.rs` — modal input system:
    - Mode enum: Normal, Command, Search, Insert (for console input)
    - `InputMode` state machine with transitions:
      - Normal mode (default): navigation keys active (j/k/g/G, Tab, Enter)
      - `:` enters Command mode (command palette opens)
      - `/` enters Search mode (search bar appears)
      - `i` or `Enter` on a session enters Insert mode (console input active)
      - `Escape` returns to Normal mode from any mode
    - Normal mode keybindings:
      - `j`/`k`: navigate session list up/down
      - `g`/`G`: jump to first/last session
      - `Enter`: select session, enter Insert mode for interaction
      - `Tab`: cycle panel focus (session list → console → context → session list)
      - `?`: toggle keybinding cheatsheet overlay
      - `d`: mark session as dead (operator-side only)
      - `r`: refresh session list
      - `1`/`2`/`3`: jump to specific panel
      - `Ctrl-L`: force redraw
    - Command mode keybindings:
      - Type command at `:` prompt
      - `Enter`: execute command
      - `Tab`: autocomplete
      - `Escape`: cancel
    - Search mode:
      - `/` prompt for search query
      - Fuzzy match against session hostnames, usernames, IPs
      - `n`/`N`: next/previous match
      - `Enter`: select matched session
      - `Escape`: cancel search
  - Update `src/event_handler.rs` to route all key events through the modal input system
  - Display current mode in the status bar (NORMAL, COMMAND, SEARCH, INSERT)

- [ ] Implement the command palette and fuzzy search:
  - Create `src/ui/palette.rs` — command palette overlay widget:
    - Triggered by `Ctrl-P` in any mode
    - Renders as a centered floating overlay (60% width, up to 50% height)
    - Search input at top with fuzzy filtering
    - Scrollable results list below
    - Categories: Commands, Sessions, Modules, Recent Tasks
    - `Enter` selects, `Escape` closes
  - Create `src/search/fuzzy.rs` — fuzzy matching algorithm:
    - Simple character-by-character fuzzy match with scoring
    - Score based on: consecutive matches, match at word boundaries, match at start
    - Returns sorted results with highlighted match positions
  - Searchable items:
    - All registered commands (from command registry)
    - All sessions (by hostname, username, IP, session ID)
    - All available modules (fetched from teamserver)
    - Recent task history (last 50 tasks)

- [ ] Implement the context panel with detailed session info and tabs:
  - Update `src/ui/context_panel.rs`:
    - Tab system at the top of the context panel: [Info] [Process] [Tasks] [Network]
    - Navigate tabs with `h`/`l` when context panel is focused
    - **Info tab** (default): full session details — hostname, username, domain, PID, process name, OS version, architecture, integrity level, internal IP, external IP, active channel, first seen, last check-in, session ID, implant version
    - **Process tab**: process tree for the target system (when data available from a `ps` task result):
      - Tree rendering with box-drawing characters
      - Highlight the implant's process in green
      - Show PID, process name, user, session for each process
    - **Tasks tab**: task history for the selected session:
      - Scrollable list of all tasks (newest first)
      - Columns: ID (short), Type, Status (icon), Submitted, Completed, Operator
      - Status icons: ⏳ queued, ▶ dispatched, ✓ complete, ✗ failed
      - `Enter` on a task: show full task output in the console panel
    - **Network tab**: placeholder for network connections data (populated by future modules)

- [ ] Implement tab completion for commands:
  - Create `src/commands/completion.rs`:
    - Context-aware tab completion in the console input:
      - Empty input: show all available commands
      - `shell `: no completion (free-form)
      - `upload `: complete local file paths (read local filesystem)
      - `download `: complete remote file paths (if remote file listing data available from previous `ls` results, cached per session)
      - `use `: complete session IDs and hostnames
      - `sleep `: suggest common intervals (5, 10, 30, 60, 300)
    - Tab cycles through completions, Shift-Tab cycles backward
    - Show completion suggestions as a small popup above the input line (max 5 items)
  - Create `src/commands/history.rs`:
    - Persistent command history (save to `~/.specter/history` file)
    - Configurable max history size (default 1000)
    - Ctrl-R reverse search: incrementally filter history as user types

- [ ] Implement the session graph view and rich output formatting:
  - Create `src/ui/session_graph.rs` — ASCII session graph:
    - Toggle with `Ctrl-G` — replaces the center panel content with a graph view
    - Nodes are sessions, edges are pivot links (SMB connections, lateral movement parent-child)
    - Render using box-drawing characters:
      ```
      ┌──────────────┐     ┌──────────────┐
      │ DC01 (SYSTEM) │────▶│ WS01 (admin) │
      │ 10.0.0.1      │     │ 10.0.0.10    │
      └──────────────┘     └──────────────┘
                                  │
                                  ▼
                           ┌──────────────┐
                           │ WS02 (user)  │
                           │ 10.0.0.11    │
                           └──────────────┘
      ```
    - Color-code nodes by session status (same colors as session list)
    - Track pivot relationships in app state (updated from lateral movement task results and teamserver session metadata)
  - Create `src/ui/output_format.rs` — rich output rendering:
    - JSON pretty-printing with syntax highlighting (keys in cyan, strings in green, numbers in yellow, booleans in magenta)
    - Hex dump for binary output (address | hex bytes | ASCII sidebar)
    - Large output pagination: if output exceeds terminal height, show `-- More (q to quit, Enter for next page) --`
    - Table formatting for structured output (process lists, file listings): auto-detect columnar data and align columns
  - Add desktop notifications:
    - Use terminal bell (`\x07`) for basic notification
    - Notify on: new session callback, session lost, high-priority task complete
    - Configurable notification level (all, important, none)
  - Update the status bar to include:
    - Alert ticker: scrolling text showing recent events (new session, completed tasks)
    - Connected operators count (from teamserver)
    - Current time (UTC and local, toggled with `t`)

- [ ] Write tests for TUI command parsing and fuzzy search:
  - `crates/specter-client/tests/command_tests.rs`:
    - Test command parsing for all built-in commands
    - Test argument validation (missing required args, invalid values)
    - Test help text generation
  - `crates/specter-client/tests/fuzzy_tests.rs`:
    - Test fuzzy matching with various inputs and expected rankings
    - Test edge cases: empty query, exact match, no match
  - `crates/specter-client/tests/completion_tests.rs`:
    - Test tab completion for each command context
    - Test history search filtering
  - Run `cargo test -p specter-client`
