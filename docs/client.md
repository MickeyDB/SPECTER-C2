# TUI Client Documentation

The TUI client (`specter-client`) is a terminal-based operator interface built with Ratatui and crossterm.

## Starting the Client

```bash
# Development mode (no auth)
cargo run -p specter-client -- --dev-mode --server http://localhost:50051

# Token authentication
cargo run -p specter-client -- --server https://teamserver:50051 --token <api-token>

# mTLS authentication
cargo run -p specter-client -- \
  --server https://teamserver:50051 \
  --cert operator.crt \
  --key operator.key \
  --ca-cert ca.crt

# First-time certificate setup
cargo run -p specter-client -- --server https://teamserver:50051 --setup
```

## UI Layout

```
┌─────────────────────────────────────────────────────┐
│  Context Panel (operator presence, session metadata) │
├──────────────────────┬──────────────────────────────┤
│                      │                              │
│   Session List       │      Main Panel              │
│   (browsable list    │   (session details,           │
│    with status       │    task list, results)        │
│    indicators)       │                              │
│                      │                              │
├──────────────────────┴──────────────────────────────┤
│  Console Panel (command input/output)                │
├─────────────────────────────────────────────────────┤
│  Chat Panel (team collaboration messages)            │
└─────────────────────────────────────────────────────┘
```

## Features

### Session Browser
- List active sessions with status indicators (NEW/ACTIVE/STALE/DEAD)
- View host metadata: hostname, username, PID, OS, integrity level, IPs
- Last check-in timestamps
- Fuzzy search across all session fields

### Session Graph
- D3-inspired network visualization of sessions
- Shows relationships and network topology

### Task Execution
- Queue tasks for selected sessions
- View task status and results in real-time
- Priority-based task ordering

### Command Console
- Interactive command input with history
- Shell completion for commands and arguments
- Command output display

### Team Collaboration
- Operator presence tracking (who is online, what session they're viewing)
- Real-time chat (global and per-session channels)

### Additional Features
- Module loading and management
- Profile compilation and testing
- Payload generation with obfuscation options
- Campaign management
- Report generation

## Key Modules

| Module | File | Purpose |
|--------|------|---------|
| App state | `app.rs` | Application state machine and mode management |
| TUI loop | `tui.rs` | Event loop and render loop |
| gRPC client | `grpc_client.rs` | Authenticated gRPC client wrapper |
| Session list | `ui/session_list.rs` | Session browser component |
| Session graph | `ui/session_graph.rs` | Network visualization |
| Console | `ui/console.rs` | Command input/output |
| Chat | `ui/chat_panel.rs` | Collaboration chat UI |
| Commands | `commands/mod.rs` | Command routing and execution |
| Completion | `commands/completion.rs` | Shell completion generation |
| History | `commands/history.rs` | Command history persistence |
| Input | `input/` | Keyboard event handling |
| Search | `search/` | Fuzzy session search |
| Config | `config.rs` | Configuration file handling |
| Events | `event_handler.rs` | gRPC event subscription processing |
| Notifications | `notifications.rs` | Status bar notifications |

## Configuration

The client reads configuration from a TOML file (default location via `dirs` crate). Configuration includes:
- Default server URL
- Authentication preferences
- UI preferences
