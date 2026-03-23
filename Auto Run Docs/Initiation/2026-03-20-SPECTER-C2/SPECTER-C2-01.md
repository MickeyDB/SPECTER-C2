# Phase 01: Build Fix, Foundation Validation & End-to-End Demo

This phase gets the existing SPECTER codebase compiling and running on Windows. The Rust workspace already contains four crates (specter-common, specter-server, specter-client, mock-implant) with protobuf definitions, a gRPC teamserver, a TUI client, and a mock implant tool — all written but currently failing to build because `protoc` is not installed. This phase installs the missing toolchain dependency, verifies the full workspace compiles, writes the remaining unit and integration tests, and validates the end-to-end demo flow. By the end, you can start the teamserver, launch the TUI, run mock implants, and watch sessions appear in real-time.

## Context

Project root: `C:\Users\localuser\Documents\SPECTER-C2`
The full technical spec lives in `C:\Users\localuser\Documents\SPECTER-C2\specter_c2_technical_specification.docx`.
Development is on Windows 11. The teamserver and TUI target Windows, Linux, and macOS. The implant (later phases) targets Windows only.

The workspace layout is:
```
crates/
  specter-common/    — Shared protobuf types, domain errors (build.rs uses tonic-build)
  specter-server/    — Teamserver (gRPC API, HTTP listeners, SQLite)
  specter-client/    — TUI operator client (Ratatui + crossterm)
tools/
  mock-implant/      — Mock implant for testing/demo
```

All source code for these four crates already exists. The only blocker is the missing `protoc` compiler needed by `tonic-build` in specter-common's `build.rs`.

## Tasks

- [x] Install protoc and verify the full workspace compiles:
  - Download the latest protoc release for Windows from https://github.com/protocolbuffers/protobuf/releases (protoc-XX.X-win64.zip)
  - Extract to a permanent location (e.g., `C:\tools\protoc\`) and add the `bin\` directory to the system PATH, or set the `PROTOC` environment variable to the full path of `protoc.exe`
  - Alternatively, install via `choco install protoc` or `winget install Google.Protobuf` if a package manager is available
  - Run `cargo check --workspace` to verify all four crates compile
  - Run `cargo build --workspace` to produce debug binaries
  - Fix any compilation errors that arise (version mismatches, Windows-specific issues)
  - Run `cargo clippy --workspace` and fix any warnings
  - Run `cargo fmt --check --all` and fix any formatting issues

- [x] Write unit and integration tests for the teamserver core:
  - Create `crates/specter-server/tests/` directory
  - `session_manager_tests.rs` — test session lifecycle:
    - register_session creates new session with valid ID
    - update_checkin updates last_checkin timestamp
    - list_sessions returns all registered sessions
    - session status transitions (ACTIVE → STALE → DEAD based on elapsed time since last check-in)
    - get_session returns correct data for existing IDs and errors for non-existing
  - `task_dispatcher_tests.rs` — test task queue:
    - queue_task creates task with correct priority
    - get_pending_tasks returns tasks ordered by priority then creation time
    - mark_dispatched changes task status
    - complete_task stores result and updates status
    - tasks are scoped to their session (no cross-session leakage)
  - `auth_tests.rs` — test authentication:
    - create_operator and authenticate flow succeeds
    - invalid credentials are rejected
    - RBAC permission checks for ADMIN, OPERATOR, OBSERVER roles
    - default admin creation on empty database
  - `listener_tests.rs` — test HTTP check-in:
    - POST /api/checkin accepts valid JSON and returns pending tasks
    - check-in creates/updates a session in the session manager
    - task results in check-in payload are processed correctly
  - Use sqlx's in-memory SQLite for test isolation (each test gets a fresh database)
  - Search existing code in `crates/specter-server/src/` for any inline `#[cfg(test)]` modules and reuse patterns found there

- [x] Run the full test suite and verify the end-to-end demo flow:
  - Run `cargo test --workspace` and ensure all tests pass
  - Run `cargo clippy --workspace` and fix any remaining warnings
  - Run `cargo fmt --check --all` and fix any formatting issues
  - Add a comment block at the top of `tools/mock-implant/src/main.rs` documenting the demo flow:
    - Terminal 1: `cargo run -p specter-server -- --dev-mode --http-port 8443 --grpc-port 50051`
    - Terminal 2: `cargo run -p specter-client -- --dev-mode --server http://localhost:50051`
    - Terminal 3: `cargo run -p mock-implant -- --server http://127.0.0.1:8443 --count 3 --interval 5`
    - Expected: TUI shows 3 sessions appearing with green ACTIVE status, cycling through check-ins
