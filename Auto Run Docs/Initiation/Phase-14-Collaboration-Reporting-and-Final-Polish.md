# Phase 14: Collaboration, Reporting & Final Polish

This phase delivers the final features that make SPECTER a production-ready multi-operator engagement platform: real-time collaboration (operator presence indicators, shared cursor visibility, in-app chat), engagement report generation (one-click Markdown/DOCX/PDF reports from the task timeline), anti-analysis countermeasures in the implant (VM/sandbox/debugger detection), the CI/CD pipeline (GitHub Actions building all components, YARA scanning, automated testing), and Docker packaging for the teamserver. By the end of this phase, SPECTER is a complete, polished C2 framework ready for professional red team engagements — with every feature from the technical specification implemented.

## Context

This is the final phase. It covers the remaining features from the spec that weren't addressed in previous phases: collaboration features (Section 10.2), report generation (Section 10.2), anti-analysis (Section 11), and CI/CD (Section 13). It also includes overall integration testing and quality hardening.

Teamserver: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`
TUI Client: `/Users/mdebaets/Documents/SPECTER/crates/specter-client/`
Web UI: `/Users/mdebaets/Documents/SPECTER/web/`
Implant: `/Users/mdebaets/Documents/SPECTER/implant/`

## Tasks

- [x] Implement real-time collaboration features in the teamserver:
  - Create `crates/specter-server/src/collaboration/mod.rs`:
    - **Operator presence tracking**:
      - `PresenceManager` struct: tracks connected operators, their active sessions, and last activity timestamp
      - When an operator connects (gRPC stream established): add to presence list
      - When an operator interacts with a session: update their active session and last activity
      - When an operator disconnects (stream closed): remove from presence list
      - Broadcast presence updates to all connected clients via the event bus
    - **Presence events**:
      - `OperatorConnected(operator_id, username)` — operator came online
      - `OperatorDisconnected(operator_id, username)` — operator went offline
      - `OperatorActiveSession(operator_id, session_id)` — operator is interacting with a session
    - Add protobuf messages and streaming RPCs:
      - `PresenceUpdate` message: operator_id, username, status (online/away/busy), active_session_id, last_activity
      - `SubscribePresence()` → server-streaming RPC for real-time presence updates
      - `GetActiveOperators()` → unary RPC returning all currently connected operators
  - Create `crates/specter-server/src/collaboration/chat.rs`:
    - **In-app operator chat**:
      - `ChatMessage` struct: id, sender_id, sender_name, content, channel (global or per-session), timestamp
      - Store messages in SQLite `chat_messages` table
      - `send_message(sender, content, channel)` → store and broadcast to all connected operators
      - `get_messages(channel, since_timestamp, limit)` → retrieve message history
    - Add protobuf messages and RPCs:
      - `SendChatMessage(content, channel)` → send a chat message
      - `SubscribeChat(channel)` → server-streaming RPC for real-time chat
      - `GetChatHistory(channel, since, limit)` → fetch historical messages
  - Update TUI client for collaboration:
    - Show operator presence in the status bar: "Operators: alice (DC01), bob (WS02), charlie (idle)"
    - Session list: show operator avatar/name next to sessions they're actively interacting with
    - Chat panel: toggle with `Ctrl-T`, shows chat messages at the bottom of the screen, input line for sending messages
  - Update Web UI for collaboration:
    - Operator avatars on the sidebar with online/offline status
    - Session list: presence indicator showing which operator is on which session
    - Chat widget: floating chat panel (bottom-right corner), supports global and per-session channels
    - Shared cursor visibility (optional): when two operators interact with the same session, show the other operator's cursor position in the terminal

- [x] Implement engagement report generation:
  - Create `crates/specter-server/src/reports/mod.rs`:
    - **Report generator** that produces engagement reports from the task timeline and audit log:
    - `ReportConfig` struct:
      - campaign_id (scope report to a campaign)
      - time_range (start_date, end_date)
      - include_sections: Vec<ReportSection> (timeline, ioc_list, findings, recommendations)
      - operator_filter: Option<Vec<operator_id>> (filter by operator)
      - format: enum (Markdown, JSON)
      - template: Option<String> (custom template path)
    - `generate_report(config: ReportConfig) -> Report`:
      1. Query task timeline for the campaign/time range
      2. Query audit log for operator actions
      3. Query session metadata for target information
      4. Build report sections:
         - **Executive summary**: campaign name, date range, number of sessions, high-level statistics
         - **Timeline of actions**: chronological list of all operator actions with timestamps, targets, and results
         - **IOC (Indicators of Compromise) list**: automatically extracted from session data and tasks:
           - IP addresses (implant callback IPs)
           - Domain names (C2 domains from profile/redirector configs)
           - File hashes (implant payload hashes)
           - Named pipes (from SMB channel configs)
           - Service names (from lateral movement tasks)
           - Process names (injection targets)
         - **Findings**: operator-annotated findings (linked from task results)
         - **Recommendations**: placeholder section for manual operator input
      5. Format output according to selected format
    - `render_markdown(report: &Report) -> String` — render report as Markdown document
    - `render_json(report: &Report) -> serde_json::Value` — structured JSON output
  - Add gRPC RPCs:
    - `GenerateReport(config)` → returns report content as string
    - `ListReports()` → list previously generated reports (stored in database)
    - `GetReport(id)` → retrieve a stored report
  - Web UI report page:
    - Create `web/src/pages/Reports.tsx`:
      - Report generation wizard: select campaign, date range, sections, format
      - Preview report in-browser (rendered Markdown)
      - Download buttons: .md, .json
      - Report history: list of previously generated reports
  - TUI command: `report generate [campaign_id] [--format md|json]` → generates and displays/saves report

- [x] Implement anti-analysis countermeasures in the implant:
  - Create `implant/core/src/evasion/antianalysis.c` and `implant/core/include/antianalysis.h`:
    - **VM detection**:
      - CPUID check: query hypervisor brand string (leaf 0x40000000) — detect VMware, Hyper-V, KVM, VirtualBox, QEMU
      - Registry artifacts: check for VM-specific registry keys (HKLM\SOFTWARE\VMware, VirtualBox Guest Additions, etc.) via bus->reg_read
      - MAC address prefix: check network adapter MAC against known VM MAC prefixes (00:0C:29 VMware, 08:00:27 VirtualBox, etc.)
      - Process enumeration: check for VM tools processes (vmtoolsd.exe, VBoxService.exe, qemu-ga.exe) via NtQuerySystemInformation
      - Firmware tables: SMBIOS strings containing "VMware", "VirtualBox", "QEMU" — via GetSystemFirmwareTable
    - **Sandbox detection**:
      - Timing check: measure elapsed time for a known-duration operation — sandboxes often accelerate time
      - Process count: very low process count indicates sandbox (typical desktop: 80+, sandbox: <30)
      - User interaction: check for recent user input (GetLastInputInfo) — sandboxes typically have no mouse/keyboard activity
      - File system artifacts: check for analysis tool artifacts (Procmon, Wireshark, IDA)
      - Recent files: check if Recent Documents has entries — fresh sandbox VMs have empty Recent
      - Screen resolution: very low resolution or single monitor suggests sandbox
    - **Debugger detection**:
      - IsDebuggerPresent equivalent: check PEB->BeingDebugged flag directly via PEB walk
      - NtQueryInformationProcess with ProcessDebugPort — non-zero means debugger attached
      - Timing-based: RDTSC delta check — debugger stepping inflates cycle counts
      - Hardware breakpoint check: read DR0-DR3 via NtGetContextThread — non-zero indicates HW breakpoints set by debugger
    - `antianalysis_check(IMPLANT_CONTEXT* ctx) -> ANALYSIS_RESULT`:
      - Run all checks, aggregate results with confidence score
      - Return: RESULT_CLEAN, RESULT_VM_DETECTED, RESULT_SANDBOX_DETECTED, RESULT_DEBUGGER_DETECTED
    - Configurable response (set in implant config):
      - EXIT: zero-fill all memory, terminate immediately
      - SLEEP_FOREVER: enter indefinite sleep (check-in interval = MAX_INT)
      - DECOY: execute a benign decoy payload (e.g., open calc.exe, display error message)
      - IGNORE: continue normally (for testing in VMs during development)
    - Integration: run anti-analysis checks once during `implant_entry()` init sequence, before establishing comms

- [x] Set up CI/CD pipeline and Docker packaging:
  - Create `.github/workflows/ci.yml` — GitHub Actions CI pipeline:
    - **Trigger**: on push to main/develop, on pull requests
    - **Jobs**:
      - `build-teamserver`: `cargo build --release -p specter-server` on ubuntu-latest, macos-latest, windows-latest
      - `build-client`: `cargo build --release -p specter-client` on all three platforms
      - `build-implant`: install mingw-w64, run `make -C implant` on ubuntu-latest (cross-compile)
      - `build-modules`: `make -C implant modules` on ubuntu-latest
      - `build-webui`: `cd web && npm ci && npm run build && npm run type-check && npm run lint`
      - `test-rust`: `cargo test --workspace` on ubuntu-latest
      - `test-implant`: `make -C implant test` on ubuntu-latest
      - `test-webui`: `cd web && npm test` on ubuntu-latest
      - `yara-scan`: run YARA rules against generated implant payloads, fail on matches
      - `clippy`: `cargo clippy --workspace -- -D warnings`
      - `fmt`: `cargo fmt --all -- --check`
    - **Artifacts**: upload compiled binaries as workflow artifacts (teamserver for all 3 platforms, client for all 3, implant .bin, modules .bin, web UI dist)
    - **Release workflow** (`.github/workflows/release.yml`):
      - Trigger: on tag push (v*)
      - Build all components in release mode
      - Create GitHub release with all binaries attached
  - Create `Dockerfile` at project root — teamserver Docker image:
    - Multi-stage build:
      - Stage 1: Rust builder (rust:latest) — build teamserver and client
      - Stage 2: Node.js builder (node:20) — build Web UI
      - Stage 3: Runtime (debian:slim) — copy binaries and web assets
    - Runtime image includes: teamserver binary, client binary, web UI dist, default profiles, YARA rules
    - Entrypoint: `specter-server` with configurable args via environment variables
    - Volume mounts: `/data` (database, certificates), `/config` (profiles, redirector configs)
    - Expose ports: 50051 (gRPC), 443 (HTTPS listener), 80 (HTTP redirect)
  - Create `docker-compose.yml` for quick deployment:
    - Service: specter-teamserver with volume mounts and port mapping
    - Optional: PostgreSQL service for multi-teamserver deployments
  - Update `CLAUDE.md` with CI/CD and Docker instructions

- [x] Implement offline capability for the Web UI:
  - Create `web/src/sw.ts` — Service Worker for offline support:
    - Cache static assets (JS, CSS, fonts) for offline access
    - Cache session data and task history in IndexedDB
    - When teamserver connection drops:
      - Show "Offline" indicator in the top bar
      - Continue displaying cached session data and task history
      - Queue task submissions for delivery on reconnection
      - Show toast notification: "Connection lost. Tasks will be queued and sent when connection is restored."
    - When connection restores:
      - Sync queued tasks to teamserver
      - Refresh session data
      - Show toast: "Connection restored. X queued tasks sent."
  - Register service worker in `web/src/main.tsx`
  - Configure Vite PWA plugin (`vite-plugin-pwa`) for service worker generation

- [x] Run comprehensive integration tests and final verification:
  - Create `tests/integration/` directory at project root for end-to-end tests:
    - `test_full_flow.sh` — shell script that:
      1. Build all components (`cargo build --workspace && make -C implant && cd web && npm run build`)
      2. Start teamserver in dev mode (background process)
      3. Wait for teamserver to be ready (poll gRPC health endpoint)
      4. Run mock implant with 5 simulated sessions
      5. Verify sessions appear via gRPC client call
      6. Queue tasks and verify results
      7. Generate a test report
      8. Stop teamserver
      9. Report pass/fail
    - `test_profile_roundtrip.sh` — test profile compilation and check-in formatting
    - `test_auth_flow.sh` — test certificate issuance, mTLS connection, RBAC enforcement
  - Final build verification:
    - `cargo build --release --workspace` — all Rust components build without warnings
    - `cargo test --workspace` — all tests pass
    - `cargo clippy --workspace -- -D warnings` — no clippy warnings
    - `make -C implant` — implant builds, size < 20KB
    - `make -C implant modules` — all modules build
    - `cd web && npm run build && npm test` — Web UI builds and tests pass
  - Run `make size -C implant` and document final implant core size in the project README
