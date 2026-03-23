# Phase 14: Collaboration, Reporting & Final Polish

This phase delivers the final features for a production-ready multi-operator platform: real-time collaboration (operator presence, in-app chat), engagement report generation (one-click Markdown/JSON from the task timeline with IOC extraction), anti-analysis countermeasures in the implant (VM/sandbox/debugger detection), the CI/CD pipeline (GitHub Actions), and Docker packaging. By the end, SPECTER is a complete, polished C2 framework ready for professional red team engagements with every feature from the technical specification implemented.

## Context

This final phase covers: collaboration (spec Section 10.2), report generation (Section 10.2), anti-analysis (Section 11), CI/CD (Section 13), and overall integration testing. It ties together all previous phases into a cohesive product.

Teamserver: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`
TUI Client: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-client\`
Web UI: `C:\Users\localuser\Documents\SPECTER-C2\web\`
Implant: `C:\Users\localuser\Documents\SPECTER-C2\implant\`

## Tasks

- [x] Implement real-time collaboration features:
  - Create `crates/specter-server/src/collaboration/mod.rs`:
    - `PresenceManager`: track connected operators, active sessions, last activity; broadcast OperatorConnected/Disconnected/ActiveSession events via event bus
    - Protobuf: `PresenceUpdate` message, `SubscribePresence()` server-streaming RPC, `GetActiveOperators()` unary RPC
  - Create `crates/specter-server/src/collaboration/chat.rs`:
    - `ChatMessage` struct (sender, content, channel: global or per-session, timestamp), store in `chat_messages` table
    - `send_message`, `get_messages(channel, since, limit)`
    - Protobuf: SendChatMessage, SubscribeChat (streaming), GetChatHistory RPCs
  - TUI updates: operator presence in status bar ("Operators: alice (DC01), bob (idle)"), session list shows active operator, Ctrl-T toggles chat panel
  - Web UI updates: operator avatars with status in sidebar, session list presence indicators, floating chat widget (bottom-right)

- [x] Implement engagement report generation:
  - Create `crates/specter-server/src/reports/mod.rs`:
    - `ReportConfig`: campaign_id, time_range, include_sections (timeline, ioc_list, findings, recommendations), operator_filter, format (Markdown/JSON)
    - `generate_report(config)`: query task timeline + audit log + session metadata → build sections:
      - Executive summary: campaign stats
      - Timeline of actions: chronological operator actions
      - IOC list: auto-extracted IPs, domains, file hashes, named pipes, service names, process names
      - Findings: operator-annotated from task results
      - Recommendations: placeholder for manual input
    - `render_markdown(report)` and `render_json(report)`
  - Add gRPC RPCs: GenerateReport, ListReports, GetReport
  - Web UI: Reports page with generation wizard, in-browser preview, download .md/.json
  - TUI: `report generate [campaign_id] [--format md|json]`

- [x] Implement anti-analysis countermeasures in the implant:
  - Create `implant/core/src/evasion/antianalysis.c` and `implant/core/include/antianalysis.h`:
    - VM detection: CPUID hypervisor brand string (VMware/Hyper-V/KVM/VBox/QEMU), registry artifacts, MAC address prefixes, VM tools processes, SMBIOS firmware strings
    - Sandbox detection: timing checks (accelerated time), process count (<30 suspicious), user interaction (GetLastInputInfo), analysis tool artifacts, empty Recent Documents, low screen resolution
    - Debugger detection: PEB->BeingDebugged flag, NtQueryInformationProcess ProcessDebugPort, RDTSC delta, hardware breakpoints (DR0-DR3)
    - `antianalysis_check(ctx) -> ANALYSIS_RESULT` (CLEAN/VM/SANDBOX/DEBUGGER with confidence)
    - Configurable response: EXIT (zero-fill + terminate), SLEEP_FOREVER, DECOY (run benign payload), IGNORE (for dev/testing)
    - Run during implant_entry init before establishing comms

- [x] Set up CI/CD pipeline and Docker packaging:
  - Create `.github/workflows/ci.yml`:
    - Trigger on push to main/develop and PRs
    - Jobs: build-teamserver (3 platforms), build-client (3 platforms), build-implant (MinGW cross-compile), build-modules, build-webui, test-rust, test-implant, test-webui, yara-scan, clippy, fmt
    - Upload artifacts: binaries for all platforms, implant .bin, modules, web dist
  - Create `.github/workflows/release.yml`: trigger on tag v*, build release, create GitHub release
  - Create `Dockerfile` — multi-stage:
    - Stage 1: Rust builder → teamserver + client binaries
    - Stage 2: Node.js builder → Web UI dist
    - Stage 3: debian:slim runtime with binaries + web assets + profiles + YARA rules
    - Expose 50051 (gRPC), 443 (HTTPS), volume mounts /data and /config
  - Create `docker-compose.yml` with specter-teamserver service

- [x] Run comprehensive integration tests and final verification:
  - Create `tests/integration/` at project root:
    - `test_full_flow.sh`: build all → start teamserver (dev mode) → run 5 mock implants → verify sessions via gRPC → queue tasks → verify results → generate report → stop → report pass/fail
    - `test_profile_roundtrip.sh`: compile profile → format check-in → validate matching
    - `test_auth_flow.sh`: cert issuance → mTLS connect → RBAC enforcement
  - Final build verification:
    - `cargo build --release --workspace` — no warnings
    - `cargo test --workspace` — all pass
    - `cargo clippy --workspace -- -D warnings` — clean
    - `make -C implant` — builds, size < 20KB
    - `make -C implant modules` — all build
    - `cd web && npm run build && npm test` — builds and passes
  - Create `web/src/sw.ts` — Service Worker for offline support:
    - Cache static assets, session data in IndexedDB, queue tasks offline, sync on reconnect
    - Register in main.tsx, configure vite-plugin-pwa
