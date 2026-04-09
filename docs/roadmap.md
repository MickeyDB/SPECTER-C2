# SPECTER C2 Framework — Roadmap

## Current Status: Stabilization Phase

The framework has a solid architecture but needs stabilization before feature expansion.
The implant beacons, executes basic commands (pwd, cd, shell), and the web UI is functional.
However, multiple code paths are undertested and several subsystems are partially integrated.

---

## Phase 0: Stabilize (CURRENT PRIORITY)

### 0.1 Fix the beacon crash
- [ ] Revert `comms_checkin` to last working state (pre goto-cleanup refactor)
- [ ] Apply minimal fix: heap-allocate only `http_buf` when payload is large
- [ ] Cache heap handle (GetProcessHeap) once at init, reuse everywhere
- [ ] Verify: `dir C:\Windows` returns output without crashing

### 0.2 Integration test
- [ ] Create `tests/e2e/` with a test that exercises: build payload → mock execute → verify checkin
- [ ] Use the mock-implant (`tools/mock-implant/`) updated to current wire format
- [ ] Run in CI before every merge

### 0.3 Remove dead code paths
- [ ] Remove legacy wire format vs profile fork — make legacy the default, profile an enhancement
- [ ] Remove TASK_SHELLCODE, TASK_UPLOAD, TASK_DOWNLOAD stubs from task_exec.c
- [ ] Remove ETW patching (user-mode only, doesn't defeat kernel ETW-TI) or clearly gate behind a flag
- [ ] Clean up stale TODO comments throughout codebase

### 0.4 Reduce patchable markers
- [ ] Consolidate SPECCFGM + SPBF into a single patchable region (e.g., 16-byte "build config" block)
- [ ] Derive config magic from PIC blob hash instead of patchable marker (both sides can compute it)
- [ ] Remove SPECSTR/SPECHASH/SPECFLOW markers — make obfuscation operate on known offsets instead

### 0.5 Cache heap handle
- [ ] Add `g_heap_handle` global set once during `sc_init` or `comms_init`
- [ ] Replace all PEB-walk-per-alloc patterns (task_alloc, crypto_heap_alloc) with cached handle
- [ ] Single PEB walk for heap at startup, reuse everywhere

---

## Phase 1: Correctness

### 1.1 TLV wire format upgrade
- [ ] Change TLV length field from u16 to u32 (both server and implant)
- [ ] Update all TLV read/write functions
- [ ] Removes the 64KB payload limit that causes silent truncation

### 1.2 AEAD for large payloads
- [ ] Fix MAC construction to be incremental (process in blocks) instead of requiring full input in memory
- [ ] Or heap-allocate MAC buffer with cached heap handle (simpler, already partially done)
- [ ] Test with 64KB command output end-to-end

### 1.3 Profile integration
- [ ] Wire profile blob from config → profile_init → comms_set_profile (code exists, bridge is in place)
- [ ] Make profile-driven path the primary path when profile is available
- [ ] Ensure profile handler on server accepts TLV binary (already fixed)
- [ ] Test: profile URI + headers used for beacon traffic through redirector

### 1.4 Hash validation
- [ ] Run `audit_hashes.py` in CI — fail build if any hash is wrong
- [ ] Add compile-time hash verification (embed expected hash, check at runtime in DEV builds)

---

## Phase 2: Evasion Hardening

### 2.1 Honest evasion documentation
- [ ] Document what each technique defeats and what it doesn't
- [ ] ETW patching: "user-mode only, does not defeat kernel ETW-TI"
- [ ] Indirect syscalls: "defeats user-mode hooks, detectable by kernel call stack analysis"
- [ ] Sleep encryption: "defeats point-in-time memory scans during sleep, not during execution"
- [ ] Stack spoofing: "defeats basic call stack inspection, not full stack unwinding with .pdata"

### 2.2 Syscall gadget rotation (implemented)
- [ ] Verify gadget pool is populated correctly
- [ ] Test that different syscalls use different gadgets

### 2.3 Module overloading RWX→RX (implemented)
- [ ] Verify the RW→copy→RX flow works on target
- [ ] Test that memory scanners see the legitimate backing file

### 2.4 Consider hardware breakpoint syscalls
- [ ] Research: does this defeat ETW-TI kernel callbacks?
- [ ] Prototype: set DR0-DR3 breakpoints on ntdll syscall stubs
- [ ] Evaluate: performance impact, compatibility across Windows versions

### 2.5 Build-time obfuscation
- [ ] Fix junk code insertion (must NOT change blob size — replace INT3 padding only)
- [ ] Verify string encryption key rotation works end-to-end
- [ ] Verify API hash salt randomization works end-to-end
- [ ] Add per-build polymorphic XOR wrapper as the outer layer

---

## Phase 3: Feature Completion

### 3.1 File transfer (upload/download)
- [ ] Implement via module bus — upload/download as built-in modules, not inline code
- [ ] Chunked transfer for large files (avoid 64KB TLV limit after Phase 1.1)
- [ ] Web UI: file picker for upload, save dialog for download

### 3.2 Interactive shell
- [ ] WebSocket-based interactive session (not poll-based)
- [ ] Server-side: ws_handler already exists, wire to session
- [ ] Implant-side: persistent cmd.exe process with stdin/stdout pipes
- [ ] Web UI: xterm.js already in place, connect to WebSocket

### 3.3 Process injection
- [ ] Implement as a module (not built-in)
- [ ] Support: classic injection, threadless injection, module stomping
- [ ] All injection goes through evasion engine (syscalls, stack spoofing)

### 3.4 Module ecosystem
- [ ] Default modules: whoami, ps, netstat, ifconfig, screenshot, keylog
- [ ] BOF compatibility layer (beacon_shim.c exists, needs testing)
- [ ] Module repository in web UI with upload, versioning, OPSEC ratings
- [ ] Per-module argument schemas for the web UI

### 3.5 Lateral movement
- [ ] SMB channel for peer-to-peer (comms/smb.c exists, needs integration)
- [ ] Token manipulation via bus API (implemented)
- [ ] Pass-the-hash / overpass-the-hash as modules

---

## Phase 4: Infrastructure

### 4.1 Redirector improvements
- [ ] Fix Azure App Service deployment (zero-dep server.js — done)
- [ ] Verify redirector domain auto-population (output key fix — done)
- [ ] Add AWS CloudFront redirector testing
- [ ] Add Cloudflare Worker redirector testing
- [ ] Domain rotation and burn detection (health monitoring exists)

### 4.2 DNS channel
- [ ] Fix DNS listener data processing (partially done)
- [ ] Test DNS-over-HTTPS (DoH) channel end-to-end
- [ ] Test subdomain encoding channel end-to-end

### 4.3 Multi-teamserver
- [ ] PostgreSQL support (Docker Compose has it commented out)
- [ ] Shared session state across teamservers
- [ ] Operator collaboration (real-time presence exists in UI)

### 4.4 Persistence
- [ ] Per-listener keypairs persisted in DB (done)
- [ ] Server CA key persistence (SPECTER_CA_KEY env var)
- [ ] Module signing key persistence across restarts
- [ ] Session recovery after teamserver restart

---

## Phase 5: Operational Polish

### 5.1 Web UI improvements
- [ ] Session interaction terminal: paste support (Ctrl+V — done), command history persistence (done)
- [ ] Profile editor: live preview of JA3, timing distribution (partially working)
- [ ] Payload builder: listener selection dropdown (done), profile URI auto-population
- [ ] Dashboard: accurate session status colors (done), redirector health
- [ ] Reports: actual report generation (exists but untested)

### 5.2 CI/CD hardening
- [ ] YARA scanning with public rule sets (done — CI job exists)
- [ ] Integration test in CI (Phase 0.2)
- [ ] Hash audit in CI (Phase 1.4)
- [ ] Implant size tracking (exists — warns on >256KB)
- [ ] Cross-platform build verification (Linux, macOS, Windows)

### 5.3 Documentation
- [ ] Deployment guide update (docs/deployment-guide.md)
- [ ] Operator guide: profile creation, payload generation, redirector setup
- [ ] Developer guide: architecture, building, testing, contributing
- [ ] Evasion transparency document (Phase 2.1)

---

## Architecture Decisions Log

### Unity build (TEMPORARY)
- **Why**: MinGW generates `.refptr` pseudo-GOT entries for cross-TU extern globals, breaking PIC loading
- **Long-term fix**: Eliminate extern globals by passing context pointers explicitly
- **When to remove**: After Phase 1 when all subsystem contexts are passed via IMPLANT_CONTEXT pointer

### Legacy vs profile code paths
- **Current**: Two separate paths in comms_checkin (legacy wire format vs profile-driven)
- **Problem**: Every change needs testing in both paths
- **Plan**: Legacy is default. Profile enhances legacy (same wire format, profile shapes the HTTP layer only)

### Heap allocation via PEB walk
- **Current**: Every task_alloc/crypto_heap_alloc does a PEB walk to find kernel32 + GetProcessHeap
- **Fix**: Cache heap handle at init (Phase 0.5)
- **Why not done**: Required a global, which conflicted with unity build constraints

### Patchable markers
- **Current**: 9+ markers in the PIC blob that the builder finds and patches
- **Problem**: Each marker is a static signature and a coordination risk
- **Plan**: Reduce to 1-2 markers (Phase 0.4), derive others from known offsets

### ETW patching
- **Current**: Patches EtwEventWrite in user-mode ntdll
- **Honest assessment**: Does NOT defeat kernel ETW-TI. CrowdStrike, MDE, SentinelOne all use kernel telemetry
- **Plan**: Keep as optional flag, document limitations clearly (Phase 2.1)

---

## Known Limitations

1. **Kernel telemetry not defeated** — ETW-TI, kernel callbacks, and minifilter drivers are out of scope for user-mode implants
2. **Behavioral detection not addressed** — network timing patterns, process creation chains, and file system activity are visible to EDRs
3. **64KB command output limit** — TLV u16 length field caps individual results (fix planned in Phase 1.1)
4. **No persistence mechanism** — implant runs in memory only, no disk persistence
5. **Single-architecture** — x86-64 Windows only (no x86, no ARM64, no Linux/macOS)
6. **Sleep techniques fragile** — Ekko timer queue pattern is documented and hunted by defenders
