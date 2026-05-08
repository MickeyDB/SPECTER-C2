# SPECTER C2 Framework — Roadmap

## Current Status

**Baseline:** Phase 1 wire-format and several operational fixes are **landed** (TLV u32 lengths, `CONFIG_VERSION` 2, profile bridge with legacy fallback, CI hash audit, cached heap allocator, minimal upload/download, sleep fallback policy, evasion playbook stub).

**Focus now:** Lab-proven beacon stability, roadmap-sized tests, chunked transfer + UI parity, and shrinking patchable surface—then evasion QA and infrastructure hardening.

---

## Phase 0: Stabilize

### 0.1 Beacon crash / large-output stability
- [x] Local PIC loader smoke harness (`implant/tests/pic_loader.c`, `scripts/pic-runtime-smoke.ps1`) maps a configured raw payload and enters offset 0 without access violation
- [x] Listener-key-aligned PIC smoke (`scripts/pic-listener-smoke.ps1`): build payload from a running listener/server key and prove encrypted `/api/beacon` succeeds from the loader
- [ ] Reproduce and close any remaining crashers using `docs/phase0-beacon-crash-repro.md` (update doc as root cause changes)
- [x] Heap-backed buffers for large check-in paths (payload / HTTP / transform tiers in `comms.c`; 4 MiB plaintext cap; oversized nested results are returned as failed results instead of being silently dropped)
- [x] Cached heap handle — `implant/core/src/heap.c` (`init_heap_cache`, `heap_alloc_cached`); used by comms and task result paths
- [x] Lab verify: synthetic >64 KiB shell output over encrypted `/api/beacon` from local PIC loader (`scripts/pic-large-output-smoke.ps1`)
- [x] Lab verify: `dir C:\Windows` without crash from local PIC loader (`scripts/pic-windows-dir-smoke.ps1`, 5,200-byte result)

### 0.2 Integration tests
- [x] Server integration tests: `crates/specter-server/tests/e2e_payload_test.rs`, `listener_tests.rs`, `builder_tests.rs` (payload build, markers, check-in, sleep persistence)
- [ ] Dedicated `tests/e2e/` layout (optional consolidation) — current coverage lives under `crates/specter-server/tests/`
- [x] `cargo test --workspace` in CI (`.github/workflows/ci.yml`) — includes the above when not filtered
- [ ] Extend mock-implant (`tools/mock-implant/`) explicitly for every wire revision between releases

### 0.3 Code path hygiene
- [ ] Treat **legacy** comms as baseline; **profile** as HTTP/transform wrapper only — reduce duplicate test matrices where safe
- [x] **TASK_UPLOAD / TASK_DOWNLOAD** — implemented in `task_exec.c` (base64, 1 MiB cap, distinct errors); *not* stubs *(optional later: module-bus implementation per 3.1)*
- [ ] **ETW patching** — `evasion_patch_etw()` exists (`evasion/etw.c`) but is **not called** from `evasion_init` today; when wired, gate behind `EVASION_FLAG_*`; document limits (user-mode only)
- [ ] Sweep stale `TODO` / dead branches (ongoing)

### 0.4 Reduce patchable markers
- [x] Remove SPECCFGM config magic marker — builder and implant now derive config magic from CRC32 of the first 64 PIC bytes
- [x] Remove SPBF build-flags marker — build flags now flow via compile-time flags and config TLV `0x8A`
- [x] Scrub remaining SPEC* builder markers (`SPECSTR`, `SPECHASH`, `SPECMGRD`, `SPECHEAP`, `SPECFLOW`, `SPECPICBLOB`) after transforms
- [ ] Reduce transform marker dependency further by moving remaining obfuscation metadata to known offsets or generated build maps

### 0.5 Cache heap handle
- [x] Cached heap + `HeapAlloc` / `HeapFree` resolved once (`heap.c`)
- [x] Hot paths use `heap_alloc_cached` / `heap_free_cached` (comms, crypto, task results)
- [ ] Audit remaining one-off allocators for consistency (ongoing)

---

## Phase 1: Correctness

### 1.1 TLV wire format upgrade
- [x] TLV length **u32** for check-in wire (`crates/specter-common/src/checkin.rs`, `implant/core/src/comms.c`)
- [x] Config blob TLV field lengths u32 (`config_gen` / `config.c`); **`CONFIG_VERSION` 2** in `config.h`
- [x] Removes old 64 KB truncation guard on that wire path — large results still bounded by check-in buffer cap and implant task design

### 1.2 AEAD for large payloads
- [x] Single large heap buffer with clear max size: plaintext check-in payload is capped at 4 MiB, with oversized individual results converted to explicit task failures
- [x] Heap allocation uses cached heap where integrated
- [x] Automated tests: **100 KiB** task result via JSON `/api/checkin` (`listener_tests::large_task_result_roundtrips_via_json_checkin`); **70 KiB** nested `RESULT_DATA` TLV parse (`specter-common` `test_binary_checkin_with_large_task_result_over_64k`)
- [x] Lab / **encrypted `/api/beacon`** path: real implant **> 64 KB** shell output end-to-end (`scripts/pic-large-output-smoke.ps1`, 110,493-byte result)

### 1.3 Profile integration
- [x] Local redirector/profile soak (`scripts/pic-profile-redirector-soak.ps1`): reverse proxy in front of profile listener, 5 transformed profile callbacks, queued shell task, and result return
- [x] Local profile-driven PIC smoke (`scripts/pic-profile-smoke.ps1`): legacy bootstrap registration, transformed profile HTTP `/api/profile`, queued shell task, and result return
- [x] Config → `profile_init` → `comms_set_profile` in `entry.c` with **NT_SUCCESS** gate and legacy fallback
- [x] Profile transport decision: legacy encrypted `/api/beacon` remains the baseline; profile HTTP is an explicit build/config choice and wrapper around the same plaintext TLV
- [x] Listener accepts **binary TLV** check-ins on profile path (`specter-server` listener)
- [ ] Execute lab checklist: **`docs/phase1.3-redirector-validation.md`** (profile + redirector + ≥5 callbacks); record evidence in doc template

### 1.3a Transport / Builder / Profile Matrix
- [x] Local transport/profile/redirector matrix: `scripts/transport-builder-profile-matrix.ps1`, latest PASS `target/local-evidence/transport-builder-profile-matrix-20260508-051223.md`
- [x] Builder matrix covers raw no-obfuscate/default/XOR marker scans plus .NET/service wrapper build checks
- [x] Wrapper runtime matrix covers direct EXE and Windows SCM service execution, latest PASS `target/local-evidence/wrapper-runtime-matrix-20260506-111657.md`
- [x] Checked-in profile fixture matrix covers `profiles/generic-https.yaml` and `profiles/slack-webhook.yaml` through direct profile listener and local reverse-proxy redirector tasking, latest PASS `target/local-evidence/profile-fixture-matrix-20260508-042823.md`
- [x] Default profile-enabled raw task/module smokes and XOR-wrapped raw task/module smokes now pass through the profile-aware listener path in `pic-listener-smoke`
- [ ] External/provider redirector validation remains under `docs/phase1.3-redirector-validation.md`

### 1.4 Hash validation
- [x] `implant/scripts/audit_hashes.py` in CI — **fails build** on mismatch (`.github/workflows/ci.yml`)
- [ ] Optional: compile-time / DEV-build embedded hash self-check

---

## Phase 2: Evasion Hardening

### 2.1 Honest evasion documentation
- [x] Operator playbook: `docs/evasion-playbook.md` (sleep, fallback, rollback)
- [x] Expand playbook with per-technique **“defeats / does not defeat”** (ETW user-mode, indirect syscalls, sleep encryption, stack spoofing) — align with `docs/implant.md` / architecture log
- [x] ETW: explicit “user-mode only; not kernel ETW-TI” in operator-facing doc
- [x] OPSEC telemetry review template: `docs/opsec-telemetry-review.md` (memory, syscall, ETW, network, process, and rollback gates)
- [x] Cross-link from deployment / operator guides when written

### 2.2 Syscall gadget rotation
- [x] Implemented (`syscalls.c`, syscall wrappers)
- [x] Static evidence: `scripts/phase2-telemetry-evidence.ps1` records `MAX_GADGETS=32`, gadget-pool scan presence, and per-entry gadget selection logic
- [x] Local Sysmon baseline: listener-aligned PIC loader smoke passed with scoped Event ID 1/5/11 evidence and no scoped Event ID 8/10 loader findings (`scripts/phase2-sysmon-pic-telemetry.ps1`)
- [ ] Verify gadget pool coverage in lab
- [ ] Tests: distinct syscalls prefer distinct gadgets where intended

### 2.3 Module overloading RWX→RX
- [x] Implemented (`evasion/modoverload.c`)
- [x] Sysmon baseline captured for the current listener smoke; confirms source collection works but does not prove memory region, backing-file, PEB, or unwind behavior
- [x] Memory scanner baseline captured: Moneta, PE-sieve, and HollowsHunter scan live `pic_loader.exe`; PE-sieve/HollowsHunter flag the current raw PIC loader as one implanted shellcode finding (`scripts/phase2-memory-scanner-evidence.ps1`)
- [x] Strict loader RW→RX sanity check captured: `--loader-protect-rx` faults before registration at payload offset `0x2678`, confirming the current flat blob needs writable state in its mapped region
- [x] Fault resolver and memory-layout contract added (`scripts/phase2-resolve-pic-offset.ps1`, `docs/phase2-memory-layout-contract.md`); `0x2678` maps to `spec_memset` during `implant_entry` zeroing `g_ctx`
- [x] Page-level split-protect prototype captured: loader marks code pages RX and data/BSS tail RW; smoke passes, but PE-sieve/HollowsHunter still flag one implanted shellcode finding via thread/callstack heuristics
- [x] Module-overload transfer prototype captured: copied PIC enters from the `urlmon.dll`-backed view with split RX/RW protections; beacon smoke passes and PE-sieve's active suspicious module moves to the backed view, but scanner count remains `implanted_shc = 1`
- [x] Original private-view cleanup captured: copied instance releases the original private allocation after transfer; beacon smoke passes, Moneta no longer reports the original private executable mapping, and PE-sieve thread `is_shellcode` dropped to `0` in that run, but process-level `implanted_shc = 1` remains
- [x] `.pdata` unwind registration evidence captured: PIC-safe table discovery avoids linker-symbol refptrs and registers successfully, but current PE-sieve/HollowsHunter scanner count remains unchanged; do not treat `.pdata` registration as a proven OPSEC win yet
- [x] NtContinue stack-clean transfer evidence captured: module-overload transfer can enter the copied image via a fresh synthetic stack, release the original view, register `.pdata`, and pass beacon smoke; PE-sieve thread `is_shellcode = 0`, but process-level `implanted_shc = 1` still remains
- [x] Build-derived layout metadata: builder parses `specter.map` and emits module-overload RW offset plus `.pdata` offset/count through config TLVs; implant consumes those values with runtime-discovery fallback
- [x] Layout-metadata scanner evidence captured: beacon smoke passes with metadata-driven split/`.pdata`, but PE-sieve/HollowsHunter still report `implanted_shc = 1`; thread classification remains scanner-run-sensitive, so this is repeatability work, not an OPSEC win
- [x] Preserve-headers module-overload variant captured: PIC copy moves into the sacrificial image executable section while leaving DLL headers intact; beacon smoke passes and PE-sieve thread `is_shellcode = 0`, but modified regions increase to 2 and process-level `implanted_shc = 1` remains
- [x] Sleep-state scanner evidence captured: harness can wait for first check-in, delay into the sleep window, and record PE-sieve code/thread details; current preserve-header module-overload path is still flagged while the thread is waiting in `NtDelayExecution`, so the remaining signal is not just process-start timing
- [x] Patch-only module-overload canary captured: modified `urlmon.dll` is reported as a patched code module even when execution stays in the original split-protected loader path, so modified backed-image bytes are independently scanner-visible
- [x] Barebone scanner comparison captured: linker layout now keeps `.text$*` code before page-aligned mutable `.data`; pure barebone payload is ~72 KiB, split-protect smoke passes with RW offset `0x8000`, and PE-sieve protection changes from RWX-style `0x40` to RW `0x4`, but PE-sieve/HollowsHunter still report `implanted_shc = 1`
- [x] Phase 2 next-strategy decision captured (`docs/phase2-next-strategy.md`): keep module overloading lab-only; next prototype is a barebone module-loader profile proving streamed functionality from the small resident stage
- [ ] Investigate the remaining modified-backed-image/call-integrity finding before treating module overloading as an evasion win
- [ ] Research decision: compare current module overloading against Astral-style remap-on-sleep; only implement if evidence justifies added VEH/loader-surface complexity

### 2.4 Hardware breakpoint syscalls *(research backlog — not a release gate)*
- Deferred: prototype only if kernel ETW-TI research justifies it

### 2.5 Build-time obfuscation
- [x] Junk code now preserves blob size by replacing INT3 padding with equal-length junk sequences
- [x] PIC size baseline script (`scripts/pic-size-baseline.ps1`): full DEV PIC 317,260 bytes; 296,780 bytes over 20 KiB target
- [x] Barebone PIC build profile (`make DEV=1 BAREBONE=1`): encrypted legacy HTTP beacon + built-in tasks, no module bus/profile/TLS/advanced sleep/evasion; 69,328-byte PIC and listener smoke PASS
- [x] Barebone memory scanner evidence: page-aligned 71,857-byte configured payload passes beacon smoke with split RX/RW protections but remains PE-sieve/HollowsHunter detectable; this keeps backed execution or streamed-stage work on the critical path
- [x] `BAREBONE_MODULES=1` resident-stage proof: clean build is 125,784-byte PIC / 126,170-byte configured payload; template module load/execute/result path PASS; resident-only, module-active, and post-cleanup scanner windows remain PE-sieve/HollowsHunter visible (`phase2-memory-scanner-resident-only-evidence-20260508-050045.md`, `phase2-memory-scanner-module-active-evidence-20260508-050151.md`, `phase2-memory-scanner-post-cleanup-evidence-20260508-045932.md`)
- [x] Junk code: **no net blob size change** (INT3 padding replacement only) — `test_junk_code_replaces_int3_padding` / `test_junk_code_no_int3_passthrough`
- [x] String encryption key rotation — scripted verification in `scripts/phase2-telemetry-evidence.ps1`
- [x] API hash salt randomization — scripted verification in `scripts/phase2-telemetry-evidence.ps1`
- [x] Local builder/runtime matrix covers raw no-obfuscate/default/XOR marker scans plus .NET/service wrapper build and runtime checks (`docs/transport-builder-profile-validation.md`)
- [x] Wrapper resident memory evidence captured for .NET/EXE and service EXE: both remain scanner-visible (`phase2-memory-scanner-resident-only-evidence-20260508-043505.md`, `phase2-memory-scanner-resident-only-evidence-20260508-043545.md`)
- [x] Wrapper module-task/post-cleanup evidence captured for .NET/EXE and service EXE with default profile-enabled tasking: both complete the template module and remain scanner-visible after cleanup (`phase2-memory-scanner-post-cleanup-evidence-20260508-045517.md`, `phase2-memory-scanner-post-cleanup-evidence-20260508-045558.md`)
- [x] Optional outer XOR layer runtime behavior: raw builder scan, raw task smoke, and raw module smoke PASS; fixed the XOR decrypt stub `jz` target and wired raw-only final payload wrapping in the builder

---

## Phase 3: Feature Completion

### 3.1 File transfer (upload/download)
- [x] **Minimal inline** upload/download (implant `task_exec.c`; TUI encodes upload; TUI saves download to `specter-<id>-<name>` in cwd)
- [x] **Chunk tasking primitives** for **> 1 MiB**: TUI splits large uploads into ordered `upload_chunk` tasks; implant supports bounded `upload_chunk` / `download_chunk` handlers with offset-based file access
- [ ] **Chunked transfer evidence**: real implant >1 MiB upload/download smoke with reassembly verification and saved artifact hash
- [ ] **Web UI:** native file picker + save-as download in session view *(today: `prompt()` for paths in `SessionInteract.tsx`; not full parity with TUI base64 upload)*

### 3.2 Interactive shell
- [x] WebSocket session command stream (server `ws_handler` queues session tasks and streams queued/result/error frames)
- [ ] Implant: persistent `cmd.exe` + pipes *(or documented module strategy)*
- [x] Web: xterm.js uses operator WebSocket when available, with gRPC queue/poll fallback

### 3.3 Process injection
- [x] Module: `implant/modules/inject/inject.c`
- [ ] Coverage: classic / threadless / stomping as applicable; evasion engine integration matrix

### 3.4 Module ecosystem
- [x] Modules present: `socks5`, `token`, `lateral`, `inject`, `exfil`, `collect`, `template`
- [ ] “Default kit” parity (whoami/ps/netstat/etc.) vs engagement needs
- [ ] BOF / `beacon_shim` — expanded testing
- [ ] Web UI: module repo, versioning, OPSEC labels, argument schemas

### 3.5 Lateral movement
- [x] `implant/core/src/comms/smb.c`, `modules/lateral/lateral.c`; token module
- [ ] SMB channel **fully integrated** with session/comms UX
- [ ] PtH / OPtH as modules *(as needed)*

---

## Phase 4: Infrastructure

### 4.1 Redirector improvements
- [x] Azure App Service pattern (zero-dep `server.js` — per prior work)
- [x] Redirector domain auto-population fixes *(where marked done in tree)*
- [ ] AWS CloudFront redirector test path
- [ ] Cloudflare Worker redirector test path
- [x] Domain rotation / health monitoring *(baseline — extend as needed)*

### 4.2 DNS channel
- [ ] Listener + implant DNS paths — harden data processing
- [ ] DoH end-to-end lab test
- [ ] Subdomain encoding lab test

### 4.3 Multi-teamserver *(deferred until product need)*
- PostgreSQL / shared session / multi-TS scale-out

### 4.4 Persistence
- [x] Per-listener keys in DB
- [x] Payload builder artifact root configurable via `--template-dir` / `SPECTER_TEMPLATE_DIR`; Docker points at `/config/implant-build`
- [ ] Server CA key persistence (`SPECTER_CA_KEY` story documented)
- [ ] Module signing key across restarts
- [ ] Session recovery after teamserver restart

---

## Phase 5: Operational Polish

### 5.1 Web UI
- [x] Session terminal: xterm.js with paste via `onData` (multi-character / Ctrl+V path), command history
- [ ] Profile editor: JA3 / timing preview — finish polish
- [x] Payload builder: listener dropdown; profile URI population *(verify against latest builder)*
- [x] Dashboard session status colors; redirector health *(iterate)*
- [ ] Reports: validate end-to-end

### 5.2 CI/CD
- [x] YARA (custom + public rule sets in CI)
- [x] Workspace `cargo test` on merge
- [x] Hash audit in CI
- [x] Implant size check / warnings
- [x] Cross-platform **Rust** builds (Linux, macOS, Windows) in CI
- [ ] Explicit “release gate” job naming for payload + mock check-in *(documentation)*

### 5.3 Documentation
- [ ] Refresh `docs/deployment-guide.md` vs current stack
- [ ] Operator guide (profile, payload, redirector)
- [ ] Developer guide (build, test, contribute)
- [x] Evasion transparency — started in `evasion-playbook.md`; extend per 2.1

---

## Architecture Decisions Log

### Unity build (TEMPORARY)
- **Why:** MinGW `.refptr` / pseudo-GOT on cross-TU `extern` breaks PIC loading
- **Long-term:** Pass `IMPLANT_CONTEXT` (and sub-contexts) explicitly; avoid new extern globals
- **When to revisit:** After contexts are fully threaded through subsystems

### Legacy vs profile code paths
- **Local evidence:** `scripts/pic-listener-smoke.ps1` covers encrypted legacy `/api/beacon`; `scripts/pic-profile-smoke.ps1` covers transformed profile HTTP `/api/profile`.
- **Current:** `comms_checkin` — legacy wire + optional profile transform/embed path
- **Plan:** Same plaintext TLV; profile shapes HTTP only. Test both paths on profile-changing PRs

### Heap allocation
- **Current:** `heap.c` caches `GetProcessHeap` + alloc/free pointers once after PEB resolution
- **Remaining:** Occasional direct APIs on non-cached paths — consolidate over time

### Patchable markers
- **Current:** No config/build-flag marker patching. Remaining SPEC* markers are transform metadata and are scrubbed after payload assembly.
- **Plan:** Reduce transform marker dependency further by moving metadata to known offsets or generated build maps.

### ETW patching
- **Current:** User-mode ntdll patch path exists in evasion stack
- **Reality:** Does **not** defeat kernel ETW-TI — document and gate (Phase 0.3 / 2.1)

---

## Known Limitations

1. **Kernel telemetry** — ETW-TI, callbacks, minifilters: out of scope for pure user-mode implants
2. **Behavioral detection** — timing, process trees, filesystem noise still visible to mature EDR
3. **Transfer / framing limits** — minimal file ops capped (~1 MiB); chunking and Web parity **not** done
4. **No built-in disk persistence** — in-memory implant model unless extended
5. **Architecture** — Windows x86-64 PIC blob focus (no x86/ARM64/Linux/macOS implant)
6. **Sleep tradecraft** — advanced timers (e.g. Ekko) are known patterns; validate per target
