# Phase 2 Next Strategy

Date: 2026-04-29

## Decision

The next prototype should be a **barebone module-streaming proof**, not another module-overload or stack-only evasion pass.

The current evidence says:

- Page-aligned barebone RX/RW split is now compatible and improves protection telemetry.
- PE-sieve/HollowsHunter still flag private shellcode/callstack signals.
- Module-overload patch-only canaries remain scanner-visible because modified image-backed code is independently detectable.
- Barebone size reduction materially reduces the patch footprint, but does not clear scanner findings by itself.

That makes the project-level direction clearer: keep the resident implant small, page-separated, and boring; stream nonessential functionality as needed; only add memory-hiding techniques when they have a measurable local evidence win.

## Research Notes

Moneta's published design focuses on dynamic or unknown code indicators: private or mapped executable memory, modified code inside mapped images, thread starts outside normal image regions, mapped images missing from the PEB, and mismatches between memory and backing files. That maps directly to our evidence: split-protect improves the protection shape, but private executable code remains visible; module-overload canaries reduce unbacked code but create modified image-backed code.

PE-sieve is explicitly designed to detect and dump replaced/injected PEs, shellcode, hooks, and in-memory patches. Its release notes also call out `/threads` as a way to inspect thread call stacks and capture sleeping beacons. Our `DelayExecution` sleep-state evidence is therefore not surprising: it is the path PE-sieve was built to inspect.

Independent memory-forensics research on modified memory-mapped image files also reinforces the same conclusion: modified executable image pages are a durable detection primitive, not just a PE-sieve quirk.

Sources:

- Moneta overview and IOC model: https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-ii-insights-from-moneta
- PE-sieve overview: https://hasherezade.github.io/pe-sieve/index.html
- PE-sieve release notes for `/threads` and `is_shellcode`: https://github.com/hasherezade/pe-sieve/releases
- Modified memory-mapped image file detection: https://insinuator.net/2023/09/identification-of-malicious-modifications-in-memory-mapped-image-files/

## Local Evidence Summary

| Evidence | Result | Meaning |
| --- | --- | --- |
| Full module-overload transfer | Smoke passes, original private view can be released, scanner still flags | Compatibility win, not an OPSEC win |
| Preserve-header module-overload | Header signal improves, scanner still flags | Header corruption is not the sole trigger |
| Patch-only module-overload | `urlmon.dll` flagged even without execution transfer | Modified backed-image bytes are independently visible |
| Barebone baseline | ~72 KiB configured payload, scanner still flags | Size reduction alone is not enough |
| Barebone split | Smoke passes with code RX and state RW | Whole-region RWX shape is fixed for barebone |
| Barebone patch-only | `urlmon.dll` patches drop to ~3.8 KiB, scanner still flags | Smaller footprint helps but does not clear this scanner class |

## Architecture Audit

The current module-streaming path is partially implemented:

- Server has `ModuleRepository` storage, signing, per-session packaging, and `LoadModule` RPC.
- Web UI has a Modules page and can call `LoadModule`.
- Implant full build has module bus, loader, guardian, BOF shim, and module task dispatch.
- Module binaries exist under `implant/modules`.

The gap:

- `SPECTER_BAREBONE` excludes the module bus/loader.
- Therefore the architecture goal "barebone first, stream required functionality as needed" is not end-to-end proven.
- `ModuleRepository::seed_default_modules()` registers stub blobs if compiled module artifacts are missing, which is useful for UI/demo but dangerous for treating module execution as proven.
- Module signing keys are generated at runtime today; persistence is still a release/deployment gap.

## Options Considered

### Option A: Keep polishing module overloading

Pros:

- Existing prototype already runs and has many evidence points.
- Can improve specific scanner fields, such as stale stack frames or header modification.

Cons:

- Patch-only canary proves modified backed-image bytes are visible without execution transfer.
- Adds loader/evasion complexity without clearing scanner findings.
- Conflicts with the goal of a small, bare resident stage.

Decision: **Do not continue as default path. Keep lab-only.**

### Option B: Implement sleep-time restore/remap

Pros:

- Directly targets point-in-time memory scanners during sleep.
- Could reduce private executable or modified image-backed artifacts at rest.

Cons:

- Adds VEH/remap/protection complexity.
- Does not solve active execution windows.
- Current scanner evidence says we should first prove the resident architecture before adding more memory tricks.

Decision: **Defer until after module streaming proof.**

### Option C: Barebone module-streaming proof

Pros:

- Aligns with "barebone and stream required functionality as needed".
- Gives an explicit resident-stage contract.
- Lets us remove shell/upload/download/profile/module-heavy functionality from the initial payload over time.
- Creates a cleaner size/evidence loop: every resident feature must justify its size and telemetry cost.

Cons:

- Current barebone excludes bus/loader, so this needs a focused implementation slice.
- Loading modules will introduce its own executable-memory telemetry; it must be measured separately.
- Requires server/Web/operator path validation, not just implant code.

Decision: **Proceed next.**

## Selected Prototype

Build a **barebone module-loader profile** with the smallest resident functionality needed to load and execute one streamed module.

Target contract:

- Keep page-aligned barebone code/state split.
- Add only the minimal module package parser/decrypt/verify/load path needed for one PIC module.
- Do not include guardian, CLR, BOF shim, SOCKS, lateral, injection, or profile transforms in the resident stage.
- Queue a `module_load` task from the server and prove a tiny module returns a result.
- Measure:
  - resident PIC size
  - module artifact size
  - successful module task result
  - Moneta/PE-sieve/HollowsHunter posture before module load, during module execution, and after module cleanup if cleanup exists

Success criteria:

- Beacon smoke passes.
- One streamed module executes and returns a result.
- Resident payload remains materially smaller than the full DEV payload.
- Scanner evidence is separated into resident-stage findings and module-execution findings.

Non-goals:

- No new injection technique.
- No new sleep-remap technique.
- No claim that streamed modules are stealthy until scanner evidence says so.

## Next Implementation Milestone

Create a `BAREBONE_MODULES=1` build profile:

- Includes minimal module package decrypt/verify and PIC loader code.
- Excludes full module bus extras unless required by the minimal test.
- Adds a local smoke script for `barebone -> module_load -> result`.
- Runs the memory scanner harness against the resident stage before and after module execution.

This is the next best evidence point because it tests the core product architecture, not just an evasion idea in isolation.

## Implementation Update: Barebone Module Profile

Status as of 2026-04-29:

- `BAREBONE_MODULES=1` now builds a resident profile with module package verify/decrypt/load support.
- The builder can embed the module repository Ed25519 public key into implant config.
- Module packaging now authenticates the same package header bytes the implant decryptor expects as AEAD AAD.
- The local smoke harness can store, package, and dispatch a module task to a barebone payload.
- PIC module blobs now place `module_entry` at raw offset 0 via `.text.entry`.
- The legacy check-in response decrypt path now accepts module-sized task responses up to the existing receive-buffer cap instead of silently ignoring payloads over 512 bytes.

Current evidence:

- Resident `DEV=1 BAREBONE=1 BAREBONE_MODULES=1` size: **125,744 bytes**.
- Module repository tests: **18/18 passing**.
- Implant native test suite: **passing** after updating PIC loader expectations.
- Return-only streamed module smoke: **passing** in RWX and split-protect loader modes.
- Template streamed module smoke with `ping`: **passing**, returning **4 bytes** (`pong`) through the task-result path.
- Current split-protect boundary for this build: `.data` starts at **0xb000** and `--loader-rw-offset 0xb000` passes.

Interpretation:

The local data path is now proven end to end for a streamed PIC module:
server repository -> package/sign/encrypt -> listener task delivery -> implant decrypt/load/execute -> module output ring -> task result check-in.
`BAREBONE_MODULES=1` is ready for Phase 2 telemetry evidence runs, with scanner findings separated between resident-stage posture and transient module-execution posture.

## Scanner Evidence Update: Streamed Module Windows

Status as of 2026-04-29:

- Scanner harness supports `BAREBONE_MODULES=1`, delayed module dispatch, post-task hold, and streamed module arguments.
- Template module now supports `wait <ms>` so scanners can sample while a streamed PIC module is actively executing.
- Resident-before-module scan report: `target/local-evidence/phase2-memory-scanner-resident-before-module.md`.
- Module-active scan report: `target/local-evidence/phase2-memory-scanner-module-active.md`.
- Post-cleanup scan report: `target/local-evidence/phase2-memory-scanner-post-cleanup.md`.

Observed scanner summary:

- All three windows completed with smoke status **PASS**.
- PE-sieve still reports **1 modified region** and **1 implanted shellcode finding** in all windows.
- HollowsHunter still reports **1 suspicious process** in all windows.
- Resident-before-module and post-cleanup show PE-sieve suspicious module size around **0x8000**.
- Module-active `wait 15000` shows PE-sieve suspicious module size around **0x1000**, confirming the transient module window is measurable separately from the resident stage.

Interpretation:

Module streaming is now functionally proven and measurable, but it does **not** by itself clear the memory scanners. The dominant remaining signal is the resident private executable PIC mapping/callstack, not the module package/data path. Treat streaming as the correct architecture for modularity and size pressure, while the next evasion work should focus on the resident stage memory shape and callstack posture.
