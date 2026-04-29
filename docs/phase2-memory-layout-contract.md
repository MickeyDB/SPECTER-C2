# Phase 2 Memory Layout Contract

This document captures the target memory contract for making Phase 2 memory telemetry work measurable instead of speculative.

## Current Evidence

- Baseline loader mode maps the flat PIC blob as `PAGE_EXECUTE_READWRITE`.
- The listener-aligned PIC smoke passes in that mode, but PE-sieve and HollowsHunter flag the live `pic_loader.exe` process as one implanted shellcode finding.
- Strict loader `RW -> copy -> RX` mode is not compatible with the current blob. `VirtualProtect` to RX succeeds, then the payload faults before registration.
- Page-level split protection works as a compatibility prototype: the loader maps/copies RW, marks code pages RX through `0x19000`, and leaves the data/BSS/unwind tail RW. The beacon registers and keeps running, but PE-sieve and HollowsHunter still flag one implanted shellcode finding via thread/callstack heuristics.
- Fault evidence:
  - Report: `target/local-evidence/phase2-memory-scanner-rx-evidence-20260428.md`
  - Resolver: `target/local-evidence/phase2-pic-offset-2678-20260428.md`
  - Fault offset: `0x2678`
  - Nearest symbol: `spec_memset + 0xa`
  - First call path: `implant_entry` clearing `g_ctx`

## Why Strict RX Fails

The linker script emits one flat `.text` blob that includes:

- code
- read-only data
- initialized data
- BSS/global state
- `.pdata` / `.xdata`

The first instruction sequence in `implant_entry` writes to `g_ctx`, which lives in the blob's `.bss` range. Protecting the whole blob as RX therefore makes the first global-state write fault.

Current section ranges from `implant/build/specter.map`:

- code/rodata body: `.text` starts at `0x540`
- initialized data: `.data` starts at `0x19dc0`
- BSS/global state: `.bss` starts at `0x1a060`
- unwind metadata: `__pdata_start = 0x4b240`, `__xdata_start = 0x4c528`

Split-protect evidence:

- Report: `target/local-evidence/phase2-memory-scanner-split-evidence-20260428.md`
- Loader log: `code=RX 0x0..0x19000 data=RW 0x19000..0x4d893`
- Smoke status: PASS
- Moneta: private allocation split into `RX` code and `RW` tail
- PE-sieve/HollowsHunter: still `implanted_shc = 1`; PE-sieve reports `SUS_CALLSTACK_SHC` and `SUS_CALLS_INTEGRITY`

Module-overload evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-fixed-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-111057`
- Smoke status: PASS after fixing two implementation issues:
  - `SEC_IMAGE` view is protected writable before the PIC copy.
  - Copy length uses `cfg_get_payload_size()` instead of `CONFIG_SCAN_MAX` or absolute linker-symbol pointers.
- PE-sieve/HollowsHunter still report `implanted_shc = 1` on the original private PIC thread.
- Moneta shows an additional modified `urlmon.dll` image view with modified code/header indicators.
- Interpretation: current module-overload copies the PIC into a backed image view but does not transfer execution there or remove/sleep the original private executable view. In this form it adds telemetry rather than reducing scanner findings.

Module-overload transfer evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-transfer-trisplit-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-112936`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload`.
- The original instance copies the PIC into the `urlmon.dll` SEC_IMAGE view, applies split protections across the full mapped view, and transfers into the copied entry with a recursion sentinel.
- Moneta shows the copied `urlmon.dll` view as RX for `0x0..0x19000`, RW for the mutable copied tail, and read-only for the unused mapped-image remainder. It still reports modified PE header/code, missing PEB module, and allocation-level RWXC history.
- PE-sieve/HollowsHunter still report one implanted shellcode finding. PE-sieve's active suspicious module is now the backed `urlmon.dll` view (`module_size = e000`, `SUS_CALLSTACK_SHC`, `SUS_CALLS_INTEGRITY`) rather than the original private PIC view.
- Interpretation: execution transfer improves the signal shape but does not reduce scanner count. The remaining OPSEC problem is original-view cleanup/remap plus valid stack/unwind presentation, not just RX/RW protection.

Original-view cleanup evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-cleanup-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-113408`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload`.
- Loader log confirms `original private view released` after the copied instance initializes its syscall wrappers.
- Moneta no longer reports the original private executable PIC mapping; the released allocation appears as non-executable reserve/metadata instead of RX private code.
- PE-sieve still reports process-level `implanted_shc = 1`, but the thread scan in this run shows `is_shellcode = 0` and only `SUS_CALLS_INTEGRITY`.
- Interpretation: releasing the original private view materially improves the thread/callstack signal, but the modified backed image remains scanner-visible.

`.pdata` registration evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-cleanup-pdata-scan-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-114005`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload -EvasionPdataRegister`.
- Loader log confirms `pdata registration OK` after replacing linker-symbol `.pdata` pointers with PIC-safe runtime table discovery.
- PE-sieve/HollowsHunter still report process-level `implanted_shc = 1`; PE-sieve still reports `SUS_CALLS_INTEGRITY`.
- Interpretation: `.pdata` registration is now functional in the copied image, but it is not enough by itself to clear the remaining scanner finding. It needs stack-frame cleanup/transfer evidence, not just unwind-table registration.

NtContinue stack-transfer evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-ntcontinue-pdata-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-121658`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload -EvasionPdataRegister -EvasionNtContinueEntry`.
- Loader log confirms `module overload NtContinue transfer`, copied-instance initialization, `original private view released`, `.pdata` registration, and successful check-in.
- PE-sieve reports thread `is_shellcode = 0` and only `SUS_CALLS_INTEGRITY`; PE-sieve/HollowsHunter process-level count still remains `implanted_shc = 1`.
- Interpretation: stack-clean transfer removes the stale original stack-frame signal in this local scanner, but it still does not clear the modified backed-image/call-integrity finding.

Build-derived layout metadata evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-layout-metadata-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-132839`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload -EvasionPdataRegister -EvasionNtContinueEntry`.
- Builder now parses `specter.map` and emits module-overload RW offset plus `.pdata` offset/count as config TLVs; the implant consumes those values and falls back to runtime discovery when absent.
- PE-sieve/HollowsHunter still report process-level `implanted_shc = 1`. In this run PE-sieve also reported `SUS_CALLSTACK_SHC` and thread `is_shellcode = 1`, so thread classification remains sensitive to scanner timing/layout details.
- Interpretation: metadata-driven layout removes hard-coded lab offsets and makes future comparisons cleaner, but it does not improve the scanner result by itself.

Preserve-headers module-overload evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-preserve-headers-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-135231`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload -EvasionPdataRegister -EvasionNtContinueEntry -EvasionModulePreserveHeaders`.
- Loader log confirms `module overload preserve headers`, NtContinue transfer, original-view release, `.pdata` registration, and successful check-in.
- PE-sieve identifies the modified module as full `urlmon.dll` (`module_file = C:\Windows\System32\urlmon.dll`, `module_size = 1ef000`) with `hdr_modified = 0`, thread `is_shellcode = 0`, and only `SUS_CALLS_INTEGRITY`.
- PE-sieve modified count increases from 1 to 2 and process-level `implanted_shc = 1` remains; HollowsHunter still reports one suspicious process.
- Interpretation: preserving headers improves module identity and thread presentation, but does not clear the implanted-shellcode finding and may add another modified-region signal. Header corruption is not the only remaining trigger.

Sleep-state scanner evidence:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-preserve-headers-sleep-state-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-161219`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload -EvasionPdataRegister -EvasionNtContinueEntry -EvasionModulePreserveHeaders -ScanAfterFirstCheckin`.
- Harness now waits for first check-in, delays into the next sleep window, and records PE-sieve code-scan plus thread-scan details instead of assuming the first `scans[0]` entry is a thread scan.
- PE-sieve observed the thread in `Waiting` / `DelayExecution` with last syscall `NtDelayExecution`, `SUS_CALLS_INTEGRITY`, and dump `is_shellcode = 0`.
- PE-sieve still reports `modified.total = 2`, `patched = 1`, `hdr_modified = 0`, `implanted_shc = 1`, with the code scan attached to `C:\Windows\System32\urlmon.dll` and `19000` patches.
- HollowsHunter still reports one suspicious process with `implanted_shc = 1`.
- Interpretation: the remaining finding persists in the sleep window, so the immediate problem is not only process-start timing or an active stale stack frame. The next useful branch is isolating modified-backed-image bytes/protection-history/call-integrity behavior before adding heavier sleep remap machinery.

Patch-only module-overload canary:

- Report: `target/local-evidence/phase2-memory-scanner-module-overload-patch-only-sleep-state-evidence-20260428.md`
- Raw scan root: `target/local-evidence/phase2-memory-scanner-20260428-165226`
- Smoke status: PASS with `-LoaderSplitProtect -EvasionModuleOverload -EvasionModulePreserveHeaders -EvasionModulePatchOnly -ScanAfterFirstCheckin`.
- The implant maps `urlmon.dll`, copies the PIC into an executable section, preserves headers, finalizes protections, and then deliberately does not transfer execution into the backed image.
- PE-sieve still reports `modified.total = 2`, `patched = 1`, `hdr_modified = 0`, `implanted_shc = 1`; the code scan is attached to `C:\Windows\System32\urlmon.dll` with `19162` patches.
- PE-sieve observed the actual executing thread in `Waiting` / `DelayExecution` with last syscall `NtDelayExecution`, `SUS_CALLS_INTEGRITY`, and dump `is_shellcode = 0`.
- HollowsHunter still reports one suspicious process with `implanted_shc = 1`.
- Interpretation: a large modified backed-image section is independently scanner-visible even without executing from it. Module overloading should not be treated as a stealth win unless the design can avoid or transiently remove that modified-image footprint.

Barebone memory scanner comparison:

- Baseline report: `target/local-evidence/phase2-memory-scanner-barebone-baseline-page-aligned-evidence-20260429.md`
- Split report: `target/local-evidence/phase2-memory-scanner-barebone-split-page-aligned-v2-evidence-20260429.md`
- Patch-only report: `target/local-evidence/phase2-memory-scanner-barebone-patch-only-page-aligned-evidence-20260429.md`
- Linker layout now collects `.text$*` function sections before read-only/mutable data and aligns `.data` to a 4 KiB boundary. Pure barebone `.data` starts at `0x8000`; barebone plus module-overload canary `.data` starts at `0x9000`.
- Pure barebone configured payload size is `71857` bytes and beacon smoke passes in the sleep-state scanner harness.
- Pure barebone baseline still reports PE-sieve `modified.total = 1`, `implanted_shc = 1`, suspicious protection `0x40`, thread `SUS_CALLSTACK_SHC` plus `SUS_CALLS_INTEGRITY`, and HollowsHunter `suspicious_count = 1`.
- Barebone split-protect now passes with `Loader RW offset: 0x8000`; PE-sieve still reports `modified.total = 1`, `implanted_shc = 1`, and the same thread indicators, but suspicious protection changes to `0x4`.
- Barebone plus minimal module-overload patch-only canary produces a `76059` byte configured payload and keeps beacon compatibility; PE-sieve reports `urlmon.dll` code patches at `3860`, still far smaller than the full patch-only canary but scanner-visible.
- Barebone patch-only still reports PE-sieve `modified.total = 2`, `patched = 1`, `hdr_modified = 0`, `implanted_shc = 1`, and HollowsHunter `suspicious_count = 1`.
- Interpretation: page-aligned state separation is now compatible and removes whole-region RWX, but it does not clear private shellcode/callstack scanner findings. Size reduction materially reduces the modified-image patch footprint, but does not clear the scanner family either. Next work should focus on backed execution/staging semantics or transient removal of scanner-visible modified images, while keeping streamed modules as the size-control path.

## Target Contract

The target layout should make these properties true:

- No long-lived private RWX mapping for the whole implant.
- Executable code bytes are RX after initialization.
- Mutable implant state is RW and not executable.
- Config/profile/channel data that must mutate at runtime is in RW state, not in RX code.
- `.pdata` / `.xdata` remain readable and valid for stack walking.
- Any temporary writable executable transition has a bounded window and is captured by the telemetry harness.

## Engineering Options

### Option A: Split Blob Layout

Produce separate build artifacts or offsets for:

- RX segment: code + read-only data + unwind metadata
- RW segment: `.data` + `.bss` + mutable runtime state

This is the cleanest long-term contract, but it requires changing how globals are addressed or how the loader supplies a state base.

### Option B: Explicit Runtime State Block

Move large mutable globals behind `IMPLANT_CONTEXT` and subsystem contexts allocated through the cached heap. Keep only minimal immutable metadata in the PIC blob.

This keeps the flat blob simpler, but still requires auditing file-scope statics such as `g_profile_cfg`, `g_syscall_table`, `g_comms_ctx`, `g_config`, and cached heap pointers.

### Option C: Module Overload / Remap Mitigation

Keep the flat blob behavior, but move or hide the active executable view during runtime/sleep.

This may reduce specific scanner signals, but it adds loader and VEH complexity. It should only be pursued after the memory scanner harness shows a measurable benefit.

## Automated Gates

- `scripts/phase2-memory-scanner-evidence.ps1`
  - Baseline scanner harness using Moneta, PE-sieve, and HollowsHunter.
  - Use `-LoaderProtectRx` to test strict loader RW-copy-RX compatibility.
- `scripts/phase2-resolve-pic-offset.ps1`
  - Resolves crash/finding offsets back to symbols and nearby disassembly.

## Next Decision

Before implementing Astral-style remap-on-sleep or heavier module-overloading behavior, first prototype a state-separation path and rerun:

```powershell
.\scripts\phase2-memory-scanner-evidence.ps1 -OutputPath target/local-evidence/phase2-memory-scanner-evidence-YYYYMMDD.md
.\scripts\phase2-memory-scanner-evidence.ps1 -LoaderProtectRx -OutputPath target/local-evidence/phase2-memory-scanner-rx-evidence-YYYYMMDD.md
```

If the scanner finding remains the same after state separation, prioritize callstack/backing-file work. If the finding drops or changes materially, continue with section-aware layout before adding more complex sleep remapping.

Current split-protect result: scanner count did not drop. The finding moved from a broad RWX-style raw mapping problem toward a private-code/callstack problem, so the next useful branch is backing-file and stack behavior rather than more page-protection-only work.

Current module-overload result: the transfer, original private-view cleanup, `.pdata` registration, NtContinue stack-transfer, build-derived layout metadata, and preserve-headers prototypes are compatible. They are still not release-ready as evasion controls because the remaining scanner finding is attached to the modified backed image/call-integrity path, and thread classification varies across scanner runs. Preserve-headers evidence suggests header corruption is not the only trigger. Next work should isolate protection-history and active-execution signals before adding heavier sleep-remap complexity.

Current sleep-state result: the preserve-header module-overload path remains detectable while the thread is waiting in `NtDelayExecution`; treat this as evidence against implementing broad sleep-remap complexity until the modified-backed-image signal is isolated.

Current patch-only result: PE-sieve reports the modified `urlmon.dll` code section even when execution does not transfer there. This moves the next decision toward smaller patch footprint, transient restore/remap, or state/section separation rather than additional stack-only work.

Current barebone result: barebone size reduction and page-aligned state separation are architecturally valuable but not sufficient by themselves. The clean split changes protection telemetry and keeps beacon compatibility, but the scanner family still sees private shellcode/callstack signals. The smaller module-overload canary remains scanner-visible as a modified backed image.
