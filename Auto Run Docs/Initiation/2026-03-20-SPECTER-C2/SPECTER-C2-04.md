# Phase 04: Evasion Engine

This phase implements the evasion engine — the architectural cornerstone of SPECTER. Every syscall the core or any module makes is routed through this engine. It provides five capabilities: call stack spoofing (synthetic frames from legitimate DLLs with valid unwind data), ETW provider suppression (targeted patching of Threat Intelligence and AMSI providers), hook evasion (fresh ntdll mapping with periodic integrity verification), memory guard (RX→RW→encrypt→sleep→decrypt→RX cycle), and return address spoofing during sleep. By the end of this phase, every syscall has a plausible spoofed call stack, critical ETW providers are silenced, and the implant's memory is indistinguishable from legitimate process memory during sleep.

## Context

The evasion engine wraps the syscall engine from Phase 02. All existing syscall wrapper functions are updated to route through the evasion engine rather than calling spec_syscall directly. The engine adds pre-call (stack spoofing, hook check) and post-call (cleanup) logic around every syscall invocation. It also manages the memory guard lifecycle that integrates with the sleep controller from Phase 03.

Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`

## Tasks

- [x] Implement call stack spoofing in `implant/core/src/evasion/stackspoof.c` and `implant/core/include/evasion.h`:
  - Create `implant/core/src/evasion/` directory
  - `FRAME_LIBRARY` structure: array of `FRAME_ENTRY` structs (code_start, code_end, unwind_info, module_hash), count, max capacity (256)
  - `evasion_init_frames(ctx)` — walk PEB→Ldr to enumerate loaded DLLs (kernel32, ntdll, user32, rpcrt4, combase), parse PE .text and .pdata sections, store valid frame entries with unwind data
  - `evasion_select_frames(lib, target_func_hash, chain_out, count)` — select semantically plausible frame chain terminating at RtlUserThreadStart/BaseThreadInitThunk, randomize selection per call
  - `evasion_build_spoofed_stack(chain, count, original_rsp)` — write spoofed return addresses, ensure RBP chain integrity, validate .pdata unwind info for each frame
  - `evasion_restore_stack(original_rsp, saved_frames)` — restore after syscall

- [x] Implement evasion-wrapped syscall invocation in `implant/core/src/evasion/evasion_core.c`:
  - `EVASION_CONTEXT` structure: frame_lib, clean_ntdll pointer, CRC table for critical exports, etw_patched/amsi_patched flags
  - `evasion_init(ctx)` — initialize frame library, compute initial CRC values
  - `evasion_syscall(ctx, func_hash, ...)` — look up SYSCALL_ENTRY → build spoofed stack → execute indirect syscall → restore stack → return NTSTATUS
  - Update all syscall wrappers in `syscall_wrappers.c` to call `evasion_syscall` instead of `spec_syscall`
  - *(Completed: evasion_core.c created with evasion_init/evasion_syscall, all 17 syscall wrappers updated to route through evasion engine, entry.c updated to call evasion_init, test suite with 41/41 tests passing)*

- [x] Implement ETW suppression in `implant/core/src/evasion/etw.c`:
  - `evasion_patch_etw(ctx)` — patch EtwEventWrite/EtwEventWriteEx in ntdll for Microsoft-Windows-Threat-Intelligence, Microsoft-Antimalware-Scan-Interface, Microsoft-Windows-Kernel-Audit-API-Calls providers: make entry writable → write `xor eax, eax; ret` → restore protection, save original bytes
  - `evasion_check_etw_patches(ctx)` — verify patches still in place, re-apply if reverted by EDR
  - `evasion_patch_amsi(ctx)` — lazy AMSI bypass (called only when CLR module loads): load amsi.dll → find AmsiScanBuffer → patch to return E_INVALIDARG
  - *(Completed: etw.c created with evasion_patch_etw, evasion_check_etw_patches, evasion_patch_amsi; hash constants added to evasion.h; test suite with 51/51 tests passing)*

- [x] Implement hook evasion and integrity monitoring in `implant/core/src/evasion/hooks.c`:
  - `evasion_compute_crc(func_addr, len)` — CRC32 of first bytes at function address
  - `evasion_init_crc_table(ctx)` — baseline CRC values for critical ntdll exports from clean mapping
  - `evasion_check_hooks(ctx)` — periodic hook detection: compute CRC of in-memory ntdll functions, compare against clean baseline, on mismatch: re-map clean ntdll, re-resolve SSNs, recompute CRCs, flag for operator alert
  - `evasion_refresh_ntdll(ctx)` — re-map clean ntdll from \KnownDlls, update all contexts
  - *(Completed: hooks.c created with evasion_compute_crc (IEEE 802.3 CRC32, table-free bit-by-bit for PIC size), evasion_init_crc_table, evasion_check_hooks, evasion_refresh_ntdll; test suite with 58/58 tests passing)*

- [x] Implement the memory guard in `implant/core/src/evasion/memguard.c`:
  - `memguard_init(ctx, implant_base, implant_size)` — record implant region, set guard pages, register VEH for guard page violations
  - `memguard_encrypt(ctx)` — pre-sleep: generate per-cycle key → flip RX→RW → encrypt implant memory (ChaCha20) → encrypt tracked heap → encrypt thread stack → store key
  - `memguard_decrypt(ctx)` — post-sleep: decrypt implant memory → flip RW→RX → decrypt heap → decrypt stack → verify integrity
  - `memguard_setup_return_spoof(ctx)` — modify sleeping thread's context so GetThreadContext returns legitimate return address
  - Integrate with sleep controller: update `sleep_ekko()` to call memguard_encrypt/decrypt instead of raw SystemFunction032
  - Verify `make` compiles all evasion engine code, `make size` confirms PIC blob stays under ~15KB (leaving room for comms/config)
  - *(Completed: memguard.c created with memguard_init/memguard_encrypt/memguard_decrypt/memguard_setup_return_spoof; MEMGUARD_STATE and STACK_REGION structs added to evasion.h; sleep_ekko updated to use memguard encrypt/decrypt cycle; memguard object adds only 2.6KB; test suite with 80/80 tests passing; all existing tests still pass — 58/58 hooks, 51/51 etw, 41/41 evasion_core, 57/57 sleep, 39/39 stackspoof; make builds clean with -Wall -Werror)*
