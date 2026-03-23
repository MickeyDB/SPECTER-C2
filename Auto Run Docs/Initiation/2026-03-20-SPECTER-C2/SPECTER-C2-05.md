# Phase 05: Module Bus & Module Loader

This phase implements the module bus — the only interface through which modules interact with the system. Modules never make direct syscalls, allocate memory, or talk to the network. They receive an API function table routed through the evasion engine. This phase also implements the module loader (reflective PIC and COFF loading), Ed25519 signature verification, per-module X25519 encryption, guardian threads for crash isolation, and the full module lifecycle (fetch → verify → decrypt → load → execute → wipe → report). By the end, the implant can receive a signed encrypted module from the teamserver, load it, execute it with full evasion coverage, and cleanly wipe it after completion.

## Context

The module bus sits between modules and the implant core. All module operations (memory, network, process, thread, token, file, registry, output) go through function pointers in the bus API table. The bus implementations call the evasion engine, which calls the syscall engine. This three-layer architecture ensures consistent evasion regardless of module origin.

Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`
Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`

## Tasks

- [x] Define and implement the module bus API table in `implant/core/src/bus/bus_api.c` and `implant/core/include/bus.h`:
  - Create `implant/core/src/bus/` directory
  - `MODULE_BUS_API` struct — function table passed to every module:
    - Memory: `mem_alloc(size, perms)`, `mem_free(ptr)`, `mem_protect(ptr, size, perms)`
    - Network: `net_connect(addr, port, proto)`, `net_send(handle, data, len)`, `net_recv(handle, buf, len)`, `net_close(handle)`
    - Process: `proc_open(pid, access)`, `proc_read(handle, addr, buf, len)`, `proc_write(handle, addr, data, len)`, `proc_close(handle)`
    - Thread: `thread_create(func, param, suspended)`, `thread_resume(handle)`, `thread_terminate(handle)`
    - Token: `token_steal(pid)`, `token_impersonate(handle)`, `token_revert()`, `token_make(user, pass, domain)`
    - File: `file_read(path, buf, len)`, `file_write(path, data, len)`, `file_delete(path)`, `file_list(path)`
    - Registry: `reg_read(hive, path, value)`, `reg_write(hive, path, value, data, type)`, `reg_delete(hive, path, value)`
    - Output: `output(data, len, type)` — OUTPUT_TEXT=0, OUTPUT_BINARY=1, OUTPUT_ERROR=2
    - Resolve: `resolve(dll_name, func_name)` — returns clean function pointer
    - Logging: `log(level, msg)`
    - All use `__cdecl` calling convention
  - Each API function routes through the evasion engine (e.g., `bus_mem_alloc` → `evasion_syscall(NtAllocateVirtualMemory)` + tracks in sleep heap list)
  - `bus_init(ctx)` — populate function table
  - Implement encrypted output ring buffer: circular buffer with ChaCha20 encryption at rest, `output_write` and `output_drain` for check-in

- [x] Implement Ed25519 signature verification in `implant/core/src/crypto_sign.c`:
  - Inline Ed25519 implementation (no external library):
    - Extended twisted Edwards curve arithmetic over GF(2^255 - 19)
    - SHA-512 hash (required for Ed25519) — inline implementation
    - `spec_ed25519_verify(public_key, message, message_len, signature)` → TRUE if valid
  - Teamserver's Ed25519 public key is embedded in implant config at build time
  - Module packages include 64-byte Ed25519 signature over encrypted content

- [x] Implement the module loader in `implant/core/src/bus/loader.c`:
  - `MODULE_PACKAGE` wire format: 4B magic ("SPEC") + 4B version + 4B module_type (PIC=0, COFF=1) + 4B encrypted_size + 32B ephemeral X25519 pubkey + 64B Ed25519 signature + encrypted module data
  - `LOADED_MODULE` structure: module ID, type, entry point, memory base/size, guardian thread handle, status enum (LOADING/RUNNING/COMPLETED/CRASHED/WIPED), output buffer ref, bus API pointer
  - `loader_verify_package` — Ed25519 signature verification
  - `loader_decrypt_package` — derive per-module key via X25519, decrypt with ChaCha20-Poly1305
  - PIC loader: `loader_load_pic` — allocate RW, copy blob, inject API table pointer, flip to RX, return entry
  - COFF loader: `loader_load_coff` — parse COFF headers, process relocations (IMAGE_REL_AMD64_ADDR64, ADDR32NB, REL32), resolve external symbols against bus API and Beacon API shim names, lay out sections, return entry

- [x] Implement guardian threads and crash isolation in `implant/core/src/bus/guardian.c`:
  - `guardian_create(entry_point, param, mod)` — register VEH, create thread in suspended state, set context, resume
  - VEH handler: on EXCEPTION_ACCESS_VIOLATION/EXCEPTION_STACK_OVERFLOW → set module CRASHED → trigger cleanup → terminate guardian thread; main implant loop continues unaffected
  - `guardian_wait(mod, timeout)` and `guardian_kill(mod)` for lifecycle management

- [x] Implement the full module lifecycle manager in `implant/core/src/bus/lifecycle.c`:
  - `MODULE_MANAGER` structure: array of LOADED_MODULE slots (max 8 concurrent), active count, implant context pointer
  - `modmgr_init(ctx)`, `modmgr_execute(mgr, package, len)` — verify → decrypt → load → execute in guardian thread
  - `modmgr_poll(mgr)` — check running modules, drain completed output, collect crash info
  - `modmgr_cleanup(mgr, slot)` — flip to RW → zero-fill → decommit → release → zero slot
  - Integrate with main check-in loop: for module-type tasks call modmgr_execute, before check-in call modmgr_poll, include results in payload
  - Update teamserver: add `module_repository` table (module_id, name, version, type, blob, signature, created_at), add `TaskType::LoadModule` to task dispatcher, package modules with Ed25519 signing + session-key encryption
  - *Completed: lifecycle.c with full module manager (36/36 tests pass), teamserver module_repository table, ModuleRepository service with Ed25519 signing + X25519/ChaCha20-Poly1305 packaging, load_module task type in check-in flow*

- [x] Write tests for module bus and loader:
  - Create `implant/tests/` directory with test harness (`test_harness.h` with mocked Windows types)
  - `test_coff_loader.c` — COFF parsing, relocation processing, symbol resolution
  - `test_bus_api.c` — bus_init populates all function pointers, output ring buffer roundtrip
  - `test_ed25519.c` — verify with RFC 8032 test vectors, reject invalid signatures
  - Add `make test` target using host compiler with mocked Windows APIs
  - *Verified: all 142 tests pass (68 bus_api + 10 ed25519 + 28 coff_loader + 36 lifecycle) via `make test` with native gcc -DTEST_BUILD*
