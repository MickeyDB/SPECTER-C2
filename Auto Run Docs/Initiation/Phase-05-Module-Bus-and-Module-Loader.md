# Phase 05: Module Bus & Module Loader

This phase implements the module bus architecture — the only interface through which modules interact with the system. Modules do not make their own syscalls, allocate their own memory, or talk to the network directly. They receive an API function table from the bus that routes everything through the evasion engine. This phase also implements the module loader (reflective loading for PIC blobs and COFF loading for BOFs), signature verification (Ed25519), module encryption (per-module ephemeral key via X25519), the guardian thread model for crash isolation, and the full module lifecycle (fetch → verify → decrypt → load → execute → wipe → report). By the end of this phase, the implant can receive a signed, encrypted module from the teamserver, load it into memory, execute it with the full evasion-aware API surface, and cleanly wipe it after completion.

## Context

The module bus sits between modules and the implant core. All module operations (memory, network, process, thread, token, file, registry, output, resolve, logging) go through function pointers in the bus API table. The bus implementations call the evasion engine, which calls the syscall engine. This three-layer architecture ensures consistent evasion regardless of who wrote the module.

Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`
Teamserver source: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`

## Tasks

- [ ] Define and implement the module bus API table in `implant/core/src/bus/bus_api.c` and `implant/core/include/bus.h`:
  - Create `implant/core/src/bus/` directory for all module bus source files
  - Define `MODULE_BUS_API` struct — the function table passed to every module:
    - **Memory**: `mem_alloc(size, perms) → ptr`, `mem_free(ptr)`, `mem_protect(ptr, size, new_perms)`
    - **Network**: `net_connect(addr, port, proto) → handle`, `net_send(handle, data, len)`, `net_recv(handle, buf, len) → bytes_read`, `net_close(handle)`
    - **Process**: `proc_open(pid, access) → handle`, `proc_read(handle, addr, buf, len)`, `proc_write(handle, addr, data, len)`, `proc_close(handle)`
    - **Thread**: `thread_create(func, param, suspended) → handle`, `thread_resume(handle)`, `thread_terminate(handle)`
    - **Token**: `token_steal(pid) → token_handle`, `token_impersonate(token_handle)`, `token_revert()`, `token_make(user, pass, domain) → token_handle`
    - **File**: `file_read(path, buf, len)`, `file_write(path, data, len)`, `file_delete(path)`, `file_list(path) → entries[]`
    - **Registry**: `reg_read(hive, path, value) → data`, `reg_write(hive, path, value, data, type)`, `reg_delete(hive, path, value)`
    - **Output**: `output(data, len, type)` — type: OUTPUT_TEXT=0, OUTPUT_BINARY=1, OUTPUT_ERROR=2
    - **Resolve**: `resolve(dll_name, func_name) → func_ptr` — returns clean function pointer from mapped ntdll/kernel32
    - **Logging**: `log(level, msg)` — levels: DEBUG=0, INFO=1, WARN=2, ERROR=3
    - All function pointers use `__cdecl` calling convention for C ABI compatibility
  - Implement each API function as a wrapper that routes through the evasion engine:
    - `bus_mem_alloc(size, perms)` → calls `evasion_syscall(NtAllocateVirtualMemory, ...)`, tracks allocation in sleep controller's heap list
    - `bus_mem_free(ptr)` → zero-fills region, calls `evasion_syscall(NtFreeVirtualMemory, ...)`, untracks from heap list
    - `bus_mem_protect(ptr, size, perms)` → calls `evasion_syscall(NtProtectVirtualMemory, ...)`
    - `bus_proc_open(pid, access)` → calls `evasion_syscall(NtOpenProcess, ...)`
    - `bus_proc_read/write` → calls `evasion_syscall(NtReadVirtualMemory/NtWriteVirtualMemory, ...)`
    - `bus_thread_create(func, param, suspended)` → calls `evasion_syscall(NtCreateThreadEx, ...)` with guardian thread wrapping (see below)
    - `bus_file_read/write/delete/list` → calls `evasion_syscall(NtCreateFile, NtReadFile, NtWriteFile, ...)`
    - `bus_net_*` → routes through the comms engine (profile-aware networking)
    - `bus_output(data, len, type)` → buffers output in an encrypted ring buffer, drained on check-ins
    - `bus_resolve(dll, func)` → uses PEB walk with clean module resolution
    - `bus_log(level, msg)` → buffers log for next check-in
  - Create `bus_init(IMPLANT_CONTEXT* ctx)` → populates the MODULE_BUS_API function table with all implementation pointers
  - Implement the output ring buffer:
    - `OUTPUT_BUFFER` struct: circular buffer of encrypted output chunks
    - `output_write(buffer, data, len, type)` → append output chunk, encrypt in-place
    - `output_drain(buffer, out, max_len)` → decrypt and extract all buffered output for check-in transmission
    - Buffer is encrypted at rest (ChaCha20 with rotating key)

- [ ] Implement Ed25519 signature verification in `implant/core/src/crypto_sign.c`:
  - Inline Ed25519 implementation (no external library):
    - Extended twisted Edwards curve arithmetic over GF(2^255 - 19)
    - Point addition, doubling, scalar multiplication
    - SHA-512 hash (required for Ed25519) — inline implementation
    - `spec_ed25519_verify(public_key, message, message_len, signature)` → returns TRUE if signature is valid
  - The teamserver's Ed25519 public key is embedded in the implant config at build time
  - Module packages include a 64-byte Ed25519 signature over the encrypted module content

- [ ] Implement the module loader in `implant/core/src/bus/loader.c`:
  - Define `MODULE_PACKAGE` structure (wire format from teamserver):
    - 4-byte magic: `SPEC`
    - 4-byte version
    - 4-byte module_type: PIC_BLOB=0, COFF_OBJ=1
    - 4-byte encrypted_size
    - 32-byte ephemeral X25519 public key (for per-module key derivation)
    - 64-byte Ed25519 signature (over everything after signature)
    - Variable-length encrypted module data (ChaCha20-Poly1305)
  - Define `LOADED_MODULE` structure:
    - Module ID, type, entry point function pointer
    - Memory base address and size
    - Thread handle (guardian thread)
    - Status enum: LOADING, RUNNING, COMPLETED, CRASHED, WIPED
    - Output buffer reference
    - Bus API table pointer
  - `loader_verify_package(BYTE* package, DWORD len, BYTE* signing_key)` → verify Ed25519 signature, return success/failure
  - `loader_decrypt_package(BYTE* package, BYTE* implant_privkey)` → derive per-module key via X25519(implant_priv, module_ephemeral_pub), decrypt with ChaCha20-Poly1305, return decrypted module blob
  - PIC blob loader:
    - `loader_load_pic(BYTE* blob, DWORD blob_len, MODULE_BUS_API* api)` → allocate RW memory, copy blob, inject API table pointer at known offset, flip to RX, return entry point
  - COFF object loader (for BOF compatibility):
    - `loader_load_coff(BYTE* coff_data, DWORD len, MODULE_BUS_API* api)` → parse COFF headers, process relocations, resolve external symbols (map Beacon API names to bus API equivalents), allocate and lay out sections, return entry point
    - COFF parsing: read section headers, symbol table, string table
    - Relocation processing: IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_ADDR32NB, IMAGE_REL_AMD64_REL32
    - Symbol resolution: match external symbols against the bus API function names and Beacon API shim names

- [ ] Implement guardian threads and crash isolation in `implant/core/src/bus/guardian.c`:
  - `guardian_create(entry_point, param, LOADED_MODULE* mod)` — create a guardian thread for module execution:
    - Register a Vectored Exception Handler (VEH) before creating the thread
    - Create thread in suspended state (via evasion_syscall NtCreateThreadEx)
    - Set thread context to enter the module entry point
    - Resume thread
  - VEH handler for crash isolation:
    - On EXCEPTION_ACCESS_VIOLATION, EXCEPTION_STACK_OVERFLOW, or other fatal exceptions:
      1. Capture fault address and exception context (for reporting)
      2. Set the module's status to CRASHED
      3. Trigger module cleanup (wipe memory)
      4. Terminate the guardian thread
      5. The main implant comms loop continues unaffected
    - The VEH only handles exceptions on the guardian thread (check thread ID)
  - `guardian_wait(LOADED_MODULE* mod, DWORD timeout)` — wait for module completion with timeout
  - `guardian_kill(LOADED_MODULE* mod)` — forcefully terminate a running module

- [ ] Implement the full module lifecycle manager in `implant/core/src/bus/lifecycle.c`:
  - Define `MODULE_MANAGER` structure:
    - Array of `LOADED_MODULE` slots (max 8 concurrent modules)
    - Active module count
    - Pointer to implant context (for comms, crypto access)
  - `modmgr_init(IMPLANT_CONTEXT* ctx)` → initialize module manager, zero all slots
  - `modmgr_execute(MODULE_MANAGER* mgr, BYTE* package, DWORD package_len)` — full lifecycle:
    1. **Verify**: `loader_verify_package()` — reject unsigned/tampered modules
    2. **Decrypt**: `loader_decrypt_package()` — decrypt with per-module key
    3. **Load**: `loader_load_pic()` or `loader_load_coff()` based on module type
    4. **Execute**: `guardian_create()` — run in isolated guardian thread
    5. Module runs asynchronously — modmgr returns immediately
  - `modmgr_poll(MODULE_MANAGER* mgr)` — check status of all running modules:
    - For completed modules: drain output buffer, set status to COMPLETED
    - For crashed modules: capture crash info, set status to CRASHED
    - Returns list of results ready for check-in
  - `modmgr_cleanup(MODULE_MANAGER* mgr, int slot)` — wipe a completed/crashed module:
    1. Flip memory to RW
    2. Zero-fill entire module memory region
    3. Decommit memory (NtFreeVirtualMemory with MEM_DECOMMIT)
    4. Release memory (NtFreeVirtualMemory with MEM_RELEASE)
    5. Zero-fill guardian thread stack
    6. Zero-fill the LOADED_MODULE slot
    7. Decrement active count
  - Integrate with the main check-in loop in `implant/core/src/entry.c`:
    - After receiving tasks from check-in: for module-type tasks, call `modmgr_execute()`
    - Before each check-in: call `modmgr_poll()` to collect results
    - Include module results in the check-in payload
  - Update teamserver to handle module tasking:
    - Add `module_repository` table in SQLite (module_id, name, version, type, blob, signature, created_at)
    - Add `TaskType::LoadModule` in the task dispatcher
    - When a module task is dispatched: package the module (sign with Ed25519, encrypt with implant's session key), include in the check-in response

- [ ] Write tests for module bus and loader:
  - Create `implant/tests/` directory with test harness:
    - Since the implant is PIC targeting Windows, tests run as regular C programs on the host (macOS) with mocked Windows APIs
    - Create `implant/tests/test_harness.h` with mock implementations of Windows types and basic assertions
  - `test_coff_loader.c`:
    - Test COFF parsing with a minimal COFF object (create a test .o file with MinGW)
    - Test relocation processing
    - Test symbol resolution
  - `test_bus_api.c`:
    - Test that bus_init populates all function pointers (non-NULL)
    - Test output ring buffer write/drain cycle
    - Test bus_mem_alloc/free cycle (mocked syscalls)
  - `test_ed25519.c`:
    - Test Ed25519 signature verification with known test vectors (RFC 8032)
    - Test rejection of invalid signatures
  - Add test targets to `implant/Makefile`:
    - `make test` — compile and run tests using the host compiler (cc, not mingw)
    - Tests link against the same source files but with mocked Windows API implementations
