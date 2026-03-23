# Phase 09: Core Modules

This phase implements the six core capability modules shipped with SPECTER: SOCKS5 reverse proxy, token manipulation, lateral movement (WMI/SCM/DCOM/Task Scheduler), process injection (CreateThread/APC/hijacking/stomping), exfiltration, and collection (keylogger/screenshots). Each module is a self-contained PIC blob using only the module bus API — no direct syscalls, no direct memory allocation, no direct networking. All operations route through the evasion engine automatically. By the end, operators can pivot, steal tokens, move laterally, inject into processes, exfiltrate data, and collect keystrokes/screenshots — all with full evasion coverage.

## Context

Modules use the MODULE_BUS_API table from Phase 05. They compile as PIC blobs using the same MinGW toolchain as the implant core. Each module is a single C file with an entry point receiving a bus API table pointer and argument blob. Output goes through `bus->output()`. Windows API calls go through `bus->resolve()`. The teamserver stores, signs, and encrypts modules per-implant before delivery.

Implant modules: `C:\Users\localuser\Documents\SPECTER-C2\implant\modules\`
Teamserver: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`

## Tasks

- [x] Set up module development framework and build system: *(Completed: created `implant/modules/` directory tree with per-module subdirs, `modules/include/module.h` with MODULE_BUS_API typedef/argument parsing/serialization/accessors/macros, `modules/template/module_template.c` reference implementation, `scripts/module_linker.ld`, updated Makefile with `make modules`/`modules-clean` targets and per-module PIC blob build rules, added `test_module_args` test — all 365 existing+new tests pass)*
  - Create `implant/modules/` directory with subdirectories per module
  - Create `implant/modules/include/module.h` — standard module header:
    - `MODULE_BUS_API` typedef matching bus API, `MODULE_ENTRY` typedef, `MODULE_ARGS` macros for parsing argument blobs (format: `[4B count][4B type][4B len][data]...`), common constants
  - Update `implant/Makefile`: each module compiles to `implant/build/modules/<name>.bin`, `make modules` target, same CFLAGS as core, entry point `module_entry`
  - Create `implant/modules/template/module_template.c` — reference template with standard entry, argument parsing, bus API usage, error handling

- [x] Implement the SOCKS5 reverse proxy module: *(Completed: created `implant/modules/socks5/socks5.c` — reverse SOCKS5 with start/stop/status subcommands, wire protocol (CONNECT_REQ/RSP, DATA, CLOSE, KEEPALIVE), 16 concurrent connections, per-check-in bandwidth throttle, IPv4+domain support, inline CRT primitives for PIC build (2432 bytes); created `crates/specter-server/src/socks/mod.rs` — SocksRelay with full SOCKS5 handshake (method selection + CONNECT), SocksManager for multi-session relay tracking, bidirectional async data relay via tasking channel; added `socks` module to server lib.rs; 6 new server tests in `tests/socks_tests.rs` — all pass along with all 365+ existing tests)*
  - Create `implant/modules/socks5/socks5.c`:
    - Reverse SOCKS architecture — implant initiates all connections outbound, no listening socket
    - SOCKS5 negotiation (method selection, CONNECT command), no BIND support
    - Data transport: tunnel data chunked into regular check-ins via `bus->output()`, per-check-in bandwidth throttle
    - Concurrent connections array (max 16), connection lifecycle management
  - Update teamserver — create `crates/specter-server/src/socks/mod.rs`:
    - SOCKS5 listener on teamserver (operator connects here), relay data to/from implant SOCKS module via tasking

- [x] Implement the token manipulation module: *(Completed: created `implant/modules/token/token.c` — four subcommands: `steal` (bus token_steal + token_impersonate), `make` (bus token_make with LOGON32_LOGON_NEW_CREDENTIALS + token_impersonate), `revert` (bus token_revert), `list` (NtQuerySystemInformation + NtOpenProcessToken + NtQueryInformationToken + LookupAccountSidW for PID|User|Session|Integrity table); inline CRT primitives for PIC build (3776 bytes); all 49 implant tests + all Rust workspace tests pass)*
  - Create `implant/modules/token/token.c`:
    - `token_steal(pid)` — proc_open → NtOpenProcessToken → NtDuplicateToken → token_impersonate
    - `token_make(domain, username, password)` — LogonUserW (LOGON32_LOGON_NEW_CREDENTIALS) via bus->resolve → token_impersonate
    - `token_revert()` — bus->token_revert()
    - `token_list()` — enumerate processes via NtQuerySystemInformation, query token user for each, output formatted table (PID | User | Session | Integrity | Privileges)
    - Argument dispatch: first arg as subcommand string ("steal", "make", "revert", "list")

- [x] Implement the lateral movement module: *(Completed: created `implant/modules/lateral/lateral.c` — four subcommands: `wmi` (SWbemLocator via CoCreateInstanceEx + ConnectServer + Win32_Process.Create via IDispatch), `scm` (OpenSCManagerW + CreateServiceW with random name + StartServiceW + DeleteService), `dcom` (three methods: mmc/MMC20.Application→ExecuteShellCommand, shell/ShellBrowserWindow→ShellExecute, windows/ShellWindows→Item→ShellExecute), `schtask` (ITaskService via CoCreateInstanceEx + NewTask + Actions.Create + RegisterTaskDefinition + auto-delete); all use direct DCOM with CoSetProxyBlanket auth, no PowerShell/wmic.exe/schtasks.exe; inline CRT primitives for PIC build (13408 bytes); all 365 implant tests + all Rust workspace tests pass)*
  - Create `implant/modules/lateral/lateral.c`:
    - `lateral_wmi(target, command)` — COM init → connect remote WMI `\\{target}\root\cimv2` → Win32_Process.Create, direct DCOM (no wmiprvse.exe spawn)
    - `lateral_scm(target, payload_path)` — OpenSCManagerW → create random-named service → start → delete immediately
    - `lateral_dcom(target, payload, method)` — ShellBrowserWindow/MMC20.Application/ShellWindows via CoCreateInstance with remote server
    - `lateral_schtask(target, payload_path)` — ITaskService COM → create immediate auto-deleting task
    - All via direct DCOM — no PowerShell, wmic.exe, or schtasks.exe
    - Argument dispatch: subcommand + target + payload args

- [x] Implement the process injection module: *(Completed: created `implant/modules/inject/inject.c` — four subcommands: `createthread` (NtAllocateVirtualMemory + proc_write + NtProtectVirtualMemory RX + NtCreateThreadEx), `apc` (alloc+write+protect + NtOpenThread + NtQueueApcThread for alertable threads), `hijack` (NtSuspendThread + NtGetContextThread + modify RIP + NtSetContextThread + NtResumeThread), `stomp` (walk remote PEB LDR InLoadOrderModuleList to find target DLL + parse PE headers for .text section + overwrite .text + NtCreateThreadEx at image-backed address); all use bus API for process ops + bus->resolve() for NT APIs, target validation via NtQueryInformationProcess WoW64 check, shared inject_write_shellcode helper; inline CRT primitives for PIC build (8128 bytes); all 365 implant tests + all Rust workspace tests pass)*
  - Create `implant/modules/inject/inject.c`:
    - `inject_createthread(pid, shellcode, len)` — proc_open → mem_alloc remote → proc_write → mem_protect RX → thread_create
    - `inject_apc(pid, tid, shellcode, len)` — open process/thread → alloc+write → NtQueueApcThread (thread must be alertable)
    - `inject_hijack(pid, tid, shellcode, len)` — suspend thread → get context → alloc+write → modify RIP → set context → resume
    - `inject_stomp(pid, dll_name, shellcode, len)` — find loaded DLL in target → overwrite .text with shellcode → create thread (lives in image-backed memory, avoids unbacked RX detection)
    - Target validation: verify PID exists, x64 architecture, accessible

- [x] Implement exfiltration and collection modules: *(Completed: created `implant/modules/exfil/exfil.c` — two subcommands: `file` (CreateFileA + ReadFile in configurable chunks + inline LZ4 compression + inline SHA256 per-chunk integrity + throttled bus->output with [chunk_idx|total_chunks|compressed_len|original_len|sha256|data] wire format) and `directory` (FindFirstFileA/FindNextFileA + wildcard pattern matching + optional single-level recursion + per-file exfil_single_file); created `implant/modules/collect/collect.c` — two subcommands: `keylog` (RegisterRawInputDevices Raw Input model + PeekMessageA polling + GetRawInputData + vkey-to-char translation with shift/caps awareness + foreground window tracking via GetForegroundWindow/GetWindowTextA + time-boxed duration up to 600s) and `screenshot` (GDI capture: CreateDCA("DISPLAY") + CreateCompatibleBitmap + BitBlt + GetDIBits to 24-bit BMP + inline LZ4 compression + configurable interval/count); both modules use inline CRT primitives for PIC build; exfil.bin=5920 bytes, collect.bin=5744 bytes; all 365 implant tests + all 524 Rust workspace tests pass)*
  - Create `implant/modules/exfil/exfil.c`:
    - `exfil_file(path, chunk_size, throttle_ms)` — read in chunks → LZ4 compress → SHA256 per chunk → bus->output with chunk metadata → throttle between chunks
    - `exfil_directory(dir, pattern, recursive, chunk_size, throttle_ms)` — list+filter+exfil each matching file
    - Teamserver reassembles chunks and verifies integrity
  - Create `implant/modules/collect/collect.c`:
    - Keylogger: Raw Input model (RegisterRawInputDevices, GetRawInputData) via bus->resolve, buffer keystrokes with timestamps and foreground window title, time-boxed duration, output on completion (no SetWindowsHookEx — heavily monitored)
    - Screen capture: GDI-based (CreateDCA, BitBlt, etc.) via bus->resolve, compress as BMP+LZ4, time-boxed count, output via bus->output
    - Both time-boxed by default, data buffered and exfiltrated via normal check-ins

- [x] Register modules in teamserver and add TUI commands: *(Completed: created `modules.proto` with ModuleInfo/ListModules/GetModuleInfo/LoadModule message types; added ListModules, GetModuleInfo, LoadModule RPCs to specter_service.proto; extended ModuleRepository with `get_module_by_name`, `get_module_id_by_name`, `seed_default_modules` (auto-seeds socks5/token/lateral/inject/exfil/collect on startup); implemented all 3 gRPC handlers in grpc/mod.rs with campaign access control, Ed25519 signing, X25519 per-session encryption via package_module, audit logging; added 7 TUI commands to CommandRegistry (socks, token, lateral, inject, keylog, screenshot, modules) with module_name_for_command mapping and module-aware build_task_args; added list_modules/load_module to SpecterClient; added handle_modules_list local handler; all 524 workspace tests pass)*
  - Create `ModuleRepository` service: register_module (sign with Ed25519), get_module, list_modules, package_module (encrypt per-session)
  - Seed repository with all six compiled .bin modules
  - Add TUI commands: `socks start/stop`, `token steal/make/revert/list`, `lateral wmi/scm/dcom/schtask`, `inject <technique> <pid>`, `download <path>`, `keylog <duration>`, `screenshot [interval] [count]`, `modules list`
  - Add gRPC RPCs: ListModules, GetModuleInfo, LoadModule(session_id, module_name, args)

- [x] Write tests for module argument parsing and repository: *(Completed: `implant/tests/test_module_args.c` already existed with 10 tests (49 assertions) covering roundtrip serialization, subcommand dispatch, type mismatch, out-of-bounds, edge cases, overflow, max args, wstring, and realistic lateral args; created `crates/specter-server/tests/module_repo_tests.rs` with 18 tests covering store/retrieve by ID and name, get_module_id_by_name, nonexistent module, list modules (populated+empty), PIC/COFF type handling, deletion, duplicate name+version rejection, signing pubkey verification, wire format validation (magic/version/type/size), Ed25519 signature verification over encrypted payload, full X25519+HKDF+ChaCha20-Poly1305 decryption roundtrip, package error for missing module, seed_default_modules (6 modules + idempotency), timestamps, per-session encryption uniqueness; `cargo test --workspace` passes all 546 tests, `make -C implant test` passes all 49/49)*
  - `implant/tests/test_module_args.c` — argument serialization/deserialization roundtrip, subcommand dispatch
  - `crates/specter-server/tests/module_repo_tests.rs` — registration, retrieval, signing, per-session encryption, list metadata
  - Run `cargo test --workspace` and `make -C implant test`
