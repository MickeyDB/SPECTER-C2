# Phase 02: Implant Build System & Syscall Engine

This phase creates the C11 implant as a position-independent code (PIC) blob targeting Windows x86-64. It sets up the cross-compilation build system using MinGW-w64, implements CRT-free standard library replacements, PEB-based module/function resolution, and the syscall engine — dynamic SSN resolution from a clean ntdll copy with indirect syscall execution through code caves. By the end of this phase, the implant compiles to a raw PIC blob under 20KB, and the syscall engine can resolve and invoke any Nt* API without static imports.

## Context

The implant is a PIC blob (not a PE executable) compiled from C11 with inline assembly. It has zero static imports, no CRT dependency, and no PE headers. All string operations, memory operations, and math are reimplemented inline. The implant targets Windows 10 1809+ (x86-64 only). Development is on Windows; cross-compilation uses MinGW-w64 (`x86_64-w64-mingw32`). Compiler flags aim for minimal size: `-O1 -Os -fno-stack-protector -nostdlib -fPIC`.

Project root: `C:\Users\localuser\Documents\SPECTER-C2`
Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`

## Tasks

- [x] Set up implant project structure and cross-compilation build system:
  <!-- COMPLETED: Created implant/ directory structure, Makefile with MinGW-w64 cross-compilation, linker.ld (single .text section, entry at implant_entry), extract_shellcode.py (size/hash reporter), stub entry.c. Build verified: produces 16-byte specter.bin PIC blob. Updated CLAUDE.md with implant build instructions. -->
  - Install MinGW-w64 cross-compiler if not present: `choco install mingw` or download from https://www.mingw-w64.org/
  - Verify `x86_64-w64-mingw32-gcc` is on PATH (or use `gcc` from MinGW-w64 directly on Windows)
  - Create `implant/` directory at project root with subdirectories:
    - `implant/core/` — implant core source files
    - `implant/core/include/` — header files
    - `implant/core/asm/` — assembly stubs (GAS syntax for MinGW)
    - `implant/build/` — build output directory
    - `implant/scripts/` — build scripts and tooling
  - Create `implant/Makefile` with:
    - `CC = x86_64-w64-mingw32-gcc` (adjust if using MinGW-w64 native on Windows without prefix)
    - `LD = x86_64-w64-mingw32-ld`
    - `OBJCOPY = x86_64-w64-mingw32-objcopy`
    - CFLAGS: `-Wall -Werror -Os -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -fpack-struct=8 -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fPIC -nostdlib -nostdinc -ffreestanding -masm=intel -std=c11 -DWIN32_LEAN_AND_MEAN`
    - Compile steps: .c → .o → link with custom linker script → extract .text section to raw binary
    - Targets: `all`, `clean`, `size` (prints final PIC blob size)
    - Output: `implant/build/specter.bin` (raw PIC blob)
  - Create `implant/scripts/linker.ld` — custom linker script:
    - Single `.text` section containing all code and data
    - Entry point symbol: `implant_entry`
    - Discard all other sections (.reloc, .rsrc, .pdata, .xdata, etc.)
    - No CRT startup code
  - Create `implant/scripts/extract_shellcode.py` — post-build script:
    - Extracts the raw .text section from the linked object using objcopy
    - Prints final blob size and SHA256 hash
    - Warns if size exceeds 20KB target
  - Update `CLAUDE.md` with implant build instructions

- [x] Implement CRT-free standard library replacements in `implant/core/`:
  <!-- COMPLETED: Created specter.h (master header with manual Windows types, PEB/TEB/LDR structures, PE header structures, forward declarations), ntdefs.h (NTSTATUS codes, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, CLIENT_ID, MEMORY_BASIC_INFORMATION, LARGE_INTEGER, memory/section/file constants), string.c (spec_strlen, spec_wcslen, spec_strcmp, spec_wcsicmp, spec_memcpy, spec_memmove, spec_memset, spec_memcmp, spec_strcpy, spec_strcat), hash.c (spec_djb2_hash, spec_djb2_hash_w with verified pre-computed hashes for ntdll.dll=0x22D3B5ED, kernel32.dll=0x7040EE75). Updated entry.c to use specter.h. Build verified: 432-byte PIC blob, zero warnings under -Wall -Werror. -->
  - Create `implant/core/include/specter.h` — master header file:
    - Windows type definitions (DWORD, HANDLE, PVOID, NTSTATUS, UNICODE_STRING, etc.) — defined manually, NOT from windows.h
    - PEB and TEB structure definitions for API resolution
    - LDR_DATA_TABLE_ENTRY structure for module enumeration
    - NT_SUCCESS macro, STATUS_SUCCESS, NULL, TRUE/FALSE
    - Forward declarations for all core subsystems
  - Create `implant/core/include/ntdefs.h` — NT API definitions:
    - NTSTATUS codes (STATUS_SUCCESS, STATUS_ACCESS_DENIED, etc.)
    - OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, CLIENT_ID, MEMORY_BASIC_INFORMATION structures
    - Memory protection and allocation type constants
  - Create `implant/core/src/string.c` — CRT-free string operations:
    - `spec_strlen`, `spec_wcslen`, `spec_strcmp`, `spec_wcsicmp`, `spec_memcpy`, `spec_memmove`, `spec_memset`, `spec_memcmp`, `spec_strcpy`, `spec_strcat`
    - All functions prefixed with `spec_` to avoid CRT conflicts
  - Create `implant/core/src/hash.c` — API hashing:
    - `spec_djb2_hash(const char* str)` and `spec_djb2_hash_w(const wchar_t* str)` for DJB2 hashing
    - Pre-computed hash constants for critical DLL names (ntdll.dll, kernel32.dll) as `#define` macros
  - Verify cross-compilation: `make` produces object files without errors

- [x] Implement PEB walking and module resolution:
  <!-- COMPLETED: Created peb.h (header with function declarations for get_peb, find_module_by_hash, find_export_by_hash, resolve_function) and peb.c (full implementation). get_peb() reads PEB via GS:[0x60] inline asm. find_module_by_hash() walks PEB→Ldr→InLoadOrderModuleList, hashes each BaseDllName with spec_djb2_hash_w. find_export_by_hash() parses PE DOS→NT→export directory, hashes export names, handles forwarded exports by parsing "DLL.FuncName" strings and recursively resolving. resolve_function() combines both. Added forward declarations to specter.h. Build verified: 944-byte PIC blob, zero warnings under -Wall -Werror. -->
  - Create `implant/core/src/peb.c` and `implant/core/include/peb.h`:
    - `get_peb()` — inline assembly to read PEB from TEB (GS:[0x60] on x64)
    - `find_module_by_hash(DWORD hash)` — walks PEB→Ldr→InLoadOrderModuleList, hashes each DLL name, returns base address on match
    - `find_export_by_hash(PVOID module_base, DWORD hash)` — parses PE export directory from module base, hashes each export name, returns function pointer
    - `resolve_function(DWORD module_hash, DWORD func_hash)` — combines both lookups
    - Handle export forwarding (forwarded exports point to "otherdll.FuncName" strings)
    - All PE header parsing done manually (DOS header → NT headers → optional header → export directory)

- [x] Implement the syscall engine:
  <!-- COMPLETED: Created syscalls.h (SYSCALL_ENTRY/SYSCALL_TABLE structs, 17 pre-computed DJB2 hashes for Nt* functions, full API declarations for sc_init/sc_resolve_ssn/sc_find_gadget/sc_get_entry, spec_syscall extern, 16 convenience wrapper prototypes). Created syscalls.c (sc_init maps clean ntdll from \KnownDlls via NtOpenSection+NtMapViewOfSection bootstrap, sc_resolve_ssn reads SSN from 4C 8B D1 B8 XX XX stub pattern with hooked-stub neighbor fallback, sc_find_gadget scans executable sections for 0F 05 C3 gadget, sc_get_entry linear cache lookup, g_syscall_table global instance). Created syscall_stub.S (GAS/Intel syntax indirect syscall: spills SSN+addr to shadow space, shifts args down by 2 slots, sets R10=RCX, loads EAX=SSN, JMPs to syscall;ret gadget, supports up to 12 real syscall args). Created syscall_wrappers.c (16 typed wrappers: spec_NtAllocateVirtualMemory through spec_NtSetInformationThread, each using SC_ENTRY_OR_FAIL macro). Added forward declarations to specter.h. Build verified: 5024-byte PIC blob (4.9KB), zero warnings under -Wall -Werror. -->
  - Create `implant/core/include/syscalls.h` — syscall engine interface:
    - `SYSCALL_ENTRY` struct: `{ DWORD ssn; PVOID syscall_addr; DWORD hash; }`
    - `SYSCALL_TABLE` struct: fixed-size array of SYSCALL_ENTRY (capacity ~50), count field
    - Hash constants for required Nt* functions (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory, NtCreateThreadEx, NtOpenProcess, NtClose, NtMapViewOfSection, NtUnmapViewOfSection, NtCreateFile, NtQueryInformationProcess, NtSetInformationThread, NtDelayExecution, NtWaitForSingleObject, NtQueueApcThread, NtOpenSection)
  - Create `implant/core/src/syscalls.c` — syscall engine implementation:
    - `sc_init(SYSCALL_TABLE* table)` — maps clean ntdll from `\KnownDlls\ntdll.dll` (NtOpenSection + NtMapViewOfSection), falls back to disk read, walks clean exports to extract SSNs, finds `syscall; ret` gadget
    - `sc_resolve_ssn(PVOID clean_ntdll, DWORD func_hash)` — reads SSN from stub pattern (`4C 8B D1 B8 XX XX 00 00`), handles hooked stubs
    - `sc_find_gadget(PVOID clean_ntdll)` — finds `0F 05 C3` gadget in ntdll .text section
    - `sc_get_entry(SYSCALL_TABLE* table, DWORD func_hash)` — cache lookup by hash
  - Create `implant/core/asm/syscall_stub.asm` — indirect syscall invocation (GAS/Intel syntax):
    - `spec_syscall(SSN, syscall_addr, arg1, arg2, arg3, arg4, ...)` — moves SSN to EAX, R10 from RCX, jumps to syscall_addr inside ntdll
    - Create variants for different argument counts (4, 8, 12 args)
  - Create `implant/core/src/syscall_wrappers.c` — convenience wrappers:
    - `spec_NtAllocateVirtualMemory`, `spec_NtProtectVirtualMemory`, `spec_NtFreeVirtualMemory`, `spec_NtCreateThreadEx`, `spec_NtDelayExecution`, `spec_NtClose`, `spec_NtMapViewOfSection`, `spec_NtUnmapViewOfSection`, `spec_NtOpenSection`, `spec_NtCreateFile`, `spec_NtWriteVirtualMemory`, `spec_NtReadVirtualMemory`, `spec_NtQueryInformationProcess`, `spec_NtWaitForSingleObject`, `spec_NtQueueApcThread`
    - Each wrapper: looks up SYSCALL_ENTRY from global table, calls spec_syscall

- [x] Create the implant entry point and core initialization:
  <!-- COMPLETED: Created IMPLANT_CONTEXT struct in specter.h (fields: syscall_table, clean_ntdll, config, comms_ctx, sleep_ctx, evasion_ctx, module_bus, running). Created globals.c with g_ctx global instance. Rewrote entry.c with full init sequence: zero context → PEB access → find ntdll/kernel32 → sc_init() syscall engine → stash clean_ntdll → NtDelayExecution proof-of-life (1s sleep via indirect syscall) → set running flag. Kept g_syscall_table in syscalls.c for wrapper compatibility, wired into g_ctx.syscall_table pointer. Build verified: 5216-byte PIC blob (5.1 KB), zero warnings under -Wall -Werror. -->
  - Create `implant/core/src/entry.c` — PIC entry point:
    - `void implant_entry(PVOID param)` — position-independent entry
    - Initialization sequence: resolve PEB → find ntdll/kernel32 → bootstrap NtOpenSection/NtMapViewOfSection → init syscall engine → placeholder calls for crypto/config/comms/sleep (TODO for later phases) → call NtDelayExecution as proof of working syscall engine → return
  - Create `implant/core/src/globals.c` — global state:
    - `SYSCALL_TABLE g_syscall_table` and `IMPLANT_CONTEXT g_ctx` struct with fields for all subsystem contexts (syscall_table, clean_ntdll, config, comms_ctx, sleep_ctx, evasion_ctx, module_bus, running flag)
  - Verify: `make` produces `implant/build/specter.bin`
  - Run `make size` to display PIC blob size (should be well under 20KB)
