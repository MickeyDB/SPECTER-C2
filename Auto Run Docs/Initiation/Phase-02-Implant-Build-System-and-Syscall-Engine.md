# Phase 02: Implant Build System & Syscall Engine

This phase creates the C11 implant project with a cross-compilation build system targeting Windows x86-64 PIC (position-independent code) output. It implements the syscall engine — the lowest-level component that all implant operations depend on. The syscall engine performs dynamic SSN resolution from a clean ntdll copy, executes indirect syscalls through ntdll code caves, and caches resolved SSNs in an encrypted lookup table. By the end of this phase, the implant compiles to a raw PIC blob from macOS using MinGW-w64 cross-compilation, and the syscall engine can resolve and invoke any Nt* API without static imports.

## Context

The implant is a PIC blob (not a PE executable) compiled from C11 with inline assembly. It has zero static imports, no CRT dependency, and no PE headers. All string operations, memory operations, and math are reimplemented inline. The implant targets Windows 10 1809+ (x86-64 only). Development is on macOS; cross-compilation uses MinGW-w64 (`x86_64-w64-mingw32`). The compiler flags aim for minimal size: `/O1 /Os /GS-` equivalent in GCC: `-O1 -Os -fno-stack-protector -nostdlib -fPIC`.

Project root: `/Users/mdebaets/Documents/SPECTER/`
Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`

## Tasks

- [ ] Set up implant project structure and cross-compilation build system:
  - Install MinGW-w64 cross-compiler if not present: `brew install mingw-w64`
  - Create `implant/` directory at project root with subdirectories:
    - `implant/core/` — implant core source files
    - `implant/core/include/` — header files
    - `implant/core/asm/` — assembly stubs (GAS syntax for MinGW)
    - `implant/build/` — build output directory
    - `implant/scripts/` — build scripts and tooling
  - Create `implant/Makefile` with:
    - `CC = x86_64-w64-mingw32-gcc`
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
  - Update project `CLAUDE.md` with implant build instructions:
    - Build: `cd implant && make`
    - Clean: `cd implant && make clean`
    - Requires: `brew install mingw-w64`

- [ ] Implement CRT-free standard library replacements in `implant/core/`:
  - Create `implant/core/include/specter.h` — master header file:
    - Windows type definitions (DWORD, HANDLE, PVOID, NTSTATUS, UNICODE_STRING, etc.) — defined manually, NOT from windows.h
    - PEB and TEB structure definitions for API resolution
    - LDR_DATA_TABLE_ENTRY structure for module enumeration
    - NT_SUCCESS macro, STATUS_SUCCESS, NULL, TRUE/FALSE
    - Forward declarations for all core subsystems
  - Create `implant/core/include/ntdefs.h` — NT API definitions:
    - NTSTATUS codes (STATUS_SUCCESS, STATUS_ACCESS_DENIED, etc.)
    - OBJECT_ATTRIBUTES structure and InitializeObjectAttributes macro
    - IO_STATUS_BLOCK structure
    - SECTION_INHERIT enum
    - MEMORY_BASIC_INFORMATION structure
    - CLIENT_ID structure
    - Memory protection constants (PAGE_READWRITE, PAGE_EXECUTE_READ, etc.)
    - Memory allocation type constants (MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, etc.)
  - Create `implant/core/src/string.c` — CRT-free string operations:
    - `spec_strlen`, `spec_wcslen` — string length
    - `spec_strcmp`, `spec_wcsicmp` — string comparison (case-sensitive and case-insensitive)
    - `spec_memcpy`, `spec_memmove`, `spec_memset`, `spec_memcmp` — memory operations
    - `spec_strcpy`, `spec_strcat` — string copy/concat
    - All functions prefixed with `spec_` to avoid CRT conflicts
  - Create `implant/core/src/hash.c` — API hashing:
    - `spec_djb2_hash(const char* str)` — DJB2 hash for ANSI strings
    - `spec_djb2_hash_w(const wchar_t* str)` — DJB2 hash for wide strings
    - Pre-computed hash constants for critical DLL names (ntdll.dll, kernel32.dll) as `#define` macros
    - Hash values generated at compile time for all required Nt* function names
  - Verify cross-compilation: `make` produces object files from these sources without errors

- [ ] Implement PEB walking and module resolution:
  - Create `implant/core/src/peb.c` — PEB-based module and function resolution:
    - `get_peb()` — inline assembly to read PEB from TEB (GS:[0x60] on x64)
    - `find_module_by_hash(DWORD hash)` — walks PEB→Ldr→InLoadOrderModuleList, hashes each DLL name (Unicode, case-insensitive), returns base address on match
    - `find_export_by_hash(PVOID module_base, DWORD hash)` — parses PE export directory from module base address, hashes each export name, returns function pointer on match
    - `resolve_function(DWORD module_hash, DWORD func_hash)` — combines both: find module → find export
    - Handle export forwarding (forwarded exports point to "otherdll.FuncName" strings)
    - All PE header parsing done manually (DOS header → NT headers → optional header → export directory → name/ordinal/function arrays)
  - Create `implant/core/include/peb.h` — header with function prototypes and hash macros

- [ ] Implement the syscall engine:
  - Create `implant/core/include/syscalls.h` — syscall engine interface:
    - `SYSCALL_ENTRY` struct: `{ DWORD ssn; PVOID syscall_addr; DWORD hash; }` — SSN, address of syscall;ret gadget in ntdll, function name hash
    - `SYSCALL_TABLE` struct: fixed-size array of SYSCALL_ENTRY (capacity for ~50 syscalls), count field
    - Function prototypes for all syscall engine operations
    - Hash constants for all required Nt* functions (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory, NtCreateThreadEx, NtOpenProcess, NtClose, NtMapViewOfSection, NtUnmapViewOfSection, NtCreateFile, NtQueryInformationProcess, NtSetInformationThread, NtDelayExecution, NtWaitForSingleObject, NtQueueApcThread, NtOpenSection)
  - Create `implant/core/src/syscalls.c` — syscall engine implementation:
    - `sc_init(SYSCALL_TABLE* table)` — initializes the syscall engine:
      1. Map a clean copy of ntdll.dll from `\KnownDlls\ntdll.dll` via PEB-resolved NtOpenSection + NtMapViewOfSection
      2. Fallback: read ntdll.dll from disk at `\SystemRoot\System32\ntdll.dll`
      3. Walk the clean ntdll's export directory to find all Nt* functions
      4. For each required function: extract SSN from the stub pattern (`mov r10, rcx; mov eax, SSN; ...`)
      5. Find a `syscall; ret` gadget within the clean ntdll .text section for indirect execution
      6. Populate the SYSCALL_TABLE with resolved entries
    - `sc_resolve_ssn(PVOID clean_ntdll, DWORD func_hash)` — resolves a single SSN:
      - Find the export in the clean ntdll by hash
      - Read the SSN from the stub: `4C 8B D1` (mov r10, rcx) followed by `B8 XX XX 00 00` (mov eax, SSN)
      - Handle edge cases: hooked stubs (jmp instruction at start), wow64 stubs
      - Return SSN value
    - `sc_find_gadget(PVOID clean_ntdll)` — finds a `syscall; ret` (0F 05 C3) gadget in ntdll's .text section for indirect syscall execution
    - `sc_get_entry(SYSCALL_TABLE* table, DWORD func_hash)` — looks up a cached syscall entry by function hash
  - Create `implant/core/asm/syscall_stub.asm` — indirect syscall invocation stub (GAS/Intel syntax):
    - Assembly function `spec_syscall(SSN, syscall_addr, arg1, arg2, arg3, arg4, ...)`:
      - Move SSN into EAX
      - Set up R10 from RCX (Windows x64 syscall convention)
      - Push remaining arguments onto the stack in correct order
      - `jmp` to the syscall_addr (which points to `syscall; ret` inside ntdll)
      - This ensures the `syscall` instruction executes from within ntdll's .text section
    - Create variants for different argument counts (4, 8, 12 args) or use a variadic approach
    - The return address on the stack will point into ntdll, not the implant — this is the indirect syscall technique
  - Create convenience wrapper functions in `implant/core/src/syscall_wrappers.c`:
    - `spec_NtAllocateVirtualMemory(handle, base, size, type, protect)` — wraps spec_syscall with correct SSN lookup
    - `spec_NtProtectVirtualMemory(handle, base, size, new_protect, old_protect)`
    - `spec_NtFreeVirtualMemory(handle, base, size, free_type)`
    - `spec_NtCreateThreadEx(...)`
    - `spec_NtDelayExecution(alertable, delay_interval)`
    - `spec_NtClose(handle)`
    - `spec_NtMapViewOfSection(...)`
    - `spec_NtUnmapViewOfSection(process, base)`
    - `spec_NtOpenSection(handle, access, object_attrs)`
    - `spec_NtCreateFile(...)`
    - `spec_NtWriteVirtualMemory(...)`
    - `spec_NtReadVirtualMemory(...)`
    - `spec_NtQueryInformationProcess(...)`
    - `spec_NtWaitForSingleObject(handle, alertable, timeout)`
    - `spec_NtQueueApcThread(...)`
    - Each wrapper: looks up SYSCALL_ENTRY from the global table, calls spec_syscall with the entry's SSN and syscall_addr
  - Verify: `make` compiles all syscall engine code into object files without errors

- [ ] Create the implant entry point and core initialization:
  - Create `implant/core/src/entry.c` — PIC entry point:
    - `void implant_entry(PVOID param)` — the single entry function, position-independent
    - Initialization sequence:
      1. Resolve PEB pointer
      2. Find ntdll.dll and kernel32.dll base addresses via PEB walk
      3. Resolve minimal bootstrap functions (NtOpenSection, NtMapViewOfSection) from the in-memory ntdll (just for bootstrapping the clean copy)
      4. Initialize syscall engine (maps clean ntdll, resolves all SSNs)
      5. Placeholder calls for subsystems initialized in later phases: `// TODO: init crypto layer`, `// TODO: init config store`, `// TODO: init comms engine`, `// TODO: init sleep controller`
      6. Placeholder for main loop: `// TODO: enter comms loop`
      7. For now: call NtDelayExecution (via syscall engine) as proof that the syscall engine works, then return
    - The entry point takes a single PVOID parameter (used by loaders/injectors to pass context)
  - Create `implant/core/src/globals.c` — global state:
    - Global `SYSCALL_TABLE g_syscall_table` — the syscall lookup table
    - Global `IMPLANT_CONTEXT g_ctx` struct (defined in specter.h) with fields:
      - `SYSCALL_TABLE* syscall_table`
      - `PVOID clean_ntdll` — mapped clean ntdll base
      - `PVOID config` — pointer to decrypted config (NULL until Phase 03)
      - `PVOID comms_ctx` — comms engine context (NULL until Phase 03)
      - `PVOID sleep_ctx` — sleep controller context (NULL until Phase 03)
      - `PVOID evasion_ctx` — evasion engine context (NULL until Phase 04)
      - `PVOID module_bus` — module bus context (NULL until Phase 05)
      - `BOOL running` — main loop flag
  - Verify: `make` produces `implant/build/specter.bin` — the raw PIC blob
  - Run `make size` to display the PIC blob size (should be well under 20KB at this stage)
