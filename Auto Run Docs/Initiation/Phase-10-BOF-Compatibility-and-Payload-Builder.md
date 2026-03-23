# Phase 10: BOF Compatibility & Payload Builder

This phase implements two major systems: the BOF (Beacon Object File) compatibility layer that allows SPECTER to execute existing Cobalt Strike BOFs with full evasion coverage, and the payload builder that generates implant payloads on demand with compile-time obfuscation. The BOF compatibility layer provides a complete Beacon API shim, extends it with SPECTER's evasion-aware module bus API, and handles COFF loading with crash isolation. The payload builder compiles implant binaries with per-build uniqueness (string key rotation, junk code insertion, control flow flattening, API hash randomization) and outputs them in multiple formats (raw shellcode, DLL sideload, service EXE, .NET assembly wrapper). By the end of this phase, operators can use the vast existing BOF ecosystem and generate unique, obfuscated implant payloads for each deployment.

## Context

BOFs are COFF object files (.o) compiled with MinGW or MSVC. They use the Cobalt Strike Beacon API (BeaconPrintf, BeaconOutput, BeaconDataParse, etc.) for interaction. SPECTER provides a shim layer that maps these Beacon API calls to the SPECTER module bus API, so existing BOFs work without modification. Additionally, BOFs can opt-in to the extended SPECTER bus API for evasion-aware operations.

The payload builder is a teamserver subsystem that cross-compiles the implant with a specific profile and obfuscation settings, producing deployment-ready artifacts.

Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`
Teamserver source: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`

## Tasks

- [ ] Implement the Cobalt Strike Beacon API compatibility shim:
  - Create `implant/core/src/bus/beacon_shim.c` and `implant/core/include/beacon.h`:
    - Define the standard Beacon API types:
      - `datap` struct (data parser): `{ char* original; char* buffer; int length; int size; }`
      - `formatp` struct (format buffer): `{ char* original; char* buffer; int length; int size; }`
    - Implement all Beacon API functions, mapping to module bus API calls:
      - **Output functions**:
        - `BeaconPrintf(type, fmt, ...)` → format string → `bus->output(formatted, len, type)`
        - `BeaconOutput(type, data, len)` → `bus->output(data, len, type)`
        - CALLBACK_OUTPUT=0, CALLBACK_OUTPUT_OEM=0x1e, CALLBACK_ERROR=0x0d
      - **Data parser functions** (for reading BOF arguments):
        - `BeaconDataParse(parser, buffer, size)` → initialize datap struct
        - `BeaconDataExtract(parser, size_out)` → extract length-prefixed string
        - `BeaconDataInt(parser)` → extract 4-byte integer
        - `BeaconDataShort(parser)` → extract 2-byte integer
        - `BeaconDataLength(parser)` → remaining bytes
      - **Format buffer functions** (for building output):
        - `BeaconFormatAlloc(format, maxsz)` → allocate format buffer
        - `BeaconFormatAppend(format, data, len)` → append data
        - `BeaconFormatPrintf(format, fmt, ...)` → format and append
        - `BeaconFormatFree(format)` → free buffer
        - `BeaconFormatToString(format, size_out)` → get final string
      - **Token functions**:
        - `BeaconUseToken(token)` → `bus->token_impersonate(token)`
        - `BeaconRevertToken()` → `bus->token_revert()`
      - **Utility functions**:
        - `BeaconIsAdmin()` → check if current token has admin privileges
        - `BeaconGetSpawnTo(x86, buffer, length)` → return spawn-to process path from config
        - `toWideChar(src, dst, max)` → ANSI to Unicode conversion
    - Build the Beacon API as a separate object file that gets linked with BOFs during COFF loading
  - Create `BEACON_API_TABLE` — function pointer table mapping Beacon API symbol names to shim implementations:
    - Used during COFF symbol resolution (loader_load_coff from Phase 05)
    - When the COFF loader encounters an external reference to "BeaconPrintf", it resolves to the shim function pointer

- [ ] Implement the extended BOF API and .NET CLR hosting:
  - Update `implant/core/src/bus/beacon_shim.c` with SPECTER extensions:
    - BOFs that want evasion-aware operations can use the `SPECTER_*` API prefix:
      - `SPECTER_MemAlloc(size, perms)` → `bus->mem_alloc()`
      - `SPECTER_Resolve(dll, func)` → `bus->resolve()`
      - `SPECTER_NetConnect(addr, port, proto)` → `bus->net_connect()`
      - `SPECTER_ProcOpen(pid, access)` → `bus->proc_open()`
      - `SPECTER_FileRead(path, buf, len)` → `bus->file_read()`
      - These are opt-in — legacy CS BOFs don't need them
    - Add the SPECTER API symbols to the COFF symbol resolution table
  - Create `implant/core/src/bus/clr.c` — .NET assembly execution:
    - Headless CLR hosting via COM interfaces:
      - Resolve mscoree.dll!CLRCreateInstance via `bus->resolve()`
      - Create ICLRRuntimeHost2 (targeting .NET 4.0+)
      - Create AppDomain for isolation
    - Before CLR init: trigger lazy AMSI bypass (`evasion_patch_amsi()` from Phase 04)
    - Before CLR init: suppress CLR ETW provider (`evasion_patch_etw()` targeting Microsoft-Windows-DotNETRuntime)
    - `clr_execute_assembly(BYTE* assembly, DWORD len, char* args)`:
      - Load assembly from memory (no disk touch) via AppDomain.Load
      - Invoke entry point with arguments
      - Capture stdout/stderr output → `bus->output()`
      - Unload AppDomain after execution
    - Crash isolation: CLR execution runs in a guardian thread (Phase 05)
  - Create `implant/core/src/bus/inline_asm.c` — inline assembly execution:
    - `exec_shellcode(BYTE* code, DWORD len)`:
      - Allocate RW memory, copy shellcode, flip to RX, create guardian thread, execute
      - No COFF parsing — direct PIC shellcode execution
      - Useful for custom shellcode tasks and simple payloads

- [ ] Implement the payload builder in the teamserver:
  - Create `crates/specter-server/src/builder/mod.rs`:
    - `PayloadBuilder` struct:
      - Implant source path (or embedded pre-compiled templates)
      - MinGW cross-compiler path
      - Profile compiler reference
      - Obfuscation settings
    - `builder_init(config)` → verify cross-compiler is available, load implant source templates
    - Build approach: the payload builder either:
      - (A) Cross-compiles the implant source on-demand with obfuscation transforms applied, OR
      - (B) Uses pre-compiled template blobs and applies binary-level transforms
      - Start with approach (B) for speed: maintain a set of pre-compiled implant core templates, apply post-compilation transforms
  - Create `crates/specter-server/src/builder/config_gen.rs` — config blob generation:
    - `generate_config(profile, keypair, channels, sleep_config, kill_date)` → produce encrypted config blob:
      - Generate implant X25519 keypair
      - Serialize IMPLANT_CONFIG structure
      - Include compiled profile blob
      - Encrypt with per-build key
      - Return config blob + implant public key (to store in session registry)
    - This replaces the Python build_config.py script from Phase 03 with a Rust implementation integrated into the teamserver

- [ ] Implement compile-time obfuscation transforms:
  - Create `crates/specter-server/src/builder/obfuscation.rs`:
    - **String encryption key rotation**:
      - Generate a random 32-byte XOR key per build
      - Re-encrypt all string constants in the PIC blob with the new key
      - Patch the decryption key location in the blob
    - **API hash randomization**:
      - Instead of fixed DJB2 hashes, use a per-build hash salt
      - Recompute all API hash constants with the new salt
      - Patch hash values and salt in the blob
    - **Junk code insertion**:
      - Insert random NOP-equivalent instruction sequences between functions
      - Sequences: `push/pop` pairs, `xchg reg,reg`, `lea reg,[reg+0]`, `mov reg,reg`
      - Varies the size and offsets of functions between builds
    - **Control flow flattening** (simplified):
      - For each function: wrap basic blocks in a switch/dispatcher loop
      - Each basic block assigned a random state number
      - Execution dispatches through the state machine rather than sequential flow
      - This is applied at the source level via a pre-compilation transform (C source rewriting) or at the binary level via a simple block reordering pass
    - `obfuscate(blob: &[u8], settings: ObfuscationSettings) -> Vec<u8>` → apply all selected transforms to the PIC blob
  - Create `ObfuscationSettings` struct:
    - string_encrypt: bool (default true)
    - hash_randomize: bool (default true)
    - junk_code: bool (default true)
    - junk_code_density: f32 (0.0-1.0, default 0.3)
    - control_flow_flatten: bool (default false — resource intensive)

- [ ] Implement output format wrappers:
  - Create `crates/specter-server/src/builder/formats.rs`:
    - **Raw shellcode** (.bin): the PIC blob as-is, with config appended — `format_raw(blob, config) -> Vec<u8>`
    - **DLL sideloading** (.dll):
      - Generate a minimal DLL with DllMain that executes the PIC blob
      - DLL exports match a legitimate DLL's export table (for proxy DLL sideloading)
      - `format_dll(blob, config, proxy_target: Option<String>) -> Vec<u8>`
      - If proxy_target specified: forward all other exports to the real DLL
    - **Service EXE** (.exe):
      - Generate a minimal service binary (ServiceMain entry point)
      - Service entry point extracts and executes the PIC blob
      - Mimics a legitimate service name and description
      - `format_service_exe(blob, config, service_name: &str) -> Vec<u8>`
    - **.NET assembly wrapper**:
      - Generate a .NET assembly that loads and executes the PIC blob
      - Uses Assembly.Load from byte array (in-memory, no disk)
      - `format_dotnet(blob, config) -> Vec<u8>`
    - **Stagers** (discouraged but supported):
      - PowerShell stager: download and execute PIC blob — `format_ps1_stager(download_url) -> String`
      - HTA stager: HTML Application wrapper — `format_hta_stager(download_url) -> String`
      - Both produce warnings in the builder output about OPSEC concerns
  - Create `crates/specter-server/src/builder/yara.rs` — YARA signature scanning:
    - Integrate `yara-x` crate for YARA rule matching
    - `scan_payload(blob: &[u8], rules_dir: &str) -> Vec<YaraMatch>`
    - Load rules from `rules/` directory (community rules + custom rules)
    - Scan every generated payload before delivery
    - If matches found: return warnings with specific rule names and offsets — operator decides whether to proceed
    - Create `rules/` directory at project root with a placeholder rule file
  - Add gRPC RPCs for the payload builder:
    - `GeneratePayload(profile_id, format, obfuscation_settings, channel_config, kill_date)` → returns the payload binary + implant public key + any YARA warnings
    - `ListFormats()` → returns available output formats
    - `GetBuildStatus(build_id)` → for async builds, check status

- [ ] Write tests for the payload builder:
  - `crates/specter-server/tests/builder_tests.rs`:
    - Test config blob generation produces valid binary with correct structure
    - Test obfuscation transforms produce unique outputs (two builds with same input produce different hashes)
    - Test string encryption key rotation changes all encrypted strings
    - Test raw shellcode format: output = obfuscated blob + encrypted config
    - Test YARA scanning with a test rule (create a rule that matches a test pattern, verify detection)
  - `crates/specter-server/tests/beacon_shim_tests.rs`:
    - Test BeaconDataParse/Extract/Int/Short roundtrip with known test data
    - Test BeaconFormatAlloc/Append/ToString produces correct output
    - Test symbol resolution table contains all expected Beacon API symbols
  - Run `cargo test --workspace`
