# Phase 10: BOF Compatibility & Payload Builder

This phase implements the BOF (Beacon Object File) compatibility layer — allowing SPECTER to execute existing Cobalt Strike BOFs with full evasion coverage — and the payload builder that generates implant payloads on demand with compile-time obfuscation. The BOF layer provides a complete Beacon API shim mapping to the module bus API. The payload builder produces unique, obfuscated implant binaries in multiple output formats (raw shellcode, DLL sideload, service EXE, .NET assembly wrapper) with YARA scanning pre-delivery. By the end, operators can leverage the vast BOF ecosystem and generate unique payloads for each deployment.

## Context

BOFs are COFF object files (.o) using the Cobalt Strike Beacon API (BeaconPrintf, BeaconOutput, BeaconDataParse, etc.). SPECTER's shim maps these calls to the module bus API, so existing BOFs work without modification. BOFs can also opt-in to the extended SPECTER bus API for evasion-aware operations.

Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`
Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`

## Tasks

- [x] Implement the Cobalt Strike Beacon API compatibility shim:
  - Create `implant/core/src/bus/beacon_shim.c` and `implant/core/include/beacon.h`:
    - Define `datap` and `formatp` structs
    - Implement all Beacon API functions mapping to bus API:
      - Output: BeaconPrintf → format → bus->output, BeaconOutput → bus->output (CALLBACK_OUTPUT=0, CALLBACK_OUTPUT_OEM=0x1e, CALLBACK_ERROR=0x0d)
      - Data parser: BeaconDataParse, BeaconDataExtract, BeaconDataInt, BeaconDataShort, BeaconDataLength
      - Format buffer: BeaconFormatAlloc, BeaconFormatAppend, BeaconFormatPrintf, BeaconFormatFree, BeaconFormatToString
      - Token: BeaconUseToken → bus->token_impersonate, BeaconRevertToken → bus->token_revert
      - Utility: BeaconIsAdmin, BeaconGetSpawnTo, toWideChar
    - `BEACON_API_TABLE` — function pointer table mapping symbol names to shim implementations, used during COFF symbol resolution

- [x] Implement extended BOF API and .NET CLR hosting:
  - SPECTER extensions (opt-in `SPECTER_*` prefix): SPECTER_MemAlloc, SPECTER_Resolve, SPECTER_NetConnect, SPECTER_ProcOpen, SPECTER_FileRead — all map to bus API
  - Create `implant/core/src/bus/clr.c` — headless .NET CLR hosting:
    - Resolve mscoree.dll!CLRCreateInstance via bus->resolve → ICLRRuntimeHost2 (.NET 4.0+) → AppDomain
    - Trigger lazy AMSI bypass + CLR ETW suppression before init
    - `clr_execute_assembly(assembly_bytes, len, args)` — load from memory, invoke entry, capture stdout/stderr → bus->output, unload AppDomain
    - Run in guardian thread for crash isolation
  - Create `implant/core/src/bus/inline_asm.c` — `exec_shellcode(code, len)`: alloc RW → copy → flip RX → guardian thread → execute

- [x] Implement the payload builder in the teamserver:
  - Create `crates/specter-server/src/builder/mod.rs`:
    - `PayloadBuilder`: uses pre-compiled template blobs with binary-level transforms for speed
    - `builder_init(config)` — verify toolchain, load templates
  - Create `crates/specter-server/src/builder/config_gen.rs`:
    - `generate_config(profile, keypair, channels, sleep_config, kill_date)` → generate implant X25519 keypair, serialize IMPLANT_CONFIG, include compiled profile, encrypt per-build, return config blob + implant public key

- [x] Implement compile-time obfuscation transforms:
  - Create `crates/specter-server/src/builder/obfuscation.rs`:
    - String encryption key rotation: random 32-byte XOR key per build, re-encrypt all strings, patch decryption key
    - API hash randomization: per-build hash salt, recompute all hash constants, patch values
    - Junk code insertion: random NOP-equivalent sequences (push/pop, xchg, lea) between functions, varying size/offsets
    - Control flow flattening (optional, resource-intensive): wrap basic blocks in switch/dispatcher loop with random state numbers
    - `obfuscate(blob, settings) -> Vec<u8>`, `ObfuscationSettings` struct with per-transform toggles and density

- [x] Implement output format wrappers and YARA scanning:
  - Create `crates/specter-server/src/builder/formats.rs`:
    - Raw shellcode (.bin): PIC blob + config — `format_raw(blob, config)`
    - DLL sideloading (.dll): minimal DLL with DllMain executing PIC blob, proxy exports — `format_dll(blob, config, proxy_target)`
    - Service EXE (.exe): minimal service binary (ServiceMain) executing PIC blob — `format_service_exe(blob, config, service_name)`
    - .NET assembly wrapper: Assembly.Load from byte array — `format_dotnet(blob, config)`
    - Stagers (with OPSEC warnings): PowerShell (`format_ps1_stager`) and HTA (`format_hta_stager`)
  - Create `crates/specter-server/src/builder/yara.rs`:
    - Integrate `yara-x` crate, load rules from `rules/` directory
    - `scan_payload(blob, rules_dir) -> Vec<YaraMatch>` — scan every payload pre-delivery, return warnings
    - Create `rules/` directory with placeholder rule file
  - Add gRPC RPCs: GeneratePayload, ListFormats, GetBuildStatus

- [x] Write tests for payload builder and BOF shim:
  - `builder_tests.rs` — config generation, obfuscation uniqueness (two builds → different hashes), string encryption, raw format output, YARA scanning
  - `beacon_shim_tests.rs` — BeaconDataParse/Extract/Int/Short roundtrip, BeaconFormatAlloc/Append/ToString, symbol table completeness
  - Run `cargo test --workspace`
  - ✅ Created `crates/specter-server/tests/builder_tests.rs` (12 tests) and `crates/specter-server/tests/beacon_shim_tests.rs` (10 tests). All 22 new tests pass. Full workspace test suite passes.
