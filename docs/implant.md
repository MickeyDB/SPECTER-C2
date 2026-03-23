# Implant Documentation

The SPECTER implant is a C11 position-independent code (PIC) blob targeting Windows x86-64. It is CRT-free, has zero static imports, and compiles as a single PIC blob.

**Final core size (all channels + evasion + modules):** 247,232 bytes (~241 KB). The full-featured build includes HTTPS, DNS, SMB named pipe, WebSocket, and Azure dead drop channels, plus the complete evasion engine (anti-analysis, ETW/AMSI patching, stack spoofing, memory guard, hook detection), Module Bus with COFF/BOF loader, and Ed25519/ChaCha20-Poly1305 crypto suite.

## Building

```bash
cd implant
make          # Build → implant/build/specter.bin
make clean    # Clean build artifacts
make size     # Print final PIC blob size
```

**Toolchain:** MinGW-w64 (`x86_64-w64-mingw32-gcc`), GNU ld, objcopy.

**Compilation flags:** `-fPIC -nostdlib -nostdinc -ffreestanding -masm=intel -Os`

The build uses a custom linker script (`scripts/`) to produce a flat binary. The `.text` section is extracted via `objcopy` to produce the final `specter.bin` PIC blob.

## Architecture

```
┌─────────────────────────────────────────┐
│              Entry Point                │
│  (config decryption, init, main loop)   │
├─────────────┬───────────────────────────┤
│ Config      │ Crypto Engine             │
│ (encrypted  │ (ChaCha20-Poly1305,       │
│  blob)      │  X25519, Ed25519, SHA256) │
├─────────────┼───────────────────────────┤
│ Comms Engine│ Profile Engine            │
│ (HTTP, DNS, │ (request/response         │
│  SMB, WS)   │  templating, transforms) │
├─────────────┼───────────────────────────┤
│ Sleep Engine│ Module Bus                │
│ (Ekko, WFS, │ (COFF loader, Beacon API │
│  Foliage…)  │  compatibility)          │
├─────────────┼───────────────────────────┤
│ Syscall     │ PEB Walker                │
│ Engine      │ (module/export            │
│ (direct     │  resolution via           │
│  syscalls)  │  DJB2 hashes)            │
└─────────────┴───────────────────────────┘
```

## Source Layout

```
implant/core/
├── include/
│   ├── specter.h      # Master header with Windows type definitions
│   ├── beacon.h       # Cobalt Strike Beacon API compatibility
│   ├── bus.h          # Module bus interface
│   ├── comms.h        # Communications engine
│   ├── config.h       # Configuration structures
│   ├── crypto.h       # Cryptography functions
│   ├── evasion.h      # Evasion technique declarations
│   ├── ntdefs.h       # NT API definitions
│   ├── profile.h      # Profile structures
│   ├── sleep.h        # Sleep method declarations
│   ├── syscalls.h     # Syscall interface
│   └── transform.h    # Data transformation
├── src/
│   ├── entry.c        # Entry point, init, main loop
│   ├── config.c       # Config decryption and loading
│   ├── crypto.c       # Crypto implementations
│   ├── comms.c        # Multi-channel communications
│   ├── profile.c      # Profile template parsing
│   ├── sleep.c        # Sleep obfuscation methods
│   ├── syscalls.c     # Direct syscall stubs
│   ├── peb.c          # PEB walking and API resolution
│   ├── string.c       # CRT-free string/memory ops (spec_str*, spec_mem*)
│   └── bus/           # Module bus and Beacon API shim
└── asm/               # Assembly stubs (GAS/Intel syntax)
```

### Modules

```
implant/modules/
├── collect/           # Information gathering
├── exfil/             # Data exfiltration
├── inject/            # Process injection
├── lateral/           # Lateral movement
├── socks5/            # SOCKS5 proxy
├── token/             # Token manipulation
└── template/          # Template for new modules
```

Each module compiles to a separate `.bin` COFF blob that can be loaded dynamically.

## Configuration

The config blob is appended after the PIC binary and encrypted with ChaCha20-Poly1305 (key derived from PIC content hash).

**Magic:** `0x53504543` ("SPEC")

**Config fields:**
| Field | Description |
|-------|-------------|
| Server X25519 public key | Teamserver's public key for key exchange |
| Implant X25519 key pair | Implant's ephemeral keys |
| Module Ed25519 signing key | For verifying module signatures |
| Sleep interval | Base sleep time between check-ins |
| Jitter | Random variance applied to sleep interval |
| Sleep method | Which sleep obfuscation to use |
| Channel configs | HTTP, DNS, SMB, WebSocket endpoints |
| Kill date | FILETIME after which implant self-terminates |
| Profile ID | Which C2 profile to use for traffic shaping |
| Check-in counter | Monotonic counter for replay protection |

## Communication Channels

| Channel | Transport | Notes |
|---------|-----------|-------|
| HTTP/HTTPS | WinHTTP via SChannel | Primary channel, TLS for encryption |
| DNS | DNS TXT/CNAME records | Low-bandwidth fallback |
| SMB | Named pipes | Internal network lateral movement |
| WebSocket | WS/WSS | Bi-directional, supports domain fronting |

**Failover:** If the primary channel fails, the implant automatically rotates through backup channels.

### Wire Protocol

```
[4 bytes LE length][24-byte header][ciphertext][16-byte auth tag]
                    ├─ 12 bytes: implant pubkey prefix
                    └─ 12 bytes: nonce
```

All payloads are LZ4-compressed then ChaCha20-Poly1305 encrypted before transmission.

## Check-in Protocol

**Implant → Server:**
```json
{
  "session_id": "optional (empty on first check-in)",
  "hostname": "DESKTOP-ABC123",
  "username": "DOMAIN\\user",
  "pid": 1234,
  "os_version": "Windows 10 22H2",
  "integrity_level": "High",
  "process_name": "explorer.exe",
  "internal_ip": "10.0.0.5",
  "external_ip": "203.0.113.42",
  "task_results": [
    {"task_id": "uuid", "status": "COMPLETE", "result": "output"}
  ]
}
```

**Server → Implant:**
```json
{
  "session_id": "assigned-uuid",
  "tasks": [
    {"task_id": "uuid", "task_type": "shell", "arguments": "whoami"}
  ]
}
```

## Cryptography

All crypto is implemented natively (no external libraries).

| Algorithm | Purpose |
|-----------|---------|
| X25519 | Ephemeral key exchange for session setup |
| ChaCha20-Poly1305 | AEAD encryption of all check-in traffic |
| Ed25519 | Module signature verification |
| SHA-256 | Hashing, HMAC |
| DJB2 | Fast hash for API name resolution |

## Sleep Obfuscation

| Method | Description |
|--------|-------------|
| Ekko | In-place memory encryption during sleep using timer callbacks |
| WaitForSingleObject | Standard NT API sleep |
| NtDelayExecution | Direct syscall sleep |
| Foliage | APC-based sleep with memory encryption |
| ThreadPool | Thread pool timer hijacking |

During sleep, the implant's memory is encrypted to evade memory scanners.

## Evasion Techniques

| Technique | Purpose |
|-----------|---------|
| PEB walking | Resolve DLLs and exports without `GetProcAddress` |
| DJB2 hash lookup | API resolution by hash, not string |
| Direct syscalls | Bypass user-mode API hooks |
| Sleep encryption | Encrypt implant memory during sleep |
| Profile templating | Shape traffic to mimic legitimate requests |
| Domain fronting | Decouple TLS SNI from HTTP Host header |
| Kill date | Automatic self-termination after engagement ends |
| No static imports | Zero entries in IAT |
| CRT-free | No C runtime dependency |

## Module System

Modules are COFF object files loaded dynamically via the module bus.

**Beacon API compatibility:** The implant provides a shim layer implementing Cobalt Strike's Beacon API, enabling BOF (Beacon Object File) compatibility:

| Function | Purpose |
|----------|---------|
| `BeaconOutput` | Send output string to operator |
| `BeaconPrintf` | Formatted output to operator |
| `BeaconDataParse` | Parse argument buffer |
| `BeaconDataInt` | Extract integer from arguments |
| `BeaconDataExtract` | Extract byte buffer from arguments |
| `BeaconFormatAlloc` | Allocate output format buffer |
| `BeaconFormatAppend` | Append data to output buffer |
| `BeaconFormatInt` | Append integer to output buffer |

**Module lifecycle:**
1. Server sends `LoadModule` task with module name
2. Implant downloads COFF blob
3. Ed25519 signature verified
4. COFF loaded and relocated in memory
5. Module entry point called with Beacon API context
6. Output collected and returned to operator
7. Module memory freed
