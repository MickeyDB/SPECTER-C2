# Phase 11: Additional Channels & Sleep Methods

This phase extends the implant's communications and sleep capabilities beyond HTTPS/Ekko. It adds three new comms channels — DNS/DoH (for DNS-only environments), SMB named pipes (for internal pivoting), and WebSockets (for low-latency interactive sessions) — plus two additional sleep methods: Foliage (APC-based) and ThreadPool (hijacking the process's native thread pool timers). It also implements automatic channel failover with exponential backoff. By the end, the implant has full multi-channel capability with automatic failover and three sleep obfuscation strategies selectable per profile.

## Context

The comms engine from Phase 03 defines a channel abstraction: connect(), send(), recv(), disconnect(), health_check(). Each new channel implements this interface. The sleep controller has a sleep_method config field selecting the strategy. All new channels and sleep methods operate through the evasion engine — no direct syscalls.

Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`
Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`

## Tasks

- [x] Implement the DNS/DoH communications channel:
  - Create `implant/core/src/comms/dns.c` and `implant/core/include/comms_dns.h`:
    - DNS resolver: build raw DNS query packets manually (A, AAAA, TXT, CNAME, NULL records), randomized TXIDs, send via UDP (port 53) through evasion engine
    - Data encoding: outbound in subdomain labels (`<base32_chunk>.<seq>.<session_id>.c2domain.com`, max 63B/label, 253B total), inbound in TXT/NULL record responses
    - Fragmentation/reassembly with sequence numbers for large payloads
    - DoH (DNS over HTTPS): construct DNS wire-format queries, send via HTTPS POST to configurable resolver (Cloudflare/Google/custom), Content-Type: application/dns-message, uses existing TLS infrastructure
    - Channel interface: `dns_connect`, `dns_send`, `dns_recv`, `dns_disconnect`, `dns_health_check`
  - **Completed**: Created `comms_dns.h` (header with full interface), `comms/dns.c` (implementation with base32 encoding, DNS wire format, subdomain encoding, fragmentation, DoH via existing TLS, response parsing), `tests/test_channels.c` (88 tests — all passing). Updated Makefile with `comms/` subdirectory support.

- [x] Implement the SMB named pipe communications channel:
  - Create `implant/core/src/comms/smb.c` and `implant/core/include/comms_smb.h`:
    - Named pipe client: profile-defined pipe names (e.g., `\\.\pipe\MSSE-1234-server`), connect via NtCreateFile through evasion_syscall, no SMB library
    - Relay architecture: HTTPS implant acts as relay, internal implants connect via named pipe, relay forwards through its HTTPS channel to teamserver
    - Length-prefixed encrypted messages (same ChaCha20-Poly1305 format as HTTPS)
    - Peer linking: teamserver records relationships, multiplexes/demultiplexes traffic
    - Channel interface: `smb_connect`, `smb_send`, `smb_recv`, `smb_disconnect`, `smb_health_check`
    - Server mode for relay implants: `smb_listen` (NtCreateNamedPipeFile), `smb_accept`, handle multiple concurrent pipes
  - **Completed**: Created `comms_smb.h` (header with full client/server interface, peer tracking, message format) and `comms/smb.c` (implementation with NT pipe path construction, length-prefixed ChaCha20-Poly1305 AEAD message encryption/decryption, client connect/send/recv/disconnect/health_check, server listen/accept/peer management via NtCreateNamedPipeFile/NtFsControlFile). Added NtReadFile/NtWriteFile/NtCreateNamedPipeFile/NtFsControlFile syscall hashes to syscalls.h. Added 56 SMB-specific tests to test_channels.c (pipe path construction, message build/parse, AEAD roundtrip, tamper detection, state machine, peer management, wire format). All 144 channel tests passing. Updated Makefile with smb.c in test build.

- [x] Implement the WebSocket communications channel:
  - Create `implant/core/src/comms/websocket.c` and `implant/core/include/comms_ws.h`:
    - HTTP Upgrade handshake: Upgrade/Connection/Sec-WebSocket-Key/Version headers, verify Sec-WebSocket-Accept (SHA-1 per RFC 6455)
    - Frame construction per RFC 6455: opcodes (text=0x1, binary=0x2, ping=0x9, pong=0xA, close=0x8), client masking, payload fragmentation
    - WSS via existing SChannel TLS infrastructure
    - Use case: interactive sessions (SOCKS, shell) where HTTP polling is too slow; falls back to HTTP if disrupted
    - Channel interface: `ws_connect`, `ws_send`, `ws_recv`, `ws_disconnect`, `ws_health_check`
  - **Completed**: Created `comms_ws.h` (header with full interface, WS_CONTEXT, WS_FRAME, SHA-1/Base64 types, frame opcodes, handshake functions) and `comms/websocket.c` (implementation with SHA-1 for Sec-WebSocket-Accept per RFC 3174, Base64 encode/decode, RFC 6455 frame build/parse with client masking, HTTP Upgrade request construction and 101 response validation, AEAD-encrypted binary frames, ping/pong/close control frame handling, WSS via existing SChannel TLS). Added 131 WebSocket-specific tests to test_channels.c (SHA-1 test vectors, Base64 encode/decode/roundtrip, key generation + accept computation, frame build for binary/text/ping/close/extended-16bit, frame parsing including masked frames, masking roundtrip, upgrade request validation, upgrade response validation, frame build/parse roundtrip, state transitions, overflow/null safety). All 275 channel tests passing. Updated Makefile with websocket.c in test build.

- [x] Implement Foliage and ThreadPool sleep methods:
  - Update `implant/core/src/sleep.c`:
    - Foliage (APC-based): generate key → RtlCaptureContext → memguard_encrypt → queue APC chain (NtProtectVirtualMemory RW → encrypt → NtDelayExecution → decrypt → NtProtectVirtualMemory RX → NtContinue) → NtTestAlert → memguard_decrypt
    - ThreadPool (hijacking native thread pool): TpAllocTimer/TpSetTimer/TpReleaseTimer from ntdll, callback performs encrypt→sleep→decrypt cycle, timer owned by process's native pool, callback runs in legitimate pool worker thread — hardest to detect
    - Update `sleep_cycle()` to dispatch based on config: SLEEP_EKKO, SLEEP_FOLIAGE, SLEEP_THREADPOOL
  - **Completed**: Added SLEEP_FOLIAGE (3) and SLEEP_THREADPOOL (4) to SLEEP_METHOD enum in config.h. Implemented `sleep_foliage()` (APC-based: queues NtContinue-driven APC chain via NtQueueApcThread, triggered by NtTestAlert — protect RW → RC4 encrypt → NtDelayExecution → RC4 decrypt → protect RX → SetEvent) and `sleep_threadpool()` (TpAllocTimer/TpSetTimer/TpReleaseTimer callback performs encrypt→sleep→decrypt in pool worker thread). Both integrate with memguard for heap/stack encryption and fall back to legacy RC4+heap encryption. Added NtTestAlert hash to syscalls.h, TpAllocTimer/TpSetTimer/TpReleaseTimer hashes and function pointer types to sleep.h, spec_NtTestAlert wrapper to syscall_wrappers.c. Updated sleep_cycle() dispatch and sleep_init() API resolution. Added 30 new tests (enum values, direct calls, init, cycle dispatch for all 5 methods, DJB2 hash verification). All 87 sleep tests and all 857 total tests passing.

- [x] Implement channel failover and multi-channel management:
  - Update `implant/core/src/comms.c`:
    - `CHANNEL_STATE` per channel: connection state, consecutive failures, last attempt, backoff delay
    - `comms_health_check(ctx)` — check active channel, reset/increment failure counter
    - `comms_failover(ctx)` — triggered at max_retries: disconnect → try next priority channel → if all exhausted: deep sleep mode (10x interval), round-robin retry
    - `comms_retry_failed(ctx)` — exponential backoff schedule (1min→5min→15min→1hr→4hr→12hr max), switch back to higher-priority channel on recovery
    - Integrate into check-in loop: health_check → failover if needed → checkin → retry_failed periodically
  - Update teamserver for multi-channel:
    - Create `crates/specter-server/src/listener/dns_listener.rs` — UDP DNS server (port 53), parse queries, extract data from subdomains, respond with TXT/NULL records
    - Add WebSocket upgrade support to HTTP listener
    - SMB handled by relay implants (no teamserver listener needed)
  - **Completed**: Added `CHANNEL_STATE` struct and `CHANNEL_HEALTH` enum to comms.h with per-channel tracking (connection state, consecutive failures, last attempt, backoff delay/index). Implemented `comms_health_check()` (checks active channel, resets/increments failure counter, transitions HEALTHY→DEGRADED→FAILED), `comms_failover()` (priority-ordered channel switching with backoff-aware skipping, deep sleep mode when all exhausted), `comms_retry_failed()` (exponential backoff: 1min→5min→15min→1hr→4hr→12hr max, recovers higher-priority channels). Created `dns_listener.rs` with full DNS wire format parsing (DnsHeader, DnsQuestion, name encoding/decoding), base32 encode/decode matching implant, C2 data extraction from subdomain labels, TXT/NULL/NXDOMAIN response builders, and fragment reassembly buffer. Created `ws_handler.rs` with WebSocket upgrade handler using axum's ws feature, binary frame processing with same wire format as /api/beacon, ping/pong/close handling. Added `test_failover.c` with 54 tests (backoff schedule, health check healthy/failed/max_retries/reset, failover to next channel/all exhausted/priority order/backoff skipping, retry recovery/backoff/escalation/priority filtering, enum values, null safety, deep sleep clearing). Added `dns_listener_tests.rs` with 29 tests (base32 encode/decode/roundtrip, header parse/response/too_short/roundtrip, name parsing, question parsing, C2 data extraction, name encoding, TXT/NULL/NXDOMAIN response building, reassembly buffer). All 911 implant tests and all Rust workspace tests passing.

- [x] Write tests for channels and sleep methods:
  - `crates/specter-server/tests/dns_listener_tests.rs` — DNS query parsing, response construction, encoding/decoding roundtrip, fragmentation
  - `implant/tests/test_channels.c` — DNS subdomain encoding, WebSocket framing, channel state machine transitions
  - `implant/tests/test_sleep.c` — jitter range, sleep method dispatch
  - Run `cargo test --workspace` and `make -C implant test`
  - **Completed**: All test files were already created during previous task implementations. Verified all tests pass: `cargo test --workspace` — 664 Rust tests passed (including 29 dns_listener_tests). `make -C implant test` — 911 implant tests passed across 11 binaries (275 channel tests covering DNS/SMB/WebSocket, 87 sleep tests covering jitter/dispatch/all 5 methods, 54 failover tests covering backoff/health/recovery). Zero failures across all test suites.
