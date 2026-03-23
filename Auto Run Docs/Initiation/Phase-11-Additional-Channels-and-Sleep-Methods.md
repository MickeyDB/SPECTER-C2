# Phase 11: Additional Channels & Sleep Methods

This phase extends the implant's communications and sleep capabilities beyond the initial HTTPS/Ekko implementation. It adds three new comms channels — DNS/DoH (for environments where only DNS traffic is allowed), SMB named pipes (for internal pivoting between compromised hosts), and WebSockets (for low-latency interactive sessions) — plus two additional sleep methods: Foliage (APC-based sleep with memory encryption) and ThreadPool (hijacking the process's native thread pool timers for maximum stealth). It also implements the channel failover logic that automatically rotates between channels when the primary becomes unavailable. By the end of this phase, the implant has full multi-channel capability with automatic failover, and three sleep obfuscation strategies that can be selected per profile.

## Context

The comms engine from Phase 03 defines a channel abstraction: `connect()`, `send()`, `recv()`, `disconnect()`, `health_check()`. Each new channel implements this interface. The sleep controller from Phase 03 has a `sleep_method` config field that selects the strategy. All new channels and sleep methods operate through the evasion engine (Phase 04) — no direct syscalls.

Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`

## Tasks

- [ ] Implement the DNS/DoH communications channel:
  - Create `implant/core/src/comms/dns.c` and `implant/core/include/comms_dns.h`:
    - **DNS resolver** (for classic DNS channel):
      - Build raw DNS query packets manually (no resolver library)
      - Support record types: A, AAAA, TXT, CNAME, NULL
      - Randomized transaction IDs, realistic TTL handling
      - Send queries via UDP socket (port 53) using raw socket operations through the bus/evasion engine
    - **Data encoding in DNS**:
      - Outbound (implant → teamserver): encode data in subdomain labels of DNS queries
        - Format: `<encoded_chunk>.<sequence>.<session_id>.c2domain.com`
        - Each label max 63 bytes, total query max 253 bytes
        - Encoding: base32 (DNS-safe alphabet, case-insensitive)
        - Chunk data across multiple queries if needed
      - Inbound (teamserver → implant): data encoded in TXT or NULL record responses
        - TXT records: base64-encoded data in TXT RDATA
        - NULL records: raw binary data (for larger payloads)
      - Data fragmentation: split large payloads across multiple DNS transactions with sequence numbers for reassembly
    - **DoH (DNS over HTTPS) channel**:
      - Construct DNS wire-format queries
      - Send via HTTPS POST to a DoH resolver endpoint (configurable: Cloudflare 1.1.1.1, Google 8.8.8.8, custom)
      - Content-Type: application/dns-message
      - Parse DNS wire-format responses
      - Uses the existing TLS/HTTP comms infrastructure from Phase 03
      - Advantage: encrypted DNS traffic is harder to inspect than plain DNS
    - Channel interface implementation:
      - `dns_connect(config)` → initialize DNS channel with configured domain and resolver
      - `dns_send(data, len)` → encode and send data via DNS queries
      - `dns_recv(buf, max_len)` → poll for DNS responses, decode data
      - `dns_disconnect()` → cleanup
      - `dns_health_check()` → send a simple A query for the C2 domain, check for valid response

- [ ] Implement the SMB named pipe communications channel:
  - Create `implant/core/src/comms/smb.c` and `implant/core/include/comms_smb.h`:
    - **Named pipe client** for internal pivoting:
      - Pipe names are profile-defined (e.g., `\\.\pipe\MSSE-1234-server`, mimicking Microsoft security agent pipes)
      - Connect via NtCreateFile on `\\<server>\pipe\<pipename>` (using evasion_syscall)
      - No SMB library dependency — uses NT API directly
    - **SMB channel as a relay**:
      - An implant with HTTPS access acts as the relay node
      - Internal implants (no internet access) connect to the relay via named pipe
      - Relay implant forwards pipe traffic through its HTTPS channel to the teamserver
      - Data format on pipe: length-prefixed encrypted messages (same ChaCha20-Poly1305 format as HTTPS)
    - **Peer linking**:
      - When an operator links two sessions via SMB, the teamserver records the relationship
      - Parent session (with HTTPS) receives child session's traffic in its check-in
      - Teamserver multiplexes/demultiplexes traffic for both sessions
    - Channel interface:
      - `smb_connect(pipe_name, server)` → open named pipe connection
      - `smb_send(data, len)` → write to pipe
      - `smb_recv(buf, max_len)` → read from pipe
      - `smb_disconnect()` → close pipe handle
      - `smb_health_check()` → attempt a small read/write to verify pipe is alive
    - Server mode (for relay implants):
      - `smb_listen(pipe_name)` → create named pipe server (NtCreateNamedPipeFile via evasion_syscall)
      - `smb_accept()` → wait for client connection
      - Handle multiple concurrent pipe connections

- [ ] Implement the WebSocket communications channel:
  - Create `implant/core/src/comms/websocket.c` and `implant/core/include/comms_ws.h`:
    - **WebSocket client** (WS/WSS) for persistent bidirectional channels:
      - HTTP Upgrade handshake: construct proper `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13` headers
      - Verify server's `Sec-WebSocket-Accept` response (SHA-1 hash per RFC 6455)
      - Frame construction per RFC 6455: opcode, mask bit, payload length, masking key, payload
      - Support frame types: text (0x1), binary (0x2), ping (0x9), pong (0xA), close (0x8)
      - Client frames must be masked (per RFC 6455 requirement)
      - Fragment large payloads across multiple frames
    - **WSS (WebSocket over TLS)**:
      - Uses the existing SChannel TLS infrastructure from Phase 03
      - Upgrade handshake happens after TLS is established
    - **Use case**: interactive sessions (SOCKS tunneling, shell) where HTTP polling is too slow
      - WebSocket provides persistent bidirectional channel — no polling delay
      - Falls back to HTTP polling if WebSocket connection is disrupted
    - Channel interface:
      - `ws_connect(url, headers)` → TCP connect, TLS handshake, WebSocket upgrade
      - `ws_send(data, len)` → frame and send WebSocket message
      - `ws_recv(buf, max_len)` → read and deframe WebSocket message
      - `ws_disconnect()` → send close frame, close connection
      - `ws_health_check()` → send ping, expect pong within timeout

- [ ] Implement Foliage and ThreadPool sleep methods:
  - Update `implant/core/src/sleep.c`:
    - **Foliage sleep method** — APC-based sleep with memory encryption:
      - `sleep_foliage(SLEEP_CONTEXT* ctx, DWORD milliseconds)`:
        1. Generate per-cycle encryption key (BCryptGenRandom)
        2. Capture current context (RtlCaptureContext)
        3. Call `memguard_encrypt()` to encrypt implant memory
        4. Queue APC chain via NtQueueApcThread to the current thread:
          - APC 1: NtProtectVirtualMemory(RW) on implant pages
          - APC 2: encrypt memory (SystemFunction032 or custom)
          - APC 3: NtDelayExecution(sleep_duration)
          - APC 4: decrypt memory
          - APC 5: NtProtectVirtualMemory(RX) — restore execute permission
          - APC 6: NtContinue(captured_context) — resume
        5. Enter alertable wait via NtTestAlert to fire the APC chain
        6. On resume: `memguard_decrypt()` to decrypt memory
      - Difference from Ekko: uses APC queue instead of timer callbacks — different detection surface
    - **ThreadPool sleep method** — hijacking process thread pool timers:
      - `sleep_threadpool(SLEEP_CONTEXT* ctx, DWORD milliseconds)`:
        1. Resolve TpAllocTimer, TpSetTimer, TpReleaseTimer from ntdll via bus->resolve
        2. Create a thread pool timer (TpAllocTimer) with a callback function
        3. The callback function performs the encrypt→sleep→decrypt cycle
        4. Set the timer (TpSetTimer) with the desired sleep interval
        5. The timer object belongs to the process's existing thread pool — not to the implant
        6. The callback executes in a legitimate thread pool worker thread
        7. EDR sees a normal thread pool callback, not a suspicious timer from an implant
      - This is the hardest to detect because:
        - Timer object is owned by the process's native thread pool
        - Callback thread is a legitimate pool worker
        - No CreateTimerQueueTimer or standalone timer objects
    - Update sleep method selection:
      - `sleep_cycle()` reads `config->sleep_method` and dispatches to `sleep_ekko()`, `sleep_foliage()`, or `sleep_threadpool()`
      - Default in config: SLEEP_EKKO (simplest, well-tested)

- [ ] Implement channel failover and multi-channel management:
  - Update `implant/core/src/comms.c` — channel failover logic:
    - `CHANNEL_STATE` struct per channel: connection state, consecutive failures, last attempt, backoff delay
    - `comms_health_check(COMMS_CONTEXT* ctx)` → call active channel's health_check:
      - On success: reset failure counter
      - On failure: increment failure counter
    - `comms_failover(COMMS_CONTEXT* ctx)` — automatic channel rotation:
      - Triggered when consecutive failures >= `config->max_retries` (default 3)
      - Disconnect current channel
      - Sort remaining channels by priority
      - Attempt to connect to next priority channel
      - If next channel also fails: continue to the next, with increasing backoff
      - If all channels exhausted: enter deep sleep mode (10x normal interval), retry round-robin
    - `comms_retry_failed(COMMS_CONTEXT* ctx)` — periodically retry failed channels:
      - Failed channels are retried on an exponential backoff schedule (1min, 5min, 15min, 1hr, 4hr, max 12hr)
      - On successful retry: if the retried channel has higher priority than the current active, switch back to it
    - Channel selection in check-in loop:
      1. `comms_health_check()` — verify current channel
      2. If unhealthy: `comms_failover()` — switch channel
      3. `comms_checkin()` — perform check-in on active channel
      4. If check-in fails: mark failure, retry next cycle
      5. Periodically: `comms_retry_failed()` — try to recover preferred channels
  - Update teamserver to handle multi-channel sessions:
    - Sessions can have multiple configured channels (stored in session config)
    - Teamserver listener must support all channel types:
      - HTTP/HTTPS listener (existing from Phase 01/03)
      - DNS listener: add DNS server capability to teamserver (UDP socket on port 53, responds to queries for configured C2 domains)
      - WebSocket endpoint: add WebSocket upgrade support to the HTTP listener
      - SMB: no teamserver listener needed (relay handled by parent implant)
    - Create `crates/specter-server/src/listener/dns_listener.rs`:
      - Bind UDP socket on configurable port (default 53)
      - Parse incoming DNS queries
      - Extract session data from subdomain labels
      - Respond with TXT/NULL records containing task data
      - Zone file for C2 domain with NS delegation

- [ ] Write tests for new channels and sleep methods:
  - `crates/specter-server/tests/dns_listener_tests.rs`:
    - Test DNS query parsing and response construction
    - Test data encoding/decoding roundtrip via DNS
    - Test fragmentation and reassembly of large payloads
  - `implant/tests/test_channels.c`:
    - Test DNS data encoding in subdomain labels
    - Test WebSocket frame construction and parsing
    - Test channel state machine transitions (connected → failed → failover → recovered)
  - `implant/tests/test_sleep.c`:
    - Test jitter calculation produces values within expected range
    - Test sleep method selection dispatches correctly
  - Run all tests: `cargo test --workspace` and `make -C implant test`
