# Phase 03: Implant Crypto, Comms & Sleep Controller

This phase implements the three remaining implant core subsystems: the crypto layer (ChaCha20-Poly1305, X25519, HKDF-SHA256, compile-time string encryption), the communications engine (custom HTTP/1.1 over raw sockets via SChannel TLS, profile-driven request/response formatting, check-in loop), and the sleep controller (Ekko timer-based sleep with full memory encryption, permission rotation, and jitter). It also implements the config store — the encrypted blob that holds all implant configuration. By the end of this phase, the implant can initialize, read its config, establish a TLS connection to the teamserver's HTTP listener, perform check-ins to send/receive tasks, and sleep with encrypted memory between callbacks.

## Context

All network and memory operations use the syscall engine from Phase 02. No Windows API is called directly. The crypto primitives are implemented inline (no external libraries). The comms engine uses SChannel (schannel.dll) for TLS — resolved dynamically via PEB walk. HTTP is built manually over raw sockets (no WinHTTP/WinINet). The sleep controller's Ekko method uses CreateTimerQueueTimer to set up an ROP chain that encrypts memory, sleeps, then decrypts.

Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`
Teamserver source: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`

## Tasks

- [ ] Implement the crypto layer in `implant/core/src/crypto.c` and `implant/core/include/crypto.h`:
  - ChaCha20 stream cipher — inline implementation:
    - Quarter-round function, column/diagonal rounds
    - `spec_chacha20_block(state, output)` — generates one 64-byte keystream block
    - `spec_chacha20_encrypt(key, nonce, counter, plaintext, len, ciphertext)` — XOR keystream with data
  - Poly1305 MAC — inline implementation:
    - `spec_poly1305_auth(tag_out, msg, msg_len, key)` — compute 16-byte authentication tag
    - 130-bit arithmetic using 64-bit limbs
  - ChaCha20-Poly1305 AEAD:
    - `spec_aead_encrypt(key, nonce, plaintext, pt_len, aad, aad_len, ciphertext, tag)` — encrypt + authenticate
    - `spec_aead_decrypt(key, nonce, ciphertext, ct_len, aad, aad_len, plaintext, tag)` — verify tag + decrypt, return success/failure
    - Nonce: 12 bytes. Key: 32 bytes. Tag: 16 bytes.
  - X25519 Diffie-Hellman key agreement:
    - Field arithmetic over curve25519 (modular add, sub, mul, square, invert)
    - `spec_x25519_scalarmult(shared_out, private_key, public_key)` — scalar multiplication
    - `spec_x25519_generate_keypair(private_out, public_out)` — generate ephemeral keypair (private = random 32 bytes, clamp, compute public)
    - Entropy source: resolve BCryptGenRandom from bcrypt.dll via PEB walk
  - HKDF-SHA256 key derivation:
    - SHA256 hash — inline implementation (full SHA-256 with padding, 64-byte blocks)
    - HMAC-SHA256 using SHA256
    - `spec_hkdf_extract(salt, salt_len, ikm, ikm_len, prk_out)` — extract step
    - `spec_hkdf_expand(prk, info, info_len, okm, okm_len)` — expand step
    - `spec_hkdf_derive(shared_secret, context, context_len, key_out, key_len)` — convenience: extract + expand
  - Compile-time string encryption:
    - Create `implant/scripts/encrypt_strings.py` — build-time tool that:
      - Scans source files for `ENCRYPTED_STRING("...")` macros
      - Generates a random 32-byte XOR key per build
      - Produces `implant/core/src/encrypted_strings.c` with encrypted byte arrays and the XOR key
    - Inline decryption function `spec_decrypt_string(encrypted, len, output)` — XOR decrypt to stack buffer, caller zeroes after use
    - Alternative: implement as C macros with `__attribute__((constructor))` equivalent for PIC

- [ ] Implement the config store in `implant/core/src/config.c` and `implant/core/include/config.h`:
  - Define `IMPLANT_CONFIG` structure:
    - `BYTE teamserver_pubkey[32]` — X25519 public key for key agreement
    - `BYTE implant_privkey[32]` — implant's X25519 private key (generated at build)
    - `BYTE implant_pubkey[32]` — implant's X25519 public key
    - `BYTE module_signing_key[32]` — Ed25519 public key for module verification
    - `DWORD sleep_interval` — base sleep interval in milliseconds
    - `DWORD jitter_percent` — jitter percentage (0-100)
    - `DWORD sleep_method` — enum: SLEEP_EKKO=0, SLEEP_FOLIAGE=1, SLEEP_THREADPOOL=2
    - `CHANNEL_CONFIG channels[4]` — array of channel configurations (URL, port, priority, type)
    - `DWORD channel_count` — number of configured channels
    - `DWORD max_retries` — consecutive failures before channel rotation
    - `UINT64 kill_date` — UTC timestamp, self-destruct after this time
    - `BYTE profile_id[16]` — identifier for the malleable profile
    - `DWORD checkin_count` — number of successful check-ins (for nonce generation)
  - `CHANNEL_CONFIG` structure:
    - `BYTE url[256]` — server URL/hostname
    - `WORD port` — server port
    - `BYTE type` — HTTP=0, DNS=1, SMB=2, WEBSOCKET=3
    - `BYTE priority` — lower = higher priority
    - `BYTE active` — currently active flag
  - `cfg_init(IMPLANT_CONTEXT* ctx)` — locate config blob at end of PIC, decrypt with embedded key, parse into IMPLANT_CONFIG structure, store pointer in ctx
  - `cfg_get(IMPLANT_CONTEXT* ctx)` — return pointer to decrypted config
  - `cfg_update(IMPLANT_CONTEXT* ctx, BYTE* update_data, DWORD len)` — apply a config update from teamserver (new channels, sleep params, etc.), verify signature before applying
  - `cfg_encrypt(IMPLANT_CONTEXT* ctx)` — re-encrypt config in memory (called before sleep)
  - `cfg_decrypt(IMPLANT_CONTEXT* ctx)` — decrypt config in memory (called on wake)
  - `cfg_check_killdate(IMPLANT_CONTEXT* ctx)` — check if kill date has passed, return TRUE if implant should self-destruct

- [ ] Implement the communications engine in `implant/core/src/comms.c` and `implant/core/include/comms.h`:
  - Define `COMMS_CONTEXT` structure:
    - Active channel index, socket handle, TLS context handle
    - Session key (32 bytes, derived from X25519 handshake)
    - Message sequence number (for nonce generation and replay protection)
    - Send/receive buffers
    - Connection state enum: DISCONNECTED, CONNECTING, CONNECTED, ERROR
  - Implement raw socket operations (via syscall engine):
    - Resolve ws2_32.dll functions via PEB walk: WSAStartup, socket, connect, send, recv, closesocket, getaddrinfo, freeaddrinfo
    - `comms_tcp_connect(host, port)` → creates TCP socket, resolves hostname, connects
    - `comms_tcp_send(socket, data, len)` → sends data
    - `comms_tcp_recv(socket, buffer, max_len)` → receives data
    - `comms_tcp_close(socket)` → closes socket
  - Implement TLS via SChannel:
    - Resolve secur32.dll/sspicli.dll functions: AcquireCredentialsHandleA, InitializeSecurityContextA, EncryptMessage, DecryptMessage, DeleteSecurityContext, FreeCredentialsHandle
    - `comms_tls_init(COMMS_CONTEXT* ctx)` → acquire TLS credentials handle
    - `comms_tls_handshake(COMMS_CONTEXT* ctx, socket, hostname)` → perform TLS handshake, return security context
    - `comms_tls_send(ctx, data, len)` → encrypt and send via TLS
    - `comms_tls_recv(ctx, buffer, max_len)` → receive and decrypt via TLS
    - `comms_tls_close(ctx)` → close TLS session
  - Implement HTTP/1.1 request/response construction:
    - `comms_http_build_request(method, uri, host, headers, body, body_len, output, output_len)` — manually construct HTTP request with proper header ordering
    - `comms_http_parse_response(data, data_len, status_code_out, headers_out, body_out, body_len_out)` — parse HTTP response, extract status code, headers, and body
    - Header construction is manual (no library): "POST /path HTTP/1.1\r\nHost: ...\r\nContent-Length: ...\r\n..."
  - Implement the check-in protocol:
    - `comms_checkin(IMPLANT_CONTEXT* ctx)` — the main check-in function:
      1. Build check-in payload: session metadata (hostname, user, PID, OS) + task results from last cycle
      2. Encrypt payload with session key (ChaCha20-Poly1305, counter-based nonce)
      3. Encode encrypted payload (base64 for now, profile-driven in Phase 06)
      4. Build HTTP POST request with encoded payload in body
      5. Send request over TLS connection
      6. Parse HTTP response
      7. Decode and decrypt response body
      8. Extract pending tasks from decrypted response
      9. Return list of tasks to execute
    - `comms_init(IMPLANT_CONTEXT* ctx)` — initialize comms:
      1. Read channel config from config store
      2. Generate ephemeral X25519 keypair
      3. Derive session key: HKDF(X25519(implant_priv, server_pub), "specter-session-v1")
      4. Connect to primary channel (TCP + TLS)
      5. Perform initial registration check-in
    - `comms_rotate_channel(IMPLANT_CONTEXT* ctx)` — switch to next priority channel on failure

- [ ] Implement the sleep controller in `implant/core/src/sleep.c` and `implant/core/include/sleep.h`:
  - Define `SLEEP_CONTEXT` structure:
    - Sleep method (from config)
    - Implant memory base address and size (for encryption)
    - Heap allocation tracking list (linked list of {ptr, size} entries)
    - Sleep encryption key (regenerated each cycle)
    - Timer queue handle (for Ekko)
    - Original memory protection flags
  - Implement heap tracking:
    - `sleep_track_alloc(SLEEP_CONTEXT* ctx, PVOID ptr, SIZE_T size)` — add to tracking list
    - `sleep_untrack_alloc(SLEEP_CONTEXT* ctx, PVOID ptr)` — remove from tracking list
    - `sleep_encrypt_heap(SLEEP_CONTEXT* ctx, BYTE* key)` — encrypt all tracked allocations with ChaCha20
    - `sleep_decrypt_heap(SLEEP_CONTEXT* ctx, BYTE* key)` — decrypt all tracked allocations
  - Implement Ekko sleep method:
    - `sleep_ekko(SLEEP_CONTEXT* ctx, DWORD milliseconds)`:
      1. Generate a random encryption key for this sleep cycle (BCryptGenRandom)
      2. Resolve required functions: RtlCaptureContext, CreateTimerQueueTimer, NtContinue, VirtualProtect (all via PEB walk, not syscall engine — these are usermode)
      3. Capture current thread context (RtlCaptureContext)
      4. Set up ROP chain via CreateTimerQueueTimer callbacks:
         - Callback 1: NtProtectVirtualMemory(implant_base, RW) — make implant writable
         - Callback 2: SystemFunction032(encrypt implant memory with key) — encrypt
         - Callback 3: NtDelayExecution(sleep_duration) — actual sleep
         - Callback 4: SystemFunction032(decrypt implant memory with key) — decrypt
         - Callback 5: NtProtectVirtualMemory(implant_base, RX) — restore execute permission
         - Callback 6: NtContinue(captured_context) — resume execution
      5. Also encrypt tracked heap allocations before sleep
      6. Fire the timer chain
      7. On resume: decrypt heap allocations, verify memory integrity
    - Note: SystemFunction032 is resolved from advapi32.dll via PEB walk — it provides RC4 encryption which can be used for the ROP chain memory encryption (the session key-based ChaCha20 encryption of heap is separate)
  - Implement jitter calculation:
    - `sleep_calc_jitter(base_interval, jitter_percent)` — for Phase 03, use uniform random jitter. Gaussian/Pareto distributions added in Phase 06 with malleable profiles.
    - Returns: base_interval ± (jitter_percent% * base_interval * random_factor)
  - `sleep_init(IMPLANT_CONTEXT* ctx)` — initialize sleep controller from config
  - `sleep_cycle(IMPLANT_CONTEXT* ctx)` — perform one sleep cycle: calculate jittered interval → execute selected sleep method

- [ ] Wire up the implant main loop and integrate with teamserver HTTP listener:
  - Update `implant/core/src/entry.c` — replace placeholder initialization with real subsystem init:
    1. `cfg_init(ctx)` — decrypt and parse config
    2. `cfg_check_killdate(ctx)` — exit if expired
    3. `sc_init(&ctx->syscall_table)` — initialize syscall engine (already done in Phase 02)
    4. `sleep_init(ctx)` — initialize sleep controller
    5. `comms_init(ctx)` — initialize comms, perform key exchange, register with teamserver
    6. Main loop (`while(ctx->running)`):
       - `comms_checkin(ctx)` — send heartbeat, receive tasks
       - Process received tasks (for now: log them, placeholder for module execution in Phase 05)
       - `cfg_check_killdate(ctx)` — check kill date each cycle
       - `sleep_cycle(ctx)` — sleep with memory encryption
    7. On exit: zero-fill all memory, free allocations, terminate thread
  - Update teamserver HTTP listener (`crates/specter-server/src/listener/`) to support the binary check-in protocol:
    - Add a `/api/beacon` endpoint that accepts the encrypted binary protocol (in addition to the existing JSON `/api/checkin` endpoint used by mock-implant)
    - Request body: 4-byte length || 24-byte nonce || ciphertext || 16-byte tag
    - Teamserver decrypts with the session key (X25519 key agreement with the implant's public key sent during registration)
    - Response: encrypted task list in the same binary format
    - Store implant public keys in the sessions table
  - Create `implant/scripts/build_config.py` — config blob generator:
    - Takes parameters: teamserver URL, port, sleep interval, jitter, kill date
    - Generates X25519 keypair for the implant
    - Takes teamserver's public key as input
    - Serializes the IMPLANT_CONFIG structure to binary
    - Encrypts the config blob with a per-build key
    - Appends the encrypted config to the end of the PIC blob (specter.bin)
    - Outputs the implant's public key (to register with teamserver)
  - Verify `make` produces a complete PIC blob with all subsystems compiled in
  - Run `make size` to confirm the blob stays under 20KB
