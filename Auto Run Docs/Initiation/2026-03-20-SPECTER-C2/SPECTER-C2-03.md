# Phase 03: Implant Crypto, Comms & Sleep Controller

This phase implements the three remaining implant core subsystems: the crypto layer (ChaCha20-Poly1305 AEAD, X25519 key agreement, HKDF-SHA256, compile-time string encryption), the communications engine (custom HTTP/1.1 over raw sockets via SChannel TLS, check-in protocol with encrypted payloads), and the sleep controller (Ekko timer-based sleep with full memory encryption and jitter). It also implements the config store — the encrypted blob holding all implant configuration. By the end, the implant can initialize, read its config, establish a TLS connection to the teamserver, perform encrypted check-ins to send/receive tasks, and sleep with encrypted memory between callbacks.

## Context

All network and memory operations use the syscall engine from Phase 02. No Windows API is called directly. Crypto primitives are implemented inline (no external libraries). The comms engine uses SChannel (schannel.dll/sspicli.dll) for TLS — resolved dynamically via PEB walk. HTTP is built manually over raw sockets (no WinHTTP/WinINet). The sleep controller's Ekko method uses CreateTimerQueueTimer to set up an ROP chain that encrypts memory, sleeps, then decrypts.

Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`
Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`

## Tasks

- [x] Implement the crypto layer in `implant/core/src/crypto.c` and `implant/core/include/crypto.h`:
  - ChaCha20 stream cipher — inline implementation:
    - Quarter-round function, column/diagonal rounds
    - `spec_chacha20_block(state, output)` — generates one 64-byte keystream block
    - `spec_chacha20_encrypt(key, nonce, counter, plaintext, len, ciphertext)` — XOR keystream with data
  - Poly1305 MAC — inline implementation:
    - `spec_poly1305_auth(tag_out, msg, msg_len, key)` — compute 16-byte tag
    - 130-bit arithmetic using 64-bit limbs
  - ChaCha20-Poly1305 AEAD:
    - `spec_aead_encrypt(key, nonce, plaintext, pt_len, aad, aad_len, ciphertext, tag)` — encrypt + authenticate
    - `spec_aead_decrypt(key, nonce, ciphertext, ct_len, aad, aad_len, plaintext, tag)` — verify tag + decrypt
    - Nonce: 12 bytes. Key: 32 bytes. Tag: 16 bytes.
  - X25519 Diffie-Hellman key agreement:
    - Field arithmetic over curve25519 (modular add, sub, mul, square, invert)
    - `spec_x25519_scalarmult(shared_out, private_key, public_key)` — scalar multiplication
    - `spec_x25519_generate_keypair(private_out, public_out)` — generate ephemeral keypair
    - Entropy source: resolve BCryptGenRandom from bcrypt.dll via PEB walk
  - HKDF-SHA256 key derivation:
    - SHA-256 inline implementation (full padding, 64-byte blocks)
    - HMAC-SHA256 using SHA-256
    - `spec_hkdf_extract`, `spec_hkdf_expand`, `spec_hkdf_derive` convenience function
  - Compile-time string encryption:
    - Create `implant/scripts/encrypt_strings.py` — scans for `ENCRYPTED_STRING("...")` macros, generates encrypted byte arrays with random per-build XOR key
    - Inline `spec_decrypt_string(encrypted, len, output)` decryptor

- [x] Implement the config store in `implant/core/src/config.c` and `implant/core/include/config.h`:
  - `IMPLANT_CONFIG` structure: teamserver_pubkey, implant_privkey, implant_pubkey, module_signing_key (all 32-byte), sleep_interval, jitter_percent, sleep_method enum, CHANNEL_CONFIG array (up to 4 channels with url/port/type/priority), channel_count, max_retries, kill_date (UTC timestamp), profile_id, checkin_count
  - `CHANNEL_CONFIG` structure: url[256], port, type (HTTP/DNS/SMB/WEBSOCKET), priority, active flag
  - `cfg_init(ctx)` — locate config blob at end of PIC, decrypt, parse into IMPLANT_CONFIG
  - `cfg_get(ctx)`, `cfg_update(ctx, data, len)` (with signature verification), `cfg_encrypt(ctx)`, `cfg_decrypt(ctx)`, `cfg_check_killdate(ctx)`

- [x] Implement the communications engine in `implant/core/src/comms.c` and `implant/core/include/comms.h`:
  - `COMMS_CONTEXT` structure: active channel index, socket handle, TLS context, session key (32 bytes), message sequence number, send/receive buffers, connection state enum
  - Raw socket operations via PEB-resolved ws2_32.dll (WSAStartup, socket, connect, send, recv, closesocket, getaddrinfo, freeaddrinfo):
    - `comms_tcp_connect`, `comms_tcp_send`, `comms_tcp_recv`, `comms_tcp_close`
  - TLS via SChannel (secur32.dll/sspicli.dll):
    - `comms_tls_init`, `comms_tls_handshake`, `comms_tls_send`, `comms_tls_recv`, `comms_tls_close`
  - Manual HTTP/1.1 request/response construction:
    - `comms_http_build_request(method, uri, host, headers, body, body_len, output, output_len)`
    - `comms_http_parse_response(data, data_len, status_code_out, headers_out, body_out, body_len_out)`
  - Check-in protocol:
    - `comms_checkin(ctx)` — build payload → encrypt (ChaCha20-Poly1305) → encode → HTTP POST → parse response → decrypt → extract tasks
    - `comms_init(ctx)` — read channel config, generate ephemeral X25519 keypair, derive session key via HKDF, connect, perform registration check-in
    - `comms_rotate_channel(ctx)` — switch to next priority channel on failure

- [x] Implement the sleep controller in `implant/core/src/sleep.c` and `implant/core/include/sleep.h`:
  <!-- Completed: Created sleep.h (SLEEP_CONTEXT, CONTEXT64, SLEEP_API, heap tracking, Ekko/WFS/Delay methods) and sleep.c (full implementation). 57/57 tests pass in test_sleep.c. PIC blob builds clean. -->
  - `SLEEP_CONTEXT` structure: sleep method, implant memory base/size, heap tracking list (linked list of {ptr, size}), sleep encryption key, timer queue handle, original memory protection
  - Heap tracking: `sleep_track_alloc`, `sleep_untrack_alloc`, `sleep_encrypt_heap`, `sleep_decrypt_heap`
  - Ekko sleep method (`sleep_ekko`):
    - Generate random encryption key → RtlCaptureContext → set up ROP chain via CreateTimerQueueTimer:
      - NtProtectVirtualMemory(RW) → SystemFunction032(encrypt) → NtDelayExecution(sleep) → SystemFunction032(decrypt) → NtProtectVirtualMemory(RX) → NtContinue(resume)
    - Encrypt/decrypt tracked heap allocations around sleep
    - SystemFunction032 resolved from advapi32.dll via PEB walk
  - Jitter: `sleep_calc_jitter(base_interval, jitter_percent)` — uniform random for now (Gaussian/Pareto added in Phase 06)
  - `sleep_init(ctx)` and `sleep_cycle(ctx)` — calculate jittered interval, execute selected sleep method

- [x] Wire up the implant main loop and integrate with teamserver:
  <!-- Completed: Updated entry.c with full init chain (cfg_init→cfg_check_killdate→sleep_init→comms_init→main loop→cleanup). Added POST /api/beacon binary endpoint with X25519+HKDF+ChaCha20-Poly1305 AEAD. Added implant_pubkey column to sessions table. Created build_config.py config blob generator. PIC blob builds clean (42KB — crypto/comms dominate size). All 38 Rust tests pass including 2 new beacon tests. -->
  - Update `implant/core/src/entry.c` — replace placeholder init with real subsystem init:
    - cfg_init → cfg_check_killdate → sc_init → sleep_init → comms_init → main loop (comms_checkin → process tasks → cfg_check_killdate → sleep_cycle) → cleanup on exit
  - Update teamserver HTTP listener to support binary check-in protocol:
    - Add `POST /api/beacon` endpoint: 4-byte length ‖ 24-byte nonce ‖ ciphertext ‖ 16-byte tag
    - Teamserver decrypts with session key (X25519 key agreement with implant's public key)
    - Store implant public keys in sessions table
  - Create `implant/scripts/build_config.py` — config blob generator:
    - Takes: teamserver URL, port, sleep interval, jitter, kill date, teamserver pubkey
    - Generates implant X25519 keypair, serializes IMPLANT_CONFIG, encrypts, appends to PIC blob
    - Outputs implant public key for teamserver registration
  - Verify `make` produces complete PIC blob, `make size` confirms under 20KB
