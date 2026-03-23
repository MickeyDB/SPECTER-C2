# Phase 06: Malleable C2 Profiles

This phase implements the malleable C2 profile system — YAML-defined application impersonation profiles controlling every observable aspect of the implant's network behavior: TLS fingerprint (JA3 targeting), HTTP transaction shaping (header ordering, URI rotation, body encoding), timing model (jitter distribution, working hours, burst windows), and payload transform chain (compress → encrypt → encode). The teamserver compiles YAML profiles into binary config for implant embedding. The first production profile (Slack webhook impersonation) is created. By the end, the implant's network traffic is shaped to be indistinguishable from the impersonated application under deep packet inspection.

## Context

The profile system has two parts: (1) teamserver-side YAML parser/compiler turning profiles into binary config and driving listener response formatting, and (2) implant-side profile interpretation shaping outgoing requests and parsing incoming responses. The comms engine from Phase 03 is refactored to be fully profile-driven rather than hardcoded HTTP formatting.

Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`
Implant source: `C:\Users\localuser\Documents\SPECTER-C2\implant\`

## Tasks

- [x] Define the YAML profile schema and parser in the teamserver:
  - Create `crates/specter-server/src/profile/` directory with `schema.rs` and `parser.rs`
  - Schema structs (all serde-deserializable from YAML):
    - `Profile` (top-level), `TlsConfig` (cipher_suites, extensions, curves, alpn, target_ja3), `HttpConfig` (request/response templates, uri_rotation, header_ordering, cookie_config)
    - `HttpTemplate` (method, uri_pattern, headers as ordered Vec<HeaderEntry>, body_template, data_embed_points), `HeaderEntry` (name, value with template variables like `{{data}}`, `1774058062781`, `{{random_hex(8)}}`)
    - `EmbedPoint` (location enum: JsonField/CookieValue/UriSegment/QueryParam/MultipartField/HeaderValue, field_name, encoding)
    - `TimingConfig` (callback_interval, jitter_distribution enum: Gaussian/Pareto/Uniform/Empirical, jitter_percent, working_hours, burst_windows, initial_delay)
    - `TransformChain` (compress: LZ4/Zstd/None, encrypt: always ChaCha20-Poly1305, encode: Base64/Base85/Hex/Raw/CustomAlphabet)
  - `parse_profile(yaml_str) -> Result<Profile>`, `validate_profile(profile) -> Result<Vec<Warning>>`
  - Add `serde_yaml` dependency

- [x] Implement profile compiler and transform chain:
  - Create `crates/specter-server/src/profile/compiler.rs`:
    - `compile_profile(profile) -> Result<Vec<u8>>` — TLV binary encoding (field_id + 2B length + value)
    - `compile_listener_config(profile) -> ListenerProfile` — response-side config for teamserver listener
  - Create `crates/specter-server/src/profile/transform.rs`:
    - `transform_encode(data, chain) -> Vec<u8>` — compress → encrypt → encode
    - `transform_decode(data, chain) -> Result<Vec<u8>>` — decode → decrypt → decompress
    - Add `lz4_flex` crate for compression
    - Encoding implementations: base64, base85, hex, custom alphabet
  - Create `profiles/` directory at project root for YAML profile files

- [x] Create the Slack webhook and generic HTTPS profiles:
  - `profiles/slack-webhook.yaml`:
    - TLS: Chrome 120+ cipher suites, ALPN h2/http1.1, target JA3 matching Chrome
    - HTTP request: POST, URI rotation (/api/chat.postMessage, /api/conversations.history, etc.), Slack-style headers (Authorization Bearer xoxb-{random}, User-Agent Slackbot 1.0), JSON body with data in `text` field (base64-encoded)
    - HTTP response: 200 JSON `{"ok": true, "message": {"text": "{{data}}"}}`; 2% error responses returning no tasking
    - Timing: 30s interval, 25% Gaussian jitter, working hours 08-18 Mon-Fri, 4x off-hours multiplier, 120s initial delay
    - Transform: LZ4 → ChaCha20-Poly1305 → Base64
  - `profiles/generic-https.yaml`:
    - Plain HTTPS POST to `/api/v1/data`, standard Chrome TLS, JSON body, 60s interval, 20% uniform jitter

- [x] Implement profile-driven request/response shaping in the implant:
  - Create `implant/core/src/profile.c` and `implant/core/include/profile.h`:
    - `PROFILE_CONFIG` structure parsed from binary profile blob
    - `profile_init(ctx)`, `profile_get_uri(cfg)` (rotation modes), `profile_build_headers(cfg, output, max_len)`, `profile_embed_data(cfg, data, len, body_out, max_len)`, `profile_extract_data(cfg, body, len, data_out, data_len_out)`
  - Create `implant/core/src/transform.c`:
    - `transform_send(plaintext, len, session_key, cfg, output, output_len)` — compress → encrypt → encode
    - `transform_recv(encoded, len, session_key, cfg, output, output_len)` — decode → decrypt → decompress
    - Inline base64 encoder/decoder, inline minimal LZ4 compressor/decompressor
  - Refactor `comms_checkin()` to use profile-driven construction: build payload → transform_send → profile_embed_data → profile_build_headers → profile_get_uri → send → parse → profile_extract_data → transform_recv → extract tasks
  - Update sleep jitter to use profile timing model: Box-Muller for Gaussian, inverse CDF for Pareto, working hours check with off-hours multiplier

- [x] Update teamserver listener and write tests:
  - Make HTTP listener profile-aware: validate incoming requests against profile format, extract embedded data, apply reverse transform, format responses per profile template, serve decoy for non-matching traffic
  - Add profiles table in SQLite, gRPC RPCs: CreateProfile, ListProfiles, GetProfile, CompileProfile
  - `crates/specter-server/tests/profile_tests.rs`:
    - Test YAML parsing for both profiles
    - Test validation catches invalid configurations
    - Test compilation produces valid binary blob
    - Test transform encode/decode roundtrip
    - Test request matching and response formatting
  - Run `cargo test --workspace`
