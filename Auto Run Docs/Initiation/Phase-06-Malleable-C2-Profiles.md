# Phase 06: Malleable C2 Profiles

This phase implements the malleable C2 profile system — YAML-defined application impersonation profiles that control every observable aspect of the implant's network behavior. A profile defines TLS fingerprint (JA3 targeting), HTTP transaction shaping (header ordering, URI rotation, body encoding), timing model (jitter distribution, working hours, burst windows), and the payload transform chain (compress → encrypt → encode → embed → shape). The teamserver compiles YAML profiles into binary config blobs for implant embedding. The first production profile (Slack webhook impersonation) is created. By the end of this phase, the implant's network traffic is shaped by a profile to be indistinguishable from the impersonated application under deep packet inspection.

## Context

The malleable profile system has two parts: (1) a teamserver-side YAML parser/compiler that turns profiles into binary config and drives the listener's response formatting, and (2) implant-side profile interpretation that shapes outgoing requests and parses incoming responses according to the profile's templates. The comms engine from Phase 03 is refactored to be fully profile-driven rather than using hardcoded HTTP formatting.

Teamserver source: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`
Implant source: `/Users/mdebaets/Documents/SPECTER/implant/`

## Tasks

- [ ] Define the YAML profile schema and create the profile parser in the teamserver:
  - Create `crates/specter-server/src/profile/` directory
  - Create `crates/specter-server/src/profile/schema.rs` — Rust structs for the full profile schema (all serde-deserializable from YAML):
    - `Profile`: top-level struct with name, description, version, and sub-sections
    - `TlsConfig`: cipher_suites (ordered Vec<String>), extensions (ordered Vec<String>), curves (Vec<String>), alpn (Vec<String>), target_ja3 (String)
    - `HttpConfig`: request_template (HttpTemplate), response_template (HttpTemplate), uri_rotation (Vec<String> + rotation_mode enum: Sequential, Random, Weighted), header_ordering (Vec<String>), cookie_config (CookieConfig)
    - `HttpTemplate`: method (String), uri_pattern (String), headers (Vec<HeaderEntry> preserving order), body_template (String), data_embed_points (Vec<EmbedPoint>)
    - `HeaderEntry`: name (String), value (String, supports template variables like `{{data}}`, `{{timestamp}}`, `{{random_hex(8)}}`)
    - `EmbedPoint`: location enum (JsonField, CookieValue, UriSegment, QueryParam, MultipartField, HeaderValue), field_name (String), encoding (Encoding enum)
    - `CookieConfig`: names (Vec<String>), value_format enum (Base64, Hex, JwtLike), rotation_policy enum (PerRequest, PerSession, Fixed)
    - `TimingConfig`: callback_interval_secs (u32), jitter_distribution enum (Gaussian, Pareto, Uniform, Empirical), jitter_percent (u8), working_hours (WorkingHours), burst_windows (Vec<BurstWindow>), initial_delay_secs (u32)
    - `WorkingHours`: start_hour (u8), end_hour (u8), days (Vec<DayOfWeek>), off_hours_multiplier (f32)
    - `BurstWindow`: start_hour (u8), end_hour (u8), interval_secs (u32) — high-frequency window
    - `TransformChain`: compress (CompressMethod enum: LZ4, Zstd, None), encrypt (always ChaCha20Poly1305 — not configurable), encode (EncodeMethod enum: Base64, Base85, Hex, Raw, CustomAlphabet), custom_alphabet (Option<String>)
  - Create `crates/specter-server/src/profile/parser.rs`:
    - `parse_profile(yaml_str: &str) -> Result<Profile>` — parse YAML into Profile struct
    - `validate_profile(profile: &Profile) -> Result<Vec<Warning>>` — validate constraints (cipher suite names valid, JA3 hash plausible, timing values sane, etc.)
    - Add `serde_yaml` dependency to specter-server

- [ ] Implement the profile compiler (YAML → binary config blob):
  - Create `crates/specter-server/src/profile/compiler.rs`:
    - `compile_profile(profile: &Profile) -> Result<Vec<u8>>` — serialize profile to a compact binary format for implant embedding:
      - Binary format: field_id (1 byte) + length (2 bytes) + value (variable) — TLV encoding
      - Encodes: URI list, header templates, body templates, embed points, timing parameters, transform chain config
      - Compact representation: strings are length-prefixed, enums are single bytes
      - Output blob is included in the implant config store (Phase 03)
    - `compile_listener_config(profile: &Profile) -> ListenerProfile` — extract the response-side config for the teamserver's HTTP listener:
      - Response template (how to format responses to match the profile)
      - Expected request format (for validation/filtering)
      - Decoy responses (for non-matching traffic)
  - Create `crates/specter-server/src/profile/transform.rs` — server-side transform chain:
    - `transform_encode(data: &[u8], chain: &TransformChain) -> Vec<u8>` — apply the transform chain (compress → encrypt → encode)
    - `transform_decode(data: &[u8], chain: &TransformChain) -> Result<Vec<u8>>` — reverse the chain (decode → decrypt → decompress)
    - LZ4 compression: add `lz4_flex` crate dependency
    - Encoding implementations: base64, base85, hex, custom alphabet
  - Integrate profile compilation into the payload builder flow (for now, store compiled profiles alongside listener configs)
  - Create `profiles/` directory at project root for YAML profile files

- [ ] Create the Slack webhook impersonation profile:
  - Create `profiles/slack-webhook.yaml` — full production profile:
    - **TLS**: cipher suites matching Chrome 120+ on Windows, extensions in Chrome order, target JA3 matching Chrome, ALPN: h2, http/1.1
    - **HTTP request template**:
      - Method: POST
      - URI rotation: `/api/chat.postMessage`, `/api/conversations.history`, `/api/users.list`, `/api/files.upload` (weighted toward postMessage)
      - Headers in Slack API client order: Host, Authorization (Bearer xoxb-{random}), Content-Type (application/json), User-Agent (Slackbot 1.0 (+https://api.slack.com/robots)), Accept (*/*), Accept-Encoding (gzip, deflate, br), Connection (keep-alive)
      - Body: JSON format `{"channel": "C{random_hex(8)}", "text": "{{data}}", "ts": "{{timestamp}}"}`
      - Data embed point: base64-encoded in the `text` JSON field
    - **HTTP response template**:
      - Status 200, Content-Type: application/json
      - Body: `{"ok": true, "channel": "C{...}", "ts": "...", "message": {"text": "{{data}}"}}`
      - Error responses at 2% probability: `{"ok": false, "error": "channel_not_found"}` (returns no tasking)
    - **Timing**: callback interval 30s, Gaussian jitter 25%, working hours 08:00-18:00 Mon-Fri, off-hours multiplier 4x, initial delay 120s
    - **Transform chain**: compress LZ4, encrypt ChaCha20-Poly1305, encode Base64
  - Create a second profile `profiles/generic-https.yaml` — simple fallback profile:
    - Plain HTTPS POST to `/api/v1/data` with JSON body
    - Standard Chrome TLS fingerprint
    - 60s interval, 20% uniform jitter
    - Useful for development and testing

- [ ] Implement profile-driven request/response shaping in the implant comms engine:
  - Create `implant/core/src/profile.c` and `implant/core/include/profile.h`:
    - `PROFILE_CONFIG` structure — parsed from binary profile blob in config store:
      - URI list (array of string pointers), rotation index, rotation mode
      - Header template (array of {name, value_template} pairs), header count
      - Body template string with embed point markers
      - Embed point configuration (where and how to insert data)
      - Timing parameters (interval, jitter percent, jitter type)
      - Transform chain parameters (compress method, encode method)
    - `profile_init(IMPLANT_CONTEXT* ctx)` → parse binary profile blob from config store into PROFILE_CONFIG
    - `profile_get_uri(PROFILE_CONFIG* cfg)` → return next URI based on rotation mode (sequential: increment index; random: pick random; weighted: weighted random)
    - `profile_build_headers(PROFILE_CONFIG* cfg, char* output, int max_len)` → generate HTTP headers from template, substituting variables ({{timestamp}}, {{random_hex(N)}}, etc.)
    - `profile_embed_data(PROFILE_CONFIG* cfg, BYTE* data, DWORD data_len, char* body_out, int max_len)` → encode data and embed into body template at the configured embed point
    - `profile_extract_data(PROFILE_CONFIG* cfg, char* body, int body_len, BYTE* data_out, DWORD* data_len_out)` → extract and decode data from response body based on embed point configuration
  - Implement the implant-side transform chain in `implant/core/src/transform.c`:
    - `transform_send(BYTE* plaintext, DWORD len, BYTE* session_key, TransformConfig* cfg, BYTE* output, DWORD* output_len)`:
      1. Compress (LZ4 inline implementation — LZ4 is simple enough for a PIC implementation)
      2. Encrypt (ChaCha20-Poly1305 with session key)
      3. Encode (base64/hex/custom alphabet)
    - `transform_recv(BYTE* encoded, DWORD len, BYTE* session_key, TransformConfig* cfg, BYTE* output, DWORD* output_len)`:
      1. Decode
      2. Decrypt + verify
      3. Decompress
    - Inline base64 encoder/decoder (no library)
    - Inline LZ4 compressor/decompressor (minimal implementation)
  - Refactor `comms_checkin()` in `implant/core/src/comms.c`:
    - Replace hardcoded HTTP formatting with profile-driven construction:
      1. Build check-in payload (metadata + results)
      2. Apply transform chain: `transform_send()`
      3. Embed transformed data into profile body: `profile_embed_data()`
      4. Build HTTP request with profile headers: `profile_build_headers()`
      5. Use profile URI: `profile_get_uri()`
      6. Send request, receive response
      7. Extract data from response: `profile_extract_data()`
      8. Apply reverse transform: `transform_recv()`
      9. Parse tasks from decrypted response
  - Update jitter calculation in sleep controller to use profile timing model:
    - Gaussian jitter: Box-Muller transform to generate normal distribution
    - Pareto jitter: inverse CDF sampling
    - Working hours: check current time against profile's working hours, apply off-hours multiplier

- [ ] Update the teamserver HTTP listener to use profile-driven response formatting:
  - Update `crates/specter-server/src/listener/` to be profile-aware:
    - Load the compiled listener profile config for the active profile
    - When a check-in arrives:
      1. Validate the request matches the profile's expected format (URI pattern, header presence, body structure)
      2. Extract embedded data from the request body using the profile's embed point config
      3. Apply reverse transform chain (decode → decrypt → decompress) using `transform_decode()`
      4. Process the decrypted check-in data (update session, process task results)
      5. Prepare response tasks
      6. Apply forward transform chain (compress → encrypt → encode)
      7. Embed transformed data into the profile's response body template
      8. Return response with profile-defined headers, status code, and body
    - For non-matching traffic (doesn't match profile format):
      - Return a configured decoy response (404 page, redirect to legitimate website, or clone of the impersonated app's real response)
      - Configurable via the profile's `decoy_response` field
  - Store profiles in the teamserver database:
    - Add `profiles` table: id, name, yaml_content, compiled_blob, compiled_listener_config, created_at, updated_at
    - Add gRPC RPCs: CreateProfile, ListProfiles, GetProfile, CompileProfile
    - When a listener starts, it loads its associated profile's compiled listener config

- [ ] Write tests for the profile system:
  - `crates/specter-server/tests/profile_tests.rs`:
    - Test YAML parsing of the Slack webhook profile
    - Test YAML parsing of the generic HTTPS profile
    - Test profile validation catches invalid configurations (bad cipher suites, invalid timing values)
    - Test profile compilation produces a valid binary blob
    - Test transform chain encode/decode roundtrip (data survives compress → encrypt → encode → decode → decrypt → decompress)
    - Test server-side request matching (valid Slack-format request accepted, random request rejected)
    - Test response formatting matches profile template
  - Run `cargo test --workspace` to verify all tests pass
