use std::collections::HashSet;

use specter_server::builder::{
    format_raw, generate_config, list_formats, obfuscate, scan_payload, ChannelConfig,
    ObfuscationSettings, SleepConfig,
};
use specter_server::profile::parse_profile;

use tempfile::TempDir;
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_profile() -> specter_server::profile::schema::Profile {
    parse_profile(
        r#"
name: builder-integration-test
description: test
tls:
  cipher_suites: ["TLS_AES_128_GCM_SHA256"]
http:
  request:
    method: POST
    uri_patterns: ["/api/checkin"]
  response:
    status_code: 200
timing:
  callback_interval: 30
transform:
  compress: lz4
  encrypt: chacha20-poly1305
  encode: base64
"#,
    )
    .unwrap()
}

fn test_channels() -> Vec<ChannelConfig> {
    vec![ChannelConfig {
        kind: "https".into(),
        address: "https://c2.example.com/api/checkin".into(),
    }]
}

fn server_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let pubkey = PublicKey::from(&secret);
    (secret, pubkey)
}

fn write_rule(dir: &std::path::Path, filename: &str, content: &str) {
    std::fs::write(dir.join(filename), content).unwrap();
}

// ---------------------------------------------------------------------------
// Config generation tests
// ---------------------------------------------------------------------------

#[test]
fn config_generation_produces_non_empty_encrypted_blob() {
    let (_secret, pubkey) = server_keypair();
    let gen = generate_config(
        &test_profile(),
        &pubkey,
        &test_channels(),
        &SleepConfig::default(),
        None,
    )
    .unwrap();

    // Nonce (12 bytes) + at least some ciphertext
    assert!(gen.config_blob.len() > 12, "config blob too small");
    assert_ne!(
        gen.implant_pubkey, [0u8; 32],
        "implant pubkey should not be zero"
    );
}

#[test]
fn config_generation_decryptable_by_server() {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use sha2::{Digest, Sha256};

    let (server_secret, server_pubkey) = server_keypair();
    let gen = generate_config(
        &test_profile(),
        &server_pubkey,
        &test_channels(),
        &SleepConfig {
            interval_secs: 45,
            jitter_percent: 20,
        },
        Some(1767225600), // 2026-01-01
    )
    .unwrap();

    // Derive the same shared secret the server would
    let implant_pubkey = PublicKey::from(gen.implant_pubkey);
    let shared = server_secret.diffie_hellman(&implant_pubkey);
    let mut hasher = Sha256::new();
    hasher.update(b"SPECTER_CONFIG_KEY_V1");
    hasher.update(shared.as_bytes());
    let key: [u8; 32] = hasher.finalize().into();

    let nonce = Nonce::from_slice(&gen.config_blob[..12]);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let plaintext = cipher
        .decrypt(nonce, &gen.config_blob[12..])
        .expect("server should be able to decrypt implant config");

    // Walk TLV entries to verify structure
    let mut pos = 0;
    while pos < plaintext.len() {
        assert!(pos + 3 <= plaintext.len(), "truncated TLV at offset {pos}");
        let _fid = plaintext[pos];
        let len = u16::from_le_bytes([plaintext[pos + 1], plaintext[pos + 2]]) as usize;
        pos += 3 + len;
    }
    assert_eq!(pos, plaintext.len(), "TLV has trailing bytes");
}

// ---------------------------------------------------------------------------
// Obfuscation uniqueness tests
// ---------------------------------------------------------------------------

#[test]
fn two_builds_produce_different_hashes() {
    let (_secret, pubkey) = server_keypair();

    let gen1 = generate_config(
        &test_profile(),
        &pubkey,
        &test_channels(),
        &SleepConfig::default(),
        None,
    )
    .unwrap();

    let gen2 = generate_config(
        &test_profile(),
        &pubkey,
        &test_channels(),
        &SleepConfig::default(),
        None,
    )
    .unwrap();

    assert_ne!(gen1.config_blob, gen2.config_blob, "two builds must differ");
    assert_ne!(
        gen1.implant_pubkey, gen2.implant_pubkey,
        "keypairs must differ"
    );
}

#[test]
fn string_encryption_changes_blob() {
    // Build a blob with SPECSTR marker
    let mut blob = vec![0u8; 64];
    blob.extend_from_slice(b"SPECSTR\x00");
    let old_key = [0xAAu8; 32];
    blob.extend_from_slice(&old_key);
    blob.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
    blob.extend_from_slice(&5u16.to_le_bytes()); // len=5
    for (i, &b) in b"hello".iter().enumerate() {
        blob.push(b ^ old_key[i % 32]);
    }
    blob.extend_from_slice(&[0u8; 32]); // padding

    let settings = ObfuscationSettings {
        string_encryption: true,
        api_hash_randomization: false,
        junk_code_insertion: false,
        junk_density: 8,
        control_flow_flattening: false,
    };

    let r1 = obfuscate(&blob, &settings).unwrap();
    let r2 = obfuscate(&blob, &settings).unwrap();

    assert_ne!(
        r1, r2,
        "two string encryption runs must produce different output"
    );
    // Key region should have changed in both
    let key_start = 64 + 8; // padding + marker
    assert_ne!(&r1[key_start..key_start + 32], &old_key);
    assert_ne!(&r2[key_start..key_start + 32], &old_key);
}

#[test]
fn obfuscation_with_junk_insertion_modifies_size() {
    // Blob with int3 padding between two code sections
    let mut blob = vec![0x48u8; 64];
    blob.extend_from_slice(&[0xCC; 16]); // inter-function padding
    blob.extend_from_slice(&[0x48u8; 64]);

    let settings = ObfuscationSettings {
        string_encryption: false,
        api_hash_randomization: false,
        junk_code_insertion: true,
        junk_density: 32,
        control_flow_flattening: false,
    };

    let result = obfuscate(&blob, &settings).unwrap();

    // Junk replaces int3 runs, so no consecutive 0xCC pairs should remain
    let cc_pairs = result
        .windows(2)
        .filter(|w| w[0] == 0xCC && w[1] == 0xCC)
        .count();
    assert_eq!(cc_pairs, 0, "int3 padding should be replaced with junk");
}

// ---------------------------------------------------------------------------
// Raw format output tests
// ---------------------------------------------------------------------------

#[test]
fn raw_format_layout_is_correct() {
    let blob = vec![0x90; 128];
    let config = vec![0xDE; 64];
    let result = format_raw(&blob, &config);

    assert_eq!(result.len(), 128 + 4 + 64);
    assert_eq!(&result[..128], &blob[..]);

    let config_len = u32::from_le_bytes([result[128], result[129], result[130], result[131]]);
    assert_eq!(config_len, 64);
    assert_eq!(&result[132..], &config[..]);
}

#[test]
fn raw_format_config_roundtrip() {
    let blob = vec![0xCC; 50];
    let config = vec![0xAB; 100];
    let result = format_raw(&blob, &config);

    // Extract config back from the raw payload
    let offset = blob.len();
    let extracted_len = u32::from_le_bytes([
        result[offset],
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]) as usize;
    assert_eq!(extracted_len, config.len());
    assert_eq!(&result[offset + 4..offset + 4 + extracted_len], &config[..]);
}

// ---------------------------------------------------------------------------
// YARA scanning tests
// ---------------------------------------------------------------------------

#[test]
fn yara_scanning_detects_known_pattern() {
    let dir = TempDir::new().unwrap();
    write_rule(
        dir.path(),
        "test_detect.yar",
        r#"
rule DetectTestPayload {
    strings:
        $marker = "SPECTER_INTEGRATION_TEST_MARKER"
    condition:
        $marker
}
"#,
    );

    let mut payload = vec![0x90; 64];
    payload.extend_from_slice(b"SPECTER_INTEGRATION_TEST_MARKER");
    payload.extend_from_slice(&[0x90; 64]);

    let matches = scan_payload(&payload, dir.path()).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "DetectTestPayload");
}

#[test]
fn yara_scanning_clean_payload_returns_empty() {
    let dir = TempDir::new().unwrap();
    write_rule(
        dir.path(),
        "test_clean.yar",
        r#"
rule DetectEvil {
    strings:
        $evil = "EVIL_BYTES_NOT_PRESENT"
    condition:
        any of them
}
"#,
    );

    let payload = vec![0x90; 256];
    let matches = scan_payload(&payload, dir.path()).unwrap();
    assert!(matches.is_empty(), "clean payload should have no matches");
}

#[test]
fn yara_scanning_missing_rules_dir_returns_error() {
    let result = scan_payload(&[0x90; 64], std::path::Path::new("/nonexistent/rules"));
    assert!(result.is_err());
}

#[test]
fn yara_scanning_multiple_rules_all_match() {
    let dir = TempDir::new().unwrap();
    write_rule(
        dir.path(),
        "rule_alpha.yar",
        r#"
rule Alpha {
    strings:
        $a = "ALPHA_MARKER"
    condition:
        $a
}
"#,
    );
    write_rule(
        dir.path(),
        "rule_beta.yar",
        r#"
rule Beta {
    strings:
        $b = "BETA_MARKER"
    condition:
        $b
}
"#,
    );

    let mut payload = vec![0x00; 16];
    payload.extend_from_slice(b"ALPHA_MARKER");
    payload.extend_from_slice(b"BETA_MARKER");

    let matches = scan_payload(&payload, dir.path()).unwrap();
    let names: HashSet<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
    assert!(names.contains("Alpha"));
    assert!(names.contains("Beta"));
}

// ---------------------------------------------------------------------------
// List formats test
// ---------------------------------------------------------------------------

#[test]
fn list_formats_returns_all_expected_formats() {
    let formats = list_formats();
    let names: Vec<&str> = formats.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"raw"));
    assert!(names.contains(&"dll"));
    assert!(names.contains(&"service_exe"));
    assert!(names.contains(&"dotnet"));
    assert!(names.contains(&"ps1_stager"));
    assert!(names.contains(&"hta_stager"));

    // Stagers should have OPSEC warnings
    for f in &formats {
        if f.name.contains("stager") {
            assert!(f.opsec_warning, "{} missing opsec_warning", f.name);
        } else {
            assert!(!f.opsec_warning, "{} should not have opsec_warning", f.name);
        }
    }
}
