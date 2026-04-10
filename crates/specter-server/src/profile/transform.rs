use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use super::schema::*;
use crate::profile::ProfileError;

/// Apply the transform chain: compress → encrypt → encode.
///
/// `key` must be exactly 32 bytes (ChaCha20-Poly1305 key).
pub fn transform_encode(
    data: &[u8],
    chain: &TransformChain,
    key: &[u8; 32],
) -> Result<Vec<u8>, ProfileError> {
    // Step 1: Compress
    let compressed = compress(data, &chain.compress)?;

    // Step 2: Encrypt (ChaCha20-Poly1305)
    let encrypted = encrypt(&compressed, key)?;

    // Step 3: Encode
    let encoded = encode(&encrypted, &chain.encode);

    Ok(encoded)
}

/// Reverse the transform chain: decode → decrypt → decompress.
///
/// `key` must be exactly 32 bytes (ChaCha20-Poly1305 key).
pub fn transform_decode(
    data: &[u8],
    chain: &TransformChain,
    key: &[u8; 32],
) -> Result<Vec<u8>, ProfileError> {
    // Step 1: Decode
    let decoded = decode(data, &chain.encode)?;

    // Step 2: Decrypt
    let decrypted = decrypt(&decoded, key)?;

    // Step 3: Decompress
    let decompressed = decompress(&decrypted, &chain.compress)?;

    Ok(decompressed)
}

// ── Compression ────────────────────────────────────────────────────────────────

fn compress(data: &[u8], algo: &Compression) -> Result<Vec<u8>, ProfileError> {
    match algo {
        Compression::None => Ok(data.to_vec()),
        Compression::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
        Compression::Zstd => Err(ProfileError::Validation(
            "Zstd compression not available. Use 'lz4' or 'none'.".into(),
        ))
    }
}

fn decompress(data: &[u8], algo: &Compression) -> Result<Vec<u8>, ProfileError> {
    match algo {
        Compression::None => Ok(data.to_vec()),
        Compression::Lz4 => lz4_flex::decompress_size_prepended(data)
            .map_err(|e| ProfileError::Validation(format!("LZ4 decompression failed: {e}"))),
        Compression::Zstd => Err(ProfileError::Validation(
            "Zstd compression not available. Use 'lz4' or 'none'.".into(),
        )),
    }
}

// ── Encryption (ChaCha20-Poly1305) ─────────────────────────────────────────────

/// Encrypt with ChaCha20-Poly1305. Output: [nonce: 12 bytes][ciphertext + tag].
fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ProfileError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| ProfileError::Validation(format!("encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt ChaCha20-Poly1305. Input: [nonce: 12 bytes][ciphertext + tag].
fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ProfileError> {
    if data.len() < 12 {
        return Err(ProfileError::Validation(
            "encrypted data too short (missing nonce)".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| ProfileError::Validation(format!("decryption failed: {e}")))
}

// ── Encoding ───────────────────────────────────────────────────────────────────

fn encode(data: &[u8], encoding: &Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Base64 => BASE64.encode(data).into_bytes(),
        Encoding::Base85 => base85_encode(data),
        Encoding::Hex => hex::encode(data).into_bytes(),
        Encoding::Raw => data.to_vec(),
        Encoding::CustomAlphabet => {
            // Fall back to base64 for custom alphabet until a custom table is provided
            BASE64.encode(data).into_bytes()
        }
    }
}

fn decode(data: &[u8], encoding: &Encoding) -> Result<Vec<u8>, ProfileError> {
    match encoding {
        Encoding::Base64 => {
            let s = std::str::from_utf8(data)
                .map_err(|e| ProfileError::Validation(format!("invalid UTF-8 in base64: {e}")))?;
            BASE64
                .decode(s)
                .map_err(|e| ProfileError::Validation(format!("base64 decode failed: {e}")))
        }
        Encoding::Base85 => base85_decode(data),
        Encoding::Hex => {
            let s = std::str::from_utf8(data)
                .map_err(|e| ProfileError::Validation(format!("invalid UTF-8 in hex: {e}")))?;
            hex::decode(s).map_err(|e| ProfileError::Validation(format!("hex decode failed: {e}")))
        }
        Encoding::Raw => Ok(data.to_vec()),
        Encoding::CustomAlphabet => {
            let s = std::str::from_utf8(data)
                .map_err(|e| ProfileError::Validation(format!("invalid UTF-8: {e}")))?;
            BASE64
                .decode(s)
                .map_err(|e| ProfileError::Validation(format!("base64 decode failed: {e}")))
        }
    }
}

// ── Base85 (RFC 1924 / z85-style) ──────────────────────────────────────────────

const BASE85_CHARS: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

fn base85_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 5 / 4 + 5);

    for chunk in data.chunks(4) {
        // Pad partial chunks with 0x00 on the right to form a full u32
        let mut padded = [0u8; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        let val = u32::from_be_bytes(padded);

        let enc_len = chunk.len() + 1; // N bytes → N+1 base85 chars

        let mut encoded = [0u8; 5];
        let mut v = val;
        for i in (0..5).rev() {
            encoded[i] = BASE85_CHARS[(v % 85) as usize];
            v /= 85;
        }
        out.extend_from_slice(&encoded[..enc_len]);
    }
    out
}

fn base85_decode(data: &[u8]) -> Result<Vec<u8>, ProfileError> {
    // Build reverse lookup
    let mut rev = [0xFFu8; 256];
    for (i, &c) in BASE85_CHARS.iter().enumerate() {
        rev[c as usize] = i as u8;
    }

    let mut out = Vec::with_capacity(data.len() * 4 / 5 + 4);

    for chunk in data.chunks(5) {
        // For partial blocks, pad with the highest base85 value (84) to 5 chars
        let mut padded = [84u8; 5]; // 84 = highest index
        for (i, &b) in chunk.iter().enumerate() {
            let idx = rev[b as usize];
            if idx == 0xFF {
                return Err(ProfileError::Validation(format!(
                    "invalid base85 character: 0x{b:02x}"
                )));
            }
            padded[i] = idx;
        }

        let mut val: u32 = 0;
        for &idx in &padded {
            val = val * 85 + idx as u32;
        }

        let dec_len = match chunk.len() {
            5 => 4,
            4 => 3,
            3 => 2,
            2 => 1,
            _ => 0,
        };

        let bytes = val.to_be_bytes();
        out.extend_from_slice(&bytes[..dec_len]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn test_roundtrip_none_base64() {
        let chain = TransformChain {
            compress: Compression::None,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Base64,
        };
        let key = test_key();
        let plaintext = b"Hello, SPECTER C2!";

        let encoded = transform_encode(plaintext, &chain, &key).unwrap();
        let decoded = transform_decode(&encoded, &chain, &key).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_roundtrip_lz4_hex() {
        let chain = TransformChain {
            compress: Compression::Lz4,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Hex,
        };
        let key = test_key();
        let plaintext = b"Repeated data for compression. Repeated data for compression.";

        let encoded = transform_encode(plaintext, &chain, &key).unwrap();
        let decoded = transform_decode(&encoded, &chain, &key).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_roundtrip_none_raw() {
        let chain = TransformChain {
            compress: Compression::None,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Raw,
        };
        let key = test_key();
        let plaintext = b"raw binary payload\x00\x01\x02";

        let encoded = transform_encode(plaintext, &chain, &key).unwrap();
        let decoded = transform_decode(&encoded, &chain, &key).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_roundtrip_lz4_base85() {
        let chain = TransformChain {
            compress: Compression::Lz4,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Base85,
        };
        let key = test_key();
        let plaintext = b"Base85 roundtrip test data for the transform chain";

        let encoded = transform_encode(plaintext, &chain, &key).unwrap();
        let decoded = transform_decode(&encoded, &chain, &key).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let chain = TransformChain {
            compress: Compression::None,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Base64,
        };
        let key = test_key();
        let mut wrong_key = test_key();
        wrong_key[0] = 0xFF;

        let encoded = transform_encode(b"secret", &chain, &key).unwrap();
        let result = transform_decode(&encoded, &chain, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_zstd_returns_error() {
        let chain = TransformChain {
            compress: Compression::Zstd,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Base64,
        };
        let key = test_key();
        let result = transform_encode(b"data", &chain, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Zstd"));
    }

    #[test]
    fn test_base85_roundtrip() {
        let data = b"test data 12345";
        let encoded = base85_encode(data);
        let decoded = base85_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let chain = TransformChain {
            compress: Compression::None,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Base64,
        };
        let key = test_key();
        let encoded = transform_encode(b"", &chain, &key).unwrap();
        let decoded = transform_decode(&encoded, &chain, &key).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_large_payload_roundtrip() {
        let chain = TransformChain {
            compress: Compression::Lz4,
            encrypt: Encryption::ChaCha20Poly1305,
            encode: Encoding::Base64,
        };
        let key = test_key();
        // 64KB of pattern data
        let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let encoded = transform_encode(&plaintext, &chain, &key).unwrap();
        let decoded = transform_decode(&encoded, &chain, &key).unwrap();
        assert_eq!(decoded, plaintext);
    }
}
