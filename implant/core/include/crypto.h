/**
 * SPECTER Implant — Crypto Layer Interface
 *
 * Inline implementations of ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD,
 * X25519 Diffie-Hellman, SHA-256, HMAC-SHA256, HKDF-SHA256, and
 * compile-time string decryption.  No external crypto libraries.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define CHACHA20_KEY_SIZE    32
#define CHACHA20_NONCE_SIZE  12
#define CHACHA20_BLOCK_SIZE  64

#define POLY1305_KEY_SIZE    32
#define POLY1305_TAG_SIZE    16

#define AEAD_KEY_SIZE        32
#define AEAD_NONCE_SIZE      12
#define AEAD_TAG_SIZE        16

#define X25519_KEY_SIZE      32

#define SHA256_BLOCK_SIZE    64
#define SHA256_DIGEST_SIZE   32

#define HKDF_SHA256_HASH_LEN 32

#define SHA512_BLOCK_SIZE    128
#define SHA512_DIGEST_SIZE   64

#define ED25519_PUBKEY_SIZE    32
#define ED25519_SIGNATURE_SIZE 64

/* ------------------------------------------------------------------ */
/*  Shared field element type — GF(2^255-19), 5 × 51-bit limbs        */
/* ------------------------------------------------------------------ */

typedef QWORD fe25519[5];

/* ------------------------------------------------------------------ */
/*  SHA-256 context                                                    */
/* ------------------------------------------------------------------ */

typedef struct _SHA256_CTX {
    DWORD state[8];
    QWORD  bitcount;
    BYTE   buffer[SHA256_BLOCK_SIZE];
    DWORD  buf_len;
} SHA256_CTX;

/* ------------------------------------------------------------------ */
/*  ChaCha20                                                           */
/* ------------------------------------------------------------------ */

/**
 * Generate one 64-byte keystream block from a ChaCha20 state.
 * state: 16 x DWORD input state (key, counter, nonce setup)
 * output: 64-byte output buffer
 */
void spec_chacha20_block(const DWORD state[16], BYTE output[64]);

/**
 * ChaCha20 stream cipher encryption/decryption (XOR with keystream).
 * key: 32 bytes, nonce: 12 bytes, counter: initial block counter.
 */
void spec_chacha20_encrypt(const BYTE key[32], const BYTE nonce[12],
                           DWORD counter, const BYTE *plaintext,
                           DWORD len, BYTE *ciphertext);

/* ------------------------------------------------------------------ */
/*  Poly1305 MAC                                                       */
/* ------------------------------------------------------------------ */

/**
 * Compute a 16-byte Poly1305 tag over a message.
 * key: 32 bytes (one-time key, typically derived from ChaCha20).
 */
void spec_poly1305_auth(BYTE tag_out[16], const BYTE *msg, DWORD msg_len,
                        const BYTE key[32]);

/* ------------------------------------------------------------------ */
/*  ChaCha20-Poly1305 AEAD                                             */
/* ------------------------------------------------------------------ */

/**
 * Encrypt and authenticate.
 * key: 32 bytes, nonce: 12 bytes.
 * ciphertext buffer must be at least pt_len bytes.
 * tag: 16-byte output.
 */
void spec_aead_encrypt(const BYTE key[32], const BYTE nonce[12],
                       const BYTE *plaintext, DWORD pt_len,
                       const BYTE *aad, DWORD aad_len,
                       BYTE *ciphertext, BYTE tag[16]);

/**
 * Verify tag and decrypt.
 * Returns TRUE on success (tag valid), FALSE on failure.
 * plaintext buffer must be at least ct_len bytes.
 */
BOOL spec_aead_decrypt(const BYTE key[32], const BYTE nonce[12],
                       const BYTE *ciphertext, DWORD ct_len,
                       const BYTE *aad, DWORD aad_len,
                       BYTE *plaintext, const BYTE tag[16]);

/* ------------------------------------------------------------------ */
/*  X25519 Diffie-Hellman                                              */
/* ------------------------------------------------------------------ */

/**
 * Scalar multiplication on Curve25519.
 * shared_out: 32-byte shared secret.
 * private_key: 32-byte scalar (clamped).
 * public_key: 32-byte point (u-coordinate).
 */
void spec_x25519_scalarmult(BYTE shared_out[32],
                            const BYTE private_key[32],
                            const BYTE public_key[32]);

/**
 * Generate an ephemeral X25519 keypair.
 * Entropy from BCryptGenRandom (bcrypt.dll resolved via PEB walk).
 * Returns TRUE on success, FALSE on failure.
 */
BOOL spec_x25519_generate_keypair(BYTE private_out[32],
                                  BYTE public_out[32]);

/* ------------------------------------------------------------------ */
/*  SHA-256                                                            */
/* ------------------------------------------------------------------ */

void spec_sha256_init(SHA256_CTX *ctx);
void spec_sha256_update(SHA256_CTX *ctx, const BYTE *data, DWORD len);
void spec_sha256_final(SHA256_CTX *ctx, BYTE digest[32]);

/** Convenience: hash a single buffer. */
void spec_sha256(const BYTE *data, DWORD len, BYTE digest[32]);

/* ------------------------------------------------------------------ */
/*  HMAC-SHA256                                                        */
/* ------------------------------------------------------------------ */

void spec_hmac_sha256(const BYTE *key, DWORD key_len,
                      const BYTE *data, DWORD data_len,
                      BYTE mac[32]);

/* ------------------------------------------------------------------ */
/*  HKDF-SHA256                                                        */
/* ------------------------------------------------------------------ */

void spec_hkdf_extract(const BYTE *salt, DWORD salt_len,
                       const BYTE *ikm, DWORD ikm_len,
                       BYTE prk[32]);

void spec_hkdf_expand(const BYTE prk[32],
                      const BYTE *info, DWORD info_len,
                      BYTE *okm, DWORD okm_len);

/** Convenience: extract + expand in one call. */
void spec_hkdf_derive(const BYTE *salt, DWORD salt_len,
                      const BYTE *ikm, DWORD ikm_len,
                      const BYTE *info, DWORD info_len,
                      BYTE *okm, DWORD okm_len);

/* ------------------------------------------------------------------ */
/*  SHA-512                                                            */
/* ------------------------------------------------------------------ */

typedef struct _SHA512_CTX {
    QWORD  state[8];
    QWORD  bitcount;
    BYTE   buffer[SHA512_BLOCK_SIZE];
    DWORD  buf_len;
} SHA512_CTX;

void spec_sha512_init(SHA512_CTX *ctx);
void spec_sha512_update(SHA512_CTX *ctx, const BYTE *data, DWORD len);
void spec_sha512_final(SHA512_CTX *ctx, BYTE digest[64]);
void spec_sha512(const BYTE *data, DWORD len, BYTE digest[64]);

/* ------------------------------------------------------------------ */
/*  Ed25519 Signature Verification                                     */
/* ------------------------------------------------------------------ */

/**
 * Verify an Ed25519 signature over a message.
 * public_key: 32-byte compressed public key.
 * signature:  64-byte signature (R || S).
 * Returns TRUE if valid, FALSE otherwise.
 */
BOOL spec_ed25519_verify(const BYTE public_key[32],
                         const BYTE *message, DWORD message_len,
                         const BYTE signature[64]);

/* ------------------------------------------------------------------ */
/*  Field element operations (shared between X25519 and Ed25519)       */
/* ------------------------------------------------------------------ */

void fe_0(fe25519 h);
void fe_1(fe25519 h);
void fe_copy(fe25519 h, const fe25519 f);
void fe_frombytes(fe25519 h, const BYTE s[32]);
void fe_tobytes(BYTE s[32], const fe25519 h);
void fe_add(fe25519 h, const fe25519 f, const fe25519 g);
void fe_sub(fe25519 h, const fe25519 f, const fe25519 g);
void fe_mul(fe25519 h, const fe25519 f, const fe25519 g);
void fe_sq(fe25519 h, const fe25519 f);
void fe_invert(fe25519 out, const fe25519 z);

/* ------------------------------------------------------------------ */
/*  Compile-time string decryption                                     */
/* ------------------------------------------------------------------ */

/**
 * Decrypt a string encrypted by encrypt_strings.py (XOR-based).
 * encrypted: input bytes, len: byte count, output: decrypted buffer.
 */
void spec_decrypt_string(const BYTE *encrypted, DWORD len, BYTE *output);

/* ------------------------------------------------------------------ */
/*  DJB2 hash for bcrypt.dll resolution                                */
/* ------------------------------------------------------------------ */

#define HASH_BCRYPT_DLL      0x730076C3  /* "bcrypt.dll" */
#define HASH_BCRYPTGENRANDOM 0xE59BE6B4  /* "BCryptGenRandom" */

#endif /* CRYPTO_H */
