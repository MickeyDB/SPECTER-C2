/**
 * SPECTER Implant — Ed25519 Signature Verification & SHA-512
 *
 * Inline implementations of SHA-512 (FIPS 180-4) and Ed25519 signature
 * verification (RFC 8032).  No external crypto libraries.
 *
 * SHA-512 is required by Ed25519 for challenge hash computation.
 * Ed25519 verifies module package signatures using the teamserver's
 * embedded public key.
 */

#include "specter.h"
#include "crypto.h"

/* ================================================================== */
/*  Big-endian load/store for SHA-512                                   */
/* ================================================================== */

static QWORD load64_be(const BYTE *p) {
    return ((QWORD)p[0] << 56) | ((QWORD)p[1] << 48) |
           ((QWORD)p[2] << 40) | ((QWORD)p[3] << 32) |
           ((QWORD)p[4] << 24) | ((QWORD)p[5] << 16) |
           ((QWORD)p[6] << 8)  |  (QWORD)p[7];
}

static void store64_be(BYTE *p, QWORD v) {
    p[0] = (BYTE)(v >> 56); p[1] = (BYTE)(v >> 48);
    p[2] = (BYTE)(v >> 40); p[3] = (BYTE)(v >> 32);
    p[4] = (BYTE)(v >> 24); p[5] = (BYTE)(v >> 16);
    p[6] = (BYTE)(v >> 8);  p[7] = (BYTE)(v);
}

static QWORD rotr64(QWORD v, int n) {
    return (v >> n) | (v << (64 - n));
}

/* ================================================================== */
/*  SHA-512 (FIPS 180-4)                                               */
/* ================================================================== */

static const QWORD sha512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_transform(SHA512_CTX *ctx, const BYTE block[128]) {
    QWORD W[80];
    QWORD a, b, c, d, e, f, g, h;
    QWORD T1, T2;
    int i;

    for (i = 0; i < 16; i++)
        W[i] = load64_be(block + 8 * i);

    for (i = 16; i < 80; i++) {
        QWORD s0 = rotr64(W[i-15], 1) ^ rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
        QWORD s1 = rotr64(W[i-2], 19) ^ rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 80; i++) {
        T1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41))
             + ((e & f) ^ (~e & g)) + sha512_K[i] + W[i];
        T2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39))
             + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

void spec_sha512_init(SHA512_CTX *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bitcount = 0;
    ctx->buf_len  = 0;
}

void spec_sha512_update(SHA512_CTX *ctx, const BYTE *data, DWORD len) {
    DWORD i = 0;

    ctx->bitcount += (QWORD)len * 8;

    /* Fill partial buffer */
    if (ctx->buf_len > 0) {
        while (ctx->buf_len < SHA512_BLOCK_SIZE && i < len)
            ctx->buffer[ctx->buf_len++] = data[i++];
        if (ctx->buf_len == SHA512_BLOCK_SIZE) {
            sha512_transform(ctx, ctx->buffer);
            ctx->buf_len = 0;
        }
    }

    /* Process full blocks directly */
    while (i + SHA512_BLOCK_SIZE <= len) {
        sha512_transform(ctx, data + i);
        i += SHA512_BLOCK_SIZE;
    }

    /* Buffer remaining bytes */
    while (i < len)
        ctx->buffer[ctx->buf_len++] = data[i++];
}

void spec_sha512_final(SHA512_CTX *ctx, BYTE digest[64]) {
    DWORD i;

    /* Append padding bit */
    ctx->buffer[ctx->buf_len++] = 0x80;

    /* If not enough room for 16-byte length, flush and start new block */
    if (ctx->buf_len > 112) {
        while (ctx->buf_len < SHA512_BLOCK_SIZE)
            ctx->buffer[ctx->buf_len++] = 0;
        sha512_transform(ctx, ctx->buffer);
        ctx->buf_len = 0;
    }

    /* Zero-pad to 112 bytes */
    while (ctx->buf_len < 112)
        ctx->buffer[ctx->buf_len++] = 0;

    /* Append 128-bit message length in big-endian */
    store64_be(ctx->buffer + 112, 0);              /* High 64 bits = 0 */
    store64_be(ctx->buffer + 120, ctx->bitcount);   /* Low 64 bits      */

    sha512_transform(ctx, ctx->buffer);

    /* Write digest (big-endian) */
    for (i = 0; i < 8; i++)
        store64_be(digest + 8 * i, ctx->state[i]);

    spec_memset(ctx, 0, sizeof(SHA512_CTX));
}

void spec_sha512(const BYTE *data, DWORD len, BYTE digest[64]) {
    SHA512_CTX ctx;
    spec_sha512_init(&ctx);
    spec_sha512_update(&ctx, data, len);
    spec_sha512_final(&ctx, digest);
}

/* ================================================================== */
/*  Ed25519 Constants                                                  */
/* ================================================================== */

/* d = -121665/121666 mod p, little-endian (RFC 8032) */
static const BYTE ed25519_d_bytes[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
    0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
    0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

/* sqrt(-1) mod p, little-endian = 2^((p-1)/4) mod p */
static const BYTE ed25519_sqrtm1_bytes[32] = {
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
    0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
    0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
};

/* Ed25519 basepoint (compressed y with sign bit), little-endian */
static const BYTE ed25519_basepoint[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

/* Group order L = 2^252 + 27742317777372353535851937790883648493 */
static const BYTE ed25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* ================================================================== */
/*  Field Element Extensions (beyond what crypto.c exports)            */
/* ================================================================== */

/* Negate: h = -f mod p */
static void fe_neg(fe25519 h, const fe25519 f) {
    fe25519 zero;
    fe_0(zero);
    fe_sub(h, zero, f);
}

/* Is f negative (odd)?  Returns 0 or 1. */
static int fe_isneg(const fe25519 f) {
    BYTE s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

/* Is f == 0?  Returns 0 or 1. */
static int fe_iszero(const fe25519 f) {
    BYTE s[32];
    BYTE d = 0;
    int i;
    fe_tobytes(s, f);
    for (i = 0; i < 32; i++) d |= s[i];
    return d == 0;
}

/*
 * Compute z^(2^252 - 3) — used for modular square root in point
 * decompression.  Same addition chain as fe_invert but ends 2 squarings
 * earlier and multiplies by z instead of z^11.
 */
static void fe_pow22523(fe25519 out, const fe25519 z) {
    fe25519 t0, t1, t2;
    int i;

    fe_sq(t0, z);                                   /* z^2             */
    fe_sq(t1, t0);
    fe_sq(t1, t1);                                   /* z^8             */
    fe_mul(t1, z, t1);                               /* z^9             */
    fe_mul(t0, t0, t1);                              /* z^11            */
    fe_sq(t0, t0);                                   /* z^22            */
    fe_mul(t0, t1, t0);                              /* z^31 = 2^5-1    */
    fe_sq(t1, t0);
    for (i = 1; i < 5; i++) fe_sq(t1, t1);          /* z^(31*2^5)      */
    fe_mul(t0, t1, t0);                              /* z^(2^10-1)      */
    fe_sq(t1, t0);
    for (i = 1; i < 10; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);                              /* z^(2^20-1)      */
    fe_sq(t2, t1);
    for (i = 1; i < 20; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);                              /* z^(2^40-1)      */
    fe_sq(t1, t1);
    for (i = 1; i < 10; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);                              /* z^(2^50-1)      */
    fe_sq(t1, t0);
    for (i = 1; i < 50; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);                              /* z^(2^100-1)     */
    fe_sq(t2, t1);
    for (i = 1; i < 100; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);                              /* z^(2^200-1)     */
    fe_sq(t1, t1);
    for (i = 1; i < 50; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);                              /* z^(2^250-1)     */
    fe_sq(t0, t0);
    fe_sq(t0, t0);                                   /* z^(2^252-4)     */
    fe_mul(out, t0, z);                              /* z^(2^252-3)     */
}

/* ================================================================== */
/*  Extended Edwards Point Representation                              */
/*                                                                     */
/*  Curve: -x^2 + y^2 = 1 + d*x^2*y^2  (a = -1)                     */
/*  Extended coordinates: x = X/Z, y = Y/Z, T = X*Y/Z                */
/* ================================================================== */

typedef struct _GE_P3 {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} GE_P3;

static void ge_p3_copy(GE_P3 *r, const GE_P3 *p) {
    fe_copy(r->X, p->X);
    fe_copy(r->Y, p->Y);
    fe_copy(r->Z, p->Z);
    fe_copy(r->T, p->T);
}

/* Set p to identity (0:1:1:0) */
static void ge_zero(GE_P3 *p) {
    fe_0(p->X);
    fe_1(p->Y);
    fe_1(p->Z);
    fe_0(p->T);
}

/*
 * Unified point addition in extended coordinates (a = -1).
 * Formula: add-2008-hwcd from https://hyperelliptic.org/EFD
 * d2 = 2*d (precomputed).
 */
static void ge_add(GE_P3 *r, const GE_P3 *p, const GE_P3 *q,
                   const fe25519 d2) {
    fe25519 a, b, c, dd, e, f, g, h, t;

    fe_sub(a, p->Y, p->X);
    fe_sub(t, q->Y, q->X);
    fe_mul(a, a, t);           /* A = (Y1-X1)(Y2-X2)  */

    fe_add(b, p->Y, p->X);
    fe_add(t, q->Y, q->X);
    fe_mul(b, b, t);           /* B = (Y1+X1)(Y2+X2)  */

    fe_mul(c, p->T, q->T);
    fe_mul(c, c, d2);          /* C = T1 * 2d * T2     */

    fe_mul(dd, p->Z, q->Z);
    fe_add(dd, dd, dd);        /* D = 2 * Z1 * Z2      */

    fe_sub(e, b, a);           /* E = B - A             */
    fe_sub(f, dd, c);          /* F = D - C             */
    fe_add(g, dd, c);          /* G = D + C             */
    fe_add(h, b, a);           /* H = B + A             */

    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

/*
 * Point doubling in extended coordinates (a = -1).
 * Formula: dbl-2008-hwcd from https://hyperelliptic.org/EFD
 */
static void ge_double(GE_P3 *r, const GE_P3 *p) {
    fe25519 a, b, c, d, e, f, g, h;

    fe_sq(a, p->X);            /* A = X1^2                */
    fe_sq(b, p->Y);            /* B = Y1^2                */
    fe_sq(c, p->Z);
    fe_add(c, c, c);           /* C = 2*Z1^2              */
    fe_neg(d, a);              /* D = a*A = -A  (a = -1)  */

    fe_add(e, p->X, p->Y);
    fe_sq(e, e);
    fe_sub(e, e, a);
    fe_sub(e, e, b);           /* E = (X1+Y1)^2 - A - B  */

    fe_add(g, d, b);           /* G = D + B               */
    fe_sub(f, g, c);           /* F = G - C               */
    fe_sub(h, d, b);           /* H = D - B               */

    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

/* Variable-time double-and-add scalar multiplication: r = scalar * p */
static void ge_scalarmult(GE_P3 *r, const BYTE scalar[32],
                          const GE_P3 *p, const fe25519 d2) {
    GE_P3 tmp;
    int i;

    ge_zero(r);

    for (i = 255; i >= 0; i--) {
        ge_double(&tmp, r);
        ge_p3_copy(r, &tmp);

        if ((scalar[i / 8] >> (i & 7)) & 1) {
            ge_add(&tmp, r, p, d2);
            ge_p3_copy(r, &tmp);
        }
    }
}

/* ================================================================== */
/*  Point Encoding / Decoding                                          */
/* ================================================================== */

/*
 * Decompress a 32-byte Ed25519 point.
 * Returns 0 on success, -1 if the point is not on the curve.
 */
static int ge_frombytes(GE_P3 *p, const BYTE s[32]) {
    fe25519 u, v, v3, vxx, check, d_fe, sqrtm1_fe;
    BYTE y_bytes[32];
    int i;

    fe_frombytes(d_fe, ed25519_d_bytes);
    fe_frombytes(sqrtm1_fe, ed25519_sqrtm1_bytes);

    /* Extract y (clear sign bit) */
    for (i = 0; i < 32; i++) y_bytes[i] = s[i];
    y_bytes[31] &= 0x7F;
    fe_frombytes(p->Y, y_bytes);
    fe_1(p->Z);

    /* u = y^2 - 1,  v = d*y^2 + 1 */
    fe_sq(u, p->Y);
    fe_mul(v, u, d_fe);
    fe_sub(u, u, p->Z);
    fe_add(v, v, p->Z);

    /* x = u * v^3 * (u * v^7)^((p-5)/8) */
    fe_sq(v3, v);
    fe_mul(v3, v3, v);          /* v^3 */
    fe_sq(p->X, v3);
    fe_mul(p->X, p->X, v);     /* v^7 */
    fe_mul(p->X, p->X, u);     /* u * v^7 */
    fe_pow22523(p->X, p->X);   /* (u*v^7)^((p-5)/8) */
    fe_mul(p->X, p->X, v3);    /* * v^3 */
    fe_mul(p->X, p->X, u);     /* * u */

    /* Verify: v * x^2 must equal u or -u */
    fe_sq(vxx, p->X);
    fe_mul(vxx, vxx, v);

    fe_sub(check, vxx, u);
    if (!fe_iszero(check)) {
        fe_add(check, vxx, u);
        if (!fe_iszero(check))
            return -1;
        fe_mul(p->X, p->X, sqrtm1_fe);
    }

    /* Adjust sign */
    if (fe_isneg(p->X) != (s[31] >> 7))
        fe_neg(p->X, p->X);

    /* T = X * Y */
    fe_mul(p->T, p->X, p->Y);

    return 0;
}

/* Compress extended point to 32-byte Ed25519 encoding */
static void ge_tobytes(BYTE s[32], const GE_P3 *p) {
    fe25519 recip, x, y;

    fe_invert(recip, p->Z);
    fe_mul(x, p->X, recip);
    fe_mul(y, p->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= (BYTE)(fe_isneg(x) << 7);
}

/* ================================================================== */
/*  Scalar Arithmetic mod L                                            */
/* ================================================================== */

/*
 * Reduce a 64-byte scalar mod L.
 * Uses the TweetNaCl reduction: 256^32 ≡ -16*L_low (mod L), so
 * for each byte i ∈ [63..32] we fold x[i]*16*L into the lower bytes.
 */
static void sc_reduce(BYTE output[32], const BYTE input[64]) {
    long long x[64];
    long long carry;
    int i, j;

    for (i = 0; i < 64; i++)
        x[i] = (long long)(unsigned char)input[i];

    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * (long long)ed25519_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }

    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * (long long)ed25519_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++)
        x[j] -= carry * (long long)ed25519_L[j];

    for (i = 0; i < 32; i++)
        output[i] = (BYTE)x[i];
}

/* Check that scalar s < L (variable-time, fine for public signatures) */
static BOOL sc_is_valid(const BYTE s[32]) {
    int i;
    for (i = 31; i >= 0; i--) {
        if (s[i] < ed25519_L[i]) return TRUE;
        if (s[i] > ed25519_L[i]) return FALSE;
    }
    return FALSE;   /* s == L, not valid */
}

/* ================================================================== */
/*  Ed25519 Verify (RFC 8032)                                          */
/*                                                                     */
/*  Verify: [S]B == R + [h]A                                          */
/*  where h = SHA-512(R || public_key || message) mod L               */
/* ================================================================== */

BOOL spec_ed25519_verify(const BYTE public_key[32],
                         const BYTE *message, DWORD message_len,
                         const BYTE signature[64]) {
    GE_P3 A, R, B, sB, hA, check_pt;
    BYTE h_buf[64], h_reduced[32];
    SHA512_CTX sha;
    fe25519 d2, d_fe;
    const BYTE *S = signature + 32;
    BYTE sB_bytes[32], check_bytes[32];
    BOOL result;

    /* Precompute 2*d for point addition */
    fe_frombytes(d_fe, ed25519_d_bytes);
    fe_add(d2, d_fe, d_fe);

    /* S must be < L */
    if (!sc_is_valid(S))
        return FALSE;

    /* Decode public key A */
    if (ge_frombytes(&A, public_key) != 0)
        return FALSE;

    /* Decode R from signature[0..31] */
    if (ge_frombytes(&R, signature) != 0)
        return FALSE;

    /* Decode basepoint B */
    if (ge_frombytes(&B, ed25519_basepoint) != 0)
        return FALSE;

    /* h = SHA-512(R || A || message) mod L */
    spec_sha512_init(&sha);
    spec_sha512_update(&sha, signature, 32);
    spec_sha512_update(&sha, public_key, 32);
    spec_sha512_update(&sha, message, message_len);
    spec_sha512_final(&sha, h_buf);
    sc_reduce(h_reduced, h_buf);

    /* [S]B */
    ge_scalarmult(&sB, S, &B, d2);

    /* [h]A */
    ge_scalarmult(&hA, h_reduced, &A, d2);

    /* R + [h]A */
    ge_add(&check_pt, &R, &hA, d2);

    /* Compare [S]B == R + [h]A */
    ge_tobytes(sB_bytes, &sB);
    ge_tobytes(check_bytes, &check_pt);

    result = (spec_memcmp(sB_bytes, check_bytes, 32) == 0);

    /* Wipe sensitive intermediates */
    spec_memset(h_buf, 0, sizeof(h_buf));
    spec_memset(h_reduced, 0, sizeof(h_reduced));

    return result;
}
