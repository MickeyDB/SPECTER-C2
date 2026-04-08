/**
 * SPECTER Implant — Transform Chain
 *
 * Profile-driven payload transform: compress → encrypt → encode (send)
 * and decode → decrypt → decompress (recv).
 *
 * Includes:
 *   - Inline minimal LZ4 compressor/decompressor
 *   - Base64, hex encoders/decoders
 *   - ChaCha20-Poly1305 AEAD (from crypto.c)
 */

#include "specter.h"
#include "ntdefs.h"
#include "transform.h"
#include "crypto.h"

/* ------------------------------------------------------------------ */
/*  Internal helpers — LE I/O                                           */
/* ------------------------------------------------------------------ */

static void store32_le_tx(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

static DWORD load32_le_tx(const BYTE *p) {
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  LZ4 Compressor (minimal, single-pass)                              */
/* ------------------------------------------------------------------ */

/*
 * Minimal LZ4 block format compressor.
 * This implements a simple hash-based compressor targeting the
 * LZ4 block format (not the frame format).
 * Output: [4-byte LE original_size][lz4 block data]
 */

#define LZ4_HASH_LOG    12
#define LZ4_HASH_SIZE   (1 << LZ4_HASH_LOG)
#define LZ4_MIN_MATCH   4
#define LZ4_LAST_LITERALS 5

static DWORD lz4_hash(DWORD v) {
    return (v * 2654435761U) >> (32 - LZ4_HASH_LOG);
}

static DWORD read32(const BYTE *p) {
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

DWORD lz4_compress(const BYTE *input, DWORD input_len,
                    BYTE *output, DWORD output_max) {
    if (!input || !output || input_len == 0)
        return 0;

    /* Reserve 4 bytes for original size prefix */
    if (output_max < 4 + input_len + (input_len / 255) + 16)
        return 0; /* Worst case: incompressible data */

    store32_le_tx(output, input_len);
    BYTE *op = output + 4;
    BYTE *op_limit = output + output_max;

    /* For very short inputs, store as a single literal run */
    if (input_len < LZ4_MIN_MATCH + LZ4_LAST_LITERALS) {
        /* Single literal run */
        DWORD lit_len = input_len;
        if (lit_len < 15) {
            if (op >= op_limit) return 0;
            *op++ = (BYTE)(lit_len << 4);
        } else {
            if (op >= op_limit) return 0;
            *op++ = 0xF0;
            DWORD rem = lit_len - 15;
            while (rem >= 255) {
                if (op >= op_limit) return 0;
                *op++ = 255;
                rem -= 255;
            }
            if (op >= op_limit) return 0;
            *op++ = (BYTE)rem;
        }
        if (op + lit_len > op_limit) return 0;
        spec_memcpy(op, input, lit_len);
        op += lit_len;
        return (DWORD)(op - output);
    }

    /* Hash table: maps hash -> input position */
    WORD hash_table[LZ4_HASH_SIZE];
    spec_memset(hash_table, 0, sizeof(hash_table));

    const BYTE *ip = input;
    const BYTE *ip_end = input + input_len;
    const BYTE *ip_limit = ip_end - LZ4_LAST_LITERALS;
    const BYTE *anchor = ip;

    ip++; /* Start from second byte */

    while (ip < ip_limit) {
        /* Hash current position */
        DWORD h = lz4_hash(read32(ip));
        DWORD ref_idx = hash_table[h];
        const BYTE *ref = input + ref_idx;
        hash_table[h] = (WORD)(ip - input);

        /* Check match */
        if (ref_idx > 0 && (ip - ref) < 65535 &&
            (ip - ref) > 0 && read32(ref) == read32(ip)) {
            /* Found a match — encode literals + match */
            DWORD lit_len = (DWORD)(ip - anchor);

            /* Extend match forward */
            const BYTE *mp = ip + LZ4_MIN_MATCH;
            const BYTE *mr = ref + LZ4_MIN_MATCH;
            const BYTE *match_limit = ip_end - LZ4_LAST_LITERALS;
            while (mp < match_limit && *mp == *mr) {
                mp++;
                mr++;
            }
            DWORD match_len = (DWORD)(mp - ip) - LZ4_MIN_MATCH;
            DWORD offset = (DWORD)(ip - ref);

            /* Write token */
            if (op >= op_limit) return 0;
            BYTE *token_ptr = op++;
            BYTE token = 0;

            /* Literal length in token */
            if (lit_len >= 15) {
                token = 0xF0;
                DWORD rem = lit_len - 15;
                while (rem >= 255) {
                    if (op >= op_limit) return 0;
                    *op++ = 255;
                    rem -= 255;
                }
                if (op >= op_limit) return 0;
                *op++ = (BYTE)rem;
            } else {
                token = (BYTE)(lit_len << 4);
            }

            /* Copy literals */
            if (op + lit_len > op_limit) return 0;
            spec_memcpy(op, anchor, lit_len);
            op += lit_len;

            /* Offset (little-endian 16-bit) */
            if (op + 2 > op_limit) return 0;
            *op++ = (BYTE)(offset & 0xFF);
            *op++ = (BYTE)(offset >> 8);

            /* Match length in token */
            if (match_len >= 15) {
                token |= 0x0F;
                DWORD rem = match_len - 15;
                while (rem >= 255) {
                    if (op >= op_limit) return 0;
                    *op++ = 255;
                    rem -= 255;
                }
                if (op >= op_limit) return 0;
                *op++ = (BYTE)rem;
            } else {
                token |= (BYTE)match_len;
            }

            *token_ptr = token;
            anchor = mp;
            ip = mp;
        } else {
            ip++;
        }
    }

    /* Write remaining literals */
    DWORD last_lit = (DWORD)(ip_end - anchor);
    if (last_lit > 0) {
        if (last_lit < 15) {
            if (op >= op_limit) return 0;
            *op++ = (BYTE)(last_lit << 4);
        } else {
            if (op >= op_limit) return 0;
            *op++ = 0xF0;
            DWORD rem = last_lit - 15;
            while (rem >= 255) {
                if (op >= op_limit) return 0;
                *op++ = 255;
                rem -= 255;
            }
            if (op >= op_limit) return 0;
            *op++ = (BYTE)rem;
        }
        if (op + last_lit > op_limit) return 0;
        spec_memcpy(op, anchor, last_lit);
        op += last_lit;
    }

    return (DWORD)(op - output);
}

/* ------------------------------------------------------------------ */
/*  LZ4 Decompressor                                                   */
/* ------------------------------------------------------------------ */

DWORD lz4_decompress(const BYTE *input, DWORD input_len,
                      BYTE *output, DWORD output_max) {
    if (!input || !output || input_len < 4)
        return 0;

    DWORD orig_size = load32_le_tx(input);
    if (orig_size > output_max)
        return 0;

    const BYTE *ip = input + 4;
    const BYTE *ip_end = input + input_len;
    BYTE *op = output;
    BYTE *op_end = output + output_max;

    while (ip < ip_end) {
        BYTE token = *ip++;

        /* Literal length */
        DWORD lit_len = (token >> 4) & 0x0F;
        if (lit_len == 15) {
            BYTE extra;
            do {
                if (ip >= ip_end) return 0;
                extra = *ip++;
                lit_len += extra;
            } while (extra == 255);
        }

        /* Copy literals */
        if (ip + lit_len > ip_end || op + lit_len > op_end)
            return 0;
        spec_memcpy(op, ip, lit_len);
        ip += lit_len;
        op += lit_len;

        /* Check if this was the last sequence (no match follows) */
        if (ip >= ip_end)
            break;

        /* Match offset (16-bit LE) */
        if (ip + 2 > ip_end) return 0;
        DWORD offset = (DWORD)ip[0] | ((DWORD)ip[1] << 8);
        ip += 2;
        if (offset == 0) return 0;

        BYTE *match = op - offset;
        if (match < output) return 0;

        /* Match length */
        DWORD match_len = (token & 0x0F) + LZ4_MIN_MATCH;
        if ((token & 0x0F) == 15) {
            BYTE extra;
            do {
                if (ip >= ip_end) return 0;
                extra = *ip++;
                match_len += extra;
            } while (extra == 255);
        }

        /* Copy match (byte-by-byte for overlapping copies) */
        if (op + match_len > op_end) return 0;
        for (DWORD i = 0; i < match_len; i++)
            op[i] = match[i];
        op += match_len;
    }

    if ((DWORD)(op - output) != orig_size)
        return 0;

    return orig_size;
}

/* ------------------------------------------------------------------ */
/*  Base64 encode/decode (standalone for transform chain)               */
/* ------------------------------------------------------------------ */

static const char tx_b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static DWORD tx_b64_encode(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_max) {
    DWORD needed = ((in_len + 2) / 3) * 4;
    if (needed > out_max) return 0;

    DWORD oi = 0, i = 0;
    while (i + 2 < in_len) {
        DWORD v = ((DWORD)in[i] << 16) | ((DWORD)in[i+1] << 8) | in[i+2];
        out[oi++] = tx_b64[(v >> 18) & 0x3F];
        out[oi++] = tx_b64[(v >> 12) & 0x3F];
        out[oi++] = tx_b64[(v >>  6) & 0x3F];
        out[oi++] = tx_b64[v & 0x3F];
        i += 3;
    }
    if (i < in_len) {
        DWORD v = (DWORD)in[i] << 16;
        if (i + 1 < in_len) v |= (DWORD)in[i+1] << 8;
        out[oi++] = tx_b64[(v >> 18) & 0x3F];
        out[oi++] = tx_b64[(v >> 12) & 0x3F];
        out[oi++] = (i + 1 < in_len) ? tx_b64[(v >> 6) & 0x3F] : '=';
        out[oi++] = '=';
    }
    return oi;
}

static BYTE tx_b64_val(BYTE c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0xFF;
}

static DWORD tx_b64_decode(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_max) {
    if (in_len % 4 != 0) return 0;

    DWORD pad = 0;
    if (in_len >= 1 && in[in_len-1] == '=') pad++;
    if (in_len >= 2 && in[in_len-2] == '=') pad++;

    DWORD out_len = (in_len / 4) * 3 - pad;
    if (out_len > out_max) return 0;

    DWORD oi = 0;
    for (DWORD i = 0; i + 3 < in_len; i += 4) {
        BYTE a = tx_b64_val(in[i]);
        BYTE b = tx_b64_val(in[i+1]);
        BYTE c = tx_b64_val(in[i+2]);
        BYTE d = tx_b64_val(in[i+3]);
        if (a == 0xFF || b == 0xFF) return 0;

        DWORD v = ((DWORD)a << 18) | ((DWORD)b << 12);
        if (c != 0xFF) v |= ((DWORD)c << 6);
        if (d != 0xFF) v |= (DWORD)d;

        if (oi < out_max) out[oi++] = (BYTE)(v >> 16);
        if (in[i+2] != '=' && oi < out_max) out[oi++] = (BYTE)(v >> 8);
        if (in[i+3] != '=' && oi < out_max) out[oi++] = (BYTE)(v);
    }
    return oi;
}

/* ------------------------------------------------------------------ */
/*  Hex encode/decode for transform                                    */
/* ------------------------------------------------------------------ */

static const char tx_hex[] = "0123456789abcdef";

static DWORD tx_hex_encode(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_max) {
    if (in_len * 2 > out_max) return 0;
    for (DWORD i = 0; i < in_len; i++) {
        out[i * 2]     = tx_hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = tx_hex[in[i] & 0x0F];
    }
    return in_len * 2;
}

static BYTE tx_hex_val(BYTE c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0xFF;
}

static DWORD tx_hex_decode(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_max) {
    if (in_len % 2 != 0) return 0;
    DWORD out_len = in_len / 2;
    if (out_len > out_max) return 0;
    for (DWORD i = 0; i < out_len; i++) {
        BYTE hi = tx_hex_val(in[i * 2]);
        BYTE lo = tx_hex_val(in[i * 2 + 1]);
        if (hi == 0xFF || lo == 0xFF) return 0;
        out[i] = (hi << 4) | lo;
    }
    return out_len;
}

/* ------------------------------------------------------------------ */
/*  Base85 encode/decode (RFC 1924 / z85-style, matches teamserver)     */
/* ------------------------------------------------------------------ */

static const char tx_b85[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

static DWORD tx_b85_encode(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_max) {
    /* Each 4-byte group → 5 base85 chars; partial groups get N+1 chars */
    DWORD needed = (in_len / 4) * 5 + ((in_len % 4) ? (in_len % 4) + 1 : 0);
    if (needed > out_max) return 0;

    DWORD oi = 0;
    DWORD i = 0;
    while (i + 4 <= in_len) {
        DWORD val = ((DWORD)in[i] << 24) | ((DWORD)in[i+1] << 16) |
                    ((DWORD)in[i+2] << 8)  | (DWORD)in[i+3];
        BYTE enc[5];
        for (int j = 4; j >= 0; j--) {
            enc[j] = tx_b85[val % 85];
            val /= 85;
        }
        spec_memcpy(out + oi, enc, 5);
        oi += 5;
        i += 4;
    }
    /* Handle remaining bytes (1-3) */
    if (i < in_len) {
        DWORD rem = in_len - i;
        BYTE padded[4] = { 0, 0, 0, 0 };
        for (DWORD j = 0; j < rem; j++) padded[j] = in[i + j];
        DWORD val = ((DWORD)padded[0] << 24) | ((DWORD)padded[1] << 16) |
                    ((DWORD)padded[2] << 8)  | (DWORD)padded[3];
        BYTE enc[5];
        for (int j = 4; j >= 0; j--) {
            enc[j] = tx_b85[val % 85];
            val /= 85;
        }
        DWORD enc_len = rem + 1;
        spec_memcpy(out + oi, enc, enc_len);
        oi += enc_len;
    }
    return oi;
}

static BYTE tx_b85_val(BYTE c) {
    /* Linear scan of 85-char alphabet */
    for (BYTE i = 0; i < 85; i++) {
        if ((BYTE)tx_b85[i] == c) return i;
    }
    return 0xFF;
}

static DWORD tx_b85_decode(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_max) {
    DWORD oi = 0;
    DWORD i = 0;
    while (i + 5 <= in_len) {
        DWORD val = 0;
        for (int j = 0; j < 5; j++) {
            BYTE v = tx_b85_val(in[i + j]);
            if (v == 0xFF) return 0;
            val = val * 85 + v;
        }
        if (oi + 4 > out_max) return 0;
        out[oi++] = (BYTE)(val >> 24);
        out[oi++] = (BYTE)(val >> 16);
        out[oi++] = (BYTE)(val >> 8);
        out[oi++] = (BYTE)(val);
        i += 5;
    }
    /* Handle remaining chars (2-4) → 1-3 bytes */
    if (i < in_len) {
        DWORD rem = in_len - i;
        /* Pad with highest base85 index (84) to fill 5 chars */
        BYTE padded[5] = { 84, 84, 84, 84, 84 };
        for (DWORD j = 0; j < rem; j++) {
            BYTE v = tx_b85_val(in[i + j]);
            if (v == 0xFF) return 0;
            padded[j] = v;
        }
        DWORD val = 0;
        for (int j = 0; j < 5; j++)
            val = val * 85 + padded[j];
        DWORD dec_len = rem - 1;
        if (oi + dec_len > out_max) return 0;
        BYTE bytes[4];
        bytes[0] = (BYTE)(val >> 24);
        bytes[1] = (BYTE)(val >> 16);
        bytes[2] = (BYTE)(val >> 8);
        bytes[3] = (BYTE)(val);
        spec_memcpy(out + oi, bytes, dec_len);
        oi += dec_len;
    }
    return oi;
}

/* ------------------------------------------------------------------ */
/*  Nonce generation for AEAD encryption                                */
/* ------------------------------------------------------------------ */

static DWORD g_transform_counter = 0;

static void generate_transform_nonce(BYTE nonce[12]) {
    /* Use counter + PRNG for nonce uniqueness */
    g_transform_counter++;
    nonce[0] = (BYTE)(g_transform_counter);
    nonce[1] = (BYTE)(g_transform_counter >> 8);
    nonce[2] = (BYTE)(g_transform_counter >> 16);
    nonce[3] = (BYTE)(g_transform_counter >> 24);

    /* Fill remaining with derived bytes from SHA-256 of counter */
    BYTE cnt_buf[4];
    cnt_buf[0] = nonce[0]; cnt_buf[1] = nonce[1];
    cnt_buf[2] = nonce[2]; cnt_buf[3] = nonce[3];
    BYTE hash[32];
    spec_sha256(cnt_buf, 4, hash);
    spec_memcpy(nonce + 4, hash, 8);
    spec_memset(hash, 0, sizeof(hash));
}

/* ------------------------------------------------------------------ */
/*  Encoding stage                                                     */
/* ------------------------------------------------------------------ */

static DWORD encode_stage(DWORD method, const BYTE *in, DWORD in_len,
                           BYTE *out, DWORD out_max) {
    switch (method) {
    case ENCODE_BASE64:
        return tx_b64_encode(in, in_len, out, out_max);
    case ENCODE_BASE85:
        return tx_b85_encode(in, in_len, out, out_max);
    case ENCODE_HEX:
        return tx_hex_encode(in, in_len, out, out_max);
    case ENCODE_CUSTOM_ALPHABET:
        /* CustomAlphabet not implemented; fall back to base64 */
        return tx_b64_encode(in, in_len, out, out_max);
    case ENCODE_RAW:
    default:
        if (in_len > out_max) return 0;
        spec_memcpy(out, in, in_len);
        return in_len;
    }
}

static DWORD decode_stage(DWORD method, const BYTE *in, DWORD in_len,
                           BYTE *out, DWORD out_max) {
    switch (method) {
    case ENCODE_BASE64:
        return tx_b64_decode(in, in_len, out, out_max);
    case ENCODE_BASE85:
        return tx_b85_decode(in, in_len, out, out_max);
    case ENCODE_HEX:
        return tx_hex_decode(in, in_len, out, out_max);
    case ENCODE_CUSTOM_ALPHABET:
        /* CustomAlphabet not implemented; fall back to base64 */
        return tx_b64_decode(in, in_len, out, out_max);
    case ENCODE_RAW:
    default:
        if (in_len > out_max) return 0;
        spec_memcpy(out, in, in_len);
        return in_len;
    }
}

/* ------------------------------------------------------------------ */
/*  transform_send: compress → encrypt → encode                        */
/* ------------------------------------------------------------------ */

NTSTATUS transform_send(const BYTE *plaintext, DWORD len,
                         const BYTE session_key[32],
                         const TRANSFORM_CONFIG *cfg,
                         BYTE *output, DWORD *output_len,
                         DWORD output_max) {
    if (!plaintext || len == 0 || !session_key || !cfg || !output || !output_len)
        return STATUS_INVALID_PARAMETER;

    /* Determine buffer size: use stack for small payloads, heap for large */
    DWORD buf_size = TRANSFORM_MAX_OUTPUT;
    DWORD needed = len + 4096; /* payload + overhead for compression/encryption/encoding */
    if (needed > buf_size) buf_size = needed;

    BYTE buf1_stack[TRANSFORM_MAX_OUTPUT];
    BYTE buf2_stack[TRANSFORM_MAX_OUTPUT];
    BYTE *buf1 = buf1_stack;
    BYTE *buf2 = buf2_stack;
    BOOL heap_alloc = FALSE;

    if (buf_size > TRANSFORM_MAX_OUTPUT) {
        BYTE *h1 = (BYTE *)crypto_heap_alloc(buf_size);
        BYTE *h2 = (BYTE *)crypto_heap_alloc(buf_size);
        if (h1 && h2) {
            buf1 = h1;
            buf2 = h2;
            heap_alloc = TRUE;
        } else {
            /* Cleanup partial alloc and fall back to stack */
            if (h1) crypto_heap_free(h1);
            if (h2) crypto_heap_free(h2);
            buf_size = TRANSFORM_MAX_OUTPUT;
        }
    }
    DWORD cur_len;

    /* ---- Stage 1: Compress ---- */
    if (cfg->compress == COMPRESS_LZ4) {
        cur_len = lz4_compress(plaintext, len, buf1, buf_size);
        if (cur_len == 0) { goto transform_send_fail; }
    } else {
        /* No compression */
        if (len > buf_size) { goto transform_send_fail; }
        spec_memcpy(buf1, plaintext, len);
        cur_len = len;
    }

    /* ---- Stage 2: Encrypt (ChaCha20-Poly1305 AEAD) ---- */
    /* Output: [12-byte nonce][ciphertext][16-byte tag] */
    {
        DWORD enc_total = 12 + cur_len + 16;
        if (enc_total > buf_size) { goto transform_send_fail; }

        BYTE nonce[12];
        generate_transform_nonce(nonce);

        spec_memcpy(buf2, nonce, 12);
        spec_aead_encrypt(session_key, nonce, buf1, cur_len,
                           NULL, 0, buf2 + 12, buf2 + 12 + cur_len);
        cur_len = enc_total;
    }

    /* ---- Stage 3: Encode ---- */
    {
        DWORD enc_len = encode_stage(cfg->encode, buf2, cur_len, output, output_max);
        if (enc_len == 0) { goto transform_send_fail; }
        *output_len = enc_len;
    }

    /* Zero intermediate buffers */
    spec_memset(buf1, 0, buf_size);
    spec_memset(buf2, 0, buf_size);
    if (heap_alloc) { crypto_heap_free(buf1); crypto_heap_free(buf2); }

    return STATUS_SUCCESS;

transform_send_fail:
    spec_memset(buf1, 0, buf_size);
    spec_memset(buf2, 0, buf_size);
    if (heap_alloc) { crypto_heap_free(buf1); crypto_heap_free(buf2); }
    return STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------ */
/*  transform_recv: decode → decrypt → decompress                      */
/* ------------------------------------------------------------------ */

NTSTATUS transform_recv(const BYTE *encoded, DWORD len,
                         const BYTE session_key[32],
                         const TRANSFORM_CONFIG *cfg,
                         BYTE *output, DWORD *output_len,
                         DWORD output_max) {
    if (!encoded || len == 0 || !session_key || !cfg || !output || !output_len)
        return STATUS_INVALID_PARAMETER;

    /* Determine buffer size: use stack for small payloads, heap for large */
    DWORD buf_size = TRANSFORM_MAX_OUTPUT;
    DWORD needed = len + 4096; /* encoded input + overhead */
    if (needed > buf_size) buf_size = needed;

    BYTE buf1_stack[TRANSFORM_MAX_OUTPUT];
    BYTE buf2_stack[TRANSFORM_MAX_OUTPUT];
    BYTE *buf1 = buf1_stack;
    BYTE *buf2 = buf2_stack;
    BOOL heap_alloc = FALSE;

    if (buf_size > TRANSFORM_MAX_OUTPUT) {
        BYTE *h1 = (BYTE *)crypto_heap_alloc(buf_size);
        BYTE *h2 = (BYTE *)crypto_heap_alloc(buf_size);
        if (h1 && h2) {
            buf1 = h1;
            buf2 = h2;
            heap_alloc = TRUE;
        } else {
            if (h1) crypto_heap_free(h1);
            if (h2) crypto_heap_free(h2);
            buf_size = TRANSFORM_MAX_OUTPUT;
        }
    }
    DWORD cur_len;

    /* ---- Stage 1: Decode ---- */
    cur_len = decode_stage(cfg->encode, encoded, len, buf1, buf_size);
    if (cur_len == 0) { goto transform_recv_fail; }

    /* ---- Stage 2: Decrypt ---- */
    /* Input: [12-byte nonce][ciphertext][16-byte tag] */
    {
        if (cur_len < 12 + 16) { goto transform_recv_fail; }

        const BYTE *nonce = buf1;
        DWORD ct_len = cur_len - 12 - 16;
        const BYTE *ct = buf1 + 12;
        const BYTE *tag = buf1 + 12 + ct_len;

        if (ct_len > buf_size) { goto transform_recv_fail; }

        BOOL ok = spec_aead_decrypt(session_key, nonce, ct, ct_len,
                                     NULL, 0, buf2, tag);
        if (!ok) { goto transform_recv_fail; }
        cur_len = ct_len;
    }

    /* ---- Stage 3: Decompress ---- */
    if (cfg->compress == COMPRESS_LZ4) {
        DWORD dec_len = lz4_decompress(buf2, cur_len, output, output_max);
        if (dec_len == 0) { goto transform_recv_fail; }
        *output_len = dec_len;
    } else {
        if (cur_len > output_max) { goto transform_recv_fail; }
        spec_memcpy(output, buf2, cur_len);
        *output_len = cur_len;
    }

    /* Zero intermediate buffers */
    spec_memset(buf1, 0, buf_size);
    spec_memset(buf2, 0, buf_size);
    if (heap_alloc) { crypto_heap_free(buf1); crypto_heap_free(buf2); }

    return STATUS_SUCCESS;

transform_recv_fail:
    spec_memset(buf1, 0, buf_size);
    spec_memset(buf2, 0, buf_size);
    if (heap_alloc) { crypto_heap_free(buf1); crypto_heap_free(buf2); }
    return STATUS_UNSUCCESSFUL;
}
