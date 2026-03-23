/**
 * SPECTER Implant — Comms Test Suite
 *
 * Verifies HTTP request builder, HTTP response parser, nonce generation,
 * wire protocol encoding, and check-in payload construction.
 * Compiled natively (not PIC) for testing on the build host.
 *
 * Build:
 *   gcc -DTEST_BUILD -I../core/include -c ../core/src/string.c -o string.o
 *   gcc -DTEST_BUILD -I../core/include -c ../core/src/hash.c -o hash.o
 *   gcc -DTEST_BUILD -I../core/include -c ../core/src/peb.c -o peb.o
 *   gcc -DTEST_BUILD -I../core/include -c ../core/src/crypto.c -o crypto.o
 *   gcc -DTEST_BUILD -I../core/include -c ../core/src/comms.c -o comms.o
 *   gcc -DTEST_BUILD -I../core/include -c test_comms.c -o test_comms.o
 *   gcc test_comms.o comms.o crypto.o string.o hash.o peb.o -o test_comms
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "ntdefs.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"

/* ------------------------------------------------------------------ */
/*  Globals required by the object files                               */
/* ------------------------------------------------------------------ */

IMPLANT_CONTEXT g_ctx;

/* ------------------------------------------------------------------ */
/*  Config stub — provides cfg_get for comms.c                         */
/* ------------------------------------------------------------------ */

static IMPLANT_CONFIG g_test_config;

NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) { (void)ctx; return &g_test_config; }
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx) { (void)ctx; return FALSE; }

/* ------------------------------------------------------------------ */
/*  Extern declarations for internal (static) functions we want to     */
/*  test — we'll access them via a test-only source arrangement.       */
/*  Since build_checkin_payload and generate_nonce are static in       */
/*  comms.c, we test them indirectly or reimplement the logic here.    */
/* ------------------------------------------------------------------ */

/* Reimplementation of internal helpers for testing (must match comms.c) */
static void store32_le_test(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

static DWORD load32_le_test(const BYTE *p) {
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static DWORD uint_to_str_test(DWORD val, char *buf, DWORD buf_size) {
    if (buf_size == 0) return 0;
    char tmp[12];
    DWORD len = 0;
    if (val == 0) {
        if (buf_size < 2) return 0;
        buf[0] = '0'; buf[1] = '\0'; return 1;
    }
    while (val > 0 && len < sizeof(tmp)) {
        tmp[len++] = '0' + (char)(val % 10);
        val /= 10;
    }
    if (len >= buf_size) return 0;
    for (DWORD i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    buf[len] = '\0';
    return len;
}

static void hex_encode_test(const BYTE *data, DWORD len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (DWORD i = 0; i < len; i++) {
        out[i * 2]     = hex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/* Nonce generation — must match comms.c generate_nonce() */
static void generate_nonce_test(DWORD seq, const BYTE *pubkey, BYTE nonce[12]) {
    store32_le_test(nonce, seq);
    BYTE hash_input[36];
    spec_memcpy(hash_input, pubkey, 32);
    store32_le_test(hash_input + 32, seq);
    BYTE digest[SHA256_DIGEST_SIZE];
    spec_sha256(hash_input, 36, digest);
    spec_memcpy(nonce + 4, digest, 8);
    spec_memset(digest, 0, sizeof(digest));
    spec_memset(hash_input, 0, sizeof(hash_input));
}

/* Payload builder — must match comms.c build_checkin_payload() */
static DWORD build_checkin_payload_test(IMPLANT_CONFIG *cfg, DWORD seq,
                                         BYTE *out, DWORD out_len) {
    DWORD needed = 4 + 32 + 4;
    if (out_len < needed) return 0;
    store32_le_test(out, seq);
    spec_memcpy(out + 4, cfg->implant_pubkey, 32);
    store32_le_test(out + 36, cfg->checkin_count);
    return needed;
}

/* ------------------------------------------------------------------ */
/*  Test helpers                                                       */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

static void hex_dump_print(const BYTE *data, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static int check_eq(const char *name, int got, int expected) {
    tests_run++;
    if (got == expected) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s (expected %d, got %d)\n", name, expected, got);
        return 0;
    }
}

static int check_str_contains(const char *name, const char *haystack, const char *needle) {
    tests_run++;
    if (strstr(haystack, needle) != NULL) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s (string not found: \"%s\")\n", name, needle);
        return 0;
    }
}

static int check_bytes_eq(const char *name, const BYTE *got, const BYTE *expected, int len) {
    tests_run++;
    if (memcmp(got, expected, len) == 0) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s\n", name);
        printf("  Expected: "); hex_dump_print(expected, len); printf("\n");
        printf("  Got:      "); hex_dump_print(got, len); printf("\n");
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Test: HTTP request builder                                         */
/* ------------------------------------------------------------------ */

static void test_http_build_get(void) {
    printf("\n=== HTTP GET Request Builder ===\n");

    BYTE buf[1024];
    DWORD len = comms_http_build_request(COMMS_HTTP_GET, "/api/tasks",
        "10.0.0.1", NULL, NULL, 0, buf, sizeof(buf));

    check_eq("GET request length > 0", len > 0, 1);

    buf[len] = '\0';
    check_str_contains("GET request line", (char *)buf, "GET /api/tasks HTTP/1.1\r\n");
    check_str_contains("GET host header", (char *)buf, "Host: 10.0.0.1\r\n");
    check_str_contains("GET connection header", (char *)buf, "Connection: keep-alive\r\n");
    check_str_contains("GET ends with CRLFCRLF", (char *)buf, "\r\n\r\n");
}

static void test_http_build_post(void) {
    printf("\n=== HTTP POST Request Builder ===\n");

    BYTE body[] = "test-payload-data";
    BYTE buf[1024];
    DWORD len = comms_http_build_request(COMMS_HTTP_POST, "/api/beacon",
        "teamserver.local", NULL, body, 17, buf, sizeof(buf));

    check_eq("POST request length > 0", len > 0, 1);

    buf[len] = '\0';
    check_str_contains("POST request line", (char *)buf, "POST /api/beacon HTTP/1.1\r\n");
    check_str_contains("POST host header", (char *)buf, "Host: teamserver.local\r\n");
    check_str_contains("POST content-length", (char *)buf, "Content-Length: 17\r\n");
    check_str_contains("POST content-type", (char *)buf, "Content-Type: application/octet-stream\r\n");
    check_str_contains("POST body present", (char *)buf, "test-payload-data");
}

static void test_http_build_with_headers(void) {
    printf("\n=== HTTP Request with Custom Headers ===\n");

    BYTE buf[1024];
    DWORD len = comms_http_build_request(COMMS_HTTP_GET, "/",
        "example.com", "X-Custom: value\r\n", NULL, 0, buf, sizeof(buf));

    check_eq("Custom header request length > 0", len > 0, 1);

    buf[len] = '\0';
    check_str_contains("Custom header present", (char *)buf, "X-Custom: value\r\n");
}

static void test_http_build_overflow(void) {
    printf("\n=== HTTP Request Buffer Overflow Protection ===\n");

    BYTE tiny_buf[10];
    DWORD len = comms_http_build_request(COMMS_HTTP_GET, "/api/long-uri",
        "example.com", NULL, NULL, 0, tiny_buf, sizeof(tiny_buf));

    check_eq("Overflow returns 0", (int)len, 0);
}

static void test_http_build_null_params(void) {
    printf("\n=== HTTP Request Null Parameter Handling ===\n");

    DWORD len = comms_http_build_request(COMMS_HTTP_GET, NULL,
        "host", NULL, NULL, 0, NULL, 0);
    check_eq("Null uri returns 0", (int)len, 0);

    BYTE buf[256];
    len = comms_http_build_request(COMMS_HTTP_GET, "/", NULL,
        NULL, NULL, 0, buf, sizeof(buf));
    check_eq("Null host returns 0", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: HTTP response parser                                         */
/* ------------------------------------------------------------------ */

static void test_http_parse_200(void) {
    printf("\n=== HTTP Response Parser — 200 OK ===\n");

    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 5\r\n"
        "X-Request-Id: abc123\r\n"
        "\r\n"
        "hello";

    DWORD status_code = 0;
    HTTP_HEADER headers[COMMS_MAX_HEADERS];
    DWORD header_count = 0;
    const BYTE *body = NULL;
    DWORD body_len = 0;

    NTSTATUS ns = comms_http_parse_response(
        (const BYTE *)response, (DWORD)strlen(response),
        &status_code, headers, &header_count, &body, &body_len);

    check_eq("Parse 200 OK status", NT_SUCCESS(ns), 1);
    check_eq("Status code is 200", (int)status_code, 200);
    check_eq("Header count is 3", (int)header_count, 3);
    check_eq("Body length is 5", (int)body_len, 5);

    check_str_contains("Header 0 name", headers[0].name, "Content-Type");
    check_str_contains("Header 0 value", headers[0].value, "application/octet-stream");
    check_str_contains("Header 2 name", headers[2].name, "X-Request-Id");
    check_str_contains("Header 2 value", headers[2].value, "abc123");

    tests_run++;
    if (body && memcmp(body, "hello", 5) == 0) {
        tests_passed++;
        printf("[PASS] Response body content\n");
    } else {
        printf("[FAIL] Response body content\n");
    }
}

static void test_http_parse_404(void) {
    printf("\n=== HTTP Response Parser — 404 Not Found ===\n");

    const char *response =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    DWORD status_code = 0;
    NTSTATUS ns = comms_http_parse_response(
        (const BYTE *)response, (DWORD)strlen(response),
        &status_code, NULL, NULL, NULL, NULL);

    check_eq("Parse 404 status", NT_SUCCESS(ns), 1);
    check_eq("Status code is 404", (int)status_code, 404);
}

static void test_http_parse_no_body(void) {
    printf("\n=== HTTP Response Parser — No Body ===\n");

    const char *response =
        "HTTP/1.1 204 No Content\r\n"
        "\r\n";

    DWORD status_code = 0;
    const BYTE *body = NULL;
    DWORD body_len = 0;

    NTSTATUS ns = comms_http_parse_response(
        (const BYTE *)response, (DWORD)strlen(response),
        &status_code, NULL, NULL, &body, &body_len);

    check_eq("Parse 204 status", NT_SUCCESS(ns), 1);
    check_eq("Status code is 204", (int)status_code, 204);
    check_eq("Body length is 0", (int)body_len, 0);
}

static void test_http_parse_incomplete(void) {
    printf("\n=== HTTP Response Parser — Incomplete Response ===\n");

    const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";

    DWORD status_code = 0;
    NTSTATUS ns = comms_http_parse_response(
        (const BYTE *)response, (DWORD)strlen(response),
        &status_code, NULL, NULL, NULL, NULL);

    check_eq("Incomplete response fails", NT_SUCCESS(ns), 0);
}

/* ------------------------------------------------------------------ */
/*  Test: uint_to_str helper                                           */
/* ------------------------------------------------------------------ */

static void test_uint_to_str(void) {
    printf("\n=== uint_to_str Helper ===\n");

    char buf[16];

    DWORD len = uint_to_str_test(0, buf, sizeof(buf));
    check_eq("uint_to_str(0) len", (int)len, 1);
    check_eq("uint_to_str(0) value", strcmp(buf, "0"), 0);

    len = uint_to_str_test(443, buf, sizeof(buf));
    check_eq("uint_to_str(443) len", (int)len, 3);
    check_eq("uint_to_str(443) value", strcmp(buf, "443"), 0);

    len = uint_to_str_test(8080, buf, sizeof(buf));
    check_eq("uint_to_str(8080) len", (int)len, 4);
    check_eq("uint_to_str(8080) value", strcmp(buf, "8080"), 0);

    len = uint_to_str_test(65535, buf, sizeof(buf));
    check_eq("uint_to_str(65535) len", (int)len, 5);
    check_eq("uint_to_str(65535) value", strcmp(buf, "65535"), 0);

    len = uint_to_str_test(12345, buf, 3);
    check_eq("uint_to_str overflow returns 0", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: hex_encode helper                                            */
/* ------------------------------------------------------------------ */

static void test_hex_encode(void) {
    printf("\n=== hex_encode Helper ===\n");

    BYTE data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    char out[16];
    hex_encode_test(data, 4, out);
    check_eq("hex_encode result", strcmp(out, "deadbeef"), 0);

    BYTE data2[] = { 0x00, 0xFF };
    hex_encode_test(data2, 2, out);
    check_eq("hex_encode 00ff", strcmp(out, "00ff"), 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Nonce generation determinism                                 */
/* ------------------------------------------------------------------ */

static void test_nonce_generation(void) {
    printf("\n=== Nonce Generation ===\n");

    BYTE pubkey[32];
    memset(pubkey, 0x42, 32);

    BYTE nonce1[12], nonce2[12], nonce3[12];
    generate_nonce_test(1, pubkey, nonce1);
    generate_nonce_test(1, pubkey, nonce2);
    generate_nonce_test(2, pubkey, nonce3);

    check_bytes_eq("Nonce deterministic (same seq)", nonce1, nonce2, 12);

    tests_run++;
    if (memcmp(nonce1, nonce3, 12) != 0) {
        tests_passed++;
        printf("[PASS] Nonce differs for different seq\n");
    } else {
        printf("[FAIL] Nonce should differ for different seq\n");
    }

    BYTE expected_seq[4] = { 0x01, 0x00, 0x00, 0x00 };
    check_bytes_eq("Nonce seq prefix (seq=1)", nonce1, expected_seq, 4);

    BYTE expected_seq2[4] = { 0x02, 0x00, 0x00, 0x00 };
    check_bytes_eq("Nonce seq prefix (seq=2)", nonce3, expected_seq2, 4);
}

/* ------------------------------------------------------------------ */
/*  Test: Check-in payload builder                                     */
/* ------------------------------------------------------------------ */

static void test_checkin_payload(void) {
    printf("\n=== Check-in Payload Builder ===\n");

    IMPLANT_CONFIG cfg;
    memset(&cfg, 0, sizeof(cfg));
    memset(cfg.implant_pubkey, 0xAA, 32);
    cfg.checkin_count = 5;

    BYTE payload[128];
    DWORD len = build_checkin_payload_test(&cfg, 42, payload, sizeof(payload));

    check_eq("Payload length is 40", (int)len, 40);

    BYTE expected_seq[4] = { 42, 0, 0, 0 };
    check_bytes_eq("Payload seq field", payload, expected_seq, 4);

    BYTE expected_pubkey[32];
    memset(expected_pubkey, 0xAA, 32);
    check_bytes_eq("Payload pubkey field", payload + 4, expected_pubkey, 32);

    BYTE expected_cc[4] = { 5, 0, 0, 0 };
    check_bytes_eq("Payload checkin_count field", payload + 36, expected_cc, 4);

    BYTE tiny[10];
    DWORD tiny_len = build_checkin_payload_test(&cfg, 1, tiny, sizeof(tiny));
    check_eq("Payload overflow returns 0", (int)tiny_len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Wire protocol encoding (AEAD encrypt/decrypt roundtrip)      */
/* ------------------------------------------------------------------ */

static void test_wire_protocol_roundtrip(void) {
    printf("\n=== Wire Protocol AEAD Roundtrip ===\n");

    BYTE session_key[32];
    memset(session_key, 0x55, 32);

    BYTE payload[] = "test-checkin-data-12345";
    DWORD payload_len = (DWORD)strlen((char *)payload);

    BYTE pubkey[32];
    memset(pubkey, 0xBB, 32);
    BYTE nonce[12];
    generate_nonce_test(7, pubkey, nonce);

    BYTE ciphertext[64];
    BYTE tag[16];
    spec_aead_encrypt(session_key, nonce, payload, payload_len,
                       NULL, 0, ciphertext, tag);

    /* Build wire frame: [4-byte len][12-byte id][12-byte nonce][ct][16-byte tag] */
    DWORD wire_body_len = COMMS_WIRE_HEADER_SIZE + payload_len + COMMS_WIRE_TAG_SIZE;
    DWORD wire_total = COMMS_WIRE_LEN_SIZE + wire_body_len;
    BYTE wire[256];

    DWORD wp = 0;
    store32_le_test(wire + wp, wire_body_len); wp += 4;
    memcpy(wire + wp, pubkey, COMMS_WIRE_IMPLANT_ID); wp += COMMS_WIRE_IMPLANT_ID;
    memcpy(wire + wp, nonce, 12); wp += 12;
    memcpy(wire + wp, ciphertext, payload_len); wp += payload_len;
    memcpy(wire + wp, tag, 16); wp += 16;

    check_eq("Wire total matches", (int)wp, (int)wire_total);

    /* Parse wire frame back */
    DWORD recv_body_len = load32_le_test(wire);
    check_eq("Wire body len matches", (int)recv_body_len, (int)wire_body_len);

    const BYTE *recv_nonce = wire + 4 + COMMS_WIRE_IMPLANT_ID;
    DWORD recv_ct_len = recv_body_len - COMMS_WIRE_HEADER_SIZE - COMMS_WIRE_TAG_SIZE;
    const BYTE *recv_ct = recv_nonce + 12;
    const BYTE *recv_tag = recv_ct + recv_ct_len;

    check_eq("Ciphertext length matches", (int)recv_ct_len, (int)payload_len);

    BYTE decrypted[64];
    BOOL ok = spec_aead_decrypt(session_key, recv_nonce, recv_ct, recv_ct_len,
                                 NULL, 0, decrypted, recv_tag);

    tests_run++;
    if (ok) {
        tests_passed++;
        printf("[PASS] AEAD decryption succeeded\n");
    } else {
        printf("[FAIL] AEAD decryption failed\n");
    }

    check_bytes_eq("Decrypted payload matches", decrypted, payload, payload_len);

    /* Verify implant ID prefix */
    const BYTE *recv_implant_id = wire + 4;
    BYTE expected_id[12];
    memset(expected_id, 0xBB, 12);
    check_bytes_eq("Implant ID in wire matches", recv_implant_id, expected_id, 12);
}

/* ------------------------------------------------------------------ */
/*  Test: Wire protocol tampered tag detection                         */
/* ------------------------------------------------------------------ */

static void test_wire_tampered_tag(void) {
    printf("\n=== Wire Protocol Tampered Tag ===\n");

    BYTE session_key[32];
    memset(session_key, 0x77, 32);

    BYTE payload[] = "secret-data";
    DWORD payload_len = 11;

    BYTE nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    BYTE ciphertext[32];
    BYTE tag[16];
    spec_aead_encrypt(session_key, nonce, payload, payload_len, NULL, 0, ciphertext, tag);

    tag[0] ^= 0xFF;

    BYTE decrypted[32];
    BOOL ok = spec_aead_decrypt(session_key, nonce, ciphertext, payload_len,
                                 NULL, 0, decrypted, tag);

    tests_run++;
    if (!ok) {
        tests_passed++;
        printf("[PASS] Tampered tag rejected\n");
    } else {
        printf("[FAIL] Tampered tag should be rejected\n");
    }
}

/* ------------------------------------------------------------------ */
/*  Test: COMMS state transitions                                      */
/* ------------------------------------------------------------------ */

static void test_comms_state_transitions(void) {
    printf("\n=== COMMS State Transitions ===\n");

    COMMS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket = INVALID_SOCKET;
    ctx.state = COMMS_STATE_DISCONNECTED;

    check_eq("Initial state is disconnected", (int)ctx.state, COMMS_STATE_DISCONNECTED);
    check_eq("COMMS_STATE_TCP_CONNECTED value", COMMS_STATE_TCP_CONNECTED, 1);
    check_eq("COMMS_STATE_TLS_HANDSHAKE value", COMMS_STATE_TLS_HANDSHAKE, 2);
    check_eq("COMMS_STATE_TLS_CONNECTED value", COMMS_STATE_TLS_CONNECTED, 3);
    check_eq("COMMS_STATE_REGISTERED value", COMMS_STATE_REGISTERED, 4);
    check_eq("COMMS_STATE_ERROR value", COMMS_STATE_ERROR, 5);
}

/* ------------------------------------------------------------------ */
/*  Test: LE encoding roundtrip                                        */
/* ------------------------------------------------------------------ */

static void test_le_encoding(void) {
    printf("\n=== Little-Endian Encoding ===\n");

    BYTE buf[4];
    store32_le_test(buf, 0x12345678);
    check_eq("LE byte 0", buf[0], 0x78);
    check_eq("LE byte 1", buf[1], 0x56);
    check_eq("LE byte 2", buf[2], 0x34);
    check_eq("LE byte 3", buf[3], 0x12);

    DWORD val = load32_le_test(buf);
    check_eq("LE roundtrip", (int)val, (int)0x12345678);

    store32_le_test(buf, 0);
    check_eq("LE zero", (int)load32_le_test(buf), 0);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("SPECTER Comms Test Suite\n");
    printf("========================\n");

    /* HTTP builder tests */
    test_http_build_get();
    test_http_build_post();
    test_http_build_with_headers();
    test_http_build_overflow();
    test_http_build_null_params();

    /* HTTP parser tests */
    test_http_parse_200();
    test_http_parse_404();
    test_http_parse_no_body();
    test_http_parse_incomplete();

    /* Helper tests */
    test_uint_to_str();
    test_hex_encode();
    test_le_encoding();

    /* Protocol tests */
    test_nonce_generation();
    test_checkin_payload();
    test_wire_protocol_roundtrip();
    test_wire_tampered_tag();

    /* State transition tests */
    test_comms_state_transitions();

    printf("\n========================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
