/**
 * SPECTER Implant — Ed25519 Signature Verification Test Suite
 *
 * Verifies Ed25519 implementation against RFC 8032 test vectors.
 * Also tests SHA-512 against FIPS 180-4 test vectors.
 *
 * Build: gcc -o test_ed25519 test_ed25519.c ../core/src/crypto.c
 *            ../core/src/crypto_sign.c ../core/src/string.c
 *            ../core/src/hash.c
 *            -I../core/include
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "crypto.h"

/* Provide definition for g_ctx */
IMPLANT_CONTEXT g_ctx;

/* Stubs for PEB functions (not used in crypto/ed25519) */
PPEB    get_peb(void) { return NULL; }
PVOID   find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID   find_export_by_hash(PVOID base, DWORD hash) { (void)base; (void)hash; return NULL; }
PVOID   resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* ------------------------------------------------------------------ */
/*  Test infrastructure                                                */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [TEST] %-50s ", name); \
} while(0)

#define PASS() do { tests_passed++; printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("[FAIL] %s\n", msg); } while(0)

static void hex_to_bytes(const char *hex, BYTE *out, int len) {
    int i;
    for (i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        out[i] = (BYTE)b;
    }
}

/* ================================================================== */
/*  SHA-512 Tests                                                      */
/* ================================================================== */

static void test_sha512_empty(void) {
    BYTE expected[64];
    BYTE digest[64];

    hex_to_bytes(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        expected, 64);

    TEST("SHA-512 empty string");
    spec_sha512((const BYTE *)"", 0, digest);
    if (memcmp(digest, expected, 64) == 0) PASS();
    else FAIL("digest mismatch");
}

static void test_sha512_abc(void) {
    BYTE expected[64];
    BYTE digest[64];

    hex_to_bytes(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        expected, 64);

    TEST("SHA-512 \"abc\"");
    spec_sha512((const BYTE *)"abc", 3, digest);
    if (memcmp(digest, expected, 64) == 0) PASS();
    else FAIL("digest mismatch");
}

static void test_sha512_448bit(void) {
    BYTE expected[64];
    BYTE digest[64];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    hex_to_bytes(
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
        "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        expected, 64);

    TEST("SHA-512 448-bit message");
    spec_sha512((const BYTE *)msg, 56, digest);
    if (memcmp(digest, expected, 64) == 0) PASS();
    else FAIL("digest mismatch");
}

static void test_sha512_incremental(void) {
    BYTE expected[64];
    BYTE digest[64];
    SHA512_CTX ctx;

    hex_to_bytes(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        expected, 64);

    TEST("SHA-512 incremental update");
    spec_sha512_init(&ctx);
    spec_sha512_update(&ctx, (const BYTE *)"a", 1);
    spec_sha512_update(&ctx, (const BYTE *)"bc", 2);
    spec_sha512_final(&ctx, digest);
    if (memcmp(digest, expected, 64) == 0) PASS();
    else FAIL("digest mismatch");
}

/* ================================================================== */
/*  Ed25519 Tests (RFC 8032 Section 7.1)                               */
/* ================================================================== */

static void test_ed25519_vector1(void) {
    /*
     * RFC 8032 TEST 1 — empty message
     * PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
     * SIGNATURE:  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555
     *             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
     */
    BYTE pubkey[32], sig[64];

    hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                 pubkey, 32);
    hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                 "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                 sig, 64);

    TEST("Ed25519 RFC 8032 test 1 (empty msg)");
    if (spec_ed25519_verify(pubkey, (const BYTE *)"", 0, sig))
        PASS();
    else
        FAIL("valid signature rejected");
}

static void test_ed25519_vector2(void) {
    /*
     * RFC 8032 TEST 2 — single byte 0x72
     * PUBLIC KEY: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
     */
    BYTE pubkey[32], sig[64], msg[1];

    hex_to_bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                 pubkey, 32);
    hex_to_bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                 "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                 sig, 64);
    msg[0] = 0x72;

    TEST("Ed25519 RFC 8032 test 2 (1-byte msg)");
    BOOL result = spec_ed25519_verify(pubkey, msg, 1, sig);
    if (result) PASS();
    else FAIL("valid signature rejected");
}

static void test_ed25519_vector3(void) {
    /*
     * RFC 8032 TEST 3 — message af82
     * PUBLIC KEY: fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
     * SIGNATURE:  6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
     *             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
     */
    BYTE pubkey[32], sig[64], msg[2];

    hex_to_bytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                 pubkey, 32);
    hex_to_bytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                 "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                 sig, 64);
    msg[0] = 0xaf; msg[1] = 0x82;

    TEST("Ed25519 RFC 8032 test 3 (2-byte msg)");
    if (spec_ed25519_verify(pubkey, msg, 2, sig))
        PASS();
    else
        FAIL("valid signature rejected");
}

static void test_ed25519_invalid_sig(void) {
    BYTE pubkey[32], sig[64];

    hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                 pubkey, 32);
    hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                 "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                 sig, 64);
    sig[0] ^= 0x01;

    TEST("Ed25519 reject corrupted signature");
    if (!spec_ed25519_verify(pubkey, (const BYTE *)"", 0, sig))
        PASS();
    else
        FAIL("corrupted signature accepted");
}

static void test_ed25519_wrong_message(void) {
    BYTE pubkey[32], sig[64];

    hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                 pubkey, 32);
    hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                 "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                 sig, 64);

    TEST("Ed25519 reject wrong message");
    if (!spec_ed25519_verify(pubkey, (const BYTE *)"wrong", 5, sig))
        PASS();
    else
        FAIL("wrong message accepted");
}

static void test_ed25519_s_ge_L(void) {
    BYTE pubkey[32], sig[64];

    hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                 pubkey, 32);
    memset(sig, 0, 64);
    /* Set S (bytes 32-63) to L — must be rejected */
    sig[32] = 0xed; sig[33] = 0xd3; sig[34] = 0xf5; sig[35] = 0x5c;
    sig[36] = 0x1a; sig[37] = 0x63; sig[38] = 0x12; sig[39] = 0x58;
    sig[40] = 0xd6; sig[41] = 0x9c; sig[42] = 0xf7; sig[43] = 0xa2;
    sig[44] = 0xde; sig[45] = 0xf9; sig[46] = 0xde; sig[47] = 0x14;
    sig[63] = 0x10;

    TEST("Ed25519 reject S >= L");
    if (!spec_ed25519_verify(pubkey, (const BYTE *)"", 0, sig))
        PASS();
    else
        FAIL("S >= L was accepted");
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void) {
    printf("\n=== SPECTER Ed25519 & SHA-512 Test Suite ===\n\n");

    printf("[SHA-512 Tests]\n");
    test_sha512_empty();
    test_sha512_abc();
    test_sha512_448bit();
    test_sha512_incremental();

    printf("\n[Ed25519 Verification Tests]\n");
    test_ed25519_vector1();
    test_ed25519_vector2();
    test_ed25519_vector3();
    test_ed25519_invalid_sig();
    test_ed25519_wrong_message();
    test_ed25519_s_ge_L();

    printf("\n=== Results: %d/%d passed, %d failed ===\n\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
