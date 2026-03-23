/**
 * SPECTER Implant — Module Lifecycle Manager Test Suite
 *
 * Tests modmgr_init, modmgr_execute, modmgr_poll, and modmgr_cleanup.
 *
 * Build: gcc -o test_lifecycle test_lifecycle.c
 *            ../core/src/bus/lifecycle.c ../core/src/bus/bus_api.c
 *            ../core/src/bus/guardian.c ../core/src/bus/loader.c
 *            ../core/src/crypto.c ../core/src/crypto_sign.c
 *            ../core/src/string.c ../core/src/hash.c
 *            -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Include project headers directly — they define all types we need */
#include "specter.h"
#include "ntdefs.h"

/* Global implant context (required by specter.h extern declaration) */
IMPLANT_CONTEXT g_ctx;

/* ------------------------------------------------------------------ */
/*  Syscall / evasion stubs                                             */
/* ------------------------------------------------------------------ */

typedef struct _SYSCALL_ENTRY_IMPL { DWORD ssn; PVOID syscall_addr; DWORD hash; } SYSCALL_ENTRY_IMPL;
SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *t, DWORD h) { (void)t; (void)h; return NULL; }
NTSTATUS evasion_syscall(void *ctx, DWORD func_hash, ...) { (void)ctx; (void)func_hash; return STATUS_PROCEDURE_NOT_FOUND; }
NTSTATUS spec_syscall(DWORD ssn, PVOID addr, ...) { (void)ssn; (void)addr; return STATUS_PROCEDURE_NOT_FOUND; }

/* PEB stubs */
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD h) { (void)h; return NULL; }
PVOID find_export_by_hash(PVOID m, DWORD h) { (void)m; (void)h; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* Sleep tracking stubs */
typedef struct _HEAP_ALLOC_ENTRY { PVOID ptr; SIZE_T size; struct _HEAP_ALLOC_ENTRY *next; } HEAP_ALLOC_ENTRY;
typedef struct _SLEEP_CONTEXT { DWORD sleep_method; PVOID implant_base; SIZE_T implant_size; HEAP_ALLOC_ENTRY *heap_list; BYTE sleep_enc_key[32]; ULONG original_protect; } SLEEP_CONTEXT;
void sleep_track_alloc(SLEEP_CONTEXT *s, PVOID p, SIZE_T sz) { (void)s; (void)p; (void)sz; }
void sleep_untrack_alloc(SLEEP_CONTEXT *s, PVOID p) { (void)s; (void)p; }

/* Crypto constants and forward declarations */
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
#define HASH_BCRYPT_DLL      0x730076C3

void spec_chacha20_encrypt(const BYTE key[32], const BYTE nonce[12],
                           DWORD counter, const BYTE *input, DWORD len, BYTE *output);
void spec_poly1305_mac(const BYTE key[32], const BYTE *msg, DWORD msg_len, BYTE tag[16]);
void spec_sha256(const BYTE *data, DWORD len, BYTE digest[32]);
void spec_hkdf_derive(const BYTE *salt, DWORD salt_len,
                       const BYTE *ikm, DWORD ikm_len,
                       const BYTE *info, DWORD info_len,
                       BYTE *okm, DWORD okm_len);
void spec_x25519_scalarmult(BYTE out[32], const BYTE scalar[32], const BYTE point[32]);
BOOL spec_aead_encrypt(const BYTE key[32], const BYTE nonce[12],
                        const BYTE *plaintext, DWORD pt_len,
                        const BYTE *aad, DWORD aad_len,
                        BYTE *ciphertext, BYTE tag[16]);
BOOL spec_aead_decrypt(const BYTE key[32], const BYTE nonce[12],
                        const BYTE *ciphertext, DWORD ct_len,
                        const BYTE *aad, DWORD aad_len,
                        BYTE *plaintext, const BYTE tag[16]);
BOOL spec_ed25519_verify(const BYTE public_key[32], const BYTE *message,
                          DWORD message_len, const BYTE signature[64]);
void spec_sha512(const BYTE *data, DWORD len, BYTE digest[64]);

/* Include bus.h after all type stubs */
#include "bus.h"

/* ------------------------------------------------------------------ */
/*  Test helpers                                                        */
/* ------------------------------------------------------------------ */

static int g_tests_passed = 0;
static int g_tests_total = 0;

/* Static context that persists across test functions */
static IMPLANT_CONTEXT g_test_ctx;

static void check(int condition, const char *label) {
    g_tests_total++;
    if (condition) {
        g_tests_passed++;
        printf("  [PASS] %s\n", label);
    } else {
        printf("  [FAIL] %s\n", label);
    }
}

/* ------------------------------------------------------------------ */
/*  Test 1: modmgr_init                                                 */
/* ------------------------------------------------------------------ */

static void test_modmgr_init(void) {
    printf("\n--- test_modmgr_init ---\n");

    memset(&g_test_ctx, 0, sizeof(g_test_ctx));
    g_test_ctx.running = TRUE;

    /* First init bus so module_bus is set */
    bus_init(&g_test_ctx);

    /* Init guardian */
    guardian_init(&g_test_ctx);

    /* Init module manager */
    NTSTATUS status = modmgr_init(&g_test_ctx);
    check(NT_SUCCESS(status), "modmgr_init returns STATUS_SUCCESS");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();
    check(mgr != NULL, "modmgr_test_get_manager returns non-NULL");
    check(mgr->initialized == TRUE, "manager is initialized");
    check(mgr->active_count == 0, "active_count starts at 0");
    check(mgr->next_module_id == 1, "next_module_id starts at 1");
    check(mgr->implant_ctx == &g_test_ctx, "implant_ctx points to ctx");

    /* Init with NULL should fail */
    NTSTATUS bad = modmgr_init(NULL);
    check(bad == STATUS_INVALID_PARAMETER, "modmgr_init(NULL) fails");
}

/* ------------------------------------------------------------------ */
/*  Test 2: modmgr_execute with bad inputs                              */
/* ------------------------------------------------------------------ */

static void test_modmgr_execute_bad_inputs(void) {
    printf("\n--- test_modmgr_execute_bad_inputs ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    /* NULL package */
    int result = modmgr_execute(mgr, NULL, 100);
    check(result == -1, "modmgr_execute(NULL package) returns -1");

    /* Zero length */
    BYTE dummy[4] = {0};
    result = modmgr_execute(mgr, dummy, 0);
    check(result == -1, "modmgr_execute(len=0) returns -1");

    /* Too-short package (bad header) */
    result = modmgr_execute(mgr, dummy, 4);
    check(result == -1, "modmgr_execute(short package) returns -1");

    /* NULL manager */
    result = modmgr_execute(NULL, dummy, 4);
    check(result == -1, "modmgr_execute(NULL mgr) returns -1");
}

/* ------------------------------------------------------------------ */
/*  Test 3: modmgr_execute with valid PIC-like package (TEST_BUILD)     */
/* ------------------------------------------------------------------ */

static void test_modmgr_execute_pic(void) {
    printf("\n--- test_modmgr_execute_pic ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    /* Build a fake PIC module package for TEST_BUILD mode.
     * In TEST_BUILD, crypto is skipped — the data after the header
     * is treated as plaintext.
     *
     * PIC blob needs: [8B api ptr slot][code...]
     * Minimum 16 bytes. Use a simple fake blob. */
    BYTE pic_blob[64];
    memset(pic_blob, 0xCC, sizeof(pic_blob));
    memset(pic_blob, 0, 8);

    /* Build MODULE_PACKAGE_HDR */
    DWORD total_len = sizeof(MODULE_PACKAGE_HDR) + sizeof(pic_blob);
    BYTE *package = (BYTE *)malloc(total_len);
    memset(package, 0, total_len);

    MODULE_PACKAGE_HDR *hdr = (MODULE_PACKAGE_HDR *)package;
    hdr->magic = 0x43455053;  /* "SPEC" */
    hdr->version = 1;
    hdr->module_type = 0;     /* MODULE_TYPE_PIC */
    hdr->encrypted_size = sizeof(pic_blob);

    memcpy(package + sizeof(MODULE_PACKAGE_HDR), pic_blob, sizeof(pic_blob));

    /* Execute — in TEST_BUILD, loader_load_pic uses bus API's mem_alloc
     * which stubs to NULL in test mode, so this will fail at the load step. */
    int slot = modmgr_execute(mgr, package, total_len);

    check(slot == -1, "modmgr_execute PIC fails gracefully when mem_alloc unavailable");
    check(mgr->active_count == 0, "active_count unchanged after failed load");

    free(package);
}

/* ------------------------------------------------------------------ */
/*  Test 4: modmgr_poll with no active modules                          */
/* ------------------------------------------------------------------ */

static void test_modmgr_poll_empty(void) {
    printf("\n--- test_modmgr_poll_empty ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    BYTE results[256];
    DWORD results_len = sizeof(results);

    DWORD finished = modmgr_poll(mgr, results, &results_len);
    check(finished == 0, "modmgr_poll returns 0 with no active modules");
    check(results_len == 0, "results_len is 0 with no active modules");

    /* Poll with NULL results buffer */
    finished = modmgr_poll(mgr, NULL, NULL);
    check(finished == 0, "modmgr_poll(NULL results) returns 0");

    /* Poll with NULL manager */
    finished = modmgr_poll(NULL, results, &results_len);
    check(finished == 0, "modmgr_poll(NULL mgr) returns 0");
}

/* ------------------------------------------------------------------ */
/*  Test 5: modmgr_cleanup on empty slot                                */
/* ------------------------------------------------------------------ */

static void test_modmgr_cleanup_empty(void) {
    printf("\n--- test_modmgr_cleanup_empty ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    modmgr_cleanup(mgr, 0);
    check(1, "modmgr_cleanup(empty slot) does not crash");

    modmgr_cleanup(mgr, 99);
    check(1, "modmgr_cleanup(out of range) does not crash");

    modmgr_cleanup(NULL, 0);
    check(1, "modmgr_cleanup(NULL mgr) does not crash");
}

/* ------------------------------------------------------------------ */
/*  Test 6: modmgr_poll with simulated completed module                 */
/* ------------------------------------------------------------------ */

static void test_modmgr_poll_completed(void) {
    printf("\n--- test_modmgr_poll_completed ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    /* Manually set up a slot as if a module was loaded and completed */
    LOADED_MODULE *mod = &mgr->slots[0];
    memset(mod, 0, sizeof(LOADED_MODULE));
    mod->module_id = 42;
    mod->module_type = MODULE_TYPE_PIC;
    mod->status = MODULE_STATUS_COMPLETED;
    mod->memory_base = NULL;
    mod->memory_size = 0;
    mod->output_ring = &mgr->output_rings[0];
    mod->bus_api = &mgr->slot_apis[0];
    mgr->active_count = 1;

    /* Write some test output to the ring */
    output_reset(&mgr->output_rings[0]);

    BYTE test_key[32], test_nonce[12];
    memset(test_key, 0xAA, 32);
    memset(test_nonce, 0xBB, 12);
    bus_test_set_ring_key(&mgr->output_rings[0], test_key, test_nonce);

    const char *test_output = "Hello from module";
    output_write(&mgr->output_rings[0], (const BYTE *)test_output,
                 (DWORD)strlen(test_output), OUTPUT_TEXT);

    /* Poll should find the completed module and drain output */
    BYTE results[512];
    DWORD results_len = sizeof(results);

    DWORD finished = modmgr_poll(mgr, results, &results_len);
    check(finished == 1, "modmgr_poll finds 1 completed module");
    check(results_len > 0, "results contain drained output");

    /* Parse the result header: [4B module_id][4B status][4B output_len] */
    if (results_len >= 12) {
        DWORD result_mod_id, result_status, result_output_len;
        memcpy(&result_mod_id, results, 4);
        memcpy(&result_status, results + 4, 4);
        memcpy(&result_output_len, results + 8, 4);

        check(result_mod_id == 42, "result module_id matches");
        check(result_status == MODULE_STATUS_COMPLETED, "result status is COMPLETED");
        check(result_output_len == strlen(test_output), "output length matches");

        if (result_output_len > 0 && results_len >= 12 + result_output_len) {
            check(memcmp(results + 12, test_output, result_output_len) == 0,
                  "drained output matches written data");
        }
    }

    check(mod->status == MODULE_STATUS_WIPED, "slot is WIPED after poll+cleanup");
    check(mgr->active_count == 0, "active_count is 0 after cleanup");
}

/* ------------------------------------------------------------------ */
/*  Test 7: modmgr_poll with simulated crashed module                   */
/* ------------------------------------------------------------------ */

static void test_modmgr_poll_crashed(void) {
    printf("\n--- test_modmgr_poll_crashed ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    LOADED_MODULE *mod = &mgr->slots[2];
    memset(mod, 0, sizeof(LOADED_MODULE));
    mod->module_id = 99;
    mod->module_type = MODULE_TYPE_COFF;
    mod->status = MODULE_STATUS_CRASHED;
    mod->memory_base = NULL;
    mod->memory_size = 0;
    mod->output_ring = &mgr->output_rings[2];
    mod->bus_api = &mgr->slot_apis[2];
    mgr->active_count = 1;

    output_reset(&mgr->output_rings[2]);

    BYTE results[512];
    DWORD results_len = sizeof(results);

    DWORD finished = modmgr_poll(mgr, results, &results_len);
    check(finished == 1, "modmgr_poll finds 1 crashed module");

    if (results_len >= 12) {
        DWORD result_mod_id, result_status;
        memcpy(&result_mod_id, results, 4);
        memcpy(&result_status, results + 4, 4);
        check(result_mod_id == 99, "crashed module_id matches");
        check(result_status == MODULE_STATUS_CRASHED, "result status is CRASHED");
    }

    check(mod->status == MODULE_STATUS_WIPED, "crashed slot is WIPED after poll");
    check(mgr->active_count == 0, "active_count is 0 after crash cleanup");
}

/* ------------------------------------------------------------------ */
/*  Test 8: modmgr_shutdown                                             */
/* ------------------------------------------------------------------ */

static void test_modmgr_shutdown(void) {
    printf("\n--- test_modmgr_shutdown ---\n");

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    modmgr_shutdown(mgr);
    check(mgr->initialized == FALSE, "manager is uninitialized after shutdown");

    modmgr_shutdown(NULL);
    check(1, "modmgr_shutdown(NULL) does not crash");
}

/* ------------------------------------------------------------------ */
/*  Test 9: modmgr_execute rejects when all slots full                  */
/* ------------------------------------------------------------------ */

static void test_modmgr_full_slots(void) {
    printf("\n--- test_modmgr_full_slots ---\n");

    /* Re-initialize using the persistent static context */
    memset(&g_test_ctx, 0, sizeof(g_test_ctx));
    g_test_ctx.running = TRUE;
    bus_init(&g_test_ctx);
    guardian_init(&g_test_ctx);
    modmgr_init(&g_test_ctx);

    MODULE_MANAGER *mgr = modmgr_test_get_manager();

    /* Fill all slots */
    mgr->active_count = MODMGR_MAX_SLOTS;
    for (DWORD i = 0; i < MODMGR_MAX_SLOTS; i++) {
        mgr->slots[i].module_id = i + 1;
        mgr->slots[i].status = MODULE_STATUS_RUNNING;
        mgr->slots[i].memory_base = (PVOID)(ULONG_PTR)(0x1000 + i);
    }

    BYTE pic_blob[64];
    memset(pic_blob, 0, sizeof(pic_blob));
    DWORD total_len = sizeof(MODULE_PACKAGE_HDR) + sizeof(pic_blob);
    BYTE *package = (BYTE *)malloc(total_len);
    memset(package, 0, total_len);
    MODULE_PACKAGE_HDR *hdr = (MODULE_PACKAGE_HDR *)package;
    hdr->magic = 0x43455053;
    hdr->version = 1;
    hdr->module_type = 0;
    hdr->encrypted_size = sizeof(pic_blob);
    memcpy(package + sizeof(MODULE_PACKAGE_HDR), pic_blob, sizeof(pic_blob));

    int result = modmgr_execute(mgr, package, total_len);
    check(result == -1, "modmgr_execute returns -1 when all slots full");

    free(package);

    /* Clean up */
    for (DWORD i = 0; i < MODMGR_MAX_SLOTS; i++) {
        memset(&mgr->slots[i], 0, sizeof(LOADED_MODULE));
    }
    mgr->active_count = 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("SPECTER — Module Lifecycle Manager Test Suite\n");
    printf("=============================================\n");

    test_modmgr_init();
    test_modmgr_execute_bad_inputs();
    test_modmgr_execute_pic();
    test_modmgr_poll_empty();
    test_modmgr_cleanup_empty();
    test_modmgr_poll_completed();
    test_modmgr_poll_crashed();
    test_modmgr_shutdown();
    test_modmgr_full_slots();

    printf("\n=============================================\n");
    printf("Results: %d/%d passed\n", g_tests_passed, g_tests_total);

    return (g_tests_passed == g_tests_total) ? 0 : 1;
}
