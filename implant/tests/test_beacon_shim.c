/**
 * SPECTER Implant — Beacon API Shim Test Suite
 *
 * Tests BeaconDataParse/Extract/Int/Short roundtrip,
 * BeaconFormatAlloc/Append/ToString, and symbol table completeness.
 *
 * Build: gcc -o test_beacon_shim test_beacon_shim.c
 *            ../core/src/bus/beacon_shim.c ../core/src/string.c
 *            -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Include project headers directly — no stub type definitions needed
 * since specter.h, bus.h, and beacon.h provide everything.
 */
#include "specter.h"
#include "bus.h"
#include "beacon.h"

/* Global context required by specter.h extern */
IMPLANT_CONTEXT g_ctx;

/* ------------------------------------------------------------------ */
/*  CRT-free function stubs (delegate to libc for tests)               */
/* ------------------------------------------------------------------ */

DWORD spec_djb2_hash(const char *str) {
    DWORD h = 5381; int c;
    while ((c = *str++)) {
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + c;
    }
    return h;
}
DWORD spec_djb2_hash_w(const WCHAR *str) { (void)str; return 0; }

/* PEB stubs */
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD h) { (void)h; return NULL; }
PVOID find_export_by_hash(PVOID m, DWORD h) { (void)m; (void)h; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* ------------------------------------------------------------------ */
/*  Mock bus API implementations for testing                           */
/* ------------------------------------------------------------------ */

static char    g_output_buf[4096];
static int     g_output_len = 0;
static DWORD   g_output_type = 0;

static BOOL mock_output(const BYTE *data, DWORD len, DWORD type) {
    if (g_output_len + (int)len < (int)sizeof(g_output_buf)) {
        memcpy(g_output_buf + g_output_len, data, len);
        g_output_len += (int)len;
    }
    g_output_type = type;
    return TRUE;
}

static PVOID mock_mem_alloc(SIZE_T size, DWORD perms) {
    (void)perms;
    return malloc((size_t)size);
}

static BOOL mock_mem_free(PVOID ptr) {
    free(ptr);
    return TRUE;
}

static BOOL mock_mem_protect(PVOID ptr, SIZE_T size, DWORD perms) {
    (void)ptr; (void)size; (void)perms;
    return TRUE;
}

static BOOL mock_token_impersonate(HANDLE h) { (void)h; return TRUE; }
static BOOL mock_token_revert(void) { return TRUE; }
static PVOID mock_resolve(const char *dll, const char *func) { (void)dll; (void)func; return NULL; }
static void mock_log(DWORD level, const char *msg) { (void)level; (void)msg; }

/* Stubs for unused bus functions */
static HANDLE stub_net_connect(const char *a, DWORD b, DWORD c) { (void)a;(void)b;(void)c; return NULL; }
static BOOL stub_net_send(HANDLE h, const BYTE *d, DWORD l) { (void)h;(void)d;(void)l; return FALSE; }
static DWORD stub_net_recv(HANDLE h, BYTE *d, DWORD l) { (void)h;(void)d;(void)l; return 0; }
static BOOL stub_net_close(HANDLE h) { (void)h; return FALSE; }
static HANDLE stub_proc_open(DWORD p, DWORD a) { (void)p;(void)a; return NULL; }
static BOOL stub_proc_read(HANDLE h, PVOID a, BYTE *b, DWORD l) { (void)h;(void)a;(void)b;(void)l; return FALSE; }
static BOOL stub_proc_write(HANDLE h, PVOID a, const BYTE *b, DWORD l) { (void)h;(void)a;(void)b;(void)l; return FALSE; }
static BOOL stub_proc_close(HANDLE h) { (void)h; return FALSE; }
static HANDLE stub_thread_create(PVOID f, PVOID p, BOOL s) { (void)f;(void)p;(void)s; return NULL; }
static BOOL stub_thread_resume(HANDLE h) { (void)h; return FALSE; }
static BOOL stub_thread_terminate(HANDLE h) { (void)h; return FALSE; }
static HANDLE stub_token_steal(DWORD p) { (void)p; return NULL; }
static HANDLE stub_token_make(const char *u, const char *p, const char *d) { (void)u;(void)p;(void)d; return NULL; }
static DWORD stub_file_read(const char *p, BYTE *b, DWORD l) { (void)p;(void)b;(void)l; return 0; }
static BOOL stub_file_write(const char *p, const BYTE *d, DWORD l) { (void)p;(void)d;(void)l; return FALSE; }
static BOOL stub_file_delete(const char *p) { (void)p; return FALSE; }
static PVOID stub_file_list(const char *p) { (void)p; return NULL; }
static DWORD stub_reg_read(DWORD h, const char *p, const char *v) { (void)h;(void)p;(void)v; return 0; }
static BOOL stub_reg_write(DWORD h, const char *p, const char *v, const BYTE *d, DWORD t) { (void)h;(void)p;(void)v;(void)d;(void)t; return FALSE; }
static BOOL stub_reg_delete(DWORD h, const char *p, const char *v) { (void)h;(void)p;(void)v; return FALSE; }

static MODULE_BUS_API g_mock_api;

static void setup_mock_api(void) {
    memset(&g_mock_api, 0, sizeof(g_mock_api));
    g_mock_api.mem_alloc        = mock_mem_alloc;
    g_mock_api.mem_free         = mock_mem_free;
    g_mock_api.mem_protect      = mock_mem_protect;
    g_mock_api.net_connect      = stub_net_connect;
    g_mock_api.net_send         = stub_net_send;
    g_mock_api.net_recv         = stub_net_recv;
    g_mock_api.net_close        = stub_net_close;
    g_mock_api.proc_open        = stub_proc_open;
    g_mock_api.proc_read        = stub_proc_read;
    g_mock_api.proc_write       = stub_proc_write;
    g_mock_api.proc_close       = stub_proc_close;
    g_mock_api.thread_create    = stub_thread_create;
    g_mock_api.thread_resume    = stub_thread_resume;
    g_mock_api.thread_terminate = stub_thread_terminate;
    g_mock_api.token_steal      = stub_token_steal;
    g_mock_api.token_impersonate = mock_token_impersonate;
    g_mock_api.token_revert     = mock_token_revert;
    g_mock_api.token_make       = stub_token_make;
    g_mock_api.file_read        = stub_file_read;
    g_mock_api.file_write       = stub_file_write;
    g_mock_api.file_delete      = stub_file_delete;
    g_mock_api.file_list        = stub_file_list;
    g_mock_api.reg_read         = stub_reg_read;
    g_mock_api.reg_write        = stub_reg_write;
    g_mock_api.reg_delete       = stub_reg_delete;
    g_mock_api.output           = mock_output;
    g_mock_api.resolve          = mock_resolve;
    g_mock_api.log              = mock_log;

    beacon_shim_init(&g_mock_api);
    g_output_len = 0;
    g_output_type = 0;
    memset(g_output_buf, 0, sizeof(g_output_buf));
}

/* ------------------------------------------------------------------ */
/*  Test framework                                                     */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

static void check(const char *name, int condition) {
    tests_run++;
    if (condition) {
        tests_passed++;
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
    }
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconDataParse / Int / Short roundtrip                      */
/* ------------------------------------------------------------------ */

static void test_data_parse_int_short(void) {
    printf("\n--- BeaconDataParse / Int / Short roundtrip ---\n");
    setup_mock_api();

    /* Build a test buffer with big-endian values:
     * int(0x12345678) + short(0x1234) + int(0xDEADBEEF)
     */
    unsigned char buf[10];
    buf[0] = 0x12; buf[1] = 0x34; buf[2] = 0x56; buf[3] = 0x78;
    buf[4] = 0x12; buf[5] = 0x34;
    buf[6] = 0xDE; buf[7] = 0xAD; buf[8] = 0xBE; buf[9] = 0xEF;

    datap parser;
    BeaconDataParse(&parser, (char *)buf, sizeof(buf));

    check("parser length is 10", parser.length == 10);
    check("parser size is 10",   parser.size == 10);

    int val1 = BeaconDataInt(&parser);
    check("first int is 0x12345678", val1 == 0x12345678);
    check("remaining after int is 6", BeaconDataLength(&parser) == 6);

    short val2 = BeaconDataShort(&parser);
    check("short is 0x1234", val2 == 0x1234);
    check("remaining after short is 4", BeaconDataLength(&parser) == 4);

    int val3 = BeaconDataInt(&parser);
    check("second int is 0xDEADBEEF", val3 == (int)0xDEADBEEF);
    check("remaining after all reads is 0", BeaconDataLength(&parser) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconDataExtract                                            */
/* ------------------------------------------------------------------ */

static void test_data_extract(void) {
    printf("\n--- BeaconDataExtract ---\n");
    setup_mock_api();

    unsigned char buf[9];
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x05;
    buf[4] = 'H'; buf[5] = 'e'; buf[6] = 'l'; buf[7] = 'l'; buf[8] = 'o';

    datap parser;
    BeaconDataParse(&parser, (char *)buf, sizeof(buf));

    int out_len = 0;
    char *data = BeaconDataExtract(&parser, &out_len);

    check("extract returns non-NULL", data != NULL);
    check("extract length is 5", out_len == 5);
    check("extracted data is Hello", data && memcmp(data, "Hello", 5) == 0);
    check("remaining is 0", BeaconDataLength(&parser) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconDataInt/Short underflow                                */
/* ------------------------------------------------------------------ */

static void test_data_underflow(void) {
    printf("\n--- BeaconData underflow ---\n");
    setup_mock_api();

    unsigned char buf[2] = {0x12, 0x34};
    datap parser;
    BeaconDataParse(&parser, (char *)buf, 2);

    int val = BeaconDataInt(&parser);
    check("int from 2 bytes returns 0", val == 0);
    check("size unchanged after failed read", parser.size == 2);

    short sv = BeaconDataShort(&parser);
    check("short from 2 bytes works", sv == 0x1234);
    check("remaining is 0", BeaconDataLength(&parser) == 0);

    short sv2 = BeaconDataShort(&parser);
    check("short from empty returns 0", sv2 == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconFormatAlloc / Append / ToString                        */
/* ------------------------------------------------------------------ */

static void test_format_alloc_append_tostring(void) {
    printf("\n--- BeaconFormatAlloc / Append / ToString ---\n");
    setup_mock_api();

    formatp fmt;
    BeaconFormatAlloc(&fmt, 256);
    check("format alloc succeeded", fmt.original != NULL);
    check("format size is 256", fmt.size == 256);
    check("format length is 0", fmt.length == 0);

    BeaconFormatAppend(&fmt, "Hello", 5);
    check("length after append is 5", fmt.length == 5);

    BeaconFormatAppend(&fmt, " World", 6);
    check("length after second append is 11", fmt.length == 11);

    int out_len = 0;
    char *str = BeaconFormatToString(&fmt, &out_len);
    check("toString returns non-NULL", str != NULL);
    check("toString length is 11", out_len == 11);
    check("toString content correct", str && memcmp(str, "Hello World", 11) == 0);

    BeaconFormatFree(&fmt);
    check("format freed (original is NULL)", fmt.original == NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconFormatReset                                            */
/* ------------------------------------------------------------------ */

static void test_format_reset(void) {
    printf("\n--- BeaconFormatReset ---\n");
    setup_mock_api();

    formatp fmt;
    BeaconFormatAlloc(&fmt, 128);
    BeaconFormatAppend(&fmt, "data", 4);
    check("length is 4 before reset", fmt.length == 4);

    BeaconFormatReset(&fmt);
    check("length is 0 after reset", fmt.length == 0);
    check("buffer is back to original", fmt.buffer == fmt.original);

    BeaconFormatAppend(&fmt, "new", 3);
    int len;
    char *s = BeaconFormatToString(&fmt, &len);
    check("content is 'new' after reset+append", s && memcmp(s, "new", 3) == 0);

    BeaconFormatFree(&fmt);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconFormatInt                                              */
/* ------------------------------------------------------------------ */

static void test_format_int(void) {
    printf("\n--- BeaconFormatInt ---\n");
    setup_mock_api();

    formatp fmt;
    BeaconFormatAlloc(&fmt, 64);

    BeaconFormatInt(&fmt, 0x41424344);
    check("length is 4 after FormatInt", fmt.length == 4);

    int len;
    char *data = BeaconFormatToString(&fmt, &len);
    check("big-endian byte 0 is 0x41", data && (unsigned char)data[0] == 0x41);
    check("big-endian byte 1 is 0x42", data && (unsigned char)data[1] == 0x42);
    check("big-endian byte 2 is 0x43", data && (unsigned char)data[2] == 0x43);
    check("big-endian byte 3 is 0x44", data && (unsigned char)data[3] == 0x44);

    BeaconFormatFree(&fmt);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconOutput sends to bus                                    */
/* ------------------------------------------------------------------ */

static void test_beacon_output(void) {
    printf("\n--- BeaconOutput ---\n");
    setup_mock_api();

    BeaconOutput(CALLBACK_OUTPUT, "test output", 11);
    check("output length is 11", g_output_len == 11);
    check("output content correct", memcmp(g_output_buf, "test output", 11) == 0);
    check("output type is TEXT", g_output_type == OUTPUT_TEXT);

    g_output_len = 0;
    BeaconOutput(CALLBACK_ERROR, "error!", 6);
    check("error output type is ERROR", g_output_type == OUTPUT_ERROR);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconPrintf formatting                                      */
/* ------------------------------------------------------------------ */

static void test_beacon_printf(void) {
    printf("\n--- BeaconPrintf ---\n");
    setup_mock_api();

    BeaconPrintf(CALLBACK_OUTPUT, "hello %s %d", "world", 42);
    check("printf output length > 0", g_output_len > 0);

    g_output_buf[g_output_len] = '\0';
    check("printf output is 'hello world 42'",
          strcmp(g_output_buf, "hello world 42") == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconUseToken / RevertToken                                 */
/* ------------------------------------------------------------------ */

static void test_token_functions(void) {
    printf("\n--- Token functions ---\n");
    setup_mock_api();

    BOOL result = BeaconUseToken((HANDLE)0x1234);
    check("BeaconUseToken returns TRUE (mock)", result == TRUE);

    BeaconRevertToken();
    check("BeaconRevertToken completes", 1);
}

/* ------------------------------------------------------------------ */
/*  Test: toWideChar                                                   */
/* ------------------------------------------------------------------ */

static void test_to_wide_char(void) {
    printf("\n--- toWideChar ---\n");
    setup_mock_api();

    WCHAR wide[32];
    memset(wide, 0, sizeof(wide));
    int count = toWideChar("ABC", wide, 32);

    check("toWideChar returns 3", count == 3);
    check("wide[0] is 'A'", wide[0] == L'A');
    check("wide[1] is 'B'", wide[1] == L'B');
    check("wide[2] is 'C'", wide[2] == L'C');
    check("wide[3] is null", wide[3] == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: BeaconGetSpawnTo                                             */
/* ------------------------------------------------------------------ */

static void test_get_spawn_to(void) {
    printf("\n--- BeaconGetSpawnTo ---\n");
    setup_mock_api();

    int len = 0;
    char *path64 = BeaconGetSpawnTo(FALSE, &len);
    check("x64 spawn-to non-NULL", path64 != NULL);
    check("x64 spawn-to length > 0", len > 0);
    check("x64 spawn-to contains System32", path64 && strstr(path64, "System32") != NULL);

    int len86 = 0;
    char *path86 = BeaconGetSpawnTo(TRUE, &len86);
    check("x86 spawn-to non-NULL", path86 != NULL);
    check("x86 spawn-to contains SysWOW64", path86 && strstr(path86, "SysWOW64") != NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: Symbol table completeness                                    */
/* ------------------------------------------------------------------ */

static void test_symbol_table_completeness(void) {
    printf("\n--- Symbol table completeness ---\n");
    setup_mock_api();

    DWORD count = 0;
    BEACON_API_ENTRY *table = beacon_shim_get_table(&count);

    check("symbol table non-NULL", table != NULL);
    check("symbol table has entries", count > 0);

    const char *required[] = {
        "BeaconOutput", "BeaconPrintf",
        "BeaconDataParse", "BeaconDataInt", "BeaconDataShort",
        "BeaconDataLength", "BeaconDataExtract",
        "BeaconFormatAlloc", "BeaconFormatReset", "BeaconFormatAppend",
        "BeaconFormatPrintf", "BeaconFormatToString", "BeaconFormatFree",
        "BeaconFormatInt",
        "BeaconUseToken", "BeaconRevertToken",
        "BeaconIsAdmin", "BeaconGetSpawnTo", "toWideChar",
        NULL
    };

    for (int i = 0; required[i] != NULL; i++) {
        int found = 0;
        for (DWORD j = 0; j < count; j++) {
            if (strcmp(table[j].name, required[i]) == 0 &&
                table[j].address != NULL) {
                found = 1;
                break;
            }
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "symbol '%s' present with non-NULL address",
                 required[i]);
        check(msg, found);
    }
}

/* ------------------------------------------------------------------ */
/*  Test: NULL safety                                                  */
/* ------------------------------------------------------------------ */

static void test_null_safety(void) {
    printf("\n--- NULL safety ---\n");

    beacon_shim_init(NULL);

    BeaconOutput(CALLBACK_OUTPUT, "test", 4);
    check("BeaconOutput with NULL bus doesn't crash", 1);

    BeaconPrintf(CALLBACK_OUTPUT, "test %d", 42);
    check("BeaconPrintf with NULL bus doesn't crash", 1);

    BeaconDataParse(NULL, "buf", 3);
    check("BeaconDataParse(NULL) doesn't crash", 1);

    check("BeaconDataInt(NULL) returns 0", BeaconDataInt(NULL) == 0);
    check("BeaconDataShort(NULL) returns 0", BeaconDataShort(NULL) == 0);
    check("BeaconDataLength(NULL) returns 0", BeaconDataLength(NULL) == 0);

    int out_len;
    check("BeaconDataExtract(NULL) returns NULL", BeaconDataExtract(NULL, &out_len) == NULL);

    formatp fmt;
    memset(&fmt, 0, sizeof(fmt));
    BeaconFormatAlloc(&fmt, 64);
    check("FormatAlloc with NULL bus sets original NULL", fmt.original == NULL);

    BeaconFormatFree(NULL);
    check("FormatFree(NULL) doesn't crash", 1);

    check("BeaconUseToken with NULL bus returns FALSE", BeaconUseToken((HANDLE)0x1) == FALSE);

    BeaconRevertToken();
    check("BeaconRevertToken with NULL bus doesn't crash", 1);

    check("BeaconIsAdmin with NULL bus returns FALSE", BeaconIsAdmin() == FALSE);

    check("toWideChar(NULL) returns 0", toWideChar(NULL, NULL, 0) == 0);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Beacon API Shim Tests ===\n");

    test_data_parse_int_short();
    test_data_extract();
    test_data_underflow();
    test_format_alloc_append_tostring();
    test_format_reset();
    test_format_int();
    test_beacon_output();
    test_beacon_printf();
    test_token_functions();
    test_to_wide_char();
    test_get_spawn_to();
    test_symbol_table_completeness();
    test_null_safety();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
