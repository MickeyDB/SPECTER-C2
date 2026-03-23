/**
 * SPECTER Implant — Extended BOF API, CLR, and Inline Shellcode Tests
 *
 * Tests SPECTER_* extension functions, CLR hosting API, and
 * exec_shellcode memory management.
 *
 * Build: gcc -o test_extended_bof test_extended_bof.c
 *            ../core/src/bus/beacon_shim.c ../core/src/bus/clr.c
 *            ../core/src/bus/inline_asm.c ../core/src/string.c
 *            -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
/*  Mock bus API — tracking calls                                      */
/* ------------------------------------------------------------------ */

static char    g_output_buf[4096];
static int     g_output_len = 0;
static DWORD   g_output_type = 0;

/* Track mem_alloc calls */
static int     g_alloc_count = 0;
static SIZE_T  g_last_alloc_size = 0;
static DWORD   g_last_alloc_perms = 0;

/* Track mem_protect calls */
static int     g_protect_count = 0;
static DWORD   g_last_protect_perms = 0;

/* Track mem_free calls */
static int     g_free_count = 0;

/* Track net_connect calls */
static int     g_net_connect_count = 0;
static char    g_last_connect_addr[256];
static DWORD   g_last_connect_port = 0;

/* Track proc_open calls */
static int     g_proc_open_count = 0;
static DWORD   g_last_proc_pid = 0;
static DWORD   g_last_proc_access = 0;

/* Track file_read calls */
static int     g_file_read_count = 0;
static char    g_last_file_path[256];

/* Track resolve calls */
static int     g_resolve_count = 0;
static char    g_last_resolve_dll[128];
static char    g_last_resolve_func[128];

/* Track log calls */
static int     g_log_count = 0;
static DWORD   g_last_log_level = 0;
static char    g_last_log_msg[512];

static BOOL mock_output(const BYTE *data, DWORD len, DWORD type) {
    if (g_output_len + (int)len < (int)sizeof(g_output_buf)) {
        memcpy(g_output_buf + g_output_len, data, len);
        g_output_len += (int)len;
    }
    g_output_type = type;
    return TRUE;
}

static PVOID mock_mem_alloc(SIZE_T size, DWORD perms) {
    g_alloc_count++;
    g_last_alloc_size = size;
    g_last_alloc_perms = perms;
    return malloc((size_t)size);
}

static BOOL mock_mem_free(PVOID ptr) {
    g_free_count++;
    free(ptr);
    return TRUE;
}

static BOOL mock_mem_protect(PVOID ptr, SIZE_T size, DWORD perms) {
    (void)ptr; (void)size;
    g_protect_count++;
    g_last_protect_perms = perms;
    return TRUE;
}

static HANDLE mock_net_connect(const char *addr, DWORD port, DWORD proto) {
    (void)proto;
    g_net_connect_count++;
    if (addr) {
        size_t len = strlen(addr);
        if (len >= sizeof(g_last_connect_addr)) len = sizeof(g_last_connect_addr) - 1;
        memcpy(g_last_connect_addr, addr, len);
        g_last_connect_addr[len] = '\0';
    }
    g_last_connect_port = port;
    return (HANDLE)(ULONG_PTR)0xC0DE;
}

static HANDLE mock_proc_open(DWORD pid, DWORD access) {
    g_proc_open_count++;
    g_last_proc_pid = pid;
    g_last_proc_access = access;
    return (HANDLE)(ULONG_PTR)0xBEEF;
}

static DWORD mock_file_read(const char *path, BYTE *buf, DWORD len) {
    g_file_read_count++;
    if (path) {
        size_t plen = strlen(path);
        if (plen >= sizeof(g_last_file_path)) plen = sizeof(g_last_file_path) - 1;
        memcpy(g_last_file_path, path, plen);
        g_last_file_path[plen] = '\0';
    }
    (void)buf; (void)len;
    return 0;
}

static PVOID mock_resolve(const char *dll, const char *func) {
    g_resolve_count++;
    if (dll) {
        size_t len = strlen(dll);
        if (len >= sizeof(g_last_resolve_dll)) len = sizeof(g_last_resolve_dll) - 1;
        memcpy(g_last_resolve_dll, dll, len);
        g_last_resolve_dll[len] = '\0';
    }
    if (func) {
        size_t len = strlen(func);
        if (len >= sizeof(g_last_resolve_func)) len = sizeof(g_last_resolve_func) - 1;
        memcpy(g_last_resolve_func, func, len);
        g_last_resolve_func[len] = '\0';
    }
    return NULL;
}

static void mock_log(DWORD level, const char *msg) {
    g_log_count++;
    g_last_log_level = level;
    if (msg) {
        size_t len = strlen(msg);
        if (len >= sizeof(g_last_log_msg)) len = sizeof(g_last_log_msg) - 1;
        memcpy(g_last_log_msg, msg, len);
        g_last_log_msg[len] = '\0';
    }
}

/* Unused stubs */
static BOOL stub_net_send(HANDLE h, const BYTE *d, DWORD l) { (void)h;(void)d;(void)l; return FALSE; }
static DWORD stub_net_recv(HANDLE h, BYTE *d, DWORD l) { (void)h;(void)d;(void)l; return 0; }
static BOOL stub_net_close(HANDLE h) { (void)h; return FALSE; }
static BOOL stub_proc_read(HANDLE h, PVOID a, BYTE *b, DWORD l) { (void)h;(void)a;(void)b;(void)l; return FALSE; }
static BOOL stub_proc_write(HANDLE h, PVOID a, const BYTE *b, DWORD l) { (void)h;(void)a;(void)b;(void)l; return FALSE; }
static BOOL stub_proc_close(HANDLE h) { (void)h; return FALSE; }
static HANDLE stub_thread_create(PVOID f, PVOID p, BOOL s) { (void)f;(void)p;(void)s; return NULL; }
static BOOL stub_thread_resume(HANDLE h) { (void)h; return FALSE; }
static BOOL stub_thread_terminate(HANDLE h) { (void)h; return FALSE; }
static HANDLE stub_token_steal(DWORD p) { (void)p; return NULL; }
static BOOL stub_token_impersonate(HANDLE h) { (void)h; return TRUE; }
static BOOL stub_token_revert(void) { return TRUE; }
static HANDLE stub_token_make(const char *u, const char *p, const char *d) { (void)u;(void)p;(void)d; return NULL; }
static BOOL stub_file_write(const char *p, const BYTE *d, DWORD l) { (void)p;(void)d;(void)l; return FALSE; }
static BOOL stub_file_delete(const char *p) { (void)p; return FALSE; }
static PVOID stub_file_list(const char *p) { (void)p; return NULL; }
static DWORD stub_reg_read(DWORD h, const char *p, const char *v) { (void)h;(void)p;(void)v; return 0; }
static BOOL stub_reg_write(DWORD h, const char *p, const char *v, const BYTE *d, DWORD t) { (void)h;(void)p;(void)v;(void)d;(void)t; return FALSE; }
static BOOL stub_reg_delete(DWORD h, const char *p, const char *v) { (void)h;(void)p;(void)v; return FALSE; }

static MODULE_BUS_API g_mock_api;

static void reset_tracking(void) {
    g_output_len = 0;
    g_output_type = 0;
    memset(g_output_buf, 0, sizeof(g_output_buf));
    g_alloc_count = 0;
    g_last_alloc_size = 0;
    g_last_alloc_perms = 0;
    g_protect_count = 0;
    g_last_protect_perms = 0;
    g_free_count = 0;
    g_net_connect_count = 0;
    memset(g_last_connect_addr, 0, sizeof(g_last_connect_addr));
    g_last_connect_port = 0;
    g_proc_open_count = 0;
    g_last_proc_pid = 0;
    g_last_proc_access = 0;
    g_file_read_count = 0;
    memset(g_last_file_path, 0, sizeof(g_last_file_path));
    g_resolve_count = 0;
    memset(g_last_resolve_dll, 0, sizeof(g_last_resolve_dll));
    memset(g_last_resolve_func, 0, sizeof(g_last_resolve_func));
    g_log_count = 0;
    g_last_log_level = 0;
    memset(g_last_log_msg, 0, sizeof(g_last_log_msg));
}

static void setup_mock_api(void) {
    memset(&g_mock_api, 0, sizeof(g_mock_api));
    g_mock_api.mem_alloc        = mock_mem_alloc;
    g_mock_api.mem_free         = mock_mem_free;
    g_mock_api.mem_protect      = mock_mem_protect;
    g_mock_api.net_connect      = mock_net_connect;
    g_mock_api.net_send         = stub_net_send;
    g_mock_api.net_recv         = stub_net_recv;
    g_mock_api.net_close        = stub_net_close;
    g_mock_api.proc_open        = mock_proc_open;
    g_mock_api.proc_read        = stub_proc_read;
    g_mock_api.proc_write       = stub_proc_write;
    g_mock_api.proc_close       = stub_proc_close;
    g_mock_api.thread_create    = stub_thread_create;
    g_mock_api.thread_resume    = stub_thread_resume;
    g_mock_api.thread_terminate = stub_thread_terminate;
    g_mock_api.token_steal      = stub_token_steal;
    g_mock_api.token_impersonate = stub_token_impersonate;
    g_mock_api.token_revert     = stub_token_revert;
    g_mock_api.token_make       = stub_token_make;
    g_mock_api.file_read        = mock_file_read;
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
    reset_tracking();
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
/*  Test: SPECTER_MemAlloc                                             */
/* ------------------------------------------------------------------ */

static void test_specter_memalloc(void) {
    printf("\n--- SPECTER_MemAlloc ---\n");
    setup_mock_api();

    PVOID ptr = SPECTER_MemAlloc(256);
    check("SPECTER_MemAlloc returns non-NULL", ptr != NULL);
    check("mem_alloc was called", g_alloc_count == 1);
    check("alloc size is 256", g_last_alloc_size == 256);
    check("alloc perms is PAGE_READWRITE", g_last_alloc_perms == PAGE_READWRITE);

    if (ptr) free(ptr);
}

static void test_specter_memalloc_null_bus(void) {
    printf("\n--- SPECTER_MemAlloc NULL bus ---\n");
    beacon_shim_init(NULL);

    PVOID ptr = SPECTER_MemAlloc(64);
    check("SPECTER_MemAlloc with NULL bus returns NULL", ptr == NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: SPECTER_Resolve                                              */
/* ------------------------------------------------------------------ */

static void test_specter_resolve(void) {
    printf("\n--- SPECTER_Resolve ---\n");
    setup_mock_api();

    PVOID result = SPECTER_Resolve("kernel32.dll", "CreateFileW");
    /* Mock returns NULL, but we check the call was made */
    check("resolve was called", g_resolve_count == 1);
    check("resolve dll is kernel32.dll",
          strcmp(g_last_resolve_dll, "kernel32.dll") == 0);
    check("resolve func is CreateFileW",
          strcmp(g_last_resolve_func, "CreateFileW") == 0);
    check("result is NULL (mock)", result == NULL);
}

static void test_specter_resolve_null_args(void) {
    printf("\n--- SPECTER_Resolve NULL args ---\n");
    setup_mock_api();

    check("NULL dll returns NULL", SPECTER_Resolve(NULL, "func") == NULL);
    check("NULL func returns NULL", SPECTER_Resolve("dll", NULL) == NULL);
    check("resolve not called for NULL args", g_resolve_count == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: SPECTER_NetConnect                                           */
/* ------------------------------------------------------------------ */

static void test_specter_netconnect(void) {
    printf("\n--- SPECTER_NetConnect ---\n");
    setup_mock_api();

    HANDLE h = SPECTER_NetConnect("10.0.0.1", 443);
    check("net_connect was called", g_net_connect_count == 1);
    check("connect addr is 10.0.0.1",
          strcmp(g_last_connect_addr, "10.0.0.1") == 0);
    check("connect port is 443", g_last_connect_port == 443);
    check("handle is non-NULL (mock)", h == (HANDLE)(ULONG_PTR)0xC0DE);
}

static void test_specter_netconnect_null(void) {
    printf("\n--- SPECTER_NetConnect NULL ---\n");
    setup_mock_api();

    HANDLE h = SPECTER_NetConnect(NULL, 80);
    check("NULL addr returns INVALID_HANDLE_VALUE",
          h == INVALID_HANDLE_VALUE);
    check("net_connect not called for NULL addr", g_net_connect_count == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: SPECTER_ProcOpen                                             */
/* ------------------------------------------------------------------ */

static void test_specter_procopen(void) {
    printf("\n--- SPECTER_ProcOpen ---\n");
    setup_mock_api();

    HANDLE h = SPECTER_ProcOpen(1234, 0x1FFFFF);
    check("proc_open was called", g_proc_open_count == 1);
    check("pid is 1234", g_last_proc_pid == 1234);
    check("access is 0x1FFFFF", g_last_proc_access == 0x1FFFFF);
    check("handle is non-NULL (mock)", h == (HANDLE)(ULONG_PTR)0xBEEF);
}

static void test_specter_procopen_null_bus(void) {
    printf("\n--- SPECTER_ProcOpen NULL bus ---\n");
    beacon_shim_init(NULL);

    HANDLE h = SPECTER_ProcOpen(1, 0);
    check("NULL bus returns INVALID_HANDLE_VALUE",
          h == INVALID_HANDLE_VALUE);
}

/* ------------------------------------------------------------------ */
/*  Test: SPECTER_FileRead                                             */
/* ------------------------------------------------------------------ */

static void test_specter_fileread(void) {
    printf("\n--- SPECTER_FileRead ---\n");
    setup_mock_api();

    BYTE buf[128];
    DWORD result = SPECTER_FileRead("C:\\test.txt", buf, sizeof(buf));
    check("file_read was called", g_file_read_count == 1);
    check("file path is C:\\test.txt",
          strcmp(g_last_file_path, "C:\\test.txt") == 0);
    check("result is 0 (mock returns 0)", result == 0);
}

static void test_specter_fileread_null(void) {
    printf("\n--- SPECTER_FileRead NULL ---\n");
    setup_mock_api();

    BYTE buf[32];
    check("NULL path returns 0", SPECTER_FileRead(NULL, buf, 32) == 0);
    check("NULL buf returns 0", SPECTER_FileRead("path", NULL, 32) == 0);
    check("zero len returns 0", SPECTER_FileRead("path", buf, 0) == 0);
    check("file_read not called for NULL args", g_file_read_count == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: Symbol table includes SPECTER_* entries                      */
/* ------------------------------------------------------------------ */

static void test_specter_symbol_table(void) {
    printf("\n--- SPECTER_* in symbol table ---\n");
    setup_mock_api();

    DWORD count = 0;
    BEACON_API_ENTRY *table = beacon_shim_get_table(&count);

    const char *specter_syms[] = {
        "SPECTER_MemAlloc",
        "SPECTER_Resolve",
        "SPECTER_NetConnect",
        "SPECTER_ProcOpen",
        "SPECTER_FileRead",
        NULL
    };

    for (int i = 0; specter_syms[i] != NULL; i++) {
        int found = 0;
        for (DWORD j = 0; j < count; j++) {
            if (strcmp(table[j].name, specter_syms[i]) == 0 &&
                table[j].address != NULL) {
                found = 1;
                break;
            }
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "symbol '%s' in table with non-NULL address",
                 specter_syms[i]);
        check(msg, found);
    }

    /* Verify total count includes both beacon + specter entries */
    check("total symbol count >= 23 (18 beacon + 5 specter)", count >= 23);
}

/* ------------------------------------------------------------------ */
/*  Test: exec_shellcode memory management                             */
/* ------------------------------------------------------------------ */

static void test_exec_shellcode_basic(void) {
    printf("\n--- exec_shellcode basic ---\n");
    setup_mock_api();

    /* Dummy shellcode — just NOP bytes (won't actually execute in TEST_BUILD) */
    BYTE code[] = { 0x90, 0x90, 0x90, 0x90, 0xC3 };  /* nop; nop; nop; nop; ret */

    DWORD result = exec_shellcode(&g_mock_api, code, sizeof(code));
    check("exec_shellcode returns 0", result == 0);
    check("mem_alloc was called", g_alloc_count == 1);
    check("alloc size matches shellcode len", g_last_alloc_size == sizeof(code));
    check("alloc perms is PAGE_READWRITE", g_last_alloc_perms == PAGE_READWRITE);
    check("mem_protect was called (RW→RX)", g_protect_count >= 1);
    check("protect perms is PAGE_EXECUTE_READ",
          g_last_protect_perms == PAGE_EXECUTE_READ);
    check("log was called", g_log_count > 0);
}

static void test_exec_shellcode_null_safety(void) {
    printf("\n--- exec_shellcode NULL safety ---\n");
    setup_mock_api();

    check("NULL api returns 1", exec_shellcode(NULL, (BYTE *)"x", 1) == 1);
    check("NULL code returns 1", exec_shellcode(&g_mock_api, NULL, 1) == 1);
    check("zero len returns 1", exec_shellcode(&g_mock_api, (BYTE *)"x", 0) == 1);
    check("no alloc on NULL inputs", g_alloc_count == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: clr_execute_assembly parameter validation                    */
/* ------------------------------------------------------------------ */

static void test_clr_null_safety(void) {
    printf("\n--- clr_execute_assembly NULL safety ---\n");
    setup_mock_api();

    BYTE dummy[] = { 0x00 };
    check("NULL api returns 1",
          clr_execute_assembly(NULL, dummy, 1, NULL) == 1);
    check("NULL assembly returns 1",
          clr_execute_assembly(&g_mock_api, NULL, 1, NULL) == 1);
    check("zero len returns 1",
          clr_execute_assembly(&g_mock_api, dummy, 0, NULL) == 1);
}

static void test_clr_init_resolve_fail(void) {
    printf("\n--- clr_execute_assembly resolve fail ---\n");
    setup_mock_api();

    /* Mock resolve returns NULL, so CLRCreateInstance can't be found */
    BYTE dummy[] = { 0x4D, 0x5A };  /* MZ header */
    DWORD result = clr_execute_assembly(&g_mock_api, dummy, sizeof(dummy), NULL);
    check("returns non-zero when CLR init fails", result != 0);
    check("resolve was called for mscoree.dll", g_resolve_count > 0);
    check("error was logged", g_log_count > 0);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Extended BOF API Tests ===\n");

    /* SPECTER_MemAlloc */
    test_specter_memalloc();
    test_specter_memalloc_null_bus();

    /* SPECTER_Resolve */
    test_specter_resolve();
    test_specter_resolve_null_args();

    /* SPECTER_NetConnect */
    test_specter_netconnect();
    test_specter_netconnect_null();

    /* SPECTER_ProcOpen */
    test_specter_procopen();
    test_specter_procopen_null_bus();

    /* SPECTER_FileRead */
    test_specter_fileread();
    test_specter_fileread_null();

    /* Symbol table */
    test_specter_symbol_table();

    /* exec_shellcode */
    test_exec_shellcode_basic();
    test_exec_shellcode_null_safety();

    /* CLR hosting */
    test_clr_null_safety();
    test_clr_init_resolve_fail();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
