/**
 * SPECTER Implant — Module Argument Parsing Test Suite
 *
 * Tests argument serialization/deserialization roundtrip, subcommand
 * dispatch, accessor functions, and edge cases.
 *
 * Build: gcc -o test_module_args test_module_args.c
 *            -I../core/include -I../modules/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "bus.h"

/* ------------------------------------------------------------------ */
/*  CRT-free function stubs (delegate to libc for tests)               */
/* ------------------------------------------------------------------ */

SIZE_T spec_strlen(const char *s) { return strlen(s); }
SIZE_T spec_wcslen(const WCHAR *s) { SIZE_T n=0; while(s[n]) n++; return n; }
int spec_strcmp(const char *a, const char *b) { return strcmp(a,b); }
int spec_wcsicmp(const WCHAR *a, const WCHAR *b) { (void)a; (void)b; return 0; }
void *spec_memcpy(void *d, const void *s, SIZE_T n) { return memcpy(d,s,n); }
void *spec_memmove(void *d, const void *s, SIZE_T n) { return memmove(d,s,n); }
void *spec_memset(void *d, int c, SIZE_T n) { return memset(d,c,n); }
int spec_memcmp(const void *a, const void *b, SIZE_T n) { return memcmp(a,b,n); }
char *spec_strcpy(char *d, const char *s) { return strcpy(d,s); }
char *spec_strcat(char *d, const char *s) { return strcat(d,s); }
DWORD spec_djb2_hash(const char *str) {
    DWORD h = 5381; int c;
    while ((c = *str++)) {
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + c;
    }
    return h;
}
DWORD spec_djb2_hash_w(const WCHAR *str) { (void)str; return 0; }
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD h) { (void)h; return NULL; }
PVOID find_export_by_hash(PVOID m, DWORD h) { (void)m; (void)h; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

IMPLANT_CONTEXT g_ctx;

/* Now include module.h which includes specter.h and bus.h (already included) */
#include "module.h"

/* ------------------------------------------------------------------ */
/*  Test helpers                                                       */
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
/*  Test: basic serialization/deserialization roundtrip                 */
/* ------------------------------------------------------------------ */

static void test_args_roundtrip(void) {
    printf("\n--- argument serialization/deserialization roundtrip ---\n");

    BYTE buf[512];
    DWORD offset;

    /* Build blob: 3 args — string, int32, bytes */
    offset = module_args_begin(buf, sizeof(buf), 3);
    check("args_begin returns 4", offset == 4);

    const char *str = "steal";
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)str,
                                (DWORD)strlen(str) + 1);
    check("append string succeeds", offset > 4);

    DWORD pid = 1234;
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_INT32, (const BYTE *)&pid, 4);
    check("append int32 succeeds", offset > 0);

    BYTE raw[] = {0xDE, 0xAD, 0xBE, 0xEF};
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_BYTES, raw, sizeof(raw));
    check("append bytes succeeds", offset > 0);

    /* Parse */
    MODULE_ARGS args;
    BOOL ok = module_parse_args(buf, offset, &args);
    check("parse succeeds", ok == TRUE);
    check("count is 3", args.count == 3);

    /* Verify string arg */
    const char *got_str = module_arg_string(&args, 0);
    check("arg[0] is string", got_str != NULL);
    check("arg[0] value matches", got_str && strcmp(got_str, "steal") == 0);

    /* Verify int32 arg */
    DWORD got_pid = module_arg_int32(&args, 1, 0);
    check("arg[1] is int32", got_pid == 1234);

    /* Verify bytes arg */
    DWORD got_len = 0;
    const BYTE *got_raw = module_arg_bytes(&args, 2, &got_len);
    check("arg[2] is bytes", got_raw != NULL);
    check("arg[2] length is 4", got_len == 4);
    check("arg[2] data matches", got_raw && memcmp(got_raw, raw, 4) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: single string argument                                       */
/* ------------------------------------------------------------------ */

static void test_single_string_arg(void) {
    printf("\n--- single string argument ---\n");

    BYTE buf[128];
    const char *cmd = "list";
    DWORD offset = module_args_begin(buf, sizeof(buf), 1);
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)cmd,
                                (DWORD)strlen(cmd) + 1);

    MODULE_ARGS args;
    BOOL ok = module_parse_args(buf, offset, &args);
    check("parse single arg", ok == TRUE);
    check("count is 1", args.count == 1);

    const char *got = module_arg_string(&args, 0);
    check("string value matches", got && strcmp(got, "list") == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: subcommand dispatch pattern                                  */
/* ------------------------------------------------------------------ */

static void test_subcommand_dispatch(void) {
    printf("\n--- subcommand dispatch ---\n");

    BYTE buf[256];
    DWORD offset;

    /* Build "steal 4567" */
    offset = module_args_begin(buf, sizeof(buf), 2);
    const char *subcmd = "steal";
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)subcmd,
                                (DWORD)strlen(subcmd) + 1);
    DWORD pid = 4567;
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_INT32, (const BYTE *)&pid, 4);

    MODULE_ARGS args;
    module_parse_args(buf, offset, &args);

    const char *cmd = module_arg_string(&args, 0);
    check("subcmd is 'steal'", cmd && strcmp(cmd, "steal") == 0);

    /* Simulate dispatch */
    int dispatched = 0;
    if (cmd) {
        if (spec_strcmp(cmd, "steal") == 0) {
            DWORD target = module_arg_int32(&args, 1, 0);
            check("steal target pid is 4567", target == 4567);
            dispatched = 1;
        } else if (spec_strcmp(cmd, "list") == 0) {
            dispatched = 2;
        }
    }
    check("dispatched to 'steal' handler", dispatched == 1);
}

/* ------------------------------------------------------------------ */
/*  Test: accessor type mismatch returns defaults                      */
/* ------------------------------------------------------------------ */

static void test_type_mismatch(void) {
    printf("\n--- accessor type mismatch ---\n");

    BYTE buf[128];
    const char *str = "hello";
    DWORD offset = module_args_begin(buf, sizeof(buf), 1);
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)str,
                                (DWORD)strlen(str) + 1);

    MODULE_ARGS args;
    module_parse_args(buf, offset, &args);

    /* Try to read string as int32 */
    DWORD val = module_arg_int32(&args, 0, 9999);
    check("int32 accessor on string returns default", val == 9999);

    /* Try to read string as bytes */
    DWORD blen = 0;
    const BYTE *bp = module_arg_bytes(&args, 0, &blen);
    check("bytes accessor on string returns NULL", bp == NULL);

    /* Try to read string as wstring */
    const WCHAR *ws = module_arg_wstring(&args, 0);
    check("wstring accessor on string returns NULL", ws == NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: out-of-bounds index                                          */
/* ------------------------------------------------------------------ */

static void test_out_of_bounds(void) {
    printf("\n--- out-of-bounds index ---\n");

    BYTE buf[64];
    DWORD offset = module_args_begin(buf, sizeof(buf), 0);

    MODULE_ARGS args;
    BOOL ok = module_parse_args(buf, offset, &args);
    check("parse zero-arg blob", ok == TRUE);
    check("count is 0", args.count == 0);

    check("string at idx 0 is NULL", module_arg_string(&args, 0) == NULL);
    check("int32 at idx 0 returns default", module_arg_int32(&args, 0, 42) == 42);
    check("bytes at idx 0 is NULL", module_arg_bytes(&args, 0, NULL) == NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: NULL and malformed blob handling                             */
/* ------------------------------------------------------------------ */

static void test_parse_edge_cases(void) {
    printf("\n--- parse edge cases ---\n");

    MODULE_ARGS args;

    check("parse NULL blob returns FALSE",
          module_parse_args(NULL, 100, &args) == FALSE);

    check("parse zero-length blob returns FALSE",
          module_parse_args((const BYTE *)"x", 0, &args) == FALSE);

    /* Blob too short (only 3 bytes, need 4 for count) */
    BYTE short_blob[3] = {1, 0, 0};
    check("parse 3-byte blob returns FALSE",
          module_parse_args(short_blob, 3, &args) == FALSE);

    /* Count says 1 arg but no data follows */
    BYTE truncated[4];
    *(DWORD *)truncated = 1;
    check("parse truncated blob returns FALSE",
          module_parse_args(truncated, 4, &args) == FALSE);

    /* Count says 1 arg, type+len present but data truncated */
    BYTE partial[12];
    *(DWORD *)partial = 1;        /* count = 1 */
    *(DWORD *)(partial + 4) = 0;  /* type = STRING */
    *(DWORD *)(partial + 8) = 10; /* len = 10 (but only 0 bytes follow) */
    check("parse with truncated data returns FALSE",
          module_parse_args(partial, 12, &args) == FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: serialization buffer overflow                                */
/* ------------------------------------------------------------------ */

static void test_serialization_overflow(void) {
    printf("\n--- serialization buffer overflow ---\n");

    BYTE tiny[8];
    DWORD offset = module_args_begin(tiny, sizeof(tiny), 1);
    check("begin in tiny buffer works", offset == 4);

    /* Try to append more data than fits */
    BYTE data[100];
    memset(data, 'A', sizeof(data));
    DWORD result = module_args_append(tiny, sizeof(tiny), offset,
                                      ARG_TYPE_BYTES, data, sizeof(data));
    check("append overflow returns 0", result == 0);

    /* begin in too-small buffer */
    BYTE micro[2];
    check("begin in 2-byte buffer returns 0",
          module_args_begin(micro, sizeof(micro), 1) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: many arguments (stress the MODULE_MAX_ARGS limit)            */
/* ------------------------------------------------------------------ */

static void test_max_args(void) {
    printf("\n--- max arguments ---\n");

    BYTE buf[4096];
    DWORD offset = module_args_begin(buf, sizeof(buf), MODULE_MAX_ARGS);

    for (DWORD i = 0; i < MODULE_MAX_ARGS; i++) {
        DWORD val = i * 100;
        offset = module_args_append(buf, sizeof(buf), offset,
                                    ARG_TYPE_INT32, (const BYTE *)&val, 4);
    }
    check("all 32 args serialized", offset > 0);

    MODULE_ARGS args;
    BOOL ok = module_parse_args(buf, offset, &args);
    check("parse 32 args succeeds", ok == TRUE);
    check("count is 32", args.count == MODULE_MAX_ARGS);

    /* Verify first and last */
    check("arg[0] = 0", module_arg_int32(&args, 0, 9999) == 0);
    check("arg[31] = 3100", module_arg_int32(&args, 31, 9999) == 3100);

    /* Exceeding MODULE_MAX_ARGS */
    BYTE over[4096];
    DWORD over_off = module_args_begin(over, sizeof(over), MODULE_MAX_ARGS + 1);
    for (DWORD i = 0; i < MODULE_MAX_ARGS + 1; i++) {
        DWORD val = i;
        over_off = module_args_append(over, sizeof(over), over_off,
                                      ARG_TYPE_INT32, (const BYTE *)&val, 4);
    }
    ok = module_parse_args(over, over_off, &args);
    check("parse MAX_ARGS+1 returns FALSE", ok == FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: wide string argument                                         */
/* ------------------------------------------------------------------ */

static void test_wstring_arg(void) {
    printf("\n--- wide string argument ---\n");

    BYTE buf[128];
    WCHAR wstr[] = {'T', 'e', 's', 't', 0};
    DWORD wstr_size = (DWORD)sizeof(wstr);

    DWORD offset = module_args_begin(buf, sizeof(buf), 1);
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_WSTRING, (const BYTE *)wstr, wstr_size);

    MODULE_ARGS args;
    BOOL ok = module_parse_args(buf, offset, &args);
    check("parse wstring blob", ok == TRUE);

    const WCHAR *got = module_arg_wstring(&args, 0);
    check("wstring accessor returns non-NULL", got != NULL);
    check("wstring first char is 'T'", got && got[0] == 'T');
    check("wstring is null-terminated", got && got[4] == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: mixed argument types in realistic scenario                   */
/* ------------------------------------------------------------------ */

static void test_realistic_lateral_args(void) {
    printf("\n--- realistic lateral movement args ---\n");

    BYTE buf[512];
    DWORD offset;

    /* Simulate: lateral wmi "192.168.1.10" "cmd.exe /c whoami" */
    offset = module_args_begin(buf, sizeof(buf), 3);

    const char *subcmd = "wmi";
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)subcmd,
                                (DWORD)strlen(subcmd) + 1);

    const char *target = "192.168.1.10";
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)target,
                                (DWORD)strlen(target) + 1);

    const char *command = "cmd.exe /c whoami";
    offset = module_args_append(buf, sizeof(buf), offset,
                                ARG_TYPE_STRING, (const BYTE *)command,
                                (DWORD)strlen(command) + 1);

    MODULE_ARGS args;
    BOOL ok = module_parse_args(buf, offset, &args);
    check("parse lateral args", ok == TRUE);
    check("count is 3", args.count == 3);

    const char *got_sub = module_arg_string(&args, 0);
    const char *got_tgt = module_arg_string(&args, 1);
    const char *got_cmd = module_arg_string(&args, 2);

    check("subcmd is 'wmi'", got_sub && strcmp(got_sub, "wmi") == 0);
    check("target is '192.168.1.10'", got_tgt && strcmp(got_tgt, "192.168.1.10") == 0);
    check("command is 'cmd.exe /c whoami'", got_cmd && strcmp(got_cmd, "cmd.exe /c whoami") == 0);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Module Argument Parsing Tests ===\n");

    test_args_roundtrip();
    test_single_string_arg();
    test_subcommand_dispatch();
    test_type_mismatch();
    test_out_of_bounds();
    test_parse_edge_cases();
    test_serialization_overflow();
    test_max_args();
    test_wstring_arg();
    test_realistic_lateral_args();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
