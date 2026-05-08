#include <stdio.h>
#include <string.h>

#include "specter.h"
#include "bus.h"

static DWORD g_outputs;
static DWORD g_errors;

static BOOL mock_output(const BYTE *data, DWORD len, DWORD type)
{
    (void)data;
    (void)len;
    g_outputs++;
    if (type == OUTPUT_ERROR)
        g_errors++;
    return TRUE;
}

static MODULE_BUS_API test_api(void)
{
    MODULE_BUS_API api;
    memset(&api, 0, sizeof(api));
    api.output = mock_output;
    return api;
}

#define module_entry inject_module_entry
#include "../modules/inject/inject.c"
#undef module_entry

static int tests_run;
static int tests_passed;

static void check(const char *name, int condition)
{
    tests_run++;
    if (condition) {
        tests_passed++;
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
    }
}

static void reset_outputs(void)
{
    g_outputs = 0;
    g_errors = 0;
}

static DWORD append_string(BYTE *buf, DWORD buf_len, DWORD offset,
                           const char *value, DWORD len)
{
    return module_args_append(buf, buf_len, offset, ARG_TYPE_STRING,
                              (const BYTE *)value, len);
}

static DWORD append_int(BYTE *buf, DWORD buf_len, DWORD offset, DWORD value)
{
    return module_args_append(buf, buf_len, offset, ARG_TYPE_INT32,
                              (const BYTE *)&value, sizeof(value));
}

static DWORD append_bytes(BYTE *buf, DWORD buf_len, DWORD offset,
                          const BYTE *value, DWORD len)
{
    return module_args_append(buf, buf_len, offset, ARG_TYPE_BYTES,
                              value, len);
}

static DWORD build_one_string_arg(BYTE *buf, DWORD buf_len,
                                  const char *arg0, DWORD arg0_len)
{
    DWORD offset = module_args_begin(buf, buf_len, 1);
    if (!offset)
        return 0;
    return append_string(buf, buf_len, offset, arg0, arg0_len);
}

static void test_inject_rejects_malformed_args(void)
{
    MODULE_BUS_API api = test_api();
    BYTE bad[3] = {0};

    reset_outputs();
    check("inject malformed args returns MODULE_ERR_ARGS",
          inject_module_entry(&api, bad, sizeof(bad)) == MODULE_ERR_ARGS);
    check("inject malformed args emits error", g_errors == 1);
}

static void test_inject_rejects_missing_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[32];
    DWORD offset = module_args_begin(buf, sizeof(buf), 0);

    reset_outputs();
    check("inject missing subcommand returns MODULE_ERR_ARGS",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("inject missing subcommand emits error", g_errors == 1);
}

static void test_inject_rejects_unterminated_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char raw[] = {'a', 'p', 'c'};
    DWORD offset = build_one_string_arg(buf, sizeof(buf), raw, sizeof(raw));

    reset_outputs();
    check("inject unterminated subcommand returns MODULE_ERR_ARGS",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("inject unterminated subcommand emits error", g_errors == 1);
}

static void test_inject_rejects_unknown_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "unknown";
    DWORD offset = build_one_string_arg(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("inject unknown subcommand returns MODULE_ERR_UNSUPPORTED",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_UNSUPPORTED);
    check("inject unknown subcommand emits error", g_errors == 1);
}

static void test_inject_valid_subcommands_fail_without_bus_callbacks(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[192];
    BYTE sc[] = {0x90};
    DWORD offset;
    DWORD pid = 1234;
    DWORD tid = 5678;
    const char createthread[] = "createthread";
    const char apc[] = "apc";
    const char hijack[] = "hijack";
    const char stomp[] = "stomp";
    const char dll[] = "kernel32.dll";

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 3);
    offset = append_string(buf, sizeof(buf), offset, createthread, sizeof(createthread));
    offset = append_int(buf, sizeof(buf), offset, pid);
    offset = append_bytes(buf, sizeof(buf), offset, sc, sizeof(sc));
    check("inject createthread without bus callbacks returns MODULE_ERR_INTERNAL",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 4);
    offset = append_string(buf, sizeof(buf), offset, apc, sizeof(apc));
    offset = append_int(buf, sizeof(buf), offset, pid);
    offset = append_int(buf, sizeof(buf), offset, tid);
    offset = append_bytes(buf, sizeof(buf), offset, sc, sizeof(sc));
    check("inject apc without bus callbacks returns MODULE_ERR_INTERNAL",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 4);
    offset = append_string(buf, sizeof(buf), offset, hijack, sizeof(hijack));
    offset = append_int(buf, sizeof(buf), offset, pid);
    offset = append_int(buf, sizeof(buf), offset, tid);
    offset = append_bytes(buf, sizeof(buf), offset, sc, sizeof(sc));
    check("inject hijack without bus callbacks returns MODULE_ERR_INTERNAL",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 4);
    offset = append_string(buf, sizeof(buf), offset, stomp, sizeof(stomp));
    offset = append_int(buf, sizeof(buf), offset, pid);
    offset = append_string(buf, sizeof(buf), offset, dll, sizeof(dll));
    offset = append_bytes(buf, sizeof(buf), offset, sc, sizeof(sc));
    check("inject stomp without bus callbacks returns MODULE_ERR_INTERNAL",
          inject_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);
}

int main(void)
{
    printf("=== inject safe-failure tests ===\n");
    test_inject_rejects_malformed_args();
    test_inject_rejects_missing_subcommand();
    test_inject_rejects_unterminated_subcommand();
    test_inject_rejects_unknown_subcommand();
    test_inject_valid_subcommands_fail_without_bus_callbacks();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
