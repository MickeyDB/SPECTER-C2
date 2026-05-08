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

static void *mock_resolve(const char *dll_name, const char *func_name)
{
    (void)dll_name;
    (void)func_name;
    return NULL;
}

static MODULE_BUS_API test_api(void)
{
    MODULE_BUS_API api;
    memset(&api, 0, sizeof(api));
    api.output = mock_output;
    api.resolve = mock_resolve;
    return api;
}

#define module_entry collect_module_entry
#include "../modules/collect/collect.c"
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

static DWORD build_string_args(BYTE *buf, DWORD buf_len,
                               const char *arg0, DWORD arg0_len)
{
    DWORD offset = module_args_begin(buf, buf_len, 1);
    if (!offset)
        return 0;
    return module_args_append(buf, buf_len, offset, ARG_TYPE_STRING,
                              (const BYTE *)arg0, arg0_len);
}

static void reset_outputs(void)
{
    g_outputs = 0;
    g_errors = 0;
}

static void test_collect_rejects_malformed_args(void)
{
    MODULE_BUS_API api = test_api();
    BYTE bad[3] = {0};

    reset_outputs();
    check("collect malformed args returns MODULE_ERR_ARGS",
          collect_module_entry(&api, bad, sizeof(bad)) == MODULE_ERR_ARGS);
    check("collect malformed args emits error", g_errors == 1);
}

static void test_collect_rejects_missing_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[32];
    DWORD offset = module_args_begin(buf, sizeof(buf), 0);

    reset_outputs();
    check("collect missing subcommand returns MODULE_ERR_ARGS",
          collect_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("collect missing subcommand emits error", g_errors == 1);
}

static void test_collect_rejects_unterminated_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char raw[] = {'k', 'e', 'y', 'l', 'o', 'g'};
    DWORD offset = build_string_args(buf, sizeof(buf), raw, sizeof(raw));

    reset_outputs();
    check("collect unterminated subcommand returns MODULE_ERR_ARGS",
          collect_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("collect unterminated subcommand emits error", g_errors == 1);
}

static void test_collect_rejects_unknown_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "unknown";
    DWORD offset = build_string_args(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("collect unknown subcommand returns MODULE_ERR_UNSUPPORTED",
          collect_module_entry(&api, buf, offset) == MODULE_ERR_UNSUPPORTED);
    check("collect unknown subcommand emits error", g_errors == 1);
}

int main(void)
{
    printf("=== collect safe-failure tests ===\n");
    test_collect_rejects_malformed_args();
    test_collect_rejects_missing_subcommand();
    test_collect_rejects_unterminated_subcommand();
    test_collect_rejects_unknown_subcommand();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
