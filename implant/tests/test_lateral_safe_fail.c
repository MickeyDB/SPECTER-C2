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

#define module_entry lateral_module_entry
#include "../modules/lateral/lateral.c"
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

static DWORD build_one_string_arg(BYTE *buf, DWORD buf_len,
                                  const char *arg0, DWORD arg0_len)
{
    DWORD offset = module_args_begin(buf, buf_len, 1);
    if (!offset)
        return 0;
    return append_string(buf, buf_len, offset, arg0, arg0_len);
}

static void test_lateral_rejects_malformed_args(void)
{
    MODULE_BUS_API api = test_api();
    BYTE bad[3] = {0};

    reset_outputs();
    check("lateral malformed args returns MODULE_ERR_ARGS",
          lateral_module_entry(&api, bad, sizeof(bad)) == MODULE_ERR_ARGS);
    check("lateral malformed args emits error", g_errors == 1);
}

static void test_lateral_rejects_missing_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[32];
    DWORD offset = module_args_begin(buf, sizeof(buf), 0);

    reset_outputs();
    check("lateral missing subcommand returns MODULE_ERR_ARGS",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("lateral missing subcommand emits error", g_errors == 1);
}

static void test_lateral_rejects_unterminated_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char raw[] = {'w', 'm', 'i'};
    DWORD offset = build_one_string_arg(buf, sizeof(buf), raw, sizeof(raw));

    reset_outputs();
    check("lateral unterminated subcommand returns MODULE_ERR_ARGS",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("lateral unterminated subcommand emits error", g_errors == 1);
}

static void test_lateral_rejects_unknown_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "unknown";
    DWORD offset = build_one_string_arg(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("lateral unknown subcommand returns MODULE_ERR_UNSUPPORTED",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_UNSUPPORTED);
    check("lateral unknown subcommand emits error", g_errors == 1);
}

static void test_lateral_valid_subcommands_fail_on_resolve(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[192];
    DWORD offset;
    const char target[] = "LABHOST";
    const char payload[] = "C:\\lab\\payload.exe";
    const char command[] = "cmd.exe /c whoami";
    const char wmi[] = "wmi";
    const char scm[] = "scm";
    const char dcom[] = "dcom";
    const char method[] = "mmc";
    const char schtask[] = "schtask";

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 3);
    offset = append_string(buf, sizeof(buf), offset, wmi, sizeof(wmi));
    offset = append_string(buf, sizeof(buf), offset, target, sizeof(target));
    offset = append_string(buf, sizeof(buf), offset, command, sizeof(command));
    check("lateral wmi resolve failure returns MODULE_ERR_RESOLVE",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 3);
    offset = append_string(buf, sizeof(buf), offset, scm, sizeof(scm));
    offset = append_string(buf, sizeof(buf), offset, target, sizeof(target));
    offset = append_string(buf, sizeof(buf), offset, payload, sizeof(payload));
    check("lateral scm resolve failure returns MODULE_ERR_RESOLVE",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 4);
    offset = append_string(buf, sizeof(buf), offset, dcom, sizeof(dcom));
    offset = append_string(buf, sizeof(buf), offset, target, sizeof(target));
    offset = append_string(buf, sizeof(buf), offset, payload, sizeof(payload));
    offset = append_string(buf, sizeof(buf), offset, method, sizeof(method));
    check("lateral dcom resolve failure returns MODULE_ERR_RESOLVE",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 3);
    offset = append_string(buf, sizeof(buf), offset, schtask, sizeof(schtask));
    offset = append_string(buf, sizeof(buf), offset, target, sizeof(target));
    offset = append_string(buf, sizeof(buf), offset, payload, sizeof(payload));
    check("lateral schtask resolve failure returns MODULE_ERR_RESOLVE",
          lateral_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);
}

int main(void)
{
    printf("=== lateral safe-failure tests ===\n");
    test_lateral_rejects_malformed_args();
    test_lateral_rejects_missing_subcommand();
    test_lateral_rejects_unterminated_subcommand();
    test_lateral_rejects_unknown_subcommand();
    test_lateral_valid_subcommands_fail_on_resolve();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
