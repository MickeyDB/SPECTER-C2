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

#define module_entry exfil_module_entry
#include "../modules/exfil/exfil.c"
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

static DWORD begin_args(BYTE *buf, DWORD buf_len, DWORD count)
{
    return module_args_begin(buf, buf_len, count);
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

static DWORD build_one_string_arg(BYTE *buf, DWORD buf_len,
                                  const char *arg0, DWORD arg0_len)
{
    DWORD offset = begin_args(buf, buf_len, 1);
    if (!offset)
        return 0;
    return append_string(buf, buf_len, offset, arg0, arg0_len);
}

static void test_exfil_rejects_malformed_args(void)
{
    MODULE_BUS_API api = test_api();
    BYTE bad[3] = {0};

    reset_outputs();
    check("exfil malformed args returns MODULE_ERR_ARGS",
          exfil_module_entry(&api, bad, sizeof(bad)) == MODULE_ERR_ARGS);
    check("exfil malformed args emits error", g_errors == 1);
}

static void test_exfil_rejects_missing_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[32];
    DWORD offset = begin_args(buf, sizeof(buf), 0);

    reset_outputs();
    check("exfil missing subcommand returns MODULE_ERR_ARGS",
          exfil_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("exfil missing subcommand emits error", g_errors == 1);
}

static void test_exfil_rejects_unterminated_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char raw[] = {'f', 'i', 'l', 'e'};
    DWORD offset = build_one_string_arg(buf, sizeof(buf), raw, sizeof(raw));

    reset_outputs();
    check("exfil unterminated subcommand returns MODULE_ERR_ARGS",
          exfil_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("exfil unterminated subcommand emits error", g_errors == 1);
}

static void test_exfil_rejects_unknown_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "unknown";
    DWORD offset = build_one_string_arg(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("exfil unknown subcommand returns MODULE_ERR_UNSUPPORTED",
          exfil_module_entry(&api, buf, offset) == MODULE_ERR_UNSUPPORTED);
    check("exfil unknown subcommand emits error", g_errors == 1);
}

static void test_exfil_file_resolve_failure_is_safe(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[160];
    const char subcmd[] = "file";
    const char path[] = "C:\\lab\\sample.txt";
    DWORD chunk_size = 0xFFFFFFFF;
    DWORD throttle = 0xFFFFFFFF;
    DWORD offset = begin_args(buf, sizeof(buf), 4);

    offset = append_string(buf, sizeof(buf), offset, subcmd, sizeof(subcmd));
    offset = append_string(buf, sizeof(buf), offset, path, sizeof(path));
    offset = append_int(buf, sizeof(buf), offset, chunk_size);
    offset = append_int(buf, sizeof(buf), offset, throttle);

    reset_outputs();
    check("exfil file resolve failure returns MODULE_ERR_RESOLVE",
          exfil_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);
    check("exfil file resolve failure emits error", g_errors == 1);
}

static void test_exfil_directory_resolve_failure_is_safe(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[192];
    const char subcmd[] = "directory";
    const char dir[] = "C:\\lab";
    const char pattern[] = "*.txt";
    DWORD recursive = 1;
    DWORD offset = begin_args(buf, sizeof(buf), 4);

    offset = append_string(buf, sizeof(buf), offset, subcmd, sizeof(subcmd));
    offset = append_string(buf, sizeof(buf), offset, dir, sizeof(dir));
    offset = append_string(buf, sizeof(buf), offset, pattern, sizeof(pattern));
    offset = append_int(buf, sizeof(buf), offset, recursive);

    reset_outputs();
    check("exfil directory resolve failure returns MODULE_ERR_RESOLVE",
          exfil_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);
    check("exfil directory resolve failure emits error", g_errors == 1);
}

int main(void)
{
    printf("=== exfil safe-failure tests ===\n");
    test_exfil_rejects_malformed_args();
    test_exfil_rejects_missing_subcommand();
    test_exfil_rejects_unterminated_subcommand();
    test_exfil_rejects_unknown_subcommand();
    test_exfil_file_resolve_failure_is_safe();
    test_exfil_directory_resolve_failure_is_safe();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
