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

#define module_entry token_module_entry
#include "../modules/token/token.c"
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

static DWORD build_one_string_arg(BYTE *buf, DWORD buf_len,
                                  const char *arg0, DWORD arg0_len)
{
    DWORD offset = module_args_begin(buf, buf_len, 1);
    if (!offset)
        return 0;
    return append_string(buf, buf_len, offset, arg0, arg0_len);
}

static void test_token_rejects_malformed_args(void)
{
    MODULE_BUS_API api = test_api();
    BYTE bad[3] = {0};

    reset_outputs();
    check("token malformed args returns MODULE_ERR_ARGS",
          token_module_entry(&api, bad, sizeof(bad)) == MODULE_ERR_ARGS);
    check("token malformed args emits error", g_errors == 1);
}

static void test_token_rejects_missing_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[32];
    DWORD offset = module_args_begin(buf, sizeof(buf), 0);

    reset_outputs();
    check("token missing subcommand returns MODULE_ERR_ARGS",
          token_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("token missing subcommand emits error", g_errors == 1);
}

static void test_token_rejects_unterminated_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char raw[] = {'s', 't', 'e', 'a', 'l'};
    DWORD offset = build_one_string_arg(buf, sizeof(buf), raw, sizeof(raw));

    reset_outputs();
    check("token unterminated subcommand returns MODULE_ERR_ARGS",
          token_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("token unterminated subcommand emits error", g_errors == 1);
}

static void test_token_rejects_unknown_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "unknown";
    DWORD offset = build_one_string_arg(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("token unknown subcommand returns MODULE_ERR_UNSUPPORTED",
          token_module_entry(&api, buf, offset) == MODULE_ERR_UNSUPPORTED);
    check("token unknown subcommand emits error", g_errors == 1);
}

static void test_token_valid_subcommands_fail_without_bus_callbacks(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[160];
    DWORD offset;
    DWORD pid = 1234;
    const char steal[] = "steal";
    const char make[] = "make";
    const char revert[] = "revert";
    const char list[] = "list";
    const char domain[] = "LAB";
    const char user[] = "operator";
    const char pass[] = "secret";

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 2);
    offset = append_string(buf, sizeof(buf), offset, steal, sizeof(steal));
    offset = append_int(buf, sizeof(buf), offset, pid);
    check("token steal without bus callbacks returns MODULE_ERR_INTERNAL",
          token_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);

    reset_outputs();
    offset = module_args_begin(buf, sizeof(buf), 4);
    offset = append_string(buf, sizeof(buf), offset, make, sizeof(make));
    offset = append_string(buf, sizeof(buf), offset, domain, sizeof(domain));
    offset = append_string(buf, sizeof(buf), offset, user, sizeof(user));
    offset = append_string(buf, sizeof(buf), offset, pass, sizeof(pass));
    check("token make without bus callbacks returns MODULE_ERR_INTERNAL",
          token_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);

    reset_outputs();
    offset = build_one_string_arg(buf, sizeof(buf), revert, sizeof(revert));
    check("token revert without bus callbacks returns MODULE_ERR_INTERNAL",
          token_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);

    reset_outputs();
    offset = build_one_string_arg(buf, sizeof(buf), list, sizeof(list));
    check("token list without bus callbacks returns MODULE_ERR_INTERNAL",
          token_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);
}

int main(void)
{
    printf("=== token safe-failure tests ===\n");
    test_token_rejects_malformed_args();
    test_token_rejects_missing_subcommand();
    test_token_rejects_unterminated_subcommand();
    test_token_rejects_unknown_subcommand();
    test_token_valid_subcommands_fail_without_bus_callbacks();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
