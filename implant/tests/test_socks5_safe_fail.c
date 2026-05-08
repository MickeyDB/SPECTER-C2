#include <stdio.h>
#include <string.h>

#include "specter.h"
#include "bus.h"

static DWORD g_outputs;
static DWORD g_errors;
static DWORD g_binary_outputs;
static DWORD g_file_reads;
static DWORD g_net_connects;
static DWORD g_sleep_calls;
static DWORD g_last_sleep_ms;
static BYTE g_file_read_payload[64];
static DWORD g_file_read_payload_len;

static BOOL mock_output(const BYTE *data, DWORD len, DWORD type)
{
    (void)data;
    (void)len;
    g_outputs++;
    if (type == OUTPUT_ERROR)
        g_errors++;
    if (type == OUTPUT_BINARY)
        g_binary_outputs++;
    return TRUE;
}

static void *mock_resolve(const char *dll_name, const char *func_name)
{
    (void)dll_name;
    (void)func_name;
    return NULL;
}

static void mock_sleep(DWORD ms)
{
    g_sleep_calls++;
    g_last_sleep_ms = ms;
}

static void *mock_resolve_sleep(const char *dll_name, const char *func_name)
{
    if (strcmp(dll_name, "kernel32.dll") == 0 &&
        strcmp(func_name, "Sleep") == 0)
        return (void *)mock_sleep;
    return NULL;
}

static DWORD mock_file_read(const char *path, BYTE *buf, DWORD len)
{
    (void)path;
    g_file_reads++;
    if (g_file_reads > 1 || g_file_read_payload_len == 0)
        return 0;
    if (g_file_read_payload_len > len)
        return (DWORD)-1;
    memcpy(buf, g_file_read_payload, g_file_read_payload_len);
    return g_file_read_payload_len;
}

static HANDLE mock_net_connect(const char *addr, DWORD port, DWORD proto)
{
    (void)addr;
    (void)port;
    (void)proto;
    g_net_connects++;
    return NULL;
}

static BOOL mock_net_send(HANDLE handle, const BYTE *data, DWORD len)
{
    (void)handle;
    (void)data;
    (void)len;
    return TRUE;
}

static DWORD mock_net_recv(HANDLE handle, BYTE *buf, DWORD len)
{
    (void)handle;
    (void)buf;
    (void)len;
    return 0;
}

static BOOL mock_net_close(HANDLE handle)
{
    (void)handle;
    return TRUE;
}

static MODULE_BUS_API test_api(void)
{
    MODULE_BUS_API api;
    memset(&api, 0, sizeof(api));
    api.output = mock_output;
    api.resolve = mock_resolve;
    return api;
}

static MODULE_BUS_API test_loop_api(void)
{
    MODULE_BUS_API api = test_api();
    api.resolve = mock_resolve_sleep;
    api.file_read = mock_file_read;
    api.net_connect = mock_net_connect;
    api.net_send = mock_net_send;
    api.net_recv = mock_net_recv;
    api.net_close = mock_net_close;
    return api;
}

#define module_entry socks5_module_entry
#include "../modules/socks5/socks5.c"
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

static DWORD build_start_args(BYTE *buf, DWORD buf_len, DWORD throttle_ms)
{
    DWORD offset = module_args_begin(buf, buf_len, 2);
    const char subcmd[] = "start";
    if (!offset)
        return 0;
    offset = module_args_append(buf, buf_len, offset, ARG_TYPE_STRING,
                                (const BYTE *)subcmd, sizeof(subcmd));
    if (!offset)
        return 0;
    return module_args_append(buf, buf_len, offset, ARG_TYPE_INT32,
                              (const BYTE *)&throttle_ms, sizeof(throttle_ms));
}

static void reset_outputs(void)
{
    g_outputs = 0;
    g_errors = 0;
    g_binary_outputs = 0;
    g_file_reads = 0;
    g_net_connects = 0;
    g_sleep_calls = 0;
    g_last_sleep_ms = 0;
    memset(g_file_read_payload, 0, sizeof(g_file_read_payload));
    g_file_read_payload_len = 0;
}

static void test_socks5_rejects_malformed_args(void)
{
    MODULE_BUS_API api = test_api();
    BYTE bad[3] = {0};

    reset_outputs();
    check("socks5 malformed args returns MODULE_ERR_ARGS",
          socks5_module_entry(&api, bad, sizeof(bad)) == MODULE_ERR_ARGS);
    check("socks5 malformed args emits error", g_errors == 1);
}

static void test_socks5_rejects_missing_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[32];
    DWORD offset = module_args_begin(buf, sizeof(buf), 0);

    reset_outputs();
    check("socks5 missing subcommand returns MODULE_ERR_ARGS",
          socks5_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("socks5 missing subcommand emits error", g_errors == 1);
}

static void test_socks5_rejects_unterminated_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char raw[] = {'s', 't', 'a', 'r', 't'};
    DWORD offset = build_string_args(buf, sizeof(buf), raw, sizeof(raw));

    reset_outputs();
    check("socks5 unterminated subcommand returns MODULE_ERR_ARGS",
          socks5_module_entry(&api, buf, offset) == MODULE_ERR_ARGS);
    check("socks5 unterminated subcommand emits error", g_errors == 1);
}

static void test_socks5_rejects_unknown_subcommand(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "unknown";
    DWORD offset = build_string_args(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("socks5 unknown subcommand returns MODULE_ERR_UNSUPPORTED",
          socks5_module_entry(&api, buf, offset) == MODULE_ERR_UNSUPPORTED);
    check("socks5 unknown subcommand emits error", g_errors == 1);
}

static void test_socks5_start_fails_without_sleep_resolve(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    const char subcmd[] = "start";
    DWORD offset = build_string_args(buf, sizeof(buf), subcmd, sizeof(subcmd));

    reset_outputs();
    check("socks5 start without Sleep returns MODULE_ERR_RESOLVE",
          socks5_module_entry(&api, buf, offset) == MODULE_ERR_RESOLVE);
    check("socks5 start without Sleep emits error", g_errors == 1);
}

static void test_socks5_start_fails_without_bus_callbacks(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[96];
    DWORD throttle = DEFAULT_THROTTLE_MS;
    DWORD offset = build_start_args(buf, sizeof(buf), throttle);

    api.resolve = mock_resolve_sleep;

    reset_outputs();
    check("socks5 start without required bus callbacks returns MODULE_ERR_INTERNAL",
          socks5_module_entry(&api, buf, offset) == MODULE_ERR_INTERNAL);
    check("socks5 start without required bus callbacks emits error",
          g_errors == 1);
}

static void test_socks5_stop_and_status_are_signal_only(void)
{
    MODULE_BUS_API api = test_api();
    BYTE buf[64];
    DWORD offset;
    const char stop[] = "stop";
    const char status[] = "status";

    reset_outputs();
    offset = build_string_args(buf, sizeof(buf), stop, sizeof(stop));
    check("socks5 stop returns success",
          socks5_module_entry(&api, buf, offset) == MODULE_SUCCESS);
    check("socks5 stop emits binary control and text",
          g_binary_outputs == 1 && g_outputs == 2 && g_errors == 0);

    reset_outputs();
    offset = build_string_args(buf, sizeof(buf), status, sizeof(status));
    check("socks5 status returns success",
          socks5_module_entry(&api, buf, offset) == MODULE_SUCCESS);
    check("socks5 status emits binary control and text",
          g_binary_outputs == 1 && g_outputs == 2 && g_errors == 0);
}

static void prepare_stop_message(void)
{
    SOCKS_MSG *msg = (SOCKS_MSG *)g_file_read_payload;
    msg->conn_id = 0;
    msg->msg_type = MSG_CLOSE;
    msg->flags = 0;
    msg->payload_len = 0;
    g_file_read_payload_len = SOCKS_MSG_HDR_SIZE;
}

static void test_socks5_start_exits_on_stop_signal(void)
{
    MODULE_BUS_API api = test_loop_api();
    BYTE buf[96];
    DWORD throttle = 0;
    DWORD offset = build_start_args(buf, sizeof(buf), throttle);

    reset_outputs();
    prepare_stop_message();
    check("socks5 start exits cleanly on inbox stop",
          socks5_module_entry(&api, buf, offset) == MODULE_SUCCESS);
    check("socks5 start polls inbox once",
          g_file_reads == 1);
    check("socks5 start uses default throttle for zero input",
          g_sleep_calls == 1 && g_last_sleep_ms == DEFAULT_THROTTLE_MS);
    check("socks5 start stop path does not connect",
          g_net_connects == 0);
}

static void test_socks5_start_clamps_large_throttle(void)
{
    MODULE_BUS_API api = test_loop_api();
    BYTE buf[96];
    DWORD throttle = 0xFFFFFFFF;
    DWORD offset = build_start_args(buf, sizeof(buf), throttle);

    reset_outputs();
    prepare_stop_message();
    check("socks5 start with large throttle exits cleanly",
          socks5_module_entry(&api, buf, offset) == MODULE_SUCCESS);
    check("socks5 start clamps large throttle",
          g_sleep_calls == 1 && g_last_sleep_ms == MAX_THROTTLE_MS);
}

static void test_socks5_rejects_oversized_wire_payload(void)
{
    MODULE_BUS_API api = test_loop_api();
    SOCKS5_STATE state;
    BYTE raw[SOCKS_MSG_HDR_SIZE];
    SOCKS_MSG *msg = (SOCKS_MSG *)raw;

    reset_outputs();
    memset(&state, 0, sizeof(state));
    msg->conn_id = 1;
    msg->msg_type = MSG_CONNECT_REQ;
    msg->flags = 0;
    msg->payload_len = 0xFFFFFFFF;

    process_message(&api, &state, raw, sizeof(raw));
    check("socks5 oversized wire payload emits no output",
          g_outputs == 0);
    check("socks5 oversized wire payload does not connect",
          g_net_connects == 0);
}

int main(void)
{
    printf("=== socks5 safe-failure tests ===\n");
    test_socks5_rejects_malformed_args();
    test_socks5_rejects_missing_subcommand();
    test_socks5_rejects_unterminated_subcommand();
    test_socks5_rejects_unknown_subcommand();
    test_socks5_start_fails_without_sleep_resolve();
    test_socks5_start_fails_without_bus_callbacks();
    test_socks5_stop_and_status_are_signal_only();
    test_socks5_start_exits_on_stop_signal();
    test_socks5_start_clamps_large_throttle();
    test_socks5_rejects_oversized_wire_payload();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
