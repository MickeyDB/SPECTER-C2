/**
 * SPECTER Implant — Channel Failover Test Suite
 *
 * Tests channel health checking, failover logic, exponential backoff,
 * retry scheduling, and multi-channel state management.
 *
 * Compiled natively (not PIC) for testing on the build host.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "ntdefs.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"

/* ------------------------------------------------------------------ */
/*  Globals required by the object files                               */
/* ------------------------------------------------------------------ */

IMPLANT_CONTEXT g_ctx;

/* ------------------------------------------------------------------ */
/*  Stubs for dependencies not under test                              */
/* ------------------------------------------------------------------ */

static IMPLANT_CONFIG g_test_config;

NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) { (void)ctx; return &g_test_config; }
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx) { (void)ctx; return FALSE; }

/* Stub PEB functions */
PVOID find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID find_export_by_hash(PVOID base, DWORD hash) { (void)base; (void)hash; return NULL; }

/* Controllable TCP/TLS stubs for testing failover behavior */
static BOOL g_tcp_connect_fail = FALSE;
static BOOL g_tls_handshake_fail = FALSE;
static int g_tcp_connect_count = 0;
static int g_tls_handshake_count = 0;
static DWORD g_last_connect_port = 0;

/* Per-channel connection failure control */
static BOOL g_tcp_fail_per_channel[CONFIG_MAX_CHANNELS] = {FALSE};
static DWORD g_connecting_channel = (DWORD)-1;

NTSTATUS comms_tcp_connect(COMMS_CONTEXT *ctx, const char *host, DWORD port) {
    (void)host;
    g_tcp_connect_count++;
    g_last_connect_port = port;

    if (g_tcp_connect_fail) return STATUS_UNSUCCESSFUL;

    /* Check per-channel failure */
    for (DWORD i = 0; i < CONFIG_MAX_CHANNELS; i++) {
        if (g_test_config.channels[i].port == port && g_tcp_fail_per_channel[i])
            return STATUS_UNSUCCESSFUL;
    }

    ctx->state = COMMS_STATE_TCP_CONNECTED;
    return STATUS_SUCCESS;
}

NTSTATUS comms_tcp_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS comms_tcp_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) { (void)ctx; (void)buf; (void)buf_len; *received = 0; return STATUS_SUCCESS; }
NTSTATUS comms_tcp_close(COMMS_CONTEXT *ctx) { ctx->state = COMMS_STATE_DISCONNECTED; return STATUS_SUCCESS; }

NTSTATUS comms_tls_init(COMMS_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS comms_tls_handshake(COMMS_CONTEXT *ctx, const char *hostname) {
    (void)hostname;
    g_tls_handshake_count++;

    if (g_tls_handshake_fail) return STATUS_UNSUCCESSFUL;

    ctx->state = COMMS_STATE_TLS_CONNECTED;
    return STATUS_SUCCESS;
}
NTSTATUS comms_tls_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) { (void)ctx; (void)data; (void)len; return STATUS_SUCCESS; }
NTSTATUS comms_tls_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) { (void)ctx; (void)buf; (void)buf_len; *received = 0; return STATUS_SUCCESS; }
NTSTATUS comms_tls_close(COMMS_CONTEXT *ctx) { ctx->state = COMMS_STATE_DISCONNECTED; return STATUS_SUCCESS; }
DWORD comms_http_build_request(DWORD method, const char *uri, const char *host,
    const char *headers, const BYTE *body, DWORD body_len,
    BYTE *output, DWORD output_len) {
    (void)method; (void)uri; (void)host; (void)headers;
    (void)body; (void)body_len; (void)output; (void)output_len;
    return 0;
}
NTSTATUS comms_http_parse_response(const BYTE *data, DWORD data_len,
    DWORD *status_code_out, HTTP_HEADER *headers_out,
    DWORD *header_count_out, const BYTE **body_out, DWORD *body_len_out) {
    (void)data; (void)data_len; (void)status_code_out; (void)headers_out;
    (void)header_count_out; (void)body_out; (void)body_len_out;
    return STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------ */
/*  Test helpers                                                       */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

static int check_eq(const char *name, int got, int expected) {
    tests_run++;
    if (got == expected) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s (expected %d, got %d)\n", name, expected, got);
        return 0;
    }
}

static int check_true(const char *name, int cond) {
    tests_run++;
    if (cond) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s\n", name);
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Test helper: setup multi-channel config                            */
/* ------------------------------------------------------------------ */

static void reset_test_state(void) {
    memset(&g_test_config, 0, sizeof(g_test_config));
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_tcp_connect_fail = FALSE;
    g_tls_handshake_fail = FALSE;
    g_tcp_connect_count = 0;
    g_tls_handshake_count = 0;
    g_last_connect_port = 0;
    for (int i = 0; i < CONFIG_MAX_CHANNELS; i++)
        g_tcp_fail_per_channel[i] = FALSE;
    g_connecting_channel = (DWORD)-1;

    comms_test_set_tick(0);
}

static void setup_multi_channel(void) {
    reset_test_state();

    /* Channel 0: HTTPS primary (priority 0) */
    strcpy(g_test_config.channels[0].url, "primary.c2.com");
    g_test_config.channels[0].port = 443;
    g_test_config.channels[0].type = CHANNEL_HTTP;
    g_test_config.channels[0].priority = 0;
    g_test_config.channels[0].active = 1;

    /* Channel 1: DNS fallback (priority 1) */
    strcpy(g_test_config.channels[1].url, "dns.c2.com");
    g_test_config.channels[1].port = 53;
    g_test_config.channels[1].type = CHANNEL_DNS;
    g_test_config.channels[1].priority = 1;
    g_test_config.channels[1].active = 1;

    /* Channel 2: SMB internal pivot (priority 2) */
    strcpy(g_test_config.channels[2].url, "smb.internal");
    g_test_config.channels[2].port = 445;
    g_test_config.channels[2].type = CHANNEL_SMB;
    g_test_config.channels[2].priority = 2;
    g_test_config.channels[2].active = 1;

    g_test_config.channel_count = 3;
    g_test_config.max_retries = 3;
    g_test_config.sleep_interval = 30000; /* 30 seconds */

    /* Initialize via comms_init stubs — manually set up context */
    COMMS_CONTEXT *ctx = comms_test_get_context();
    memset(ctx, 0, sizeof(COMMS_CONTEXT));
    ctx->active_channel = 0;
    ctx->state = COMMS_STATE_TLS_CONNECTED;
    ctx->deep_sleep_mode = FALSE;
    for (int i = 0; i < CONFIG_MAX_CHANNELS; i++) {
        ctx->channel_states[i].health = CHANNEL_HEALTHY;
        ctx->channel_states[i].conn_state = COMMS_STATE_DISCONNECTED;
    }
    ctx->channel_states[0].conn_state = COMMS_STATE_TLS_CONNECTED;

    g_ctx.comms_ctx = ctx;
    g_ctx.config = &g_test_config;
}

/* ================================================================== */
/*  Tests: Backoff Schedule                                           */
/* ================================================================== */

static void test_backoff_schedule(void) {
    printf("\n=== Backoff Schedule ===\n");

    check_eq("Backoff index 0 = 60s (1min)", (int)comms_get_backoff_delay(0), 60000);
    check_eq("Backoff index 1 = 300s (5min)", (int)comms_get_backoff_delay(1), 300000);
    check_eq("Backoff index 2 = 900s (15min)", (int)comms_get_backoff_delay(2), 900000);
    check_eq("Backoff index 3 = 3600s (1hr)", (int)comms_get_backoff_delay(3), 3600000);
    check_eq("Backoff index 4 = 14400s (4hr)", (int)comms_get_backoff_delay(4), 14400000);
    check_eq("Backoff index 5 = 43200s (12hr)", (int)comms_get_backoff_delay(5), 43200000);
    /* Clamp beyond max */
    check_eq("Backoff index 6 clamped = 12hr", (int)comms_get_backoff_delay(6), 43200000);
    check_eq("Backoff index 100 clamped = 12hr", (int)comms_get_backoff_delay(100), 43200000);
}

/* ================================================================== */
/*  Tests: Channel Health Check                                       */
/* ================================================================== */

static void test_health_check_healthy(void) {
    printf("\n=== Health Check — Healthy Channel ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Channel is TLS connected → healthy */
    NTSTATUS status = comms_health_check(&g_ctx);
    check_eq("Health check returns success for connected channel", (int)NT_SUCCESS(status), 1);
    check_eq("Consecutive failures = 0", (int)ctx->channel_states[0].consecutive_fails, 0);
    check_eq("Channel health = HEALTHY", (int)ctx->channel_states[0].health, CHANNEL_HEALTHY);
}

static void test_health_check_failed(void) {
    printf("\n=== Health Check — Failed Channel ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Set channel to error state */
    ctx->state = COMMS_STATE_ERROR;

    NTSTATUS status = comms_health_check(&g_ctx);
    check_eq("Health check fails for error state", (int)NT_SUCCESS(status), 0);
    check_eq("Consecutive failures = 1", (int)ctx->channel_states[0].consecutive_fails, 1);
    check_eq("Channel health = DEGRADED", (int)ctx->channel_states[0].health, CHANNEL_DEGRADED);
}

static void test_health_check_max_retries(void) {
    printf("\n=== Health Check — Max Retries Exceeded ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();
    ctx->state = COMMS_STATE_ERROR;

    /* Fail max_retries times */
    for (DWORD i = 0; i < g_test_config.max_retries; i++) {
        comms_health_check(&g_ctx);
    }

    check_eq("Consecutive failures = max_retries",
             (int)ctx->channel_states[0].consecutive_fails, (int)g_test_config.max_retries);
    check_eq("Channel health = FAILED",
             (int)ctx->channel_states[0].health, CHANNEL_FAILED);
}

static void test_health_check_reset_on_success(void) {
    printf("\n=== Health Check — Reset on Success ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Accumulate some failures */
    ctx->state = COMMS_STATE_ERROR;
    comms_health_check(&g_ctx);
    comms_health_check(&g_ctx);
    check_eq("Has 2 failures", (int)ctx->channel_states[0].consecutive_fails, 2);

    /* Now succeed */
    ctx->state = COMMS_STATE_TLS_CONNECTED;
    comms_health_check(&g_ctx);
    check_eq("Failures reset to 0", (int)ctx->channel_states[0].consecutive_fails, 0);
    check_eq("Health back to HEALTHY", (int)ctx->channel_states[0].health, CHANNEL_HEALTHY);
}

/* ================================================================== */
/*  Tests: Channel Failover                                           */
/* ================================================================== */

static void test_failover_to_next_channel(void) {
    printf("\n=== Failover — Switch to Next Channel ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Primary channel is failed, failover should pick DNS (priority 1) */
    ctx->state = COMMS_STATE_ERROR;
    ctx->channel_states[0].health = CHANNEL_FAILED;
    ctx->channel_states[0].consecutive_fails = g_test_config.max_retries;

    NTSTATUS status = comms_failover(&g_ctx);
    check_eq("Failover succeeds", (int)NT_SUCCESS(status), 1);
    check_eq("Active channel changed to 1 (DNS)", (int)ctx->active_channel, 1);
    check_eq("New channel health = HEALTHY", (int)ctx->channel_states[1].health, CHANNEL_HEALTHY);
}

static void test_failover_all_channels_exhausted(void) {
    printf("\n=== Failover — All Channels Exhausted ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();
    ctx->state = COMMS_STATE_ERROR;

    /* Make all other channels fail to connect */
    g_tcp_connect_fail = TRUE;

    NTSTATUS status = comms_failover(&g_ctx);
    check_eq("Failover fails when all exhausted", (int)NT_SUCCESS(status), 0);
    check_eq("Deep sleep mode enabled", (int)ctx->deep_sleep_mode, 1);
}

static void test_failover_priority_order(void) {
    printf("\n=== Failover — Priority Order ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();
    ctx->state = COMMS_STATE_ERROR;

    /* Make DNS (channel 1) fail, so it should go to SMB (channel 2) */
    g_tcp_fail_per_channel[1] = TRUE;

    NTSTATUS status = comms_failover(&g_ctx);
    check_eq("Failover succeeds", (int)NT_SUCCESS(status), 1);
    check_eq("Skipped DNS, went to SMB (channel 2)", (int)ctx->active_channel, 2);
}

static void test_failover_skips_backoff_channels(void) {
    printf("\n=== Failover — Skips Channels in Backoff ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();
    ctx->state = COMMS_STATE_ERROR;

    /* Mark DNS channel as recently failed with backoff */
    ctx->channel_states[1].health = CHANNEL_FAILED;
    ctx->channel_states[1].backoff_delay = 60000; /* 1 minute backoff */
    ctx->channel_states[1].last_attempt = 0;
    comms_test_set_tick(30000); /* Only 30 seconds have passed */

    NTSTATUS status = comms_failover(&g_ctx);
    check_eq("Failover succeeds", (int)NT_SUCCESS(status), 1);
    check_eq("Skipped DNS (in backoff), went to SMB", (int)ctx->active_channel, 2);
}

/* ================================================================== */
/*  Tests: Retry Failed Channels                                      */
/* ================================================================== */

static void test_retry_recovers_higher_priority(void) {
    printf("\n=== Retry — Recovers Higher Priority Channel ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Current: on DNS (channel 1), HTTP (channel 0) previously failed */
    ctx->active_channel = 1;
    ctx->state = COMMS_STATE_TCP_CONNECTED;
    ctx->channel_states[0].health = CHANNEL_FAILED;
    ctx->channel_states[0].backoff_delay = 60000;
    ctx->channel_states[0].last_attempt = 0;

    /* Advance time past the backoff period */
    comms_test_set_tick(120000); /* 2 minutes past */

    NTSTATUS status = comms_retry_failed(&g_ctx);
    check_eq("Retry succeeds", (int)NT_SUCCESS(status), 1);
    check_eq("Switched back to HTTP (channel 0)", (int)ctx->active_channel, 0);
    check_eq("Recovered channel is HEALTHY", (int)ctx->channel_states[0].health, CHANNEL_HEALTHY);
    check_eq("Backoff reset to 0", (int)ctx->channel_states[0].backoff_delay, 0);
}

static void test_retry_no_recovery_during_backoff(void) {
    printf("\n=== Retry — No Recovery During Backoff ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Current: on DNS (channel 1), HTTP (channel 0) recently failed */
    ctx->active_channel = 1;
    ctx->state = COMMS_STATE_TCP_CONNECTED;
    ctx->channel_states[0].health = CHANNEL_FAILED;
    ctx->channel_states[0].backoff_delay = 60000;
    ctx->channel_states[0].last_attempt = 50000;

    /* Not enough time has passed */
    comms_test_set_tick(60000); /* Only 10 seconds since failure */

    NTSTATUS status = comms_retry_failed(&g_ctx);
    check_eq("Retry fails during backoff", (int)NT_SUCCESS(status), 0);
    check_eq("Still on DNS (channel 1)", (int)ctx->active_channel, 1);
}

static void test_retry_escalates_backoff_on_failure(void) {
    printf("\n=== Retry — Escalates Backoff on Failure ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Current: on DNS (channel 1), HTTP (channel 0) failed */
    ctx->active_channel = 1;
    ctx->state = COMMS_STATE_TCP_CONNECTED;
    ctx->channel_states[0].health = CHANNEL_FAILED;
    ctx->channel_states[0].backoff_delay = 60000;
    ctx->channel_states[0].backoff_index = 0;
    ctx->channel_states[0].last_attempt = 0;

    /* Advance time past backoff but make connection fail */
    comms_test_set_tick(120000);
    g_tcp_fail_per_channel[0] = TRUE;

    NTSTATUS status = comms_retry_failed(&g_ctx);
    check_eq("Retry fails", (int)NT_SUCCESS(status), 0);
    check_eq("Still on DNS (channel 1)", (int)ctx->active_channel, 1);
    check_eq("Backoff index advanced to 1", (int)ctx->channel_states[0].backoff_index, 1);
    check_eq("Backoff delay = 5min", (int)ctx->channel_states[0].backoff_delay, 300000);
}

static void test_retry_ignores_lower_priority(void) {
    printf("\n=== Retry — Ignores Lower Priority Channels ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Current: on HTTP (channel 0, highest priority) */
    ctx->active_channel = 0;
    ctx->state = COMMS_STATE_TLS_CONNECTED;

    /* DNS (channel 1) is failed but lower priority — shouldn't retry */
    ctx->channel_states[1].health = CHANNEL_FAILED;
    ctx->channel_states[1].backoff_delay = 0;

    comms_test_set_tick(0);

    NTSTATUS status = comms_retry_failed(&g_ctx);
    check_eq("Retry returns UNSUCCESSFUL (nothing to recover)", (int)NT_SUCCESS(status), 0);
    check_eq("Still on HTTP (channel 0)", (int)ctx->active_channel, 0);
}

/* ================================================================== */
/*  Tests: CHANNEL_STATE and enums                                    */
/* ================================================================== */

static void test_channel_state_enum_values(void) {
    printf("\n=== Channel State — Enum Values ===\n");

    check_eq("CHANNEL_HEALTHY = 0", CHANNEL_HEALTHY, 0);
    check_eq("CHANNEL_DEGRADED = 1", CHANNEL_DEGRADED, 1);
    check_eq("CHANNEL_FAILED = 2", CHANNEL_FAILED, 2);
    check_eq("CHANNEL_DEEP_SLEEP = 3", CHANNEL_DEEP_SLEEP, 3);
}

static void test_channel_state_sizeof(void) {
    printf("\n=== Channel State — Struct Size ===\n");

    /* CHANNEL_STATE should be a reasonable size */
    check_true("CHANNEL_STATE size > 0", sizeof(CHANNEL_STATE) > 0);
    check_true("COMMS_CONTEXT includes channel_states array",
               sizeof(COMMS_CONTEXT) >= sizeof(CHANNEL_STATE) * CONFIG_MAX_CHANNELS);
}

/* ================================================================== */
/*  Tests: Null safety                                                */
/* ================================================================== */

static void test_null_safety(void) {
    printf("\n=== Null Safety ===\n");

    check_eq("health_check(NULL) returns INVALID_PARAMETER",
             (int)comms_health_check(NULL), (int)STATUS_INVALID_PARAMETER);
    check_eq("failover(NULL) returns INVALID_PARAMETER",
             (int)comms_failover(NULL), (int)STATUS_INVALID_PARAMETER);
    check_eq("retry_failed(NULL) returns INVALID_PARAMETER",
             (int)comms_retry_failed(NULL), (int)STATUS_INVALID_PARAMETER);

    /* Context without comms_ctx */
    IMPLANT_CONTEXT empty_ctx = {0};
    check_eq("health_check with no comms_ctx",
             (int)comms_health_check(&empty_ctx), (int)STATUS_INVALID_PARAMETER);
    check_eq("failover with no comms_ctx",
             (int)comms_failover(&empty_ctx), (int)STATUS_INVALID_PARAMETER);
    check_eq("retry_failed with no comms_ctx",
             (int)comms_retry_failed(&empty_ctx), (int)STATUS_INVALID_PARAMETER);
}

/* ================================================================== */
/*  Tests: Deep sleep mode                                            */
/* ================================================================== */

static void test_deep_sleep_cleared_on_recovery(void) {
    printf("\n=== Deep Sleep — Cleared on Recovery ===\n");
    setup_multi_channel();

    COMMS_CONTEXT *ctx = comms_test_get_context();

    /* Enter deep sleep */
    ctx->deep_sleep_mode = TRUE;
    ctx->active_channel = 1;
    ctx->state = COMMS_STATE_TCP_CONNECTED;

    /* Channel 0 was failed, now retry succeeds */
    ctx->channel_states[0].health = CHANNEL_FAILED;
    ctx->channel_states[0].backoff_delay = 60000;
    ctx->channel_states[0].last_attempt = 0;
    comms_test_set_tick(120000);

    NTSTATUS status = comms_retry_failed(&g_ctx);
    check_eq("Retry succeeds", (int)NT_SUCCESS(status), 1);
    check_eq("Deep sleep cleared", (int)ctx->deep_sleep_mode, 0);
}

/* ================================================================== */
/*  Main                                                              */
/* ================================================================== */

int main(void) {
    printf("=== SPECTER Channel Failover Test Suite ===\n");

    /* Backoff schedule tests */
    test_backoff_schedule();

    /* Health check tests */
    test_health_check_healthy();
    test_health_check_failed();
    test_health_check_max_retries();
    test_health_check_reset_on_success();

    /* Failover tests */
    test_failover_to_next_channel();
    test_failover_all_channels_exhausted();
    test_failover_priority_order();
    test_failover_skips_backoff_channels();

    /* Retry tests */
    test_retry_recovers_higher_priority();
    test_retry_no_recovery_during_backoff();
    test_retry_escalates_backoff_on_failure();
    test_retry_ignores_lower_priority();

    /* Enum and struct tests */
    test_channel_state_enum_values();
    test_channel_state_sizeof();

    /* Null safety tests */
    test_null_safety();

    /* Deep sleep tests */
    test_deep_sleep_cleared_on_recovery();

    printf("\n===============================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
