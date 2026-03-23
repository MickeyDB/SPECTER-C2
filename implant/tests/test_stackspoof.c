/**
 * SPECTER Implant — Stack Spoofing Test Suite
 *
 * Tests frame library initialization from mock PE modules,
 * frame chain selection with termination functions, and
 * stack spoofing/restoration.
 *
 * Build (native, not PIC):
 *   gcc -o test_stackspoof test_stackspoof.c \
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

/* Syscall stubs */
NTSTATUS spec_syscall(DWORD ssn, PVOID addr, ...) { (void)ssn; (void)addr; return STATUS_SUCCESS; }
SYSCALL_TABLE g_syscall_table;
SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *t, DWORD h) { (void)t; (void)h; return NULL; }

/* ------------------------------------------------------------------ */
/* Include evasion header after stubs                                  */
/* ------------------------------------------------------------------ */

/* Redefine IMAGE_DIRECTORY_ENTRY_EXCEPTION since we need it */
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

/* Include evasion types inline (avoid double-include issues with stubs) */
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

/* Declarations from stackspoof.c */
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
/*  Test: evasion_init_frames returns failure with no PEB (test stub)  */
/* ------------------------------------------------------------------ */

static void test_init_frames_no_peb(void) {
    printf("[test_init_frames_no_peb]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* With our stub PEB (returns NULL), init should fail gracefully */
    NTSTATUS status = evasion_init_frames(&ctx);
    ASSERT(!NT_SUCCESS(status), "init_frames fails with no modules");
    ASSERT(ctx.frame_lib.count == 0, "frame count is 0");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_init_frames rejects NULL ctx                         */
/* ------------------------------------------------------------------ */

static void test_init_frames_null(void) {
    printf("[test_init_frames_null]\n");

    NTSTATUS status = evasion_init_frames(NULL);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: frame library structure defaults                             */
/* ------------------------------------------------------------------ */

static void test_frame_library_defaults(void) {
    printf("[test_frame_library_defaults]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* After failed init, max_capacity should still be set */
    evasion_init_frames(&ctx);
    ASSERT(ctx.frame_lib.max_capacity == FRAME_MAX_ENTRIES, "max_capacity is 256");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_select_frames with empty library                     */
/* ------------------------------------------------------------------ */

static void test_select_frames_empty(void) {
    printf("[test_select_frames_empty]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.frame_lib.max_capacity = FRAME_MAX_ENTRIES;

    FRAME_ENTRY *chain[FRAME_CHAIN_MAX];
    DWORD count = evasion_select_frames(&ctx, 0, chain, 4);
    ASSERT(count == 0, "select from empty lib returns 0");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_select_frames with populated library                 */
/* ------------------------------------------------------------------ */

static void test_select_frames_populated(void) {
    printf("[test_select_frames_populated]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.frame_lib.max_capacity = FRAME_MAX_ENTRIES;
    ctx.prng_state = 0x42424242;

    /* Create synthetic frame entries */
    static BYTE fake_code[10][256]; /* 10 fake functions, 256 bytes each */
    static BYTE fake_unwind[10][8];

    for (int i = 0; i < 10; i++) {
        /* Set up unwind info: version 1 */
        fake_unwind[i][0] = 0x01; /* version=1, flags=0 */

        ctx.frame_lib.entries[i].code_start = &fake_code[i][0];
        ctx.frame_lib.entries[i].code_end = &fake_code[i][256];
        ctx.frame_lib.entries[i].unwind_info = &fake_unwind[i][0];
        ctx.frame_lib.entries[i].module_hash = HASH_KERNEL32_DLL;
    }
    ctx.frame_lib.count = 10;

    FRAME_ENTRY *chain[FRAME_CHAIN_MAX];
    DWORD count = evasion_select_frames(&ctx, 0, chain, 4);
    ASSERT(count > 0, "select from populated lib returns frames");
    ASSERT(count <= FRAME_CHAIN_MAX, "count within bounds");

    /* All chain entries should be valid pointers */
    for (DWORD i = 0; i < count; i++) {
        ASSERT(chain[i] != NULL, "chain entry is non-NULL");
        ASSERT(chain[i]->code_start != NULL, "chain entry has code_start");
    }

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: evasion_select_frames NULL params                            */
/* ------------------------------------------------------------------ */

static void test_select_frames_null(void) {
    printf("[test_select_frames_null]\n");

    FRAME_ENTRY *chain[4];
    ASSERT(evasion_select_frames(NULL, 0, chain, 4) == 0, "NULL ctx returns 0");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT(evasion_select_frames(&ctx, 0, NULL, 4) == 0, "NULL chain returns 0");
    ASSERT(evasion_select_frames(&ctx, 0, chain, 0) == 0, "zero count returns 0");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: build/restore spoofed stack                                  */
/* ------------------------------------------------------------------ */

static void test_build_restore_stack(void) {
    printf("[test_build_restore_stack]\n");

    /* Allocate a fake stack region */
    QWORD fake_stack[64];
    memset(fake_stack, 0, sizeof(fake_stack));

    /* Fill with known patterns */
    for (int i = 0; i < 64; i++) {
        fake_stack[i] = 0xDEADBEEF00000000ULL | (QWORD)i;
    }

    /* Create synthetic frames */
    static BYTE code_a[256], code_b[256], code_c[256];
    static BYTE unwind_a[8] = {0x01}, unwind_b[8] = {0x01}, unwind_c[8] = {0x01};

    FRAME_ENTRY frames[3] = {
        { code_a, code_a + 256, unwind_a, HASH_KERNEL32_DLL },
        { code_b, code_b + 256, unwind_b, HASH_NTDLL_DLL },
        { code_c, code_c + 256, unwind_c, HASH_NTDLL_DLL },
    };
    FRAME_ENTRY *chain[3] = { &frames[0], &frames[1], &frames[2] };

    /* Save original values for verification */
    QWORD orig_values[6];
    memcpy(orig_values, fake_stack, sizeof(orig_values));

    SAVED_STACK_FRAMES saved;
    memset(&saved, 0, sizeof(saved));

    QWORD rsp = (QWORD)&fake_stack[0];
    NTSTATUS status = evasion_build_spoofed_stack(chain, 3, rsp, &saved);
    ASSERT(NT_SUCCESS(status), "build_spoofed_stack succeeds");
    ASSERT(saved.frame_count == 3, "saved 3 frames");
    ASSERT(saved.original_rsp == rsp, "saved RSP matches");

    /* Verify spoofed values are different from originals */
    BOOL modified = FALSE;
    for (int i = 0; i < 6; i++) {
        if (fake_stack[i] != orig_values[i]) {
            modified = TRUE;
            break;
        }
    }
    ASSERT(modified, "stack was modified by spoofing");

    /* Verify return addresses point within function bodies */
    for (DWORD i = 0; i < saved.frame_count; i++) {
        QWORD ret_addr = fake_stack[i * 2];
        ULONG_PTR start = (ULONG_PTR)chain[i]->code_start;
        ULONG_PTR end = (ULONG_PTR)chain[i]->code_end;
        ASSERT(ret_addr >= start && ret_addr < end,
               "spoofed ret addr within function bounds");
    }

    /* Verify last frame's RBP is 0 (termination) */
    ASSERT(fake_stack[2 * 2 + 1] == 0, "last frame RBP is 0 (terminated)");

    /* Now restore */
    evasion_restore_stack(&saved);

    /* Verify original values restored */
    BOOL restored = TRUE;
    for (int i = 0; i < 6; i++) {
        if (fake_stack[i] != orig_values[i]) {
            restored = FALSE;
            break;
        }
    }
    ASSERT(restored, "stack restored to original after evasion_restore_stack");
    ASSERT(saved.frame_count == 0, "saved state zeroed after restore");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: build spoofed stack NULL params                              */
/* ------------------------------------------------------------------ */

static void test_build_stack_null_params(void) {
    printf("[test_build_stack_null_params]\n");

    SAVED_STACK_FRAMES saved;
    FRAME_ENTRY *chain[1] = { NULL };

    ASSERT(evasion_build_spoofed_stack(NULL, 1, 0x1000, &saved) == STATUS_INVALID_PARAMETER,
           "NULL chain returns invalid param");
    ASSERT(evasion_build_spoofed_stack(chain, 0, 0x1000, &saved) == STATUS_INVALID_PARAMETER,
           "zero count returns invalid param");
    ASSERT(evasion_build_spoofed_stack(chain, 1, 0, &saved) == STATUS_INVALID_PARAMETER,
           "zero RSP returns invalid param");
    ASSERT(evasion_build_spoofed_stack(chain, 1, 0x1000, NULL) == STATUS_INVALID_PARAMETER,
           "NULL saved returns invalid param");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: restore stack with NULL/empty saved                          */
/* ------------------------------------------------------------------ */

static void test_restore_stack_edge_cases(void) {
    printf("[test_restore_stack_edge_cases]\n");

    /* Should not crash */
    evasion_restore_stack(NULL);

    SAVED_STACK_FRAMES saved;
    memset(&saved, 0, sizeof(saved));
    evasion_restore_stack(&saved); /* frame_count == 0 */

    saved.frame_count = 1;
    saved.original_rsp = 0; /* invalid RSP */
    evasion_restore_stack(&saved); /* Should handle gracefully */

    ASSERT(1, "edge cases handled without crash");
    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: PRNG seed in test mode                                       */
/* ------------------------------------------------------------------ */

static void test_prng_seed(void) {
    printf("[test_prng_seed]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.prng_state = 0;

    evasion_test_set_prng_seed(&ctx, 0x42424242);
    ASSERT(ctx.prng_state == 0x42424242, "PRNG seed set correctly");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Test: frame entry structure sizes                                  */
/* ------------------------------------------------------------------ */

static void test_structure_sizes(void) {
    printf("[test_structure_sizes]\n");

    ASSERT(sizeof(FRAME_ENTRY) > 0, "FRAME_ENTRY has non-zero size");
    ASSERT(sizeof(FRAME_LIBRARY) > 0, "FRAME_LIBRARY has non-zero size");
    ASSERT(sizeof(SAVED_STACK_FRAMES) > 0, "SAVED_STACK_FRAMES has non-zero size");
    ASSERT(sizeof(EVASION_CONTEXT) > 0, "EVASION_CONTEXT has non-zero size");

    /* Verify FRAME_LIBRARY has room for 256 entries */
    FRAME_LIBRARY lib;
    ASSERT(sizeof(lib.entries) / sizeof(lib.entries[0]) == FRAME_MAX_ENTRIES,
           "FRAME_LIBRARY holds 256 entries");

    printf("  Passed.\n");
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Stack Spoofing Test Suite ===\n\n");

    test_init_frames_no_peb();
    test_init_frames_null();
    test_frame_library_defaults();
    test_select_frames_empty();
    test_select_frames_populated();
    test_select_frames_null();
    test_build_restore_stack();
    test_build_stack_null_params();
    test_restore_stack_edge_cases();
    test_prng_seed();
    test_structure_sizes();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
