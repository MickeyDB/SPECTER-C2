/**
 * SPECTER Implant — Memory Guard Test Suite
 *
 * Tests memguard_init, memguard_encrypt, memguard_decrypt,
 * memguard_setup_return_spoof, and sleep_ekko integration with
 * memory guard encryption/decryption cycles.
 *
 * Build (native, not PIC):
 *   gcc -o test_memguard test_memguard.c \
 *       ../core/src/evasion/memguard.c \
 *       ../core/src/crypto.c \
 *       ../core/src/sleep.c \
 *       ../core/src/config.c \
 *       -I../core/include -DTEST_BUILD -lm
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
#define STATUS_NOT_IMPLEMENTED      ((NTSTATUS)0xC0000002)
#define STATUS_INVALID_HANDLE       ((NTSTATUS)0xC0000008)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000D)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define STATUS_PROCEDURE_NOT_FOUND  ((NTSTATUS)0xC000007A)
#define STATUS_NO_MEMORY            ((NTSTATUS)0xC0000017)
#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_GUARD              0x100

#define MEM_COMMIT   0x00001000
#define MEM_RESERVE  0x00002000
#define MEM_RELEASE  0x00008000

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

/* Memory guard types */
typedef struct _STACK_REGION {
    PVOID  base;
    SIZE_T size;
    PVOID  sp_at_encrypt;
} STACK_REGION;

#define MEMGUARD_KEY_SIZE    32
#define MEMGUARD_NONCE_SIZE  12
#define MEMGUARD_HASH_SIZE   32
#define MEMGUARD_NONCE_MAGIC "SPECMGRD\x00\x00\x00\x00"

typedef struct _MEMGUARD_STATE {
    PVOID   implant_base;
    SIZE_T  implant_size;
    BYTE    enc_key[MEMGUARD_KEY_SIZE];
    BYTE    nonce[MEMGUARD_NONCE_SIZE];
    BYTE    integrity_hash[MEMGUARD_HASH_SIZE];
    STACK_REGION  stack;
    PVOID   veh_handle;
    ULONG   original_protect;
    PVOID   return_spoof_addr;
    BOOL    initialized;
    BOOL    encrypted;
    DWORD   prng_state;
} MEMGUARD_STATE;

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
    MEMGUARD_STATE memguard;
} EVASION_CONTEXT;

/* Sleep types (minimal for heap tracking) */
#define SLEEP_MAX_HEAP_ENTRIES 64

typedef struct _HEAP_ALLOC_ENTRY {
    PVOID                      ptr;
    SIZE_T                     size;
    struct _HEAP_ALLOC_ENTRY  *next;
} HEAP_ALLOC_ENTRY;

typedef struct _SLEEP_CONTEXT {
    DWORD              sleep_method;
    PVOID              implant_base;
    SIZE_T             implant_size;
    HEAP_ALLOC_ENTRY  *heap_list;
    BYTE               sleep_enc_key[32];
    ULONG              original_protect;
    BYTE               api_pad[256]; /* Placeholder for SLEEP_API */
    HEAP_ALLOC_ENTRY   heap_pool[SLEEP_MAX_HEAP_ENTRIES];
    DWORD              heap_pool_used;
} SLEEP_CONTEXT;

/* Config types */
#define SLEEP_EKKO  0
#define SLEEP_WFS   1
#define SLEEP_DELAY 2

typedef struct _IMPLANT_CONFIG {
    DWORD sleep_interval;
    DWORD jitter_percent;
    DWORD sleep_method;
    DWORD max_retries;
    DWORD kill_date;
    BYTE  padding[256];
} IMPLANT_CONFIG;

/* ------------------------------------------------------------------ */
/* Mock/stub implementations                                           */
/* ------------------------------------------------------------------ */

void* spec_memcpy(void *dst, const void *src, SIZE_T n) {
    return memcpy(dst, src, (size_t)n);
}

void* spec_memset(void *dst, int c, SIZE_T n) {
    return memset(dst, c, (size_t)n);
}

int spec_memcmp(const void *a, const void *b, SIZE_T n) {
    return memcmp(a, b, (size_t)n);
}

SIZE_T spec_strlen(const char *s) { return (SIZE_T)strlen(s); }

/* Mock PEB resolution */
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID find_export_by_hash(PVOID base, DWORD hash) {
    (void)base; (void)hash; return NULL;
}
PVOID resolve_function(DWORD mod_hash, DWORD func_hash) {
    (void)mod_hash; (void)func_hash; return NULL;
}

DWORD spec_djb2_hash(const char *str) {
    DWORD h = 5381;
    while (*str) h = ((h << 5) + h) + (unsigned char)*str++;
    return h;
}

DWORD spec_djb2_hash_w(const WCHAR *str) {
    DWORD h = 5381;
    while (*str) { h = ((h << 5) + h) + (BYTE)(*str & 0xFF); str++; }
    return h;
}

/* Mock syscall stubs */
NTSTATUS spec_syscall(DWORD ssn, PVOID addr, ...) {
    (void)ssn; (void)addr;
    return STATUS_SUCCESS;
}

SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *table, DWORD hash) {
    if (!table) return NULL;
    for (DWORD i = 0; i < table->count; i++)
        if (table->entries[i].hash == hash) return &table->entries[i];
    return NULL;
}

NTSTATUS spec_NtAllocateVirtualMemory(HANDLE p, PVOID *b, ULONG_PTR z,
    PSIZE_T s, ULONG a, ULONG pr) {
    (void)p;(void)b;(void)z;(void)s;(void)a;(void)pr; return STATUS_SUCCESS;
}
NTSTATUS spec_NtProtectVirtualMemory(HANDLE p, PVOID *b, PSIZE_T s,
    ULONG np, PULONG op) {
    (void)p;(void)b;(void)s;(void)np;
    if (op) *op = PAGE_EXECUTE_READ;
    return STATUS_SUCCESS;
}
NTSTATUS spec_NtFreeVirtualMemory(HANDLE p, PVOID *b, PSIZE_T s, ULONG f) {
    (void)p;(void)b;(void)s;(void)f; return STATUS_SUCCESS;
}
NTSTATUS spec_NtWriteVirtualMemory(HANDLE p, PVOID b, PVOID buf, SIZE_T s, PSIZE_T w) {
    (void)p;(void)b;(void)buf;(void)s;(void)w; return STATUS_SUCCESS;
}
NTSTATUS spec_NtReadVirtualMemory(HANDLE p, PVOID b, PVOID buf, SIZE_T s, PSIZE_T r) {
    (void)p;(void)b;(void)buf;(void)s;(void)r; return STATUS_SUCCESS;
}
NTSTATUS spec_NtCreateThreadEx(PHANDLE t, ULONG a, POBJECT_ATTRIBUTES o,
    HANDLE p, PVOID st, PVOID pa, ULONG f, SIZE_T z, SIZE_T ss, SIZE_T ms, PVOID al) {
    (void)t;(void)a;(void)o;(void)p;(void)st;(void)pa;(void)f;(void)z;(void)ss;(void)ms;(void)al; return STATUS_SUCCESS;
}
NTSTATUS spec_NtOpenProcess(PHANDLE p, ULONG a, POBJECT_ATTRIBUTES o, PCLIENT_ID c) {
    (void)p;(void)a;(void)o;(void)c; return STATUS_SUCCESS;
}
NTSTATUS spec_NtClose(HANDLE h) { (void)h; return STATUS_SUCCESS; }
NTSTATUS spec_NtMapViewOfSection(HANDLE sec, HANDLE proc, PVOID *b,
    ULONG_PTR z, SIZE_T c, PLARGE_INTEGER off, PSIZE_T vs,
    SECTION_INHERIT inh, ULONG at, ULONG pr) {
    (void)sec;(void)proc;(void)b;(void)z;(void)c;(void)off;(void)vs;(void)inh;(void)at;(void)pr; return STATUS_SUCCESS;
}
NTSTATUS spec_NtUnmapViewOfSection(HANDLE p, PVOID b) { (void)p;(void)b; return STATUS_SUCCESS; }
NTSTATUS spec_NtOpenSection(PHANDLE s, ULONG a, POBJECT_ATTRIBUTES o) {
    (void)s;(void)a;(void)o; return STATUS_SUCCESS;
}
NTSTATUS spec_NtCreateFile(PHANDLE f, ULONG a, POBJECT_ATTRIBUTES o,
    PIO_STATUS_BLOCK io, PLARGE_INTEGER as, ULONG fa, ULONG sa, ULONG d,
    ULONG co, PVOID ea, ULONG el) {
    (void)f;(void)a;(void)o;(void)io;(void)as;(void)fa;(void)sa;(void)d;(void)co;(void)ea;(void)el; return STATUS_SUCCESS;
}
NTSTATUS spec_NtQueryInformationProcess(HANDLE p, PROCESSINFOCLASS ic,
    PVOID i, ULONG il, PULONG rl) {
    (void)p;(void)ic;(void)i;(void)il;(void)rl; return STATUS_SUCCESS;
}
NTSTATUS spec_NtDelayExecution(BOOL a, PLARGE_INTEGER i) {
    (void)a;(void)i; return STATUS_SUCCESS;
}
NTSTATUS spec_NtWaitForSingleObject(HANDLE h, BOOL a, PLARGE_INTEGER t) {
    (void)h;(void)a;(void)t; return STATUS_SUCCESS;
}
NTSTATUS spec_NtQueueApcThread(HANDLE t, PVOID r, PVOID a1, PVOID a2, PVOID a3) {
    (void)t;(void)r;(void)a1;(void)a2;(void)a3; return STATUS_SUCCESS;
}
NTSTATUS spec_NtSetInformationThread(HANDLE t, DWORD ic, PVOID i, ULONG il) {
    (void)t;(void)ic;(void)i;(void)il; return STATUS_SUCCESS;
}

DWORD sc_resolve_ssn(PVOID ntdll, DWORD hash) { (void)ntdll; return hash & 0xFF; }
PVOID sc_find_gadget(PVOID ntdll) { (void)ntdll; return (PVOID)(ULONG_PTR)0xCAFE; }
NTSTATUS sc_init(SYSCALL_TABLE *t) { (void)t; return STATUS_SUCCESS; }

/* Mock config */
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) {
    (void)ctx;
    static IMPLANT_CONFIG cfg = { .sleep_interval = 1000, .jitter_percent = 0, .sleep_method = SLEEP_DELAY };
    return &cfg;
}

/* ------------------------------------------------------------------ */
/* Declarations from memguard.c                                        */
/* ------------------------------------------------------------------ */

NTSTATUS memguard_init(EVASION_CONTEXT *ctx, PVOID implant_base,
                       SIZE_T implant_size);
NTSTATUS memguard_encrypt(EVASION_CONTEXT *ctx);
NTSTATUS memguard_decrypt(EVASION_CONTEXT *ctx);
NTSTATUS memguard_setup_return_spoof(EVASION_CONTEXT *ctx);

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
/* Test data                                                           */
/* ------------------------------------------------------------------ */

#define TEST_IMPLANT_SIZE 4096
static BYTE test_implant[TEST_IMPLANT_SIZE];
static BYTE test_implant_backup[TEST_IMPLANT_SIZE];

#define TEST_HEAP_SIZE 256
static BYTE test_heap_a[TEST_HEAP_SIZE];
static BYTE test_heap_a_backup[TEST_HEAP_SIZE];
static BYTE test_heap_b[TEST_HEAP_SIZE];
static BYTE test_heap_b_backup[TEST_HEAP_SIZE];

#define TEST_STACK_SIZE 512
static BYTE test_stack[TEST_STACK_SIZE];
static BYTE test_stack_backup[TEST_STACK_SIZE];

static SLEEP_CONTEXT test_sleep_ctx;

static void fill_test_data(void) {
    /* Fill implant with recognizable pattern */
    for (int i = 0; i < TEST_IMPLANT_SIZE; i++)
        test_implant[i] = (BYTE)(i & 0xFF);
    memcpy(test_implant_backup, test_implant, TEST_IMPLANT_SIZE);

    /* Fill heap blocks */
    memset(test_heap_a, 0xAA, TEST_HEAP_SIZE);
    memcpy(test_heap_a_backup, test_heap_a, TEST_HEAP_SIZE);
    memset(test_heap_b, 0xBB, TEST_HEAP_SIZE);
    memcpy(test_heap_b_backup, test_heap_b, TEST_HEAP_SIZE);

    /* Fill stack */
    memset(test_stack, 0xCC, TEST_STACK_SIZE);
    memcpy(test_stack_backup, test_stack, TEST_STACK_SIZE);
}

static void setup_sleep_ctx_with_heap(void) {
    memset(&test_sleep_ctx, 0, sizeof(SLEEP_CONTEXT));

    /* Track two heap allocations */
    test_sleep_ctx.heap_pool[0].ptr = test_heap_a;
    test_sleep_ctx.heap_pool[0].size = TEST_HEAP_SIZE;
    test_sleep_ctx.heap_pool[0].next = &test_sleep_ctx.heap_pool[1];

    test_sleep_ctx.heap_pool[1].ptr = test_heap_b;
    test_sleep_ctx.heap_pool[1].size = TEST_HEAP_SIZE;
    test_sleep_ctx.heap_pool[1].next = NULL;

    test_sleep_ctx.heap_list = &test_sleep_ctx.heap_pool[0];
    test_sleep_ctx.heap_pool_used = 2;

    g_ctx.sleep_ctx = &test_sleep_ctx;
}

/* ================================================================== */
/*  memguard_init tests                                                */
/* ================================================================== */

static void test_init_null_ctx(void) {
    printf("[test_init_null_ctx]\n");
    NTSTATUS status = memguard_init(NULL, test_implant, TEST_IMPLANT_SIZE);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL ctx returns invalid param");
    printf("  Passed.\n");
}

static void test_init_null_base(void) {
    printf("[test_init_null_base]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    NTSTATUS status = memguard_init(&ctx, NULL, TEST_IMPLANT_SIZE);
    ASSERT(status == STATUS_INVALID_PARAMETER, "NULL base returns invalid param");
    printf("  Passed.\n");
}

static void test_init_zero_size(void) {
    printf("[test_init_zero_size]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    NTSTATUS status = memguard_init(&ctx, test_implant, 0);
    ASSERT(status == STATUS_INVALID_PARAMETER, "zero size returns invalid param");
    printf("  Passed.\n");
}

static void test_init_success(void) {
    printf("[test_init_success]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);
    ASSERT(NT_SUCCESS(status), "init succeeds");
    ASSERT(ctx.memguard.initialized == TRUE, "initialized flag set");
    ASSERT(ctx.memguard.encrypted == FALSE, "not encrypted initially");
    ASSERT(ctx.memguard.implant_base == test_implant, "implant_base stored");
    ASSERT(ctx.memguard.implant_size == TEST_IMPLANT_SIZE, "implant_size stored");
    ASSERT(ctx.memguard.prng_state != 0, "PRNG seeded");

    printf("  Passed.\n");
}

static void test_init_idempotent_reinit(void) {
    printf("[test_init_idempotent_reinit]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);
    DWORD first_prng = ctx.memguard.prng_state;

    /* Re-init with different region */
    BYTE other_buf[128];
    memguard_init(&ctx, other_buf, 128);
    ASSERT(ctx.memguard.implant_base == other_buf, "base updated on reinit");
    ASSERT(ctx.memguard.implant_size == 128, "size updated on reinit");
    ASSERT(ctx.memguard.encrypted == FALSE, "not encrypted after reinit");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  memguard_encrypt tests                                             */
/* ================================================================== */

static void test_encrypt_null_ctx(void) {
    printf("[test_encrypt_null_ctx]\n");
    ASSERT(memguard_encrypt(NULL) == STATUS_INVALID_PARAMETER,
           "NULL ctx returns invalid param");
    printf("  Passed.\n");
}

static void test_encrypt_uninitialized(void) {
    printf("[test_encrypt_uninitialized]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT(memguard_encrypt(&ctx) == STATUS_UNSUCCESSFUL,
           "uninitialized returns unsuccessful");
    printf("  Passed.\n");
}

static void test_encrypt_changes_implant(void) {
    printf("[test_encrypt_changes_implant]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;  /* No heap tracking */

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    NTSTATUS status = memguard_encrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "encrypt succeeds");
    ASSERT(ctx.memguard.encrypted == TRUE, "encrypted flag set");

    /* Verify implant data has changed */
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) != 0,
           "implant memory changed after encryption");

    printf("  Passed.\n");
}

static void test_encrypt_idempotent(void) {
    printf("[test_encrypt_idempotent]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);
    BYTE after_first[TEST_IMPLANT_SIZE];
    memcpy(after_first, test_implant, TEST_IMPLANT_SIZE);

    /* Second encrypt should be no-op (already encrypted) */
    NTSTATUS status = memguard_encrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "second encrypt returns success");
    ASSERT(memcmp(test_implant, after_first, TEST_IMPLANT_SIZE) == 0,
           "double encrypt is idempotent");

    printf("  Passed.\n");
}

static void test_encrypt_key_generated(void) {
    printf("[test_encrypt_key_generated]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Key should be all zeros before encrypt */
    BYTE zero_key[MEMGUARD_KEY_SIZE];
    memset(zero_key, 0, MEMGUARD_KEY_SIZE);
    ASSERT(memcmp(ctx.memguard.enc_key, zero_key, MEMGUARD_KEY_SIZE) == 0,
           "key is zero before encrypt");

    memguard_encrypt(&ctx);

    ASSERT(memcmp(ctx.memguard.enc_key, zero_key, MEMGUARD_KEY_SIZE) != 0,
           "key is non-zero after encrypt");

    printf("  Passed.\n");
}

static void test_encrypt_integrity_hash_stored(void) {
    printf("[test_encrypt_integrity_hash_stored]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);

    /* Integrity hash should be non-zero */
    BYTE zero_hash[MEMGUARD_HASH_SIZE];
    memset(zero_hash, 0, MEMGUARD_HASH_SIZE);
    ASSERT(memcmp(ctx.memguard.integrity_hash, zero_hash, MEMGUARD_HASH_SIZE) != 0,
           "integrity hash stored");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  memguard_decrypt tests                                             */
/* ================================================================== */

static void test_decrypt_null_ctx(void) {
    printf("[test_decrypt_null_ctx]\n");
    ASSERT(memguard_decrypt(NULL) == STATUS_INVALID_PARAMETER,
           "NULL ctx returns invalid param");
    printf("  Passed.\n");
}

static void test_decrypt_uninitialized(void) {
    printf("[test_decrypt_uninitialized]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT(memguard_decrypt(&ctx) == STATUS_UNSUCCESSFUL,
           "uninitialized returns unsuccessful");
    printf("  Passed.\n");
}

static void test_decrypt_not_encrypted(void) {
    printf("[test_decrypt_not_encrypted]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Not encrypted — should be a no-op */
    NTSTATUS status = memguard_decrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "decrypt on non-encrypted returns success");
    printf("  Passed.\n");
}

static void test_encrypt_decrypt_roundtrip(void) {
    printf("[test_encrypt_decrypt_roundtrip]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) != 0,
           "data is encrypted");

    NTSTATUS status = memguard_decrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "decrypt succeeds");
    ASSERT(ctx.memguard.encrypted == FALSE, "encrypted flag cleared");
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) == 0,
           "data restored after decrypt");

    printf("  Passed.\n");
}

static void test_decrypt_clears_key(void) {
    printf("[test_decrypt_clears_key]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);
    memguard_decrypt(&ctx);

    /* Key should be zeroed after decrypt */
    BYTE zero_key[MEMGUARD_KEY_SIZE];
    memset(zero_key, 0, MEMGUARD_KEY_SIZE);
    ASSERT(memcmp(ctx.memguard.enc_key, zero_key, MEMGUARD_KEY_SIZE) == 0,
           "key zeroed after decrypt");

    printf("  Passed.\n");
}

static void test_integrity_check_passes(void) {
    printf("[test_integrity_check_passes]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);
    NTSTATUS status = memguard_decrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "integrity check passes on clean decrypt");

    printf("  Passed.\n");
}

static void test_integrity_check_detects_corruption(void) {
    printf("[test_integrity_check_detects_corruption]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);

    /* Corrupt encrypted data to simulate memory tampering */
    test_implant[100] ^= 0xFF;
    test_implant[101] ^= 0xFF;

    NTSTATUS status = memguard_decrypt(&ctx);
    ASSERT(status == STATUS_UNSUCCESSFUL,
           "integrity check fails on corrupted data");

    printf("  Passed.\n");
}

static void test_multiple_cycles(void) {
    printf("[test_multiple_cycles]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Run three full encrypt/decrypt cycles */
    for (int cycle = 0; cycle < 3; cycle++) {
        NTSTATUS enc = memguard_encrypt(&ctx);
        ASSERT(NT_SUCCESS(enc), "encrypt succeeds in cycle");
        ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) != 0,
               "data encrypted in cycle");

        NTSTATUS dec = memguard_decrypt(&ctx);
        ASSERT(NT_SUCCESS(dec), "decrypt succeeds in cycle");
        ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) == 0,
               "data restored in cycle");
    }

    printf("  Passed.\n");
}

static void test_different_keys_per_cycle(void) {
    printf("[test_different_keys_per_cycle]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* First cycle: capture encrypted form */
    memguard_encrypt(&ctx);
    BYTE enc1[TEST_IMPLANT_SIZE];
    memcpy(enc1, test_implant, TEST_IMPLANT_SIZE);
    memguard_decrypt(&ctx);

    /* Second cycle: should produce different ciphertext (different key) */
    memguard_encrypt(&ctx);
    BYTE enc2[TEST_IMPLANT_SIZE];
    memcpy(enc2, test_implant, TEST_IMPLANT_SIZE);
    memguard_decrypt(&ctx);

    ASSERT(memcmp(enc1, enc2, TEST_IMPLANT_SIZE) != 0,
           "different keys produce different ciphertext");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Heap encryption integration tests                                  */
/* ================================================================== */

static void test_encrypt_with_heap(void) {
    printf("[test_encrypt_with_heap]\n");
    fill_test_data();
    setup_sleep_ctx_with_heap();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);

    /* Verify heap blocks are encrypted */
    ASSERT(memcmp(test_heap_a, test_heap_a_backup, TEST_HEAP_SIZE) != 0,
           "heap A encrypted");
    ASSERT(memcmp(test_heap_b, test_heap_b_backup, TEST_HEAP_SIZE) != 0,
           "heap B encrypted");

    printf("  Passed.\n");
}

static void test_decrypt_with_heap_roundtrip(void) {
    printf("[test_decrypt_with_heap_roundtrip]\n");
    fill_test_data();
    setup_sleep_ctx_with_heap();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);
    memguard_decrypt(&ctx);

    /* Verify all data restored */
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) == 0,
           "implant data restored");
    ASSERT(memcmp(test_heap_a, test_heap_a_backup, TEST_HEAP_SIZE) == 0,
           "heap A data restored");
    ASSERT(memcmp(test_heap_b, test_heap_b_backup, TEST_HEAP_SIZE) == 0,
           "heap B data restored");

    printf("  Passed.\n");
}

static void test_encrypt_no_heap_ctx(void) {
    printf("[test_encrypt_no_heap_ctx]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Should succeed even without heap context */
    NTSTATUS status = memguard_encrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "encrypt works without heap context");

    memguard_decrypt(&ctx);
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) == 0,
           "implant restored without heap context");

    printf("  Passed.\n");
}

static void test_encrypt_empty_heap_list(void) {
    printf("[test_encrypt_empty_heap_list]\n");
    fill_test_data();

    memset(&test_sleep_ctx, 0, sizeof(SLEEP_CONTEXT));
    test_sleep_ctx.heap_list = NULL;
    g_ctx.sleep_ctx = &test_sleep_ctx;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    NTSTATUS status = memguard_encrypt(&ctx);
    ASSERT(NT_SUCCESS(status), "encrypt works with empty heap list");

    memguard_decrypt(&ctx);
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) == 0,
           "implant restored with empty heap list");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Stack encryption tests                                             */
/* ================================================================== */

static void test_encrypt_with_stack(void) {
    printf("[test_encrypt_with_stack]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Set up test stack region */
    ctx.memguard.stack.base = test_stack;
    ctx.memguard.stack.size = TEST_STACK_SIZE;

    memguard_encrypt(&ctx);

    /* Verify stack is encrypted */
    ASSERT(memcmp(test_stack, test_stack_backup, TEST_STACK_SIZE) != 0,
           "stack encrypted");

    printf("  Passed.\n");
}

static void test_encrypt_decrypt_stack_roundtrip(void) {
    printf("[test_encrypt_decrypt_stack_roundtrip]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    ctx.memguard.stack.base = test_stack;
    ctx.memguard.stack.size = TEST_STACK_SIZE;

    memguard_encrypt(&ctx);
    memguard_decrypt(&ctx);

    ASSERT(memcmp(test_stack, test_stack_backup, TEST_STACK_SIZE) == 0,
           "stack data restored after roundtrip");

    printf("  Passed.\n");
}

static void test_full_encrypt_decrypt_all_regions(void) {
    printf("[test_full_encrypt_decrypt_all_regions]\n");
    fill_test_data();
    setup_sleep_ctx_with_heap();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);
    ctx.memguard.stack.base = test_stack;
    ctx.memguard.stack.size = TEST_STACK_SIZE;

    memguard_encrypt(&ctx);

    /* All regions should be encrypted */
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) != 0,
           "implant encrypted");
    ASSERT(memcmp(test_heap_a, test_heap_a_backup, TEST_HEAP_SIZE) != 0,
           "heap A encrypted");
    ASSERT(memcmp(test_heap_b, test_heap_b_backup, TEST_HEAP_SIZE) != 0,
           "heap B encrypted");
    ASSERT(memcmp(test_stack, test_stack_backup, TEST_STACK_SIZE) != 0,
           "stack encrypted");

    memguard_decrypt(&ctx);

    /* All regions should be restored */
    ASSERT(memcmp(test_implant, test_implant_backup, TEST_IMPLANT_SIZE) == 0,
           "implant restored");
    ASSERT(memcmp(test_heap_a, test_heap_a_backup, TEST_HEAP_SIZE) == 0,
           "heap A restored");
    ASSERT(memcmp(test_heap_b, test_heap_b_backup, TEST_HEAP_SIZE) == 0,
           "heap B restored");
    ASSERT(memcmp(test_stack, test_stack_backup, TEST_STACK_SIZE) == 0,
           "stack restored");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  memguard_setup_return_spoof tests                                  */
/* ================================================================== */

static void test_return_spoof_null_ctx(void) {
    printf("[test_return_spoof_null_ctx]\n");
    ASSERT(memguard_setup_return_spoof(NULL) == STATUS_INVALID_PARAMETER,
           "NULL ctx returns invalid param");
    printf("  Passed.\n");
}

static void test_return_spoof_uninitialized(void) {
    printf("[test_return_spoof_uninitialized]\n");
    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT(memguard_setup_return_spoof(&ctx) == STATUS_UNSUCCESSFUL,
           "uninitialized returns unsuccessful");
    printf("  Passed.\n");
}

/* Fake code regions for frame library */
static BYTE fake_code_region[256];

static void test_return_spoof_with_frames(void) {
    printf("[test_return_spoof_with_frames]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Populate frame library with a test frame from ntdll */
    ctx.frame_lib.entries[0].code_start = fake_code_region;
    ctx.frame_lib.entries[0].code_end = fake_code_region + 128;
    ctx.frame_lib.entries[0].unwind_info = NULL;
    ctx.frame_lib.entries[0].module_hash = HASH_NTDLL_DLL;
    ctx.frame_lib.count = 1;

    NTSTATUS status = memguard_setup_return_spoof(&ctx);
    ASSERT(NT_SUCCESS(status), "return spoof succeeds with frames");
    ASSERT(ctx.memguard.return_spoof_addr != NULL, "spoof address set");

    /* Verify address is within the frame's code region */
    BYTE *addr = (BYTE *)ctx.memguard.return_spoof_addr;
    ASSERT(addr >= fake_code_region && addr < fake_code_region + 128,
           "spoof address within frame bounds");

    printf("  Passed.\n");
}

static void test_return_spoof_prefers_ntdll(void) {
    printf("[test_return_spoof_prefers_ntdll]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* Add a user32 frame first, then ntdll */
    static BYTE user32_code[64];
    ctx.frame_lib.entries[0].code_start = user32_code;
    ctx.frame_lib.entries[0].code_end = user32_code + 64;
    ctx.frame_lib.entries[0].module_hash = HASH_USER32_DLL;

    ctx.frame_lib.entries[1].code_start = fake_code_region;
    ctx.frame_lib.entries[1].code_end = fake_code_region + 128;
    ctx.frame_lib.entries[1].module_hash = HASH_KERNEL32_DLL;
    ctx.frame_lib.count = 2;

    NTSTATUS status = memguard_setup_return_spoof(&ctx);
    ASSERT(NT_SUCCESS(status), "return spoof succeeds");

    /* Should pick the kernel32 frame (ntdll or kernel32 preferred) */
    BYTE *addr = (BYTE *)ctx.memguard.return_spoof_addr;
    ASSERT(addr >= fake_code_region && addr < fake_code_region + 128,
           "prefers kernel32/ntdll frame");

    printf("  Passed.\n");
}

static void test_return_spoof_fallback_to_clean_ntdll(void) {
    printf("[test_return_spoof_fallback_to_clean_ntdll]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    /* No frames, but clean_ntdll is set */
    ctx.frame_lib.count = 0;
    ctx.clean_ntdll = (PVOID)(ULONG_PTR)0x7FFE0000;

    NTSTATUS status = memguard_setup_return_spoof(&ctx);
    ASSERT(NT_SUCCESS(status), "fallback to clean_ntdll succeeds");
    ASSERT(ctx.memguard.return_spoof_addr != NULL, "spoof address set via fallback");

    /* Should be clean_ntdll + 0x1000 */
    ASSERT(ctx.memguard.return_spoof_addr == (PVOID)(ULONG_PTR)0x7FFE1000,
           "fallback address correct");

    printf("  Passed.\n");
}

static void test_return_spoof_no_frames_no_ntdll(void) {
    printf("[test_return_spoof_no_frames_no_ntdll]\n");

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    ctx.frame_lib.count = 0;
    ctx.clean_ntdll = NULL;

    NTSTATUS status = memguard_setup_return_spoof(&ctx);
    ASSERT(status == STATUS_UNSUCCESSFUL,
           "fails with no frames and no clean_ntdll");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Edge cases and stress tests                                        */
/* ================================================================== */

static void test_small_implant(void) {
    printf("[test_small_implant]\n");
    BYTE small_buf[16];
    BYTE small_backup[16];
    memset(small_buf, 0x42, 16);
    memcpy(small_backup, small_buf, 16);

    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, small_buf, 16);

    memguard_encrypt(&ctx);
    ASSERT(memcmp(small_buf, small_backup, 16) != 0, "small buffer encrypted");

    memguard_decrypt(&ctx);
    ASSERT(memcmp(small_buf, small_backup, 16) == 0, "small buffer restored");

    printf("  Passed.\n");
}

static void test_single_byte_implant(void) {
    printf("[test_single_byte_implant]\n");
    BYTE one_byte = 0x55;
    BYTE backup = one_byte;

    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, &one_byte, 1);

    memguard_encrypt(&ctx);
    /* Might or might not change depending on keystream, but roundtrip should work */
    memguard_decrypt(&ctx);
    ASSERT(one_byte == backup, "single byte roundtrip");

    printf("  Passed.\n");
}

static void test_encrypt_decrypt_preserves_prng_state(void) {
    printf("[test_encrypt_decrypt_preserves_prng_state]\n");
    fill_test_data();
    g_ctx.sleep_ctx = NULL;

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);
    DWORD prng_after_encrypt = ctx.memguard.prng_state;

    memguard_decrypt(&ctx);
    /* PRNG state should not be reset by decrypt */
    ASSERT(ctx.memguard.prng_state == prng_after_encrypt,
           "PRNG state preserved through decrypt");

    printf("  Passed.\n");
}

static void test_heap_corruption_detected(void) {
    printf("[test_heap_corruption_detected]\n");
    fill_test_data();
    setup_sleep_ctx_with_heap();

    EVASION_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    memguard_init(&ctx, test_implant, TEST_IMPLANT_SIZE);

    memguard_encrypt(&ctx);

    /* Corrupt the implant memory while encrypted */
    test_implant[0] ^= 0xFF;
    test_implant[1] ^= 0xFF;
    test_implant[2] ^= 0xFF;
    test_implant[3] ^= 0xFF;

    NTSTATUS status = memguard_decrypt(&ctx);
    ASSERT(!NT_SUCCESS(status), "integrity violation detected");

    printf("  Passed.\n");
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void) {
    printf("=== SPECTER Memory Guard Test Suite ===\n\n");

    /* memguard_init tests */
    test_init_null_ctx();
    test_init_null_base();
    test_init_zero_size();
    test_init_success();
    test_init_idempotent_reinit();

    /* memguard_encrypt tests */
    test_encrypt_null_ctx();
    test_encrypt_uninitialized();
    test_encrypt_changes_implant();
    test_encrypt_idempotent();
    test_encrypt_key_generated();
    test_encrypt_integrity_hash_stored();

    /* memguard_decrypt tests */
    test_decrypt_null_ctx();
    test_decrypt_uninitialized();
    test_decrypt_not_encrypted();
    test_encrypt_decrypt_roundtrip();
    test_decrypt_clears_key();
    test_integrity_check_passes();
    test_integrity_check_detects_corruption();
    test_multiple_cycles();
    test_different_keys_per_cycle();

    /* Heap integration tests */
    test_encrypt_with_heap();
    test_decrypt_with_heap_roundtrip();
    test_encrypt_no_heap_ctx();
    test_encrypt_empty_heap_list();

    /* Stack encryption tests */
    test_encrypt_with_stack();
    test_encrypt_decrypt_stack_roundtrip();
    test_full_encrypt_decrypt_all_regions();

    /* Return spoof tests */
    test_return_spoof_null_ctx();
    test_return_spoof_uninitialized();
    test_return_spoof_with_frames();
    test_return_spoof_prefers_ntdll();
    test_return_spoof_fallback_to_clean_ntdll();
    test_return_spoof_no_frames_no_ntdll();

    /* Edge cases */
    test_small_implant();
    test_single_byte_implant();
    test_encrypt_decrypt_preserves_prng_state();
    test_heap_corruption_detected();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
