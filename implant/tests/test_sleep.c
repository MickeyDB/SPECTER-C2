/**
 * SPECTER Implant — Sleep Controller Test Suite
 *
 * Tests jitter calculation, heap tracking, heap encryption/decryption,
 * and sleep context initialization.
 *
 * Build (native, not PIC):
 *   gcc -o test_sleep test_sleep.c ../core/src/sleep.c \
 *       ../core/src/crypto.c ../core/src/config.c \
 *       ../core/src/evasion/memguard.c \
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
#define STATUS_NOT_IMPLEMENTED      ((NTSTATUS)0xC0000002)
#define STATUS_INVALID_HANDLE       ((NTSTATUS)0xC0000008)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000D)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define STATUS_NO_MEMORY            ((NTSTATUS)0xC0000017)
#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40

#define MEM_COMMIT   0x00001000
#define MEM_RESERVE  0x00002000
#define MEM_RELEASE  0x00008000

/* Stub PEB/PE types */
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

/* Stub structures */
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

/* Syscall stubs (not used in test builds, but needed for linking) */
NTSTATUS spec_NtDelayExecution(BOOL alertable, PLARGE_INTEGER interval) {
    (void)alertable; (void)interval;
    return STATUS_SUCCESS;
}
NTSTATUS spec_NtProtectVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG new_protect, PULONG old_protect) {
    (void)process; (void)base; (void)size; (void)new_protect; (void)old_protect;
    return STATUS_SUCCESS;
}
NTSTATUS spec_NtAllocateVirtualMemory(HANDLE p, PVOID *b, ULONG_PTR z,
    PSIZE_T s, ULONG at, ULONG pr) {
    (void)p;(void)b;(void)z;(void)s;(void)at;(void)pr; return STATUS_SUCCESS;
}
NTSTATUS spec_NtFreeVirtualMemory(HANDLE p, PVOID *b, PSIZE_T s, ULONG ft) {
    (void)p;(void)b;(void)s;(void)ft; return STATUS_SUCCESS;
}
NTSTATUS spec_NtWaitForSingleObject(HANDLE h, BOOL a, PLARGE_INTEGER t) {
    (void)h;(void)a;(void)t; return STATUS_SUCCESS;
}
NTSTATUS spec_NtQueueApcThread(HANDLE thread, PVOID apc_routine,
    PVOID arg1, PVOID arg2, PVOID arg3) {
    (void)thread;(void)apc_routine;(void)arg1;(void)arg2;(void)arg3;
    return STATUS_SUCCESS;
}
NTSTATUS spec_NtTestAlert(void) { return STATUS_SUCCESS; }

/* Crypto declarations */
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

void spec_chacha20_block(const DWORD state[16], BYTE output[64]);
void spec_chacha20_encrypt(const BYTE key[32], const BYTE nonce[12], DWORD counter, const BYTE *plaintext, DWORD len, BYTE *ciphertext);
void spec_poly1305_auth(BYTE tag_out[16], const BYTE *msg, DWORD msg_len, const BYTE key[32]);
void spec_aead_encrypt(const BYTE key[32], const BYTE nonce[12], const BYTE *plaintext, DWORD pt_len, const BYTE *aad, DWORD aad_len, BYTE *ciphertext, BYTE tag[16]);
BOOL spec_aead_decrypt(const BYTE key[32], const BYTE nonce[12], const BYTE *ciphertext, DWORD ct_len, const BYTE *aad, DWORD aad_len, BYTE *plaintext, const BYTE tag[16]);
void spec_sha256_init(SHA256_CTX *ctx);
void spec_sha256_update(SHA256_CTX *ctx, const BYTE *data, DWORD len);
void spec_sha256_final(SHA256_CTX *ctx, BYTE digest[32]);
void spec_sha256(const BYTE *data, DWORD len, BYTE digest[32]);
void spec_hmac_sha256(const BYTE *key, DWORD key_len, const BYTE *data, DWORD data_len, BYTE mac[32]);
void spec_hkdf_extract(const BYTE *salt, DWORD salt_len, const BYTE *ikm, DWORD ikm_len, BYTE prk[32]);
void spec_hkdf_expand(const BYTE prk[32], const BYTE *info, DWORD info_len, BYTE *okm, DWORD okm_len);
void spec_hkdf_derive(const BYTE *salt, DWORD salt_len, const BYTE *ikm, DWORD ikm_len, const BYTE *info, DWORD info_len, BYTE *okm, DWORD okm_len);
void spec_decrypt_string(const BYTE *encrypted, DWORD len, BYTE *output);

/* Config declarations */
#define CONFIG_MAGIC           0x53504543
#define CONFIG_VERSION         1
#define CONFIG_MAX_CHANNELS    4
#define CONFIG_KEY_INPUT_SIZE  64
#define CONFIG_SCAN_MAX        0x10000
#define CONFIG_SCAN_START      256

typedef enum _CHANNEL_TYPE { CHANNEL_HTTP=0, CHANNEL_DNS=1, CHANNEL_SMB=2, CHANNEL_WEBSOCKET=3 } CHANNEL_TYPE;
typedef enum _SLEEP_METHOD { SLEEP_EKKO=0, SLEEP_WFS=1, SLEEP_DELAY=2, SLEEP_FOLIAGE=3, SLEEP_THREADPOOL=4 } SLEEP_METHOD;

typedef struct _CHANNEL_CONFIG {
    char   url[256];
    DWORD  port;
    DWORD  type;
    DWORD  priority;
    DWORD  active;
} CHANNEL_CONFIG;

typedef struct _IMPLANT_CONFIG {
    BYTE           teamserver_pubkey[32];
    BYTE           implant_privkey[32];
    BYTE           implant_pubkey[32];
    BYTE           module_signing_key[32];
    DWORD          sleep_interval;
    DWORD          jitter_percent;
    DWORD          sleep_method;
    CHANNEL_CONFIG channels[CONFIG_MAX_CHANNELS];
    DWORD          channel_count;
    DWORD          max_retries;
    QWORD          kill_date;
    DWORD          profile_id;
    DWORD          checkin_count;
} IMPLANT_CONFIG;

typedef struct _CONFIG_BLOB_HEADER {
    DWORD magic;
    DWORD version;
    DWORD data_size;
    BYTE  nonce[12];
    BYTE  tag[16];
} CONFIG_BLOB_HEADER;

/* Config stubs */
NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return NULL;
    return (IMPLANT_CONFIG *)ctx->config;
}
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) {
    (void)ctx;(void)data;(void)len; return STATUS_SUCCESS;
}
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx) { (void)ctx; return STATUS_SUCCESS; }
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx) { (void)ctx; return FALSE; }
void cfg_test_set_pic_base(PVOID base) { (void)base; }
void cfg_test_set_system_time(QWORD time) { (void)time; }

/* Comms stub */
typedef struct _PROFILE_CONFIG { int dummy; } PROFILE_CONFIG;
PROFILE_CONFIG *comms_get_profile_ptr(PVOID comms_ctx) {
    (void)comms_ctx; return NULL;
}

/* Evasion/memguard stubs */
typedef struct _MEMGUARD_STATE { BOOL initialized; PVOID return_spoof_addr; } MEMGUARD_STATE;
typedef struct _EVASION_CONTEXT { MEMGUARD_STATE memguard; } EVASION_CONTEXT;
NTSTATUS memguard_encrypt(EVASION_CONTEXT *ectx) { (void)ectx; return STATUS_SUCCESS; }
NTSTATUS memguard_decrypt(EVASION_CONTEXT *ectx) { (void)ectx; return STATUS_SUCCESS; }
void memguard_setup_return_spoof(EVASION_CONTEXT *ectx) { (void)ectx; }

/* Sleep declarations */
#define HASH_ADVAPI32_DLL           0x67208A49
#define HASH_CREATETIMERQUEUETIMER  0x1F94D320
#define HASH_CREATETIMERQUEUE       0x101BB45F
#define HASH_DELETETIMERQUEUE       0xADEE00DE
#define HASH_CREATEEVENTW           0xC612B212
#define HASH_SETEVENT               0x11FC6813
#define HASH_CLOSEHANDLE            0x2EAC8647
#define HASH_RTLCAPTURECONTEXT      0xD9BEFB30
#define HASH_NTCONTINUE             0x8197216C
#define HASH_SYSTEMFUNCTION032      0xD3A21DC5
#define HASH_WAITFORSINGLEOBJECT_K  0xDA18E23A
#define HASH_NTTESTALERT_SLEEP      0xB67D903F
#define HASH_TPALLOCTIMER           0x879C7315
#define HASH_TPSETTIMER             0x983AA036
#define HASH_TPRELEASETIMER         0xBFF7AD2B

#define WT_EXECUTEINTIMERTHREAD     0x00000020
#define WT_EXECUTEONLYONCE          0x00000008

#define CONTEXT_AMD64               0x00100000
#define CONTEXT_FULL_FLAGS          (CONTEXT_AMD64 | 0x0B)

typedef struct __attribute__((aligned(16))) _CONTEXT64 {
    QWORD P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    DWORD ContextFlags; DWORD MxCsr;
    WORD SegCs, SegDs, SegEs, SegFs, SegGs, SegSs; DWORD EFlags;
    QWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    QWORD Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    QWORD R8, R9, R10, R11, R12, R13, R14, R15;
    QWORD Rip;
    BYTE FltSave[512]; BYTE VectorRegister[416]; QWORD VectorControl;
    QWORD DebugControl, LastBranchToRip, LastBranchFromRip;
    QWORD LastExceptionToRip, LastExceptionFromRip;
} CONTEXT64;

typedef struct _USTRING { DWORD Length; DWORD MaximumLength; PVOID Buffer; } USTRING;

typedef HANDLE (__attribute__((ms_abi)) *fn_CreateTimerQueue)(void);
typedef BOOL (__attribute__((ms_abi)) *fn_CreateTimerQueueTimer)(PHANDLE, HANDLE, PVOID, PVOID, DWORD, DWORD, ULONG);
typedef BOOL (__attribute__((ms_abi)) *fn_DeleteTimerQueue)(HANDLE);
typedef HANDLE (__attribute__((ms_abi)) *fn_CreateEventW)(PVOID, BOOL, BOOL, PVOID);
typedef BOOL (__attribute__((ms_abi)) *fn_SetEvent)(HANDLE);
typedef BOOL (__attribute__((ms_abi)) *fn_CloseHandle)(HANDLE);
typedef void (__attribute__((ms_abi)) *fn_RtlCaptureContext)(CONTEXT64 *);
typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtContinue)(CONTEXT64 *, BOOL);
typedef NTSTATUS (__attribute__((ms_abi)) *fn_SystemFunction032)(USTRING *, USTRING *);
typedef DWORD (__attribute__((ms_abi)) *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtTestAlert)(void);
typedef NTSTATUS (__attribute__((ms_abi)) *fn_TpAllocTimer)(PVOID *, PVOID, PVOID, PVOID);
typedef void (__attribute__((ms_abi)) *fn_TpSetTimer)(PVOID, PLARGE_INTEGER, DWORD, DWORD);
typedef void (__attribute__((ms_abi)) *fn_TpReleaseTimer)(PVOID);

typedef struct _SLEEP_API {
    fn_CreateTimerQueue CreateTimerQueue; fn_CreateTimerQueueTimer CreateTimerQueueTimer;
    fn_DeleteTimerQueue DeleteTimerQueue; fn_CreateEventW CreateEventW;
    fn_SetEvent SetEvent; fn_CloseHandle CloseHandle;
    fn_WaitForSingleObject WaitForSingleObject;
    fn_RtlCaptureContext RtlCaptureContext; fn_NtContinue NtContinue;
    fn_SystemFunction032 SystemFunction032;
    fn_NtTestAlert NtTestAlert;
    fn_TpAllocTimer TpAllocTimer; fn_TpSetTimer TpSetTimer; fn_TpReleaseTimer TpReleaseTimer;
    BOOL resolved;
} SLEEP_API;

#define SLEEP_MAX_HEAP_ENTRIES  64

typedef struct _HEAP_ALLOC_ENTRY {
    PVOID ptr; SIZE_T size; struct _HEAP_ALLOC_ENTRY *next;
} HEAP_ALLOC_ENTRY;

typedef struct _SLEEP_CONTEXT {
    DWORD sleep_method; PVOID implant_base; SIZE_T implant_size;
    HEAP_ALLOC_ENTRY *heap_list; BYTE sleep_enc_key[32]; ULONG original_protect;
    SLEEP_API api; HEAP_ALLOC_ENTRY heap_pool[SLEEP_MAX_HEAP_ENTRIES]; DWORD heap_pool_used;
} SLEEP_CONTEXT;

NTSTATUS sleep_init(IMPLANT_CONTEXT *ctx);
NTSTATUS sleep_cycle(IMPLANT_CONTEXT *ctx);
DWORD sleep_calc_jitter(DWORD base_interval, DWORD jitter_percent);
void sleep_track_alloc(SLEEP_CONTEXT *sctx, PVOID ptr, SIZE_T size);
void sleep_untrack_alloc(SLEEP_CONTEXT *sctx, PVOID ptr);
void sleep_encrypt_heap(SLEEP_CONTEXT *sctx);
void sleep_decrypt_heap(SLEEP_CONTEXT *sctx);
NTSTATUS sleep_ekko(SLEEP_CONTEXT *sctx, DWORD sleep_ms);
NTSTATUS sleep_wfs(SLEEP_CONTEXT *sctx, DWORD sleep_ms);
NTSTATUS sleep_delay(SLEEP_CONTEXT *sctx, DWORD sleep_ms);
NTSTATUS sleep_foliage(SLEEP_CONTEXT *sctx, DWORD sleep_ms);
NTSTATUS sleep_threadpool(SLEEP_CONTEXT *sctx, DWORD sleep_ms);
void sleep_test_set_random_seed(DWORD seed);
void sleep_test_set_implant_region(PVOID base, SIZE_T size);

/* ------------------------------------------------------------------ */
/* Test helpers                                                        */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_TRUE(name, cond) do { \
    tests_run++; \
    if (cond) { tests_passed++; printf("[PASS] %s\n", name); } \
    else { printf("[FAIL] %s\n", name); } \
} while(0)

#define ASSERT_STATUS(name, status, expected) do { \
    tests_run++; \
    if ((NTSTATUS)(status) == (NTSTATUS)(expected)) { \
        tests_passed++; printf("[PASS] %s\n", name); \
    } else { \
        printf("[FAIL] %s (got 0x%08lX, expected 0x%08lX)\n", \
               name, (unsigned long)(DWORD)(status), (unsigned long)(DWORD)(expected)); \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* Test: sleep_calc_jitter                                             */
/* ------------------------------------------------------------------ */

static void test_jitter_zero(void) {
    printf("\n=== Jitter Zero Tests ===\n");

    ASSERT_TRUE("jitter 0% returns base",
                sleep_calc_jitter(60000, 0) == 60000);

    ASSERT_TRUE("jitter with 0 interval returns 0",
                sleep_calc_jitter(0, 50) == 0);

    ASSERT_TRUE("both zero returns 0",
                sleep_calc_jitter(0, 0) == 0);
}

static void test_jitter_range(void) {
    printf("\n=== Jitter Range Tests ===\n");

    sleep_test_set_random_seed(12345);

    DWORD base = 60000;
    DWORD jitter = 25;
    DWORD max_delta = (base * jitter) / 100;  /* 15000 */

    BOOL all_in_range = TRUE;
    BOOL saw_variation = FALSE;
    DWORD first = 0;

    for (int i = 0; i < 100; i++) {
        DWORD result = sleep_calc_jitter(base, jitter);
        if (i == 0) first = result;
        if (result != first) saw_variation = TRUE;

        if (result < (base - max_delta) || result > (base + max_delta)) {
            all_in_range = FALSE;
            printf("  out of range: %u (expected %u +/- %u)\n",
                   result, base, max_delta);
        }
    }

    ASSERT_TRUE("all jittered values in [base-delta, base+delta]", all_in_range);
    ASSERT_TRUE("jitter produces variation", saw_variation);
}

static void test_jitter_clamp(void) {
    printf("\n=== Jitter Clamp Tests ===\n");

    sleep_test_set_random_seed(99999);

    /* Jitter > 100 should be clamped to 100 */
    DWORD result = sleep_calc_jitter(10000, 200);
    ASSERT_TRUE("jitter clamped to 100%, result in [0, 20000]",
                result <= 20000);
}

static void test_jitter_small_interval(void) {
    printf("\n=== Jitter Small Interval Tests ===\n");

    sleep_test_set_random_seed(42);

    /* Very small interval with jitter */
    DWORD result = sleep_calc_jitter(10, 50);
    /* max_delta = 5, so result in [5, 15] */
    ASSERT_TRUE("small interval with jitter in range",
                result <= 15);
}

static void test_jitter_deterministic(void) {
    printf("\n=== Jitter Deterministic Tests ===\n");

    /* Same seed should produce same sequence */
    sleep_test_set_random_seed(7777);
    DWORD a1 = sleep_calc_jitter(60000, 25);
    DWORD a2 = sleep_calc_jitter(60000, 25);

    sleep_test_set_random_seed(7777);
    DWORD b1 = sleep_calc_jitter(60000, 25);
    DWORD b2 = sleep_calc_jitter(60000, 25);

    ASSERT_TRUE("deterministic: seed 7777 first value matches",  a1 == b1);
    ASSERT_TRUE("deterministic: seed 7777 second value matches", a2 == b2);
}

/* ------------------------------------------------------------------ */
/* Test: heap tracking                                                 */
/* ------------------------------------------------------------------ */

static void test_heap_track(void) {
    printf("\n=== Heap Track Tests ===\n");

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));

    BYTE buf1[64], buf2[128], buf3[256];

    /* Track allocations */
    sleep_track_alloc(&sctx, buf1, sizeof(buf1));
    sleep_track_alloc(&sctx, buf2, sizeof(buf2));
    sleep_track_alloc(&sctx, buf3, sizeof(buf3));

    ASSERT_TRUE("heap_pool_used == 3", sctx.heap_pool_used == 3);
    ASSERT_TRUE("heap_list non-NULL", sctx.heap_list != NULL);

    /* Verify linked list has all 3 entries */
    int count = 0;
    HEAP_ALLOC_ENTRY *cur = sctx.heap_list;
    while (cur) { count++; cur = cur->next; }
    ASSERT_TRUE("linked list has 3 entries", count == 3);

    /* Untrack middle entry */
    sleep_untrack_alloc(&sctx, buf2);

    count = 0;
    cur = sctx.heap_list;
    BOOL found_buf2 = FALSE;
    while (cur) {
        if (cur->ptr == buf2) found_buf2 = TRUE;
        count++;
        cur = cur->next;
    }
    ASSERT_TRUE("after untrack, list has 2 entries", count == 2);
    ASSERT_TRUE("buf2 no longer in list", !found_buf2);
}

static void test_heap_track_null(void) {
    printf("\n=== Heap Track NULL Tests ===\n");

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));

    /* NULL pointer should be ignored */
    sleep_track_alloc(&sctx, NULL, 64);
    ASSERT_TRUE("NULL ptr not tracked", sctx.heap_pool_used == 0);

    /* Zero size should be ignored */
    BYTE buf[16];
    sleep_track_alloc(&sctx, buf, 0);
    ASSERT_TRUE("zero size not tracked", sctx.heap_pool_used == 0);

    /* NULL context should not crash */
    sleep_track_alloc(NULL, buf, 16);
    sleep_untrack_alloc(NULL, buf);
    ASSERT_TRUE("NULL context operations don't crash", TRUE);

    /* Untrack something that isn't tracked */
    sleep_track_alloc(&sctx, buf, 16);
    BYTE other[16];
    sleep_untrack_alloc(&sctx, other);
    ASSERT_TRUE("untrack non-existent ptr leaves list intact",
                sctx.heap_pool_used == 1);
}

static void test_heap_pool_overflow(void) {
    printf("\n=== Heap Pool Overflow Tests ===\n");

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));

    BYTE bufs[SLEEP_MAX_HEAP_ENTRIES + 5][4];

    /* Fill pool to capacity */
    for (int i = 0; i < SLEEP_MAX_HEAP_ENTRIES; i++) {
        sleep_track_alloc(&sctx, bufs[i], sizeof(bufs[i]));
    }
    ASSERT_TRUE("pool at capacity",
                sctx.heap_pool_used == SLEEP_MAX_HEAP_ENTRIES);

    /* Attempt to exceed capacity */
    sleep_track_alloc(&sctx, bufs[SLEEP_MAX_HEAP_ENTRIES], 4);
    ASSERT_TRUE("overflow rejected",
                sctx.heap_pool_used == SLEEP_MAX_HEAP_ENTRIES);
}

/* ------------------------------------------------------------------ */
/* Test: heap encryption / decryption                                  */
/* ------------------------------------------------------------------ */

static void test_heap_encrypt_decrypt(void) {
    printf("\n=== Heap Encrypt/Decrypt Tests ===\n");

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));

    /* Set a known encryption key (32 bytes for ChaCha20) */
    for (int i = 0; i < 32; i++)
        sctx.sleep_enc_key[i] = (BYTE)(0xAA + i);

    /* Create test buffers with known content */
    BYTE buf1[32], buf2[64];
    BYTE orig1[32], orig2[64];

    for (int i = 0; i < 32; i++) buf1[i] = (BYTE)(i * 3 + 7);
    for (int i = 0; i < 64; i++) buf2[i] = (BYTE)(i * 5 + 11);
    memcpy(orig1, buf1, 32);
    memcpy(orig2, buf2, 64);

    /* Track the buffers */
    sleep_track_alloc(&sctx, buf1, sizeof(buf1));
    sleep_track_alloc(&sctx, buf2, sizeof(buf2));

    /* Encrypt */
    sleep_encrypt_heap(&sctx);

    /* Verify data changed */
    ASSERT_TRUE("buf1 changed after encrypt",
                memcmp(buf1, orig1, 32) != 0);
    ASSERT_TRUE("buf2 changed after encrypt",
                memcmp(buf2, orig2, 64) != 0);

    /* Decrypt (ChaCha20 XOR is self-inverse) */
    sleep_decrypt_heap(&sctx);

    /* Verify data restored */
    ASSERT_TRUE("buf1 restored after decrypt",
                memcmp(buf1, orig1, 32) == 0);
    ASSERT_TRUE("buf2 restored after decrypt",
                memcmp(buf2, orig2, 64) == 0);
}

static void test_heap_encrypt_empty(void) {
    printf("\n=== Heap Encrypt Empty Tests ===\n");

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));

    /* Encrypt with no tracked allocations — should not crash */
    sleep_encrypt_heap(&sctx);
    sleep_decrypt_heap(&sctx);
    ASSERT_TRUE("encrypt/decrypt empty list doesn't crash", TRUE);

    /* NULL context */
    sleep_encrypt_heap(NULL);
    sleep_decrypt_heap(NULL);
    ASSERT_TRUE("encrypt/decrypt NULL context doesn't crash", TRUE);
}

/* ------------------------------------------------------------------ */
/* Test: sleep_init                                                    */
/* ------------------------------------------------------------------ */

static void test_sleep_init(void) {
    printf("\n=== sleep_init Tests ===\n");

    BYTE fake_implant[4096];
    memset(fake_implant, 0x90, sizeof(fake_implant));
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Without config, should default to SLEEP_DELAY */
    NTSTATUS status = sleep_init(&ctx);
    ASSERT_STATUS("sleep_init returns SUCCESS", status, STATUS_SUCCESS);
    ASSERT_TRUE("sleep_ctx set", ctx.sleep_ctx != NULL);

    SLEEP_CONTEXT *sctx = (SLEEP_CONTEXT *)ctx.sleep_ctx;
    ASSERT_TRUE("default method is SLEEP_DELAY",
                sctx->sleep_method == SLEEP_DELAY);
    ASSERT_TRUE("heap list is NULL", sctx->heap_list == NULL);
    ASSERT_TRUE("heap_pool_used is 0", sctx->heap_pool_used == 0);
}

static void test_sleep_init_null(void) {
    printf("\n=== sleep_init NULL Tests ===\n");

    NTSTATUS status = sleep_init(NULL);
    ASSERT_STATUS("sleep_init(NULL) returns INVALID_PARAMETER",
                  status, STATUS_INVALID_PARAMETER);
}

static void test_sleep_init_with_config(void) {
    printf("\n=== sleep_init With Config Tests ===\n");

    /* Create a mock config */
    static IMPLANT_CONFIG mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.sleep_interval = 30000;
    mock_cfg.jitter_percent = 20;
    mock_cfg.sleep_method = SLEEP_EKKO;

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &mock_cfg;

    BYTE fake_implant[1024];
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    NTSTATUS status = sleep_init(&ctx);
    ASSERT_STATUS("sleep_init with config succeeds", status, STATUS_SUCCESS);

    SLEEP_CONTEXT *sctx = (SLEEP_CONTEXT *)ctx.sleep_ctx;
    ASSERT_TRUE("method set from config (SLEEP_EKKO)",
                sctx->sleep_method == SLEEP_EKKO);
}

/* ------------------------------------------------------------------ */
/* Test: sleep_cycle (with TEST_BUILD, Ekko is a no-op)                */
/* ------------------------------------------------------------------ */

static void test_sleep_cycle(void) {
    printf("\n=== sleep_cycle Tests ===\n");

    /* Set up config and init */
    static IMPLANT_CONFIG mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.sleep_interval = 1000;
    mock_cfg.jitter_percent = 10;
    mock_cfg.sleep_method = SLEEP_EKKO;

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &mock_cfg;

    BYTE fake_implant[512];
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    sleep_init(&ctx);

    /* sleep_cycle should succeed (Ekko is no-op in TEST_BUILD) */
    NTSTATUS status = sleep_cycle(&ctx);
    ASSERT_STATUS("sleep_cycle returns SUCCESS", status, STATUS_SUCCESS);
}

static void test_sleep_cycle_null(void) {
    printf("\n=== sleep_cycle NULL Tests ===\n");

    NTSTATUS status = sleep_cycle(NULL);
    ASSERT_STATUS("sleep_cycle(NULL) returns INVALID_PARAMETER",
                  status, STATUS_INVALID_PARAMETER);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    status = sleep_cycle(&ctx);
    ASSERT_STATUS("sleep_cycle with NULL sleep_ctx returns INVALID_PARAMETER",
                  status, STATUS_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ */
/* Test: CONTEXT64 structure size                                      */
/* ------------------------------------------------------------------ */

static void test_context64_layout(void) {
    printf("\n=== CONTEXT64 Layout Tests ===\n");

    /* CONTEXT64 must be 1232 bytes for compatibility with Windows */
    ASSERT_TRUE("CONTEXT64 size == 1232",
                sizeof(CONTEXT64) == 1232);

    /* Verify key field offsets */
    CONTEXT64 ctx;
    char *base = (char *)&ctx;

    ASSERT_TRUE("ContextFlags at offset 0x30",
                (char *)&ctx.ContextFlags - base == 0x30);
    ASSERT_TRUE("Rax at offset 0x78",
                (char *)&ctx.Rax - base == 0x78);
    ASSERT_TRUE("Rcx at offset 0x80",
                (char *)&ctx.Rcx - base == 0x80);
    ASSERT_TRUE("Rdx at offset 0x88",
                (char *)&ctx.Rdx - base == 0x88);
    ASSERT_TRUE("Rsp at offset 0x98",
                (char *)&ctx.Rsp - base == 0x98);
    ASSERT_TRUE("Rip at offset 0xF8",
                (char *)&ctx.Rip - base == 0xF8);
    ASSERT_TRUE("R8 at offset 0xB8",
                (char *)&ctx.R8 - base == 0xB8);
    ASSERT_TRUE("R9 at offset 0xC0",
                (char *)&ctx.R9 - base == 0xC0);
}

/* ------------------------------------------------------------------ */
/* Test: DJB2 hash verification                                        */
/* ------------------------------------------------------------------ */

static void test_hash_values(void) {
    printf("\n=== DJB2 Hash Verification ===\n");

    ASSERT_TRUE("HASH_ADVAPI32_DLL correct",
                spec_djb2_hash("advapi32.dll") == HASH_ADVAPI32_DLL);
    ASSERT_TRUE("HASH_CREATETIMERQUEUETIMER correct",
                spec_djb2_hash("CreateTimerQueueTimer") == HASH_CREATETIMERQUEUETIMER);
    ASSERT_TRUE("HASH_CREATETIMERQUEUE correct",
                spec_djb2_hash("CreateTimerQueue") == HASH_CREATETIMERQUEUE);
    ASSERT_TRUE("HASH_DELETETIMERQUEUE correct",
                spec_djb2_hash("DeleteTimerQueue") == HASH_DELETETIMERQUEUE);
    ASSERT_TRUE("HASH_CREATEEVENTW correct",
                spec_djb2_hash("CreateEventW") == HASH_CREATEEVENTW);
    ASSERT_TRUE("HASH_SETEVENT correct",
                spec_djb2_hash("SetEvent") == HASH_SETEVENT);
    ASSERT_TRUE("HASH_CLOSEHANDLE correct",
                spec_djb2_hash("CloseHandle") == HASH_CLOSEHANDLE);
    ASSERT_TRUE("HASH_RTLCAPTURECONTEXT correct",
                spec_djb2_hash("RtlCaptureContext") == HASH_RTLCAPTURECONTEXT);
    ASSERT_TRUE("HASH_NTCONTINUE correct",
                spec_djb2_hash("NtContinue") == HASH_NTCONTINUE);
    ASSERT_TRUE("HASH_SYSTEMFUNCTION032 correct",
                spec_djb2_hash("SystemFunction032") == HASH_SYSTEMFUNCTION032);
    ASSERT_TRUE("HASH_WAITFORSINGLEOBJECT_K correct",
                spec_djb2_hash("WaitForSingleObject") == HASH_WAITFORSINGLEOBJECT_K);
}

/* ------------------------------------------------------------------ */
/* Test: Foliage and ThreadPool sleep methods                          */
/* ------------------------------------------------------------------ */

static void test_sleep_method_enum(void) {
    printf("\n=== Sleep Method Enum Tests ===\n");

    ASSERT_TRUE("SLEEP_EKKO == 0", SLEEP_EKKO == 0);
    ASSERT_TRUE("SLEEP_WFS == 1", SLEEP_WFS == 1);
    ASSERT_TRUE("SLEEP_DELAY == 2", SLEEP_DELAY == 2);
    ASSERT_TRUE("SLEEP_FOLIAGE == 3", SLEEP_FOLIAGE == 3);
    ASSERT_TRUE("SLEEP_THREADPOOL == 4", SLEEP_THREADPOOL == 4);

    /* Enum values are distinct */
    ASSERT_TRUE("FOLIAGE != EKKO", SLEEP_FOLIAGE != SLEEP_EKKO);
    ASSERT_TRUE("THREADPOOL != FOLIAGE", SLEEP_THREADPOOL != SLEEP_FOLIAGE);
    ASSERT_TRUE("THREADPOOL != DELAY", SLEEP_THREADPOOL != SLEEP_DELAY);
}

static void test_foliage_direct(void) {
    printf("\n=== Foliage Direct Call Tests ===\n");

    BYTE fake_implant[1024];
    memset(fake_implant, 0x90, sizeof(fake_implant));
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));
    sctx.sleep_method = SLEEP_FOLIAGE;
    sctx.implant_base = fake_implant;
    sctx.implant_size = sizeof(fake_implant);

    /* In TEST_BUILD, foliage is a no-op → should succeed */
    NTSTATUS status = sleep_foliage(&sctx, 1000);
    ASSERT_STATUS("sleep_foliage returns SUCCESS", status, STATUS_SUCCESS);
}

static void test_threadpool_direct(void) {
    printf("\n=== ThreadPool Direct Call Tests ===\n");

    BYTE fake_implant[1024];
    memset(fake_implant, 0x90, sizeof(fake_implant));
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    SLEEP_CONTEXT sctx;
    memset(&sctx, 0, sizeof(sctx));
    sctx.sleep_method = SLEEP_THREADPOOL;
    sctx.implant_base = fake_implant;
    sctx.implant_size = sizeof(fake_implant);

    /* In TEST_BUILD, threadpool is a no-op → should succeed */
    NTSTATUS status = sleep_threadpool(&sctx, 1000);
    ASSERT_STATUS("sleep_threadpool returns SUCCESS", status, STATUS_SUCCESS);
}

static void test_sleep_init_foliage(void) {
    printf("\n=== sleep_init Foliage Config Tests ===\n");

    static IMPLANT_CONFIG mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.sleep_interval = 5000;
    mock_cfg.jitter_percent = 15;
    mock_cfg.sleep_method = SLEEP_FOLIAGE;

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &mock_cfg;

    BYTE fake_implant[512];
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    NTSTATUS status = sleep_init(&ctx);
    ASSERT_STATUS("sleep_init with FOLIAGE config succeeds", status, STATUS_SUCCESS);

    SLEEP_CONTEXT *sctx = (SLEEP_CONTEXT *)ctx.sleep_ctx;
    ASSERT_TRUE("method set from config (SLEEP_FOLIAGE)",
                sctx->sleep_method == SLEEP_FOLIAGE);
}

static void test_sleep_init_threadpool(void) {
    printf("\n=== sleep_init ThreadPool Config Tests ===\n");

    static IMPLANT_CONFIG mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.sleep_interval = 10000;
    mock_cfg.jitter_percent = 30;
    mock_cfg.sleep_method = SLEEP_THREADPOOL;

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &mock_cfg;

    BYTE fake_implant[512];
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    NTSTATUS status = sleep_init(&ctx);
    ASSERT_STATUS("sleep_init with THREADPOOL config succeeds", status, STATUS_SUCCESS);

    SLEEP_CONTEXT *sctx = (SLEEP_CONTEXT *)ctx.sleep_ctx;
    ASSERT_TRUE("method set from config (SLEEP_THREADPOOL)",
                sctx->sleep_method == SLEEP_THREADPOOL);
}

static void test_sleep_cycle_foliage(void) {
    printf("\n=== sleep_cycle Foliage Tests ===\n");

    static IMPLANT_CONFIG mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.sleep_interval = 1000;
    mock_cfg.jitter_percent = 10;
    mock_cfg.sleep_method = SLEEP_FOLIAGE;

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &mock_cfg;

    BYTE fake_implant[512];
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    sleep_init(&ctx);

    NTSTATUS status = sleep_cycle(&ctx);
    ASSERT_STATUS("sleep_cycle with FOLIAGE returns SUCCESS", status, STATUS_SUCCESS);
}

static void test_sleep_cycle_threadpool(void) {
    printf("\n=== sleep_cycle ThreadPool Tests ===\n");

    static IMPLANT_CONFIG mock_cfg;
    memset(&mock_cfg, 0, sizeof(mock_cfg));
    mock_cfg.sleep_interval = 1000;
    mock_cfg.jitter_percent = 10;
    mock_cfg.sleep_method = SLEEP_THREADPOOL;

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.config = &mock_cfg;

    BYTE fake_implant[512];
    sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

    sleep_init(&ctx);

    NTSTATUS status = sleep_cycle(&ctx);
    ASSERT_STATUS("sleep_cycle with THREADPOOL returns SUCCESS", status, STATUS_SUCCESS);
}

static void test_sleep_method_dispatch(void) {
    printf("\n=== Sleep Method Dispatch Tests ===\n");

    /* Verify that sleep_cycle dispatches all 5 methods correctly */
    DWORD methods[] = { SLEEP_EKKO, SLEEP_WFS, SLEEP_DELAY,
                        SLEEP_FOLIAGE, SLEEP_THREADPOOL };
    const char *names[] = { "EKKO", "WFS", "DELAY", "FOLIAGE", "THREADPOOL" };

    for (int i = 0; i < 5; i++) {
        static IMPLANT_CONFIG mock_cfg;
        memset(&mock_cfg, 0, sizeof(mock_cfg));
        mock_cfg.sleep_interval = 500;
        mock_cfg.jitter_percent = 0;  /* No jitter for determinism */
        mock_cfg.sleep_method = methods[i];

        IMPLANT_CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.config = &mock_cfg;

        BYTE fake_implant[256];
        sleep_test_set_implant_region(fake_implant, sizeof(fake_implant));

        sleep_init(&ctx);

        SLEEP_CONTEXT *sctx = (SLEEP_CONTEXT *)ctx.sleep_ctx;
        ASSERT_TRUE("method stored correctly",
                    sctx->sleep_method == methods[i]);

        NTSTATUS status = sleep_cycle(&ctx);

        char msg[64];
        snprintf(msg, sizeof(msg), "sleep_cycle dispatches %s correctly", names[i]);
        ASSERT_STATUS(msg, status, STATUS_SUCCESS);
    }
}

static void test_hash_values_new(void) {
    printf("\n=== DJB2 Hash Verification (New APIs) ===\n");

    ASSERT_TRUE("HASH_NTTESTALERT_SLEEP correct",
                spec_djb2_hash("NtTestAlert") == HASH_NTTESTALERT_SLEEP);
    ASSERT_TRUE("HASH_TPALLOCTIMER correct",
                spec_djb2_hash("TpAllocTimer") == HASH_TPALLOCTIMER);
    ASSERT_TRUE("HASH_TPSETTIMER correct",
                spec_djb2_hash("TpSetTimer") == HASH_TPSETTIMER);
    ASSERT_TRUE("HASH_TPRELEASETIMER correct",
                spec_djb2_hash("TpReleaseTimer") == HASH_TPRELEASETIMER);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("SPECTER Sleep Controller Test Suite\n");
    printf("====================================\n");

    test_jitter_zero();
    test_jitter_range();
    test_jitter_clamp();
    test_jitter_small_interval();
    test_jitter_deterministic();
    test_heap_track();
    test_heap_track_null();
    test_heap_pool_overflow();
    test_heap_encrypt_decrypt();
    test_heap_encrypt_empty();
    test_sleep_init();
    test_sleep_init_null();
    test_sleep_init_with_config();
    test_sleep_cycle();
    test_sleep_cycle_null();
    test_context64_layout();
    test_hash_values();
    test_sleep_method_enum();
    test_foliage_direct();
    test_threadpool_direct();
    test_sleep_init_foliage();
    test_sleep_init_threadpool();
    test_sleep_cycle_foliage();
    test_sleep_cycle_threadpool();
    test_sleep_method_dispatch();
    test_hash_values_new();

    printf("\n====================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
