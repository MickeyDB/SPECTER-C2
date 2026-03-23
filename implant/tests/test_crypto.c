/**
 * SPECTER Implant — Crypto Test Suite
 *
 * Verifies crypto implementations against RFC test vectors.
 * Compiled natively (not PIC) for testing on the build host.
 *
 * Build: gcc -o test_crypto test_crypto.c ../core/src/crypto.c
 *            ../core/src/string.c ../core/src/hash.c ../core/src/peb.c
 *            -I../core/include -DTEST_BUILD
 * (peb.c won't work natively, but we stub out what's needed)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Provide stubs for the specter types */
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

#define TRUE  1
#define FALSE 0
#ifndef NULL
#define NULL ((void*)0)
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

/* Stub out PEB structures we don't need for testing */
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWCHAR Buffer; } UNICODE_STRING;
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

/* String/memory functions from string.c — we redefine for native build */
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

/* Now include the crypto header (uses our types) */
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

/* Declare the functions we're testing */
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
void spec_x25519_scalarmult(BYTE shared_out[32], const BYTE private_key[32], const BYTE public_key[32]);
void spec_decrypt_string(const BYTE *encrypted, DWORD len, BYTE *output);

/* ------------------------------------------------------------------ */
/* Test helpers                                                        */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

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
/* Test: SHA-256 (FIPS 180-4 examples)                                 */
/* ------------------------------------------------------------------ */

static void test_sha256(void) {
    printf("\n=== SHA-256 Tests ===\n");

    /* Test 1: "abc" */
    {
        BYTE digest[32];
        spec_sha256((const BYTE *)"abc", 3, digest);
        BYTE expected[] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        check_bytes("SHA-256(\"abc\")", digest, expected, 32);
    }

    /* Test 2: empty string */
    {
        BYTE digest[32];
        spec_sha256((const BYTE *)"", 0, digest);
        BYTE expected[] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        check_bytes("SHA-256(\"\")", digest, expected, 32);
    }

    /* Test 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    {
        BYTE digest[32];
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        spec_sha256((const BYTE *)msg, strlen(msg), digest);
        BYTE expected[] = {
            0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
            0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
            0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
            0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
        };
        check_bytes("SHA-256(\"abcdbcde...nopq\")", digest, expected, 32);
    }
}

/* ------------------------------------------------------------------ */
/* Test: ChaCha20 (RFC 8439 Section 2.4.2)                             */
/* ------------------------------------------------------------------ */

static void test_chacha20(void) {
    printf("\n=== ChaCha20 Tests ===\n");

    /* RFC 8439 Section 2.4.2 test vector */
    BYTE key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    BYTE nonce[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00};
    const char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    DWORD pt_len = strlen(plaintext);

    BYTE ciphertext[256];
    spec_chacha20_encrypt(key, nonce, 1, (const BYTE *)plaintext, pt_len, ciphertext);

    /* Expected ciphertext from RFC 8439 */
    BYTE expected[] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,
        0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
        0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,
        0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
        0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,
        0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
        0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,
        0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,
        0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,
        0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
        0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,
        0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
        0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,
        0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
        0x87,0x4d
    };
    check_bytes("ChaCha20 RFC 8439 §2.4.2", ciphertext, expected, pt_len);
}

/* ------------------------------------------------------------------ */
/* Test: Poly1305 (RFC 8439 Section 2.5.2)                             */
/* ------------------------------------------------------------------ */

static void test_poly1305(void) {
    printf("\n=== Poly1305 Tests ===\n");

    /* RFC 8439 Section 2.5.2 test vector */
    BYTE key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    const char *msg = "Cryptographic Forum Research Group";
    BYTE tag[16];
    spec_poly1305_auth(tag, (const BYTE *)msg, strlen(msg), key);

    BYTE expected[] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };
    check_bytes("Poly1305 RFC 8439 §2.5.2", tag, expected, 16);
}

/* ------------------------------------------------------------------ */
/* Test: ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8.2)               */
/* ------------------------------------------------------------------ */

static void test_aead(void) {
    printf("\n=== AEAD Tests ===\n");

    /* RFC 8439 Section 2.8.2 */
    BYTE key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    BYTE nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47
    };
    BYTE aad[] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    const char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    DWORD pt_len = strlen(plaintext);

    BYTE ciphertext[256];
    BYTE tag[16];
    spec_aead_encrypt(key, nonce, (const BYTE *)plaintext, pt_len, aad, sizeof(aad), ciphertext, tag);

    BYTE expected_ct[] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
        0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
        0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
        0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
        0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
        0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16
    };
    BYTE expected_tag[] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };

    check_bytes("AEAD encrypt ciphertext", ciphertext, expected_ct, pt_len);
    check_bytes("AEAD encrypt tag", tag, expected_tag, 16);

    /* Test decryption */
    BYTE decrypted[256];
    BOOL ok = spec_aead_decrypt(key, nonce, expected_ct, pt_len, aad, sizeof(aad), decrypted, expected_tag);
    tests_run++;
    if (ok && memcmp(decrypted, plaintext, pt_len) == 0) {
        tests_passed++;
        printf("[PASS] AEAD decrypt roundtrip\n");
    } else {
        printf("[FAIL] AEAD decrypt roundtrip (ok=%d)\n", ok);
    }

    /* Test tampered tag */
    BYTE bad_tag[16];
    memcpy(bad_tag, expected_tag, 16);
    bad_tag[0] ^= 0xFF;
    ok = spec_aead_decrypt(key, nonce, expected_ct, pt_len, aad, sizeof(aad), decrypted, bad_tag);
    tests_run++;
    if (!ok) {
        tests_passed++;
        printf("[PASS] AEAD reject tampered tag\n");
    } else {
        printf("[FAIL] AEAD should reject tampered tag\n");
    }
}

/* ------------------------------------------------------------------ */
/* Test: HMAC-SHA256 (RFC 4231 test case 2)                            */
/* ------------------------------------------------------------------ */

static void test_hmac_sha256(void) {
    printf("\n=== HMAC-SHA256 Tests ===\n");

    /* RFC 4231 Test Case 2 */
    BYTE key[] = "Jefe";
    BYTE data[] = "what do ya want for nothing?";
    BYTE mac[32];
    spec_hmac_sha256(key, 4, data, 28, mac);

    BYTE expected[] = {
        0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,
        0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
        0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,
        0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
    };
    check_bytes("HMAC-SHA256 RFC 4231 TC2", mac, expected, 32);
}

/* ------------------------------------------------------------------ */
/* Test: HKDF-SHA256 (RFC 5869 Test Case 1)                            */
/* ------------------------------------------------------------------ */

static void test_hkdf(void) {
    printf("\n=== HKDF-SHA256 Tests ===\n");

    /* RFC 5869 Test Case 1 */
    BYTE ikm[22];
    memset(ikm, 0x0b, 22);
    BYTE salt[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    BYTE info[] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};

    BYTE prk[32];
    spec_hkdf_extract(salt, 13, ikm, 22, prk);
    BYTE expected_prk[] = {
        0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,
        0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
        0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,
        0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5
    };
    check_bytes("HKDF extract (PRK)", prk, expected_prk, 32);

    BYTE okm[42];
    spec_hkdf_expand(prk, info, 10, okm, 42);
    BYTE expected_okm[] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65
    };
    check_bytes("HKDF expand (OKM)", okm, expected_okm, 42);
}

/* ------------------------------------------------------------------ */
/* Test: X25519 (RFC 7748 Section 6.1)                                 */
/* ------------------------------------------------------------------ */

static void test_x25519(void) {
    printf("\n=== X25519 Tests ===\n");

    /* RFC 7748 Section 6.1 test vectors */
    BYTE alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    BYTE bob_priv[32] = {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
    };

    /* Base point = 9 */
    BYTE basepoint[32] = {9};

    BYTE alice_pub[32], bob_pub[32];
    spec_x25519_scalarmult(alice_pub, alice_priv, basepoint);
    spec_x25519_scalarmult(bob_pub, bob_priv, basepoint);

    BYTE expected_alice_pub[] = {
        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
        0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
        0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
        0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    };
    BYTE expected_bob_pub[] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
        0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
        0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    };
    check_bytes("X25519 Alice public", alice_pub, expected_alice_pub, 32);
    check_bytes("X25519 Bob public", bob_pub, expected_bob_pub, 32);

    /* Shared secrets must match */
    BYTE alice_shared[32], bob_shared[32];
    spec_x25519_scalarmult(alice_shared, alice_priv, bob_pub);
    spec_x25519_scalarmult(bob_shared, bob_priv, alice_pub);

    BYTE expected_shared[] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
        0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
        0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    };
    check_bytes("X25519 Alice shared", alice_shared, expected_shared, 32);
    check_bytes("X25519 Bob shared", bob_shared, expected_shared, 32);
}

/* ------------------------------------------------------------------ */
/* Test: String decryption                                             */
/* ------------------------------------------------------------------ */

static void test_decrypt_string(void) {
    printf("\n=== String Decryption Tests ===\n");

    /* Encrypt "hello" with XOR key 0xAB */
    BYTE xor_key = 0xAB;
    const char *original = "hello";
    BYTE encrypted[6]; /* key + 5 chars */
    encrypted[0] = xor_key;
    for (int i = 0; i < 5; i++)
        encrypted[i + 1] = original[i] ^ xor_key;

    BYTE decrypted[6];
    spec_decrypt_string(encrypted, 6, decrypted);

    tests_run++;
    if (memcmp(decrypted, "hello", 5) == 0 && decrypted[5] == 0) {
        tests_passed++;
        printf("[PASS] String decryption\n");
    } else {
        printf("[FAIL] String decryption\n");
        printf("  Expected: hello\n");
        printf("  Got:      %s\n", decrypted);
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("SPECTER Crypto Test Suite\n");
    printf("========================\n");

    test_sha256();
    test_chacha20();
    test_poly1305();
    test_aead();
    test_hmac_sha256();
    test_hkdf();
    test_x25519();
    test_decrypt_string();

    printf("\n========================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
