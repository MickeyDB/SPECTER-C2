/**
 * SPECTER Module Development Header
 *
 * Standard header for all SPECTER modules.  Provides the MODULE_BUS_API
 * typedef, entry point signature, argument parsing macros, and common
 * constants.  Modules include only this header — it pulls in the bus
 * API definition and specter base types.
 */

#ifndef MODULE_H
#define MODULE_H

#include "specter.h"
#include "bus.h"

/* ------------------------------------------------------------------ */
/*  Module entry point signature                                       */
/* ------------------------------------------------------------------ */

/**
 * Every module exports a single entry point:
 *   DWORD module_entry(MODULE_BUS_API *api, BYTE *args, DWORD args_len)
 *
 * Returns 0 on success, non-zero error code on failure.
 */
typedef DWORD (*MODULE_ENTRY)(MODULE_BUS_API *api, BYTE *args, DWORD args_len);

/* ------------------------------------------------------------------ */
/*  Module argument blob format                                        */
/*                                                                     */
/*  Wire format:                                                       */
/*    [4B count]                                                       */
/*    [4B type][4B len][data] ...  (repeated `count` times)            */
/*                                                                     */
/*  Argument types:                                                    */
/* ------------------------------------------------------------------ */

#define ARG_TYPE_STRING     0   /* Null-terminated UTF-8 string        */
#define ARG_TYPE_INT32      1   /* 4-byte little-endian integer        */
#define ARG_TYPE_BYTES      2   /* Raw byte buffer                     */
#define ARG_TYPE_WSTRING    3   /* Null-terminated UTF-16LE string     */

/* ------------------------------------------------------------------ */
/*  MODULE_ARGS — parsed argument context                              */
/* ------------------------------------------------------------------ */

#define MODULE_MAX_ARGS     32  /* Maximum arguments per invocation    */

typedef struct _MODULE_ARG {
    DWORD   type;       /* ARG_TYPE_*                                  */
    DWORD   len;        /* Length of data in bytes                     */
    BYTE   *data;       /* Pointer into the original args blob         */
} MODULE_ARG;

typedef struct _MODULE_ARGS {
    DWORD       count;                      /* Number of arguments     */
    MODULE_ARG  args[MODULE_MAX_ARGS];      /* Parsed argument array   */
} MODULE_ARGS;

/* ------------------------------------------------------------------ */
/*  Argument parsing functions                                         */
/* ------------------------------------------------------------------ */

/**
 * Parse a raw argument blob into a MODULE_ARGS structure.
 * Returns TRUE on success, FALSE if the blob is malformed.
 */
static inline BOOL module_parse_args(const BYTE *blob, DWORD blob_len,
                                     MODULE_ARGS *out)
{
    DWORD i, offset;

    spec_memset(out, 0, sizeof(MODULE_ARGS));

    if (!blob || blob_len < 4)
        return FALSE;

    /* Read argument count */
    out->count = *(const DWORD *)blob;
    offset = 4;

    if (out->count > MODULE_MAX_ARGS)
        return FALSE;

    for (i = 0; i < out->count; i++) {
        /* Need at least 8 bytes for type + len */
        if (offset + 8 > blob_len)
            return FALSE;

        out->args[i].type = *(const DWORD *)(blob + offset);
        offset += 4;

        out->args[i].len = *(const DWORD *)(blob + offset);
        offset += 4;

        /* Validate data fits in blob */
        if (offset + out->args[i].len > blob_len)
            return FALSE;

        out->args[i].data = (BYTE *)(blob + offset);
        offset += out->args[i].len;
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Convenience accessors                                              */
/* ------------------------------------------------------------------ */

/**
 * Get argument at index as a C string.  Returns NULL if index is out
 * of bounds or argument type is not ARG_TYPE_STRING.
 */
static inline const char *module_arg_string(const MODULE_ARGS *args, DWORD idx)
{
    if (idx >= args->count)
        return NULL;
    if (args->args[idx].type != ARG_TYPE_STRING)
        return NULL;
    return (const char *)args->args[idx].data;
}

/**
 * Get argument at index as a 32-bit integer.  Returns default_val
 * if index is out of bounds or argument type is not ARG_TYPE_INT32.
 */
static inline DWORD module_arg_int32(const MODULE_ARGS *args, DWORD idx,
                                     DWORD default_val)
{
    if (idx >= args->count)
        return default_val;
    if (args->args[idx].type != ARG_TYPE_INT32)
        return default_val;
    if (args->args[idx].len < 4)
        return default_val;
    return *(const DWORD *)args->args[idx].data;
}

/**
 * Get argument at index as a raw byte buffer.  Sets *out_len to the
 * data length.  Returns NULL if index is out of bounds or type is
 * not ARG_TYPE_BYTES.
 */
static inline const BYTE *module_arg_bytes(const MODULE_ARGS *args, DWORD idx,
                                           DWORD *out_len)
{
    if (idx >= args->count)
        return NULL;
    if (args->args[idx].type != ARG_TYPE_BYTES)
        return NULL;
    if (out_len)
        *out_len = args->args[idx].len;
    return args->args[idx].data;
}

/**
 * Get argument at index as a wide string.  Returns NULL if index is
 * out of bounds or type is not ARG_TYPE_WSTRING.
 */
static inline const WCHAR *module_arg_wstring(const MODULE_ARGS *args, DWORD idx)
{
    if (idx >= args->count)
        return NULL;
    if (args->args[idx].type != ARG_TYPE_WSTRING)
        return NULL;
    return (const WCHAR *)args->args[idx].data;
}

/* ------------------------------------------------------------------ */
/*  Argument serialization (for test and teamserver use)               */
/* ------------------------------------------------------------------ */

/**
 * Begin building an argument blob.  Writes the count header.
 * buf: destination buffer, buf_len: capacity.
 * Returns offset after header (4), or 0 on failure.
 */
static inline DWORD module_args_begin(BYTE *buf, DWORD buf_len, DWORD count)
{
    if (buf_len < 4)
        return 0;
    *(DWORD *)buf = count;
    return 4;
}

/**
 * Append one argument to the blob.
 * offset: current write position. Returns new offset, or 0 on failure.
 */
static inline DWORD module_args_append(BYTE *buf, DWORD buf_len, DWORD offset,
                                       DWORD type, const BYTE *data, DWORD data_len)
{
    if (offset + 8 + data_len > buf_len)
        return 0;
    *(DWORD *)(buf + offset) = type;
    offset += 4;
    *(DWORD *)(buf + offset) = data_len;
    offset += 4;
    if (data_len > 0)
        spec_memcpy(buf + offset, data, data_len);
    return offset + data_len;
}

/* ------------------------------------------------------------------ */
/*  Common module return codes                                         */
/* ------------------------------------------------------------------ */

#define MODULE_SUCCESS          0
#define MODULE_ERR_ARGS         1   /* Invalid or missing arguments     */
#define MODULE_ERR_RESOLVE      2   /* Failed to resolve API function   */
#define MODULE_ERR_ALLOC        3   /* Memory allocation failed         */
#define MODULE_ERR_IO           4   /* I/O operation failed             */
#define MODULE_ERR_ACCESS       5   /* Access denied                    */
#define MODULE_ERR_TIMEOUT      6   /* Operation timed out              */
#define MODULE_ERR_INTERNAL     7   /* Internal / unexpected error      */
#define MODULE_ERR_UNSUPPORTED  8   /* Unsupported subcommand/feature   */

/* ------------------------------------------------------------------ */
/*  Helper macros                                                      */
/* ------------------------------------------------------------------ */

/**
 * Output a text string through the bus API.
 */
#define MODULE_OUTPUT_TEXT(api, msg) \
    (api)->output((const BYTE *)(msg), (DWORD)spec_strlen(msg), OUTPUT_TEXT)

/**
 * Output an error string through the bus API.
 */
#define MODULE_OUTPUT_ERROR(api, msg) \
    (api)->output((const BYTE *)(msg), (DWORD)spec_strlen(msg), OUTPUT_ERROR)

/**
 * Output binary data through the bus API.
 */
#define MODULE_OUTPUT_BINARY(api, data, len) \
    (api)->output((const BYTE *)(data), (DWORD)(len), OUTPUT_BINARY)

/**
 * Log a message through the bus API.
 */
#define MODULE_LOG(api, level, msg) \
    (api)->log((level), (msg))

#endif /* MODULE_H */
