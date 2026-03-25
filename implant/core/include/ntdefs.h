/**
 * SPECTER Implant — NT API Definitions
 *
 * NTSTATUS codes, NT structures required by syscall wrappers.
 * No windows.h dependency.
 */

#ifndef NTDEFS_H
#define NTDEFS_H

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  NTSTATUS codes                                                     */
/* ------------------------------------------------------------------ */

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001)
#define STATUS_NOT_IMPLEMENTED      ((NTSTATUS)0xC0000002)
#define STATUS_INVALID_HANDLE       ((NTSTATUS)0xC0000008)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000D)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define STATUS_PROCEDURE_NOT_FOUND  ((NTSTATUS)0xC000007A)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define STATUS_NO_MEMORY            ((NTSTATUS)0xC0000017)
#define STATUS_BUFFER_OVERFLOW      ((NTSTATUS)0x80000005)
#define STATUS_NOT_FOUND            ((NTSTATUS)0xC0000225)
#define STATUS_DATA_ERROR           ((NTSTATUS)0xC000003E)
#define STATUS_CONNECTION_RESET     ((NTSTATUS)0xC000020D)

/* ------------------------------------------------------------------ */
/*  OBJECT_ATTRIBUTES                                                  */
/* ------------------------------------------------------------------ */

#define OBJ_CASE_INSENSITIVE  0x00000040
#define OBJ_KERNEL_HANDLE     0x00000200

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = (r); \
        (p)->ObjectName = (n); \
        (p)->Attributes = (a); \
        (p)->SecurityDescriptor = (s); \
        (p)->SecurityQualityOfService = NULL; \
    } while (0)

/* ------------------------------------------------------------------ */
/*  IO_STATUS_BLOCK                                                    */
/* ------------------------------------------------------------------ */

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* ------------------------------------------------------------------ */
/*  CLIENT_ID                                                          */
/* ------------------------------------------------------------------ */

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* ------------------------------------------------------------------ */
/*  MEMORY_BASIC_INFORMATION                                           */
/* ------------------------------------------------------------------ */

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID       BaseAddress;
    PVOID       AllocationBase;
    DWORD       AllocationProtect;
    WORD        PartitionId;
    WORD        Padding;
    SIZE_T      RegionSize;
    DWORD       State;
    DWORD       Protect;
    DWORD       Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

/* ------------------------------------------------------------------ */
/*  LARGE_INTEGER                                                      */
/* ------------------------------------------------------------------ */

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    };
    long long QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

/* ------------------------------------------------------------------ */
/*  Memory protection constants                                        */
/* ------------------------------------------------------------------ */

#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_EXECUTE_WRITECOPY  0x80
#define PAGE_GUARD              0x100

/* ------------------------------------------------------------------ */
/*  Memory allocation type constants                                   */
/* ------------------------------------------------------------------ */

#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_DECOMMIT            0x00004000
#define MEM_RELEASE             0x00008000
#define MEM_FREE                0x00010000
#define MEM_PRIVATE             0x00020000
#define MEM_MAPPED              0x00040000

/* ------------------------------------------------------------------ */
/*  Section access rights                                              */
/* ------------------------------------------------------------------ */

#define SECTION_MAP_READ        0x0004
#define SECTION_MAP_WRITE       0x0002
#define SECTION_MAP_EXECUTE     0x0008
#define SECTION_QUERY           0x0001
#define SECTION_ALL_ACCESS      0x000F

/* Section allocation attributes */
#define SEC_IMAGE               0x01000000
#define SEC_COMMIT              0x08000000

/* ------------------------------------------------------------------ */
/*  File access & creation constants                                   */
/* ------------------------------------------------------------------ */

#define FILE_READ_DATA          0x0001
#define FILE_READ_ATTRIBUTES    0x0080
#define FILE_WRITE_DATA_NTDEFS  0x0002
#define FILE_APPEND_DATA        0x0004
#define SYNCHRONIZE             0x00100000
#define DELETE_ACCESS            0x00010000
#define GENERIC_READ            0x80000000
#define GENERIC_WRITE           0x40000000

#define FILE_SHARE_READ         0x00000001
#define FILE_SHARE_WRITE        0x00000002
#define FILE_SHARE_DELETE       0x00000004

#define FILE_OPEN               0x00000001
#define FILE_CREATE_NTDEFS      0x00000002
#define FILE_OPEN_IF_NTDEFS     0x00000003
#define FILE_OVERWRITE_IF       0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_DELETE_ON_CLOSE    0x00001000
#define FILE_DIRECTORY_FILE     0x00000001
#define FILE_NON_DIRECTORY_FILE_NTDEFS 0x00000040

/* File attribute constants */
#define FILE_ATTRIBUTE_NORMAL   0x00000080
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010

/* File list directory access */
#define FILE_LIST_DIRECTORY     0x0001

/* ------------------------------------------------------------------ */
/*  Registry key access rights                                         */
/* ------------------------------------------------------------------ */

#define KEY_QUERY_VALUE          0x0001
#define KEY_SET_VALUE            0x0002
#define KEY_CREATE_SUB_KEY       0x0004
#define KEY_ENUMERATE_SUB_KEYS   0x0008
#define KEY_READ                 0x20019
#define KEY_WRITE                0x20006
#define KEY_ALL_ACCESS           0xF003F

/* Registry value information classes */
#define KeyValuePartialInformation      2

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    BYTE  Data[1];    /* Variable length */
} KEY_VALUE_PARTIAL_INFORMATION;

/* ------------------------------------------------------------------ */
/*  Token access rights and types                                      */
/* ------------------------------------------------------------------ */

#define TOKEN_DUPLICATE         0x0002
#define TOKEN_QUERY             0x0008
#define TOKEN_IMPERSONATE       0x0004
#define TOKEN_ASSIGN_PRIMARY    0x0001

/* Token types */
#define TokenPrimary            1
#define TokenImpersonation      2

/* Thread information classes */
#define ThreadImpersonationToken 5

/* Process access rights */
#define PROCESS_QUERY_INFORMATION       0x0400
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

/* ------------------------------------------------------------------ */
/*  Directory file query structures                                    */
/* ------------------------------------------------------------------ */

/* FILE_INFORMATION_CLASS values */
#define FileBothDirectoryInformation     3

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LARGE_INTEGER   CreationTime;
    LARGE_INTEGER   LastAccessTime;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   ChangeTime;
    LARGE_INTEGER   EndOfFile;
    LARGE_INTEGER   AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    ULONG           EaSize;
    BYTE            ShortNameLength;
    BYTE            Reserved;
    WCHAR           ShortName[12];
    WCHAR           FileName[1];    /* Variable length */
} FILE_BOTH_DIR_INFORMATION;

/* STATUS codes for directory enumeration */
#define STATUS_NO_MORE_FILES    ((NTSTATUS)0x80000006)

/* ------------------------------------------------------------------ */
/*  Process information classes                                        */
/* ------------------------------------------------------------------ */

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29,
} PROCESSINFOCLASS;

/* ------------------------------------------------------------------ */
/*  ViewShare                                                          */
/* ------------------------------------------------------------------ */

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2,
} SECTION_INHERIT;

/* ------------------------------------------------------------------ */
/*  Exception handling structures (for VEH)                            */
/* ------------------------------------------------------------------ */

#define EXCEPTION_MAXIMUM_PARAMETERS 15

#define EXCEPTION_CONTINUE_EXECUTION ((LONG)-1)
#define EXCEPTION_CONTINUE_SEARCH    ((LONG)0)

#define STATUS_GUARD_PAGE_VIOLATION  ((NTSTATUS)0x80000001)

#ifndef _EXCEPTION_RECORD_DEFINED
#define _EXCEPTION_RECORD_DEFINED
typedef struct _EXCEPTION_RECORD {
    NTSTATUS ExceptionCode;
    DWORD    ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID    ExceptionAddress;
    DWORD    NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

/* Forward-declare CONTEXT64 — full definition in sleep.h */
typedef struct _CONTEXT64 CONTEXT64;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    CONTEXT64        *ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
#endif

/* ------------------------------------------------------------------ */
/*  CONTEXT64 — defined in sleep.h (canonical definition).             */
/*  Include sleep.h for CONTEXT64.  Only define CONTEXT_FULL here.     */
/* ------------------------------------------------------------------ */

#ifndef CONTEXT_FULL
#define CONTEXT_FULL            0x10000F
#endif

/* ------------------------------------------------------------------ */
/*  RUNTIME_FUNCTION — .pdata entry for x64 exception handling         */
/* ------------------------------------------------------------------ */

/* Note: RUNTIME_FUNCTION is already defined in evasion.h — this is
   provided here for files that include ntdefs.h but not evasion.h.
   Guard against double definition. */
#ifndef _RUNTIME_FUNCTION_DEFINED
#define _RUNTIME_FUNCTION_DEFINED
/* Defined in evasion.h */
#endif

#endif /* NTDEFS_H */
