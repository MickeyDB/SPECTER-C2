/**
 * SPECTER Implant — Transform Chain Interface
 *
 * Profile-driven payload transform: compress → encrypt → encode (send)
 * and decode → decrypt → decompress (recv).  Inline LZ4 compressor,
 * base64/hex encoders, using existing ChaCha20-Poly1305 from crypto.c.
 */

#ifndef TRANSFORM_H
#define TRANSFORM_H

#include "specter.h"
#include "profile.h"
#include "crypto.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define TRANSFORM_MAX_OUTPUT   8192

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/**
 * Send-side transform: compress → encrypt → encode.
 * plaintext/len: input payload.
 * session_key: 32-byte AEAD key.
 * cfg: profile transform config.
 * output/output_len: output buffer and written length.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS transform_send(const BYTE *plaintext, DWORD len,
                         const BYTE session_key[32],
                         const TRANSFORM_CONFIG *cfg,
                         BYTE *output, DWORD *output_len,
                         DWORD output_max);

/**
 * Recv-side transform: decode → decrypt → decompress.
 * encoded/len: input encoded payload.
 * session_key: 32-byte AEAD key.
 * cfg: profile transform config.
 * output/output_len: output buffer and written length.
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS transform_recv(const BYTE *encoded, DWORD len,
                         const BYTE session_key[32],
                         const TRANSFORM_CONFIG *cfg,
                         BYTE *output, DWORD *output_len,
                         DWORD output_max);

/* ------------------------------------------------------------------ */
/*  Inline LZ4 (minimal subset)                                        */
/* ------------------------------------------------------------------ */

/**
 * LZ4 compress. Output format: [4-byte LE original_size][compressed_data].
 * Returns compressed size (including size prefix), or 0 on failure.
 */
DWORD lz4_compress(const BYTE *input, DWORD input_len,
                    BYTE *output, DWORD output_max);

/**
 * LZ4 decompress. Input format: [4-byte LE original_size][compressed_data].
 * Returns decompressed size, or 0 on failure.
 */
DWORD lz4_decompress(const BYTE *input, DWORD input_len,
                      BYTE *output, DWORD output_max);

#endif /* TRANSFORM_H */
