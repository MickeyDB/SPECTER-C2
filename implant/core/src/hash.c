/**
 * SPECTER Implant — DJB2 API Hashing
 *
 * Used for runtime resolution of module names and export names
 * without embedding cleartext strings.
 */

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  DJB2 hash — narrow (char) strings                                  */
/* ------------------------------------------------------------------ */

DWORD spec_djb2_hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        /* Lowercase for case-insensitive matching */
        if (c >= 'A' && c <= 'Z') c += 0x20;
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }
    return hash;
}

/* ------------------------------------------------------------------ */
/*  DJB2 hash — wide (WCHAR) strings                                   */
/* ------------------------------------------------------------------ */

DWORD spec_djb2_hash_w(const WCHAR *str) {
    DWORD hash = 5381;
    WCHAR c;
    while ((c = *str++)) {
        /* Lowercase ASCII range for DLL name comparison */
        if (c >= L'A' && c <= L'Z') c += 0x20;
        hash = ((hash << 5) + hash) + (DWORD)c;
    }
    return hash;
}
