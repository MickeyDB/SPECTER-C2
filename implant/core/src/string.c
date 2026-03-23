/**
 * SPECTER Implant — CRT-free String / Memory Operations
 *
 * All functions prefixed with spec_ to avoid CRT symbol conflicts.
 */

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  String length                                                      */
/* ------------------------------------------------------------------ */

SIZE_T spec_strlen(const char *s) {
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

SIZE_T spec_wcslen(const WCHAR *s) {
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

/* ------------------------------------------------------------------ */
/*  String comparison                                                  */
/* ------------------------------------------------------------------ */

int spec_strcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int spec_wcsicmp(const WCHAR *a, const WCHAR *b) {
    WCHAR ca, cb;
    while (*a) {
        ca = *a;
        cb = *b;
        /* Lowercase ASCII range only — sufficient for DLL name comparison */
        if (ca >= L'A' && ca <= L'Z') ca += 0x20;
        if (cb >= L'A' && cb <= L'Z') cb += 0x20;
        if (ca != cb) return (int)ca - (int)cb;
        a++;
        b++;
    }
    return (int)*a - (int)*b;
}

/* ------------------------------------------------------------------ */
/*  Memory operations                                                  */
/* ------------------------------------------------------------------ */

void *spec_memcpy(void *dst, const void *src, SIZE_T n) {
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *spec_memmove(void *dst, const void *src, SIZE_T n) {
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *(--d) = *(--s);
    }
    return dst;
}

void *spec_memset(void *dst, int c, SIZE_T n) {
    BYTE *d = (BYTE *)dst;
    while (n--) *d++ = (BYTE)c;
    return dst;
}

int spec_memcmp(const void *a, const void *b, SIZE_T n) {
    const BYTE *pa = (const BYTE *)a;
    const BYTE *pb = (const BYTE *)b;
    while (n--) {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        pa++;
        pb++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  String copy / concatenate                                          */
/* ------------------------------------------------------------------ */

char *spec_strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++));
    return dst;
}

char *spec_strncpy(char *dst, const char *src, SIZE_T n) {
    SIZE_T i;
    for (i = 0; i < n && src[i]; i++)
        dst[i] = src[i];
    if (i < n)
        dst[i] = '\0';
    else if (n > 0)
        dst[n - 1] = '\0';
    return dst;
}

char *spec_strcat(char *dst, const char *src) {
    char *d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

char *spec_strncat(char *dst, const char *src, SIZE_T n) {
    char *d = dst;
    while (*d) d++;
    SIZE_T remaining = n - (SIZE_T)(d - dst);
    if (remaining <= 1) {
        if (n > 0) dst[n - 1] = '\0';
        return dst;
    }
    remaining--; /* reserve space for null */
    while (*src && remaining > 0) {
        *d++ = *src++;
        remaining--;
    }
    *d = '\0';
    return dst;
}
