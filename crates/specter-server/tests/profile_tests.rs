use specter_server::db;
use specter_server::listener::{extract_embedded_data, format_profile_response};
use specter_server::profile::{
    compile_profile, parse_profile, transform_decode, transform_encode, validate_profile,
    ProfileStore,
};

fn load_profile_yaml(name: &str) -> String {
    let path = format!(
        "{}/../../profiles/{}.yaml",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e))
}

fn minimal_yaml() -> &'static str {
    r#"
name: test-profile
description: Minimal test profile
tls:
  cipher_suites: ["TLS_AES_128_GCM_SHA256"]
  alpn: ["h2"]
http:
  request:
    method: POST
    uri_patterns: ["/api/test"]
    headers:
      - name: Content-Type
        value: application/json
    body_template: '{"data": "{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: data
  response:
    status_code: 200
    body_template: '{"ok": true, "result": "{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: result
timing:
  callback_interval: 30
  jitter_distribution: uniform
  jitter_percent: 20
transform:
  compress: none
  encrypt: chacha20-poly1305
  encode: base64
"#
}

// ── YAML Parsing Tests ──────────────────────────────────────────────────────

#[test]
fn parse_slack_webhook_profile() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).expect("slack-webhook should parse");
    assert_eq!(profile.name, "slack-webhook");
    assert_eq!(profile.timing.callback_interval, 30);
    assert_eq!(profile.http.request.method, "POST");
    assert!(profile.http.request.uri_patterns.len() >= 4);
}

#[test]
fn parse_generic_https_profile() {
    let yaml = load_profile_yaml("generic-https");
    let profile = parse_profile(&yaml).expect("generic-https should parse");
    assert_eq!(profile.name, "generic-https");
    assert_eq!(profile.timing.callback_interval, 60);
    assert_eq!(profile.http.request.uri_patterns, vec!["/api/v1/data"]);
}

// ── Validation Tests ────────────────────────────────────────────────────────

#[test]
fn validate_catches_empty_name() {
    let yaml = r#"
name: ""
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/test"]
  response: {}
timing:
  callback_interval: 10
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let err = validate_profile(&profile).unwrap_err();
    assert!(err.to_string().contains("name cannot be empty"));
}

#[test]
fn validate_catches_zero_interval() {
    let yaml = r#"
name: bad
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/test"]
  response: {}
timing:
  callback_interval: 0
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let err = validate_profile(&profile).unwrap_err();
    assert!(err.to_string().contains("callback_interval must be > 0"));
}

#[test]
fn validate_catches_invalid_jitter_range() {
    let yaml = r#"
name: bad
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/test"]
  response: {}
timing:
  callback_interval: 10
  jitter_percent: 150
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let err = validate_profile(&profile).unwrap_err();
    assert!(err.to_string().contains("jitter_percent"));
}

#[test]
fn validate_catches_empty_uri_patterns() {
    let yaml = r#"
name: bad
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: []
  response: {}
timing:
  callback_interval: 10
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let err = validate_profile(&profile).unwrap_err();
    assert!(err.to_string().contains("uri_patterns"));
}

#[test]
fn validate_catches_invalid_working_hours() {
    let yaml = r#"
name: bad-hours
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/api"]
  response: {}
timing:
  callback_interval: 30
  working_hours:
    start_hour: 25
    end_hour: 18
    off_hours_multiplier: 4.0
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let err = validate_profile(&profile).unwrap_err();
    assert!(err.to_string().contains("0-23"));
}

#[test]
fn validate_catches_invalid_error_rate() {
    let yaml = r#"
name: bad-rate
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/api"]
  response:
    error_rate_percent: 150.0
timing:
  callback_interval: 30
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let err = validate_profile(&profile).unwrap_err();
    assert!(err.to_string().contains("error_rate_percent"));
}

#[test]
fn validate_warns_on_missing_embed_points() {
    let yaml = r#"
name: sparse
tls: { cipher_suites: ["TLS_AES_256"] }
http:
  request:
    uri_patterns: ["/api/v1"]
  response: {}
timing:
  callback_interval: 30
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let warnings = validate_profile(&profile).unwrap();
    assert!(warnings.len() >= 2);
}

#[test]
fn parse_invalid_yaml_returns_error() {
    let result = parse_profile("not: [valid: yaml: {{");
    assert!(result.is_err());
}

// ── Compilation Tests ───────────────────────────────────────────────────────

#[test]
fn compile_produces_valid_binary_blob() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let blob = compile_profile(&profile).unwrap();
    assert!(!blob.is_empty());

    // Walk TLV entries to verify structure
    let mut pos = 0;
    while pos < blob.len() {
        assert!(pos + 3 <= blob.len(), "truncated TLV at pos {pos}");
        let _fid = blob[pos];
        let len = u16::from_le_bytes([blob[pos + 1], blob[pos + 2]]) as usize;
        pos += 3 + len;
    }
    assert_eq!(pos, blob.len(), "trailing bytes in blob");
}

#[test]
fn compile_slack_webhook_produces_blob() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).unwrap();
    let blob = compile_profile(&profile).expect("compilation should succeed");
    assert!(blob.len() > 50, "compiled blob should have meaningful size");
}

#[test]
fn compile_generic_https_produces_blob() {
    let yaml = load_profile_yaml("generic-https");
    let profile = parse_profile(&yaml).unwrap();
    let blob = compile_profile(&profile).expect("compilation should succeed");
    assert!(!blob.is_empty());
}

// ── Transform Roundtrip Tests ───────────────────────────────────────────────

#[test]
fn transform_roundtrip_base64_no_compression() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let key: [u8; 32] = [0x42u8; 32];
    let plaintext = b"hello from specter implant";

    let encoded = transform_encode(plaintext, &profile.transform, &key).unwrap();
    assert_ne!(&encoded[..], plaintext);

    let decoded = transform_decode(&encoded, &profile.transform, &key).unwrap();
    assert_eq!(&decoded[..], plaintext);
}

#[test]
fn transform_roundtrip_slack_webhook_lz4_base64() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).unwrap();
    let key: [u8; 32] = [0xABu8; 32];
    let plaintext = b"test data for slack webhook transform chain";

    let encoded = transform_encode(plaintext, &profile.transform, &key).unwrap();
    let decoded = transform_decode(&encoded, &profile.transform, &key).unwrap();
    assert_eq!(&decoded[..], plaintext);
}

#[test]
fn transform_wrong_key_fails_decode() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let key: [u8; 32] = [0x42u8; 32];
    let mut wrong_key: [u8; 32] = [0x42u8; 32];
    wrong_key[0] = 0xFF;

    let encoded = transform_encode(b"secret", &profile.transform, &key).unwrap();
    let result = transform_decode(&encoded, &profile.transform, &wrong_key);
    assert!(result.is_err());
}

// ── Request Matching & Response Formatting Tests ────────────────────────────

#[test]
fn extract_embedded_data_from_json_body() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let body = br#"{"data": "SGVsbG8gV29ybGQ="}"#;

    let extracted = extract_embedded_data(body, &profile.http.request);
    assert!(extracted.is_some());
    assert_eq!(extracted.unwrap(), b"SGVsbG8gV29ybGQ=");
}

#[test]
fn extract_embedded_data_returns_none_for_missing_field() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let body = br#"{"other_field": "value"}"#;

    let extracted = extract_embedded_data(body, &profile.http.request);
    assert!(extracted.is_none());
}

#[test]
fn extract_embedded_data_returns_none_for_invalid_json() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let body = b"not valid json";

    let extracted = extract_embedded_data(body, &profile.http.request);
    assert!(extracted.is_none());
}

#[test]
fn extract_embedded_data_returns_body_when_no_embed_points() {
    let yaml = r#"
name: no-embed
tls: { cipher_suites: [] }
http:
  request:
    method: POST
    uri_patterns: ["/api/test"]
  response: {}
timing:
  callback_interval: 30
transform: {}
"#;
    let profile = parse_profile(yaml).unwrap();
    let body = b"raw body data";

    let extracted = extract_embedded_data(body, &profile.http.request);
    assert!(extracted.is_some());
    assert_eq!(extracted.unwrap(), b"raw body data");
}

#[tokio::test]
async fn format_response_embeds_data_in_template() {
    let profile = parse_profile(minimal_yaml()).unwrap();
    let data = b"encoded_payload_data";

    let response = format_profile_response(data, &profile.http.response);
    let resp = axum::response::IntoResponse::into_response(response);

    assert_eq!(resp.status(), 200);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains("encoded_payload_data"));
    assert!(body_str.contains("\"ok\": true"));
}

// ── Profile Store Tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn profile_store_create_and_get() {
    let pool = db::init_db(":memory:").await.unwrap();
    let store = ProfileStore::new(pool);

    let stored = store
        .create_profile("test-profile", "A test profile", minimal_yaml())
        .await
        .expect("create should succeed");

    assert_eq!(stored.name, "test-profile");
    assert_eq!(stored.description, "A test profile");
    assert!(stored.compiled_blob.is_some());
    assert!(!stored.compiled_blob.unwrap().is_empty());

    // Get by ID
    let fetched = store
        .get_profile(&stored.id)
        .await
        .expect("get should succeed")
        .expect("profile should exist");
    assert_eq!(fetched.name, "test-profile");
    assert_eq!(fetched.yaml_content, minimal_yaml());
}

#[tokio::test]
async fn profile_store_list() {
    let pool = db::init_db(":memory:").await.unwrap();
    let store = ProfileStore::new(pool);

    store
        .create_profile("profile-a", "", minimal_yaml())
        .await
        .unwrap();
    store
        .create_profile("profile-b", "", minimal_yaml())
        .await
        .unwrap();

    let profiles = store.list_profiles().await.unwrap();
    assert_eq!(profiles.len(), 2);

    let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"profile-a"));
    assert!(names.contains(&"profile-b"));
}

#[tokio::test]
async fn profile_store_create_rejects_invalid_yaml() {
    let pool = db::init_db(":memory:").await.unwrap();
    let store = ProfileStore::new(pool);

    let result = store
        .create_profile("bad", "", "not: [valid: yaml: {{")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn profile_store_compile_by_id() {
    let pool = db::init_db(":memory:").await.unwrap();
    let store = ProfileStore::new(pool);

    let stored = store
        .create_profile("compile-test", "", minimal_yaml())
        .await
        .unwrap();

    let blob = store
        .compile_profile_by_id(&stored.id)
        .await
        .expect("compile should succeed");
    assert!(!blob.is_empty());
}

#[tokio::test]
async fn profile_store_get_nonexistent_returns_none() {
    let pool = db::init_db(":memory:").await.unwrap();
    let store = ProfileStore::new(pool);

    let result = store.get_profile("nonexistent-id").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn profile_store_compile_nonexistent_fails() {
    let pool = db::init_db(":memory:").await.unwrap();
    let store = ProfileStore::new(pool);

    let result = store.compile_profile_by_id("nonexistent-id").await;
    assert!(result.is_err());
}
