use specter_server::profile::{
    compile_profile, parse_profile, transform_decode, transform_encode, validate_profile,
};

fn load_profile_yaml(name: &str) -> String {
    let path = format!(
        "{}/../../profiles/{}.yaml",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e))
}

#[test]
fn slack_webhook_profile_parses_successfully() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).expect("slack-webhook profile should parse");
    assert_eq!(profile.name, "slack-webhook");
    assert_eq!(profile.timing.callback_interval, 30);
    assert_eq!(profile.timing.jitter_percent, 25.0);
    assert_eq!(profile.timing.initial_delay, 120);
    assert_eq!(profile.http.request.method, "POST");
    assert!(profile.http.request.uri_patterns.len() >= 4);
    assert!(profile.tls.target_ja3.is_some());
    assert_eq!(profile.tls.alpn, vec!["h2", "http/1.1"]);
}

#[test]
fn slack_webhook_profile_validates_without_errors() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).unwrap();
    let warnings = validate_profile(&profile).expect("validation should not error");
    // Warnings are OK (non-fatal), but there should be no validation errors
    for w in &warnings {
        eprintln!("Warning: {} - {}", w.field, w.message);
    }
}

#[test]
fn generic_https_profile_parses_successfully() {
    let yaml = load_profile_yaml("generic-https");
    let profile = parse_profile(&yaml).expect("generic-https profile should parse");
    assert_eq!(profile.name, "generic-https");
    assert_eq!(profile.timing.callback_interval, 60);
    assert_eq!(profile.timing.jitter_percent, 20.0);
    assert_eq!(profile.http.request.uri_patterns, vec!["/api/v1/data"]);
    assert_eq!(profile.http.request.method, "POST");
}

#[test]
fn generic_https_profile_validates_without_errors() {
    let yaml = load_profile_yaml("generic-https");
    let profile = parse_profile(&yaml).unwrap();
    let warnings = validate_profile(&profile).expect("validation should not error");
    for w in &warnings {
        eprintln!("Warning: {} - {}", w.field, w.message);
    }
}

#[test]
fn slack_webhook_profile_compiles_to_binary() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).unwrap();
    let blob = compile_profile(&profile).expect("compilation should succeed");
    assert!(
        !blob.is_empty(),
        "compiled profile blob should not be empty"
    );
    // TLV binary should be reasonably sized
    assert!(blob.len() > 50, "compiled blob should have meaningful size");
}

#[test]
fn generic_https_profile_compiles_to_binary() {
    let yaml = load_profile_yaml("generic-https");
    let profile = parse_profile(&yaml).unwrap();
    let blob = compile_profile(&profile).expect("compilation should succeed");
    assert!(!blob.is_empty());
}

#[test]
fn slack_webhook_transform_roundtrip() {
    let yaml = load_profile_yaml("slack-webhook");
    let profile = parse_profile(&yaml).unwrap();
    let key: [u8; 32] = [0x42u8; 32];
    let plaintext = b"hello from specter implant";

    let encoded =
        transform_encode(plaintext, &profile.transform, &key).expect("encode should succeed");
    assert_ne!(&encoded[..], plaintext);

    let decoded =
        transform_decode(&encoded, &profile.transform, &key).expect("decode should succeed");
    assert_eq!(&decoded[..], plaintext);
}

#[test]
fn generic_https_transform_roundtrip() {
    let yaml = load_profile_yaml("generic-https");
    let profile = parse_profile(&yaml).unwrap();
    let key: [u8; 32] = [0xABu8; 32];
    let plaintext = b"test data for generic profile transform chain";

    let encoded =
        transform_encode(plaintext, &profile.transform, &key).expect("encode should succeed");
    let decoded =
        transform_decode(&encoded, &profile.transform, &key).expect("decode should succeed");
    assert_eq!(&decoded[..], plaintext);
}
