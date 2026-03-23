use std::sync::Arc;

use sqlx::SqlitePool;

use specter_server::db;
use specter_server::event::EventBus;
use specter_server::listener::azure_listener::{
    build_blob_url, build_create_container_url, build_list_url, command_blob_name, decrypt_blob,
    encrypt_blob, parse_blob_names_xml, parse_blob_seq, parse_key_hex, result_blob_name,
    AzureListenerConfig, AzureListenerManager, AzureListenerStatus,
};
use specter_server::session::SessionManager;
use specter_server::task::TaskDispatcher;

// ── Helpers ────────────────────────────────────────────────────────────────

async fn setup() -> (SqlitePool, AzureListenerManager) {
    let pool = db::init_db(":memory:").await.unwrap();
    let bus = Arc::new(EventBus::new(64));
    let session_mgr = Arc::new(SessionManager::new(pool.clone(), bus.clone()));
    let task_disp = Arc::new(TaskDispatcher::new(pool.clone(), bus.clone()));
    let manager = AzureListenerManager::new(pool.clone(), session_mgr, task_disp, bus);
    (pool, manager)
}

fn sample_listener_config(id: &str) -> AzureListenerConfig {
    AzureListenerConfig {
        id: id.to_string(),
        name: format!("azure-{id}"),
        account_name: "specterstorage".into(),
        account_sas_token: "sv=2020-10-02&ss=b&srt=sco&sp=rwdlac&se=2030-01-01&sig=test".into(),
        poll_interval_secs: 10,
        max_blob_age_secs: 3600,
        encryption_key_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .into(),
    }
}

// ── Blob naming tests ──────────────────────────────────────────────────────

#[test]
fn command_blob_names_are_zero_padded() {
    assert_eq!(command_blob_name(0), "command-000000");
    assert_eq!(command_blob_name(1), "command-000001");
    assert_eq!(command_blob_name(42), "command-000042");
    assert_eq!(command_blob_name(999999), "command-999999");
}

#[test]
fn result_blob_names_are_zero_padded() {
    assert_eq!(result_blob_name(0), "result-000000");
    assert_eq!(result_blob_name(1), "result-000001");
    assert_eq!(result_blob_name(42), "result-000042");
    assert_eq!(result_blob_name(999999), "result-999999");
}

#[test]
fn parse_blob_seq_extracts_number_from_valid_names() {
    assert_eq!(parse_blob_seq("result-000000", "result-"), Some(0));
    assert_eq!(parse_blob_seq("result-000005", "result-"), Some(5));
    assert_eq!(parse_blob_seq("result-000123", "result-"), Some(123));
    assert_eq!(parse_blob_seq("command-000042", "command-"), Some(42));
}

#[test]
fn parse_blob_seq_returns_none_for_invalid_inputs() {
    assert_eq!(parse_blob_seq("result-abc", "result-"), None);
    assert_eq!(parse_blob_seq("other-000005", "result-"), None);
    assert_eq!(parse_blob_seq("metadata", "result-"), None);
    assert_eq!(parse_blob_seq("", "result-"), None);
    assert_eq!(parse_blob_seq("result-", "result-"), None);
}

#[test]
fn blob_naming_consistency() {
    // Verify that command/result names can be round-tripped through parse
    for seq in [0, 1, 100, 999999] {
        let cmd_name = command_blob_name(seq);
        let result_name = result_blob_name(seq);

        assert_eq!(parse_blob_seq(&cmd_name, "command-"), Some(seq));
        assert_eq!(parse_blob_seq(&result_name, "result-"), Some(seq));
    }
}

// ── SAS URL construction tests ─────────────────────────────────────────────

#[test]
fn build_blob_url_constructs_correct_format() {
    let url = build_blob_url(
        "specterstorage",
        "session-abc123",
        "result-000001",
        "sv=2020-10-02&sig=abc",
    );
    assert_eq!(
        url,
        "https://specterstorage.blob.core.windows.net/session-abc123/result-000001?sv=2020-10-02&sig=abc"
    );
}

#[test]
fn build_blob_url_with_different_accounts() {
    let url1 = build_blob_url("account1", "container", "blob", "sas=1");
    let url2 = build_blob_url("account2", "container", "blob", "sas=1");
    assert!(url1.starts_with("https://account1.blob.core.windows.net/"));
    assert!(url2.starts_with("https://account2.blob.core.windows.net/"));
}

#[test]
fn build_list_url_with_prefix() {
    let url = build_list_url(
        "specterstorage",
        "session-abc123",
        Some("result-"),
        "sv=2020-10-02&sig=abc",
    );
    assert!(url.contains("restype=container"));
    assert!(url.contains("comp=list"));
    assert!(url.contains("prefix=result-"));
    assert!(url.contains("sv=2020-10-02&sig=abc"));
    assert!(url.starts_with("https://specterstorage.blob.core.windows.net/session-abc123?"));
}

#[test]
fn build_list_url_without_prefix() {
    let url = build_list_url(
        "specterstorage",
        "session-abc123",
        None,
        "sv=2020-10-02&sig=abc",
    );
    assert!(!url.contains("prefix="));
    assert!(url.contains("restype=container&comp=list"));
}

#[test]
fn build_create_container_url_correct_format() {
    let url =
        build_create_container_url("specterstorage", "session-abc123", "sv=2020-10-02&sig=abc");
    assert_eq!(
        url,
        "https://specterstorage.blob.core.windows.net/session-abc123?restype=container&sv=2020-10-02&sig=abc"
    );
}

// ── Encryption roundtrip tests ─────────────────────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip_with_random_key() {
    let key: [u8; 32] = rand::random();
    let plaintext = b"hello from specter c2";

    let encrypted = encrypt_blob(&key, plaintext).unwrap();
    assert!(encrypted.len() > plaintext.len());
    // First 12 bytes = nonce, rest = ciphertext + 16-byte tag
    assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

    let decrypted = decrypt_blob(&key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_empty_payload() {
    let key: [u8; 32] = rand::random();
    let plaintext = b"";

    let encrypted = encrypt_blob(&key, plaintext).unwrap();
    let decrypted = decrypt_blob(&key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn encrypt_decrypt_large_payload() {
    let key: [u8; 32] = rand::random();
    let plaintext = vec![0xABu8; 65536];

    let encrypted = encrypt_blob(&key, &plaintext).unwrap();
    let decrypted = decrypt_blob(&key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let key1: [u8; 32] = rand::random();
    let key2: [u8; 32] = rand::random();
    let plaintext = b"secret task data";

    let encrypted = encrypt_blob(&key1, plaintext).unwrap();
    let result = decrypt_blob(&key2, &encrypted);
    assert!(result.is_err());
}

#[test]
fn decrypt_too_short_data_fails() {
    let key: [u8; 32] = rand::random();

    // Less than nonce (12) + tag (16) = 28 bytes minimum
    assert!(decrypt_blob(&key, &[0u8; 0]).is_err());
    assert!(decrypt_blob(&key, &[0u8; 10]).is_err());
    assert!(decrypt_blob(&key, &[0u8; 27]).is_err());
}

#[test]
fn decrypt_tampered_ciphertext_fails() {
    let key: [u8; 32] = rand::random();
    let plaintext = b"important data";

    let mut encrypted = encrypt_blob(&key, plaintext).unwrap();
    // Tamper with a ciphertext byte (after the 12-byte nonce)
    encrypted[15] ^= 0xFF;

    let result = decrypt_blob(&key, &encrypted);
    assert!(result.is_err());
}

#[test]
fn each_encryption_produces_different_ciphertext() {
    let key: [u8; 32] = rand::random();
    let plaintext = b"same input data";

    let enc1 = encrypt_blob(&key, plaintext).unwrap();
    let enc2 = encrypt_blob(&key, plaintext).unwrap();

    // Different nonces => different ciphertext
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    assert_eq!(decrypt_blob(&key, &enc1).unwrap(), plaintext);
    assert_eq!(decrypt_blob(&key, &enc2).unwrap(), plaintext);
}

// ── Key parsing tests ──────────────────────────────────────────────────────

#[test]
fn parse_valid_hex_key() {
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key = parse_key_hex(hex).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(key[0], 0x01);
    assert_eq!(key[1], 0x23);
}

#[test]
fn parse_key_hex_wrong_length_fails() {
    // Too short (16 bytes)
    assert!(parse_key_hex("0123456789abcdef0123456789abcdef").is_err());
    // Too long
    assert!(
        parse_key_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00")
            .is_err()
    );
    // Empty
    assert!(parse_key_hex("").is_err());
}

#[test]
fn parse_key_hex_invalid_chars_fails() {
    assert!(
        parse_key_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err()
    );
}

// ── XML blob name parsing tests ────────────────────────────────────────────

#[test]
fn parse_blob_names_from_valid_xml() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults>
  <Blobs>
    <Blob><Name>result-000001</Name><Properties><Content-Length>128</Content-Length></Properties></Blob>
    <Blob><Name>result-000002</Name><Properties /></Blob>
    <Blob><Name>command-000000</Name><Properties /></Blob>
    <Blob><Name>metadata</Name><Properties /></Blob>
  </Blobs>
</EnumerationResults>"#;

    let names = parse_blob_names_xml(xml);
    assert_eq!(names.len(), 4);
    assert_eq!(names[0], "result-000001");
    assert_eq!(names[1], "result-000002");
    assert_eq!(names[2], "command-000000");
    assert_eq!(names[3], "metadata");
}

#[test]
fn parse_blob_names_from_empty_blob_list() {
    let xml = r#"<?xml version="1.0"?>
<EnumerationResults><Blobs></Blobs></EnumerationResults>"#;
    let names = parse_blob_names_xml(xml);
    assert!(names.is_empty());
}

#[test]
fn parse_blob_names_from_empty_string() {
    let names = parse_blob_names_xml("");
    assert!(names.is_empty());
}

#[test]
fn parse_blob_names_single_blob() {
    let xml = r#"<EnumerationResults><Blobs><Blob><Name>result-000042</Name></Blob></Blobs></EnumerationResults>"#;
    let names = parse_blob_names_xml(xml);
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "result-000042");
}

// ── Azure listener manager integration tests ──────────────────────────────

#[tokio::test]
async fn create_listener_stores_in_db() {
    let (_pool, manager) = setup().await;
    let config = sample_listener_config("az-1");

    let result = manager.create_listener(&config).await;
    assert!(result.is_ok());

    let listeners = manager.list_listeners().await.unwrap();
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].0.id, "az-1");
    assert_eq!(listeners[0].0.name, "azure-az-1");
    assert_eq!(listeners[0].0.account_name, "specterstorage");
    assert_eq!(listeners[0].1, AzureListenerStatus::Stopped);
}

#[tokio::test]
async fn create_multiple_listeners() {
    let (_pool, manager) = setup().await;

    manager
        .create_listener(&sample_listener_config("az-1"))
        .await
        .unwrap();
    manager
        .create_listener(&sample_listener_config("az-2"))
        .await
        .unwrap();
    manager
        .create_listener(&sample_listener_config("az-3"))
        .await
        .unwrap();

    let listeners = manager.list_listeners().await.unwrap();
    assert_eq!(listeners.len(), 3);
    // All should be Stopped initially
    assert!(listeners
        .iter()
        .all(|(_, s)| *s == AzureListenerStatus::Stopped));
}

#[tokio::test]
async fn duplicate_listener_id_fails() {
    let (_pool, manager) = setup().await;

    manager
        .create_listener(&sample_listener_config("az-dup"))
        .await
        .unwrap();
    let result = manager
        .create_listener(&sample_listener_config("az-dup"))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn listener_config_serialization_roundtrip() {
    let (_pool, manager) = setup().await;
    let config = sample_listener_config("az-serde");

    manager.create_listener(&config).await.unwrap();

    let listeners = manager.list_listeners().await.unwrap();
    let (stored_config, _) = &listeners[0];
    assert_eq!(stored_config.id, config.id);
    assert_eq!(stored_config.account_name, config.account_name);
    assert_eq!(stored_config.poll_interval_secs, config.poll_interval_secs);
    assert_eq!(stored_config.max_blob_age_secs, config.max_blob_age_secs);
    assert_eq!(stored_config.encryption_key_hex, config.encryption_key_hex);
}

#[tokio::test]
async fn list_containers_returns_empty_initially() {
    let (_pool, manager) = setup().await;
    let config = sample_listener_config("az-empty");
    manager.create_listener(&config).await.unwrap();

    let containers = manager.list_containers("az-empty").await.unwrap();
    assert!(containers.is_empty());
}

#[tokio::test]
async fn sas_token_rotation_fails_for_unknown_session() {
    let (_pool, manager) = setup().await;

    let result = manager
        .rotate_sas_token("nonexistent-session", "new-token")
        .await;
    assert!(result.is_err());
}
