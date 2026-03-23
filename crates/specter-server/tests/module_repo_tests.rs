use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use specter_server::db;
use specter_server::module::{ModuleRepository, ModuleType};
use x25519_dalek::{PublicKey, StaticSecret};

async fn test_pool() -> sqlx::SqlitePool {
    db::init_db(":memory:").await.unwrap()
}

fn test_signing_key() -> SigningKey {
    // Deterministic key for reproducible tests
    let seed: [u8; 32] = [0x42; 32];
    SigningKey::from_bytes(&seed)
}

// --- Registration and retrieval ---

#[tokio::test]
async fn store_and_retrieve_module_by_id() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let blob = vec![0xCC; 64];
    let id = repo
        .store_module("socks5", "1.0.0", ModuleType::Pic, "SOCKS5 proxy", &blob)
        .await
        .unwrap();

    let module = repo.get_module(&id).await.unwrap().unwrap();
    assert_eq!(module.name, "socks5");
    assert_eq!(module.version, "1.0.0");
    assert_eq!(module.module_type, "PIC");
    assert_eq!(module.description, "SOCKS5 proxy");
    assert_eq!(module.blob_size, 64);
}

#[tokio::test]
async fn retrieve_module_by_name() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let blob = vec![0xAA; 32];
    repo.store_module("token", "1.0.0", ModuleType::Pic, "Token ops", &blob)
        .await
        .unwrap();

    let module = repo.get_module_by_name("token").await.unwrap().unwrap();
    assert_eq!(module.name, "token");
    assert_eq!(module.blob_size, 32);
}

#[tokio::test]
async fn get_module_id_by_name() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let blob = vec![0xBB; 16];
    let id = repo
        .store_module("inject", "1.0.0", ModuleType::Pic, "Injection", &blob)
        .await
        .unwrap();

    let fetched_id = repo.get_module_id_by_name("inject").await.unwrap().unwrap();
    assert_eq!(fetched_id, id);
}

#[tokio::test]
async fn get_nonexistent_module_returns_none() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    assert!(repo.get_module("no-such-id").await.unwrap().is_none());
    assert!(repo
        .get_module_by_name("no-such-name")
        .await
        .unwrap()
        .is_none());
    assert!(repo.get_module_id_by_name("nope").await.unwrap().is_none());
}

// --- List ---

#[tokio::test]
async fn list_modules_returns_all_stored() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    repo.store_module("mod-a", "1.0.0", ModuleType::Pic, "A", &[1; 8])
        .await
        .unwrap();
    repo.store_module("mod-b", "2.0.0", ModuleType::Coff, "B", &[2; 16])
        .await
        .unwrap();
    repo.store_module("mod-c", "1.0.0", ModuleType::Pic, "C", &[3; 24])
        .await
        .unwrap();

    let modules = repo.list_modules().await.unwrap();
    assert_eq!(modules.len(), 3);

    // Verify names are present (order is by created_at DESC)
    let names: Vec<&str> = modules.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"mod-a"));
    assert!(names.contains(&"mod-b"));
    assert!(names.contains(&"mod-c"));
}

#[tokio::test]
async fn list_modules_empty_repo() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let modules = repo.list_modules().await.unwrap();
    assert!(modules.is_empty());
}

// --- Module type handling ---

#[tokio::test]
async fn module_type_pic_and_coff() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    repo.store_module("pic-mod", "1.0.0", ModuleType::Pic, "", &[0; 8])
        .await
        .unwrap();
    repo.store_module("coff-mod", "1.0.0", ModuleType::Coff, "", &[0; 8])
        .await
        .unwrap();

    let pic = repo.get_module_by_name("pic-mod").await.unwrap().unwrap();
    assert_eq!(pic.module_type, "PIC");

    let coff = repo.get_module_by_name("coff-mod").await.unwrap().unwrap();
    assert_eq!(coff.module_type, "COFF");
}

// --- Deletion ---

#[tokio::test]
async fn delete_module_removes_it() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let id = repo
        .store_module("ephemeral", "1.0.0", ModuleType::Pic, "", &[0xEE; 8])
        .await
        .unwrap();

    assert!(repo.get_module(&id).await.unwrap().is_some());
    repo.delete_module(&id).await.unwrap();
    assert!(repo.get_module(&id).await.unwrap().is_none());
}

// --- Duplicate name+version rejected ---

#[tokio::test]
async fn duplicate_name_version_rejected() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    repo.store_module("socks5", "1.0.0", ModuleType::Pic, "first", &[1; 8])
        .await
        .unwrap();

    let result = repo
        .store_module("socks5", "1.0.0", ModuleType::Pic, "duplicate", &[2; 8])
        .await;
    assert!(result.is_err());
}

// --- Signing ---

#[tokio::test]
async fn signing_pubkey_matches_key() {
    let key = test_signing_key();
    let expected_pub = key.verifying_key().to_bytes();

    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, key);

    assert_eq!(repo.signing_pubkey_bytes(), expected_pub);
}

// --- Package: wire format, encryption, signing ---

#[tokio::test]
async fn package_module_wire_format() {
    let pool = test_pool().await;
    let signing_key = test_signing_key();
    let repo = ModuleRepository::with_signing_key(pool, signing_key.clone());

    let blob = b"test module payload for packaging";
    let id = repo
        .store_module("pkg-test", "1.0.0", ModuleType::Pic, "packaging test", blob)
        .await
        .unwrap();

    // Generate a session X25519 keypair
    let session_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let session_pubkey = PublicKey::from(&session_secret);

    let package = repo
        .package_module(&id, session_pubkey.as_bytes())
        .await
        .unwrap();

    // Verify header: [4B magic][4B version][4B type][4B size][32B pubkey][64B sig]
    assert!(
        package.len() >= 112,
        "package must be at least 112 bytes (header)"
    );

    // Magic: "SPEC" = 0x43455053 LE
    let magic = u32::from_le_bytes(package[0..4].try_into().unwrap());
    assert_eq!(magic, 0x43455053, "magic should be SPEC");

    // Version
    let version = u32::from_le_bytes(package[4..8].try_into().unwrap());
    assert_eq!(version, 1);

    // Module type: PIC = 0
    let module_type = u32::from_le_bytes(package[8..12].try_into().unwrap());
    assert_eq!(module_type, 0);

    // Encrypted size
    let encrypted_size = u32::from_le_bytes(package[12..16].try_into().unwrap()) as usize;
    assert_eq!(
        package.len(),
        112 + encrypted_size,
        "total size = header + encrypted payload"
    );

    // Encrypted payload must be larger than original (nonce + tag overhead)
    // nonce(12) + ciphertext(blob.len()) + tag(16)
    assert_eq!(encrypted_size, 12 + blob.len() + 16);
}

#[tokio::test]
async fn package_module_signature_verifies() {
    let pool = test_pool().await;
    let signing_key = test_signing_key();
    let verifying_key = VerifyingKey::from(&signing_key);
    let repo = ModuleRepository::with_signing_key(pool, signing_key);

    let blob = b"signed module content";
    let id = repo
        .store_module("sig-test", "1.0.0", ModuleType::Pic, "", blob)
        .await
        .unwrap();

    let session_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let session_pubkey = PublicKey::from(&session_secret);

    let package = repo
        .package_module(&id, session_pubkey.as_bytes())
        .await
        .unwrap();

    // Extract signature (bytes 48..112) and encrypted payload (bytes 112..)
    let sig_bytes: [u8; 64] = package[48..112].try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let enc_payload = &package[112..];

    // Verify signature over encrypted payload
    assert!(
        verifying_key.verify(enc_payload, &signature).is_ok(),
        "Ed25519 signature must verify over encrypted payload"
    );
}

#[tokio::test]
async fn package_module_decrypts_correctly() {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let original_blob = b"decryptable module payload 1234567890";
    let id = repo
        .store_module("dec-test", "1.0.0", ModuleType::Pic, "", original_blob)
        .await
        .unwrap();

    // Session keypair
    let session_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let session_pubkey = PublicKey::from(&session_secret);

    let package = repo
        .package_module(&id, session_pubkey.as_bytes())
        .await
        .unwrap();

    // Extract ephemeral public key (bytes 16..48) and encrypted payload (bytes 112..)
    let ephemeral_pub_bytes: [u8; 32] = package[16..48].try_into().unwrap();
    let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);
    let enc_payload = &package[112..];

    // Perform X25519 key agreement from session side
    let shared_secret = session_secret.diffie_hellman(&ephemeral_pub);

    // HKDF-SHA256 key derivation (same as server)
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"SPECTER-MODULE").unwrap();
    mac.update(shared_secret.as_bytes());
    let prk = mac.finalize().into_bytes();

    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    mac2.update(b"module-decrypt");
    mac2.update(&[0x01]);
    let okm = mac2.finalize().into_bytes();

    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&okm);

    // Decrypt: enc_payload = [12B nonce][ciphertext][16B tag]
    let nonce = Nonce::from_slice(&enc_payload[..12]);
    let ciphertext_and_tag = &enc_payload[12..];

    let cipher = ChaCha20Poly1305::new_from_slice(&derived_key).unwrap();
    let decrypted = cipher.decrypt(nonce, ciphertext_and_tag).unwrap();

    assert_eq!(
        decrypted, original_blob,
        "decrypted blob must match original"
    );
}

#[tokio::test]
async fn package_nonexistent_module_returns_error() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let fake_pubkey = [0u8; 32];
    let result = repo.package_module("does-not-exist", &fake_pubkey).await;
    assert!(result.is_err());
}

// --- Seed default modules ---

#[tokio::test]
async fn seed_default_modules_registers_all_six() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    repo.seed_default_modules().await.unwrap();

    let modules = repo.list_modules().await.unwrap();
    assert_eq!(modules.len(), 6);

    let names: Vec<&str> = modules.iter().map(|m| m.name.as_str()).collect();
    for expected in &["socks5", "token", "lateral", "inject", "exfil", "collect"] {
        assert!(names.contains(expected), "missing module: {}", expected);
    }
}

#[tokio::test]
async fn seed_default_modules_is_idempotent() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    repo.seed_default_modules().await.unwrap();
    repo.seed_default_modules().await.unwrap(); // second call should skip existing

    let modules = repo.list_modules().await.unwrap();
    assert_eq!(
        modules.len(),
        6,
        "idempotent seed should not duplicate modules"
    );
}

// --- Metadata fields ---

#[tokio::test]
async fn stored_module_timestamps_are_set() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let id = repo
        .store_module("ts-test", "1.0.0", ModuleType::Pic, "", &[0; 4])
        .await
        .unwrap();

    let module = repo.get_module(&id).await.unwrap().unwrap();
    assert!(module.created_at > 0);
    assert_eq!(module.created_at, module.updated_at);
}

// --- Per-session encryption produces unique packages ---

#[tokio::test]
async fn different_sessions_produce_different_packages() {
    let pool = test_pool().await;
    let repo = ModuleRepository::with_signing_key(pool, test_signing_key());

    let id = repo
        .store_module("uniq-test", "1.0.0", ModuleType::Pic, "", &[0xAB; 32])
        .await
        .unwrap();

    let secret_a = StaticSecret::random_from_rng(rand::thread_rng());
    let pubkey_a = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pubkey_b = PublicKey::from(&secret_b);

    let pkg_a = repo.package_module(&id, pubkey_a.as_bytes()).await.unwrap();
    let pkg_b = repo.package_module(&id, pubkey_b.as_bytes()).await.unwrap();

    // Different ephemeral keys → different encrypted payloads
    assert_ne!(pkg_a, pkg_b, "packages for different sessions must differ");

    // But both have the same magic/version/type header
    assert_eq!(pkg_a[0..12], pkg_b[0..12], "header fields should match");
}
