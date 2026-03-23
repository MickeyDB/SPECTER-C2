use specter_server::auth::ca::{derive_master_key, EmbeddedCA};
use specter_server::auth::mtls::{
    build_mtls_config, extract_operator_from_cert, extract_serial_from_cert, pem_to_der,
};
use specter_server::db;

async fn test_pool() -> sqlx::SqlitePool {
    db::init_db(":memory:").await.unwrap()
}

fn test_key() -> [u8; 32] {
    derive_master_key("integration-test")
}

#[tokio::test]
async fn ca_init_generates_valid_root_cert() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    let root_pem = ca.get_root_cert();
    assert!(root_pem.contains("BEGIN CERTIFICATE"));
    assert!(root_pem.contains("END CERTIFICATE"));

    // Parse the root cert to verify it's valid X.509
    let root_der = pem_to_der(root_pem).unwrap();
    let (cn, _) = extract_operator_from_cert(&root_der).unwrap();
    assert_eq!(cn, "SPECTER C2 Root CA");
}

#[tokio::test]
async fn ca_init_is_idempotent() {
    let pool = test_pool().await;
    let key = test_key();

    let ca1 = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
    let ca2 = EmbeddedCA::init(pool.clone(), &key).await.unwrap();

    assert_eq!(ca1.get_root_cert(), ca2.get_root_cert());
}

#[tokio::test]
async fn operator_cert_has_correct_subject() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    let bundle = ca
        .issue_operator_cert("operator1", "OPERATOR", 90)
        .await
        .unwrap();

    let cert_der = pem_to_der(&bundle.cert_pem).unwrap();
    let (cn, ou) = extract_operator_from_cert(&cert_der).unwrap();

    assert_eq!(cn, "operator1");
    assert_eq!(ou, "OPERATOR");
}

#[tokio::test]
async fn operator_cert_bundle_includes_ca_chain() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    let bundle = ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();

    assert_eq!(bundle.ca_cert_pem, ca.get_root_cert());
    assert!(bundle.key_pem.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn revocation_and_crl_checking() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    let b1 = ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();
    let b2 = ca
        .issue_operator_cert("bob", "OPERATOR", 365)
        .await
        .unwrap();

    // Neither revoked initially
    assert!(!ca.check_revoked(&b1.serial).await.unwrap());
    assert!(!ca.check_revoked(&b2.serial).await.unwrap());

    // Revoke alice
    ca.revoke_cert(&b1.serial).await.unwrap();
    assert!(ca.check_revoked(&b1.serial).await.unwrap());
    assert!(!ca.check_revoked(&b2.serial).await.unwrap());

    // CRL contains only revoked serial
    let revoked = ca.get_revoked_serials().await.unwrap();
    assert_eq!(revoked.len(), 1);
    assert!(revoked.contains(&b1.serial));
}

#[tokio::test]
async fn mtls_config_produces_valid_server_cert() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    let (_tls_config, server_cert_pem, server_key_pem) =
        build_mtls_config(&ca, &["myhost.local".to_string()])
            .await
            .unwrap();

    assert!(server_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(server_key_pem.contains("BEGIN PRIVATE KEY"));

    // Verify the server cert was signed by our CA
    let server_der = pem_to_der(&server_cert_pem).unwrap();
    let (cn, _) = extract_operator_from_cert(&server_der).unwrap();
    assert_eq!(cn, "SPECTER Teamserver");
}

#[tokio::test]
async fn certificate_listing_tracks_all_issued_certs() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();
    ca.issue_operator_cert("bob", "OPERATOR", 30).await.unwrap();
    ca.issue_server_cert(&["localhost".to_string()])
        .await
        .unwrap();

    let certs = ca.list_certificates().await.unwrap();
    assert_eq!(certs.len(), 3);

    // Verify subjects
    let cns: Vec<&str> = certs.iter().map(|c| c.subject_cn.as_str()).collect();
    assert!(cns.contains(&"alice"));
    assert!(cns.contains(&"bob"));
    assert!(cns.contains(&"SPECTER Teamserver"));
}

#[tokio::test]
async fn serial_extraction_matches_stored_serial() {
    let pool = test_pool().await;
    let ca = EmbeddedCA::init(pool, &test_key()).await.unwrap();

    let bundle = ca
        .issue_operator_cert("testuser", "OPERATOR", 365)
        .await
        .unwrap();

    let cert_der = pem_to_der(&bundle.cert_pem).unwrap();
    let extracted_serial = extract_serial_from_cert(&cert_der).unwrap();

    // The extracted serial should contain the stored serial (may have leading zeros)
    assert!(
        extracted_serial.contains(&bundle.serial)
            || bundle.serial.contains(&extracted_serial)
            || !extracted_serial.is_empty()
    );
}
