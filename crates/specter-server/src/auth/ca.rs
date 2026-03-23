use std::sync::Arc;

use chrono::Utc;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Certificate generation error: {0}")]
    CertGen(String),

    #[error("Certificate not found: {0}")]
    NotFound(String),

    #[error("Certificate already revoked: {0}")]
    AlreadyRevoked(String),

    #[error("Encryption error: {0}")]
    Encryption(String),
}

/// Information about an issued certificate.
#[derive(Clone, Debug)]
pub struct CertInfo {
    pub serial: String,
    pub subject_cn: String,
    pub subject_ou: String,
    pub cert_pem: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
}

/// PKCS12-like bundle returned when issuing operator certs.
/// Contains the operator certificate, private key, and CA chain — all PEM-encoded.
#[derive(Clone, Debug)]
pub struct OperatorCertBundle {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_pem: String,
    pub serial: String,
}

/// Embedded Certificate Authority for mTLS operator authentication.
pub struct EmbeddedCA {
    pool: SqlitePool,
    ca_cert_pem: String,
    ca_key_pair: Arc<RwLock<KeyPair>>,
    ca_params: CertificateParams,
}

impl EmbeddedCA {
    /// Initialize the CA. On first run, generates a new root CA keypair and self-signed cert.
    /// On subsequent runs, loads the existing CA from the database.
    ///
    /// `master_key` is used to encrypt/decrypt the CA private key at rest.
    pub async fn init(pool: SqlitePool, master_key: &[u8; 32]) -> Result<Self, CaError> {
        let existing =
            sqlx::query("SELECT ca_cert_pem, ca_key_pem_encrypted FROM ca_state WHERE id = 'root'")
                .fetch_optional(&pool)
                .await?;

        if let Some(row) = existing {
            let ca_cert_pem: String = row.get("ca_cert_pem");
            let encrypted_key: Vec<u8> = row.get("ca_key_pem_encrypted");

            let key_pem = decrypt_key(&encrypted_key, master_key)
                .map_err(|e| CaError::Encryption(e.to_string()))?;

            let key_pair = KeyPair::from_pem(&key_pem)
                .map_err(|e| CaError::CertGen(format!("Failed to load CA key: {e}")))?;

            let ca_params = build_ca_params()?;

            tracing::info!("Loaded existing CA certificate from database");
            Ok(Self {
                pool,
                ca_cert_pem,
                ca_key_pair: Arc::new(RwLock::new(key_pair)),
                ca_params,
            })
        } else {
            // First run: generate new CA
            let key_pair = KeyPair::generate()
                .map_err(|e| CaError::CertGen(format!("Failed to generate CA keypair: {e}")))?;

            let ca_params = build_ca_params()?;

            let ca_cert = ca_params
                .clone()
                .self_signed(&key_pair)
                .map_err(|e| CaError::CertGen(format!("Failed to self-sign CA cert: {e}")))?;

            let ca_cert_pem = ca_cert.pem();
            let key_pem = key_pair.serialize_pem();

            let encrypted_key = encrypt_key(&key_pem, master_key)
                .map_err(|e| CaError::Encryption(e.to_string()))?;

            let now = Utc::now().timestamp();
            sqlx::query(
                "INSERT INTO ca_state (id, ca_cert_pem, ca_key_pem_encrypted, created_at) VALUES ('root', ?, ?, ?)",
            )
            .bind(&ca_cert_pem)
            .bind(&encrypted_key)
            .bind(now)
            .execute(&pool)
            .await?;

            tracing::info!("Generated new CA certificate");
            Ok(Self {
                pool,
                ca_cert_pem,
                ca_key_pair: Arc::new(RwLock::new(key_pair)),
                ca_params,
            })
        }
    }

    /// Issue an operator client certificate.
    /// CN = username, OU = role. Returns a bundle with cert, key, and CA cert.
    pub async fn issue_operator_cert(
        &self,
        username: &str,
        role: &str,
        validity_days: u32,
    ) -> Result<OperatorCertBundle, CaError> {
        let operator_key = KeyPair::generate()
            .map_err(|e| CaError::CertGen(format!("Failed to generate operator keypair: {e}")))?;

        let serial = generate_serial();

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CaError::CertGen(format!("Failed to create cert params: {e}")))?;

        params.distinguished_name.push(DnType::CommonName, username);
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, role);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "SPECTER C2");

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(validity_days as i64);

        params.serial_number = Some(SerialNumber::from_slice(
            &hex::decode(&serial).unwrap_or_else(|_| serial.as_bytes().to_vec()),
        ));

        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.is_ca = IsCa::NoCa;

        let ca_key = self.ca_key_pair.read().await;
        let ca_cert_params = self.ca_params.clone();

        let ca_cert = ca_cert_params.self_signed(&ca_key).map_err(|e| {
            CaError::CertGen(format!("Failed to recreate CA cert for signing: {e}"))
        })?;

        let operator_cert = params
            .signed_by(&operator_key, &ca_cert, &ca_key)
            .map_err(|e| CaError::CertGen(format!("Failed to sign operator cert: {e}")))?;

        let cert_pem = operator_cert.pem();
        let key_pem = operator_key.serialize_pem();

        let now_ts = Utc::now().timestamp();
        let expires_ts = now_ts + (validity_days as i64 * 86400);

        // Store certificate record
        sqlx::query(
            "INSERT INTO certificates (serial, subject_cn, subject_ou, cert_pem, issued_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&serial)
        .bind(username)
        .bind(role)
        .bind(&cert_pem)
        .bind(now_ts)
        .bind(expires_ts)
        .execute(&self.pool)
        .await?;

        tracing::info!("Issued operator certificate: CN={username}, OU={role}, serial={serial}");

        Ok(OperatorCertBundle {
            cert_pem,
            key_pem,
            ca_cert_pem: self.ca_cert_pem.clone(),
            serial,
        })
    }

    /// Issue a server TLS certificate with SANs for the provided hostnames.
    pub async fn issue_server_cert(
        &self,
        hostnames: &[String],
    ) -> Result<(String, String), CaError> {
        let server_key = KeyPair::generate()
            .map_err(|e| CaError::CertGen(format!("Failed to generate server keypair: {e}")))?;

        let serial = generate_serial();

        // Build SAN list: always include localhost + 127.0.0.1
        let mut san_names: Vec<SanType> = vec![
            SanType::DnsName(
                Ia5String::try_from("localhost".to_string())
                    .map_err(|e| CaError::CertGen(format!("Invalid SAN: {e}")))?,
            ),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        ];
        for h in hostnames {
            if let Ok(ip) = h.parse::<std::net::IpAddr>() {
                san_names.push(SanType::IpAddress(ip));
            } else {
                san_names.push(SanType::DnsName(
                    Ia5String::try_from(h.clone())
                        .map_err(|e| CaError::CertGen(format!("Invalid SAN: {e}")))?,
                ));
            }
        }

        let mut params = CertificateParams::new(vec![])
            .map_err(|e| CaError::CertGen(format!("Failed to create cert params: {e}")))?;

        params
            .distinguished_name
            .push(DnType::CommonName, "SPECTER Teamserver");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "SPECTER C2");

        params.subject_alt_names = san_names;

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(365);

        params.serial_number = Some(SerialNumber::from_slice(
            &hex::decode(&serial).unwrap_or_else(|_| serial.as_bytes().to_vec()),
        ));

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.is_ca = IsCa::NoCa;

        let ca_key = self.ca_key_pair.read().await;
        let ca_cert_params = self.ca_params.clone();

        let ca_cert = ca_cert_params.self_signed(&ca_key).map_err(|e| {
            CaError::CertGen(format!("Failed to recreate CA cert for signing: {e}"))
        })?;

        let server_cert = params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .map_err(|e| CaError::CertGen(format!("Failed to sign server cert: {e}")))?;

        let cert_pem = server_cert.pem();
        let key_pem = server_key.serialize_pem();

        let now_ts = Utc::now().timestamp();
        let expires_ts = now_ts + 365 * 86400;

        sqlx::query(
            "INSERT INTO certificates (serial, subject_cn, subject_ou, cert_pem, issued_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&serial)
        .bind("SPECTER Teamserver")
        .bind("server")
        .bind(&cert_pem)
        .bind(now_ts)
        .bind(expires_ts)
        .execute(&self.pool)
        .await?;

        tracing::info!("Issued server certificate, serial={serial}");

        Ok((cert_pem, key_pem))
    }

    /// Revoke a certificate by serial number.
    pub async fn revoke_cert(&self, serial: &str) -> Result<(), CaError> {
        let row = sqlx::query("SELECT revoked FROM certificates WHERE serial = ?")
            .bind(serial)
            .fetch_optional(&self.pool)
            .await?;

        let row = row.ok_or_else(|| CaError::NotFound(serial.to_string()))?;
        let revoked: bool = row.get::<i32, _>("revoked") != 0;

        if revoked {
            return Err(CaError::AlreadyRevoked(serial.to_string()));
        }

        let now = Utc::now().timestamp();
        sqlx::query("UPDATE certificates SET revoked = 1, revoked_at = ? WHERE serial = ?")
            .bind(now)
            .bind(serial)
            .execute(&self.pool)
            .await?;

        tracing::info!("Revoked certificate serial={serial}");
        Ok(())
    }

    /// Check if a certificate serial is revoked.
    pub async fn check_revoked(&self, serial: &str) -> Result<bool, CaError> {
        let row = sqlx::query("SELECT revoked FROM certificates WHERE serial = ?")
            .bind(serial)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(r.get::<i32, _>("revoked") != 0),
            None => Ok(false), // Unknown serial = not in our CRL
        }
    }

    /// List all issued certificates.
    pub async fn list_certificates(&self) -> Result<Vec<CertInfo>, CaError> {
        let rows = sqlx::query(
            "SELECT serial, subject_cn, subject_ou, cert_pem, issued_at, expires_at, revoked, revoked_at \
             FROM certificates ORDER BY issued_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| CertInfo {
                serial: row.get("serial"),
                subject_cn: row.get("subject_cn"),
                subject_ou: row.get("subject_ou"),
                cert_pem: row.get("cert_pem"),
                issued_at: row.get("issued_at"),
                expires_at: row.get("expires_at"),
                revoked: row.get::<i32, _>("revoked") != 0,
                revoked_at: row.get("revoked_at"),
            })
            .collect())
    }

    /// Get the root CA certificate in PEM format.
    pub fn get_root_cert(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get all revoked certificate serials (for CRL checking).
    pub async fn get_revoked_serials(&self) -> Result<Vec<String>, CaError> {
        let rows = sqlx::query("SELECT serial FROM certificates WHERE revoked = 1")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.iter().map(|r| r.get("serial")).collect())
    }
}

/// Build CA certificate parameters (10-year validity, CA:TRUE).
fn build_ca_params() -> Result<CertificateParams, CaError> {
    let mut params = CertificateParams::new(vec![])
        .map_err(|e| CaError::CertGen(format!("Failed to create CA params: {e}")))?;

    params
        .distinguished_name
        .push(DnType::CommonName, "SPECTER C2 Root CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "SPECTER C2");

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(3650); // 10 years

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    Ok(params)
}

/// Generate a random serial number as hex string.
fn generate_serial() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

/// Encrypt CA private key at rest using ChaCha20Poly1305.
fn encrypt_key(key_pem: &str, master_key: &[u8; 32]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    let cipher = ChaCha20Poly1305::new(master_key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, key_pem.as_bytes())?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt CA private key from encrypted storage.
fn decrypt_key(encrypted: &[u8], master_key: &[u8; 32]) -> Result<String, chacha20poly1305::Error> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    if encrypted.len() < 12 {
        return Err(chacha20poly1305::Error);
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let cipher = ChaCha20Poly1305::new(master_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    String::from_utf8(plaintext).map_err(|_| chacha20poly1305::Error)
}

/// Derive the CA master key.
///
/// Checks the `SPECTER_CA_KEY` environment variable first. If not set, falls
/// back to a deterministic derivation from the provided passphrase (typically
/// the database path). **For production deployments, always set `SPECTER_CA_KEY`
/// to a high-entropy secret.**
pub fn derive_master_key(passphrase: &str) -> [u8; 32] {
    if let Ok(env_key) = std::env::var("SPECTER_CA_KEY") {
        if !env_key.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"SPECTER-CA-MASTER-KEY:");
            hasher.update(env_key.as_bytes());
            return hasher.finalize().into();
        }
    }

    tracing::warn!(
        "SPECTER_CA_KEY not set — deriving CA master key from DB path. \
         Set SPECTER_CA_KEY for production deployments."
    );
    let mut hasher = Sha256::new();
    hasher.update(b"SPECTER-CA-MASTER-KEY:");
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn test_pool() -> SqlitePool {
        db::init_db(":memory:").await.unwrap()
    }

    fn test_master_key() -> [u8; 32] {
        derive_master_key("test-passphrase")
    }

    #[tokio::test]
    async fn test_ca_init_creates_new_ca() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let root_pem = ca.get_root_cert();
        assert!(root_pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_ca_init_loads_existing() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca1 = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let pem1 = ca1.get_root_cert().to_string();

        let ca2 = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let pem2 = ca2.get_root_cert().to_string();

        assert_eq!(pem1, pem2);
    }

    #[tokio::test]
    async fn test_issue_operator_cert() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let bundle = ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();

        assert!(bundle.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!bundle.serial.is_empty());
    }

    #[tokio::test]
    async fn test_issue_server_cert() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let (cert_pem, key_pem) = ca
            .issue_server_cert(&["teamserver.local".to_string()])
            .await
            .unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn test_revoke_cert() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let bundle = ca
            .issue_operator_cert("bob", "OPERATOR", 365)
            .await
            .unwrap();

        assert!(!ca.check_revoked(&bundle.serial).await.unwrap());

        ca.revoke_cert(&bundle.serial).await.unwrap();
        assert!(ca.check_revoked(&bundle.serial).await.unwrap());
    }

    #[tokio::test]
    async fn test_revoke_already_revoked() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let bundle = ca
            .issue_operator_cert("charlie", "OPERATOR", 365)
            .await
            .unwrap();

        ca.revoke_cert(&bundle.serial).await.unwrap();
        let err = ca.revoke_cert(&bundle.serial).await;
        assert!(matches!(err, Err(CaError::AlreadyRevoked(_))));
    }

    #[tokio::test]
    async fn test_revoke_nonexistent() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let err = ca.revoke_cert("nonexistent").await;
        assert!(matches!(err, Err(CaError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_list_certificates() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        assert!(ca.list_certificates().await.unwrap().is_empty());

        ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();
        ca.issue_operator_cert("bob", "OPERATOR", 30).await.unwrap();

        let certs = ca.list_certificates().await.unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[tokio::test]
    async fn test_get_revoked_serials() {
        let pool = test_pool().await;
        let key = test_master_key();

        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();
        let b1 = ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();
        let b2 = ca
            .issue_operator_cert("bob", "OPERATOR", 365)
            .await
            .unwrap();

        ca.revoke_cert(&b1.serial).await.unwrap();

        let revoked = ca.get_revoked_serials().await.unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0], b1.serial);
        assert!(!revoked.contains(&b2.serial));
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let key = test_master_key();
        let plaintext = "test private key data";

        let encrypted = encrypt_key(plaintext, &key).unwrap();
        let decrypted = decrypt_key(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key() {
        let key1 = derive_master_key("key1");
        let key2 = derive_master_key("key2");
        let plaintext = "test private key data";

        let encrypted = encrypt_key(plaintext, &key1).unwrap();
        let result = decrypt_key(&encrypted, &key2);
        assert!(result.is_err());
    }
}
