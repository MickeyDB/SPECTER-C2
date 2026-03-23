//! Configuration management for the SPECTER client.
//!
//! Stores connection settings and certificate paths in `~/.specter/config.toml`.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const SPECTER_DIR: &str = ".specter";
const CONFIG_FILE: &str = "config.toml";
const CERT_FILE: &str = "operator.pem";
const KEY_FILE: &str = "operator-key.pem";
const CA_FILE: &str = "ca.pem";

/// Persisted client configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    /// Teamserver gRPC address.
    #[serde(default)]
    pub server: Option<String>,
    /// Path to operator certificate PEM.
    #[serde(default)]
    pub cert_path: Option<String>,
    /// Path to operator private key PEM.
    #[serde(default)]
    pub key_path: Option<String>,
    /// Path to CA certificate PEM.
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

/// Returns the `~/.specter/` directory path.
pub fn specter_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(SPECTER_DIR))
}

/// Ensure `~/.specter/` exists.
pub fn ensure_specter_dir() -> Option<PathBuf> {
    let dir = specter_dir()?;
    let _ = fs::create_dir_all(&dir);
    Some(dir)
}

/// Load config from `~/.specter/config.toml`, returning default if missing.
pub fn load_config() -> ClientConfig {
    let path = match specter_dir() {
        Some(d) => d.join(CONFIG_FILE),
        None => return ClientConfig::default(),
    };
    match fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => ClientConfig::default(),
    }
}

/// Save config to `~/.specter/config.toml`.
pub fn save_config(config: &ClientConfig) -> Result<(), String> {
    let dir = ensure_specter_dir().ok_or("Cannot determine home directory")?;
    let path = dir.join(CONFIG_FILE);
    let content = toml::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())
}

/// Save operator certificate bundle to `~/.specter/`.
/// Returns `(cert_path, key_path, ca_path)`.
pub fn save_cert_bundle(
    cert_pem: &str,
    key_pem: &str,
    ca_cert_pem: &str,
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let dir = ensure_specter_dir().ok_or("Cannot determine home directory")?;

    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    let ca_path = dir.join(CA_FILE);

    fs::write(&cert_path, cert_pem).map_err(|e| format!("Failed to write cert: {e}"))?;
    fs::write(&key_path, key_pem).map_err(|e| format!("Failed to write key: {e}"))?;
    fs::write(&ca_path, ca_cert_pem).map_err(|e| format!("Failed to write CA cert: {e}"))?;

    Ok((cert_path, key_path, ca_path))
}

/// Default certificate paths in `~/.specter/`.
pub fn default_cert_paths() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dir = specter_dir()?;
    let cert = dir.join(CERT_FILE);
    let key = dir.join(KEY_FILE);
    let ca = dir.join(CA_FILE);
    if cert.exists() && key.exists() && ca.exists() {
        Some((cert, key, ca))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_config_roundtrip() {
        let config = ClientConfig {
            server: Some("https://10.0.0.1:50051".to_string()),
            cert_path: Some("/home/op/.specter/operator.pem".to_string()),
            key_path: Some("/home/op/.specter/operator-key.pem".to_string()),
            ca_cert_path: Some("/home/op/.specter/ca.pem".to_string()),
        };
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: ClientConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(
            deserialized.server.as_deref(),
            Some("https://10.0.0.1:50051")
        );
        assert!(deserialized.cert_path.is_some());
    }

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert!(config.server.is_none());
        assert!(config.cert_path.is_none());
    }

    #[test]
    fn test_parse_empty_config() {
        let config: ClientConfig = toml::from_str("").unwrap();
        assert!(config.server.is_none());
    }

    #[test]
    fn test_save_and_load_cert_bundle() {
        let dir = std::env::temp_dir().join("specter-test-config");
        let _ = fs::create_dir_all(&dir);

        let cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
        let ca = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----";

        let cert_path = dir.join("operator.pem");
        let key_path = dir.join("operator-key.pem");
        let ca_path = dir.join("ca.pem");

        fs::write(&cert_path, cert).unwrap();
        fs::write(&key_path, key).unwrap();
        fs::write(&ca_path, ca).unwrap();

        assert_eq!(fs::read_to_string(&cert_path).unwrap(), cert);
        assert_eq!(fs::read_to_string(&key_path).unwrap(), key);
        assert_eq!(fs::read_to_string(&ca_path).unwrap(), ca);

        let _ = fs::remove_dir_all(&dir);
    }
}
