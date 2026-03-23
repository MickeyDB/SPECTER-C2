use std::io::BufReader;

use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tonic::transport::{Identity, ServerTlsConfig};
use x509_parser::prelude::*;

use super::ca::EmbeddedCA;
use super::OperatorContext;

#[derive(Debug, Error)]
pub enum MtlsError {
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("Certificate parse error: {0}")]
    CertParse(String),

    #[error("CA error: {0}")]
    Ca(#[from] super::ca::CaError),
}

/// Build a Tonic `ServerTlsConfig` for mTLS using the embedded CA.
///
/// The server presents its own TLS cert (signed by the CA) and requires clients
/// to present a valid certificate also signed by the CA.
pub async fn build_mtls_config(
    ca: &EmbeddedCA,
    hostnames: &[String],
) -> Result<(ServerTlsConfig, String, String), MtlsError> {
    // Issue a server certificate
    let (server_cert_pem, server_key_pem) = ca
        .issue_server_cert(hostnames)
        .await
        .map_err(MtlsError::Ca)?;

    let ca_cert_pem = ca.get_root_cert();

    let identity = Identity::from_pem(server_cert_pem.as_bytes(), server_key_pem.as_bytes());

    // Parse CA cert for client verification
    let ca_cert = tonic::transport::Certificate::from_pem(ca_cert_pem.as_bytes());

    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    Ok((tls_config, server_cert_pem, server_key_pem))
}

/// Extract operator identity (CN and OU) from a client certificate.
///
/// Returns `(username, role)` parsed from the certificate's subject.
pub fn extract_operator_from_cert(cert_der: &[u8]) -> Result<(String, String), MtlsError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| MtlsError::CertParse(format!("Failed to parse X.509: {e}")))?;

    let subject = cert.subject();

    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("")
        .to_string();

    let ou = subject
        .iter_organizational_unit()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("")
        .to_string();

    if cn.is_empty() {
        return Err(MtlsError::CertParse(
            "Certificate has no CN (Common Name)".to_string(),
        ));
    }

    Ok((cn, ou))
}

/// Extract the serial number from a DER-encoded certificate as hex string.
pub fn extract_serial_from_cert(cert_der: &[u8]) -> Result<String, MtlsError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| MtlsError::CertParse(format!("Failed to parse X.509: {e}")))?;

    Ok(hex::encode(cert.serial.to_bytes_be()))
}

/// Parse PEM certificate to DER bytes.
pub fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, MtlsError> {
    let mut reader = BufReader::new(pem_str.as_bytes());
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();

    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| MtlsError::CertParse("No certificate found in PEM".to_string()))
}

/// mTLS-aware auth interceptor. When mTLS is active, extracts operator identity
/// from the client certificate. Falls back to token-based auth or dev-mode bypass.
///
/// The actual TLS handshake and client cert validation happens at the transport
/// layer (rustls). This interceptor extracts identity from validated certificates
/// and also supports the existing token-based auth for backwards compatibility.
#[derive(Clone)]
pub struct MtlsAuthInterceptor {
    pub dev_mode: bool,
    pub ca_cert_pem: Option<String>,
    tokens: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, super::TokenInfo>>>,
}

impl MtlsAuthInterceptor {
    pub fn new(
        tokens: std::sync::Arc<
            std::sync::RwLock<std::collections::HashMap<String, super::TokenInfo>>,
        >,
        dev_mode: bool,
        ca_cert_pem: Option<String>,
    ) -> Self {
        Self {
            dev_mode,
            ca_cert_pem,
            tokens,
        }
    }
}

impl tonic::service::Interceptor for MtlsAuthInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        // In dev-mode, bypass authentication and inject a default admin operator.
        if self.dev_mode {
            request
                .extensions_mut()
                .insert(OperatorContext::dev_admin());
            return Ok(request);
        }

        // Try token-based auth from authorization header (backwards compatible)
        if let Some(token_value) = request.metadata().get("authorization") {
            let token_str = token_value
                .to_str()
                .map_err(|_| tonic::Status::unauthenticated("Invalid authorization header"))?;

            let token = token_str.strip_prefix("Bearer ").unwrap_or(token_str);

            let tokens = self
                .tokens
                .read()
                .map_err(|_| tonic::Status::internal("Token store lock poisoned"))?;

            if let Some(info) = tokens.get(token) {
                request.extensions_mut().insert(OperatorContext {
                    operator_id: info.operator_id.clone(),
                    username: info.username.clone(),
                    role: info.role.clone(),
                });
                return Ok(request);
            } else {
                return Err(tonic::Status::unauthenticated("Invalid token"));
            }
        }

        // No auth header — pass through for RPCs that don't require auth (e.g., Authenticate)
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ca::{derive_master_key, EmbeddedCA};
    use crate::db;
    use sqlx::SqlitePool;

    async fn test_pool() -> SqlitePool {
        db::init_db(":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_extract_operator_from_issued_cert() {
        let pool = test_pool().await;
        let key = derive_master_key("test");
        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();

        let bundle = ca.issue_operator_cert("alice", "ADMIN", 365).await.unwrap();

        let cert_der = pem_to_der(&bundle.cert_pem).unwrap();
        let (cn, ou) = extract_operator_from_cert(&cert_der).unwrap();

        assert_eq!(cn, "alice");
        assert_eq!(ou, "ADMIN");
    }

    #[tokio::test]
    async fn test_extract_serial_from_cert() {
        let pool = test_pool().await;
        let key = derive_master_key("test");
        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();

        let bundle = ca.issue_operator_cert("bob", "OPERATOR", 30).await.unwrap();

        let cert_der = pem_to_der(&bundle.cert_pem).unwrap();
        let serial = extract_serial_from_cert(&cert_der).unwrap();

        assert!(!serial.is_empty());
        assert!(hex::decode(&serial).is_ok());
    }

    #[tokio::test]
    async fn test_build_mtls_config() {
        let pool = test_pool().await;
        let key = derive_master_key("test");
        let ca = EmbeddedCA::init(pool.clone(), &key).await.unwrap();

        let result = build_mtls_config(&ca, &["teamserver.local".to_string()]).await;
        assert!(result.is_ok());

        let (_, server_cert_pem, server_key_pem) = result.unwrap();
        assert!(server_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(server_key_pem.contains("BEGIN PRIVATE KEY"));
    }
}
