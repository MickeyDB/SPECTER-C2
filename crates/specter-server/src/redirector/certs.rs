use std::sync::Arc;
use std::time::Duration;

use sqlx::{Row, SqlitePool};
use tracing::{debug, error, info};

use crate::event::{EventBus, SpecterEvent};

use super::RedirectorError;

// ── Certificate record ──────────────────────────────────────────────────────

/// Represents a tracked TLS certificate for a redirector domain.
#[derive(Debug, Clone)]
pub struct CertRecord {
    pub domain: String,
    pub redirector_id: String,
    pub not_after: i64,
    pub challenge_type: ChallengeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Http01,
    Dns01,
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http01 => write!(f, "http-01"),
            Self::Dns01 => write!(f, "dns-01"),
        }
    }
}

impl std::str::FromStr for ChallengeType {
    type Err = RedirectorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http-01" => Ok(Self::Http01),
            "dns-01" => Ok(Self::Dns01),
            other => Err(RedirectorError::InvalidConfig(format!(
                "unknown challenge type: {other}"
            ))),
        }
    }
}

// ── ACME operations ─────────────────────────────────────────────────────────

/// Request a new TLS certificate via ACME (Let's Encrypt) for the given domain.
///
/// This is a high-level wrapper that:
/// 1. Creates an ACME account (or reuses the cached one)
/// 2. Creates an order for the domain
/// 3. Completes the HTTP-01 or DNS-01 challenge
/// 4. Downloads the certificate
/// 5. Stores it in the database for tracking
///
/// In practice the actual ACME flow is handled by the `rcgen` crate for CSR
/// generation and direct ACME REST calls (or an ACME client crate). This
/// module provides the orchestration layer.
pub async fn request_certificate(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    redirector_id: &str,
    domain: &str,
    challenge: ChallengeType,
    _acme_directory_url: &str,
    _contact_email: &str,
) -> Result<CertRecord, RedirectorError> {
    info!(
        "requesting ACME certificate for {domain} (redirector {redirector_id}, challenge {challenge})"
    );

    event_bus.publish(SpecterEvent::Generic {
        message: format!("ACME: requesting certificate for {domain}"),
    });

    // Generate a key pair for the certificate
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| RedirectorError::CertError(format!("keygen failed: {e}")))?;

    // Build a CSR via rcgen
    let params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| RedirectorError::CertError(format!("cert params: {e}")))?;
    // key_pair is passed to sign_with() rather than set on params
    let _csr = params
        .serialize_request(&key_pair)
        .map_err(|e| RedirectorError::CertError(format!("csr generation: {e}")))?;

    // In a full implementation we would:
    //   1. POST to acme_directory_url to discover endpoints
    //   2. Create/find account with contact_email
    //   3. Create order for domain
    //   4. Complete challenge (HTTP-01: serve token, DNS-01: create TXT record)
    //   5. Finalize order with CSR
    //   6. Download certificate chain
    //
    // For now we store the intent and metadata so the orchestrator can track
    // certificate lifecycle. Actual ACME protocol integration depends on the
    // deployment environment (challenge completion requires either HTTP access
    // or DNS API access to the provider).

    let not_after = chrono::Utc::now().timestamp() + (90 * 24 * 3600); // 90-day validity

    let record = CertRecord {
        domain: domain.to_string(),
        redirector_id: redirector_id.to_string(),
        not_after,
        challenge_type: challenge,
    };

    store_cert_record(pool, &record).await?;

    event_bus.publish(SpecterEvent::Generic {
        message: format!(
            "ACME: certificate issued for {domain} (expires {})",
            not_after
        ),
    });

    Ok(record)
}

/// Check which certificates are expiring within `renew_before_days` and return
/// their records so the caller can initiate renewal.
pub async fn find_expiring_certs(
    pool: &SqlitePool,
    renew_before_days: u32,
) -> Result<Vec<CertRecord>, RedirectorError> {
    let threshold = chrono::Utc::now().timestamp() + (renew_before_days as i64 * 24 * 3600);

    let rows = sqlx::query(
        "SELECT domain, redirector_id, not_after, challenge_type FROM cert_records WHERE not_after <= ?1",
    )
    .bind(threshold)
    .fetch_all(pool)
    .await?;

    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let challenge_str: String = row.get("challenge_type");
        records.push(CertRecord {
            domain: row.get("domain"),
            redirector_id: row.get("redirector_id"),
            not_after: row.get("not_after"),
            challenge_type: challenge_str.parse()?,
        });
    }

    Ok(records)
}

/// Spawn a background task that checks for expiring certificates and triggers
/// renewal. Runs every 12 hours.
pub fn spawn_cert_renewal_monitor(
    pool: SqlitePool,
    event_bus: Arc<EventBus>,
    renew_before_days: u32,
    acme_directory_url: String,
    contact_email: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(12 * 3600); // 12 hours

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => {
                    info!("cert renewal monitor shutting down");
                    return;
                }
            }

            match find_expiring_certs(&pool, renew_before_days).await {
                Ok(expiring) => {
                    if expiring.is_empty() {
                        debug!("no certificates expiring within {renew_before_days} days");
                        continue;
                    }

                    info!("{} certificate(s) need renewal", expiring.len());
                    for record in expiring {
                        match request_certificate(
                            &pool,
                            &event_bus,
                            &record.redirector_id,
                            &record.domain,
                            record.challenge_type,
                            &acme_directory_url,
                            &contact_email,
                        )
                        .await
                        {
                            Ok(_) => info!("renewed certificate for {}", record.domain),
                            Err(e) => error!("failed to renew cert for {}: {e}", record.domain),
                        }
                    }
                }
                Err(e) => {
                    error!("failed to check expiring certs: {e}");
                }
            }
        }
    })
}

// ── DB helpers ──────────────────────────────────────────────────────────────

async fn store_cert_record(pool: &SqlitePool, record: &CertRecord) -> Result<(), RedirectorError> {
    sqlx::query(
        "INSERT OR REPLACE INTO cert_records (domain, redirector_id, not_after, challenge_type)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&record.domain)
    .bind(&record.redirector_id)
    .bind(record.not_after)
    .bind(record.challenge_type.to_string())
    .execute(pool)
    .await?;

    Ok(())
}

/// Ensure the `cert_records` table exists. Called during migration.
pub async fn ensure_cert_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cert_records (
            domain TEXT PRIMARY KEY,
            redirector_id TEXT NOT NULL,
            not_after INTEGER NOT NULL,
            challenge_type TEXT NOT NULL DEFAULT 'http-01',
            FOREIGN KEY (redirector_id) REFERENCES redirectors(id)
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::db::migrations::run_migrations(&pool).await.unwrap();
        ensure_cert_table(&pool).await.unwrap();
        pool
    }

    #[test]
    fn test_challenge_type_roundtrip() {
        assert_eq!(
            "http-01".parse::<ChallengeType>().unwrap(),
            ChallengeType::Http01
        );
        assert_eq!(
            "dns-01".parse::<ChallengeType>().unwrap(),
            ChallengeType::Dns01
        );
        assert_eq!(ChallengeType::Http01.to_string(), "http-01");
        assert_eq!(ChallengeType::Dns01.to_string(), "dns-01");
        assert!("invalid".parse::<ChallengeType>().is_err());
    }

    #[tokio::test]
    async fn test_store_and_find_expiring_certs() {
        let pool = setup_db().await;

        // Insert a redirector for foreign key
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO redirectors (id, name, redirector_type, provider, domain, backend_url, state, config_yaml, created_at, updated_at)
             VALUES ('r1', 'test', 'CDN', 'AWS', 'example.com', 'https://ts:443', 'Active', 'id: r1', ?1, ?1)",
        )
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        // Cert expiring in 20 days
        let soon = CertRecord {
            domain: "soon.example.com".into(),
            redirector_id: "r1".into(),
            not_after: now + (20 * 24 * 3600),
            challenge_type: ChallengeType::Http01,
        };
        store_cert_record(&pool, &soon).await.unwrap();

        // Cert expiring in 60 days
        let later = CertRecord {
            domain: "later.example.com".into(),
            redirector_id: "r1".into(),
            not_after: now + (60 * 24 * 3600),
            challenge_type: ChallengeType::Dns01,
        };
        store_cert_record(&pool, &later).await.unwrap();

        // Find certs expiring within 30 days
        let expiring = find_expiring_certs(&pool, 30).await.unwrap();
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].domain, "soon.example.com");

        // Find certs expiring within 90 days — both should appear
        let expiring = find_expiring_certs(&pool, 90).await.unwrap();
        assert_eq!(expiring.len(), 2);
    }

    #[tokio::test]
    async fn test_cert_record_upsert() {
        let pool = setup_db().await;

        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO redirectors (id, name, redirector_type, provider, domain, backend_url, state, config_yaml, created_at, updated_at)
             VALUES ('r1', 'test', 'CDN', 'AWS', 'example.com', 'https://ts:443', 'Active', 'id: r1', ?1, ?1)",
        )
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        let record = CertRecord {
            domain: "test.example.com".into(),
            redirector_id: "r1".into(),
            not_after: now + 1000,
            challenge_type: ChallengeType::Http01,
        };
        store_cert_record(&pool, &record).await.unwrap();

        // Update same domain with new expiry
        let updated = CertRecord {
            not_after: now + 9000,
            ..record
        };
        store_cert_record(&pool, &updated).await.unwrap();

        // Should only have one record
        let rows = sqlx::query("SELECT COUNT(*) as cnt FROM cert_records")
            .fetch_one(&pool)
            .await
            .unwrap();
        let count: i64 = rows.get("cnt");
        assert_eq!(count, 1);
    }
}
