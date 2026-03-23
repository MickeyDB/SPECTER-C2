use std::path::Path;
use std::sync::Arc;

use sqlx::{Row, SqlitePool};
use tracing::{info, warn};

use crate::event::{EventBus, SpecterEvent};

use super::{RedirectorConfig, RedirectorError, RedirectorState};

// ── Domain pool status ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainStatus {
    Available,
    Active,
    Burned,
}

impl std::fmt::Display for DomainStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available => write!(f, "available"),
            Self::Active => write!(f, "active"),
            Self::Burned => write!(f, "burned"),
        }
    }
}

impl std::str::FromStr for DomainStatus {
    type Err = RedirectorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "available" => Ok(Self::Available),
            "active" => Ok(Self::Active),
            "burned" => Ok(Self::Burned),
            other => Err(RedirectorError::InvalidConfig(format!(
                "unknown domain status: {other}"
            ))),
        }
    }
}

/// Entry from the `domain_pool` table.
#[derive(Debug, Clone)]
pub struct DomainPoolEntry {
    pub domain: String,
    pub provider: String,
    pub status: DomainStatus,
    pub redirector_id: Option<String>,
}

// ── Domain pool management ──────────────────────────────────────────────────

/// Add a domain to the rotation pool.
pub async fn add_domain(
    pool: &SqlitePool,
    domain: &str,
    provider: &str,
) -> Result<(), RedirectorError> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO domain_pool (domain, provider, status, added_at) VALUES (?1, ?2, 'available', ?3)",
    )
    .bind(domain)
    .bind(provider)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// List all domains in the pool.
pub async fn list_domains(pool: &SqlitePool) -> Result<Vec<DomainPoolEntry>, RedirectorError> {
    let rows = sqlx::query(
        "SELECT domain, provider, status, redirector_id FROM domain_pool ORDER BY added_at",
    )
    .fetch_all(pool)
    .await?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let status_str: String = row.get("status");
        entries.push(DomainPoolEntry {
            domain: row.get("domain"),
            provider: row.get("provider"),
            status: status_str.parse()?,
            redirector_id: row.get("redirector_id"),
        });
    }

    Ok(entries)
}

/// Pick the next available domain from the pool for a given provider.
async fn acquire_domain(
    pool: &SqlitePool,
    provider: &str,
    redirector_id: &str,
) -> Result<Option<String>, RedirectorError> {
    let row = sqlx::query(
        "SELECT domain FROM domain_pool WHERE provider = ?1 AND status = 'available' LIMIT 1",
    )
    .bind(provider)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        let domain: String = row.get("domain");
        sqlx::query(
            "UPDATE domain_pool SET status = 'active', redirector_id = ?1 WHERE domain = ?2",
        )
        .bind(redirector_id)
        .bind(&domain)
        .execute(pool)
        .await?;

        Ok(Some(domain))
    } else {
        Ok(None)
    }
}

/// Mark a domain as burned.
async fn burn_domain(pool: &SqlitePool, domain: &str) -> Result<(), RedirectorError> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE domain_pool SET status = 'burned', burned_at = ?1 WHERE domain = ?2")
        .bind(now)
        .bind(domain)
        .execute(pool)
        .await?;

    Ok(())
}

/// Release a domain back to available (e.g. on destroy without burn).
pub async fn release_domain(pool: &SqlitePool, domain: &str) -> Result<(), RedirectorError> {
    sqlx::query(
        "UPDATE domain_pool SET status = 'available', redirector_id = NULL WHERE domain = ?1",
    )
    .bind(domain)
    .execute(pool)
    .await?;
    Ok(())
}

// ── Burn and replace ────────────────────────────────────────────────────────

/// Burn a redirector and deploy a replacement using a domain from the pool.
///
/// 1. Mark the redirector as Burning
/// 2. Destroy its Terraform infrastructure
/// 3. Mark it as Burned, mark the domain as burned in the pool
/// 4. Acquire a replacement domain from the pool
/// 5. Deploy a new redirector with the replacement domain
///
/// Returns the new redirector ID, or `None` if no replacement domain was
/// available.
pub async fn burn_and_replace(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    id: &str,
    infra_root: &Path,
) -> Result<Option<String>, RedirectorError> {
    // Load current config
    let row = sqlx::query("SELECT config_yaml, state FROM redirectors WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RedirectorError::NotFound(id.to_string()))?;

    let config_yaml: String = row.get("config_yaml");
    let state_str: String = row.get("state");
    let current_state: RedirectorState = state_str.parse()?;

    let old_config: RedirectorConfig = serde_yaml::from_str(&config_yaml)
        .map_err(|e| RedirectorError::InvalidConfig(e.to_string()))?;

    // Step 1: Transition to Burning (if not already)
    if current_state != RedirectorState::Burning {
        if !current_state.can_transition_to(RedirectorState::Burning) {
            return Err(RedirectorError::InvalidStateTransition {
                from: current_state,
                to: RedirectorState::Burning,
            });
        }
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE redirectors SET state = 'Burning', updated_at = ?1 WHERE id = ?2")
            .bind(now)
            .bind(id)
            .execute(pool)
            .await?;
    }

    event_bus.publish(SpecterEvent::Generic {
        message: format!("Redirector '{id}': burn and replace initiated"),
    });

    // Step 2: Destroy infrastructure
    super::deploy::destroy_terraform(pool, event_bus, id, infra_root).await?;

    // Step 3: Burn the domain in the pool
    burn_domain(pool, &old_config.domain).await?;

    info!("redirector {id} burned domain '{}'", old_config.domain);

    // Step 4: Acquire replacement domain
    let provider_str = old_config.provider.to_string();
    let replacement_domain = acquire_domain(pool, &provider_str, id).await?;

    let new_domain = match replacement_domain {
        Some(d) => d,
        None => {
            warn!(
                "no replacement domain available for provider {}",
                provider_str
            );
            event_bus.publish(SpecterEvent::Generic {
                message: format!(
                    "Redirector '{id}': burned, but no replacement domain available for {provider_str}"
                ),
            });
            return Ok(None);
        }
    };

    // Step 5: Deploy replacement
    let new_id = uuid::Uuid::new_v4().to_string();
    let new_config = RedirectorConfig {
        id: new_id.clone(),
        name: format!("{}-rotated", old_config.name),
        domain: new_domain.clone(),
        ..old_config
    };

    // Insert new redirector in Provisioning
    let now = chrono::Utc::now().timestamp();
    let new_yaml = serde_yaml::to_string(&new_config)
        .map_err(|e| RedirectorError::InvalidConfig(e.to_string()))?;

    sqlx::query(
        "INSERT INTO redirectors (id, name, redirector_type, provider, domain, alternative_domains, tls_cert_mode, backend_url, filtering_rules, health_check_interval, auto_rotate_on_block, state, config_yaml, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'Provisioning', ?12, ?13, ?13)",
    )
    .bind(&new_id)
    .bind(&new_config.name)
    .bind(new_config.redirector_type.to_string())
    .bind(new_config.provider.to_string())
    .bind(&new_config.domain)
    .bind(serde_json::to_string(&new_config.alternative_domains).unwrap_or_default())
    .bind(new_config.tls_cert_mode.to_string())
    .bind(&new_config.backend_url)
    .bind(serde_json::to_string(&new_config.filtering_rules).unwrap_or_default())
    .bind(new_config.health_check_interval as i64)
    .bind(new_config.auto_rotate_on_block)
    .bind(&new_yaml)
    .bind(now)
    .execute(pool)
    .await?;

    // Deploy via Terraform
    match super::deploy::deploy_terraform(pool, event_bus, &new_config, infra_root).await {
        Ok(outputs) => {
            info!(
                "replacement redirector {new_id} deployed on domain {new_domain} with {} outputs",
                outputs.len()
            );
            event_bus.publish(SpecterEvent::Generic {
                message: format!("Redirector '{id}' replaced by '{new_id}' on domain {new_domain}"),
            });
        }
        Err(e) => {
            // Mark replacement as failed but don't lose it
            let now = chrono::Utc::now().timestamp();
            let _ = sqlx::query(
                "UPDATE redirectors SET state = 'Failed', updated_at = ?1 WHERE id = ?2",
            )
            .bind(now)
            .bind(&new_id)
            .execute(pool)
            .await;

            return Err(e);
        }
    }

    Ok(Some(new_id))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_pool_crud() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::db::migrations::run_migrations(&pool).await.unwrap();

        // Add domains
        add_domain(&pool, "redir1.example.com", "CloudFlare")
            .await
            .unwrap();
        add_domain(&pool, "redir2.example.com", "CloudFlare")
            .await
            .unwrap();
        add_domain(&pool, "aws-redir.example.com", "AWS")
            .await
            .unwrap();

        // List
        let domains = list_domains(&pool).await.unwrap();
        assert_eq!(domains.len(), 3);
        assert!(domains.iter().all(|d| d.status == DomainStatus::Available));

        // Acquire
        let acquired = acquire_domain(&pool, "CloudFlare", "r1").await.unwrap();
        assert!(acquired.is_some());
        let acquired_domain = acquired.unwrap();

        let domains = list_domains(&pool).await.unwrap();
        let active = domains
            .iter()
            .find(|d| d.domain == acquired_domain)
            .unwrap();
        assert_eq!(active.status, DomainStatus::Active);
        assert_eq!(active.redirector_id.as_deref(), Some("r1"));

        // Burn
        burn_domain(&pool, &acquired_domain).await.unwrap();
        let domains = list_domains(&pool).await.unwrap();
        let burned = domains
            .iter()
            .find(|d| d.domain == acquired_domain)
            .unwrap();
        assert_eq!(burned.status, DomainStatus::Burned);

        // No more CloudFlare domains available (one burned, one still available)
        let next = acquire_domain(&pool, "CloudFlare", "r2").await.unwrap();
        assert!(next.is_some()); // redir2.example.com still available

        let next = acquire_domain(&pool, "CloudFlare", "r3").await.unwrap();
        assert!(next.is_none()); // no more
    }

    #[tokio::test]
    async fn test_release_domain() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::db::migrations::run_migrations(&pool).await.unwrap();

        add_domain(&pool, "test.example.com", "AWS").await.unwrap();
        let acquired = acquire_domain(&pool, "AWS", "r1").await.unwrap().unwrap();
        assert_eq!(acquired, "test.example.com");

        // Release
        release_domain(&pool, "test.example.com").await.unwrap();

        // Should be available again
        let acquired = acquire_domain(&pool, "AWS", "r2").await.unwrap();
        assert!(acquired.is_some());
    }

    #[test]
    fn test_domain_status_roundtrip() {
        for (s, expected) in [
            ("available", DomainStatus::Available),
            ("active", DomainStatus::Active),
            ("burned", DomainStatus::Burned),
        ] {
            let parsed: DomainStatus = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }

        assert!("invalid".parse::<DomainStatus>().is_err());
    }
}
