use std::sync::Arc;
use std::time::Duration;

use sqlx::{Row, SqlitePool};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::event::{EventBus, SpecterEvent};

use super::{RedirectorError, RedirectorState};

/// Configuration for the background health-check loop.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Base polling interval — individual redirectors may override via their
    /// own `health_check_interval` field.
    pub default_interval: Duration,
    /// Number of consecutive failures before transitioning Active → Degraded.
    pub failure_threshold: u32,
    /// Number of consecutive failures while Degraded before auto-burning
    /// (only when `auto_rotate_on_block` is enabled on the redirector).
    pub auto_burn_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            default_interval: Duration::from_secs(60),
            failure_threshold: 3,
            auto_burn_threshold: 10,
        }
    }
}

/// Tracks consecutive failure counts per redirector.
struct FailureTracker {
    counts: std::collections::HashMap<String, u32>,
}

impl FailureTracker {
    fn new() -> Self {
        Self {
            counts: std::collections::HashMap::new(),
        }
    }

    fn record_failure(&mut self, id: &str) -> u32 {
        let count = self.counts.entry(id.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    fn reset(&mut self, id: &str) {
        self.counts.remove(id);
    }
}

/// Spawn the background health-check task. Returns a `JoinHandle` that runs
/// until `shutdown_rx` signals.
pub fn spawn_health_monitor(
    pool: SqlitePool,
    event_bus: Arc<EventBus>,
    config: HealthCheckConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let mut tracker = FailureTracker::new();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(config.default_interval) => {}
                _ = shutdown_rx.changed() => {
                    info!("health monitor shutting down");
                    return;
                }
            }

            if let Err(e) = check_all(&pool, &event_bus, &client, &config, &mut tracker).await {
                error!("health check sweep error: {e}");
            }
        }
    })
}

/// Run a single sweep: query all Active/Degraded redirectors and probe each.
async fn check_all(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    client: &reqwest::Client,
    config: &HealthCheckConfig,
    tracker: &mut FailureTracker,
) -> Result<(), RedirectorError> {
    let rows = sqlx::query(
        "SELECT id, domain, state, config_yaml FROM redirectors WHERE state IN ('Active', 'Degraded')",
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let id: String = row.get("id");
        let domain: String = row.get("domain");
        let state_str: String = row.get("state");
        let config_yaml: String = row.get("config_yaml");

        let state: RedirectorState = match state_str.parse() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let redir_config: super::RedirectorConfig = match serde_yaml::from_str(&config_yaml) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let healthy = probe_redirector(client, &domain).await;

        if healthy {
            tracker.reset(&id);
            if state == RedirectorState::Degraded {
                transition(pool, event_bus, &id, RedirectorState::Active).await;
            }
        } else {
            let failures = tracker.record_failure(&id);
            debug!("redirector {id} failure #{failures}");

            match state {
                RedirectorState::Active if failures >= config.failure_threshold => {
                    warn!("redirector {id} degraded after {failures} failures");
                    transition(pool, event_bus, &id, RedirectorState::Degraded).await;
                }
                RedirectorState::Degraded
                    if redir_config.auto_rotate_on_block
                        && failures >= config.auto_burn_threshold =>
                {
                    warn!("redirector {id} auto-burning after {failures} failures");
                    transition(pool, event_bus, &id, RedirectorState::Burning).await;
                    tracker.reset(&id);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Probe a redirector's health by sending an HTTP GET to `https://{domain}/`.
/// A redirector is healthy if we get any HTTP response (even 404 — that's the
/// expected decoy). Connection timeouts / TLS errors count as failures.
async fn probe_redirector(client: &reqwest::Client, domain: &str) -> bool {
    let url = format!("https://{domain}/");
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status();
            debug!("health probe {domain}: HTTP {status}");
            // Any response means the redirector is reachable (even decoy 404).
            true
        }
        Err(e) => {
            debug!("health probe {domain} failed: {e}");
            false
        }
    }
}

/// Best-effort state transition, logs errors but doesn't fail the sweep.
async fn transition(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    id: &str,
    target: RedirectorState,
) {
    let now = chrono::Utc::now().timestamp();
    match sqlx::query("UPDATE redirectors SET state = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(target.to_string())
        .bind(now)
        .bind(id)
        .execute(pool)
        .await
    {
        Ok(_) => {
            event_bus.publish(SpecterEvent::Generic {
                message: format!("Health monitor: redirector {id} → {target}"),
            });
        }
        Err(e) => {
            error!("failed to transition {id} to {target}: {e}");
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_tracker() {
        let mut tracker = FailureTracker::new();

        assert_eq!(tracker.record_failure("r1"), 1);
        assert_eq!(tracker.record_failure("r1"), 2);
        assert_eq!(tracker.record_failure("r1"), 3);
        assert_eq!(tracker.record_failure("r2"), 1);

        tracker.reset("r1");
        assert_eq!(tracker.record_failure("r1"), 1);
    }

    #[test]
    fn test_health_config_defaults() {
        let config = HealthCheckConfig::default();
        assert_eq!(config.default_interval, Duration::from_secs(60));
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.auto_burn_threshold, 10);
    }

    #[tokio::test]
    async fn test_health_check_state_transitions() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::db::migrations::run_migrations(&pool).await.unwrap();

        let event_bus = Arc::new(EventBus::new(64));
        let now = chrono::Utc::now().timestamp();

        // Insert a redirector in Active state
        let config = super::super::RedirectorConfig {
            id: "health-test".into(),
            name: "ht".into(),
            redirector_type: super::super::RedirectorType::VPS,
            provider: super::super::RedirectorProvider::DigitalOcean,
            domain: "test.example.com".into(),
            alternative_domains: vec![],
            tls_cert_mode: super::super::TlsCertMode::Acme,
            backend_url: "https://ts:443".into(),
            filtering_rules: super::super::FilteringRules {
                profile_id: "p1".into(),
                decoy_response: "nope".into(),
            },
            health_check_interval: 60,
            auto_rotate_on_block: true,
            fronting: None,
        };

        let config_yaml = serde_yaml::to_string(&config).unwrap();
        sqlx::query(
            "INSERT INTO redirectors (id, name, redirector_type, provider, domain, backend_url, state, config_yaml, created_at, updated_at)
             VALUES ('health-test', 'ht', 'VPS', 'DigitalOcean', 'test.example.com', 'https://ts:443', 'Active', ?1, ?2, ?2)",
        )
        .bind(&config_yaml)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        // Transition to Degraded
        transition(&pool, &event_bus, "health-test", RedirectorState::Degraded).await;
        let row = sqlx::query("SELECT state FROM redirectors WHERE id = 'health-test'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let state: String = row.get("state");
        assert_eq!(state, "Degraded");

        // Transition back to Active
        transition(&pool, &event_bus, "health-test", RedirectorState::Active).await;
        let row = sqlx::query("SELECT state FROM redirectors WHERE id = 'health-test'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let state: String = row.get("state");
        assert_eq!(state, "Active");
    }
}
