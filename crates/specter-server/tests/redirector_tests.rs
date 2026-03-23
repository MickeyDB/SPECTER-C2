use std::sync::Arc;

use specter_server::db;
use specter_server::event::EventBus;
use specter_server::redirector::{
    DomainFrontingConfig, FilteringRules, RedirectorConfig, RedirectorError,
    RedirectorOrchestrator, RedirectorProvider, RedirectorState, RedirectorType, TlsCertMode,
};

// ── Helpers ────────────────────────────────────────────────────────────────

async fn setup() -> (SqlitePool, Arc<EventBus>, RedirectorOrchestrator) {
    let pool = db::init_db(":memory:").await.unwrap();
    let bus = Arc::new(EventBus::new(64));
    let orch = RedirectorOrchestrator::new(pool.clone(), bus.clone());
    (pool, bus, orch)
}

use sqlx::SqlitePool;

fn sample_config() -> RedirectorConfig {
    RedirectorConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name: "test-redir".into(),
        redirector_type: RedirectorType::CDN,
        provider: RedirectorProvider::CloudFlare,
        domain: "cdn.example.com".into(),
        alternative_domains: vec!["alt1.example.com".into(), "alt2.example.com".into()],
        tls_cert_mode: TlsCertMode::ProviderManaged,
        backend_url: "https://teamserver.internal:443".into(),
        filtering_rules: FilteringRules {
            profile_id: "profile-abc".into(),
            decoy_response: "<html>Not Found</html>".into(),
        },
        health_check_interval: 30,
        auto_rotate_on_block: true,
        fronting: None,
    }
}

// ── Config parsing tests ───────────────────────────────────────────────────

#[test]
fn yaml_roundtrip_preserves_all_fields() {
    let config = sample_config();
    let yaml = serde_yaml::to_string(&config).unwrap();
    let parsed: RedirectorConfig = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(parsed.id, config.id);
    assert_eq!(parsed.name, config.name);
    assert_eq!(parsed.redirector_type, config.redirector_type);
    assert_eq!(parsed.provider, config.provider);
    assert_eq!(parsed.domain, config.domain);
    assert_eq!(parsed.alternative_domains, config.alternative_domains);
    assert_eq!(parsed.tls_cert_mode, config.tls_cert_mode);
    assert_eq!(parsed.backend_url, config.backend_url);
    assert_eq!(
        parsed.filtering_rules.profile_id,
        config.filtering_rules.profile_id
    );
    assert_eq!(
        parsed.filtering_rules.decoy_response,
        config.filtering_rules.decoy_response
    );
    assert_eq!(parsed.health_check_interval, config.health_check_interval);
    assert_eq!(parsed.auto_rotate_on_block, config.auto_rotate_on_block);
    assert!(parsed.fronting.is_none());
}

#[test]
fn yaml_roundtrip_with_domain_fronting() {
    let mut config = sample_config();
    config.redirector_type = RedirectorType::DomainFront;
    config.fronting = Some(DomainFrontingConfig {
        front_domain: "cdn.highrepdomain.com".into(),
        actual_domain: "hidden.c2domain.com".into(),
    });

    let yaml = serde_yaml::to_string(&config).unwrap();
    let parsed: RedirectorConfig = serde_yaml::from_str(&yaml).unwrap();

    let fronting = parsed.fronting.unwrap();
    assert_eq!(fronting.front_domain, "cdn.highrepdomain.com");
    assert_eq!(fronting.actual_domain, "hidden.c2domain.com");
}

#[test]
fn yaml_defaults_health_check_interval_when_missing() {
    let yaml = r#"
id: test-1
name: test
type: VPS
provider: DigitalOcean
domain: redir.example.com
tls_cert_mode: Acme
backend_url: "https://ts:443"
filtering_rules:
  profile_id: p1
  decoy_response: "nope"
"#;
    let parsed: RedirectorConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(parsed.health_check_interval, 60); // default
    assert!(!parsed.auto_rotate_on_block); // default false
    assert!(parsed.alternative_domains.is_empty()); // default empty
}

#[test]
fn json_roundtrip_preserves_all_fields() {
    let config = sample_config();
    let json = serde_json::to_string(&config).unwrap();
    let parsed: RedirectorConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.id, config.id);
    assert_eq!(parsed.redirector_type, config.redirector_type);
    assert_eq!(parsed.provider, config.provider);
}

#[test]
fn all_redirector_type_variants_roundtrip() {
    for (s, expected) in [
        ("CDN", RedirectorType::CDN),
        ("CloudFunction", RedirectorType::CloudFunction),
        ("VPS", RedirectorType::VPS),
        ("DomainFront", RedirectorType::DomainFront),
    ] {
        let parsed: RedirectorType = s.parse().unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_string(), s);
    }
}

#[test]
fn all_provider_variants_roundtrip() {
    for (s, expected) in [
        ("CloudFlare", RedirectorProvider::CloudFlare),
        ("AWS", RedirectorProvider::AWS),
        ("GCP", RedirectorProvider::GCP),
        ("Azure", RedirectorProvider::Azure),
        ("DigitalOcean", RedirectorProvider::DigitalOcean),
    ] {
        let parsed: RedirectorProvider = s.parse().unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_string(), s);
    }
}

#[test]
fn all_tls_cert_mode_variants_roundtrip() {
    for (s, expected) in [
        ("Acme", TlsCertMode::Acme),
        ("ProviderManaged", TlsCertMode::ProviderManaged),
        ("Manual", TlsCertMode::Manual),
    ] {
        let parsed: TlsCertMode = s.parse().unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_string(), s);
    }
}

#[test]
fn invalid_enum_strings_return_errors() {
    assert!("BadType".parse::<RedirectorType>().is_err());
    assert!("BadProvider".parse::<RedirectorProvider>().is_err());
    assert!("BadState".parse::<RedirectorState>().is_err());
    assert!("BadMode".parse::<TlsCertMode>().is_err());
    assert!("".parse::<RedirectorType>().is_err());
}

// ── State machine transition tests ─────────────────────────────────────────

#[test]
fn valid_state_transitions_are_accepted() {
    let valid = [
        (RedirectorState::Provisioning, RedirectorState::Active),
        (RedirectorState::Provisioning, RedirectorState::Failed),
        (RedirectorState::Active, RedirectorState::Degraded),
        (RedirectorState::Active, RedirectorState::Burning),
        (RedirectorState::Degraded, RedirectorState::Active),
        (RedirectorState::Degraded, RedirectorState::Burning),
        (RedirectorState::Degraded, RedirectorState::Failed),
        (RedirectorState::Burning, RedirectorState::Burned),
        (RedirectorState::Burning, RedirectorState::Failed),
    ];

    for (from, to) in valid {
        assert!(from.can_transition_to(to), "{from} -> {to} should be valid");
    }
}

#[test]
fn invalid_state_transitions_are_rejected() {
    let invalid = [
        (RedirectorState::Active, RedirectorState::Provisioning),
        (RedirectorState::Active, RedirectorState::Active),
        (RedirectorState::Burned, RedirectorState::Active),
        (RedirectorState::Burned, RedirectorState::Burning),
        (RedirectorState::Failed, RedirectorState::Active),
        (RedirectorState::Failed, RedirectorState::Provisioning),
        (RedirectorState::Provisioning, RedirectorState::Burning),
        (RedirectorState::Provisioning, RedirectorState::Degraded),
        (RedirectorState::Provisioning, RedirectorState::Burned),
    ];

    for (from, to) in invalid {
        assert!(
            !from.can_transition_to(to),
            "{from} -> {to} should be invalid"
        );
    }
}

#[test]
fn self_transitions_are_rejected() {
    let states = [
        RedirectorState::Provisioning,
        RedirectorState::Active,
        RedirectorState::Degraded,
        RedirectorState::Burning,
        RedirectorState::Burned,
        RedirectorState::Failed,
    ];

    for state in states {
        assert!(
            !state.can_transition_to(state),
            "{state} -> {state} self-transition should be invalid"
        );
    }
}

#[test]
fn terminal_states_cannot_transition() {
    let targets = [
        RedirectorState::Provisioning,
        RedirectorState::Active,
        RedirectorState::Degraded,
        RedirectorState::Burning,
        RedirectorState::Burned,
        RedirectorState::Failed,
    ];

    for target in targets {
        assert!(
            !RedirectorState::Burned.can_transition_to(target),
            "Burned -> {target} should be invalid"
        );
        assert!(
            !RedirectorState::Failed.can_transition_to(target),
            "Failed -> {target} should be invalid"
        );
    }
}

#[test]
fn all_state_variants_roundtrip() {
    for (s, expected) in [
        ("Provisioning", RedirectorState::Provisioning),
        ("Active", RedirectorState::Active),
        ("Degraded", RedirectorState::Degraded),
        ("Burning", RedirectorState::Burning),
        ("Burned", RedirectorState::Burned),
        ("Failed", RedirectorState::Failed),
    ] {
        let parsed: RedirectorState = s.parse().unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_string(), s);
    }
}

// ── Orchestrator integration tests ─────────────────────────────────────────

#[tokio::test]
async fn deploy_creates_redirector_in_provisioning_state() {
    let (_pool, _bus, orch) = setup().await;
    let config = sample_config();

    let id = orch.deploy(&config).await.unwrap();
    assert_eq!(id, config.id);

    let (returned_config, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Provisioning);
    assert_eq!(returned_config.name, config.name);
    assert_eq!(returned_config.domain, config.domain);
}

#[tokio::test]
async fn deploy_multiple_and_list() {
    let (_pool, _bus, orch) = setup().await;

    let mut c1 = sample_config();
    c1.id = "redir-001".into();
    c1.name = "first".into();

    let mut c2 = sample_config();
    c2.id = "redir-002".into();
    c2.name = "second".into();

    orch.deploy(&c1).await.unwrap();
    orch.deploy(&c2).await.unwrap();

    let items = orch.list().await.unwrap();
    assert_eq!(items.len(), 2);
    // All should be Provisioning
    assert!(items
        .iter()
        .all(|(_, s)| *s == RedirectorState::Provisioning));
}

#[tokio::test]
async fn status_returns_not_found_for_unknown_id() {
    let (_pool, _bus, orch) = setup().await;

    let result = orch.status("nonexistent-id").await;
    assert!(matches!(result, Err(RedirectorError::NotFound(_))));
}

#[tokio::test]
async fn health_check_transitions_active_to_degraded() {
    let (pool, bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Manually transition to Active (simulating successful terraform deploy)
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Active', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    // Failed health check -> Degraded
    orch.health_check(&id, false).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Degraded);
}

#[tokio::test]
async fn health_check_transitions_degraded_to_active() {
    let (pool, _bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Set to Active then Degraded
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Degraded', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    // Healthy check -> back to Active
    orch.health_check(&id, true).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Active);
}

#[tokio::test]
async fn health_check_noop_when_already_healthy() {
    let (pool, _bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Set to Active
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Active', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    // Healthy check on Active -> stays Active (noop)
    orch.health_check(&id, true).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Active);
}

#[tokio::test]
async fn burn_transitions_active_to_burning() {
    let (pool, _bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Set to Active
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Active', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    orch.burn(&id).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Burning);
}

#[tokio::test]
async fn burn_from_provisioning_fails() {
    let (_pool, _bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Provisioning -> Burning should fail
    let result = orch.burn(&id).await;
    assert!(matches!(
        result,
        Err(RedirectorError::InvalidStateTransition { .. })
    ));
}

#[tokio::test]
async fn destroy_already_burned_is_noop() {
    let (pool, _bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Set to Burned
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Burned', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    // Destroy on Burned -> noop (Ok)
    orch.destroy(&id).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Burned);
}

#[tokio::test]
async fn full_lifecycle_provisioning_to_burned() {
    let (pool, bus, orch) = setup().await;
    let config = sample_config();
    let id = orch.deploy(&config).await.unwrap();

    // Provisioning -> Active
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Active', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    // Active -> Degraded (health failure)
    orch.health_check(&id, false).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Degraded);

    // Degraded -> Active (recovery)
    orch.health_check(&id, true).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Active);

    // Active -> Burning (burn)
    orch.burn(&id).await.unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Burning);

    // Burning -> Burned (destroy completes)
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = 'Burned', updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    let (_, state) = orch.status(&id).await.unwrap();
    assert_eq!(state, RedirectorState::Burned);
}

// ── Domain rotation tests ──────────────────────────────────────────────────

#[tokio::test]
async fn domain_pool_add_and_list() {
    let (_pool, _bus, orch) = setup().await;

    orch.add_domain_to_pool("d1.example.com", "CloudFlare")
        .await
        .unwrap();
    orch.add_domain_to_pool("d2.example.com", "AWS")
        .await
        .unwrap();
    orch.add_domain_to_pool("d3.example.com", "CloudFlare")
        .await
        .unwrap();

    // Domains were added (verified via direct DB query since list_domains
    // is not exposed through the orchestrator public API)
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM domain_pool")
        .fetch_one(&_pool)
        .await
        .unwrap();
    let count: i64 = sqlx::Row::get(&row, "cnt");
    assert_eq!(count, 3);
}

#[tokio::test]
async fn duplicate_domain_fails() {
    let (_pool, _bus, orch) = setup().await;

    orch.add_domain_to_pool("dup.example.com", "CloudFlare")
        .await
        .unwrap();
    let result = orch
        .add_domain_to_pool("dup.example.com", "CloudFlare")
        .await;
    assert!(result.is_err()); // primary key violation
}
