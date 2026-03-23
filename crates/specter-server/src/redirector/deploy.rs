use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sqlx::{Row, SqlitePool};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::event::{EventBus, SpecterEvent};

use super::{
    RedirectorConfig, RedirectorError, RedirectorProvider, RedirectorState, RedirectorType,
};

// ── Terraform output parsed from `terraform output -json` ──────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct TerraformOutput {
    value: serde_json::Value,
}

/// Deploys redirector infrastructure via Terraform.
///
/// Generates `.tfvars.json` from `RedirectorConfig`, runs `terraform init` then
/// `apply`, parses outputs, and stores both the parsed outputs and the raw
/// Terraform state blob in the database.
pub async fn deploy_terraform(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    config: &RedirectorConfig,
    infra_root: &Path,
) -> Result<HashMap<String, serde_json::Value>, RedirectorError> {
    let module_dir = resolve_module_dir(infra_root, config)?;

    if !module_dir.exists() {
        return Err(RedirectorError::InvalidConfig(format!(
            "terraform module not found: {}",
            module_dir.display()
        )));
    }

    // Create a working directory for this specific redirector so parallel
    // deploys don't share lock files.
    let work_dir = infra_root.join("workspaces").join(&config.id);
    tokio::fs::create_dir_all(&work_dir).await.map_err(|e| {
        RedirectorError::TerraformError(format!("failed to create workspace dir: {e}"))
    })?;

    // Generate tfvars — canonicalize the path so it works regardless of
    // Terraform's current_dir (which is set to the module directory).
    let vars = build_tfvars(config);
    let vars_path = work_dir.join("terraform.tfvars.json");
    let vars_json = serde_json::to_string_pretty(&vars)
        .map_err(|e| RedirectorError::TerraformError(format!("serialize tfvars: {e}")))?;
    tokio::fs::write(&vars_path, &vars_json)
        .await
        .map_err(|e| RedirectorError::TerraformError(format!("write tfvars: {e}")))?;

    event_bus.publish(SpecterEvent::Generic {
        message: format!("Redirector '{}': running terraform init", config.id),
    });

    // Restore any previously-stored state from the DB so that re-deploys are
    // idempotent and do not orphan cloud resources.
    restore_state_from_db(pool, &config.id, &work_dir).await?;

    // terraform init
    run_terraform(
        &module_dir,
        &work_dir,
        &["init", "-input=false", "-no-color"],
    )
    .await?;

    event_bus.publish(SpecterEvent::Generic {
        message: format!("Redirector '{}': running terraform apply", config.id),
    });

    // terraform apply
    run_terraform(
        &module_dir,
        &work_dir,
        &[
            "apply",
            "-auto-approve",
            "-input=false",
            "-no-color",
            &format!("-var-file={}", vars_path.display()),
        ],
    )
    .await?;

    // Parse outputs
    let outputs = parse_outputs(&module_dir, &work_dir).await?;

    // Persist Terraform state as a blob in the DB
    persist_state_to_db(pool, &config.id, &work_dir).await?;

    // Transition to Active
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET state = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(RedirectorState::Active.to_string())
        .bind(now)
        .bind(&config.id)
        .execute(pool)
        .await?;

    event_bus.publish(SpecterEvent::Generic {
        message: format!(
            "Redirector '{}' ({}) deployed successfully",
            config.name, config.id
        ),
    });

    Ok(outputs)
}

/// Destroy the infrastructure for a redirector via `terraform destroy`.
pub async fn destroy_terraform(
    pool: &SqlitePool,
    event_bus: &Arc<EventBus>,
    id: &str,
    infra_root: &Path,
) -> Result<(), RedirectorError> {
    // Load config from DB
    let row = sqlx::query("SELECT config_yaml FROM redirectors WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RedirectorError::NotFound(id.to_string()))?;

    let config_yaml: String = row.get("config_yaml");
    let config: RedirectorConfig = serde_yaml::from_str(&config_yaml)
        .map_err(|e| RedirectorError::InvalidConfig(e.to_string()))?;

    let module_dir = resolve_module_dir(infra_root, &config)?;
    let work_dir = infra_root.join("workspaces").join(id);

    if !work_dir.exists() {
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| RedirectorError::TerraformError(format!("create workspace dir: {e}")))?;
    }

    // Restore state from DB
    restore_state_from_db(pool, id, &work_dir).await?;

    // Generate vars file so destroy can reference variable declarations
    let vars = build_tfvars(&config);
    let vars_path = work_dir.join("terraform.tfvars.json");
    let vars_json = serde_json::to_string_pretty(&vars)
        .map_err(|e| RedirectorError::TerraformError(format!("serialize tfvars: {e}")))?;
    tokio::fs::write(&vars_path, &vars_json)
        .await
        .map_err(|e| RedirectorError::TerraformError(format!("write tfvars: {e}")))?;

    event_bus.publish(SpecterEvent::Generic {
        message: format!("Redirector '{id}': running terraform destroy"),
    });

    run_terraform(
        &module_dir,
        &work_dir,
        &["init", "-input=false", "-no-color"],
    )
    .await?;

    run_terraform(
        &module_dir,
        &work_dir,
        &[
            "destroy",
            "-auto-approve",
            "-input=false",
            "-no-color",
            &format!("-var-file={}", vars_path.display()),
        ],
    )
    .await?;

    // Clear terraform state in DB and transition to Burned
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "UPDATE redirectors SET state = ?1, terraform_state = NULL, updated_at = ?2 WHERE id = ?3",
    )
    .bind(RedirectorState::Burned.to_string())
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    // Cleanup workspace
    if work_dir.exists() {
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
    }

    event_bus.publish(SpecterEvent::Generic {
        message: format!("Redirector '{id}' infrastructure destroyed"),
    });

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Map a `RedirectorConfig` to the corresponding Terraform module directory.
fn resolve_module_dir(
    infra_root: &Path,
    config: &RedirectorConfig,
) -> Result<PathBuf, RedirectorError> {
    let module_name = match (&config.redirector_type, &config.provider) {
        (RedirectorType::CDN, RedirectorProvider::CloudFlare) => "cloudflare-cdn",
        (RedirectorType::CDN, RedirectorProvider::AWS) => "aws-cloudfront",
        (RedirectorType::CloudFunction, RedirectorProvider::Azure) => "azure-function",
        (RedirectorType::VPS, RedirectorProvider::DigitalOcean)
        | (RedirectorType::VPS, RedirectorProvider::AWS) => "vps-nginx",
        (RedirectorType::VPS, RedirectorProvider::Azure) => "azure-appservice",
        (RedirectorType::DomainFront, RedirectorProvider::CloudFlare) => "cloudflare-cdn",
        (RedirectorType::DomainFront, RedirectorProvider::AWS) => "aws-cloudfront",
        (rt, prov) => {
            return Err(RedirectorError::InvalidConfig(format!(
                "no terraform module for type={rt}, provider={prov}"
            )));
        }
    };

    Ok(infra_root
        .join("terraform")
        .join("modules")
        .join(module_name))
}

/// Build the `.tfvars.json` values from a config.
fn build_tfvars(config: &RedirectorConfig) -> serde_json::Value {
    serde_json::json!({
        "redirector_id": config.id,
        "domain": config.domain,
        "alternative_domains": config.alternative_domains,
        "backend_url": config.backend_url,
        "profile_id": config.filtering_rules.profile_id,
        "decoy_response": config.filtering_rules.decoy_response,
    })
}

/// Execute a terraform command, returning an error if it fails.
async fn run_terraform(
    module_dir: &Path,
    work_dir: &Path,
    args: &[&str],
) -> Result<String, RedirectorError> {
    debug!(
        "terraform {} (module={}, work={})",
        args.first().unwrap_or(&""),
        module_dir.display(),
        work_dir.display()
    );

    let output = Command::new("terraform")
        .args(args)
        .current_dir(module_dir)
        .env("TF_DATA_DIR", work_dir.join(".terraform"))
        .env("TF_STATE", work_dir.join("terraform.tfstate"))
        .output()
        .await
        .map_err(|e| RedirectorError::TerraformError(format!("failed to spawn terraform: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        error!("terraform failed: {stderr}");
        return Err(RedirectorError::TerraformError(format!(
            "terraform {} failed (exit {}): {}",
            args.first().unwrap_or(&""),
            output.status,
            stderr.lines().take(20).collect::<Vec<_>>().join("\n")
        )));
    }

    if !stderr.is_empty() {
        debug!("terraform stderr: {stderr}");
    }

    Ok(stdout)
}

/// Parse `terraform output -json` into a map.
async fn parse_outputs(
    module_dir: &Path,
    work_dir: &Path,
) -> Result<HashMap<String, serde_json::Value>, RedirectorError> {
    let raw = run_terraform(module_dir, work_dir, &["output", "-json", "-no-color"]).await?;

    let outputs: HashMap<String, TerraformOutput> = serde_json::from_str(&raw).unwrap_or_default();

    Ok(outputs.into_iter().map(|(k, v)| (k, v.value)).collect())
}

/// Save the `terraform.tfstate` file from the workspace into the DB blob column.
async fn persist_state_to_db(
    pool: &SqlitePool,
    id: &str,
    work_dir: &Path,
) -> Result<(), RedirectorError> {
    let state_path = work_dir.join("terraform.tfstate");
    if !state_path.exists() {
        warn!("no terraform.tfstate found for {id}, skipping persist");
        return Ok(());
    }

    let state_bytes = tokio::fs::read(&state_path)
        .await
        .map_err(|e| RedirectorError::TerraformError(format!("read tfstate: {e}")))?;

    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE redirectors SET terraform_state = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&state_bytes)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

    info!(
        "persisted terraform state ({} bytes) for {id}",
        state_bytes.len()
    );
    Ok(())
}

/// Restore a previously-persisted `terraform.tfstate` from the DB into the
/// workspace directory so that subsequent `terraform` commands operate on
/// existing infrastructure instead of creating duplicates.
async fn restore_state_from_db(
    pool: &SqlitePool,
    id: &str,
    work_dir: &Path,
) -> Result<(), RedirectorError> {
    let row = sqlx::query("SELECT terraform_state FROM redirectors WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let blob: Option<Vec<u8>> = row.get("terraform_state");
        if let Some(state_bytes) = blob {
            let state_path = work_dir.join("terraform.tfstate");
            tokio::fs::write(&state_path, &state_bytes)
                .await
                .map_err(|e| RedirectorError::TerraformError(format!("write tfstate: {e}")))?;
            debug!(
                "restored terraform state ({} bytes) for {id}",
                state_bytes.len()
            );
        }
    }

    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_module_dir() {
        let root = Path::new("/infra");

        let make_config = |rt: RedirectorType, prov: RedirectorProvider| RedirectorConfig {
            id: "test".into(),
            name: "test".into(),
            redirector_type: rt,
            provider: prov,
            domain: "example.com".into(),
            alternative_domains: vec![],
            tls_cert_mode: super::super::TlsCertMode::Acme,
            backend_url: "https://ts:443".into(),
            filtering_rules: super::super::FilteringRules {
                profile_id: "p1".into(),
                decoy_response: "nope".into(),
            },
            health_check_interval: 60,
            auto_rotate_on_block: false,
            fronting: None,
        };

        assert_eq!(
            resolve_module_dir(
                root,
                &make_config(RedirectorType::CDN, RedirectorProvider::CloudFlare)
            )
            .unwrap(),
            PathBuf::from("/infra/terraform/modules/cloudflare-cdn")
        );
        assert_eq!(
            resolve_module_dir(
                root,
                &make_config(RedirectorType::CDN, RedirectorProvider::AWS)
            )
            .unwrap(),
            PathBuf::from("/infra/terraform/modules/aws-cloudfront")
        );
        assert_eq!(
            resolve_module_dir(
                root,
                &make_config(RedirectorType::CloudFunction, RedirectorProvider::Azure)
            )
            .unwrap(),
            PathBuf::from("/infra/terraform/modules/azure-function")
        );
        assert_eq!(
            resolve_module_dir(
                root,
                &make_config(RedirectorType::VPS, RedirectorProvider::DigitalOcean)
            )
            .unwrap(),
            PathBuf::from("/infra/terraform/modules/vps-nginx")
        );
        assert_eq!(
            resolve_module_dir(
                root,
                &make_config(RedirectorType::VPS, RedirectorProvider::AWS)
            )
            .unwrap(),
            PathBuf::from("/infra/terraform/modules/vps-nginx")
        );
        assert_eq!(
            resolve_module_dir(
                root,
                &make_config(RedirectorType::VPS, RedirectorProvider::Azure)
            )
            .unwrap(),
            PathBuf::from("/infra/terraform/modules/azure-appservice")
        );

        // Invalid combo
        assert!(resolve_module_dir(
            root,
            &make_config(RedirectorType::CDN, RedirectorProvider::GCP)
        )
        .is_err());
    }

    #[test]
    fn test_build_tfvars() {
        let config = RedirectorConfig {
            id: "redir-001".into(),
            name: "cf-cdn".into(),
            redirector_type: RedirectorType::CDN,
            provider: RedirectorProvider::CloudFlare,
            domain: "cdn.example.com".into(),
            alternative_domains: vec!["alt.example.com".into()],
            tls_cert_mode: super::super::TlsCertMode::ProviderManaged,
            backend_url: "https://ts:443".into(),
            filtering_rules: super::super::FilteringRules {
                profile_id: "profile-abc".into(),
                decoy_response: "<html>404</html>".into(),
            },
            health_check_interval: 30,
            auto_rotate_on_block: true,
            fronting: None,
        };

        let vars = build_tfvars(&config);
        assert_eq!(vars["redirector_id"], "redir-001");
        assert_eq!(vars["domain"], "cdn.example.com");
        assert_eq!(vars["backend_url"], "https://ts:443");
        assert_eq!(vars["profile_id"], "profile-abc");
        assert_eq!(vars["alternative_domains"][0], "alt.example.com");
    }

    #[tokio::test]
    async fn test_persist_and_restore_state() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::db::migrations::run_migrations(&pool).await.unwrap();

        // Insert a redirector row
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO redirectors (id, name, redirector_type, provider, domain, backend_url, state, config_yaml, created_at, updated_at)
             VALUES ('r1', 'test', 'CDN', 'AWS', 'example.com', 'https://ts:443', 'Provisioning', 'id: r1', ?1, ?1)",
        )
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().to_path_buf();

        // Write a fake state file and persist it
        let fake_state = b"{\"version\": 4, \"resources\": []}";
        tokio::fs::write(work.join("terraform.tfstate"), fake_state)
            .await
            .unwrap();

        persist_state_to_db(&pool, "r1", &work).await.unwrap();

        // Remove local file
        tokio::fs::remove_file(work.join("terraform.tfstate"))
            .await
            .unwrap();
        assert!(!work.join("terraform.tfstate").exists());

        // Restore
        restore_state_from_db(&pool, "r1", &work).await.unwrap();

        let restored = tokio::fs::read(work.join("terraform.tfstate"))
            .await
            .unwrap();
        assert_eq!(restored, fake_state);
    }
}
