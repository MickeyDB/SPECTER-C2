pub mod ca;
pub mod interceptor;
pub mod mtls;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use prost_types::Timestamp;
use rand::Rng;
use sqlx::{Row, SqlitePool};
use thiserror::Error;

use specter_common::proto::specter::v1::{Operator, OperatorRole};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Password hash error: {0}")]
    PasswordHash(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Permission denied")]
    #[allow(dead_code)]
    PermissionDenied,
}

/// Operator context injected into gRPC request extensions by the auth interceptor.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct OperatorContext {
    pub operator_id: String,
    pub username: String,
    pub role: String,
}

impl OperatorContext {
    pub fn dev_admin() -> Self {
        Self {
            operator_id: "dev-admin".to_string(),
            username: "admin".to_string(),
            role: "ADMIN".to_string(),
        }
    }
}

/// In-memory token info for fast lookup.
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub operator_id: String,
    pub username: String,
    pub role: String,
}

pub struct AuthService {
    pool: SqlitePool,
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
}

impl AuthService {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the shared token store for use by the auth interceptor.
    pub fn token_store(&self) -> Arc<RwLock<HashMap<String, TokenInfo>>> {
        Arc::clone(&self.tokens)
    }

    /// Hash a password with Argon2.
    pub fn hash_password(password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(e.to_string()))?;
        Ok(hash.to_string())
    }

    /// Verify a password against an Argon2 hash.
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| AuthError::PasswordHash(e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Generate a random 32-byte hex API token.
    pub fn generate_api_token() -> String {
        let bytes: [u8; 32] = rand::thread_rng().gen();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Create a new operator in the database.
    pub async fn create_operator(
        &self,
        username: &str,
        password: &str,
        role: &str,
    ) -> Result<Operator, AuthError> {
        let id = uuid::Uuid::new_v4().to_string();
        let password_hash = Self::hash_password(password)?;
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO operators (id, username, password_hash, role, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(username)
        .bind(&password_hash)
        .bind(role)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(Operator {
            id,
            username: username.to_string(),
            role: str_to_role(role),
            created_at: Some(Timestamp {
                seconds: now,
                nanos: 0,
            }),
            last_login: None,
        })
    }

    /// Authenticate an operator with username and password.
    /// Returns the operator info and a new API token on success.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(Operator, String), AuthError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role, created_at, last_login \
             FROM operators WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        let row = row.ok_or(AuthError::InvalidCredentials)?;

        let password_hash: String = row.get("password_hash");
        if !Self::verify_password(password, &password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        let id: String = row.get("id");
        let role: String = row.get("role");
        let created_at: i64 = row.get("created_at");

        // Update last_login
        let now = Utc::now().timestamp();
        sqlx::query("UPDATE operators SET last_login = ? WHERE id = ?")
            .bind(now)
            .bind(&id)
            .execute(&self.pool)
            .await?;

        // Generate and store session token
        let token = Self::generate_api_token();
        {
            let mut tokens = self
                .tokens
                .write()
                .map_err(|_| AuthError::PasswordHash("Token store lock poisoned".to_string()))?;
            tokens.insert(
                token.clone(),
                TokenInfo {
                    operator_id: id.clone(),
                    username: username.to_string(),
                    role: role.clone(),
                },
            );
        }

        let operator = Operator {
            id,
            username: username.to_string(),
            role: str_to_role(&role),
            created_at: Some(Timestamp {
                seconds: created_at,
                nanos: 0,
            }),
            last_login: Some(Timestamp {
                seconds: now,
                nanos: 0,
            }),
        };

        Ok((operator, token))
    }

    /// Validate an API token and return the associated operator context.
    #[allow(dead_code)]
    pub fn validate_token(&self, token: &str) -> Option<OperatorContext> {
        let tokens = self.tokens.read().ok()?;
        tokens.get(token).map(|info| OperatorContext {
            operator_id: info.operator_id.clone(),
            username: info.username.clone(),
            role: info.role.clone(),
        })
    }

    /// List all operators (without password hashes).
    pub async fn list_operators(&self) -> Result<Vec<Operator>, AuthError> {
        let rows = sqlx::query("SELECT id, username, role, created_at, last_login FROM operators")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .iter()
            .map(|row| {
                let created_at: i64 = row.get("created_at");
                let last_login: Option<i64> = row.get("last_login");
                Operator {
                    id: row.get("id"),
                    username: row.get("username"),
                    role: str_to_role(row.get("role")),
                    created_at: Some(Timestamp {
                        seconds: created_at,
                        nanos: 0,
                    }),
                    last_login: last_login.map(|t| Timestamp {
                        seconds: t,
                        nanos: 0,
                    }),
                }
            })
            .collect())
    }

    /// Check if an operator with a given role has permission to perform an action.
    ///
    /// RBAC rules:
    /// - ADMIN: all actions
    /// - OPERATOR: everything except managing operators
    /// - OBSERVER: read-only (list/get) and event subscription only
    pub fn check_permission(role: &str, action: &str) -> bool {
        match role {
            "ADMIN" => true,
            "OPERATOR" => action != "manage_operators",
            "OBSERVER" => {
                action.starts_with("list_")
                    || action.starts_with("get_")
                    || action == "subscribe_events"
            }
            _ => false,
        }
    }

    /// Check if the operators table is empty (for first-run setup).
    pub async fn is_first_run(&self) -> Result<bool, AuthError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM operators")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0 == 0)
    }
}

fn str_to_role(s: &str) -> i32 {
    match s {
        "ADMIN" => OperatorRole::Admin.into(),
        "OPERATOR" => OperatorRole::Operator.into(),
        "OBSERVER" => OperatorRole::Observer.into(),
        _ => OperatorRole::Unspecified.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn test_pool() -> SqlitePool {
        db::init_db(":memory:").await.unwrap()
    }

    #[test]
    fn test_hash_and_verify_password() {
        let password = "s3cret!";
        let hash = AuthService::hash_password(password).unwrap();
        assert!(AuthService::verify_password(password, &hash).unwrap());
        assert!(!AuthService::verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_generate_api_token_length_and_uniqueness() {
        let t1 = AuthService::generate_api_token();
        let t2 = AuthService::generate_api_token();
        assert_eq!(t1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(t1, t2);
    }

    #[tokio::test]
    async fn test_create_operator_and_authenticate() {
        let pool = test_pool().await;
        let svc = AuthService::new(pool);

        let op = svc
            .create_operator("alice", "password123", "ADMIN")
            .await
            .unwrap();
        assert_eq!(op.username, "alice");
        assert_eq!(op.role, i32::from(OperatorRole::Admin));

        let (authed_op, token) = svc.authenticate("alice", "password123").await.unwrap();
        assert_eq!(authed_op.username, "alice");
        assert!(!token.is_empty());

        // Token should be valid
        let ctx = svc.validate_token(&token).unwrap();
        assert_eq!(ctx.username, "alice");
        assert_eq!(ctx.role, "ADMIN");
    }

    #[tokio::test]
    async fn test_authenticate_invalid_credentials() {
        let pool = test_pool().await;
        let svc = AuthService::new(pool);
        svc.create_operator("bob", "goodpass", "OPERATOR")
            .await
            .unwrap();

        // Wrong password
        let err = svc.authenticate("bob", "badpass").await;
        assert!(err.is_err());

        // Non-existent user
        let err = svc.authenticate("nobody", "pass").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_invalid() {
        let pool = test_pool().await;
        let svc = AuthService::new(pool);
        assert!(svc.validate_token("nonexistent-token").is_none());
    }

    #[tokio::test]
    async fn test_is_first_run() {
        let pool = test_pool().await;
        let svc = AuthService::new(pool);

        assert!(svc.is_first_run().await.unwrap());
        svc.create_operator("admin", "pass", "ADMIN").await.unwrap();
        assert!(!svc.is_first_run().await.unwrap());
    }

    #[tokio::test]
    async fn test_list_operators() {
        let pool = test_pool().await;
        let svc = AuthService::new(pool);

        assert!(svc.list_operators().await.unwrap().is_empty());

        svc.create_operator("admin", "pass", "ADMIN").await.unwrap();
        svc.create_operator("viewer", "pass", "OBSERVER")
            .await
            .unwrap();

        let ops = svc.list_operators().await.unwrap();
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_rbac_admin_can_do_everything() {
        assert!(AuthService::check_permission("ADMIN", "list_sessions"));
        assert!(AuthService::check_permission("ADMIN", "queue_task"));
        assert!(AuthService::check_permission("ADMIN", "create_listener"));
        assert!(AuthService::check_permission("ADMIN", "manage_operators"));
        assert!(AuthService::check_permission("ADMIN", "subscribe_events"));
    }

    #[test]
    fn test_rbac_operator_cannot_manage_operators() {
        assert!(AuthService::check_permission("OPERATOR", "list_sessions"));
        assert!(AuthService::check_permission("OPERATOR", "queue_task"));
        assert!(AuthService::check_permission("OPERATOR", "create_listener"));
        assert!(AuthService::check_permission(
            "OPERATOR",
            "subscribe_events"
        ));
        assert!(AuthService::check_permission("OPERATOR", "list_operators"));
        assert!(!AuthService::check_permission(
            "OPERATOR",
            "manage_operators"
        ));
    }

    #[test]
    fn test_rbac_observer_read_only() {
        assert!(AuthService::check_permission("OBSERVER", "list_sessions"));
        assert!(AuthService::check_permission("OBSERVER", "get_session"));
        assert!(AuthService::check_permission("OBSERVER", "list_operators"));
        assert!(AuthService::check_permission(
            "OBSERVER",
            "subscribe_events"
        ));
        assert!(!AuthService::check_permission("OBSERVER", "queue_task"));
        assert!(!AuthService::check_permission(
            "OBSERVER",
            "create_listener"
        ));
        assert!(!AuthService::check_permission("OBSERVER", "start_listener"));
        assert!(!AuthService::check_permission("OBSERVER", "stop_listener"));
        assert!(!AuthService::check_permission(
            "OBSERVER",
            "manage_operators"
        ));
    }

    #[test]
    fn test_rbac_unknown_role_denied() {
        assert!(!AuthService::check_permission("UNKNOWN", "list_sessions"));
        assert!(!AuthService::check_permission("", "list_sessions"));
    }
}
