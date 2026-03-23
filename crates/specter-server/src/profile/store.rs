use chrono::Utc;
use sqlx::{Row, SqlitePool};

use super::compiler::compile_profile;
use super::parser::{parse_profile, validate_profile, ProfileError};

/// Stored profile record from the database.
#[derive(Debug, Clone)]
pub struct StoredProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub yaml_content: String,
    pub compiled_blob: Option<Vec<u8>>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Profile storage backed by SQLite.
pub struct ProfileStore {
    pool: SqlitePool,
}

impl ProfileStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new profile. Validates and compiles the YAML before storing.
    pub async fn create_profile(
        &self,
        name: &str,
        description: &str,
        yaml_content: &str,
    ) -> Result<StoredProfile, ProfileError> {
        // Parse and validate
        let profile = parse_profile(yaml_content)?;
        let _warnings = validate_profile(&profile)?;

        // Compile to binary blob
        let compiled = compile_profile(&profile)?;

        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO profiles (id, name, description, yaml_content, compiled_blob, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(description)
        .bind(yaml_content)
        .bind(&compiled)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| ProfileError::Validation(format!("database error: {e}")))?;

        Ok(StoredProfile {
            id,
            name: name.to_string(),
            description: description.to_string(),
            yaml_content: yaml_content.to_string(),
            compiled_blob: Some(compiled),
            created_at: now,
            updated_at: now,
        })
    }

    /// List all profiles.
    pub async fn list_profiles(&self) -> Result<Vec<StoredProfile>, ProfileError> {
        let rows = sqlx::query(
            "SELECT id, name, description, yaml_content, compiled_blob, created_at, updated_at FROM profiles",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ProfileError::Validation(format!("database error: {e}")))?;

        Ok(rows
            .iter()
            .map(|row| StoredProfile {
                id: row.get("id"),
                name: row.get("name"),
                description: row.get("description"),
                yaml_content: row.get("yaml_content"),
                compiled_blob: row.get("compiled_blob"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect())
    }

    /// Get a profile by ID.
    pub async fn get_profile(&self, id: &str) -> Result<Option<StoredProfile>, ProfileError> {
        let row = sqlx::query(
            "SELECT id, name, description, yaml_content, compiled_blob, created_at, updated_at \
             FROM profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ProfileError::Validation(format!("database error: {e}")))?;

        Ok(row.map(|r| StoredProfile {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            yaml_content: r.get("yaml_content"),
            compiled_blob: r.get("compiled_blob"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    /// Get a profile by name.
    pub async fn get_profile_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredProfile>, ProfileError> {
        let row = sqlx::query(
            "SELECT id, name, description, yaml_content, compiled_blob, created_at, updated_at \
             FROM profiles WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ProfileError::Validation(format!("database error: {e}")))?;

        Ok(row.map(|r| StoredProfile {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            yaml_content: r.get("yaml_content"),
            compiled_blob: r.get("compiled_blob"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    /// Compile a profile by ID and return the binary blob.
    /// Re-parses and re-compiles from stored YAML.
    pub async fn compile_profile_by_id(&self, id: &str) -> Result<Vec<u8>, ProfileError> {
        let stored = self
            .get_profile(id)
            .await?
            .ok_or_else(|| ProfileError::Validation(format!("profile not found: {id}")))?;

        let profile = parse_profile(&stored.yaml_content)?;
        let blob = compile_profile(&profile)?;

        // Update the stored compiled blob
        let now = Utc::now().timestamp();
        let _ = sqlx::query("UPDATE profiles SET compiled_blob = ?, updated_at = ? WHERE id = ?")
            .bind(&blob)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await;

        Ok(blob)
    }
}
