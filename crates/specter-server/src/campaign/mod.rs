use chrono::Utc;
use sqlx::{Row, SqlitePool};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CampaignError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("campaign not found: {0}")]
    NotFound(String),

    #[error("campaign already exists: {0}")]
    AlreadyExists(String),

    #[error("access denied")]
    AccessDenied,
}

/// Access level for an operator within a campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    Full,
    ReadOnly,
}

impl AccessLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::ReadOnly => "READ_ONLY",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "READ_ONLY" => Self::ReadOnly,
            _ => Self::Full,
        }
    }

    pub fn from_proto(v: i32) -> Self {
        match v {
            1 => Self::ReadOnly,
            _ => Self::Full,
        }
    }

    pub fn to_proto(self) -> i32 {
        match self {
            Self::ReadOnly => 1,
            Self::Full => 2,
        }
    }
}

/// A campaign groups sessions and operators for an engagement.
#[derive(Debug, Clone)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: i64,
    pub created_by: String,
    pub listener_id: String,
}

/// An operator's membership in a campaign.
#[derive(Debug, Clone)]
pub struct CampaignOperatorEntry {
    pub operator_id: String,
    pub username: String,
    pub access_level: AccessLevel,
}

pub struct CampaignManager {
    pool: SqlitePool,
}

impl CampaignManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new campaign.
    pub async fn create_campaign(
        &self,
        name: &str,
        description: &str,
        created_by: &str,
        listener_id: &str,
    ) -> Result<Campaign, CampaignError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO campaigns (id, name, description, created_at, created_by, listener_id) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(description)
        .bind(now)
        .bind(created_by)
        .bind(listener_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.message().contains("UNIQUE") {
                    return CampaignError::AlreadyExists(name.to_string());
                }
            }
            CampaignError::Database(e)
        })?;

        Ok(Campaign {
            id,
            name: name.to_string(),
            description: description.to_string(),
            created_at: now,
            created_by: created_by.to_string(),
            listener_id: listener_id.to_string(),
        })
    }

    /// Get a campaign by ID.
    pub async fn get_campaign(&self, id: &str) -> Result<Campaign, CampaignError> {
        let row = sqlx::query(
            "SELECT id, name, description, created_at, created_by, listener_id \
             FROM campaigns WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| Campaign {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            created_at: r.get("created_at"),
            created_by: r.get("created_by"),
            listener_id: r.get("listener_id"),
        })
        .ok_or_else(|| CampaignError::NotFound(id.to_string()))
    }

    /// List all campaigns.
    pub async fn list_campaigns(&self) -> Result<Vec<Campaign>, CampaignError> {
        let rows = sqlx::query(
            "SELECT id, name, description, created_at, created_by, listener_id FROM campaigns",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| Campaign {
                id: r.get("id"),
                name: r.get("name"),
                description: r.get("description"),
                created_at: r.get("created_at"),
                created_by: r.get("created_by"),
                listener_id: r.get("listener_id"),
            })
            .collect())
    }

    /// Add a session to a campaign.
    pub async fn add_session(
        &self,
        campaign_id: &str,
        session_id: &str,
    ) -> Result<(), CampaignError> {
        // Verify campaign exists
        let _ = self.get_campaign(campaign_id).await?;

        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT OR IGNORE INTO campaign_sessions (campaign_id, session_id, added_at) \
             VALUES (?, ?, ?)",
        )
        .bind(campaign_id)
        .bind(session_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Remove a session from a campaign.
    pub async fn remove_session(
        &self,
        campaign_id: &str,
        session_id: &str,
    ) -> Result<(), CampaignError> {
        sqlx::query("DELETE FROM campaign_sessions WHERE campaign_id = ? AND session_id = ?")
            .bind(campaign_id)
            .bind(session_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Add an operator to a campaign with a given access level.
    pub async fn add_operator(
        &self,
        campaign_id: &str,
        operator_id: &str,
        access_level: AccessLevel,
    ) -> Result<(), CampaignError> {
        // Verify campaign exists
        let _ = self.get_campaign(campaign_id).await?;

        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO campaign_operators (campaign_id, operator_id, access_level, added_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(campaign_id, operator_id) DO UPDATE SET access_level = excluded.access_level",
        )
        .bind(campaign_id)
        .bind(operator_id)
        .bind(access_level.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Remove an operator from a campaign.
    pub async fn remove_operator(
        &self,
        campaign_id: &str,
        operator_id: &str,
    ) -> Result<(), CampaignError> {
        sqlx::query("DELETE FROM campaign_operators WHERE campaign_id = ? AND operator_id = ?")
            .bind(campaign_id)
            .bind(operator_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get session IDs belonging to a campaign.
    pub async fn get_campaign_sessions(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<String>, CampaignError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT session_id FROM campaign_sessions WHERE campaign_id = ?")
                .bind(campaign_id)
                .fetch_all(&self.pool)
                .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Get operators belonging to a campaign.
    pub async fn get_campaign_operators(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<CampaignOperatorEntry>, CampaignError> {
        let rows = sqlx::query(
            "SELECT co.operator_id, COALESCE(o.username, co.operator_id) as username, co.access_level \
             FROM campaign_operators co \
             LEFT JOIN operators o ON o.id = co.operator_id \
             WHERE co.campaign_id = ?",
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| {
                let level_str: String = r.get("access_level");
                CampaignOperatorEntry {
                    operator_id: r.get("operator_id"),
                    username: r.get("username"),
                    access_level: AccessLevel::from_str(&level_str),
                }
            })
            .collect())
    }

    /// Check if an operator has access to a session (via any campaign).
    /// Returns the highest access level if access is granted.
    /// Admin role bypasses all checks.
    pub async fn check_session_access(
        &self,
        operator_id: &str,
        operator_role: &str,
        session_id: &str,
    ) -> Result<Option<AccessLevel>, CampaignError> {
        // Admin bypasses all campaign-based access control
        if operator_role == "ADMIN" {
            return Ok(Some(AccessLevel::Full));
        }

        // Check if there are ANY campaigns at all — if none exist, allow access
        // (backwards-compat: no campaigns means no isolation)
        let campaign_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM campaigns")
            .fetch_one(&self.pool)
            .await?;
        if campaign_count.0 == 0 {
            return Ok(Some(AccessLevel::Full));
        }

        // Check if the session belongs to any campaign the operator is in
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT co.access_level FROM campaign_operators co \
             INNER JOIN campaign_sessions cs ON cs.campaign_id = co.campaign_id \
             WHERE co.operator_id = ? AND cs.session_id = ? \
             ORDER BY CASE co.access_level WHEN 'FULL' THEN 0 ELSE 1 END \
             LIMIT 1",
        )
        .bind(operator_id)
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(level,)| AccessLevel::from_str(&level)))
    }

    /// Get session IDs the operator has access to (via campaigns).
    /// Admin role returns None (meaning all sessions).
    pub async fn get_accessible_session_ids(
        &self,
        operator_id: &str,
        operator_role: &str,
    ) -> Result<Option<Vec<String>>, CampaignError> {
        // Admin sees everything
        if operator_role == "ADMIN" {
            return Ok(None);
        }

        // No campaigns means no isolation
        let campaign_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM campaigns")
            .fetch_one(&self.pool)
            .await?;
        if campaign_count.0 == 0 {
            return Ok(None);
        }

        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT cs.session_id FROM campaign_sessions cs \
             INNER JOIN campaign_operators co ON co.campaign_id = cs.campaign_id \
             WHERE co.operator_id = ?",
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(Some(rows.into_iter().map(|(id,)| id).collect()))
    }

    /// Find the campaign associated with a listener (for auto-assigning sessions).
    pub async fn find_campaign_by_listener(
        &self,
        listener_id: &str,
    ) -> Result<Option<String>, CampaignError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM campaigns WHERE listener_id = ? LIMIT 1")
                .bind(listener_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|(id,)| id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        crate::db::migrations::run_migrations(&pool).await.unwrap();
        pool
    }

    async fn insert_operator(pool: &SqlitePool, id: &str, username: &str, role: &str) {
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO operators (id, username, password_hash, role, created_at) VALUES (?, ?, 'hash', ?, ?)",
        )
        .bind(id)
        .bind(username)
        .bind(role)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_session(pool: &SqlitePool, id: &str) {
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO sessions (id, hostname, username, pid, last_checkin, first_seen) \
             VALUES (?, 'host', 'user', 1234, ?, ?)",
        )
        .bind(id)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_campaign() {
        let pool = setup_test_db().await;
        let mgr = CampaignManager::new(pool);

        let campaign = mgr
            .create_campaign("test-engagement", "A test campaign", "op1", "listener-1")
            .await
            .unwrap();

        assert_eq!(campaign.name, "test-engagement");
        assert_eq!(campaign.description, "A test campaign");
        assert_eq!(campaign.created_by, "op1");
        assert_eq!(campaign.listener_id, "listener-1");
        assert!(!campaign.id.is_empty());
    }

    #[tokio::test]
    async fn test_create_duplicate_campaign_fails() {
        let pool = setup_test_db().await;
        let mgr = CampaignManager::new(pool);

        mgr.create_campaign("dup", "desc", "op1", "").await.unwrap();
        let result = mgr.create_campaign("dup", "desc2", "op1", "").await;
        assert!(matches!(result, Err(CampaignError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_get_and_list_campaigns() {
        let pool = setup_test_db().await;
        let mgr = CampaignManager::new(pool);

        let c1 = mgr.create_campaign("c1", "", "op1", "").await.unwrap();
        let _c2 = mgr.create_campaign("c2", "", "op1", "").await.unwrap();

        let fetched = mgr.get_campaign(&c1.id).await.unwrap();
        assert_eq!(fetched.name, "c1");

        let all = mgr.list_campaigns().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_get_nonexistent_campaign() {
        let pool = setup_test_db().await;
        let mgr = CampaignManager::new(pool);

        let result = mgr.get_campaign("nonexistent").await;
        assert!(matches!(result, Err(CampaignError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_add_and_list_sessions() {
        let pool = setup_test_db().await;
        insert_session(&pool, "sess-1").await;
        insert_session(&pool, "sess-2").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "op1", "").await.unwrap();

        mgr.add_session(&campaign.id, "sess-1").await.unwrap();
        mgr.add_session(&campaign.id, "sess-2").await.unwrap();

        let sessions = mgr.get_campaign_sessions(&campaign.id).await.unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&"sess-1".to_string()));
        assert!(sessions.contains(&"sess-2".to_string()));
    }

    #[tokio::test]
    async fn test_remove_session() {
        let pool = setup_test_db().await;
        insert_session(&pool, "sess-1").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "op1", "").await.unwrap();

        mgr.add_session(&campaign.id, "sess-1").await.unwrap();
        mgr.remove_session(&campaign.id, "sess-1").await.unwrap();

        let sessions = mgr.get_campaign_sessions(&campaign.id).await.unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_list_operators() {
        let pool = setup_test_db().await;
        insert_operator(&pool, "op1", "alice", "OPERATOR").await;
        insert_operator(&pool, "op2", "bob", "OPERATOR").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        mgr.add_operator(&campaign.id, "op1", AccessLevel::Full)
            .await
            .unwrap();
        mgr.add_operator(&campaign.id, "op2", AccessLevel::ReadOnly)
            .await
            .unwrap();

        let operators = mgr.get_campaign_operators(&campaign.id).await.unwrap();
        assert_eq!(operators.len(), 2);

        let alice = operators.iter().find(|o| o.operator_id == "op1").unwrap();
        assert_eq!(alice.access_level, AccessLevel::Full);
        assert_eq!(alice.username, "alice");

        let bob = operators.iter().find(|o| o.operator_id == "op2").unwrap();
        assert_eq!(bob.access_level, AccessLevel::ReadOnly);
    }

    #[tokio::test]
    async fn test_remove_operator() {
        let pool = setup_test_db().await;
        insert_operator(&pool, "op1", "alice", "OPERATOR").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        mgr.add_operator(&campaign.id, "op1", AccessLevel::Full)
            .await
            .unwrap();
        mgr.remove_operator(&campaign.id, "op1").await.unwrap();

        let operators = mgr.get_campaign_operators(&campaign.id).await.unwrap();
        assert!(operators.is_empty());
    }

    #[tokio::test]
    async fn test_session_access_admin_bypasses() {
        let pool = setup_test_db().await;
        insert_session(&pool, "sess-1").await;

        let mgr = CampaignManager::new(pool);
        // Create a campaign so isolation is active
        mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        let access = mgr
            .check_session_access("admin1", "ADMIN", "sess-1")
            .await
            .unwrap();
        assert_eq!(access, Some(AccessLevel::Full));
    }

    #[tokio::test]
    async fn test_session_access_no_campaigns_allows_all() {
        let pool = setup_test_db().await;
        insert_session(&pool, "sess-1").await;

        let mgr = CampaignManager::new(pool);
        // No campaigns exist → no isolation
        let access = mgr
            .check_session_access("op1", "OPERATOR", "sess-1")
            .await
            .unwrap();
        assert_eq!(access, Some(AccessLevel::Full));
    }

    #[tokio::test]
    async fn test_session_isolation_denies_unassigned() {
        let pool = setup_test_db().await;
        insert_operator(&pool, "op1", "alice", "OPERATOR").await;
        insert_operator(&pool, "op2", "bob", "OPERATOR").await;
        insert_session(&pool, "sess-1").await;
        insert_session(&pool, "sess-2").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        // Add op1 and sess-1 to campaign
        mgr.add_operator(&campaign.id, "op1", AccessLevel::Full)
            .await
            .unwrap();
        mgr.add_session(&campaign.id, "sess-1").await.unwrap();

        // op1 can access sess-1
        let access = mgr
            .check_session_access("op1", "OPERATOR", "sess-1")
            .await
            .unwrap();
        assert_eq!(access, Some(AccessLevel::Full));

        // op1 cannot access sess-2 (not in any campaign op1 is in)
        let access = mgr
            .check_session_access("op1", "OPERATOR", "sess-2")
            .await
            .unwrap();
        assert!(access.is_none());

        // op2 cannot access sess-1 (op2 not in campaign)
        let access = mgr
            .check_session_access("op2", "OPERATOR", "sess-1")
            .await
            .unwrap();
        assert!(access.is_none());
    }

    #[tokio::test]
    async fn test_get_accessible_session_ids() {
        let pool = setup_test_db().await;
        insert_operator(&pool, "op1", "alice", "OPERATOR").await;
        insert_session(&pool, "sess-1").await;
        insert_session(&pool, "sess-2").await;
        insert_session(&pool, "sess-3").await;

        let mgr = CampaignManager::new(pool);
        let c1 = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        mgr.add_operator(&c1.id, "op1", AccessLevel::Full)
            .await
            .unwrap();
        mgr.add_session(&c1.id, "sess-1").await.unwrap();
        mgr.add_session(&c1.id, "sess-2").await.unwrap();

        // Admin gets None (all sessions)
        let ids = mgr
            .get_accessible_session_ids("admin1", "ADMIN")
            .await
            .unwrap();
        assert!(ids.is_none());

        // op1 gets only sess-1 and sess-2
        let ids = mgr
            .get_accessible_session_ids("op1", "OPERATOR")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"sess-1".to_string()));
        assert!(ids.contains(&"sess-2".to_string()));
    }

    #[tokio::test]
    async fn test_find_campaign_by_listener() {
        let pool = setup_test_db().await;
        let mgr = CampaignManager::new(pool);

        let c = mgr
            .create_campaign("c1", "", "admin1", "listener-abc")
            .await
            .unwrap();

        let found = mgr.find_campaign_by_listener("listener-abc").await.unwrap();
        assert_eq!(found, Some(c.id));

        let not_found = mgr.find_campaign_by_listener("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_add_session_to_nonexistent_campaign_fails() {
        let pool = setup_test_db().await;
        insert_session(&pool, "sess-1").await;
        let mgr = CampaignManager::new(pool);

        let result = mgr.add_session("nonexistent", "sess-1").await;
        assert!(matches!(result, Err(CampaignError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_operator_access_level() {
        let pool = setup_test_db().await;
        insert_operator(&pool, "op1", "alice", "OPERATOR").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        mgr.add_operator(&campaign.id, "op1", AccessLevel::ReadOnly)
            .await
            .unwrap();

        // Update to Full
        mgr.add_operator(&campaign.id, "op1", AccessLevel::Full)
            .await
            .unwrap();

        let operators = mgr.get_campaign_operators(&campaign.id).await.unwrap();
        assert_eq!(operators[0].access_level, AccessLevel::Full);
    }

    #[tokio::test]
    async fn test_read_only_access() {
        let pool = setup_test_db().await;
        insert_operator(&pool, "op1", "alice", "OPERATOR").await;
        insert_session(&pool, "sess-1").await;

        let mgr = CampaignManager::new(pool);
        let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

        mgr.add_operator(&campaign.id, "op1", AccessLevel::ReadOnly)
            .await
            .unwrap();
        mgr.add_session(&campaign.id, "sess-1").await.unwrap();

        let access = mgr
            .check_session_access("op1", "OPERATOR", "sess-1")
            .await
            .unwrap();
        assert_eq!(access, Some(AccessLevel::ReadOnly));
    }
}
