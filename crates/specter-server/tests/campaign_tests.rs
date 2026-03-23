use chrono::Utc;
use specter_server::campaign::{AccessLevel, CampaignManager};
use specter_server::db;

async fn test_pool() -> sqlx::SqlitePool {
    db::init_db(":memory:").await.unwrap()
}

async fn insert_operator(pool: &sqlx::SqlitePool, id: &str, username: &str, role: &str) {
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

async fn insert_session(pool: &sqlx::SqlitePool, id: &str) {
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

// --- Campaign CRUD ---

#[tokio::test]
async fn create_campaign_and_retrieve_by_id() {
    let pool = test_pool().await;
    let mgr = CampaignManager::new(pool);

    let campaign = mgr
        .create_campaign("red-team-op", "Annual pentest", "admin1", "listener-1")
        .await
        .unwrap();

    assert_eq!(campaign.name, "red-team-op");
    assert_eq!(campaign.description, "Annual pentest");
    assert_eq!(campaign.created_by, "admin1");

    let fetched = mgr.get_campaign(&campaign.id).await.unwrap();
    assert_eq!(fetched.name, "red-team-op");
    assert_eq!(fetched.listener_id, "listener-1");
}

#[tokio::test]
async fn duplicate_campaign_name_rejected() {
    let pool = test_pool().await;
    let mgr = CampaignManager::new(pool);

    mgr.create_campaign("dup-name", "", "op1", "")
        .await
        .unwrap();
    let result = mgr
        .create_campaign("dup-name", "different desc", "op1", "")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn list_campaigns_returns_all() {
    let pool = test_pool().await;
    let mgr = CampaignManager::new(pool);

    mgr.create_campaign("c1", "", "op1", "").await.unwrap();
    mgr.create_campaign("c2", "", "op1", "").await.unwrap();
    mgr.create_campaign("c3", "", "op2", "").await.unwrap();

    let all = mgr.list_campaigns().await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn get_nonexistent_campaign_returns_not_found() {
    let pool = test_pool().await;
    let mgr = CampaignManager::new(pool);

    let result = mgr.get_campaign("does-not-exist").await;
    assert!(result.is_err());
}

// --- Campaign membership ---

#[tokio::test]
async fn add_operators_with_access_levels() {
    let pool = test_pool().await;
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
async fn add_and_remove_sessions() {
    let pool = test_pool().await;
    insert_session(&pool, "s1").await;
    insert_session(&pool, "s2").await;

    let mgr = CampaignManager::new(pool);
    let campaign = mgr.create_campaign("c1", "", "op1", "").await.unwrap();

    mgr.add_session(&campaign.id, "s1").await.unwrap();
    mgr.add_session(&campaign.id, "s2").await.unwrap();

    let sessions = mgr.get_campaign_sessions(&campaign.id).await.unwrap();
    assert_eq!(sessions.len(), 2);

    mgr.remove_session(&campaign.id, "s1").await.unwrap();
    let sessions = mgr.get_campaign_sessions(&campaign.id).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert!(sessions.contains(&"s2".to_string()));
}

#[tokio::test]
async fn add_session_to_nonexistent_campaign_fails() {
    let pool = test_pool().await;
    insert_session(&pool, "s1").await;
    let mgr = CampaignManager::new(pool);

    let result = mgr.add_session("no-such-campaign", "s1").await;
    assert!(result.is_err());
}

// --- Session isolation ---

#[tokio::test]
async fn admin_bypasses_session_isolation() {
    let pool = test_pool().await;
    insert_session(&pool, "s1").await;
    insert_session(&pool, "s2").await;

    let mgr = CampaignManager::new(pool);
    // Create a campaign so isolation is active
    mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

    // Admin can access any session regardless of campaign membership
    let access = mgr
        .check_session_access("admin1", "ADMIN", "s1")
        .await
        .unwrap();
    assert_eq!(access, Some(AccessLevel::Full));

    let access = mgr
        .check_session_access("admin1", "ADMIN", "s2")
        .await
        .unwrap();
    assert_eq!(access, Some(AccessLevel::Full));
}

#[tokio::test]
async fn admin_get_accessible_sessions_returns_none_meaning_all() {
    let pool = test_pool().await;
    let mgr = CampaignManager::new(pool);
    mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

    let ids = mgr
        .get_accessible_session_ids("admin1", "ADMIN")
        .await
        .unwrap();
    assert!(ids.is_none(), "None means admin sees all sessions");
}

#[tokio::test]
async fn no_campaigns_means_no_isolation() {
    let pool = test_pool().await;
    insert_session(&pool, "s1").await;

    let mgr = CampaignManager::new(pool);
    // No campaigns exist at all
    let access = mgr
        .check_session_access("op1", "OPERATOR", "s1")
        .await
        .unwrap();
    assert_eq!(access, Some(AccessLevel::Full));

    let ids = mgr
        .get_accessible_session_ids("op1", "OPERATOR")
        .await
        .unwrap();
    assert!(ids.is_none());
}

#[tokio::test]
async fn operator_can_only_access_sessions_in_their_campaigns() {
    let pool = test_pool().await;
    insert_operator(&pool, "op1", "alice", "OPERATOR").await;
    insert_operator(&pool, "op2", "bob", "OPERATOR").await;
    insert_session(&pool, "s1").await;
    insert_session(&pool, "s2").await;
    insert_session(&pool, "s3").await;

    let mgr = CampaignManager::new(pool);
    let c1 = mgr
        .create_campaign("campaign-a", "", "admin1", "")
        .await
        .unwrap();
    let c2 = mgr
        .create_campaign("campaign-b", "", "admin1", "")
        .await
        .unwrap();

    // op1 in campaign-a with s1, s2
    mgr.add_operator(&c1.id, "op1", AccessLevel::Full)
        .await
        .unwrap();
    mgr.add_session(&c1.id, "s1").await.unwrap();
    mgr.add_session(&c1.id, "s2").await.unwrap();

    // op2 in campaign-b with s3
    mgr.add_operator(&c2.id, "op2", AccessLevel::Full)
        .await
        .unwrap();
    mgr.add_session(&c2.id, "s3").await.unwrap();

    // op1 can access s1 and s2, not s3
    assert!(mgr
        .check_session_access("op1", "OPERATOR", "s1")
        .await
        .unwrap()
        .is_some());
    assert!(mgr
        .check_session_access("op1", "OPERATOR", "s2")
        .await
        .unwrap()
        .is_some());
    assert!(mgr
        .check_session_access("op1", "OPERATOR", "s3")
        .await
        .unwrap()
        .is_none());

    // op2 can access s3, not s1
    assert!(mgr
        .check_session_access("op2", "OPERATOR", "s3")
        .await
        .unwrap()
        .is_some());
    assert!(mgr
        .check_session_access("op2", "OPERATOR", "s1")
        .await
        .unwrap()
        .is_none());

    // op1's accessible sessions
    let ids = mgr
        .get_accessible_session_ids("op1", "OPERATOR")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"s1".to_string()));
    assert!(ids.contains(&"s2".to_string()));
}

#[tokio::test]
async fn read_only_access_reported_correctly() {
    let pool = test_pool().await;
    insert_operator(&pool, "op1", "alice", "OPERATOR").await;
    insert_session(&pool, "s1").await;

    let mgr = CampaignManager::new(pool);
    let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

    mgr.add_operator(&campaign.id, "op1", AccessLevel::ReadOnly)
        .await
        .unwrap();
    mgr.add_session(&campaign.id, "s1").await.unwrap();

    let access = mgr
        .check_session_access("op1", "OPERATOR", "s1")
        .await
        .unwrap();
    assert_eq!(access, Some(AccessLevel::ReadOnly));
}

#[tokio::test]
async fn operator_access_level_can_be_updated() {
    let pool = test_pool().await;
    insert_operator(&pool, "op1", "alice", "OPERATOR").await;

    let mgr = CampaignManager::new(pool);
    let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

    mgr.add_operator(&campaign.id, "op1", AccessLevel::ReadOnly)
        .await
        .unwrap();
    mgr.add_operator(&campaign.id, "op1", AccessLevel::Full)
        .await
        .unwrap();

    let ops = mgr.get_campaign_operators(&campaign.id).await.unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].access_level, AccessLevel::Full);
}

#[tokio::test]
async fn remove_operator_revokes_access() {
    let pool = test_pool().await;
    insert_operator(&pool, "op1", "alice", "OPERATOR").await;
    insert_session(&pool, "s1").await;

    let mgr = CampaignManager::new(pool);
    let campaign = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();

    mgr.add_operator(&campaign.id, "op1", AccessLevel::Full)
        .await
        .unwrap();
    mgr.add_session(&campaign.id, "s1").await.unwrap();

    // op1 has access
    assert!(mgr
        .check_session_access("op1", "OPERATOR", "s1")
        .await
        .unwrap()
        .is_some());

    // Remove op1 from campaign
    mgr.remove_operator(&campaign.id, "op1").await.unwrap();

    // op1 no longer has access
    assert!(mgr
        .check_session_access("op1", "OPERATOR", "s1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn find_campaign_by_listener_for_auto_assignment() {
    let pool = test_pool().await;
    let mgr = CampaignManager::new(pool);

    let c = mgr
        .create_campaign("c1", "", "admin1", "listener-abc")
        .await
        .unwrap();

    let found = mgr.find_campaign_by_listener("listener-abc").await.unwrap();
    assert_eq!(found, Some(c.id));

    let not_found = mgr
        .find_campaign_by_listener("no-such-listener")
        .await
        .unwrap();
    assert!(not_found.is_none());
}

#[tokio::test]
async fn multi_campaign_membership_grants_union_access() {
    let pool = test_pool().await;
    insert_operator(&pool, "op1", "alice", "OPERATOR").await;
    insert_session(&pool, "s1").await;
    insert_session(&pool, "s2").await;

    let mgr = CampaignManager::new(pool);
    let c1 = mgr.create_campaign("c1", "", "admin1", "").await.unwrap();
    let c2 = mgr.create_campaign("c2", "", "admin1", "").await.unwrap();

    // op1 in both campaigns, each with a different session
    mgr.add_operator(&c1.id, "op1", AccessLevel::Full)
        .await
        .unwrap();
    mgr.add_session(&c1.id, "s1").await.unwrap();

    mgr.add_operator(&c2.id, "op1", AccessLevel::ReadOnly)
        .await
        .unwrap();
    mgr.add_session(&c2.id, "s2").await.unwrap();

    // op1 can access both sessions
    let ids = mgr
        .get_accessible_session_ids("op1", "OPERATOR")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"s1".to_string()));
    assert!(ids.contains(&"s2".to_string()));
}
