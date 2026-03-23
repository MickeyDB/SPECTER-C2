use std::sync::Arc;

use specter_common::proto::specter::v1::SessionStatus;
use specter_server::db;
use specter_server::event::EventBus;
use specter_server::session::SessionManager;
use sqlx::SqlitePool;

async fn setup() -> (SqlitePool, Arc<EventBus>, Arc<SessionManager>) {
    let pool = db::init_db(":memory:").await.unwrap();
    let bus = Arc::new(EventBus::new(64));
    let mgr = Arc::new(SessionManager::new(pool.clone(), bus.clone()));
    (pool, bus, mgr)
}

async fn register_test_session(mgr: &SessionManager) -> String {
    mgr.register_session(
        "WORKSTATION".into(),
        "admin".into(),
        1234,
        "Windows 11".into(),
        "High".into(),
        "explorer.exe".into(),
        "192.168.1.10".into(),
        "1.2.3.4".into(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn register_session_creates_new_session_with_valid_id() {
    let (_pool, _bus, mgr) = setup().await;
    let id = register_test_session(&mgr).await;

    assert!(!id.is_empty());
    // UUID v4 format
    assert_eq!(id.len(), 36);

    let session = mgr.get_session(&id).await.unwrap().unwrap();
    assert_eq!(session.hostname, "WORKSTATION");
    assert_eq!(session.username, "admin");
    assert_eq!(session.pid, 1234);
    assert_eq!(session.os_version, "Windows 11");
    assert_eq!(session.status, i32::from(SessionStatus::New));
}

#[tokio::test]
async fn update_checkin_updates_last_checkin_timestamp() {
    let (_pool, _bus, mgr) = setup().await;
    let id = register_test_session(&mgr).await;

    let before = mgr.get_session(&id).await.unwrap().unwrap();
    let before_ts = before.last_checkin.unwrap().seconds;

    // Small delay to ensure timestamp changes
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    mgr.update_checkin(&id).await.unwrap();

    let after = mgr.get_session(&id).await.unwrap().unwrap();
    let after_ts = after.last_checkin.unwrap().seconds;

    assert!(after_ts >= before_ts);
    assert_eq!(after.status, i32::from(SessionStatus::Active));
}

#[tokio::test]
async fn list_sessions_returns_all_registered_sessions() {
    let (_pool, _bus, mgr) = setup().await;

    assert!(mgr.list_sessions().await.unwrap().is_empty());

    register_test_session(&mgr).await;
    mgr.register_session(
        "SERVER01".into(),
        "svc_account".into(),
        5678,
        "Windows Server 2022".into(),
        "System".into(),
        "svchost.exe".into(),
        "10.0.0.5".into(),
        "5.6.7.8".into(),
    )
    .await
    .unwrap();

    let sessions = mgr.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn session_status_transitions_based_on_elapsed_time() {
    let (pool, _bus, mgr) = setup().await;
    let id = register_test_session(&mgr).await;

    // Set last_checkin far in the past to trigger STALE (interval=10, stale threshold = 10*3=30s)
    let now = chrono::Utc::now().timestamp();
    let stale_time = now - 50; // 50s ago, with interval=10: 50 > 30 (3*10) but < 100 (10*10)
    sqlx::query("UPDATE sessions SET last_checkin = ?, status = 'ACTIVE' WHERE id = ?")
        .bind(stale_time)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    mgr.update_statuses(10).await.unwrap();
    let session = mgr.get_session(&id).await.unwrap().unwrap();
    assert_eq!(session.status, i32::from(SessionStatus::Stale));

    // Set last_checkin very far in the past to trigger DEAD (>= interval*10 = 100s)
    let dead_time = now - 200;
    sqlx::query("UPDATE sessions SET last_checkin = ?, status = 'STALE' WHERE id = ?")
        .bind(dead_time)
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();

    mgr.update_statuses(10).await.unwrap();
    let session = mgr.get_session(&id).await.unwrap().unwrap();
    assert_eq!(session.status, i32::from(SessionStatus::Dead));
}

#[tokio::test]
async fn get_session_returns_correct_data_for_existing_id() {
    let (_pool, _bus, mgr) = setup().await;
    let id = register_test_session(&mgr).await;

    let session = mgr.get_session(&id).await.unwrap();
    assert!(session.is_some());
    let session = session.unwrap();
    assert_eq!(session.id, id);
    assert_eq!(session.hostname, "WORKSTATION");
    assert_eq!(session.internal_ip, "192.168.1.10");
}

#[tokio::test]
async fn get_session_returns_none_for_nonexistent_id() {
    let (_pool, _bus, mgr) = setup().await;
    let session = mgr.get_session("nonexistent-id").await.unwrap();
    assert!(session.is_none());
}

#[tokio::test]
async fn remove_session_soft_deletes() {
    let (_pool, _bus, mgr) = setup().await;
    let id = register_test_session(&mgr).await;

    assert!(mgr.get_session(&id).await.unwrap().is_some());

    mgr.remove_session(&id).await.unwrap();

    // Soft deleted: not visible
    assert!(mgr.get_session(&id).await.unwrap().is_none());
    assert!(mgr.list_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn register_or_update_finds_existing_session() {
    let (_pool, _bus, mgr) = setup().await;
    let id1 = mgr
        .register_or_update(
            "HOST1", "user1", 100, "Win11", "High", "cmd.exe", "10.0.0.1", "1.1.1.1",
        )
        .await
        .unwrap();

    let id2 = mgr
        .register_or_update(
            "HOST1", "user1", 100, "Win11", "High", "cmd.exe", "10.0.0.1", "1.1.1.1",
        )
        .await
        .unwrap();

    assert_eq!(id1, id2, "Same host/user/pid should return same session");

    let id3 = mgr
        .register_or_update(
            "HOST2", "user1", 100, "Win11", "High", "cmd.exe", "10.0.0.1", "1.1.1.1",
        )
        .await
        .unwrap();

    assert_ne!(id1, id3, "Different host should create new session");
}
