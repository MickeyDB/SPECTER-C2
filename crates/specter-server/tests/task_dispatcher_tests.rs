use std::sync::Arc;

use specter_common::proto::specter::v1::{TaskPriority, TaskStatus};
use specter_server::db;
use specter_server::event::EventBus;
use specter_server::session::SessionManager;
use specter_server::task::TaskDispatcher;
use sqlx::SqlitePool;

async fn setup() -> (SqlitePool, Arc<TaskDispatcher>, Arc<SessionManager>) {
    let pool = db::init_db(":memory:").await.unwrap();
    let bus = Arc::new(EventBus::new(64));
    let session_mgr = Arc::new(SessionManager::new(pool.clone(), bus.clone()));
    let task_disp = Arc::new(TaskDispatcher::new(pool.clone(), bus));
    (pool, task_disp, session_mgr)
}

/// Helper: create a session and return its ID.
async fn create_session(mgr: &SessionManager) -> String {
    mgr.register_session(
        "HOST".into(),
        "user".into(),
        1000,
        "Win11".into(),
        "High".into(),
        "test.exe".into(),
        "10.0.0.1".into(),
        "1.2.3.4".into(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn queue_task_creates_task_with_correct_priority() {
    let (_pool, disp, session_mgr) = setup().await;
    let sid = create_session(&session_mgr).await;

    let tid = disp
        .queue_task(&sid, "shell", b"whoami", TaskPriority::High, "op1")
        .await
        .unwrap();

    assert!(!tid.is_empty());
    assert_eq!(tid.len(), 36); // UUID

    let task = disp.get_task(&tid).await.unwrap().unwrap();
    assert_eq!(task.session_id, sid);
    assert_eq!(task.task_type, "shell");
    assert_eq!(task.arguments, b"whoami");
    assert_eq!(task.priority, i32::from(TaskPriority::High));
    assert_eq!(task.status, i32::from(TaskStatus::Queued));
    assert_eq!(task.operator_id, "op1");
}

#[tokio::test]
async fn get_pending_tasks_returns_ordered_by_priority_then_creation() {
    let (_pool, disp, session_mgr) = setup().await;
    let sid = create_session(&session_mgr).await;

    let low_id = disp
        .queue_task(&sid, "shell", b"ls", TaskPriority::Low, "op1")
        .await
        .unwrap();
    let normal_id = disp
        .queue_task(&sid, "shell", b"pwd", TaskPriority::Normal, "op1")
        .await
        .unwrap();
    let high_id = disp
        .queue_task(&sid, "shell", b"id", TaskPriority::High, "op1")
        .await
        .unwrap();

    let pending = disp.get_pending_tasks(&sid).await.unwrap();
    assert_eq!(pending.len(), 3);

    // HIGH first, then NORMAL, then LOW
    assert_eq!(pending[0].id, high_id);
    assert_eq!(pending[1].id, normal_id);
    assert_eq!(pending[2].id, low_id);
}

#[tokio::test]
async fn mark_dispatched_changes_task_status() {
    let (_pool, disp, session_mgr) = setup().await;
    let sid = create_session(&session_mgr).await;

    let tid = disp
        .queue_task(&sid, "shell", b"whoami", TaskPriority::Normal, "op1")
        .await
        .unwrap();

    disp.mark_dispatched(&tid).await.unwrap();

    let task = disp.get_task(&tid).await.unwrap().unwrap();
    assert_eq!(task.status, i32::from(TaskStatus::Dispatched));

    // Should no longer appear in pending tasks
    let pending = disp.get_pending_tasks(&sid).await.unwrap();
    assert!(pending.is_empty());
}

#[tokio::test]
async fn complete_task_stores_result_and_updates_status() {
    let (_pool, disp, session_mgr) = setup().await;
    let sid = create_session(&session_mgr).await;

    let tid = disp
        .queue_task(&sid, "shell", b"whoami", TaskPriority::Normal, "op1")
        .await
        .unwrap();

    // Complete successfully
    disp.complete_task(&tid, b"root", true).await.unwrap();

    let task = disp.get_task(&tid).await.unwrap().unwrap();
    assert_eq!(task.status, i32::from(TaskStatus::Complete));
    assert_eq!(task.result, b"root");
    assert!(task.completed_at.is_some());
}

#[tokio::test]
async fn complete_task_with_failure_sets_failed_status() {
    let (_pool, disp, session_mgr) = setup().await;
    let sid = create_session(&session_mgr).await;

    let tid = disp
        .queue_task(&sid, "shell", b"cmd", TaskPriority::Normal, "op1")
        .await
        .unwrap();

    disp.complete_task(&tid, b"access denied", false)
        .await
        .unwrap();

    let task = disp.get_task(&tid).await.unwrap().unwrap();
    assert_eq!(task.status, i32::from(TaskStatus::Failed));
    assert_eq!(task.result, b"access denied");
}

#[tokio::test]
async fn tasks_are_scoped_to_their_session() {
    let (_pool, disp, session_mgr) = setup().await;
    let sid1 = create_session(&session_mgr).await;

    // Create a second session with different hostname
    let sid2 = session_mgr
        .register_session(
            "HOST2".into(),
            "user2".into(),
            2000,
            "Win11".into(),
            "High".into(),
            "test.exe".into(),
            "10.0.0.2".into(),
            "5.6.7.8".into(),
        )
        .await
        .unwrap();

    disp.queue_task(&sid1, "shell", b"whoami", TaskPriority::Normal, "op1")
        .await
        .unwrap();
    disp.queue_task(&sid1, "shell", b"hostname", TaskPriority::Normal, "op1")
        .await
        .unwrap();
    disp.queue_task(&sid2, "shell", b"id", TaskPriority::Normal, "op1")
        .await
        .unwrap();

    let pending1 = disp.get_pending_tasks(&sid1).await.unwrap();
    let pending2 = disp.get_pending_tasks(&sid2).await.unwrap();

    assert_eq!(pending1.len(), 2);
    assert_eq!(pending2.len(), 1);

    // list_tasks also scoped
    let all1 = disp.list_tasks(&sid1).await.unwrap();
    let all2 = disp.list_tasks(&sid2).await.unwrap();
    assert_eq!(all1.len(), 2);
    assert_eq!(all2.len(), 1);
}

#[tokio::test]
async fn get_task_returns_none_for_nonexistent_id() {
    let (_pool, disp, _session_mgr) = setup().await;
    let task = disp.get_task("nonexistent").await.unwrap();
    assert!(task.is_none());
}
