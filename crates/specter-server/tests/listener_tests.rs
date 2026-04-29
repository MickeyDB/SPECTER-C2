use std::sync::Arc;

use axum::body::Body;
use http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;
use x25519_dalek::{PublicKey, StaticSecret};

use specter_common::checkin::{CheckinRequest, CheckinResponse, TaskResultPayload};
use specter_common::proto::specter::v1::TaskPriority;
use specter_server::db;
use specter_server::event::EventBus;
use specter_server::listener::{build_router, HttpState};
use specter_server::session::SessionManager;
use specter_server::task::TaskDispatcher;

async fn setup() -> (Arc<SessionManager>, Arc<TaskDispatcher>, axum::Router) {
    let pool = db::init_db(":memory:").await.unwrap();
    let bus = Arc::new(EventBus::new(64));
    let session_mgr = Arc::new(SessionManager::new(pool.clone(), bus.clone()));
    let task_disp = Arc::new(TaskDispatcher::new(pool.clone(), bus));

    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let pubkey = PublicKey::from(&secret);

    let state = HttpState {
        session_manager: session_mgr.clone(),
        task_dispatcher: task_disp.clone(),
        module_repository: None,
        server_secret: Arc::new(secret),
        server_pubkey: Arc::new(pubkey),
        listener_profile: None,
        profile_session_key: None,
        pool: pool.clone(),
    };
    let router = build_router(state);
    (session_mgr, task_disp, router)
}

fn checkin_request_body(req: &CheckinRequest) -> Body {
    Body::from(serde_json::to_vec(req).unwrap())
}

#[tokio::test]
async fn checkin_accepts_valid_json_and_returns_pending_tasks() {
    let (session_mgr, task_disp, app) = setup().await;

    // First check-in: creates session
    let checkin = CheckinRequest {
        session_id: None,
        hostname: "VICTIM01".into(),
        username: "admin".into(),
        pid: 4444,
        os_version: "Windows 11".into(),
        integrity_level: "High".into(),
        process_name: "implant.exe".into(),
        internal_ip: "192.168.1.50".into(),
        external_ip: "8.8.8.8".into(),
        task_results: vec![],
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let cr: CheckinResponse = serde_json::from_slice(&body).unwrap();
    assert!(!cr.session_id.is_empty());
    assert!(cr.tasks.is_empty()); // No tasks queued yet

    // Queue a task for the session
    let session_id = cr.session_id.clone();
    task_disp
        .queue_task(&session_id, "shell", b"whoami", TaskPriority::Normal, "op1")
        .await
        .unwrap();

    // Second check-in: should get the pending task
    let checkin2 = CheckinRequest {
        session_id: Some(session_id.clone()),
        hostname: "VICTIM01".into(),
        username: "admin".into(),
        pid: 4444,
        ..checkin.clone()
    };

    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin2))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp2.status(), 200);

    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let cr2: CheckinResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(cr2.session_id, session_id);
    assert_eq!(cr2.tasks.len(), 1);
    assert_eq!(cr2.tasks[0].task_type, "shell");

    // Verify session was created/updated in session manager
    let sessions = session_mgr.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].hostname, "VICTIM01");
}

#[tokio::test]
async fn checkin_creates_or_updates_session() {
    let (session_mgr, _task_disp, app) = setup().await;

    let checkin = CheckinRequest {
        session_id: None,
        hostname: "HOST_A".into(),
        username: "user_a".into(),
        pid: 1111,
        os_version: "Linux".into(),
        integrity_level: "root".into(),
        process_name: "implant".into(),
        internal_ip: "10.0.0.1".into(),
        external_ip: "2.2.2.2".into(),
        task_results: vec![],
    };

    // First check-in
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let cr1: CheckinResponse = serde_json::from_slice(&body).unwrap();

    // Second check-in with same host/user/pid — should return same session ID
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin))
                .unwrap(),
        )
        .await
        .unwrap();
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let cr2: CheckinResponse = serde_json::from_slice(&body2).unwrap();

    assert_eq!(cr1.session_id, cr2.session_id);

    // Only one session in the database
    let sessions = session_mgr.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 1);
}

#[tokio::test]
async fn task_results_in_checkin_are_processed_correctly() {
    let (_session_mgr, task_disp, app) = setup().await;

    // Create a session via check-in
    let checkin = CheckinRequest {
        session_id: None,
        hostname: "HOST_B".into(),
        username: "user_b".into(),
        pid: 2222,
        os_version: "Win10".into(),
        integrity_level: "Medium".into(),
        process_name: "beacon.exe".into(),
        internal_ip: "10.0.0.2".into(),
        external_ip: "3.3.3.3".into(),
        task_results: vec![],
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let cr: CheckinResponse = serde_json::from_slice(&body).unwrap();
    let session_id = cr.session_id;

    // Queue a task
    let tid = task_disp
        .queue_task(
            &session_id,
            "shell",
            b"hostname",
            TaskPriority::Normal,
            "op1",
        )
        .await
        .unwrap();

    // Check-in with task result
    let checkin_with_result = CheckinRequest {
        session_id: Some(session_id),
        hostname: "HOST_B".into(),
        username: "user_b".into(),
        pid: 2222,
        os_version: "Win10".into(),
        integrity_level: "Medium".into(),
        process_name: "beacon.exe".into(),
        internal_ip: "10.0.0.2".into(),
        external_ip: "3.3.3.3".into(),
        task_results: vec![TaskResultPayload {
            task_id: tid.clone(),
            status: "COMPLETE".into(),
            result: "HOST_B".into(),
        }],
    };

    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin_with_result))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);

    // Verify the task was completed
    let task = task_disp.get_task(&tid).await.unwrap().unwrap();
    assert_eq!(
        task.status,
        i32::from(specter_common::proto::specter::v1::TaskStatus::Complete)
    );
    assert_eq!(task.result, b"HOST_B");
}

/// Phase 1.2: task result larger than legacy 64 KiB TLV limit must round-trip on JSON check-in.
#[tokio::test]
async fn large_task_result_roundtrips_via_json_checkin() {
    const LARGE_LEN: usize = 100 * 1024;
    let (_session_mgr, task_disp, app) = setup().await;

    let checkin = CheckinRequest {
        session_id: None,
        hostname: "HOST_LARGE".into(),
        username: "user_large".into(),
        pid: 7777,
        os_version: "Win11".into(),
        integrity_level: "Medium".into(),
        process_name: "beacon.exe".into(),
        internal_ip: "10.0.0.7".into(),
        external_ip: "7.7.7.7".into(),
        task_results: vec![],
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let cr: CheckinResponse = serde_json::from_slice(&body).unwrap();
    let session_id = cr.session_id;

    let tid = task_disp
        .queue_task(
            &session_id,
            "shell",
            b"generate-big-output",
            TaskPriority::Normal,
            "op1",
        )
        .await
        .unwrap();

    let mut big = String::with_capacity(LARGE_LEN);
    big.push_str("SPECTER_LARGE_HEAD:");
    while big.len() < LARGE_LEN - "SPECTER_LARGE_TAIL".len() {
        big.push('A');
    }
    big.push_str("SPECTER_LARGE_TAIL");
    assert_eq!(big.len(), LARGE_LEN);

    let checkin_with_result = CheckinRequest {
        session_id: Some(session_id),
        hostname: "HOST_LARGE".into(),
        username: "user_large".into(),
        pid: 7777,
        os_version: "Win11".into(),
        integrity_level: "Medium".into(),
        process_name: "beacon.exe".into(),
        internal_ip: "10.0.0.7".into(),
        external_ip: "7.7.7.7".into(),
        task_results: vec![TaskResultPayload {
            task_id: tid.clone(),
            status: "COMPLETE".into(),
            result: big.clone(),
        }],
    };

    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin_with_result))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);

    let task = task_disp.get_task(&tid).await.unwrap().unwrap();
    assert_eq!(
        task.status,
        i32::from(specter_common::proto::specter::v1::TaskStatus::Complete)
    );
    assert_eq!(task.result.len(), LARGE_LEN);
    assert!(task.result.starts_with(b"SPECTER_LARGE_HEAD:"));
    assert!(task.result.ends_with(b"SPECTER_LARGE_TAIL"));
}

#[tokio::test]
async fn sleep_result_persists_and_beacon_remains_live_across_followup_checkins() {
    let (session_mgr, task_disp, app) = setup().await;

    // Initial check-in to create session.
    let checkin = CheckinRequest {
        session_id: None,
        hostname: "HOST_SLEEP".into(),
        username: "user_sleep".into(),
        pid: 3333,
        os_version: "Windows 11".into(),
        integrity_level: "High".into(),
        process_name: "beacon.exe".into(),
        internal_ip: "10.0.0.3".into(),
        external_ip: "4.4.4.4".into(),
        task_results: vec![],
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&checkin))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let created: CheckinResponse = serde_json::from_slice(&body).unwrap();
    let sid = created.session_id;

    // Queue a sleep task.
    let sleep_tid = task_disp
        .queue_task(&sid, "sleep", b"45 20", TaskPriority::Normal, "op1")
        .await
        .unwrap();

    // Dispatch queued sleep task on next check-in.
    let dispatch_req = CheckinRequest {
        session_id: Some(sid.clone()),
        task_results: vec![],
        ..checkin.clone()
    };
    let dispatch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&dispatch_req))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dispatch_resp.status(), 200);
    let dispatch_body = dispatch_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let dispatched: CheckinResponse = serde_json::from_slice(&dispatch_body).unwrap();
    assert_eq!(dispatched.tasks.len(), 1);
    assert_eq!(dispatched.tasks[0].task_id, sleep_tid);
    assert_eq!(dispatched.tasks[0].task_type, "sleep");

    // Send sleep result and then perform follow-up check-ins.
    let complete_req = CheckinRequest {
        session_id: Some(sid.clone()),
        task_results: vec![TaskResultPayload {
            task_id: sleep_tid,
            status: "COMPLETE".into(),
            result: "interval=45s jitter=20%".into(),
        }],
        ..checkin.clone()
    };
    let complete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/checkin")
                .header("content-type", "application/json")
                .body(checkin_request_body(&complete_req))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(complete_resp.status(), 200);

    for _ in 0..5 {
        let follow_req = CheckinRequest {
            session_id: Some(sid.clone()),
            task_results: vec![],
            ..checkin.clone()
        };
        let follow_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/checkin")
                    .header("content-type", "application/json")
                    .body(checkin_request_body(&follow_req))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(follow_resp.status(), 200);
    }

    // Validate persisted sleep metadata and active status.
    let session = session_mgr.get_session(&sid).await.unwrap().unwrap();
    assert_eq!(session.sleep_interval, 45);
    assert_eq!(session.sleep_jitter, 20);
    assert_eq!(
        session.status,
        i32::from(specter_common::proto::specter::v1::SessionStatus::Active)
    );
}

#[tokio::test]
async fn health_endpoint_returns_200() {
    let (_session_mgr, _task_disp, app) = setup().await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn beacon_rejects_short_payload() {
    let (_session_mgr, _task_disp, app) = setup().await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/beacon")
                .header("content-type", "application/octet-stream")
                .body(Body::from(vec![0u8; 10]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn beacon_rejects_unknown_implant() {
    let (_session_mgr, _task_disp, app) = setup().await;

    // Craft a minimal but structurally valid beacon with unknown implant ID
    let fake_implant_id = [0xAAu8; 12];
    let fake_nonce = [0xBBu8; 12];
    let fake_ct = [0xCCu8; 32];
    let fake_tag = [0xDDu8; 16];

    let total_len = (24 + 32 + 16) as u32;
    let mut payload = Vec::new();
    payload.extend_from_slice(&total_len.to_le_bytes());
    payload.extend_from_slice(&fake_implant_id);
    payload.extend_from_slice(&fake_nonce);
    payload.extend_from_slice(&fake_ct);
    payload.extend_from_slice(&fake_tag);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/beacon")
                .header("content-type", "application/octet-stream")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be unauthorized since the implant is unknown
    assert_eq!(resp.status(), 401);
}
