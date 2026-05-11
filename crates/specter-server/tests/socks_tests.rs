use std::sync::Arc;

use specter_server::db;
use specter_server::event::EventBus;
use specter_server::session::SessionManager;
use specter_server::socks::SocksManager;
use specter_server::task::TaskDispatcher;

async fn setup() -> (Arc<SessionManager>, Arc<TaskDispatcher>, SocksManager) {
    let pool = db::init_db(":memory:").await.unwrap();
    let bus = Arc::new(EventBus::new(64));
    let session_mgr = Arc::new(SessionManager::new(pool.clone(), bus.clone()));
    let task_disp = Arc::new(TaskDispatcher::new(pool.clone(), bus.clone()));
    let socks_mgr = SocksManager::new(session_mgr.clone(), task_disp.clone());
    (session_mgr, task_disp, socks_mgr)
}

#[tokio::test]
async fn start_relay_creates_listener() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    // Register a session first
    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    // Start a SOCKS relay on a random high port
    let result = socks_mgr
        .start_relay(
            &session_id,
            "127.0.0.1:0",
            "wss://redirector.example/api/socks/ws",
            "task-start",
        )
        .await;

    // Should succeed (port 0 lets OS pick a free port — but TcpListener::bind
    // with port 0 works; the relay just stores the requested address)
    assert!(result.is_ok(), "start_relay should succeed: {:?}", result);

    // List should show the relay
    let relays = socks_mgr.list_relays().await;
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].session_id, session_id);
    assert_eq!(relays[0].started_task_id, "task-start");
    assert_eq!(relays[0].transport, "beacon_fallback");
    assert_eq!(relays[0].state, "starting");
    assert_eq!(
        relays[0].channel_url,
        "wss://redirector.example/api/socks/ws"
    );
}

#[tokio::test]
async fn start_result_marks_relay_ready() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-start")
        .await
        .unwrap();

    socks_mgr
        .mark_started_task_result(&session_id, "task-start", true)
        .await;

    let relay = socks_mgr.relay_info(&session_id).await.unwrap();
    assert_eq!(relay.state, "ready");
}

#[tokio::test]
async fn prepare_start_rejects_active_relay_without_requeue() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-start")
        .await
        .unwrap();

    let err = socks_mgr.prepare_start(&session_id).await.unwrap_err();
    assert!(err.contains("already active"));
    assert!(err.contains("state=starting"));
}

#[tokio::test]
async fn prepare_start_replaces_degraded_relay() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-start")
        .await
        .unwrap();
    socks_mgr
        .mark_started_task_result(&session_id, "task-start", false)
        .await;

    socks_mgr.prepare_start(&session_id).await.unwrap();
    assert!(socks_mgr.relay_info(&session_id).await.is_none());

    socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-retry")
        .await
        .unwrap();
    let relay = socks_mgr.relay_info(&session_id).await.unwrap();
    assert_eq!(relay.started_task_id, "task-retry");
    assert_eq!(relay.state, "starting");
}

#[tokio::test]
async fn failed_start_releases_bind_port() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind_addr = probe.local_addr().unwrap();
    drop(probe);

    socks_mgr
        .start_relay(&session_id, &bind_addr.to_string(), "", "task-start")
        .await
        .unwrap();
    socks_mgr
        .mark_started_task_result(&session_id, "task-start", false)
        .await;

    let relay = socks_mgr.relay_info(&session_id).await.unwrap();
    assert_eq!(relay.state, "degraded");

    let rebound = tokio::net::TcpListener::bind(bind_addr).await;
    assert!(
        rebound.is_ok(),
        "port should be released after failed module start"
    );
}

#[tokio::test]
async fn start_relay_rejects_duplicate() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-start")
        .await
        .unwrap();

    // Second start should fail
    let result = socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-start-2")
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already active"));
}

#[tokio::test]
async fn stop_relay_removes_from_list() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    socks_mgr
        .start_relay(&session_id, "127.0.0.1:0", "", "task-start")
        .await
        .unwrap();

    let result = socks_mgr.stop_relay(&session_id).await;
    assert!(result.is_ok());

    let relays = socks_mgr.list_relays().await;
    assert_eq!(relays.len(), 0);
}

#[tokio::test]
async fn stop_relay_releases_bind_port() {
    let (session_mgr, _task_disp, socks_mgr) = setup().await;

    let session_id = session_mgr
        .register_session(
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
        .unwrap();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind_addr = probe.local_addr().unwrap();
    drop(probe);

    socks_mgr
        .start_relay(&session_id, &bind_addr.to_string(), "", "task-start")
        .await
        .unwrap();

    socks_mgr.stop_relay(&session_id).await.unwrap();

    let rebound = tokio::net::TcpListener::bind(bind_addr).await;
    assert!(rebound.is_ok(), "port should be released after stop");
}

#[tokio::test]
async fn stop_nonexistent_relay_returns_error() {
    let (_session_mgr, _task_disp, socks_mgr) = setup().await;

    let result = socks_mgr.stop_relay("nonexistent-session").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No SOCKS relay"));
}

#[tokio::test]
async fn route_message_to_nonexistent_relay_is_noop() {
    let (_session_mgr, _task_disp, socks_mgr) = setup().await;

    // Should not panic or error — just silently drop
    socks_mgr.route_message("nonexistent", &[0u8; 16]).await;
}

#[tokio::test]
async fn wire_protocol_message_format() {
    // Verify the wire format matches expectations:
    // [2B conn_id LE][1B msg_type][1B flags][4B payload_len LE][payload]

    let conn_id: u16 = 42;
    let msg_type: u8 = 0x03; // MSG_DATA
    let flags: u8 = 0;
    let payload = b"hello";
    let payload_len = payload.len() as u32;

    let mut buf = Vec::new();
    buf.extend_from_slice(&conn_id.to_le_bytes());
    buf.push(msg_type);
    buf.push(flags);
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(payload);

    assert_eq!(buf.len(), 8 + 5); // header + payload
    assert_eq!(buf[0], 42); // conn_id low byte
    assert_eq!(buf[1], 0); // conn_id high byte
    assert_eq!(buf[2], 0x03); // msg_type
    assert_eq!(buf[3], 0); // flags
    assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 5); // payload_len
    assert_eq!(&buf[8..], b"hello");
}
