//! SOCKS5 Reverse-Proxy Relay
//!
//! The teamserver hosts a local SOCKS5 listener where operator tools
//! (proxychains, browsers, Burp, etc.) connect.  For each incoming
//! SOCKS5 connection, the relay:
//!
//!   1. Completes the SOCKS5 handshake (method selection + CONNECT).
//!   2. Assigns a `conn_id` and sends a CONNECT_REQ message to the
//!      implant's socks5 module via the normal tasking channel.
//!   3. Relays bidirectional DATA messages between the operator's
//!      TCP stream and the implant module output.
//!   4. Handles CLOSE in both directions.
//!
//! Wire protocol (matches the implant module's SOCKS_MSG):
//!
//!   ```text
//!   [2B conn_id LE][1B msg_type][1B flags][4B payload_len LE]
//!   [payload_len bytes of data]
//!   ```

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};

use specter_common::proto::specter::v1::TaskPriority;

use crate::session::SessionManager;
use crate::task::TaskDispatcher;

/// Wire protocol message types (must match implant module constants).
const MSG_CONNECT_REQ: u8 = 0x01;
const MSG_CONNECT_RSP: u8 = 0x02;
const MSG_DATA: u8 = 0x03;
const MSG_CLOSE: u8 = 0x04;
const MSG_KEEPALIVE: u8 = 0x05;

/// SOCKS5 constants.
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAIL: u8 = 0x01;
const SOCKS5_REP_CMD_UNSUP: u8 = 0x07;

const SOCKS_MSG_HDR_SIZE: usize = 8;

/// Per-connection channel for receiving data from the implant.
type ConnSender = mpsc::Sender<Vec<u8>>;
type ConnReceiver = mpsc::Receiver<Vec<u8>>;

/// Tracks the SOCKS5 relay state for one implant session.
pub struct SocksRelay {
    session_id: String,
    bind_addr: String,
    next_conn_id: Mutex<u16>,
    /// Map of conn_id → sender for routing implant data to the right TCP stream.
    conn_channels: RwLock<HashMap<u16, ConnSender>>,
    _session_manager: Arc<SessionManager>,
    task_dispatcher: Arc<TaskDispatcher>,
    running: RwLock<bool>,
}

impl SocksRelay {
    pub fn new(
        session_id: String,
        bind_addr: String,
        session_manager: Arc<SessionManager>,
        task_dispatcher: Arc<TaskDispatcher>,
    ) -> Self {
        Self {
            session_id,
            bind_addr,
            next_conn_id: Mutex::new(1),
            conn_channels: RwLock::new(HashMap::new()),
            _session_manager: session_manager,
            task_dispatcher,
            running: RwLock::new(false),
        }
    }

    /// Allocate the next connection ID (wraps around, skips 0).
    async fn alloc_conn_id(&self) -> u16 {
        let mut id = self.next_conn_id.lock().await;
        let current = *id;
        *id = if current == u16::MAX { 1 } else { current + 1 };
        current
    }

    /// Register a connection channel for receiving implant data.
    async fn register_conn(&self, conn_id: u16) -> ConnReceiver {
        let (tx, rx) = mpsc::channel(256);
        self.conn_channels.write().await.insert(conn_id, tx);
        rx
    }

    /// Unregister a connection channel.
    async fn unregister_conn(&self, conn_id: u16) {
        self.conn_channels.write().await.remove(&conn_id);
    }

    /// Route an incoming message from the implant to the appropriate connection.
    pub async fn route_implant_message(&self, data: &[u8]) {
        if data.len() < SOCKS_MSG_HDR_SIZE {
            return;
        }

        let conn_id = u16::from_le_bytes([data[0], data[1]]);
        let msg_type = data[2];
        let payload_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        if data.len() < SOCKS_MSG_HDR_SIZE + payload_len {
            return;
        }

        let payload = data[SOCKS_MSG_HDR_SIZE..SOCKS_MSG_HDR_SIZE + payload_len].to_vec();

        match msg_type {
            MSG_CONNECT_RSP | MSG_DATA | MSG_CLOSE => {
                let channels = self.conn_channels.read().await;
                if let Some(tx) = channels.get(&conn_id) {
                    // Build a small message with type prefix so the receiver can distinguish
                    let mut msg = Vec::with_capacity(1 + payload.len());
                    msg.push(msg_type);
                    msg.extend_from_slice(&payload);
                    let _ = tx.send(msg).await;
                }
            }
            MSG_KEEPALIVE => {
                tracing::debug!("SOCKS relay: keepalive from session {}", self.session_id);
            }
            _ => {}
        }
    }

    /// Send a wire-protocol message to the implant via task queue.
    async fn send_to_implant(
        &self,
        conn_id: u16,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), String> {
        let mut buf = Vec::with_capacity(SOCKS_MSG_HDR_SIZE + payload.len());
        buf.extend_from_slice(&conn_id.to_le_bytes());
        buf.push(msg_type);
        buf.push(0); // flags
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);

        self.task_dispatcher
            .queue_task(
                &self.session_id,
                "socks_data",
                &buf,
                TaskPriority::Normal,
                "system",
            )
            .await
            .map_err(|e| format!("Failed to queue socks task: {e}"))?;

        Ok(())
    }

    /// Start the SOCKS5 listener. Returns a handle that can be used to stop it.
    pub async fn start(self: Arc<Self>) -> Result<(), String> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("SOCKS relay already running".to_string());
            }
            *running = true;
        }

        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| format!("Failed to bind SOCKS5 listener on {}: {e}", self.bind_addr))?;

        tracing::info!(
            "SOCKS5 relay started on {} for session {}",
            self.bind_addr,
            self.session_id
        );

        let relay = Arc::clone(&self);
        tokio::spawn(async move {
            loop {
                {
                    let running = relay.running.read().await;
                    if !*running {
                        break;
                    }
                }

                match listener.accept().await {
                    Ok((stream, addr)) => {
                        tracing::debug!("SOCKS5 connection from {addr}");
                        let r = Arc::clone(&relay);
                        tokio::spawn(async move {
                            if let Err(e) = r.handle_client(stream).await {
                                tracing::debug!("SOCKS5 client error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("SOCKS5 accept error: {e}");
                    }
                }
            }
            tracing::info!("SOCKS5 relay stopped for session {}", relay.session_id);
        });

        Ok(())
    }

    /// Stop the SOCKS5 listener.
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        // Send stop signal to implant module (CLOSE with conn_id=0)
        let _ = self.send_to_implant(0, MSG_CLOSE, &[]).await;
    }

    /// Handle a single SOCKS5 client connection.
    async fn handle_client(self: Arc<Self>, mut stream: TcpStream) -> Result<(), String> {
        // --- SOCKS5 method selection ---
        let mut buf = [0u8; 258];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read error: {e}"))?;

        if n < 2 || buf[0] != SOCKS5_VERSION {
            return Err("Not a SOCKS5 client".to_string());
        }

        let nmethods = buf[1] as usize;
        if n < 2 + nmethods {
            return Err("Truncated method selection".to_string());
        }

        // Check if NO_AUTH is offered
        let mut has_noauth = false;
        for i in 0..nmethods {
            if buf[2 + i] == SOCKS5_AUTH_NONE {
                has_noauth = true;
                break;
            }
        }

        if !has_noauth {
            stream
                .write_all(&[SOCKS5_VERSION, 0xFF])
                .await
                .map_err(|e| format!("write error: {e}"))?;
            return Err("Client does not support NO_AUTH".to_string());
        }

        // Accept NO_AUTH
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
            .await
            .map_err(|e| format!("write error: {e}"))?;

        // --- SOCKS5 CONNECT request ---
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read error: {e}"))?;

        if n < 4 || buf[0] != SOCKS5_VERSION {
            return Err("Invalid SOCKS5 request".to_string());
        }

        let cmd = buf[1];
        // buf[2] is RSV
        let atyp = buf[3];

        if cmd != SOCKS5_CMD_CONNECT {
            // Send command not supported reply
            let reply = socks5_reply(SOCKS5_REP_CMD_UNSUP, &[0, 0, 0, 0], 0);
            let _ = stream.write_all(&reply).await;
            return Err("Only CONNECT command is supported".to_string());
        }

        // Parse the address portion to build the CONNECT_REQ payload
        // Payload format for implant: [1B atyp][variable addr][2B port_be]
        let (connect_payload, _target_desc) = match atyp {
            SOCKS5_ATYP_IPV4 => {
                if n < 10 {
                    return Err("Truncated IPv4 request".to_string());
                }
                let mut payload = Vec::with_capacity(7);
                payload.push(SOCKS5_ATYP_IPV4);
                payload.extend_from_slice(&buf[4..8]); // 4 bytes IPv4
                payload.extend_from_slice(&buf[8..10]); // 2 bytes port
                let desc = format!(
                    "{}.{}.{}.{}:{}",
                    buf[4],
                    buf[5],
                    buf[6],
                    buf[7],
                    u16::from_be_bytes([buf[8], buf[9]])
                );
                (payload, desc)
            }
            SOCKS5_ATYP_DOMAIN => {
                if n < 5 {
                    return Err("Truncated domain request".to_string());
                }
                let dlen = buf[4] as usize;
                if n < 5 + dlen + 2 {
                    return Err("Truncated domain request".to_string());
                }
                let mut payload = Vec::with_capacity(2 + dlen + 2);
                payload.push(SOCKS5_ATYP_DOMAIN);
                payload.push(buf[4]); // domain length
                payload.extend_from_slice(&buf[5..5 + dlen]); // domain
                payload.extend_from_slice(&buf[5 + dlen..5 + dlen + 2]); // port
                let domain = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
                let port = u16::from_be_bytes([buf[5 + dlen], buf[5 + dlen + 1]]);
                let desc = format!("{domain}:{port}");
                (payload, desc)
            }
            SOCKS5_ATYP_IPV6 => {
                if n < 22 {
                    return Err("Truncated IPv6 request".to_string());
                }
                // We forward the request to the implant which will reject IPv6
                let mut payload = Vec::with_capacity(19);
                payload.push(SOCKS5_ATYP_IPV6);
                payload.extend_from_slice(&buf[4..20]); // 16 bytes IPv6
                payload.extend_from_slice(&buf[20..22]); // 2 bytes port
                (payload, "IPv6 target".to_string())
            }
            _ => {
                let reply = socks5_reply(SOCKS5_REP_GENERAL_FAIL, &[0, 0, 0, 0], 0);
                let _ = stream.write_all(&reply).await;
                return Err(format!("Unknown address type: {atyp}"));
            }
        };

        // Allocate a connection ID and register the channel
        let conn_id = self.alloc_conn_id().await;
        let mut rx = self.register_conn(conn_id).await;

        // Send CONNECT_REQ to implant
        if let Err(e) = self
            .send_to_implant(conn_id, MSG_CONNECT_REQ, &connect_payload)
            .await
        {
            self.unregister_conn(conn_id).await;
            let reply = socks5_reply(SOCKS5_REP_GENERAL_FAIL, &[0, 0, 0, 0], 0);
            let _ = stream.write_all(&reply).await;
            return Err(format!("Failed to send connect request: {e}"));
        }

        // Wait for CONNECT_RSP from implant
        let connect_result =
            tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv()).await;

        match connect_result {
            Ok(Some(msg)) if msg.len() >= 2 && msg[0] == MSG_CONNECT_RSP => {
                let rep = msg[1];
                if rep != SOCKS5_REP_SUCCESS {
                    self.unregister_conn(conn_id).await;
                    let reply = socks5_reply(rep, &[0, 0, 0, 0], 0);
                    let _ = stream.write_all(&reply).await;
                    return Err(format!("Implant connect failed with code {rep:#x}"));
                }
            }
            Ok(Some(msg)) if !msg.is_empty() && msg[0] == MSG_CLOSE => {
                self.unregister_conn(conn_id).await;
                let reply = socks5_reply(SOCKS5_REP_GENERAL_FAIL, &[0, 0, 0, 0], 0);
                let _ = stream.write_all(&reply).await;
                return Err("Connection closed by implant".to_string());
            }
            _ => {
                self.unregister_conn(conn_id).await;
                let reply = socks5_reply(SOCKS5_REP_GENERAL_FAIL, &[0, 0, 0, 0], 0);
                let _ = stream.write_all(&reply).await;
                return Err("Connect response timeout or channel closed".to_string());
            }
        }

        // Send SOCKS5 success reply (bind address 0.0.0.0:0)
        let reply = socks5_reply(SOCKS5_REP_SUCCESS, &[0, 0, 0, 0], 0);
        stream
            .write_all(&reply)
            .await
            .map_err(|e| format!("write error: {e}"))?;

        // --- Data relay phase ---
        let (mut read_half, mut write_half) = stream.into_split();

        let relay_send = Arc::clone(&self);
        let send_conn_id = conn_id;

        // Task 1: Read from operator TCP → send to implant
        let send_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if relay_send
                            .send_to_implant(send_conn_id, MSG_DATA, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Notify implant that connection is closed
            let _ = relay_send
                .send_to_implant(send_conn_id, MSG_CLOSE, &[])
                .await;
        });

        // Task 2: Receive from implant → write to operator TCP
        let recv_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if msg.is_empty() {
                    continue;
                }
                match msg[0] {
                    MSG_DATA => {
                        if msg.len() > 1
                            && write_half.write_all(&msg[1..]).await.is_err() {
                                break;
                            }
                    }
                    MSG_CLOSE => break,
                    _ => {}
                }
            }
        });

        // Wait for either direction to finish
        tokio::select! {
            _ = send_task => {}
            _ = recv_task => {}
        }

        self.unregister_conn(conn_id).await;
        Ok(())
    }
}

/// Build a SOCKS5 reply packet.
fn socks5_reply(rep: u8, bind_addr: &[u8; 4], bind_port: u16) -> Vec<u8> {
    let mut reply = Vec::with_capacity(10);
    reply.push(SOCKS5_VERSION);
    reply.push(rep);
    reply.push(0x00); // RSV
    reply.push(SOCKS5_ATYP_IPV4);
    reply.extend_from_slice(bind_addr);
    reply.extend_from_slice(&bind_port.to_be_bytes());
    reply
}

/// Manager that tracks SOCKS relays across multiple sessions.
pub struct SocksManager {
    relays: RwLock<HashMap<String, Arc<SocksRelay>>>,
    session_manager: Arc<SessionManager>,
    task_dispatcher: Arc<TaskDispatcher>,
}

impl SocksManager {
    pub fn new(session_manager: Arc<SessionManager>, task_dispatcher: Arc<TaskDispatcher>) -> Self {
        Self {
            relays: RwLock::new(HashMap::new()),
            session_manager,
            task_dispatcher,
        }
    }

    /// Start a SOCKS5 relay for a session on the given bind address.
    pub async fn start_relay(&self, session_id: &str, bind_addr: &str) -> Result<(), String> {
        {
            let relays = self.relays.read().await;
            if relays.contains_key(session_id) {
                return Err(format!(
                    "SOCKS relay already active for session {session_id}"
                ));
            }
        }

        let relay = Arc::new(SocksRelay::new(
            session_id.to_string(),
            bind_addr.to_string(),
            Arc::clone(&self.session_manager),
            Arc::clone(&self.task_dispatcher),
        ));

        relay.clone().start().await?;

        self.relays
            .write()
            .await
            .insert(session_id.to_string(), relay);

        Ok(())
    }

    /// Stop a SOCKS5 relay for a session.
    pub async fn stop_relay(&self, session_id: &str) -> Result<(), String> {
        let relay = self
            .relays
            .write()
            .await
            .remove(session_id)
            .ok_or_else(|| format!("No SOCKS relay for session {session_id}"))?;

        relay.stop().await;
        Ok(())
    }

    /// Route an implant SOCKS message to the appropriate relay.
    pub async fn route_message(&self, session_id: &str, data: &[u8]) {
        let relays = self.relays.read().await;
        if let Some(relay) = relays.get(session_id) {
            relay.route_implant_message(data).await;
        }
    }

    /// List active SOCKS relays.
    pub async fn list_relays(&self) -> Vec<(String, String)> {
        let relays = self.relays.read().await;
        relays
            .iter()
            .map(|(sid, r)| (sid.clone(), r.bind_addr.clone()))
            .collect()
    }
}
