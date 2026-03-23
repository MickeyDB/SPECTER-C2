use std::sync::Arc;

use hyper::header;
use tonic::transport::Server;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;

use specter_common::proto::specter::v1::specter_service_server::SpecterServiceServer;

use crate::audit::AuditLog;
use crate::auth::ca::{derive_master_key, EmbeddedCA};
use crate::auth::interceptor::AuthInterceptor;
use crate::auth::mtls::{build_mtls_config, MtlsAuthInterceptor};
use crate::auth::AuthService;
use crate::campaign::CampaignManager;
use crate::collaboration::chat::ChatService;
use crate::collaboration::PresenceManager;
use crate::db;
use crate::event::webhooks::WebhookManager;
use crate::event::EventBus;
use crate::grpc::SpecterGrpcService;
use crate::listener::ListenerManager;
use crate::module::ModuleRepository;
use crate::profile::ProfileStore;
use crate::reports::ReportGenerator;
use crate::session::SessionManager;
use crate::task::TaskDispatcher;

/// Configuration parsed from CLI flags.
pub struct ServerConfig {
    pub bind: String,
    pub grpc_port: u16,
    pub http_port: u16,
    pub db_path: String,
    pub dev_mode: bool,
    /// Optional path to the Web UI static assets directory (web/dist/).
    pub web_ui_dir: Option<String>,
}

pub async fn run_server(cfg: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Database
    let pool = db::init_db(&cfg.db_path).await?;
    tracing::info!("Database initialised at {}", cfg.db_path);

    // 2. Auth service
    let auth_service = Arc::new(AuthService::new(pool.clone()));

    // Auto-create default admin on first startup (empty operators table).
    if auth_service.is_first_run().await? {
        let password = AuthService::generate_api_token();
        auth_service
            .create_operator("admin", &password, "ADMIN")
            .await?;
        tracing::info!("Default admin operator created");
        println!();
        println!("  ┌─ Default admin operator created ─────────────────────────────────────┐");
        println!("  │  Username: admin");
        println!("  │  Password: {password}");
        println!("  │  Save these credentials — they will not be shown again.");
        println!("  └──────────────────────────────────────────────────────────────────────┘");
        println!();
    }

    // 3. Event bus
    let event_bus = Arc::new(EventBus::new(1024));

    // 4. Managers
    let session_manager = Arc::new(SessionManager::new(pool.clone(), Arc::clone(&event_bus)));
    let task_dispatcher = Arc::new(TaskDispatcher::new(pool.clone(), Arc::clone(&event_bus)));
    let listener_manager = Arc::new(ListenerManager::new(
        pool.clone(),
        Arc::clone(&session_manager),
        Arc::clone(&task_dispatcher),
        Arc::clone(&event_bus),
    ));
    let module_repository = Arc::new(ModuleRepository::new(pool.clone()));
    let profile_store = Arc::new(ProfileStore::new(pool.clone()));
    let audit_log = Arc::new(AuditLog::new(pool.clone()));
    let webhook_manager = Arc::new(WebhookManager::new(pool.clone()));
    let campaign_manager = Arc::new(CampaignManager::new(pool.clone()));
    let presence_manager = Arc::new(PresenceManager::new(Arc::clone(&event_bus)));
    let chat_service = Arc::new(ChatService::new(pool.clone(), Arc::clone(&event_bus)));
    let report_generator = Arc::new(ReportGenerator::new(pool.clone()));

    // Seed default modules into the repository
    module_repository.seed_default_modules().await?;
    tracing::info!("Module repository seeded with default modules");

    // 5. Background session status updater (every 5 s, assumes 10 s default check-in interval)
    session_manager.start_status_updater(5, 10);

    // Log server X25519 public key (needed for implant config generation)
    let server_pubkey = listener_manager.server_pubkey_bytes();
    tracing::info!("Server X25519 public key: {}", hex::encode(server_pubkey));

    // Log Ed25519 module signing public key (must be embedded in implant config)
    let signing_pubkey = module_repository.signing_pubkey_bytes();
    tracing::info!(
        "Module signing Ed25519 public key: {}",
        hex::encode(signing_pubkey)
    );

    // 6. Auto-create a default HTTP listener and start it in dev-mode
    if cfg.dev_mode {
        tracing::info!(
            "Dev-mode enabled — creating default HTTP listener on port {}",
            cfg.http_port
        );
        let listener = listener_manager
            .create_listener("default-http", &cfg.bind, cfg.http_port as u32, "http")
            .await?;
        listener_manager
            .start_listener(&listener.id)
            .await
            .map_err(|e| format!("Failed to start default listener: {e}"))?;
    }

    // 7. Initialize embedded CA (unless dev-mode)
    let ca = if !cfg.dev_mode {
        // Use a deterministic master key derived from the DB path for now.
        // In production, this should come from a secure key store or env var.
        let master_key = derive_master_key(&cfg.db_path);
        let ca = EmbeddedCA::init(pool.clone(), &master_key).await?;
        tracing::info!("CA root certificate fingerprint: (loaded)");
        Some(Arc::new(ca))
    } else {
        tracing::info!("Dev-mode: CA disabled, using token auth only");
        None
    };

    // 8. Start webhook event forwarding
    webhook_manager.start_forwarding(event_bus.subscribe());
    tracing::info!("Webhook event forwarding started");

    // 9. gRPC server with auth interceptor + gRPC-Web support
    let mut grpc_service = SpecterGrpcService::new(
        Arc::clone(&session_manager),
        Arc::clone(&task_dispatcher),
        Arc::clone(&listener_manager),
        Arc::clone(&event_bus),
        Arc::clone(&auth_service),
        Arc::clone(&module_repository),
        Arc::clone(&profile_store),
        Arc::clone(&audit_log),
        Arc::clone(&webhook_manager),
        Arc::clone(&campaign_manager),
        Arc::clone(&presence_manager),
        Arc::clone(&chat_service),
        Arc::clone(&report_generator),
    );

    if let Some(ref ca) = ca {
        grpc_service = grpc_service.with_ca(Arc::clone(ca));
    }

    // CORS layer for gRPC-Web browser requests
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            "x-grpc-web".parse().unwrap(),
            "x-user-agent".parse().unwrap(),
        ])
        .expose_headers([
            "grpc-status".parse().unwrap(),
            "grpc-message".parse().unwrap(),
        ])
        .allow_methods([hyper::Method::POST, hyper::Method::OPTIONS]);

    let grpc_addr = format!("{}:{}", cfg.bind, cfg.grpc_port).parse()?;
    tracing::info!("gRPC server listening on {grpc_addr}");

    if let Some(ref web_dir) = cfg.web_ui_dir {
        tracing::info!("Serving Web UI from {web_dir} at /ui/");
    }

    // Build a function that creates the combined gRPC + static-file router.
    // We use axum::Router as the top-level service so we can add a fallback
    // for serving the Web UI static files alongside gRPC-Web.
    let web_dir = cfg.web_ui_dir.clone();

    if let Some(ref ca) = ca {
        // mTLS mode: configure TLS on the gRPC server
        let hostnames = vec![cfg.bind.clone(), "localhost".to_string()];
        let (tls_config, _server_cert, _server_key) = build_mtls_config(ca, &hostnames)
            .await
            .map_err(|e| format!("Failed to build mTLS config: {e}"))?;

        let interceptor = MtlsAuthInterceptor::new(
            auth_service.token_store(),
            false,
            Some(ca.get_root_cert().to_string()),
        );

        let grpc_web_svc = tonic_web::enable(SpecterServiceServer::with_interceptor(
            grpc_service,
            interceptor,
        ));

        let mut builder = Server::builder()
            .tls_config(tls_config)?
            .accept_http1(true)
            .layer(cors);

        if let Some(ref dir) = web_dir {
            let serve = ServeDir::new(dir)
                .append_index_html_on_directories(true);
            let web_routes: axum::Router = axum::Router::new()
                .fallback_service(serve);
            builder
                .add_routes(web_routes.into())
                .add_service(grpc_web_svc)
                .serve(grpc_addr)
                .await?;
        } else {
            builder
                .add_service(grpc_web_svc)
                .serve(grpc_addr)
                .await?;
        }
    } else {
        // Dev-mode: plain gRPC with token auth
        let interceptor = AuthInterceptor::new(auth_service.token_store(), cfg.dev_mode);

        let grpc_web_svc = tonic_web::enable(SpecterServiceServer::with_interceptor(
            grpc_service,
            interceptor,
        ));

        let mut builder = Server::builder()
            .accept_http1(true)
            .layer(cors);

        if let Some(ref dir) = web_dir {
            let serve = ServeDir::new(dir)
                .append_index_html_on_directories(true);
            let web_routes: axum::Router = axum::Router::new()
                .fallback_service(serve);
            builder
                .add_routes(web_routes.into())
                .add_service(grpc_web_svc)
                .serve(grpc_addr)
                .await?;
        } else {
            builder
                .add_service(grpc_web_svc)
                .serve(grpc_addr)
                .await?;
        }
    }

    Ok(())
}
