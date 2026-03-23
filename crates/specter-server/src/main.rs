use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "specter-server", about = "SPECTER C2 Teamserver")]
struct Cli {
    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// gRPC API port
    #[arg(long, default_value_t = 50051)]
    grpc_port: u16,

    /// Default HTTP listener port
    #[arg(long, default_value_t = 443)]
    http_port: u16,

    /// SQLite database path
    #[arg(long, default_value = "specter.db")]
    db_path: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Development mode — disables auth, auto-creates default listener
    #[arg(long)]
    dev_mode: bool,

    /// Path to Web UI static assets directory (web/dist/)
    #[arg(long)]
    web_ui_dir: Option<String>,

    /// Generate an operator mTLS certificate bundle and exit.
    /// Writes operator.pem, operator-key.pem, ca.pem, and operator.p12 to the output dir.
    #[arg(long, value_name = "USERNAME")]
    init_cert: Option<String>,

    /// Output directory for --init-cert files (default: current directory)
    #[arg(long, default_value = ".")]
    cert_out: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    // --init-cert: generate operator certificate and exit
    if let Some(ref username) = cli.init_cert {
        tracing::info!("Generating operator certificate for '{username}'");

        let pool = specter_server::db::init_db(&cli.db_path).await?;
        let master_key =
            specter_server::auth::ca::derive_master_key(&cli.db_path);
        let ca =
            specter_server::auth::ca::EmbeddedCA::init(pool.clone(), &master_key).await?;

        let bundle = ca
            .issue_operator_cert(username, "ADMIN", 365)
            .await
            .map_err(|e| format!("Failed to issue cert: {e}"))?;

        let out = std::path::Path::new(&cli.cert_out);
        std::fs::create_dir_all(out)?;

        let cert_path = out.join("operator.pem");
        let key_path = out.join("operator-key.pem");
        let ca_path = out.join("ca.pem");

        std::fs::write(&cert_path, &bundle.cert_pem)?;
        std::fs::write(&key_path, &bundle.key_pem)?;
        std::fs::write(&ca_path, &bundle.ca_cert_pem)?;

        println!();
        println!("  ┌─ Operator certificate generated ──────────────────────────────────┐");
        println!("  │  Certificate : {}", cert_path.display());
        println!("  │  Private key : {}", key_path.display());
        println!("  │  CA cert     : {}", ca_path.display());
        println!("  │                                                                    │");
        println!("  │  For browser import, generate PKCS12 with:                         │");
        println!("  │  openssl pkcs12 -export -out operator.p12 \\                        │");
        println!("  │    -inkey operator-key.pem -in operator.pem -certfile ca.pem       │");
        println!("  │                                                                    │");
        println!("  │  Use operator.pem + operator-key.pem for the TUI client.           │");
        println!("  └────────────────────────────────────────────────────────────────────┘");
        println!();

        return Ok(());
    }

    tracing::info!("Starting SPECTER teamserver");

    specter_server::server::run_server(specter_server::server::ServerConfig {
        bind: cli.bind,
        grpc_port: cli.grpc_port,
        http_port: cli.http_port,
        db_path: cli.db_path,
        dev_mode: cli.dev_mode,
        web_ui_dir: cli.web_ui_dir,
    })
    .await
}
