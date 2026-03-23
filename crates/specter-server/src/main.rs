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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

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
