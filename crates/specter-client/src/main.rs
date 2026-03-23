use clap::Parser;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

mod app;
mod commands;
mod config;
mod event_handler;
mod grpc_client;
pub mod input;
pub mod notifications;
pub mod search;
mod tui;
mod ui;

use app::App;
use grpc_client::{AuthMode, SpecterClient};

use std::sync::Arc;

#[derive(Parser)]
#[command(name = "specter-client", about = "SPECTER C2 TUI Client")]
struct Cli {
    /// Teamserver gRPC address
    #[arg(long, default_value = "http://localhost:50051")]
    server: String,

    /// API authentication token
    #[arg(long)]
    token: Option<String>,

    /// Path to operator certificate PEM file
    #[arg(long)]
    cert: Option<String>,

    /// Path to operator private key PEM file
    #[arg(long)]
    key: Option<String>,

    /// Path to CA certificate PEM file
    #[arg(long)]
    ca_cert: Option<String>,

    /// Connect without authentication (development mode)
    #[arg(long, default_value_t = false)]
    dev_mode: bool,

    /// First-time setup: issue a certificate via dev-mode server
    #[arg(long)]
    setup: bool,

    /// Operator username for first-time setup
    #[arg(long, default_value = "operator")]
    username: String,

    /// Operator role for first-time setup (ADMIN, OPERATOR, OBSERVER)
    #[arg(long, default_value = "OPERATOR")]
    role: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    // Determine auth mode
    let auth_mode = resolve_auth_mode(&cli).await?;

    let (update_tx, update_rx) = mpsc::unbounded_channel();

    let client = SpecterClient::new(cli.server.clone(), auth_mode);
    client.start_background_tasks(update_tx);

    let mut app = App::new(cli.server);
    tui::run(&mut app, update_rx, &client).await?;

    Ok(())
}

/// Determine the authentication mode from CLI args, config, and on-disk certs.
async fn resolve_auth_mode(cli: &Cli) -> Result<AuthMode, Box<dyn std::error::Error>> {
    // 1. First-time setup flow
    if cli.setup {
        eprintln!("Performing first-time certificate setup...");
        let creds =
            grpc_client::first_time_cert_setup(&cli.server, &cli.username, &cli.role).await?;
        eprintln!("Certificate saved to ~/.specter/");
        // Switch endpoint to https for mTLS
        return Ok(AuthMode::Mtls(Arc::new(creds)));
    }

    // 2. Dev mode (no auth)
    if cli.dev_mode {
        return Ok(AuthMode::DevMode);
    }

    // 3. Explicit token
    if let Some(ref token) = cli.token {
        return Ok(AuthMode::Token(token.clone()));
    }

    // 4. Explicit cert paths from CLI
    if let (Some(cert), Some(key), Some(ca)) = (&cli.cert, &cli.key, &cli.ca_cert) {
        let creds = grpc_client::load_tls_credentials(cert, key, ca)?;
        return Ok(AuthMode::Mtls(Arc::new(creds)));
    }

    // 5. Check saved config for cert paths
    let cfg = config::load_config();
    if let (Some(cert), Some(key), Some(ca)) = (&cfg.cert_path, &cfg.key_path, &cfg.ca_cert_path) {
        match grpc_client::load_tls_credentials(cert, key, ca) {
            Ok(creds) => return Ok(AuthMode::Mtls(Arc::new(creds))),
            Err(e) => {
                tracing::warn!("Failed to load saved certificates: {e}");
            }
        }
    }

    // 6. Check default cert locations in ~/.specter/
    if let Some((cert, key, ca)) = config::default_cert_paths() {
        match grpc_client::load_tls_credentials(
            &cert.display().to_string(),
            &key.display().to_string(),
            &ca.display().to_string(),
        ) {
            Ok(creds) => return Ok(AuthMode::Mtls(Arc::new(creds))),
            Err(e) => {
                tracing::warn!("Failed to load default certificates: {e}");
            }
        }
    }

    // 7. Fallback to dev mode with warning
    eprintln!(
        "Warning: No authentication configured. Use --token, --cert/--key/--ca-cert, or --setup."
    );
    eprintln!("Connecting without authentication (dev mode).");
    Ok(AuthMode::DevMode)
}
