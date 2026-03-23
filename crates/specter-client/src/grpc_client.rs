use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::Request;

use specter_common::proto::specter::v1::specter_service_client::SpecterServiceClient;
use specter_common::proto::specter::v1::*;

use crate::app::ConnectionStatus;
use crate::config;

/// Updates sent from background gRPC tasks to the TUI main loop.
#[allow(dead_code)]
pub enum AppUpdate {
    Sessions(Vec<SessionInfo>),
    ConnectionStatus(ConnectionStatus),
    Event(Box<Event>),
}

/// TLS material for mTLS connections.
#[derive(Clone)]
pub struct TlsCredentials {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_cert_pem: Vec<u8>,
}

/// Connection mode for the client.
#[derive(Clone)]
pub enum AuthMode {
    /// Dev mode: no authentication.
    DevMode,
    /// Token-based authentication (legacy).
    Token(String),
    /// mTLS with client certificate.
    Mtls(Arc<TlsCredentials>),
}

pub struct SpecterClient {
    endpoint: String,
    auth_mode: AuthMode,
}

impl SpecterClient {
    pub fn new(endpoint: String, auth_mode: AuthMode) -> Self {
        Self {
            endpoint,
            auth_mode,
        }
    }

    /// Build a tonic channel, optionally with mTLS.
    async fn connect(&self) -> Result<SpecterServiceClient<Channel>, Box<dyn std::error::Error>> {
        let channel = match &self.auth_mode {
            AuthMode::Mtls(creds) => {
                let tls = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(&creds.ca_cert_pem))
                    .identity(Identity::from_pem(&creds.cert_pem, &creds.key_pem))
                    .domain_name("localhost");

                Endpoint::from_shared(self.endpoint.clone())?
                    .tls_config(tls)?
                    .connect()
                    .await?
            }
            _ => {
                Endpoint::from_shared(self.endpoint.clone())?
                    .connect()
                    .await?
            }
        };
        Ok(SpecterServiceClient::new(channel))
    }

    /// Get the token if in token mode, for attaching to requests.
    fn token(&self) -> Option<String> {
        match &self.auth_mode {
            AuthMode::Token(t) => Some(t.clone()),
            _ => None,
        }
    }

    /// Queue a task on a session (for future interactive use).
    #[allow(dead_code)]
    pub async fn queue_task(
        &self,
        session_id: &str,
        task_type: &str,
        args: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let mut request = Request::new(QueueTaskRequest {
            session_id: session_id.to_string(),
            task_type: task_type.to_string(),
            arguments: args.to_vec(),
            priority: TaskPriority::Normal.into(),
            operator_id: String::new(),
        });
        attach_auth(&self.token(), &mut request);
        let response = client.queue_task(request).await?;
        Ok(response.into_inner().task_id)
    }

    /// List all available modules from the teamserver.
    #[allow(dead_code)]
    pub async fn list_modules(&self) -> Result<Vec<ModuleInfo>, Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let mut request = Request::new(ListModulesRequest {});
        attach_auth(&self.token(), &mut request);
        let response = client.list_modules(request).await?;
        Ok(response.into_inner().modules)
    }

    /// Load a module on a session (packages, encrypts, and queues for delivery).
    #[allow(dead_code)]
    pub async fn load_module(
        &self,
        session_id: &str,
        module_name: &str,
        args: &[u8],
    ) -> Result<LoadModuleResponse, Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let mut request = Request::new(LoadModuleRequest {
            session_id: session_id.to_string(),
            module_name: module_name.to_string(),
            arguments: args.to_vec(),
        });
        attach_auth(&self.token(), &mut request);
        let response = client.load_module(request).await?;
        Ok(response.into_inner())
    }

    /// Spawn background tokio tasks that periodically fetch sessions and
    /// subscribe to the event stream, sending updates through the channel.
    pub fn start_background_tasks(&self, update_tx: mpsc::UnboundedSender<AppUpdate>) {
        let endpoint = self.endpoint.clone();
        let auth_mode = self.auth_mode.clone();

        // ── Periodic session fetch with auto-reconnect ──────────────────
        let fetch_tx = update_tx.clone();
        let fetch_endpoint = endpoint.clone();
        let fetch_auth = auth_mode.clone();

        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(30);

            loop {
                match connect_channel(&fetch_endpoint, &fetch_auth).await {
                    Ok(channel) => {
                        let mut client = SpecterServiceClient::new(channel);
                        let _ =
                            fetch_tx.send(AppUpdate::ConnectionStatus(ConnectionStatus::Connected));
                        backoff = Duration::from_secs(1);

                        loop {
                            let mut request = Request::new(ListSessionsRequest {});
                            attach_auth(&token_from_auth(&fetch_auth), &mut request);
                            match client.list_sessions(request).await {
                                Ok(response) => {
                                    let _ = fetch_tx
                                        .send(AppUpdate::Sessions(response.into_inner().sessions));
                                    tokio::time::sleep(Duration::from_secs(2)).await;
                                }
                                Err(e) => {
                                    tracing::warn!("Session fetch failed: {e}");
                                    let _ = fetch_tx.send(AppUpdate::ConnectionStatus(
                                        ConnectionStatus::Disconnected,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Connect failed: {e}");
                        let _ = fetch_tx
                            .send(AppUpdate::ConnectionStatus(ConnectionStatus::Disconnected));
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        });

        // ── Event subscription with auto-reconnect ──────────────────────
        let event_tx = update_tx;

        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(30);

            loop {
                match connect_channel(&endpoint, &auth_mode).await {
                    Ok(channel) => {
                        let mut client = SpecterServiceClient::new(channel);
                        let mut request = Request::new(SubscribeEventsRequest {});
                        attach_auth(&token_from_auth(&auth_mode), &mut request);
                        match client.subscribe_events(request).await {
                            Ok(response) => {
                                backoff = Duration::from_secs(1);
                                let mut stream = response.into_inner();
                                while let Ok(Some(event)) = stream.message().await {
                                    let _ = event_tx.send(AppUpdate::Event(Box::new(event)));
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Event subscribe failed: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Event connect failed: {e}");
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        });
    }

    /// Send a chat message via the teamserver.
    pub async fn send_chat_message(
        &self,
        content: &str,
        channel: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;
        let mut request = Request::new(SendChatMessageRequest {
            content: content.to_string(),
            channel: channel.to_string(),
        });
        attach_auth(&self.token(), &mut request);
        client.send_chat_message(request).await?;
        Ok(())
    }

    /// Generate an engagement report for a campaign.
    #[allow(dead_code)]
    pub async fn generate_report(
        &self,
        campaign_id: &str,
        format: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut client = self.connect().await?;

        let format_proto = match format {
            "json" => 1, // REPORT_FORMAT_JSON
            _ => 0,      // REPORT_FORMAT_MARKDOWN
        };

        let mut request = Request::new(GenerateReportRequest {
            campaign_id: campaign_id.to_string(),
            time_range_start: None,
            time_range_end: None,
            include_sections: Some(ReportIncludeSections {
                timeline: true,
                ioc_list: true,
                findings: true,
                recommendations: true,
            }),
            operator_filter: String::new(),
            format: format_proto,
        });
        attach_auth(&self.token(), &mut request);
        let response = client.generate_report(request).await?;
        let report = response
            .into_inner()
            .report
            .ok_or("No report in response")?;
        Ok(report.content)
    }
}

/// First-time setup: connect in dev-mode, request an operator certificate,
/// and save it to `~/.specter/`.
pub async fn first_time_cert_setup(
    endpoint: &str,
    username: &str,
    role: &str,
) -> Result<TlsCredentials, Box<dyn std::error::Error>> {
    tracing::info!("Starting first-time certificate setup for {username}");

    // Connect without TLS (dev-mode server)
    let mut client = SpecterServiceClient::connect(endpoint.to_string()).await?;

    let response = client
        .issue_operator_certificate(Request::new(IssueOperatorCertificateRequest {
            username: username.to_string(),
            role: role.to_string(),
            validity_days: 365,
        }))
        .await?;

    let resp = response.into_inner();

    // Save certificate bundle to ~/.specter/
    let (cert_path, key_path, ca_path) =
        config::save_cert_bundle(&resp.cert_pem, &resp.key_pem, &resp.ca_cert_pem)?;

    // Update config with paths
    let mut cfg = config::load_config();
    cfg.server = Some(endpoint.to_string());
    cfg.cert_path = Some(cert_path.display().to_string());
    cfg.key_path = Some(key_path.display().to_string());
    cfg.ca_cert_path = Some(ca_path.display().to_string());
    config::save_config(&cfg)?;

    tracing::info!("Certificate saved to ~/.specter/");

    Ok(TlsCredentials {
        cert_pem: resp.cert_pem.into_bytes(),
        key_pem: resp.key_pem.into_bytes(),
        ca_cert_pem: resp.ca_cert_pem.into_bytes(),
    })
}

/// Load TLS credentials from PEM files on disk.
pub fn load_tls_credentials(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: &str,
) -> Result<TlsCredentials, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    let ca_cert_pem = std::fs::read(ca_cert_path)?;
    Ok(TlsCredentials {
        cert_pem,
        key_pem,
        ca_cert_pem,
    })
}

/// Build a tonic Channel with optional mTLS.
async fn connect_channel(
    endpoint: &str,
    auth_mode: &AuthMode,
) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
    match auth_mode {
        AuthMode::Mtls(creds) => {
            let tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(&creds.ca_cert_pem))
                .identity(Identity::from_pem(&creds.cert_pem, &creds.key_pem))
                .domain_name("localhost");

            Ok(Endpoint::from_shared(endpoint.to_string())?
                .tls_config(tls)?
                .connect()
                .await?)
        }
        _ => Ok(Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?),
    }
}

fn token_from_auth(auth_mode: &AuthMode) -> Option<String> {
    match auth_mode {
        AuthMode::Token(t) => Some(t.clone()),
        _ => None,
    }
}

fn attach_auth<T>(token: &Option<String>, request: &mut Request<T>) {
    if let Some(token) = token {
        if let Ok(val) = format!("Bearer {token}").parse() {
            request.metadata_mut().insert("authorization", val);
        }
    }
}
