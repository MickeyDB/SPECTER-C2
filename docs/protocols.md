# Protocols & API Reference

## gRPC Service: SpecterService

The teamserver exposes a single gRPC service (`SpecterService`) with 40+ RPC methods. The web UI connects via gRPC-Web (served by `tonic-web`), while the TUI client uses native gRPC.

### Protobuf Definitions

All proto files are in `crates/specter-common/proto/specter/v1/`:

| File | Contents |
|------|----------|
| `specter_service.proto` | Main service definition (all RPCs) |
| `sessions.proto` | Session message types |
| `tasks.proto` | Task and result types |
| `listeners.proto` | Listener configuration types |
| `operators.proto` | Operator and auth types |
| `profiles.proto` | C2 profile types |
| `certificates.proto` | mTLS certificate types |
| `collaboration.proto` | Presence and chat types |
| `webhooks.proto` | Webhook configuration types |
| `campaigns.proto` | Campaign and membership types |
| `modules.proto` | Module repository types |
| `builder.proto` | Payload generation types |
| `azure.proto` | Azure dead-drop types |
| `reports.proto` | Engagement report types |

### RPC Methods by Domain

#### Sessions

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `ListSessions` | `ListSessionsRequest` | `ListSessionsResponse` | List all sessions (filtered by campaign access) |
| `GetSession` | `GetSessionRequest` | `GetSessionResponse` | Get single session by ID |

#### Tasks

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `QueueTask` | `QueueTaskRequest` | `QueueTaskResponse` | Queue a task for a session |
| `ListTasks` | `ListTasksRequest` | `ListTasksResponse` | List tasks for a session |
| `GetTaskResult` | `GetTaskResultRequest` | `GetTaskResultResponse` | Get result of a completed task |

#### Listeners

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `CreateListener` | `CreateListenerRequest` | `CreateListenerResponse` | Create a new listener |
| `ListListeners` | `ListListenersRequest` | `ListListenersResponse` | List all listeners |
| `StartListener` | `StartListenerRequest` | `StartListenerResponse` | Start a stopped listener |
| `StopListener` | `StopListenerRequest` | `StopListenerResponse` | Stop a running listener |

#### Operators & Auth

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `Authenticate` | `AuthenticateRequest` | `AuthenticateResponse` | Login with username/password |
| `ListOperators` | `ListOperatorsRequest` | `ListOperatorsResponse` | List registered operators |

#### Profiles

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `CreateProfile` | `CreateProfileRequest` | `CreateProfileResponse` | Upload a new C2 profile |
| `ListProfiles` | `ListProfilesRequest` | `ListProfilesResponse` | List available profiles |
| `GetProfile` | `GetProfileRequest` | `GetProfileResponse` | Get profile YAML by ID |
| `CompileProfile` | `CompileProfileRequest` | `CompileProfileResponse` | Compile profile to listener config |

#### Certificates (mTLS PKI)

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `IssueOperatorCertificate` | `IssueOperatorCertificateRequest` | `IssueOperatorCertificateResponse` | Issue client cert for operator |
| `RevokeOperatorCertificate` | `RevokeOperatorCertificateRequest` | `RevokeOperatorCertificateResponse` | Revoke a client certificate |
| `ListOperatorCertificates` | `ListOperatorCertificatesRequest` | `ListOperatorCertificatesResponse` | List issued certificates |
| `GetCACertificate` | `GetCACertificateRequest` | `GetCACertificateResponse` | Get CA root certificate |
| `RotateServerCertificate` | `RotateServerCertificateRequest` | `RotateServerCertificateResponse` | Rotate the server TLS cert |

#### Webhooks

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `CreateWebhook` | `CreateWebhookRequest` | `CreateWebhookResponse` | Create event forwarding webhook |
| `ListWebhooks` | `ListWebhooksRequest` | `ListWebhooksResponse` | List configured webhooks |
| `DeleteWebhook` | `DeleteWebhookRequest` | `DeleteWebhookResponse` | Delete a webhook |
| `TestWebhook` | `TestWebhookRequest` | `TestWebhookResponse` | Send test event to webhook |

Webhook formats: `GenericJSON`, `Slack`, `CEF`

#### Campaigns

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `CreateCampaign` | `CreateCampaignRequest` | `CreateCampaignResponse` | Create a new campaign |
| `ListCampaigns` | `ListCampaignsRequest` | `ListCampaignsResponse` | List campaigns |
| `GetCampaign` | `GetCampaignRequest` | `GetCampaignResponse` | Get campaign details |
| `AddSessionToCampaign` | `AddSessionToCampaignRequest` | `AddSessionToCampaignResponse` | Assign session to campaign |
| `RemoveSessionFromCampaign` | `RemoveSessionFromCampaignRequest` | `RemoveSessionFromCampaignResponse` | Remove session from campaign |
| `AddOperatorToCampaign` | `AddOperatorToCampaignRequest` | `AddOperatorToCampaignResponse` | Add operator to campaign |
| `RemoveOperatorFromCampaign` | `RemoveOperatorFromCampaignRequest` | `RemoveOperatorFromCampaignResponse` | Remove operator from campaign |

#### Modules

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `ListModules` | `ListModulesRequest` | `ListModulesResponse` | List available modules |
| `GetModuleInfo` | `GetModuleInfoRequest` | `GetModuleInfoResponse` | Get module details |
| `LoadModule` | `LoadModuleRequest` | `LoadModuleResponse` | Upload module to repository |

#### Builder (Payload Generation)

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `GeneratePayload` | `GeneratePayloadRequest` | `GeneratePayloadResponse` | Generate implant payload |
| `ListFormats` | `ListFormatsRequest` | `ListFormatsResponse` | List available output formats |
| `GetBuildStatus` | `GetBuildStatusRequest` | `GetBuildStatusResponse` | Check async build status |

**Output formats:** DLL, EXE, Service EXE, Stager

**Obfuscation options:** String encryption, junk code insertion, API hashing, control-flow graph flattening

#### Azure & Redirectors

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `CreateAzureListener` | `CreateAzureListenerRequest` | `CreateAzureListenerResponse` | Create Azure dead-drop listener |
| `ListAzureContainers` | `ListAzureContainersRequest` | `ListAzureContainersResponse` | List Azure blob containers |
| `DeployRedirector` | `DeployRedirectorRequest` | `DeployRedirectorResponse` | Deploy traffic redirector |
| `DestroyRedirector` | `DestroyRedirectorRequest` | `DestroyRedirectorResponse` | Tear down redirector |
| `BurnRedirector` | `BurnRedirectorRequest` | `BurnRedirectorResponse` | Emergency burn (rotate domain) |
| `ListRedirectors` | `ListRedirectorsRequest` | `ListRedirectorsResponse` | List deployed redirectors |
| `GetRedirectorHealth` | `GetRedirectorHealthRequest` | `GetRedirectorHealthResponse` | Check redirector health |
| `AddDomainToPool` | `AddDomainToPoolRequest` | `AddDomainToPoolResponse` | Add domain to available pool |

#### Collaboration

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `UpdatePresence` | `UpdatePresenceRequest` | `UpdatePresenceResponse` | Update operator presence |
| `GetActiveOperators` | `GetActiveOperatorsRequest` | `GetActiveOperatorsResponse` | List online operators |
| `SubscribePresence` | `SubscribePresenceRequest` | stream `PresenceUpdate` | Stream presence changes |
| `SendChatMessage` | `SendChatMessageRequest` | `SendChatMessageResponse` | Send chat message |
| `GetChatHistory` | `GetChatHistoryRequest` | `GetChatHistoryResponse` | Get chat history |
| `SubscribeChat` | `SubscribeChatRequest` | stream `ChatMessage` | Stream new chat messages |

#### Reports

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `GenerateReport` | `GenerateReportRequest` | `GenerateReportResponse` | Generate engagement report |
| `ListReports` | `ListReportsRequest` | `ListReportsResponse` | List generated reports |
| `GetReport` | `GetReportRequest` | `GetReportResponse` | Download a report |

Report formats: Markdown, JSON

#### Streaming

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `SubscribeEvents` | `SubscribeEventsRequest` | stream `Event` | Stream all system events |

**Event types:** SessionNew, SessionCheckin, SessionStale, SessionDead, TaskQueued, TaskDispatched, TaskComplete, TaskFailed, PresenceUpdate, ChatMessage

---

## HTTP Listener Protocol

### Default Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/checkin` | Implant check-in (session registration, task exchange) |
| POST | `/api/beacon` | Alternative check-in endpoint |
| GET | `/api/health` | Listener health check |

### Profile-Driven Endpoints

When a C2 profile is compiled and assigned to a listener, additional endpoints are generated dynamically from the profile's URI definitions. These can mimic legitimate web traffic patterns.

### Request/Response Format

Check-in payloads are encrypted:

```
POST /api/checkin HTTP/1.1
Content-Type: application/octet-stream

[4B LE payload length]
[12B implant pubkey prefix]
[12B nonce]
[ciphertext (LZ4-compressed JSON)]
[16B Poly1305 auth tag]
```

The response follows the same wire format.
