# Phase 08: Teamserver Security & mTLS

This phase hardens the teamserver with production-grade security: an embedded Certificate Authority (CA) for mTLS operator authentication (replacing the API token auth from Phase 01), certificate lifecycle management (issuance, rotation, revocation), an immutable tamper-evident audit log (hash-chained), the event webhook system (Slack, SIEM, custom endpoints), campaign management (grouping sessions and operations by engagement), and session isolation (operators can only access authorized sessions). By the end of this phase, the teamserver uses mTLS for all operator connections, every action is cryptographically audited, and the system is ready for multi-operator engagements with proper access control.

## Context

Phase 01 implemented basic API token authentication and RBAC roles (admin, operator, observer). This phase replaces token auth with mTLS client certificates and adds the full security model from the spec. The teamserver acts as its own CA, issuing client certificates to operators. Certificate-based auth is more secure and enables operator identification without password transmission.

Teamserver source: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`
Client source: `/Users/mdebaets/Documents/SPECTER/crates/specter-client/`

## Tasks

- [ ] Implement the embedded Certificate Authority in the teamserver:
  - Create `crates/specter-server/src/auth/ca.rs`:
    - Add dependencies: `rcgen` (certificate generation), `rustls` (TLS), `x509-parser` (certificate parsing)
    - `EmbeddedCA` struct:
      - Root CA private key (Ed25519 or ECDSA P-256) and self-signed certificate
      - CA cert validity: 10 years
      - CA cert stored in the database, private key encrypted at rest with a server master key
    - `ca_init(db, master_key)` → on first run: generate root CA keypair + self-signed cert, store in DB. On subsequent runs: load from DB.
    - `ca_issue_operator_cert(ca, username, role, validity_days)` → generate operator keypair + CSR, sign with CA, return PKCS12 bundle (.p12 file containing cert + private key + CA chain)
      - Certificate subject: CN=username, O=SPECTER, OU=role
      - Certificate extensions: custom OID for RBAC role embedding
      - Default validity: 365 days
    - `ca_issue_server_cert(ca, hostnames)` → generate server TLS certificate signed by CA, with SANs for provided hostnames + localhost + 127.0.0.1
    - `ca_revoke_cert(ca, serial_number)` → add serial to CRL (Certificate Revocation List) in database
    - `ca_check_revoked(ca, serial_number)` → check if certificate is revoked
    - `ca_get_root_cert(ca)` → return root CA certificate (PEM format, for clients to trust)
  - Create `crates/specter-server/src/auth/mtls.rs`:
    - Configure Tonic gRPC server with mTLS using rustls:
      - Server certificate: issued by the embedded CA
      - Client certificate validation: verify against CA root, check CRL, extract operator identity from cert subject
      - Reject expired or revoked certificates
    - `extract_operator_from_cert(cert)` → parse CN (username) and OU (role) from client cert
    - Replace the token-based auth interceptor from Phase 01 with certificate-based auth
    - Maintain `--dev-mode` flag: when set, accept connections without client certs (for development)
  - Add gRPC RPCs for certificate management:
    - `IssueOperatorCertificate(username, role, validity_days)` → admin-only, returns PKCS12 bundle
    - `RevokeOperatorCertificate(username)` → admin-only, revokes the operator's cert
    - `ListOperatorCertificates()` → admin-only, returns list of issued certs with status (valid/revoked/expired)
    - `GetCACertificate()` → returns the root CA cert (PEM) — any role can call this
    - `RotateServerCertificate(hostnames)` → admin-only, reissue server cert with new hostnames

- [ ] Update the TUI client for mTLS authentication:
  - Update `crates/specter-client/src/grpc_client.rs`:
    - Add `--cert` CLI arg: path to operator's PKCS12 file
    - Add `--ca-cert` CLI arg: path to CA root certificate (PEM)
    - Add `--cert-password` CLI arg: password for PKCS12 file (prompted interactively if not provided)
    - Configure tonic client with rustls:
      - Load client certificate from PKCS12
      - Set CA root for server verification
      - Enable mTLS
    - Connection flow:
      1. Load client cert and CA cert
      2. Create TLS config with mTLS
      3. Connect to teamserver
      4. On successful connection: display operator identity from cert in status bar
    - First-time setup flow (when `--dev-mode` is used):
      1. Connect without cert
      2. Call IssueOperatorCertificate (using default admin creds from Phase 01)
      3. Save PKCS12 to `~/.specter/operator.p12`
      4. Save CA cert to `~/.specter/ca.pem`
      5. Reconnect with mTLS
  - Create `~/.specter/` config directory on first run
  - Store connection settings in `~/.specter/config.toml` (server address, cert paths)

- [ ] Implement the immutable tamper-evident audit log:
  - Create `crates/specter-server/src/audit/mod.rs`:
    - `AuditLog` struct backed by a dedicated SQLite table `audit_log`:
      - id (auto-increment)
      - sequence_number (monotonic, gap-free)
      - timestamp (UTC, millisecond precision)
      - operator_id (from cert CN)
      - action (enum: SessionInteract, TaskQueue, TaskComplete, ModuleLoad, ListenerCreate, ListenerStart, OperatorCreate, OperatorRevoke, ConfigChange, SystemStart, SystemStop)
      - target (session_id, listener_id, or other context-specific ID)
      - details (JSON blob with action-specific data)
      - prev_hash (SHA-256 hash of the previous log entry — creates a hash chain)
      - entry_hash (SHA-256 hash of this entry: H(sequence || timestamp || operator || action || target || details || prev_hash))
    - `audit_append(operator, action, target, details)` → create new audit entry:
      - Fetch prev_hash from the last entry
      - Compute entry_hash
      - Insert atomically
      - The hash chain makes it tamper-evident: modifying any past entry breaks the chain
    - `audit_verify_chain()` → walk the full chain, recompute hashes, detect any tampering
    - `audit_query(filter)` → query log with filters: by operator, by action, by time range, by target
    - `audit_export(format)` → export log as JSON or CSV for compliance reporting
  - Wire audit logging into all teamserver operations:
    - Task submission, task completion, session interactions, operator management, listener management, config changes
    - Every gRPC handler that modifies state must call `audit_append()` with the authenticated operator identity

- [ ] Implement the event webhook system:
  - Create `crates/specter-server/src/event/webhooks.rs`:
    - `WebhookManager` struct:
      - List of configured webhook endpoints (URL, event filters, format)
      - HTTP client (reqwest) for sending webhook payloads
      - Retry queue for failed deliveries (3 retries with exponential backoff)
    - Webhook configuration stored in database:
      - `webhooks` table: id, name, url, secret (for HMAC signing), event_filters (JSON array of event types), format enum (Slack, Generic JSON, SIEM/CEF), enabled, created_at
    - `webhook_send(event)` → for each configured webhook that matches the event type:
      - Format payload according to webhook's format setting
      - Slack format: `{"text": "SPECTER: New session from DESKTOP-1234 (admin@CORP)", "blocks": [...]}`
      - Generic JSON: `{"event_type": "session_new", "timestamp": "...", "data": {...}}`
      - SIEM/CEF: Common Event Format string
      - Sign payload with HMAC-SHA256 using webhook secret (in X-Signature header)
      - POST payload to webhook URL
      - On failure: enqueue for retry
    - Subscribe to the internal event bus (from Phase 01) and forward matching events to webhooks
  - Add gRPC RPCs:
    - `CreateWebhook(name, url, secret, events, format)` → admin-only
    - `ListWebhooks()` → admin-only
    - `DeleteWebhook(id)` → admin-only
    - `TestWebhook(id)` → send a test event to verify connectivity

- [ ] Implement campaign management and session isolation:
  - Create `crates/specter-server/src/campaign/mod.rs`:
    - `Campaign` struct: id, name, description, start_date, end_date, status (Active, Completed, Archived), created_by
    - `campaigns` table in SQLite
    - `campaign_sessions` junction table: campaign_id, session_id (sessions can belong to multiple campaigns)
    - `campaign_operators` junction table: campaign_id, operator_id, access_level enum (Full, ReadOnly)
    - `CampaignManager`:
      - `create_campaign(name, description, operator_id)` → create new campaign, assign creator as Full access
      - `add_session_to_campaign(campaign_id, session_id)` → associate a session with a campaign
      - `add_operator_to_campaign(campaign_id, operator_id, access_level)` → grant operator access to campaign
      - `check_access(operator_id, session_id)` → verify operator has access to the session via campaign membership
  - Implement session isolation:
    - Update all session-related gRPC handlers to check campaign-based access:
      - `ListSessions` → only return sessions the operator has access to (via campaigns)
      - `GetSession` / `QueueTask` / `GetTaskResult` → verify operator access to the target session
      - Admin role bypasses all access checks
    - When a new session checks in: auto-assign to the campaign associated with the listener that received the check-in
  - Add gRPC RPCs:
    - `CreateCampaign`, `ListCampaigns`, `GetCampaign`, `UpdateCampaign`
    - `AddSessionToCampaign`, `RemoveSessionFromCampaign`
    - `AddOperatorToCampaign`, `RemoveOperatorFromCampaign`

- [ ] Write tests for security features:
  - `crates/specter-server/tests/ca_tests.rs`:
    - Test CA initialization (first run generates CA, second run loads it)
    - Test operator certificate issuance and PKCS12 generation
    - Test certificate revocation and CRL checking
    - Test server certificate generation with SANs
    - Test mTLS connection with valid cert succeeds
    - Test mTLS connection with revoked cert is rejected
  - `crates/specter-server/tests/audit_tests.rs`:
    - Test audit log append and hash chain integrity
    - Test chain verification detects tampering (modify an entry, verify fails)
    - Test query filtering by operator, action, time range
    - Test export format correctness
  - `crates/specter-server/tests/campaign_tests.rs`:
    - Test session isolation (operator A cannot see operator B's sessions without campaign access)
    - Test admin bypass
    - Test campaign membership management
  - Run `cargo test --workspace`
