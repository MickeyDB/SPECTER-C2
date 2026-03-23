# Phase 08: Teamserver Security & mTLS

This phase hardens the teamserver with production-grade security: an embedded Certificate Authority (CA) for mTLS operator authentication (replacing API token auth from Phase 01), certificate lifecycle management (issuance, rotation, revocation with CRL), an immutable tamper-evident hash-chained audit log, the event webhook system (Slack, SIEM, custom endpoints), campaign management for grouping sessions/operations by engagement, and session isolation (operators only access authorized sessions). By the end, the teamserver uses mTLS for all operator connections, every action is cryptographically audited, and the system supports multi-operator engagements with proper access control.

## Context

Phase 01 implemented basic API token authentication and RBAC (admin, operator, observer). This phase replaces tokens with mTLS client certificates and adds the full security model. The teamserver acts as its own CA, issuing client certificates to operators. `--dev-mode` remains available for development.

Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`
Client source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-client\`
Search existing code in `src/auth/` to understand the current auth interceptor before replacing it.

## Tasks

- [x] Implement the embedded Certificate Authority:
  - Create `crates/specter-server/src/auth/ca.rs`:
    - Add dependencies: `rcgen` (cert generation), `rustls` (TLS), `x509-parser` (cert parsing)
    - `EmbeddedCA` struct with root CA keypair (Ed25519 or ECDSA P-256) and self-signed cert (10-year validity), stored in DB with private key encrypted at rest
    - `ca_init(db, master_key)` — first run: generate CA keypair + cert, store. Subsequent: load from DB.
    - `ca_issue_operator_cert(ca, username, role, validity_days)` — generate operator keypair + CSR, sign with CA, return PKCS12 bundle (.p12 with cert + key + chain), CN=username, OU=role
    - `ca_issue_server_cert(ca, hostnames)` — server TLS cert with SANs for provided hostnames + localhost
    - `ca_revoke_cert(ca, serial)` — add to CRL in database
    - `ca_check_revoked(ca, serial)`, `ca_get_root_cert(ca)` → PEM format
  - Create `crates/specter-server/src/auth/mtls.rs`:
    - Configure Tonic gRPC with mTLS via rustls: server cert from CA, client cert validation against CA root + CRL
    - `extract_operator_from_cert(cert)` — parse CN (username) and OU (role)
    - Replace token-based auth interceptor; maintain `--dev-mode` bypass
  - Add gRPC RPCs: IssueOperatorCertificate, RevokeOperatorCertificate, ListOperatorCertificates, GetCACertificate, RotateServerCertificate

- [x] Update TUI client for mTLS authentication:
  - Update `crates/specter-client/src/grpc_client.rs`:
    - Add CLI args: `--cert` (PKCS12 path), `--ca-cert` (CA cert PEM), `--cert-password` (prompted if not provided)
    - Configure tonic client with rustls mTLS
    - First-time setup flow (dev-mode): connect without cert → call IssueOperatorCertificate → save to `~/.specter/operator.p12` and `~/.specter/ca.pem` → reconnect with mTLS
  - Create `~/.specter/` config directory, store connection settings in `~/.specter/config.toml`

- [x] Implement the immutable tamper-evident audit log:
  - Create `crates/specter-server/src/audit/mod.rs`:
    - `AuditLog` backed by `audit_log` table: id, sequence_number (monotonic gap-free), timestamp (UTC ms), operator_id, action enum (SessionInteract, TaskQueue, TaskComplete, ModuleLoad, ListenerCreate, OperatorCreate, etc.), target, details (JSON), prev_hash (SHA-256 of previous entry), entry_hash
    - `audit_append(operator, action, target, details)` — fetch prev_hash, compute entry_hash = H(sequence ‖ timestamp ‖ operator ‖ action ‖ target ‖ details ‖ prev_hash), insert atomically
    - `audit_verify_chain()` — walk full chain, recompute hashes, detect tampering
    - `audit_query(filter)` — by operator, action, time range, target
    - `audit_export(format)` — JSON or CSV
  - Wire audit logging into all state-modifying gRPC handlers
  - ✅ Completed: 11 unit tests (chain integrity, tamper detection, filtering, export). All state-modifying gRPC handlers wired.

- [x] Implement event webhook system:
  - Create `crates/specter-server/src/event/webhooks.rs`:
    - `WebhookManager`: configured endpoints (URL, event filters, format), reqwest HTTP client, retry queue (3 retries, exponential backoff)
    - `webhooks` table: id, name, url, secret (HMAC signing), event_filters (JSON), format enum (Slack/GenericJSON/SIEM-CEF), enabled
    - Format payloads per webhook format, sign with HMAC-SHA256 in X-Signature header, POST to URL
    - Subscribe to internal event bus, forward matching events
  - Add gRPC RPCs: CreateWebhook, ListWebhooks, DeleteWebhook, TestWebhook
  - ✅ Completed: 14 unit tests (CRUD, HMAC signing, format payloads for GenericJSON/Slack/SIEM-CEF, event type mapping, filter persistence, proto roundtrip). All 469 workspace tests pass.

- [x] Implement campaign management and session isolation:
  - Create `crates/specter-server/src/campaign/mod.rs`:
    - `Campaign` struct, `campaigns` table, `campaign_sessions` and `campaign_operators` junction tables
    - `CampaignManager`: create_campaign, add_session, add_operator (with access_level enum Full/ReadOnly), check_access
    - Session isolation: update session-related gRPC handlers to check campaign-based access (ListSessions, GetSession, QueueTask only return/accept sessions the operator has access to via campaigns; Admin bypasses all)
    - Auto-assign new sessions to campaign associated with receiving listener
  - Add gRPC RPCs: CreateCampaign, ListCampaigns, GetCampaign, AddSessionToCampaign, AddOperatorToCampaign, etc.
  - ✅ Completed: 15 unit tests (CRUD, session isolation, admin bypass, access levels, listener association). CampaignManager with Full/ReadOnly access levels, session isolation on ListSessions/GetSession/QueueTask/ListTasks. All 483 workspace tests pass.

- [x] Write tests for security features:
  - `ca_tests.rs` — CA init, cert issuance, PKCS12 generation, revocation, CRL checking, mTLS with valid/revoked certs
  - `audit_tests.rs` — append + hash chain integrity, tamper detection, query filtering, export formats
  - `campaign_tests.rs` — session isolation, admin bypass, campaign membership
  - Run `cargo test --workspace`
  - ✅ Completed: Created `audit_tests.rs` (15 integration tests: hash chain integrity, tamper detection for entry_hash/prev_hash/content, sequence monotonicity, query filtering by operator/action/target/combined, JSON/CSV export, filtered export, unique IDs) and `campaign_tests.rs` (17 integration tests: CRUD, membership, session isolation, admin bypass, no-campaigns fallback, read-only access, access level updates, operator removal revokes access, listener association, multi-campaign union access). Existing `ca_tests.rs` already had 8 integration tests covering CA init, cert issuance, PKCS12, revocation, CRL, mTLS. All 511 workspace tests pass.
