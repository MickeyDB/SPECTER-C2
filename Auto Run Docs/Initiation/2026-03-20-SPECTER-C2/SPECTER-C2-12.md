# Phase 12: Redirector Orchestration & Infrastructure

This phase implements the redirector orchestration system and the Azure dead drop channel. Redirectors forward C2 traffic while filtering non-matching requests with decoy responses. The orchestrator auto-deploys redirectors via Terraform across cloud providers (CloudFlare, AWS, Azure, DigitalOcean), monitors health, handles domain rotation when burned, manages TLS certificates via Let's Encrypt ACME, and supports CDN domain fronting. The Azure dead drop channel provides comms through Azure Blob Storage for environments where custom domains are blocked but Azure endpoints are allowed. By the end, SPECTER's infrastructure is fully automated — operators deploy, rotate, and burn infrastructure with single commands.

## Context

Redirectors are YAML-configured and managed by the teamserver's orchestrator. They are standard cloud resources (nginx reverse proxy, CDN config, cloud function) configured to forward profile-matching traffic to the teamserver. The teamserver manages their lifecycle via Terraform.

Teamserver source: `C:\Users\localuser\Documents\SPECTER-C2\crates\specter-server\`
Infrastructure templates: `C:\Users\localuser\Documents\SPECTER-C2\infrastructure\`

## Tasks

- [x] Define redirector configuration and orchestrator framework:
  - Create `infrastructure/` at project root with `terraform/`, `configs/` subdirectories
  - Create `crates/specter-server/src/redirector/mod.rs`:
    - `RedirectorConfig` struct (serde/YAML): id, name, type (CDN/CloudFunction/VPS/DomainFront), provider (CloudFlare/AWS/GCP/Azure/DigitalOcean), domain, alternative_domains, tls_cert_mode, backend URL, filtering_rules (profile_id, decoy_response), health_check_interval, auto_rotate_on_block
    - `RedirectorState` enum: Provisioning, Active, Degraded, Burning, Burned, Failed
    - `RedirectorOrchestrator`: deploy, destroy, status, burn, health_check, list
    - Store configs and state in SQLite `redirectors` table

- [x] Create Terraform templates for each provider:
  - `infrastructure/terraform/modules/cloudflare-cdn/` — CloudFlare DNS + CDN + Worker script for traffic filtering (inspect URI/headers, forward matches to backend, serve decoy for others)
  - `infrastructure/terraform/modules/aws-cloudfront/` — CloudFront distribution + Lambda@Edge for request inspection + ACM certificate
  - `infrastructure/terraform/modules/vps-nginx/` — DigitalOcean/EC2 droplet + cloud-init with nginx reverse proxy + certbot TLS + profile-aware location blocks
  - `infrastructure/terraform/modules/azure-function/` — Function App + HTTP trigger for filtering/forwarding + custom domain + TLS

- [x] Implement deployment, health checking, and domain rotation:
  - Create `crates/specter-server/src/redirector/deploy.rs`:
    - `deploy_terraform(config)` — generate var files → terraform init + apply → parse outputs → store state in DB
    - `destroy_terraform(id)` — load state → terraform destroy → cleanup
    - Store Terraform state files as DB blobs (prevents state loss, enables multi-teamserver)
  - Create `crates/specter-server/src/redirector/health.rs`:
    - Background health check: HTTP request to redirector URL, check response code + TLS + decoy body, mark Degraded after N failures, auto-burn if domain blocked
  - Create `crates/specter-server/src/redirector/rotation.rs`:
    - `burn_and_replace(id)` — mark Burning → destroy → mark Burned → deploy replacement from domain pool → push config update to implants
    - `domain_pool` table: domain, provider, status (available/active/burned)
  - Create `crates/specter-server/src/redirector/certs.rs`:
    - ACME via `instant-acme` or similar: DNS-01/HTTP-01 challenges, auto-renew 30 days before expiry

- [x] Implement CDN domain fronting support:
  - Create `crates/specter-server/src/redirector/fronting.rs`:
    - Config: front_domain (high-reputation in TLS SNI) + actual_domain (in HTTP Host header)
    - CloudFlare fronting: both domains on CloudFlare, actual_domain origin → teamserver
    - AWS CloudFront: distribution for actual_domain, implant connects to cloudfront.net with Host header
    - Update implant comms config: sni_domain for TLS, host_domain for HTTP Host
    - Update profile schema to include fronting fields
  - **Completed**: Created `fronting.rs` with `DomainFrontingConfig`, `FrontingSetup`, validation for CloudFlare/AWS providers, and `ImplantFrontingUpdate`. Added `fronting` field to `RedirectorConfig`. Updated `profiles.proto` with `DomainFrontingConfig` message. Updated implant `CHANNEL_CONFIG` with `sni_domain`/`host_domain` fields and added fronting helpers to `comms.h`. 11 tests covering all validation paths.

- [x] Implement the Azure dead drop channel:
  - Create `implant/core/src/comms/azure_deadrop.c` and `implant/core/include/comms_azure.h`:
    - Azure Blob Storage as encrypted mailbox: both sides read/write same storage account, no direct connection
    - Per-implant SAS tokens scoped to individual container (not account-wide)
    - Container per implant: `session-{id}`, blobs: `command-{seq}` (teamserver), `result-{seq}` (implant), `metadata` (registration)
    - Raw HTTP REST API (no Azure SDK): PUT/GET/LIST via `https://{account}.blob.core.windows.net/{container}/{blob}?{sas}`
    - All blob contents encrypted with ChaCha20-Poly1305 before upload
    - Channel interface: azure_connect, azure_send, azure_recv, azure_disconnect, azure_health_check
  - Create `crates/specter-server/src/listener/azure_listener.rs`:
    - Poll Azure containers for `result-*` blobs, download/decrypt/process, write `command-*` blobs with tasks, clean old blobs
    - Container provisioning on implant build, SAS token rotation via config updates
    - Add `azure_storage_blobs` crate
  - Add gRPC RPCs: CreateAzureListener, ListAzureContainers, DeployRedirector, DestroyRedirector, BurnRedirector, ListRedirectors, GetRedirectorHealth, AddDomainToPool

- [x] Write tests for redirector orchestration and Azure channel:
  - `redirector_tests.rs` — config parsing, state machine transitions, domain rotation, health check states
  - `azure_listener_tests.rs` — blob naming, SAS URL construction, encryption roundtrip, polling logic (mocked HTTP)
  - Run `cargo test --workspace`
  - **Completed**: Created `tests/redirector_tests.rs` (25 tests) and `tests/azure_listener_tests.rs` (30 tests). Redirector tests cover: YAML/JSON config roundtrips, default values, all enum variant roundtrips, valid/invalid/self/terminal state transitions, orchestrator deploy/list/status/health_check/burn/destroy lifecycle, domain pool operations. Azure tests cover: blob naming zero-padding, sequence parsing, SAS URL construction (blob/list/create-container), encryption roundtrip (random key, empty, large, wrong key, too short, tampered, nonce uniqueness), hex key parsing, XML blob name parsing, listener manager CRUD and serialization roundtrip. All 55 new tests pass. Full `cargo test --workspace` passes.
