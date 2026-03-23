# Phase 12: Redirector Orchestration & Infrastructure

This phase implements the redirector orchestration system and the Azure dead drop channel. Redirectors are the middle layer between implants and the teamserver — they forward C2 traffic while filtering non-matching requests with decoy responses. The orchestrator auto-deploys redirectors using Terraform/Pulumi templates across multiple cloud providers (CloudFlare, AWS, Azure, DigitalOcean), monitors their health, handles domain rotation when domains are burned, manages TLS certificates via Let's Encrypt ACME, and supports CDN domain fronting. The Azure dead drop channel provides an alternative comms path through Azure Blob Storage for environments where custom domain traffic is blocked but Azure endpoints are allowed. By the end of this phase, SPECTER's infrastructure is fully automated and resilient — operators can deploy, rotate, and burn infrastructure with single commands.

## Context

Redirectors are defined in YAML configuration and managed by the teamserver's orchestrator. They are not running SPECTER code — they are standard cloud resources (nginx reverse proxy, CDN config, cloud function) configured to forward traffic matching the malleable profile to the teamserver. The teamserver manages their lifecycle via cloud provider APIs through Terraform/Pulumi.

Teamserver source: `/Users/mdebaets/Documents/SPECTER/crates/specter-server/`
Infrastructure templates: `/Users/mdebaets/Documents/SPECTER/infrastructure/`

## Tasks

- [ ] Define redirector configuration schema and create the orchestrator framework:
  - Create `infrastructure/` directory at project root with subdirectories:
    - `infrastructure/terraform/` — Terraform template modules
    - `infrastructure/pulumi/` — Pulumi programs (TypeScript)
    - `infrastructure/configs/` — example redirector YAML configs
  - Create `crates/specter-server/src/redirector/mod.rs`:
    - Define `RedirectorConfig` struct (serde-deserializable from YAML):
      - id, name, type enum (CDN, CloudFunction, VPS, DomainFront)
      - provider enum (CloudFlare, AWS, GCP, Azure, DigitalOcean)
      - domain (String), alternative_domains (Vec<String>)
      - tls_cert_mode enum (LetsEncrypt, Custom, CDNManaged)
      - backend (teamserver listener endpoint URL)
      - filtering_rules: profile_id (traffic must match this profile), decoy_response (what to return for non-matching traffic)
      - health_check_interval_secs (default 60)
      - auto_rotate_on_block (bool, default true)
    - Define `RedirectorState` enum: Provisioning, Active, Degraded, Burning, Burned, Failed
    - Store redirector configs and state in SQLite `redirectors` table
  - Create `RedirectorOrchestrator` service:
    - `deploy(config: RedirectorConfig)` → provision infrastructure
    - `destroy(redirector_id)` → tear down infrastructure
    - `status(redirector_id)` → check current state
    - `burn(redirector_id)` → initiate domain burn sequence (tear down, provision replacement)
    - `health_check(redirector_id)` → verify redirector is functioning
    - `list()` → list all redirectors with their states

- [ ] Create Terraform templates for each provider:
  - Create `infrastructure/terraform/modules/cloudflare-cdn/` — CloudFlare CDN redirector:
    - `main.tf`: CloudFlare DNS record, CDN configuration, page rules for traffic forwarding
    - `variables.tf`: domain, backend_url, ssl_mode, origin_cert
    - `outputs.tf`: redirector URL, DNS record ID
    - CloudFlare Worker script for traffic filtering:
      - Inspect incoming requests against profile patterns (URI, headers)
      - Matching traffic: forward to teamserver backend
      - Non-matching traffic: serve decoy response (configurable: 404, redirect, mirror)
  - Create `infrastructure/terraform/modules/aws-cloudfront/` — AWS CloudFront CDN:
    - `main.tf`: CloudFront distribution, origin config pointing to teamserver, Lambda@Edge for traffic filtering
    - `variables.tf`: domain, certificate_arn, origin_domain
    - ACM certificate provisioning or import
    - Lambda@Edge function for request inspection/filtering
  - Create `infrastructure/terraform/modules/vps-nginx/` — generic VPS (DigitalOcean/AWS EC2):
    - `main.tf`: droplet/instance creation, security group, DNS record
    - `variables.tf`: provider_token, region, size, domain, backend_url
    - `cloud-init.yaml`: bootstrap nginx with reverse proxy config:
      - Forward matching traffic to teamserver
      - Serve decoy site for non-matching traffic
      - TLS via Let's Encrypt (certbot)
    - nginx.conf template with profile-aware location blocks
  - Create `infrastructure/terraform/modules/azure-function/` — Azure Functions redirector:
    - `main.tf`: Function App, Application Insights, Storage Account
    - Function code: HTTP trigger that filters and forwards traffic
    - Custom domain and TLS binding

- [ ] Implement the orchestrator's deployment and lifecycle management:
  - Create `crates/specter-server/src/redirector/deploy.rs`:
    - `deploy_terraform(config: &RedirectorConfig) -> Result<DeploymentResult>`:
      - Generate Terraform variable files from RedirectorConfig
      - Shell out to `terraform init` + `terraform apply -auto-approve` (or use terraform-exec library)
      - Parse terraform output for deployment results (URLs, IPs, resource IDs)
      - Store deployment state in database
    - `destroy_terraform(redirector_id) -> Result<()>`:
      - Load Terraform state for the redirector
      - Run `terraform destroy -auto-approve`
      - Clean up state files
    - State management: store Terraform state files in the database (as blobs) per redirector, not on disk — prevents state loss and enables multi-teamserver deployments
  - Create `crates/specter-server/src/redirector/health.rs`:
    - Background health check task (runs on configurable interval):
      - For each active redirector: send HTTP request to redirector's URL
      - Check: HTTP response code, TLS certificate validity, response body matches expected decoy
      - If health check fails N times consecutively: mark redirector as Degraded, alert operators
      - If domain blocked (returns cloud provider block page): initiate auto-burn if configured
    - `health_check_single(redirector_id)` → on-demand health check
    - Publish health events to the event bus for TUI/Web UI display

- [ ] Implement domain rotation and certificate management:
  - Create `crates/specter-server/src/redirector/rotation.rs`:
    - `burn_and_replace(redirector_id)` — domain burn sequence:
      1. Mark current redirector as Burning
      2. Destroy current infrastructure (terraform destroy)
      3. Mark as Burned (domain is compromised, never reuse)
      4. If replacement domain is available:
        - Create new RedirectorConfig with replacement domain, same backend/profile
        - Deploy new redirector
        - Push config update to all active implants on their next check-in:
          - Add new channel with new domain
          - Implants automatically pick up the new channel on next check-in
      5. Publish domain rotation event
    - `get_replacement_domain(provider)` → fetch next available domain from a pre-configured domain pool (stored in database table `domain_pool`: domain, provider, status [available, active, burned], registered_at)
  - Create `crates/specter-server/src/redirector/certs.rs`:
    - ACME certificate provisioning via Let's Encrypt:
      - Add `instant-acme` or `acme-lib` crate dependency
      - `provision_cert(domain)` → perform ACME challenge (HTTP-01 or DNS-01), obtain certificate
      - DNS-01 challenge: create TXT record via cloud provider API (preferred — works with CDN and domain fronting)
      - HTTP-01 challenge: serve challenge response on the redirector (simpler but requires HTTP access)
    - Certificate renewal monitoring:
      - Track certificate expiry dates in the database
      - Auto-renew certificates 30 days before expiry
      - Alert operators if renewal fails

- [ ] Implement CDN domain fronting support:
  - Create `crates/specter-server/src/redirector/fronting.rs`:
    - Domain fronting configuration:
      - `front_domain`: the high-reputation domain used in TLS SNI (e.g., a legitimate CDN customer domain)
      - `actual_domain`: the C2 domain in the HTTP Host header
      - CDN routes based on Host header, not SNI — traffic appears destined for front_domain in network logs
    - CloudFlare fronting setup:
      - Both front_domain and actual_domain must be on CloudFlare
      - Configure actual_domain's origin to point to teamserver
      - Implant's TLS SNI = front_domain, HTTP Host header = actual_domain
    - AWS CloudFront fronting:
      - Create CloudFront distribution for actual_domain
      - Implant connects to d1234567.cloudfront.net (or any CloudFront IP)
      - HTTP Host header specifies the actual_domain's distribution
    - Update implant comms config:
      - Profile includes fronting configuration: sni_domain, host_domain
      - Comms engine sets TLS SNI to sni_domain, HTTP Host header to host_domain
    - Update profile schema (Phase 06) to include fronting fields

- [ ] Implement the Azure dead drop channel:
  - Create `implant/core/src/comms/azure_deadrop.c` and `implant/core/include/comms_azure.h`:
    - **Azure Blob Storage as encrypted mailbox**:
      - Architecture: both implant and teamserver read/write from the same storage account
      - No direct implant-to-teamserver connection
    - **SAS token authentication**:
      - Per-implant SAS tokens with minimal permissions (read, write, list on specific container)
      - Token scoped to individual container (not account-wide — improvement over Loki C2)
      - Token stored in implant config, rotatable via config update
    - **Container structure**:
      - One container per implant: `session-{session_id_short}`
      - Blob naming: `command-{sequence_number}` (teamserver writes), `result-{sequence_number}` (implant writes)
      - Metadata blob: `metadata` (write-once by implant on registration, read by teamserver)
    - **Implant-side implementation**:
      - `azure_connect(sas_token, container_url)` → initialize Azure channel
      - `azure_send(data, len)` → encrypt data with session key, upload as blob `result-{seq}`
      - `azure_recv(buf, max_len)` → list blobs matching `command-*`, download newest unread, decrypt
      - `azure_disconnect()` → cleanup
      - `azure_health_check()` → list blobs in container, verify accessible
      - HTTP REST API to Azure Blob Storage (no Azure SDK — raw HTTP requests):
        - PUT `https://{account}.blob.core.windows.net/{container}/{blob}?{sas}` — upload blob
        - GET `https://{account}.blob.core.windows.net/{container}/{blob}?{sas}` — download blob
        - GET `https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&{sas}` — list blobs
      - All blob contents are encrypted with ChaCha20-Poly1305 before upload
  - Create `crates/specter-server/src/listener/azure_listener.rs`:
    - **Teamserver-side Azure dead drop listener**:
      - Periodically poll Azure containers for new `result-*` blobs
      - Download, decrypt, process as check-in data
      - Write `command-*` blobs with pending tasks
      - Clean up old blobs to prevent container bloat
    - **Container provisioning**:
      - On new implant build: create Azure storage container, generate SAS token
      - Store container URL and SAS in implant config
      - Azure SDK (`azure_storage_blobs` crate) for teamserver-side operations
    - **SAS token rotation**:
      - Generate new SAS tokens periodically
      - Push new token to implant via config update in a `command-*` blob
  - Add gRPC RPCs:
    - `CreateAzureListener(storage_account, access_key)` → configure Azure dead drop listener
    - `ListAzureContainers()` → show all active dead drop containers

- [ ] Write tests for redirector orchestration and Azure channel:
  - `crates/specter-server/tests/redirector_tests.rs`:
    - Test redirector config YAML parsing
    - Test state machine transitions (Provisioning → Active → Burning → Burned)
    - Test domain rotation logic (burn creates replacement with new domain)
    - Test health check state transitions (Active → Degraded after failures)
  - `crates/specter-server/tests/azure_listener_tests.rs`:
    - Test Azure blob naming convention
    - Test SAS token URL construction
    - Test blob content encryption/decryption roundtrip
    - Test container listing and blob polling logic (with mocked HTTP responses)
  - Add gRPC RPCs for redirector management:
    - `DeployRedirector`, `DestroyRedirector`, `BurnRedirector`
    - `ListRedirectors`, `GetRedirectorHealth`
    - `AddDomainToPool`, `ListDomainPool`
  - Run `cargo test --workspace`
