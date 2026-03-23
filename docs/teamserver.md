# Teamserver Documentation

The teamserver (`specter-server`) is the central component of SPECTER. It manages sessions, tasks, listeners, operators, and provides the gRPC API consumed by operator clients.

## Architecture

```
┌────────────────────────────────────────────────────┐
│                   Teamserver                       │
│                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ gRPC API │  │HTTP/WS   │  │ Azure Dead-Drop  │ │
│  │ (Tonic)  │  │Listeners │  │ Listener         │ │
│  │ +Web     │  │ (Axum)   │  │                  │ │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
│       │              │                 │           │
│  ┌────▼──────────────▼─────────────────▼─────────┐ │
│  │              Core Services                    │ │
│  │  Session │ Task │ Auth │ Profile │ Builder    │ │
│  │  Event   │ Audit│ Campaign │ Module│ Reports  │ │
│  └────────────────────┬──────────────────────────┘ │
│                       │                            │
│              ┌────────▼────────┐                   │
│              │     SQLite      │                   │
│              └─────────────────┘                   │
└────────────────────────────────────────────────────┘
```

## Starting the Teamserver

```bash
# Development (no auth, auto-creates default listener)
cargo run -p specter-server -- --dev-mode

# Production (mTLS)
cargo run -p specter-server -- \
  --bind 0.0.0.0 \
  --grpc-port 50051 \
  --http-port 8443 \
  --db-path /var/specter/specter.db
```

## Core Modules

### Session Management (`session/`)

Sessions represent active implant connections. Each session tracks:
- Host metadata (hostname, username, PID, OS, integrity level)
- Network info (internal/external IP, active channel)
- Timing (first seen, last check-in)
- Status lifecycle: `NEW` → `ACTIVE` → `STALE` → `DEAD`

Status transitions are automatic based on check-in timing relative to the configured sleep interval.

### Task Queue (`task/`)

Tasks are queued per-session and dispatched on the next implant check-in.

**Priority levels:** HIGH → NORMAL → LOW (dispatched in priority order, then by creation time).

**Task lifecycle:** `QUEUED` → `DISPATCHED` → `COMPLETE` or `FAILED`

### HTTP Listener (`listener/`)

Built on Axum. Supports three endpoint modes:

1. **Default endpoints:** `/api/checkin`, `/api/beacon`, `/api/health`
2. **Profile-driven:** Dynamic URIs from compiled C2 profile
3. **Fallback:** Decoy 404 responses for unmatched requests

**Check-in flow:**
1. Implant POSTs encrypted check-in
2. Listener extracts payload using profile transform pipeline
3. Session registered or updated
4. Task results processed
5. Pending tasks marshaled, encrypted, and returned

### WebSocket Handler (`listener/ws_handler.rs`)

Bi-directional WebSocket communication channel for implants that support it. Provides lower latency compared to HTTP polling.

The WebSocket handler follows the same wire protocol as the HTTP beacon endpoint:
1. Implant sends binary frame with encrypted check-in
2. Handler decrypts, parses JSON check-in, registers/updates session
3. Task results are processed
4. Pending tasks are marshaled, encrypted, and returned as a binary frame

### Azure Dead-Drop Listener (`listener/azure_listener.rs`)

Uses Azure Blob Storage as an intermediary. Each session gets its own container with SAS tokens. Commands and results are exchanged via blob uploads/downloads.

### Profile Engine (`profile/`)

C2 profiles define how implant traffic looks on the wire.

| File | Purpose |
|------|---------|
| `schema.rs` | Profile YAML structure definitions |
| `parser.rs` | YAML parsing and validation |
| `compiler.rs` | Compiles profile to listener config |
| `transform.rs` | Data encoding/decoding transform pipeline |

**Transforms supported:** Base64, hex, XOR, prepend/append, header injection, URI templating.

### Authentication & Authorization (`auth/`)

| File | Purpose |
|------|---------|
| `ca.rs` | Embedded Certificate Authority for mTLS (master key via `SPECTER_CA_KEY` env var) |
| `mtls.rs` | mTLS TLS configuration |
| `interceptor.rs` | gRPC request authentication interceptor |

**Auth flow (token mode):**
1. Operator calls `Authenticate` RPC with username/password
2. Server verifies Argon2 hash
3. Returns HMAC-SHA256 signed token
4. Token included in subsequent gRPC metadata

**Auth flow (mTLS):**
1. Operator presents client certificate
2. Server validates against embedded CA
3. Extracts operator identity from certificate CN

### Payload Builder (`builder/`)

Generates implant payloads with embedded configuration.

| File | Purpose |
|------|---------|
| `formats.rs` | Output format definitions (DLL, EXE, service, stager) |
| `config_gen.rs` | Implant config blob generation |
| `obfuscation.rs` | Code obfuscation (string encryption, junk code, API hashing, CFG flattening) |
| `yara.rs` | YARA scanning of generated payloads |

### Module Repository (`module/`)

Manages loadable implant modules (COFF/BOF format). Modules are Ed25519-signed for integrity verification.

### Redirector Orchestration (`redirector/`)

Terraform-based deployment and management of traffic redirectors.

| File | Purpose |
|------|---------|
| `deploy.rs` | Terraform-based provisioning |
| `health.rs` | Redirector health monitoring |
| `fronting.rs` | Domain fronting configuration |
| `certs.rs` | TLS certificate rotation |

### Campaign Management (`campaign/`)

Groups operators and sessions for multi-team engagements. Campaigns enforce access control — operators only see sessions assigned to their campaigns.

### Event System (`event/`)

Publish-subscribe event bus using `tokio::sync::broadcast`.

**Event types:**
- `SessionNew`, `SessionCheckin`, `SessionStale`, `SessionDead`
- `TaskQueued`, `TaskDispatched`, `TaskComplete`, `TaskFailed`
- `PresenceUpdate`, `ChatMessage`

Consumed by webhook forwarding, gRPC streaming subscriptions, and audit logging.

### Collaboration (`collaboration/`)

Real-time operator presence tracking and team chat. Supports global and per-session chat channels.

### Audit Logging (`audit/`)

Tamper-proof audit trail with SHA-256 hash chaining. Every operator action is logged with:
- Sequence number
- Operator ID
- Action and target
- Previous entry hash → current entry hash (chain integrity)

**API:** Use `audit_log.log_append(...)` for fire-and-forget logging (logs a warning on failure). Use `audit_log.append(...)` when the caller needs to handle errors explicitly.

### Reporting (`reports/`)

Generates engagement reports in Markdown or JSON format covering sessions, tasks, and timeline.

## Database Schema

SQLite database with the following tables:

| Table | Purpose |
|-------|---------|
| `operators` | Operator credentials and roles |
| `sessions` | Implant session metadata |
| `tasks` | Task queue with priority ordering |
| `listeners` | HTTP/WS listener configuration |
| `profiles` | C2 profile YAML and compiled blobs |
| `campaigns` | Campaign definitions |
| `campaign_sessions` | Session-to-campaign mapping |
| `campaign_operators` | Operator-to-campaign mapping |
| `module_repository` | Loaded modules with signatures |
| `certificates` | Issued operator certificates |
| `ca_state` | CA root certificate and encrypted key |
| `webhooks` | Event forwarding webhook configs |
| `redirectors` | Redirector state and Terraform config |
| `domain_pool` | Available domains for redirectors |
| `cert_records` | Domain certificate records |
| `azure_listeners` | Azure dead-drop configs |
| `azure_containers` | Per-session Azure containers |
| `audit_log` | Tamper-proof audit entries |
| `chat_messages` | Team collaboration messages |
| `reports` | Generated engagement reports |

Migrations are applied automatically on startup via `db/migrations.rs`.

## gRPC-Web Support

The teamserver serves gRPC-Web via `tonic-web`, enabling the React web UI to connect directly. No separate proxy is required in production — the teamserver handles both native gRPC and gRPC-Web on the same port.
