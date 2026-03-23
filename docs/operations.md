# Operations Guide

This guide covers common operational workflows for SPECTER C2 during authorized red team engagements.

## Deployment Modes

### Development / Lab

```bash
# Single terminal — all-in-one
cargo run -p specter-server -- --dev-mode --http-port 8443 --grpc-port 50051
cargo run -p specter-client -- --dev-mode
cargo run -p mock-implant -- --server http://127.0.0.1:8443 --count 5 --interval 5
```

No authentication, auto-created listener, mock implants for testing.

### Production (mTLS)

1. Set the CA master key and start teamserver (generates CA on first run):
   ```bash
   export SPECTER_CA_KEY="$(openssl rand -hex 32)"
   cargo run -p specter-server --release -- \
     --bind 0.0.0.0 \
     --grpc-port 50051 \
     --http-port 443 \
     --db-path /var/specter/specter.db
   ```
   **Important:** Always set `SPECTER_CA_KEY` for production. Without it, the CA private key is encrypted with a key derived from the database path, which is predictable.

2. Issue operator certificates:
   ```bash
   # Via TUI client (first operator uses default admin creds)
   cargo run -p specter-client -- --server https://teamserver:50051 --setup
   ```

3. Connect with mTLS:
   ```bash
   cargo run -p specter-client -- \
     --server https://teamserver:50051 \
     --cert operator.crt --key operator.key --ca-cert ca.crt
   ```

## Engagement Workflow

### 1. Infrastructure Setup

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Teamserver  │◄────│  Redirector  │◄────│   Implant    │
│  (internal)  │     │  (cloud)     │     │  (target)    │
└──────────────┘     └──────────────┘     └──────────────┘
```

**Deploy redirectors** via the gRPC API or web UI:
- Terraform-based provisioning
- Domain fronting support
- Automatic health monitoring
- Emergency burn (rotate domain) if detected

### 2. Create C2 Profile

Profiles shape implant traffic to mimic legitimate HTTP patterns. Create a YAML profile with:
- Request URI patterns
- HTTP headers
- Data transforms (base64, XOR, prepend/append)
- Response templates

Compile the profile and assign it to a listener.

### 3. Generate Payload

Navigate to the **Builder** page in the web UI (or use the TUI client / gRPC API directly):
- Select output format (raw, DLL, service EXE, .NET, PS1 stager, HTA stager)
- Choose a compiled C2 profile
- Add callback channels (primary + fallback endpoints)
- Configure sleep interval and jitter
- Enable obfuscation (string encryption, junk code, API hashing, CFG flattening)
- Set kill date
- Format-specific options: DLL proxy target, service name, stager download URL

The builder runs YARA scans against the generated payload and returns warnings. The response includes the implant's X25519 public key (needed for session key derivation).

### 4. Deploy & Interact

Once the implant checks in:
1. Session appears in TUI/web UI
2. Queue tasks (shell commands, module loads, etc.)
3. Results return on next check-in
4. Use campaigns to organize sessions by target/objective

### 5. Module Operations

Load capability modules dynamically:
- **collect/** — Information gathering (system info, credential harvesting)
- **exfil/** — Data exfiltration
- **inject/** — Process injection techniques
- **lateral/** — Lateral movement
- **socks5/** — SOCKS5 proxy for pivoting
- **token/** — Token impersonation and manipulation

Modules are COFF/BOF-compatible and Ed25519-signed.

### 6. Reporting

Generate engagement reports from the teamserver:
- Session timeline and metadata
- Task execution log
- Operator activity
- Output in Markdown or JSON

## Campaign Management

Campaigns enable multi-team operations with access control.

**Setup:**
1. Create campaign with name and description
2. Associate a listener
3. Add operators with access levels:
   - `FULL` — Can queue tasks, manage sessions
   - `READ_ONLY` — View only
4. Assign sessions to campaigns as they check in

**Effect:** Operators only see sessions belonging to their campaigns. Admins see all sessions.

## Webhook Integration

Forward events to external systems:

| Format | Use Case |
|--------|----------|
| GenericJSON | Custom integrations, SIEM ingestion |
| Slack | Team notifications |
| CEF | Security tool integration |

**Filterable events:** Session lifecycle, task lifecycle, presence changes, chat messages.

## Audit Trail

Every operator action is recorded in a tamper-proof audit log:
- SHA-256 hash chain (each entry hashes with the previous)
- Operator identity
- Action, target, and details
- Timestamp

The hash chain enables detection of log tampering.

## Operational Security Considerations

### Traffic Shaping
- Use C2 profiles to match legitimate traffic patterns
- Deploy redirectors with domain fronting
- Configure appropriate sleep intervals and jitter

### Implant Stealth
- Sleep obfuscation encrypts implant memory during idle periods
- Direct syscalls bypass user-mode API hooks
- PEB walking avoids `GetProcAddress` calls
- No static imports (clean IAT)
- Profile-driven request/response shaping

### Infrastructure
- Use multiple redirectors for redundancy
- Monitor redirector health
- Prepare burn procedures for detected infrastructure
- Set kill dates on all implants
- Use separate campaigns for different objectives

### Comms Security
- All gRPC traffic is TLS-encrypted
- Implant check-ins use X25519 + ChaCha20-Poly1305
- Module blobs are Ed25519-signed
- Operator credentials use Argon2 hashing
