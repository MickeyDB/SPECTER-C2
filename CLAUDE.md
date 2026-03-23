# SPECTER C2 Framework

## Project Overview
SPECTER is a Command & Control (C2) framework for authorized red team engagements. Built in Rust.

## Toolchain & Conventions
- **Rust stable toolchain**, 2021 edition
- **Teamserver**: Tokio async runtime, Tonic gRPC, SQLite via sqlx
- **TUI Client**: Ratatui + crossterm
- **Protobuf definitions**: `crates/specter-common/proto/`
- **Error types**: All crates use `thiserror` for error types

## Workspace Layout
```
crates/
  specter-common/    — Shared protobuf types, domain errors
  specter-server/    — Teamserver (gRPC API, HTTP listeners, SQLite)
  specter-client/    — TUI operator client
web/                 — React/TypeScript Web UI (Vite, Tailwind, gRPC-Web)
  src/gen/           — Auto-generated protobuf TypeScript (do not edit)
  src/components/    — Reusable UI components
  src/pages/         — Route pages
  src/lib/           — gRPC client, transport, utilities
  src/store/         — Zustand state stores
  src/hooks/         — Custom React hooks
  src/auth/          — Authentication (mTLS, OAuth2)
implant/
  core/              — C11 PIC implant (CRT-free, zero imports)
    include/         — Header files
    src/             — Source files
    asm/             — Assembly stubs (GAS/Intel syntax)
  build/             — Build output (specter.bin PIC blob)
  scripts/           — Linker script, post-build tooling
tools/
  mock-implant/      — Mock implant for testing/demo
```

## Commands

### Rust (Teamserver/Client)
- **Format**: `cargo fmt --all`
- **Lint**: `cargo clippy --workspace`
- **Test**: `cargo test --workspace`
- **Build**: `cargo build --workspace`
- **Check**: `cargo check --workspace`

### Web UI
- **Install**: `cd web && npm install`
- **Dev server**: `cd web && npm run dev` — starts Vite dev server with gRPC proxy
- **Build**: `cd web && npm run build` — outputs to `web/dist/`
- **Lint**: `cd web && npm run lint`
- **Type-check**: `cd web && npm run type-check`
- **Test**: `cd web && npm run test`
- **Generate protos**: `cd web && npm run generate` — regenerates `src/gen/` from proto files
- **Stack**: React 19, TypeScript, Vite, Tailwind CSS 4, Connect-ES (gRPC-Web), Zustand, Recharts, D3, xterm.js
- **gRPC-Web**: Teamserver uses `tonic-web` to serve gRPC-Web; Web UI connects via `@connectrpc/connect-web`

### Implant (C11 PIC Blob)
- **Build**: `cd implant && make` — compiles to `implant/build/specter.bin`
- **Clean**: `cd implant && make clean`
- **Size**: `cd implant && make size` — prints final PIC blob size
- **Toolchain**: MinGW-w64 (`x86_64-w64-mingw32-gcc`), GNU ld, objcopy
- **Target**: Windows x86-64 PIC blob, CRT-free, no static imports, <20KB

### CI/CD (GitHub Actions)
- **CI pipeline**: `.github/workflows/ci.yml` — runs on push to main/develop and PRs
  - Rust: fmt check, clippy (warnings as errors), workspace tests
  - Teamserver & client: cross-platform builds (Linux, macOS, Windows)
  - Implant: MinGW cross-compile, size check, YARA scan against `rules/*.yar`
  - Modules: build all implant modules
  - Web UI: npm ci, type-check, build, lint, tests
- **Release pipeline**: `.github/workflows/release.yml` — triggered on `v*` tag push
  - Builds all components in release mode, creates GitHub release with binaries
- **YARA rules**: `rules/` directory — scanned against implant payloads in CI

### Docker
- **Build image**: `docker build -t specter .`
- **Run**: `docker compose up -d`
- **Dockerfile**: Multi-stage build (Rust builder → Node.js builder → Debian slim runtime)
- **Ports**: 50051 (gRPC), 443 (HTTPS listener), 80 (HTTP redirect)
- **Volumes**: `/data` (database, certificates), `/config` (profiles, redirector configs)
- **PostgreSQL**: Optional service in `docker-compose.yml` (uncomment for multi-teamserver deployments)

## Deployment

### Prerequisites (Linux Teamserver)
- **Rust**: stable toolchain ≥1.85 (`rustup update stable`)
- **Node.js**: ≥20 (`curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs`)
- **protoc**: `sudo apt-get install -y protobuf-compiler`
- **MinGW** (for implant cross-compile): `sudo apt-get install -y gcc-mingw-w64-x86-64`
- **Terraform**: required for redirector deployment
- **Azure CLI**: `az login` required before deploying Azure redirectors

### First Run
```bash
# Build everything
cargo build --workspace --release
cd web && npm install && npm run build && cd ..

# Generate initial operator certificate for browser access
./target/release/specter-server --init-cert admin --cert-out ~/certs

# Create PKCS12 for browser import
cd ~/certs
openssl pkcs12 -export -out operator.p12 \
  -inkey operator-key.pem -in operator.pem -certfile ca.pem

# Import operator.p12 into your browser (macOS: Keychain, Windows: certmgr, Linux: pk12util)

# Start the server
./target/release/specter-server --web-ui-dir /path/to/web/dist/
```

### Server CLI Flags
- `--bind <addr>` — bind address (default: `0.0.0.0`)
- `--grpc-port <port>` — gRPC API port (default: `50051`)
- `--http-port <port>` — default HTTP listener port (default: `443`)
- `--db-path <path>` — SQLite database path (default: `specter.db`)
- `--dev-mode` — disables mTLS, uses token auth only, auto-creates HTTP listener
- `--web-ui-dir <path>` — serve Web UI static files from this directory at `/ui/`
- `--init-cert <username>` — generate operator cert bundle and exit
- `--cert-out <dir>` — output directory for `--init-cert` (default: `.`)

### Authentication
- **mTLS mode** (default): browser needs operator `.p12` cert imported; server validates client certs against embedded CA
- **Token auth**: username + password shown on first startup; works alongside mTLS
- **Dev mode** (`--dev-mode`): no auth required, CA disabled
- Web UI supports both: "Authenticate with Certificate" button (mTLS) or username/password form (token)
- The Web UI at `/ui/` is served on the same port as gRPC (50051) — both go through mTLS

### Implant Build (Linux Cross-Compile)
The Makefile uses MinGW cross-compiler tools (`x86_64-w64-mingw32-gcc`, `x86_64-w64-mingw32-ld`, `x86_64-w64-mingw32-objcopy`) and `python3` for post-processing.

## Redirector Infrastructure

### Architecture
Redirectors are cloud-deployed proxies that sit between implants and the teamserver. They filter traffic (only forwarding requests matching C2 profiles) and return decoy responses to everything else.

### Deployment Flow
1. Operator creates a **traffic profile** (YAML) defining URI patterns, headers, timing, TLS fingerprint
2. Operator deploys a **redirector** via the Web UI wizard, selecting provider, type, domain, and profile
3. Server generates Terraform config and runs `terraform init` + `terraform apply`
4. Redirector proxy (Node.js on Azure App Service, etc.) is deployed with filtering rules from the profile
5. Background health monitor probes redirectors every 60s; auto-degrades after failures

### Azure App Service Redirectors
- **Prerequisites**: `az login` on teamserver, Terraform installed
- **Terraform modules**: `infrastructure/terraform/modules/azure-appservice/` (VPS), `azure-function/` (serverless)
- **Credentials**: Terraform inherits Azure auth from the environment — no per-deployment credential UI
- **What's deployed**: Resource Group, App Service Plan (B1 ~$13/mo), Linux Web App (Node 20), custom domain + managed TLS cert
- **Proxy behavior**: matches requests by URI pattern + header pattern from profile; proxies matches to teamserver; returns decoy 404 for everything else; strips Azure headers both directions; supports WebSocket upgrade

### Burn & Replace
- "Burn" tears down infrastructure, marks domain as burned, acquires replacement from domain pool, deploys new redirector
- Domain pool tracks available/in-use/burned domains per provider

## Traffic Profiles

### YAML Schema
Profiles use `snake_case` for all enum values (not PascalCase):
- Locations: `json_field`, `cookie_value`, `uri_segment`, `query_param`, `multipart_field`, `header_value`
- Encodings: `base64`, `base85`, `hex`, `raw`
- Distributions: `uniform`, `gaussian`, `pareto`, `empirical`
- Compression: `none`, `lz4`, `zstd`
- Encryption: `cha_cha20_poly1305`
- Timing fields: `callback_interval` (not `sleep`), `jitter_percent` (not `jitter`), `jitter_distribution`

### Profile ↔ Redirector Mapping
| Profile Field | Redirector Setting | Purpose |
|---|---|---|
| `http.request.uri_patterns` | `URI_PATTERN` env var | Only proxy matching paths |
| `http.request.headers` | `HEADER_NAME` + `HEADER_PATTERN` | Only proxy matching headers |
| `filtering_rules.decoy_response` | `DECOY_RESPONSE` env var | HTML returned to non-matching requests |

### Compilation
Profiles are compiled to TLV (Type-Length-Value) binary blobs embedded in the implant. The `CompileProfile` RPC triggers this.
