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
