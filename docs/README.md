# SPECTER C2 Framework

SPECTER is a Command & Control (C2) framework built for authorized red team engagements. It provides a multi-component architecture consisting of a Rust teamserver, TUI and web operator clients, and a compact C11 position-independent implant targeting Windows x86-64.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Components](#components)
- [Building](#building)
- [Configuration](#configuration)
- [Security Model](#security-model)

---

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐
│   TUI Client    │    │    Web UI        │
│  (Ratatui)      │    │  (React/TS)      │
└────────┬────────┘    └────────┬─────────┘
         │  gRPC                │  gRPC-Web
         └──────────┬───────────┘
                    │
            ┌───────▼────────┐
            │   Teamserver   │
            │  (Rust/Tonic)  │
            │                │
            │  ┌──────────┐  │
            │  │  SQLite   │  │
            │  └──────────┘  │
            └───────┬────────┘
                    │  HTTP / DNS / SMB / WS / Azure
                    │
        ┌───────────▼───────────┐
        │     Redirectors       │
        │  (Terraform-managed)  │
        └───────────┬───────────┘
                    │
            ┌───────▼────────┐
            │    Implant     │
            │  (C11 PIC)     │
            │  Windows x64   │
            └────────────────┘
```

**Data flow:** Implants check in via HTTP (or other channels) through optional redirectors. The teamserver queues tasks for each session. Operators interact via TUI or web UI over gRPC.

---

## Quick Start

### Prerequisites

- Rust stable toolchain (2021 edition)
- Node.js 18+ and npm (for web UI)
- MinGW-w64 cross-compiler (for implant builds)
- Protobuf compiler (`protoc`) and `buf` CLI (for proto regeneration)

### Development Mode (No Auth)

**Terminal 1 — Teamserver:**
```bash
cargo run -p specter-server -- --dev-mode --http-port 8443 --grpc-port 50051
```

**Terminal 2 — TUI Client:**
```bash
cargo run -p specter-client -- --dev-mode --server http://localhost:50051
```

**Terminal 3 — Mock Implants (for testing):**
```bash
cargo run -p mock-implant -- --server http://127.0.0.1:8443 --count 3 --interval 5
```

**Terminal 4 — Web UI (optional):**
```bash
cd web && npm install && npm run dev
```

---

## Components

| Component | Location | Language | Description |
|-----------|----------|----------|-------------|
| Teamserver | `crates/specter-server/` | Rust | gRPC API, HTTP listeners, SQLite persistence |
| TUI Client | `crates/specter-client/` | Rust | Terminal operator interface (Ratatui) |
| Common | `crates/specter-common/` | Rust/Proto | Shared protobuf types and error definitions |
| Web UI | `web/` | TypeScript/React | Browser-based operator dashboard |
| Implant | `implant/` | C11/ASM | Position-independent Windows agent |
| Mock Implant | `tools/mock-implant/` | Rust | Testing/demo implant simulator |

See component-specific docs:
- **[Production Deployment Guide](./deployment-guide.md)** — End-to-end walkthrough from build to operation
- [Teamserver](./teamserver.md)
- [TUI Client](./client.md)
- [Web UI](./web-ui.md)
- [Implant](./implant.md)
- [Protocols & API](./protocols.md)
- [Operations Guide](./operations.md)

---

## Building

### Rust Workspace (Teamserver + Client)

```bash
cargo build --workspace          # Debug build
cargo build --workspace --release # Release build
cargo test --workspace           # Run all tests
cargo clippy --workspace         # Lint
cargo fmt --all                  # Format
```

### Web UI

```bash
cd web
npm install          # Install dependencies
npm run dev          # Development server with hot reload
npm run build        # Production build → web/dist/
npm run lint         # ESLint
npm run type-check   # TypeScript type checking
npm run generate     # Regenerate protobuf TypeScript from proto files
```

### Implant

```bash
cd implant
make                 # Build → implant/build/specter.bin
make clean           # Clean build artifacts
make size            # Print PIC blob size
```

Requires MinGW-w64 (`x86_64-w64-mingw32-gcc`).

---

## Configuration

### Teamserver CLI Flags

| Flag           | Default      | Description                                   |
| -------------- | ------------ | --------------------------------------------- |
| `--bind`       | `0.0.0.0`    | Bind address                                  |
| `--grpc-port`  | `50051`      | gRPC API port                                 |
| `--http-port`  | `8443`       | HTTP listener port                            |
| `--db-path`    | `specter.db` | SQLite database path                          |
| `--dev-mode`   | `false`      | Disable authentication                        |
| `--web-ui-dir` | —            | Serve web UI static files from this directory |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SPECTER_CA_KEY` | CA master key for encrypting the embedded CA private key. **Set this for production deployments.** If unset, falls back to a deterministic derivation from the database path (insecure). |

### TUI Client CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:50051` | Teamserver gRPC URL |
| `--token` | — | API authentication token |
| `--cert` | — | mTLS client certificate path |
| `--key` | — | mTLS client key path |
| `--ca-cert` | — | CA certificate path |
| `--dev-mode` | `false` | Connect without authentication |
| `--setup` | `false` | First-time certificate setup |

---

## Security Model

### Authentication Modes

| Mode | Use Case | Mechanism |
|------|----------|-----------|
| Dev mode | Local testing | No authentication |
| Token mode | Quick setup | HMAC-SHA256 signed API tokens |
| mTLS mode | Production | Client certificates from embedded CA |

### Role-Based Access Control

| Role | Permissions |
|------|-------------|
| ADMIN | Full access — manage operators, listeners, campaigns |
| OPERATOR | Queue tasks, interact with sessions, load modules |
| OBSERVER | Read-only — view sessions, tasks, reports |

### Cryptography

| Purpose | Algorithm |
|---------|-----------|
| Key exchange | X25519 |
| Check-in encryption | ChaCha20-Poly1305 (AEAD) |
| Password hashing | Argon2 |
| Module signing | Ed25519 |
| TLS | rustls (server), SChannel (implant) |
| Audit log integrity | SHA-256 hash chain |

---

## Workspace Layout

```
SPECTER-C2/
├── crates/
│   ├── specter-common/      # Shared protobuf types, domain errors
│   │   └── proto/specter/v1/ # 13 proto definition files
│   ├── specter-server/      # Teamserver
│   └── specter-client/      # TUI client
├── web/                     # React/TypeScript web UI
│   ├── src/gen/             # Auto-generated proto TypeScript (do not edit)
│   ├── src/components/      # Reusable UI components
│   ├── src/pages/           # Route pages
│   ├── src/lib/             # gRPC client, transport, utilities
│   ├── src/store/           # Zustand state stores
│   ├── src/hooks/           # Custom React hooks
│   └── src/auth/            # Authentication (mTLS, OAuth2)
├── implant/
│   ├── core/                # C11 PIC implant source
│   │   ├── include/         # Header files
│   │   ├── src/             # Source files
│   │   └── asm/             # Assembly stubs
│   ├── modules/             # Implant modules (COFF/BOF)
│   ├── build/               # Build output (specter.bin)
│   └── scripts/             # Linker script, post-build tooling
├── tools/
│   └── mock-implant/        # Mock implant for testing/demo
├── profiles/                # C2 profile templates
├── rules/                   # Detection/signature rules
├── infrastructure/          # Terraform deployment configs
└── docs/                    # Documentation (you are here)
```
