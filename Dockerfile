# Stage 1: Rust builder — teamserver + client binaries
FROM rust:1.83-bookworm AS rust-builder

WORKDIR /build

# Cache dependencies by copying manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/specter-common/Cargo.toml crates/specter-common/Cargo.toml
COPY crates/specter-server/Cargo.toml crates/specter-server/Cargo.toml
COPY crates/specter-client/Cargo.toml crates/specter-client/Cargo.toml
COPY tools/mock-implant/Cargo.toml tools/mock-implant/Cargo.toml

# Create dummy source files for dependency caching
RUN mkdir -p crates/specter-common/src crates/specter-server/src crates/specter-client/src tools/mock-implant/src && \
    echo "fn main() {}" > crates/specter-server/src/main.rs && \
    echo "fn main() {}" > crates/specter-client/src/main.rs && \
    echo "fn main() {}" > tools/mock-implant/src/main.rs && \
    touch crates/specter-common/src/lib.rs crates/specter-server/src/lib.rs

# Install protobuf compiler for tonic/prost builds
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Build dependencies (cached layer)
RUN cargo build --release --workspace 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/
COPY tools/ tools/

# Build release binaries
RUN cargo build --release -p specter-server -p specter-client

# Stage 2: Node.js builder — Web UI dist
FROM node:22-bookworm-slim AS web-builder

WORKDIR /build/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
COPY crates/specter-common/proto/ ../crates/specter-common/proto/
COPY buf.yaml buf.gen.yaml ../

RUN npm run build

# Stage 3: Runtime — slim Debian with binaries + web assets
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /usr/sbin/nologin specter

# Copy binaries from Rust builder
COPY --from=rust-builder /build/target/release/specter-server /usr/local/bin/
COPY --from=rust-builder /build/target/release/specter-client /usr/local/bin/

# Copy Web UI from Node builder
COPY --from=web-builder /build/web/dist/ /opt/specter/web/

# Copy profiles if present
COPY profiles/ /opt/specter/profiles/

# Copy YARA rules if present (use wildcard to avoid failure if missing)
COPY rule[s]/ /opt/specter/rules/

# Data and config volumes
RUN mkdir -p /data /config && chown specter:specter /data /config
VOLUME ["/data", "/config"]

# Expose gRPC and HTTPS
EXPOSE 50051 443 80

USER specter

ENTRYPOINT ["specter-server"]
CMD ["--data-dir", "/data", "--config-dir", "/config", "--web-dir", "/opt/specter/web"]
