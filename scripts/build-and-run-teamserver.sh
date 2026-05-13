#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMPLANT_DIR="$ROOT_DIR/implant"
WEB_DIR="$ROOT_DIR/web"

DEV_BUILD=1
RELEASE_BUILD=1
RUN_SERVER=1
OPERATOR_MTLS=0
SERVER_ARGS=()

usage() {
  cat <<'EOF'
Usage: scripts/build-and-run-teamserver.sh [options] [-- extra specter-server args]

Builds the implant artifacts, modules, Web UI, Rust workspace, then starts the
teamserver against web/dist.

Options:
  --dev              Build implant with DEV=1 (default)
  --no-dev           Build implant without DEV=1
  --debug-rust       Use cargo build instead of cargo build --release
  --no-run           Build everything but do not start the teamserver
  --operator-mtls    Pass --operator-mtls when starting the teamserver
  -h, --help         Show this help

Examples:
  scripts/build-and-run-teamserver.sh --operator-mtls
  scripts/build-and-run-teamserver.sh --no-run
  scripts/build-and-run-teamserver.sh -- --init-cert admin
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)
      DEV_BUILD=1
      shift
      ;;
    --no-dev)
      DEV_BUILD=0
      shift
      ;;
    --debug-rust)
      RELEASE_BUILD=0
      shift
      ;;
    --no-run)
      RUN_SERVER=0
      shift
      ;;
    --operator-mtls)
      OPERATOR_MTLS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      SERVER_ARGS+=("$@")
      break
      ;;
    *)
      SERVER_ARGS+=("$1")
      shift
      ;;
  esac
done

run() {
  echo
  echo "+ $*"
  "$@"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' was not found in PATH" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd make
require_cmd npm

echo "== SPECTER build and run =="
echo "repo: $ROOT_DIR"

echo
echo "== Implant artifacts =="
run make -C "$IMPLANT_DIR" clean
if [[ "$DEV_BUILD" -eq 1 ]]; then
  run make -C "$IMPLANT_DIR" DEV=1 stubs
  run make -C "$IMPLANT_DIR" DEV=1 modules
  run make -C "$IMPLANT_DIR" DEV=1
else
  run make -C "$IMPLANT_DIR" stubs
  run make -C "$IMPLANT_DIR" modules
  run make -C "$IMPLANT_DIR"
fi

FEATURE_FILE="$IMPLANT_DIR/build/specter.features"
if ! grep -qx "profile_response_dynamic=1" "$FEATURE_FILE"; then
  echo "error: $FEATURE_FILE is missing profile_response_dynamic=1" >&2
  exit 1
fi

PIC_SIZE="$(stat -c '%s' "$IMPLANT_DIR/build/specter.bin")"
PIC_SHA="$(sha256sum "$IMPLANT_DIR/build/specter.bin" | awk '{print $1}')"
echo "PIC artifact: $PIC_SIZE bytes sha256=$PIC_SHA"

echo
echo "== Web UI =="
if [[ -f "$WEB_DIR/package-lock.json" ]]; then
  run npm --prefix "$WEB_DIR" ci
else
  run npm --prefix "$WEB_DIR" install
fi
run npm --prefix "$WEB_DIR" run generate
run npm --prefix "$WEB_DIR" run build

echo
echo "== Rust workspace =="
if [[ "$RELEASE_BUILD" -eq 1 ]]; then
  run cargo build --workspace --release
  SERVER_BIN="$ROOT_DIR/target/release/specter-server"
else
  run cargo build --workspace
  SERVER_BIN="$ROOT_DIR/target/debug/specter-server"
fi

if [[ "$RUN_SERVER" -eq 0 ]]; then
  echo
  echo "Build complete. Teamserver not started because --no-run was set."
  exit 0
fi

echo
echo "== Starting teamserver =="
START_ARGS=("--web-ui-dir" "$WEB_DIR/dist")
if [[ "$OPERATOR_MTLS" -eq 1 ]]; then
  START_ARGS+=("--operator-mtls")
fi
START_ARGS+=("${SERVER_ARGS[@]}")

echo "+ $SERVER_BIN ${START_ARGS[*]}"
exec "$SERVER_BIN" "${START_ARGS[@]}"
