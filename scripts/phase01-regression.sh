#!/usr/bin/env bash
# Phase 0.1 server-side smoke: sleep persistence + task result processing.
# Run from repo root or via: ./scripts/phase01-regression.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
cargo test -p specter-server --test listener_tests sleep_result_persists
cargo test -p specter-server --test listener_tests task_results_in_checkin
echo "Phase 0.1 regression: PASS (specter-server listener_tests filters)"
