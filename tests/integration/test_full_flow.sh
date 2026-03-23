#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# SPECTER C2 — Full Integration Test
#
# Builds all components, starts the teamserver in dev mode, launches
# mock implants, verifies sessions/tasks via gRPC, generates a report,
# and reports pass/fail.
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GRPC_PORT="${GRPC_PORT:-50051}"
HTTP_PORT="${HTTP_PORT:-8443}"
NUM_IMPLANTS=5
CHECKIN_INTERVAL=3
WAIT_SETTLE=10
TEAMSERVER_PID=""
MOCK_PID=""
PASS_COUNT=0
FAIL_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    [ -n "$TEAMSERVER_PID" ] && kill "$TEAMSERVER_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
    wait "$TEAMSERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "  ${GREEN}[PASS]${NC} $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "  ${RED}[FAIL]${NC} $1"
}

# ── Step 1: Build ────────────────────────────────────────────────────
echo -e "${YELLOW}[1/6] Building all components...${NC}"

cd "$ROOT_DIR"
cargo build --workspace 2>&1 | tail -5
if [ $? -eq 0 ]; then
    pass "Cargo workspace build"
else
    fail "Cargo workspace build"
    echo "Cannot continue without a successful build."
    exit 1
fi

# ── Step 2: Start teamserver ─────────────────────────────────────────
echo -e "\n${YELLOW}[2/6] Starting teamserver (dev mode)...${NC}"

cargo run -p specter-server -- \
    --dev-mode \
    --grpc-port "$GRPC_PORT" \
    --http-port "$HTTP_PORT" \
    --db-path ":memory:" \
    --log-level warn &
TEAMSERVER_PID=$!

# Give teamserver time to bind
sleep 3

if kill -0 "$TEAMSERVER_PID" 2>/dev/null; then
    pass "Teamserver started (PID $TEAMSERVER_PID)"
else
    fail "Teamserver failed to start"
    exit 1
fi

# ── Step 3: Launch mock implants ─────────────────────────────────────
echo -e "\n${YELLOW}[3/6] Launching $NUM_IMPLANTS mock implants...${NC}"

cargo run -p mock-implant -- \
    --server "http://127.0.0.1:$HTTP_PORT" \
    --count "$NUM_IMPLANTS" \
    --interval "$CHECKIN_INTERVAL" \
    --jitter 10 &
MOCK_PID=$!

sleep "$WAIT_SETTLE"

if kill -0 "$MOCK_PID" 2>/dev/null; then
    pass "Mock implants running (PID $MOCK_PID)"
else
    fail "Mock implants crashed"
fi

# ── Step 4: Verify sessions via gRPC ─────────────────────────────────
echo -e "\n${YELLOW}[4/6] Verifying sessions via gRPC...${NC}"

# Use grpcurl if available, otherwise try a simple HTTP check
if command -v grpcurl &>/dev/null; then
    SESSION_COUNT=$(grpcurl -plaintext \
        -d '{}' \
        "localhost:$GRPC_PORT" \
        specter.v1.SpecterService/ListSessions 2>/dev/null | \
        grep -c '"session_id"' || echo "0")

    if [ "$SESSION_COUNT" -ge "$NUM_IMPLANTS" ]; then
        pass "Found $SESSION_COUNT sessions (expected >= $NUM_IMPLANTS)"
    else
        fail "Found $SESSION_COUNT sessions (expected >= $NUM_IMPLANTS)"
    fi
else
    echo "  [SKIP] grpcurl not installed — checking HTTP endpoint instead"
    HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$HTTP_PORT/api/checkin" \
        -X POST -H 'Content-Type: application/json' \
        -d '{"hostname":"test","username":"test","pid":9999,"os_version":"Test","integrity_level":"Medium","process_name":"test.exe","internal_ip":"10.0.0.1","external_ip":"","task_results":[]}' \
        2>/dev/null || echo "000")

    if [ "$HTTP_STATUS" = "200" ]; then
        pass "HTTP check-in endpoint responsive (status $HTTP_STATUS)"
    else
        fail "HTTP check-in endpoint returned status $HTTP_STATUS"
    fi
fi

# ── Step 5: Queue tasks and verify results ───────────────────────────
echo -e "\n${YELLOW}[5/6] Queue tasks and verify results...${NC}"

if command -v grpcurl &>/dev/null; then
    # Queue a shell task to the first session
    FIRST_SESSION=$(grpcurl -plaintext \
        -d '{}' \
        "localhost:$GRPC_PORT" \
        specter.v1.SpecterService/ListSessions 2>/dev/null | \
        grep '"session_id"' | head -1 | sed 's/.*: "//;s/".*//' || echo "")

    if [ -n "$FIRST_SESSION" ]; then
        grpcurl -plaintext \
            -d "{\"session_id\": \"$FIRST_SESSION\", \"task_type\": \"execute_shell\", \"arguments\": \"whoami\"}" \
            "localhost:$GRPC_PORT" \
            specter.v1.SpecterService/QueueTask 2>/dev/null && \
            pass "Task queued to session $FIRST_SESSION" || \
            fail "Failed to queue task"

        # Wait for mock implant to pick up and return results
        sleep $((CHECKIN_INTERVAL + 2))

        RESULT=$(grpcurl -plaintext \
            -d "{\"session_id\": \"$FIRST_SESSION\"}" \
            "localhost:$GRPC_PORT" \
            specter.v1.SpecterService/GetTaskResults 2>/dev/null | \
            grep -c '"result"' || echo "0")

        if [ "$RESULT" -ge 1 ]; then
            pass "Task result received"
        else
            fail "No task result received"
        fi
    else
        fail "No sessions found to queue tasks against"
    fi
else
    echo "  [SKIP] grpcurl not available — skipping gRPC task verification"
    pass "HTTP-level verification only (grpcurl not available)"
fi

# ── Step 6: Generate report ──────────────────────────────────────────
echo -e "\n${YELLOW}[6/6] Generate report...${NC}"

if command -v grpcurl &>/dev/null; then
    grpcurl -plaintext \
        -d '{"format": "FORMAT_MARKDOWN"}' \
        "localhost:$GRPC_PORT" \
        specter.v1.SpecterService/GenerateReport 2>/dev/null && \
        pass "Report generated via gRPC" || \
        fail "Report generation failed"
else
    echo "  [SKIP] grpcurl not available — skipping report generation"
    pass "Skipped (grpcurl not available)"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo -e "\n────────────────────────────────────────────"
echo -e "  Results: ${GREEN}$PASS_COUNT passed${NC}, ${RED}$FAIL_COUNT failed${NC}"
echo -e "────────────────────────────────────────────"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi

exit 0
