#!/bin/bash
# Scan payload against downloaded public YARA rules
# First run: downloads rules to ~/.specter/yara-rules/
# Subsequent runs: uses cached rules (refresh with --update)
#
# Usage: ./scripts/scan-local.sh [--update] [--strict] [--json report.json] [artifact ...]
# Requires: python3, yara-python, git

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$HOME/.specter/yara-rules"
UPDATE=0
ARGS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --update)
            UPDATE=1
            shift
            ;;
        --strict)
            ARGS+=("--strict")
            shift
            ;;
        --json)
            ARGS+=("--json" "$2")
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [ "$UPDATE" = "1" ] || [ ! -d "$CACHE_DIR/signature-base" ]; then
    echo "Downloading public YARA rules..."
    mkdir -p "$CACHE_DIR"
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$CACHE_DIR/signature-base" 2>/dev/null || git -C "$CACHE_DIR/signature-base" pull
    git clone --depth 1 https://github.com/Yara-Rules/rules.git "$CACHE_DIR/yara-rules" 2>/dev/null || git -C "$CACHE_DIR/yara-rules" pull
    git clone --depth 1 https://github.com/elastic/protections-artifacts.git "$CACHE_DIR/elastic" 2>/dev/null || git -C "$CACHE_DIR/elastic" pull
    git clone --depth 1 https://github.com/reversinglabs/reversinglabs-yara-rules.git "$CACHE_DIR/rl-rules" 2>/dev/null || git -C "$CACHE_DIR/rl-rules" pull
fi

# Symlink cached rules to /tmp paths expected by scan-public-rules.py
ln -sfn "$CACHE_DIR/signature-base" /tmp/signature-base
ln -sfn "$CACHE_DIR/yara-rules" /tmp/yara-rules
ln -sfn "$CACHE_DIR/elastic" /tmp/elastic-rules
ln -sfn "$CACHE_DIR/rl-rules" /tmp/rl-rules

cd "$REPO_ROOT"
python3 "$SCRIPT_DIR/scan-public-rules.py" "${ARGS[@]}"
