#!/bin/bash
# Scan payload against downloaded public YARA rules
# First run: downloads rules to ~/.specter/yara-rules/
# Subsequent runs: uses cached rules (refresh with --update)
#
# Usage: ./scripts/scan-local.sh [--update] [path/to/blob]
# Requires: python3, yara-python, git

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="$HOME/.specter/yara-rules"
BLOB="${1:-implant/build/specter.bin}"

if [ "$1" = "--update" ] || [ ! -d "$CACHE_DIR/signature-base" ]; then
    echo "Downloading public YARA rules..."
    mkdir -p "$CACHE_DIR"
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$CACHE_DIR/signature-base" 2>/dev/null || git -C "$CACHE_DIR/signature-base" pull
    git clone --depth 1 https://github.com/Yara-Rules/rules.git "$CACHE_DIR/yara-rules" 2>/dev/null || git -C "$CACHE_DIR/yara-rules" pull
    git clone --depth 1 https://github.com/elastic/protections-artifacts.git "$CACHE_DIR/elastic" 2>/dev/null || git -C "$CACHE_DIR/elastic" pull
    git clone --depth 1 https://github.com/reversinglabs/reversinglabs-yara-rules.git "$CACHE_DIR/rl-rules" 2>/dev/null || git -C "$CACHE_DIR/rl-rules" pull
    if [ "$1" = "--update" ]; then shift; BLOB="${1:-implant/build/specter.bin}"; fi
fi

# Symlink cached rules to /tmp paths expected by scan-public-rules.py
ln -sfn "$CACHE_DIR/signature-base" /tmp/signature-base
ln -sfn "$CACHE_DIR/yara-rules" /tmp/yara-rules
ln -sfn "$CACHE_DIR/elastic" /tmp/elastic-rules
ln -sfn "$CACHE_DIR/rl-rules" /tmp/rl-rules

python3 "$SCRIPT_DIR/scan-public-rules.py" "$BLOB"
