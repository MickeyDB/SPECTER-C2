#!/bin/bash
# SPECTER C2 — Pre-delivery YARA scan
#
# Usage: ./scripts/check-payload.sh [path/to/blob]
#
# Scans the built implant PIC blob against all YARA detection rules.
# Exits non-zero if any critical-severity rule matches.
# Requires: python3, yara-python (pip install yara-python)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLOB="${1:-$REPO_ROOT/implant/build/specter.bin}"
RULES_DIR="$REPO_ROOT/rules"

if [ ! -f "$BLOB" ]; then
    echo "ERROR: No blob found at $BLOB"
    echo "Build the implant first: make -C implant"
    exit 1
fi

if ! python3 -c "import yara" 2>/dev/null; then
    echo "ERROR: yara-python not installed"
    echo "Install with: pip install yara-python"
    exit 1
fi

echo "Scanning $BLOB..."
echo "Rules directory: $RULES_DIR"
echo "---"

python3 -c "
import yara, sys, glob, os

rules_dir = '$RULES_DIR'
rule_files = glob.glob(os.path.join(rules_dir, '*.yar')) + \
             glob.glob(os.path.join(rules_dir, '*.yara'))

if not rule_files:
    print('No YARA rules found in', rules_dir)
    sys.exit(1)

print(f'Loaded {len(rule_files)} rule file(s)')

filepaths = {f'ns{i}': path for i, path in enumerate(rule_files)}
rules = yara.compile(filepaths=filepaths)
matches = rules.match('$BLOB')

has_critical = False
for m in matches:
    sev = m.meta.get('severity', 'unknown')
    desc = m.meta.get('description', '')
    print(f'[{sev.upper()}] {m.rule}: {desc}')
    if sev == 'critical':
        has_critical = True

if not matches:
    print('[CLEAN] No detections')

sys.exit(1 if has_critical else 0)
"

echo ""
echo "For public rule scanning: ./scripts/scan-local.sh $BLOB"
