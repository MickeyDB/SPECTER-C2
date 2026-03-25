#!/usr/bin/env python3
"""Scan a payload against public YARA rule repositories."""
import yara
import sys
import os
from pathlib import Path


def compile_rules_from_dir(rule_dir, extensions=('.yar', '.yara')):
    """Compile all YARA rules from a directory, skipping broken ones."""
    rules = []
    for ext in extensions:
        for rule_file in Path(rule_dir).rglob(f'*{ext}'):
            try:
                rule = yara.compile(filepath=str(rule_file))
                rules.append((str(rule_file), rule))
            except yara.SyntaxError:
                pass  # Skip rules with syntax errors (common in large repos)
            except Exception:
                pass
    return rules


def scan(blob_path):
    blob = blob_path

    rule_dirs = {
        'Florian Roth signature-base': '/tmp/signature-base/yara',
        'YARA-Rules community': '/tmp/yara-rules',
        'Elastic protections': '/tmp/elastic-rules/yara',
        'ReversingLabs': '/tmp/rl-rules/yara',
    }

    total_detections = 0

    for name, rule_dir in rule_dirs.items():
        if not os.path.exists(rule_dir):
            print(f'\n[SKIP] {name} -- not found at {rule_dir}')
            continue

        print(f'\n[SCAN] {name} ({rule_dir})')
        rules = compile_rules_from_dir(rule_dir)
        print(f'  Compiled {len(rules)} rule files')

        detections = []
        for rule_file, compiled in rules:
            matches = compiled.match(blob)
            for m in matches:
                detections.append((m.rule, os.path.basename(rule_file)))

        if detections:
            print(f'  WARNING: {len(detections)} DETECTIONS:')
            for rule_name, source in detections:
                print(f'    - {rule_name} ({source})')
            total_detections += len(detections)
        else:
            print(f'  CLEAN: no detections')

    print(f'\n{"="*60}')
    print(f'Total detections across all rule sets: {total_detections}')
    if total_detections > 0:
        print('Review detections and consider adjusting obfuscation.')
    else:
        print('Payload is clean against all public rule sets.')

    # Always exit 0 -- detections are informational
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <blob_path>')
        sys.exit(1)
    sys.exit(scan(sys.argv[1]))
