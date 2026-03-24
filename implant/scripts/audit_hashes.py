#!/usr/bin/env python3
"""Audit all DJB2 hash constants in the SPECTER implant against spec_djb2_hash()."""
import re, os, sys

def djb2(name):
    h = 5381
    for c in name.lower():
        h = ((h * 33) + ord(c)) & 0xFFFFFFFF
    return h

# Pattern: #define HASH_XXX  0xYYYYYYYY  /* "string" */
HASH_RE = re.compile(r'#define\s+(HASH_\w+)\s+(0x[0-9A-Fa-f]+)\s*/\*\s*"([^"]+)"')

root = os.path.join(os.path.dirname(__file__), '..', 'core')
mismatches = []
ok_count = 0

for dirpath, _, filenames in os.walk(root):
    for fn in sorted(filenames):
        if not (fn.endswith('.h') or fn.endswith('.c')):
            continue
        path = os.path.join(dirpath, fn)
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                m = HASH_RE.search(line)
                if m:
                    define, hex_val, name = m.group(1), m.group(2), m.group(3)
                    expected = int(hex_val, 16)
                    computed = djb2(name)
                    rel = os.path.relpath(path, root)
                    if computed == expected:
                        ok_count += 1
                    else:
                        mismatches.append((rel, lineno, define, name, expected, computed))

print(f"Checked {ok_count + len(mismatches)} hashes: {ok_count} OK, {len(mismatches)} MISMATCH")
if mismatches:
    print("\n--- MISMATCHES ---")
    for rel, lineno, define, name, expected, computed in mismatches:
        print(f"  {rel}:{lineno}  {define}")
        print(f"    string=\"{name}\"  current=0x{expected:08X}  correct=0x{computed:08X}")
    # Generate fix lines
    print("\n--- FIXES (copy-paste) ---")
    for rel, lineno, define, name, expected, computed in mismatches:
        pad = max(1, 40 - len(define))
        print(f'#define {define}{" "*pad}0x{computed:08X}  /* "{name}" */')
