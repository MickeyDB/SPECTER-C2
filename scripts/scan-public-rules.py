#!/usr/bin/env python3
"""Scan payload artifacts against public YARA rule repositories.

The scanner is intentionally a validation/reporting gate. It does not modify
payloads or suggest bypasses; it makes detector coverage visible before lab use.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import yara


DEFAULT_RULE_DIRS = {
    "Florian Roth signature-base": "/tmp/signature-base/yara",
    "YARA-Rules community": "/tmp/yara-rules",
    "Elastic protections": "/tmp/elastic-rules/yara",
    "ReversingLabs": "/tmp/rl-rules/yara",
}

DEFAULT_ARTIFACTS = [
    "implant/build/specter.bin",
    "implant/build/modules",
    "implant/build/dotnet_stub.exe",
    "implant/build/service_stub.exe",
    "implant/build/sideload_stub.dll",
]

ARTIFACT_SUFFIXES = {
    ".bin",
    ".dll",
    ".exe",
    ".raw",
    ".dat",
}


def compile_rules_from_dir(rule_dir, extensions=(".yar", ".yara")):
    """Compile all YARA rules from a directory, skipping broken rules."""
    rules = []
    skipped = 0
    for ext in extensions:
        for rule_file in Path(rule_dir).rglob(f"*{ext}"):
            try:
                rule = yara.compile(filepath=str(rule_file))
                rules.append((str(rule_file), rule))
            except yara.SyntaxError:
                skipped += 1
            except Exception:
                skipped += 1
    return rules, skipped


def discover_artifacts(paths):
    artifacts = []
    seen = set()
    for raw in paths:
        path = Path(raw)
        candidates = []
        if path.is_dir():
            candidates = [
                p
                for p in path.rglob("*")
                if p.is_file() and p.suffix.lower() in ARTIFACT_SUFFIXES
            ]
        elif path.is_file():
            candidates = [path]

        for candidate in candidates:
            resolved = str(candidate)
            if resolved not in seen:
                seen.add(resolved)
                artifacts.append(candidate)
    return artifacts


def scan_artifact(artifact, compiled_rules):
    detections = []
    for corpus_name, rule_file, compiled in compiled_rules:
        for match in compiled.match(str(artifact)):
            detections.append(
                {
                    "artifact": str(artifact),
                    "corpus": corpus_name,
                    "rule": match.rule,
                    "source": os.path.basename(rule_file),
                    "meta": dict(match.meta),
                    "tags": list(match.tags),
                }
            )
    return detections


def load_rule_corpora(rule_dirs):
    compiled = []
    corpus_counts = {}
    skipped_counts = {}
    for name, rule_dir in rule_dirs.items():
        if not os.path.exists(rule_dir):
            corpus_counts[name] = 0
            skipped_counts[name] = None
            continue

        rules, skipped = compile_rules_from_dir(rule_dir)
        corpus_counts[name] = len(rules)
        skipped_counts[name] = skipped
        for rule_file, compiled_rule in rules:
            compiled.append((name, rule_file, compiled_rule))
    return compiled, corpus_counts, skipped_counts


def parse_rule_dir_args(values):
    if not values:
        return DEFAULT_RULE_DIRS

    rule_dirs = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"rule directory must use NAME=PATH form: {value}")
        name, path = value.split("=", 1)
        name = name.strip()
        path = path.strip()
        if not name or not path:
            raise ValueError(f"rule directory must use NAME=PATH form: {value}")
        rule_dirs[name] = path
    return rule_dirs


def print_summary(artifacts, corpus_counts, skipped_counts, detections):
    print("Public YARA scan")
    print("=" * 60)
    print(f"Artifacts: {len(artifacts)}")
    for artifact in artifacts:
        try:
            size = artifact.stat().st_size
        except OSError:
            size = 0
        print(f"  - {artifact} ({size} bytes)")

    print("\nRule corpora:")
    for name, count in corpus_counts.items():
        skipped = skipped_counts[name]
        if skipped is None:
            print(f"  - {name}: SKIP (not found)")
        else:
            print(f"  - {name}: {count} compiled, {skipped} skipped")

    print("\nDetections:")
    if not detections:
        print("  CLEAN: no detections")
        return

    by_artifact = {}
    for detection in detections:
        by_artifact.setdefault(detection["artifact"], []).append(detection)

    for artifact, artifact_detections in by_artifact.items():
        print(f"  {artifact}: {len(artifact_detections)} detection(s)")
        for detection in artifact_detections:
            print(
                "    - "
                f"{detection['rule']} "
                f"({detection['corpus']} / {detection['source']})"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Scan payload artifacts against cached public YARA corpora."
    )
    parser.add_argument(
        "artifacts",
        nargs="*",
        help="Files or directories to scan. Defaults to implant PIC, modules, and wrapper stubs.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any public rule detects an artifact.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Write machine-readable scan results to this path.",
    )
    parser.add_argument(
        "--rule-dir",
        dest="rule_dirs",
        action="append",
        help="Rule corpus in NAME=PATH form. When supplied, only these corpora are scanned.",
    )
    args = parser.parse_args()

    artifact_inputs = args.artifacts or DEFAULT_ARTIFACTS
    artifacts = discover_artifacts(artifact_inputs)
    if not artifacts:
        print("ERROR: no artifact files found to scan", file=sys.stderr)
        return 2

    try:
        rule_dirs = parse_rule_dir_args(args.rule_dirs)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    compiled_rules, corpus_counts, skipped_counts = load_rule_corpora(rule_dirs)
    if not compiled_rules:
        print("ERROR: no public YARA rules were available", file=sys.stderr)
        return 2

    detections = []
    for artifact in artifacts:
        detections.extend(scan_artifact(artifact, compiled_rules))

    print_summary(artifacts, corpus_counts, skipped_counts, detections)

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(
                {
                    "artifacts": [str(a) for a in artifacts],
                    "corpora": corpus_counts,
                    "skipped": skipped_counts,
                    "detections": detections,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    return 1 if args.strict and detections else 0


if __name__ == "__main__":
    sys.exit(main())
