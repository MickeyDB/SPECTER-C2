#!/usr/bin/env python3
"""Remove generated implant build artifacts without shell glob semantics."""

from pathlib import Path
import sys


def main() -> int:
    build_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "build")
    build_dir.mkdir(parents=True, exist_ok=True)
    for suffix in {".o", ".elf", ".bin", ".map"}:
        for path in build_dir.glob(f"*{suffix}"):
            if path.is_file():
                path.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
