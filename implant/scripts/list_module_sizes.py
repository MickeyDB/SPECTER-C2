#!/usr/bin/env python3
"""Print module artifact sizes for make modules."""

import os
import sys


def main() -> int:
    for path in sys.argv[1:]:
        print(f"  {path} ({os.path.getsize(path)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
