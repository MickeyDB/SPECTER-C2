#!/usr/bin/env python3
"""Print a file size without relying on shell-specific wc/tr behavior."""

import os
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: print_size.py <path>", file=sys.stderr)
        return 2
    print(os.path.getsize(sys.argv[1]), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
