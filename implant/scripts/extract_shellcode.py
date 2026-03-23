#!/usr/bin/env python3
"""Post-build script: prints PIC blob size and SHA256 hash, warns if >20KB."""

import hashlib
import os
import sys

MAX_SIZE = 20 * 1024  # 20KB target

def main():
    if len(sys.argv) < 2:
        print("Usage: extract_shellcode.py <blob_path>")
        sys.exit(1)

    blob_path = sys.argv[1]

    if not os.path.isfile(blob_path):
        print(f"[!] File not found: {blob_path}")
        sys.exit(1)

    with open(blob_path, "rb") as f:
        data = f.read()

    size = len(data)
    sha256 = hashlib.sha256(data).hexdigest()

    print(f"[*] SPECTER PIC blob: {blob_path}")
    print(f"    Size  : {size} bytes ({size / 1024:.1f} KB)")
    print(f"    SHA256: {sha256}")

    if size > MAX_SIZE:
        print(f"[!] WARNING: Blob exceeds {MAX_SIZE // 1024}KB target by {size - MAX_SIZE} bytes!")
    else:
        print(f"[+] OK: Under {MAX_SIZE // 1024}KB target ({MAX_SIZE - size} bytes remaining)")

if __name__ == "__main__":
    main()
