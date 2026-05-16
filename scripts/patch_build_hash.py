#!/usr/bin/env python3
"""
Post-build script: inject SHA-256 build hash into firmware binary.

Searches for the 16-byte placeholder string "buildhash_plchld"
and replaces it with the first 16 hex chars of the SHA-256 of the firmware binary.
"""
import hashlib
import sys
import os

PLACEHOLDER = b"buildhash_plchld"


def patch_firmware(bin_path):
    if not os.path.exists(bin_path):
        print(f"patch_build_hash: {bin_path} not found, skipping")
        return False

    with open(bin_path, "rb") as f:
        data = f.read()

    if PLACEHOLDER not in data:
        print(f"patch_build_hash: placeholder not found in {bin_path}, skipping")
        return False

    sha_full = hashlib.sha256(data).hexdigest()
    sha_short = sha_full[:16]
    hash_bytes = sha_short.encode("ascii")

    data = data.replace(PLACEHOLDER, hash_bytes, 1)

    with open(bin_path, "wb") as f:
        f.write(data)

    print(f"patch_build_hash: injected build hash {sha_short} into {bin_path}")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware.bin>", file=sys.stderr)
        sys.exit(1)
    success = patch_firmware(sys.argv[1])
    sys.exit(0 if success else 1)
