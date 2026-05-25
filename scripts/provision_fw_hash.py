#!/usr/bin/env python3
"""Factory provisioning: compute the SHA-256 of a firmware image and write it
to the device's secure-element firmware-hash slot (SE051_OBJ_FW_HASH / ATECC
slot 0x0C).  The wallet must NOT yet be initialised — the firmware rejects
the command once a seed has been provisioned, so the integrity hash can be
written at the factory but not overwritten by an attacker later.

Wire protocol (one line, '\n'-terminated, 115200 8N1 over USB CDC):

    -> PROVISION_HASH:<64-hex-chars>
    <- HASH_OK            on success
    <- HASH_ERR           on any failure

Usage:
    python3 scripts/provision_fw_hash.py firmware.bin /dev/ttyACM0
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time

try:
    import serial  # type: ignore
except ImportError:  # pragma: no cover - tooling guidance only
    sys.stderr.write(
        "pyserial is required: pip install pyserial\n"
    )
    sys.exit(2)


READ_TIMEOUT_S = 5.0
BAUD = 115200


def sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.digest()


def read_until_token(ser: "serial.Serial", deadline: float) -> str:
    """Read complete lines from the device until one matches HASH_OK / HASH_ERR
    or the deadline expires.  Other lines (boot banners etc.) are discarded."""
    buf = bytearray()
    while time.monotonic() < deadline:
        chunk = ser.read(64)
        if not chunk:
            continue
        buf.extend(chunk)
        while b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            buf = bytearray(rest)
            text = line.decode("utf-8", errors="replace").strip()
            if text in ("HASH_OK", "HASH_ERR"):
                return text
    return ""


def provision(firmware_path: str, port: str) -> int:
    digest = sha256_file(firmware_path)
    hex_digest = digest.hex()
    print(f"firmware: {firmware_path}")
    print(f"sha256:   {hex_digest}")

    with serial.Serial(port, BAUD, timeout=0.2) as ser:
        # Give the device a moment to settle after USB CDC enumerates.
        time.sleep(0.5)
        ser.reset_input_buffer()

        line = f"PROVISION_HASH:{hex_digest}\n".encode("ascii")
        ser.write(line)
        ser.flush()

        deadline = time.monotonic() + READ_TIMEOUT_S
        result = read_until_token(ser, deadline)

    if result == "HASH_OK":
        print("OK: firmware hash written to secure element")
        return 0
    if result == "HASH_ERR":
        print(
            "ERR: device rejected PROVISION_HASH (wallet already initialised, "
            "SE offline, or slot locked)",
            file=sys.stderr,
        )
        return 1
    print("ERR: no reply within timeout", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("firmware", help="path to firmware.bin")
    ap.add_argument("port", help="serial port, e.g. /dev/ttyACM0 or COM5")
    args = ap.parse_args()
    return provision(args.firmware, args.port)


if __name__ == "__main__":
    sys.exit(main())
