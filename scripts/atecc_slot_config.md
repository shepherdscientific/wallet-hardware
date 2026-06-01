# ATECC608B Slot Configuration — Firmware Hash Slot (US-031)

This document is the **factory-provisioning checklist** for the ATECC608B
slot that backs `SE051_OBJ_FW_HASH` (slot ID `0x06` in the SE abstraction,
mapped to **ATECC slot `0x0C`** in `atecc608_hal_esp.cpp`).

The firmware integrity check (US-030) reads this slot on every boot,
computes the running partition's SHA-256, and halts with `FIRMWARE
TAMPERED!` on mismatch.  For the check to be both **functional** and
**tamper-resistant** the slot must allow:

1. A single 32-byte clear-text write at the factory (PROVISION_HASH command).
2. Read-anywhere afterwards.
3. **No further writes** once the configuration zone is locked.

## Slot 0x0C target configuration

| Field | Value | Meaning |
|-------|-------|---------|
| `SlotConfig[0x0C]` | `0x0F0F` | ReadKey=0xF (clear read), NoMac=1, LimitedUse=0, EncryptRead=0, IsSecret=0, WriteKey=0xF, WriteConfig=0x0F (Always; only meaningful before DataZone lock) |
| `KeyConfig[0x0C]`  | `0x003C` | KeyType=7 (not-an-ECC-key / raw data), Lockable=1, ReqRandom=0, ReqAuth=0, AuthKey=0, IntrusionDisable=0, X509id=0 |

In plain English:

- **Read**: clear-text, no auth, no encryption.  Boot can fetch the hash
  without negotiating a session key.
- **Write before DataZone lock**: clear-text from any host.  This is the
  window in which `scripts/provision_fw_hash.py` writes the hash.
- **Write after DataZone lock**: rejected by the ATECC.  Any later
  `PROVISION_HASH` returns `HASH_ERR` even if a malicious peer reaches
  the USB CDC — defence-in-depth on top of the firmware's
  `!wallet_is_initialized()` gate.

## Provisioning order at the factory

1. **Wake** the ATECC and verify `INFO Revision` succeeds
   (`scripts/post_build.py` / `pio device monitor` both exercise this).
2. **Write `Config` zone** with the slot/key bytes above.  Slot 0x0C lives
   at config-zone offset `0x18 + 0x0C*2 = 0x30..0x31`; KeyConfig at
   `0x60 + 0x0C*2 = 0x78..0x79`.  Use the ATECC `Write` command in
   config-zone mode (P1 zone byte = `0x00`).
3. **Lock the Config zone** (`Lock` command, mode `0x00`, summary CRC).
   This freezes the slot policy but leaves data writeable.
4. **Build and flash** the production firmware.
5. **Run** `python3 scripts/provision_fw_hash.py firmware.bin <port>`.
   The firmware's PROVISION_HASH handler in `wallet1.ino` calls
   `se051_store_key(SE051_OBJ_FW_HASH, hash, 32)`, which dispatches to
   `atecc_write_slot32(0x0C, hash)`.  Wait for `HASH_OK`.
6. **Lock the Data zone** (`Lock` command, mode `0x01`).  After this,
   the slot is read-only forever and any future PROVISION_HASH command
   from the firmware will receive `SE_ERR_LOCKED` from the ATECC and the
   serial handler will reply `HASH_ERR`.
7. **Power-cycle** the device.  The boot screen should display
   "Integrity OK" for ~1 s before the READY screen.

## Verifying the lock

After step 6, on the host:

```
$ python3 scripts/provision_fw_hash.py firmware.bin /dev/ttyACM0
firmware: firmware.bin
sha256:   <same hex as before>
ERR: device rejected PROVISION_HASH (wallet already initialised,
SE offline, or slot locked)
```

This `HASH_ERR` is the success signal for the lock step — the device
correctly refuses to re-provision.

## Tamper test (US-031 acceptance criterion)

1. Edit any byte of `firmware.bin` (e.g. flip the build hash placeholder).
2. Reflash via `pio run -e production -t upload`.
3. On boot the device displays the inverted **FIRMWARE TAMPERED!**
   screen and loops without feeding the watchdog so the TWDT keeps
   resetting back into the tamper screen.  Power-cycle does **not**
   clear it — only re-flashing the original signed image does.

## Notes & gotchas

- The slot must be ≥ 32 bytes; ATECC slots 8-15 satisfy this (slot 0x0C
  is 416 bytes).  Slots 0-7 are too small and would also collide with
  the secp256k1 private-key slots used by US-003.
- `atecc_write_slot32()` writes via `Write` opcode `0x12` with P1
  `0x82` (32-byte data-zone transfer).  Status `0x00` from the ATECC is
  surfaced as `SE_OK`; any non-zero status (e.g. `0x01` ExecError when
  the slot is unlocked, `0x04` ParseError) is surfaced as
  `SE_ERR_LOCKED` — semantically "the SE will not honour this write".
- Blank slots return all-zero (factory default) or all-FF (erased);
  `se051_read_object` treats either as `SE_ERR_NOTFOUND` so the boot
  check skips cleanly on un-provisioned units instead of tripping a
  false tamper alarm.
