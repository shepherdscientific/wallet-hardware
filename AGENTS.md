# AGENTS.md — CoinCube Hardware Wallet

## Build & Flash

```bash
pio run -e dev         # Development (WiFi OTA enabled, -DDEV_BUILD)
pio run -e production  # Production (WiFi disabled, -DPRODUCTION_BUILD)
pio run                # Build both (CI)
pio run -e dev -t upload
pio device monitor -b 115200
```

- PlatformIO, Arduino framework, target: esp32-s3-devkitc-1
- `version.h` contains `#define BUILD_HASH "buildhash_plchld"` — post-build, `scripts/post_build.py` replaces the placeholder in the `.bin` with the first 16 hex chars of its SHA-256
- SDK configs: `sdkconfig.defaults.dev` (no secure boot), `sdkconfig.defaults.production` (secure boot v2 + flash encryption)

## Tests (Host-Based, No ESP32 Toolchain)

All tests compile and run on the host:

```bash
g++ -DUSE_SE_STUB -std=c++11 -I. <sources...> test_*.cpp -o test_*
./test_*
```

- `-DUSE_SE_STUB` selects the stub HAL backend (no ESP32, no I2C)
- Each `test_*.cpp` has its own `main()` — no framework
- Test macros (copied in each file): `TEST(name)`, `PASS()`, `FAIL(msg)`, `ASSERT_EQ(a,b)`, `ASSERT_TRUE(x)`, `ASSERT_FALSE(x)`
- Each test function returns `void`; macros use early `return` on failure
- Test binaries are gitignored

### Existing Test Suites

| Test | Compile Command (from repo root) |
|------|----------------------------------|
| `test_account_manager` | `g++ -std=c++11 -I. account_manager.cpp test_account_manager.cpp -o test_account_manager` |
| `test_balance` | `g++ -DUSE_SE_STUB -std=c++11 -I. balance.cpp test_balance.cpp -o test_balance` |
| `test_settings` | `g++ -DUSE_SE_STUB -std=c++11 -I. settings.cpp test_settings.cpp -o test_settings` |
| `test_tx_history` | `g++ -DUSE_SE_STUB -std=c++11 -I. tx_history.cpp test_tx_history.cpp -o test_tx_history` |
| `test_watchdog` | `g++ -DUSE_SE_STUB -std=c++11 -I. watchdog.cpp test_watchdog.cpp -o test_watchdog` |
| `test_coin_control` | `g++ -DUSE_SE_STUB -std=c++11 -I. psbt.cpp bip32.cpp sha256.cpp sha512.cpp hmac_sha256.cpp hmac_sha512.cpp ripemd160.cpp base58.cpp bech32.cpp se051_hal_stub.cpp address.cpp bip39.cpp wallet_storage.cpp psbt_signer.cpp test_coin_control.cpp -o test_coin_control` |
| `test_multisig` | `g++ -DUSE_SE_STUB -std=c++11 -I. psbt.cpp bip32.cpp sha256.cpp sha512.cpp hmac_sha256.cpp hmac_sha512.cpp ripemd160.cpp base58.cpp bech32.cpp se051_hal_stub.cpp address.cpp bip39.cpp wallet_storage.cpp psbt_signer.cpp test_multisig.cpp -o test_multisig` |
| `test_tx_metadata` | `g++ -DUSE_SE_STUB -std=c++11 -I. psbt.cpp bip32.cpp sha256.cpp sha512.cpp hmac_sha256.cpp hmac_sha512.cpp ripemd160.cpp base58.cpp bech32.cpp se051_hal_stub.cpp address.cpp bip39.cpp wallet_storage.cpp test_tx_metadata.cpp -o test_tx_metadata` |
| `test_fw_integrity` | `g++ -DUSE_SE_STUB -std=c++11 -I. se051_hal_stub.cpp fw_integrity.cpp test_fw_integrity.cpp -o test_fw_integrity` |

Earlier test sources (`test_bip39`, `test_wallet_storage`, `test_bip32`, `test_address`, `test_pin_manager`, `test_psbt`, `test_psbt_signer`, `test_qr_renderer`) were deleted in commit `449db4e` — their sources are recoverable from git history if needed.

Run a single test: compile and run the matching command above, then `./test_*`.

## Architecture

- **Flat structure** — no `src/`, `lib/`, or `include/` subdirectories. All `.h`/`.cpp` pairs are at root.
- **Single entrypoint**: `wallet1.ino` (`setup()` + `loop()`). Arduino `.ino` file, not a standard `.cpp`. State machine drives UI on SSD1306 OLED (I2C 0x3C) via two buttons (CONFIRM=GPIO1, CANCEL=GPIO2, `INPUT_PULLUP`).

### SEAL (Secure Element Abstraction Layer)

- All SE access through `se051_hal.h` interface — **never call `Wire.*` directly** from higher-level code
- Two backends selected at compile time:
  - `-DUSE_SE051` — real I2C to NXP SE051C2 (addr 0x48, SDA=GPIO8, SCL=GPIO9)
  - `-DUSE_SE_STUB` — deterministic host mock (LCG random, fixed keys)
- I2C retry: 3 attempts with 50ms back-off before returning `SE_ERR_COMM`
- APDU framing per ISO 7816-4 (CLA/INS/P1/P2/Lc/data/Le); status word 0x9000 = success
- Typed error codes via enums: `se051_err_t`, `psbt_err_t`, etc. HAL functions never return void.

### NVS Persistence

Dual-backend pattern used by `account_manager`, `settings`, `balance`, `tx_history`:

```cpp
#if defined(ARDUINO) && defined(ESP32)
  // Real NVS via Preferences.h
#else
  // In-memory static globals for host testing
#endif
```

### Sensitive Data Handling

- Zero sensitive buffers with volatile pointer pattern after use: `volatile uint8_t *p = buf; while (len--) *p++ = 0;`
- Partial SE state: if storing key A succeeds but key B fails, delete key A before returning error

### Factory Provisioning (US-031)

- `SE051_OBJ_FW_HASH` (object id `0x06`, ATECC slot `0x0C` via `map_key_id` in `atecc608_hal_esp.cpp`) holds the expected SHA-256 of the running firmware partition
- Write path: `se051_store_key(SE051_OBJ_FW_HASH, hash, 32)` → `atecc_write_slot32` (Write opcode `0x12`, P1 `0x82`)
- Wallet handler in `wallet1.ino` (`handle_provision_hash`) gates on `!wallet_is_initialized()` so the hash cannot be overwritten after setup, even over USB CDC
- Host script: `python3 scripts/provision_fw_hash.py firmware.bin /dev/ttyACM0` sends `PROVISION_HASH:<hex64>\n`, expects `HASH_OK` (success) or `HASH_ERR`
- Slot policy and lock order documented in `scripts/atecc_slot_config.md` — DataZone is locked after provisioning so further writes return `SE_ERR_LOCKED`

## Conventions

### Commits

Conventional commits with user-story scope: `feat(US-029):`, `chore(US-025):`, `chore(ralph):`

### PRD & Progress

- `prd.json` — 30 user stories (US-001 through US-030), each with title, description, agents, acceptance criteria, priority, passes, notes
- **Edit `prd.json` only with `jq`**, never manually or with sed/awk (will create duplicate keys)
- `progress.txt` — manual development log, update after each story completion
- No CI/CD pipeline configured

### Build Flags

| Flag | Effect |
|------|--------|
| `DEV_BUILD` | Enables WiFi, ArduinoOTA, mock test vectors |
| `PRODUCTION_BUILD` | Calls `esp_wifi_stop()` + `esp_wifi_deinit()`, no radio |
| `USE_SE051` | Real SE051C2 I2C driver |
| `USE_SE_STUB` | Host mock (tests only) |

## Key Module Map

| Layer | Files |
|-------|-------|
| Crypto primitives | `sha256`, `sha512`, `hmac_sha256`, `hmac_sha512`, `ripemd160` |
| Wallet crypto | `bip32` (HD derivation), `bip39` (mnemonic), `bip39_english` (wordlist) |
| Addresses | `address`, `base58`, `bech32` |
| Bitcoin protocol | `psbt` (BIP174/370 parser), `psbt_signer` (BIP143/341 signing) |
| SE hardware | `se051_hal`, `se051_hal_esp`, `se051_hal_stub` |
| Wallet logic | `wallet_storage`, `pin_manager`, `account_manager`, `settings`, `balance`, `tx_history` |
| Display | `qrcode` (C lib, extern "C"), `qr_renderer` |
| Transport | `serial_transport` (USB CDC) |
| System | `watchdog` (TWDT 10s), `version` (build hash placeholder) |
