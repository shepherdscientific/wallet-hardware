# CoinCube Hardware Wallet

A fully air-gapped Bitcoin hardware wallet built on the ESP32-S3, featuring a 128×64 OLED display, two tactile buttons, and a hardware secure element for all private key operations.

---

## Hardware Components

| Component | Part | Role |
|---|---|---|
| Microcontroller | ESP32-S3 (any module) | Application processor, USB CDC, BIP32/39 logic |
| Display | SSD1306 128×64 OLED | Transaction review, address display, QR codes |
| Secure Element | Microchip ATECC608B *(current)* | Key storage, ECDSA signing, TRNG, monotonic counter |
| Button 1 | Tactile N/O (any 6×6 mm) | CONFIRM — select / sign / advance |
| Button 2 | Tactile N/O (any 6×6 mm) | CANCEL — cycle / reject / back |

---

## Secure Element Roadmap

CoinCube uses a compile-time–selectable SE HAL (`USE_ATECC608B` / `USE_SE051` / `USE_SE_STUB` / `USE_SE_FPGA`). Swapping the backend requires only a new HAL implementation file — all wallet logic above is portable.

| Phase | Chip | Status | Notes |
|-------|------|--------|-------|
| **Current** | Microchip ATECC608B | ✅ In use | I²C `0x64`, ECDSA P-256, TRNG, monotonic counter, slot-based key store |
| **Near-term** | NXP SE051E / SE050E | 🔜 On order | GlobalPlatform SCP03 secure channel, native Schnorr support, post-quantum extensions (CRYSTALS-Kyber, CRYSTALS-Dilithium via SE051E PQC variant) |
| **Research** | Tang Nano 9K FPGA custom SE | 🔬 In design | Ternary-logic co-processor targeting ternary-accelerated lattice-based PQC (NTRU / CRYSTALS variants); interfaces over SPI/I²C with the same HAL abstraction |

The FPGA SE is a longer-horizon research track — the goal is a fully open, auditable, ternary-native cryptographic core that can be independently verified down to the gate level, unlike closed-source silicon SEs.

---

## Pin Assignments

```
ESP32-S3 Pin  │  Signal       │  Destination
──────────────┼───────────────┼──────────────────────────────────
GPIO 8        │  I²C SDA      │  SSD1306 SDA  +  ATECC608B SDA
GPIO 9        │  I²C SCL      │  SSD1306 SCL  +  ATECC608B SCL
GPIO 1        │  BTN_CONFIRM  │  Tactile button → GND
GPIO 2        │  BTN_CANCEL   │  Tactile button → GND
3V3           │  Power        │  SSD1306 VCC  +  ATECC608B VCC
GND           │  Ground       │  SSD1306 GND  +  ATECC608B GND  +  Buttons
USB D+/D−     │  Native USB   │  USB-C connector (PSBT exchange / firmware)
```

---

## Wiring Diagram

```
                    ┌─────────────────────────────────────┐
                    │            ESP32-S3                 │
                    │                                     │
  ┌──────────────┐  │ 3V3 ──────────────────────────────  │
  │ SSD1306 OLED │  │ GND ──────────────────────────────  │
  │  128×64 px   │  │                                     │
  │  I²C 0x3C    │  │ GPIO8 (SDA) ───────────────────────►│
  │              │  │ GPIO9 (SCL) ───────────────────────►│
  │ VCC ◄────────┼──┤ 3V3                                 │
  │ GND ◄────────┼──┤ GND                     GPIO1 ◄─────┼── [CONFIRM]─── GND
  │ SDA ◄────────┼──┤ GPIO8 (SDA) ──┐         GPIO2 ◄─────┼── [CANCEL] ─── GND
  │ SCL ◄────────┼──┤ GPIO9 (SCL) ──┤                     │
  └──────────────┘  │               │ shared I²C bus       │
                    │               │                     │
  ┌──────────────┐  │               │                     │
  │ ATECC608B    │  │               │            USB D+/D─ ◄─── USB-C
  │  Secure Elem │  │               │                     │
  │  I²C 0x64    │  │               │                     │
  │              │  │               │                     │
  │ VCC ◄────────┼──┤ 3V3           │                     │
  │ GND ◄────────┼──┤ GND           │                     │
  │ SDA ◄────────┼──┘ (shared) ─────┘                     │
  │ SCL ◄────────┼── GPIO9 (shared)                       │
  └──────────────┘  └─────────────────────────────────────┘

  [CONFIRM] = tactile button, normally open, pin A → GPIO1, pin B → GND
  [CANCEL]  = tactile button, normally open, pin A → GPIO2, pin B → GND
  Both buttons use ESP32-S3 internal pull-ups (INPUT_PULLUP). No external resistors needed.
  Both I²C devices share the same SDA/SCL lines. Pull-ups: 4.7 kΩ to 3V3 recommended.
```

---

## Component Notes

### SSD1306 OLED (128×64)
The display communicates over I²C at address `0x3C`. It is driven by the Adafruit SSD1306 library. At 128×64 pixels and `textSize(1)`, each character is 6×8 px giving 21 characters across and 8 rows — enough to display a chunked Bech32m address, transaction amounts, and a menu simultaneously. The display is set to auto-off after a configurable timeout (default 60 s) to prevent burn-in and reduce the side-channel attack surface.

### Microchip ATECC608B Secure Element *(current)*
The ATECC608B is the current security boundary of the wallet. It communicates over I²C at address `0x64` on the same bus as the OLED. All of the following happen **inside the SE and never leave it**:

- Master private key storage (slot-mapped BIP32 key material)
- ECDSA signatures (P2WPKH inputs, BIP143 sighash)
- True random number generation (used for seed entropy and anti-phishing code)
- Monotonic PIN attempt counter (tamper-resistant, cannot be reset by reflashing)
- PIN hash storage and firmware integrity hash (slot 0x0C)

The ESP32-S3 only ever sees public keys and signatures. The HAL (`atecc608_hal_esp.cpp`, compiled under `-DUSE_ATECC608B`) implements the Microchip CryptoAuthLib-compatible wire protocol including the LSB-first CRC-16/8005 variant and the chip wake sequence.

> **SE HAL abstraction:** the SE interface is compile-time selectable via `USE_ATECC608B`, `USE_SE051`, `USE_SE_STUB`, or `USE_SE_FPGA` build flags. All wallet logic above the HAL is portable across backends. See the SE Roadmap table above for planned integrations.

### Buttons (GPIO1 / GPIO2)
Both buttons are simple normally-open tactile switches wired from their GPIO pin to GND. The ESP32-S3's internal pull-up resistors are enabled via `INPUT_PULLUP` — no external resistors are required. A press reads `LOW`; idle reads `HIGH`. A 180 ms software debounce delay is applied after each detected press.

Button roles adapt by context:

| Screen | CONFIRM (GPIO1) | CANCEL (GPIO2) |
|---|---|---|
| Main menu | Enter selected item | Cycle to next item |
| Submenus / info | Return to menu | Return to menu |
| Sign TX | Sign and return PSBT | Reject and return to menu |
| PIN entry | Select current digit | Advance to next digit |
| Mnemonic display | Confirm word 24 / done | Advance to next word |

### Native USB (ESP32-S3)
The ESP32-S3 has a built-in USB 1.1 full-speed PHY. In development builds this runs Arduino OTA over WiFi. In **production builds, WiFi is fully disabled** (`-DPRODUCTION_BUILD`) and the USB port exposes a CDC serial interface only. The PSBT exchange protocol over USB is newline-delimited base64:

```
Host  →  Device :  PSBT:<base64>\n
Device →  Host  :  SIGNED:<base64>\n  |  REJECTED\n  |  ERROR:<code>\n
```

---

## I²C Bus Notes

The SSD1306 and ATECC608B share the same I²C bus (SDA=GPIO8, SCL=GPIO9). This is safe because they have different addresses (`0x3C` vs `0x64`) and the ESP32-S3 is the sole bus master. Recommended bus pull-up resistors: **4.7 kΩ to 3V3** on both SDA and SCL. Many SSD1306 breakout boards include these on-board; if yours does, no additional pull-ups are needed. The ATECC608B module typically does not include them.

I²C clock speed: **400 kHz (Fast Mode)** is recommended. The ATECC608B supports up to 1 MHz; the SSD1306 is typically rated to 400 kHz.

The Wire timeout is set to **50 ms** per transaction in the SE HAL (`Wire.setTimeOut(50)`). The ATECC608B wake token (broadcasting address 0x00) is sent first; if the chip does not ACK within the retry window the HAL returns `SE_ERR_COMM` and the wallet boots without SE (`seAvailable = false`). When the NXP SE051 is integrated, the SCP03 handshake will extend the init time slightly but remains well within the 50 ms per-transfer budget.

---

## Power

The wallet runs from the USB 5V rail regulated to 3V3 by the ESP32-S3 module's onboard LDO. Typical current draw:
- Idle (OLED on, SE idle): ~40 mA
- During signing (SE active): ~60 mA
- OLED off (display timeout): ~15 mA

A decoupling capacitor of **100 nF** close to the SE051C2 VCC pin is strongly recommended to suppress I²C transaction noise.

---

## Build Targets

The project uses PlatformIO (`platformio.ini`) with two environments:

```bash
# Install PlatformIO (if not already installed)
pip install platformio

# Development build (WiFi OTA enabled, mock data allowed)
pio run -e dev

# Production build (WiFi disabled, OTA disabled, no mock data)
pio run -e production

# Build both environments (CI)
pio run
```

### Flashing

```bash
# Flash development firmware via USB
pio run -e dev -t upload

# Flash production firmware via USB
pio run -e production -t upload

# Monitor serial output
pio device monitor -b 115200
```

### Production Verification

```bash
# Production binary must be < 1.2 MB (WiFi stack excluded)
pio run -e production
ls -l .pio/build/production/firmware.bin
# macOS: stat -f%z .pio/build/production/firmware.bin
# Linux: stat -c%s .pio/build/production/firmware.bin
```

### WiFi / OTA: Dev vs Production

| Aspect | Dev Build (`DEV_BUILD`) | Production Build (`PRODUCTION_BUILD`) |
|--------|--------------------------|---------------------------------------|
| WiFi stack | Linked and enabled | Radio powered off at boot (`esp_wifi_stop` / `esp_wifi_deinit`) |
| OTA updates | Over WiFi (ArduinoOTA) | Over USB only (DFU / UART bootloader) |
| `secrets.h` | Required (contains SSID/password) | Not included; no dependency |
| Binary size | ~1.5 MB (with WiFi stack) | Should be < 1.2 MB |

The production firmware has **no wireless capability at all** — the WiFi stack is excluded at compile time and the radio is explicitly powered off at boot. This ensures the device is truly air-gapped in production.

---

## Secure Boot v2 & Flash Encryption (Production)

### Overview

ESP32-S3 secure boot v2 ensures only signed firmware executes on the device. Combined with flash encryption, it protects against:
- Physical flash chip extraction and analysis
- Unauthorized firmware replacement
- Rollback attacks (via anti-rollback eFuse)

**Both features are PERMANENT once eFuses are burned. Test thoroughly before burning.**

### Key Ceremony

The signing key must be generated in a secure offline environment and never exposed to networked systems:

```bash
# 1. Generate secure boot signing key (offline, air-gapped machine)
#    ESP32-S3 secure boot v2 uses ECDSA P-256 with SHA-256
openssl ecparam -name prime256v1 -genkey -noout -out secure_boot_signing_key.pem

# 2. Extract public key for eFuse burning
openssl ec -in secure_boot_signing_key.pem -pubout -out secure_boot_signing_key.pub

# 3. Generate flash encryption key (256-bit AES)
#    ESP32-S3 uses XTS-AES-256 for flash encryption
openssl rand -out flash_encryption_key.bin 32

# 4. Store keys securely (HSM, air-gapped encrypted storage)
#    NEVER commit keys to the repository or share them over the network
```

### Build Configuration

```bash
# Generate production sdkconfig with secure boot + flash encryption
./scripts/gen_sdkconfig.sh production

# Edit the generated sdkconfig.production:
#   - Set CONFIG_SECURE_BOOT_SIGNING_KEY="secure_boot_signing_key.pem"
#   - Verify CONFIG_SECURE_BOOT_V2_ENABLED=y
#   - Verify CONFIG_FLASH_ENCRYPTION_ENABLED=y

# Build with secure boot enabled
pio run -e production
```

The `sdkconfig.defaults.production` file contains the minimal security overrides. The `scripts/gen_sdkconfig.sh` script merges these with the auto-generated PlatformIO sdkconfig.

### eFuse Burning (Manufacturing)

**WARNING: eFuse burning is IRREVERSIBLE. Once burned, unsigned firmware will NOT boot.**

Test the firmware WITHOUT burning eFuses first (the ESP32-S3 ROM bootloader checks eFuses — if they're not burned, any firmware boots):

```bash
# Flash and test WITHOUT eFuses
pio run -e production -t upload
pio device monitor -b 115200
# Verify: boot splash, PIN entry, About screen shows correct version and SE serial
# Verify: signing a transaction works correctly

# Only after successful testing, burn eFuses:
pip install esptool

# Burn secure boot key digest (BLOCK_KEY0 for ESP32-S3)
espefuse.py --port /dev/cu.usbmodem* burn_key BLOCK_KEY0 secure_boot_signing_key.pem SECURE_BOOT

# Enable secure boot
espefuse.py --port /dev/cu.usbmodem* burn_efuse SECURE_BOOT_EN 1

# Burn flash encryption key (BLOCK_KEY1)
espefuse.py --port /dev/cu.usbmodem* burn_key BLOCK_KEY1 flash_encryption_key.bin FLASH_CRYPT

# Enable flash encryption (release mode)
espefuse.py --port /dev/cu.usbmodem* burn_efuse FLASH_CRYPT_CNT 127

# Verify eFuse summary
espefuse.py --port /dev/cu.usbmodem* summary
```

After eFuse burning, the device will:
1. Reject any unsigned firmware at boot (ESP32-S3 ROM verifier)
2. Run flash encryption on first boot (encrypts all partitions transparently)
3. Store NVS and firmware encrypted at rest

### Firmware Version Attestation

The device's About screen (Settings → About) displays:
- **FW**: firmware version (`FIRMWARE_VERSION` in `version.h`)
- **Hash**: first 16 hex chars of SHA-256 of the firmware binary (injected post-build by `scripts/post_build.py`)
- **SE**: secure element serial number (read via `se051_get_serial()`)

Users can verify the firmware hash against the published build artifacts to confirm they are running authentic software.

The build hash is injected by the PlatformIO post-build script (`scripts/post_build.py`). It replaces the `buildhash_plchld` placeholder in `version.h` with the first 16 hex characters of the firmware SHA-256.

> **Known limitation:** `post_build.py` modifies the binary after the ESP-IDF bootloader app-image digest is computed. This invalidates the digest and causes the bootloader to reject the image (`rst:0x3`, Saved PC in bootloader IRAM). The script is therefore **disabled for the dev environment**. Before re-enabling it for production, `post_build.py` must be updated to recompute and re-seal the image digest with `esptool.py` after patching — or the build hash should instead be stored as an NVS key written at first boot.

### Disabling Secure Boot (Development)

For development boards, do NOT burn eFuses. Use the dev environment:

```bash
pio run -e dev -t upload
```

Dev builds have no secure boot and no flash encryption — allowing rapid iteration and debugging via USB.
