# CoinCube Hardware Wallet

A fully air-gapped Bitcoin hardware wallet built on the ESP32-S3, featuring a 128×64 OLED display, two tactile buttons, and an NXP SE051C2 secure element for all private key operations.

---

## Hardware Components

| Component | Part | Role |
|---|---|---|
| Microcontroller | ESP32-S3 (any module) | Application processor, USB CDC, BIP32/39 logic |
| Display | SSD1306 128×64 OLED | Transaction review, address display, QR codes |
| Secure Element | NXP SE051C2 | Key storage, ECDSA/Schnorr signing, TRNG, monotonic counter |
| Button 1 | Tactile N/O (any 6×6 mm) | CONFIRM — select / sign / advance |
| Button 2 | Tactile N/O (any 6×6 mm) | CANCEL — cycle / reject / back |

> **Note on SE migration:** early prototypes use an ATECC608B on the same I²C bus (address `0x60`). The NXP SE051C2 (address `0x48`) replaces it for production. The SE HAL is abstracted so swapping the driver is the only code change required.

---

## Pin Assignments

```
ESP32-S3 Pin  │  Signal       │  Destination
──────────────┼───────────────┼─────────────────────────────
GPIO 8        │  I²C SDA      │  SSD1306 SDA  +  SE051C2 SDA
GPIO 9        │  I²C SCL      │  SSD1306 SCL  +  SE051C2 SCL
GPIO 1        │  BTN_CONFIRM  │  Tactile button → GND
GPIO 2        │  BTN_CANCEL   │  Tactile button → GND
3V3           │  Power        │  SSD1306 VCC  +  SE051C2 VCC
GND           │  Ground       │  SSD1306 GND  +  SE051C2 GND  +  Buttons
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
  │ NXP SE051C2  │  │               │            USB D+/D─ ◄─── USB-C
  │  Secure Elem │  │               │                     │
  │  I²C 0x48    │  │               │                     │
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

### NXP SE051C2 Secure Element
The SE051C2 is the security boundary of the wallet. It communicates over I²C at address `0x48` on the same bus as the OLED. All of the following happen **inside the SE and never leave it**:

- Master private key storage (BIP32 key object)
- Child key derivation for signing
- ECDSA signatures (P2WPKH inputs, BIP143 sighash)
- Schnorr signatures (P2TR inputs, BIP341 sighash)
- True random number generation (used for seed entropy and anti-phishing code)
- Monotonic PIN attempt counter (tamper-resistant, cannot be reset by reflashing)
- PIN hash storage

The ESP32-S3 only ever sees public keys and signatures. The SE uses GlobalPlatform SCP03 for its secure channel; the HAL handles session management transparently.

> **ATECC608B compatibility:** the legacy driver is still present under `#ifdef USE_ATECC608B` for development boards that have not yet been upgraded. The SE HAL interface is identical for both chips, so all higher-level code is portable.

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

Both the SSD1306 and SE051C2 share the same I²C bus (SDA=GPIO8, SCL=GPIO9). This is safe because they have different addresses (`0x3C` vs `0x48`) and the ESP32-S3 is the sole bus master. Recommended bus pull-up resistors: **4.7 kΩ to 3V3** on both SDA and SCL. Many SSD1306 breakout boards include these on-board; if yours does, no additional pull-ups are needed. The SE051C2 bare die / module typically does not include them.

I²C clock speed: **400 kHz (Fast Mode)** is recommended. The SE051C2 supports up to 1 MHz; the SSD1306 is typically rated to 400 kHz.

---

## Power

The wallet runs from the USB 5V rail regulated to 3V3 by the ESP32-S3 module's onboard LDO. Typical current draw:
- Idle (OLED on, SE idle): ~40 mA
- During signing (SE active): ~60 mA
- OLED off (display timeout): ~15 mA

A decoupling capacitor of **100 nF** close to the SE051C2 VCC pin is strongly recommended to suppress I²C transaction noise.

---

## Build Targets

```bash
# Development (WiFi OTA enabled, mock data allowed)
idf.py build -DDEV_BUILD=1

# Production (WiFi disabled, OTA disabled, no mock data)
idf.py build -DPRODUCTION_BUILD=1
```

See `prd.json` for the full feature specification and implementation order.
