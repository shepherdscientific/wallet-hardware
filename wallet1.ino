#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "esp_partition.h"
#include "se051_hal.h"
#include "sha256.h"
#include "pin_manager.h"
#include "wallet_storage.h"
#include "bip39.h"
#include "address.h"
#include "bip32.h"
#include "qr_renderer.h"
#include "psbt.h"
#include "psbt_signer.h"
#include "bech32.h"
#include "serial_transport.h"
#include "base64.h"
#include "account_manager.h"
#include "settings.h"
#include "version.h"
#include "watchdog.h"
#include "balance.h"
#include "tx_history.h"
#include "fw_integrity.h"

Adafruit_SSD1306 display(128, 64, &Wire, -1);
bool seAvailable = false;

// ─── US-030: Firmware Integrity Self-Test ────────────────────────────────
//
// Reads the expected SHA-256 hash from SE object 0x06 (written at factory
// provisioning), then computes SHA-256 over the running firmware partition
// and compares.  If no hash is provisioned (SE_ERR_NOTFOUND), the check is
// skipped gracefully — the device has not been through factory provisioning.
// Build with -DSKIP_INTEGRITY_CHECK to bypass entirely (dev builds).

#ifndef SKIP_INTEGRITY_CHECK

// Returns true  → firmware OK (or no hash provisioned yet)
// Returns false → hash mismatch, tamper detected
static bool firmware_integrity_check(void) {
  if (!seAvailable) return true;   // SE offline → cannot verify, allow boot

  // Read expected hash from SE object 0x06
  uint8_t stored_hash[SHA256_DIGEST_LENGTH];
  size_t  stored_len = 0;
  se051_err_t rc = se051_read_object(SE051_OBJ_FW_HASH,
                                     stored_hash, sizeof(stored_hash),
                                     &stored_len);
  if (rc == SE_ERR_NOTFOUND || stored_len != SHA256_DIGEST_LENGTH) {
    return true;   // not provisioned yet — skip check
  }
  if (rc != SE_OK) return true;    // SE read error → fail-open (dev safety)

  // Locate the running firmware partition
  const esp_partition_t *part = esp_partition_find_first(
    ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
  if (!part) return false;

  // Stream-hash the partition in 4 KB chunks
  sha256_ctx ctx;
  sha256_init(&ctx);

  static uint8_t chunk[4096];          // static: avoids large stack frame
  uint32_t offset    = 0;
  uint32_t remaining = part->size;

  while (remaining > 0) {
    uint32_t to_read = (remaining < sizeof(chunk)) ? remaining
                                                   : (uint32_t)sizeof(chunk);
    if (esp_partition_read(part, offset, chunk, to_read) != ESP_OK) {
      return false;
    }
    sha256_update(&ctx, chunk, (size_t)to_read);
    offset    += to_read;
    remaining -= to_read;
    watchdog_feed();                   // keep watchdog happy during long hash
  }

  uint8_t computed[SHA256_DIGEST_LENGTH];
  sha256_final(&ctx, computed);

  return memcmp(computed, stored_hash, SHA256_DIGEST_LENGTH) == 0;
}

// Call after SE init.  Blocks forever on tamper; shows 1-second OK banner.
static void run_integrity_check(void) {
  bool ok = firmware_integrity_check();

  if (!ok) {
    // ── TAMPER DETECTED ──────────────────────────────────────────────────
    display.invertDisplay(true);
    display.clearDisplay();
    display.setTextSize(2);
    display.setCursor(0, 4);
    display.println("FIRMWARE");
    display.println("TAMPERED!");
    display.setTextSize(1);
    display.setCursor(0, 48);
    display.println("Power-cycle to retry");
    display.display();
    // Loop indefinitely.  Do NOT feed the watchdog — let it reset the device
    // so the tamper screen re-appears on every reboot until physically fixed.
    for (;;) { delay(500); }
  }

  // ── INTEGRITY OK ─────────────────────────────────────────────────────
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(16, 22);
  display.println("Integrity OK");
  display.setCursor(48, 34);
  display.println("OK");
  display.display();
  delay(1000);
}

#endif // SKIP_INTEGRITY_CHECK

static void i2c_bus_sweep(void) {
  for (uint8_t addr = 1; addr < 128; addr++) {
    Wire.beginTransmission(addr);
    Wire.endTransmission();
  }
}

void showBootSplash() {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(15, 18);
  display.println("COINCUBE");
  display.setTextSize(1);
  display.setCursor(10, 40);
  display.println("SECURE APPARATUS");
  display.display();
  delay(2000);
}

void setup() {
  Serial.begin(115200);
  serial_init();
  Wire.begin(8, 9);

  i2c_bus_sweep();

  display.begin(SSD1306_SWITCHCAPVCC, 0x3C) || display.begin(SSD1306_EXTERNALVCC, 0x3C);
  pinMode(1, INPUT_PULLUP);
  pinMode(2, INPUT_PULLUP);

  showBootSplash();

  watchdog_init();
  account_init();
  settings_init();
  balance_init();
  display.ssd1306_command(SSD1306_SETCONTRAST);
  display.ssd1306_command(settings_get_contrast());

  i2c_bus_sweep();
  delay(2);

  // ── I2C scan: collect responding addresses ──────────────────────────────
  uint8_t found[8];
  uint8_t nfound = 0;
  for (uint8_t addr = 1; addr < 128 && nfound < 8; addr++) {
    Wire.beginTransmission(addr);
    if (Wire.endTransmission() == 0) found[nfound++] = addr;
  }

  se051_err_t seErr = se051_init();
  seAvailable = (seErr == SE_OK);

#ifndef SKIP_INTEGRITY_CHECK
  run_integrity_check();
#endif

  display.clearDisplay();
  display.setTextSize(2);
  display.setCursor(10, 10);
  display.println("READY");
  display.setTextSize(1);

  // Row 1: SE status + error code if failed
  display.setCursor(0, 34);
  display.print("SE:");
  display.print(seAvailable ? "YES" : "NO");
  if (!seAvailable) {
    display.print(" E");
    display.print((int)seErr);
  }

  // Row 2: I2C addresses found
  display.setCursor(0, 46);
  display.print("I2C:");
  for (uint8_t i = 0; i < nfound; i++) {
    display.print("0x");
    display.print(found[i], HEX);
    display.print(" ");
  }
  if (nfound == 0) display.print("none");

  display.display();
}

// ─── US-031: Factory provisioning handler ────────────────────────────────
//
// Handles a single line of PROVISION_HASH:<64-hex-chars> arriving over USB
// CDC.  The command is rejected after the wallet is set up so a post-setup
// attacker cannot overwrite the stored firmware hash and bypass US-030's
// tamper detection.  Reply is the single token "HASH_OK" on success or
// "HASH_ERR" on any failure (wallet already initialized, SE offline, or
// SE write rejected).
static void handle_provision_hash(const uint8_t *hash32) {
  if (!hash32 || wallet_is_initialized() || !seAvailable) {
    serial_send_hash_err();
    return;
  }
  se051_err_t rc = se051_store_key(SE051_OBJ_FW_HASH, hash32, 32);
  if (rc == SE_OK) serial_send_hash_ok();
  else             serial_send_hash_err();
}

// File-scope static: the serial_msg_t struct is 8 KB (data[8192]).
// Declaring it here moves it to the BSS segment instead of the loopTask
// stack (default 8 KB), preventing the "Stack canary watchpoint triggered
// (loopTask)" crash introduced when serial_poll() was called by value.
static serial_msg_t g_serial_msg;

void loop() {
  watchdog_feed();

  serial_poll_into(&g_serial_msg);
  if (g_serial_msg.cmd == SERIAL_CMD_PROVISION_HASH && g_serial_msg.data_len == 32) {
    handle_provision_hash(g_serial_msg.data);
  }

  bool c = (digitalRead(1) == LOW);
  bool l = (digitalRead(2) == LOW);
  if (c || l) {
    display.clearDisplay();
    display.setCursor(0,0);
    if (c) display.println("C");
    if (l) display.println("L");
    display.display();
  }
  delay(50);
}
