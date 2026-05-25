#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "se051_hal.h"
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

Adafruit_SSD1306 display(128, 64, &Wire, -1);
bool seAvailable = false;

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

void loop() {
  watchdog_feed();
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
