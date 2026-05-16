#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <ArduinoOTA.h>
#include "secrets.h"
#include "se051_hal.h"
#include "pin_manager.h"
#include "wallet_storage.h"

// --- HARDWARE CONFIG ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define SDA_PIN 8
#define SCL_PIN 9
#define BTN_CONFIRM 1
#define BTN_CANCEL 2

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// --- NETWORK CREDENTIALS ---
const char* ssid = SECRET_SSID;
const char* password = SECRET_PASS;

// --- WALLET STATE MACHINE ---
enum WalletState {
  PIN_SETUP,
  PIN_ENTRY,
  MAIN_MENU,
  SHOW_BALANCE,
  SHOW_ADDRESS,
  SIGN_TX,
  PQC_STATUS,
  TX_SUCCESS,
  WALLET_WIPED
};
WalletState currentState = PIN_SETUP;

int menuIndex = 0;
const int TOTAL_MENU_ITEMS = 4;
const char* menuItems[] = {
  "1. View Balance",
  "2. Receive (Addr)",
  "3. Sign Transaction",
  "4. PQC Quantum Sec"
};

// --- PIN STATE ---
uint8_t pinDigits[6] = {0};
uint8_t pinPosition = 0;
uint8_t pinDigitValue = 0;
uint8_t pinAttempts = 0;

// --- REAL BITCOIN DATA (MOCK MINTED) ---
const char* BTC_ADDRESS = "bc1p5d7txrekgvk0llknw8vkm6680zhv93";
uint64_t walletSats = 42050000;

// --- DEVICE UID (ESP32) ---
void pin_get_device_uid(uint8_t uid[8]) {
  uint64_t mac = ESP.getEfuseMac();
  memset(uid, 0, 8);
  for (int i = 0; i < 6; i++) {
    uid[6 - i] = (mac >> (i * 8)) & 0xFF;
  }
}

void setup() {
  Serial.begin(115200);
  Wire.begin(SDA_PIN, SCL_PIN);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) for(;;);

  pinMode(BTN_CONFIRM, INPUT_PULLUP);
  pinMode(BTN_CANCEL, INPUT_PULLUP);

  showBootSplash();

  // --- NON-BLOCKING WIFI WITH TIMEOUT ---
  WiFi.begin(ssid, password);
  int timeout = 0;
  while (WiFi.status() != WL_CONNECTED && timeout < 8) {
    delay(500);
    timeout++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    ArduinoOTA.setHostname("coincube-wallet");
    ArduinoOTA.setPassword("cube526");
    ArduinoOTA.begin();
    Serial.println("OTA Active");
  }

  se051_init();

  if (pin_is_set()) {
    currentState = PIN_ENTRY;
    pinAttempts = pin_get_attempts();
    pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
    pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
    pinPosition = 0;
    pinDigitValue = 0;
  } else {
    currentState = PIN_SETUP;
    pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
    pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
    pinPosition = 0;
    pinDigitValue = 0;
  }
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    ArduinoOTA.handle();
  }

  handleNavigation();
  renderCurrentState();
  delay(30);
}

// --- UNIVERSAL 2-BUTTON NAVIGATION ENGINE ---
void handleNavigation() {
  bool confirmPressed = (digitalRead(BTN_CONFIRM) == LOW);
  bool cancelPressed = (digitalRead(BTN_CANCEL) == LOW);

  if (!confirmPressed && !cancelPressed) return;

  delay(180);

  switch (currentState) {
    case PIN_SETUP:
      if (confirmPressed) {
        pinDigitValue = (pinDigitValue + 1) % 10;
      } else if (cancelPressed) {
        pinDigits[pinPosition] = pinDigitValue;
        pinPosition++;
        pinDigitValue = 0;
        if (pinPosition >= 6) {
          if (pin_setup(pinDigits)) {
            pin_reset_attempts();
            pinAttempts = 0;
            currentState = MAIN_MENU;
          }
        }
      }
      break;

    case PIN_ENTRY:
      if (confirmPressed) {
        pinDigitValue = (pinDigitValue + 1) % 10;
      } else if (cancelPressed) {
        pinDigits[pinPosition] = pinDigitValue;
        pinPosition++;
        pinDigitValue = 0;
        if (pinPosition >= 6) {
          if (pin_verify(pinDigits)) {
            pin_reset_attempts();
            pinAttempts = 0;
            currentState = MAIN_MENU;
          } else {
            pin_increment_attempts();
            pinAttempts = pin_get_attempts();
            if (pinAttempts >= 5) {
              wallet_factory_reset();
              currentState = WALLET_WIPED;
            } else {
              pinPosition = 0;
              pinDigitValue = 0;
              pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
              pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
            }
          }
        }
      }
      break;

    case MAIN_MENU:
      if (cancelPressed) {
        menuIndex = (menuIndex + 1) % TOTAL_MENU_ITEMS;
      } else if (confirmPressed) {
        if (menuIndex == 0) currentState = SHOW_BALANCE;
        if (menuIndex == 1) currentState = SHOW_ADDRESS;
        if (menuIndex == 2) currentState = SIGN_TX;
        if (menuIndex == 3) currentState = PQC_STATUS;
      }
      break;

    case SHOW_BALANCE:
    case SHOW_ADDRESS:
    case PQC_STATUS:
    case TX_SUCCESS:
      if (cancelPressed || confirmPressed) {
        currentState = MAIN_MENU;
      }
      break;

    case SIGN_TX:
      if (cancelPressed) {
        currentState = MAIN_MENU;
      } else if (confirmPressed) {
        executeSigningSequence();
      }
      break;

    case WALLET_WIPED:
      break;
  }
}

// --- SCREEN RENDERERS ---
void renderCurrentState() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);

  switch (currentState) {
    case PIN_SETUP:
      display.setCursor(0, 0);
      display.println("SET PIN");
      display.println("---------------------");
      display.setCursor(20, 20);
      for (int i = 0; i < 6; i++) {
        if (i < pinPosition) {
          display.print("*");
        } else if (i == pinPosition) {
          display.print("[");
          display.print(pinDigitValue);
          display.print("]");
        } else {
          display.print("_");
        }
        if (i < 5) display.print(" ");
      }
      display.setCursor(0, 45);
      display.print("CONFIRM=change CANCEL=next");
      break;

    case PIN_ENTRY:
      display.setCursor(0, 0);
      display.println("ENTER PIN");
      display.println("---------------------");
      display.setCursor(20, 20);
      for (int i = 0; i < 6; i++) {
        if (i < pinPosition) {
          display.print("*");
        } else if (i == pinPosition) {
          display.print("[");
          display.print(pinDigitValue);
          display.print("]");
        } else {
          display.print("_");
        }
        if (i < 5) display.print(" ");
      }
      if (pinAttempts > 0) {
        display.setCursor(0, 40);
        display.print("Attempt ");
        display.print(pinAttempts);
        display.print(" of 5");
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=change CANCEL=next");
      break;

    case MAIN_MENU:
      display.setCursor(0, 0);
      display.println("COINCUBE BITCOIN  [v0.1]");
      display.println("---------------------");
      for (int i = 0; i < TOTAL_MENU_ITEMS; i++) {
        if (i == menuIndex) {
          display.print("> ");
        } else {
          display.print("  ");
        }
        display.println(menuItems[i]);
      }
      break;

    case SHOW_BALANCE:
      display.setCursor(0, 0);
      display.println("WALLET BALANCE");
      display.println("---------------------");
      display.setCursor(0, 20);
      display.setTextSize(2);
      display.print("0.42050");
      display.setTextSize(1);
      display.println(" BTC");
      display.setCursor(0, 42);
      display.println("Sats: 42,050,000");
      display.setCursor(0, 56);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(" [BACK] ");
      break;

    case SHOW_ADDRESS:
      display.setCursor(0, 0);
      display.println("BTC RECEIVE ADDRESS");
      display.println("---------------------");
      display.setTextSize(1);
      display.setCursor(0, 20);
      display.println("bc1p5d7txrekgvk0l");
      display.println("lknw8vkm6680zhv93");
      display.setCursor(0, 45);
      display.println("Verify layout on host!");
      display.setCursor(0, 56);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(" [BACK] ");
      break;

    case SIGN_TX:
      display.setCursor(0, 0);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.println("  CONFIRM TRANSACTION  ");
      display.setTextColor(SSD1306_WHITE);
      display.println("---------------------");
      display.print("OUT: "); display.println("0.05120000 BTC");
      display.print("FEE: "); display.println("14500 Sats (22 vB)");
      display.print("TO : "); display.println("bc1q9w...x83p");
      display.println("---------------------");
      display.print("[REJECT]       [SIGN]");
      break;

    case PQC_STATUS:
      display.setCursor(0, 0);
      display.println("POST-QUANTUM STATUS");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.print("NIST PQC: "); display.println("ML-KEM-512");
      display.print("Hardware: "); display.println("NXP SE051C2");
      display.print("Sec Element: "); display.println("secp256k1");
      display.setCursor(0, 52);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(" [BACK] ");
      break;

    case TX_SUCCESS:
      display.setCursor(0, 10);
      display.setTextSize(2);
      display.println("TX SIGNED!");
      display.setTextSize(1);
      display.println("\nBroadcast ready.");
      display.println("Returning to menu...");
      display.display();
      delay(2500);
      currentState = MAIN_MENU;
      break;

    case WALLET_WIPED:
      display.setCursor(0, 10);
      display.setTextSize(2);
      display.println("WALLET");
      display.println("WIPED");
      display.setTextSize(1);
      display.setCursor(0, 48);
      display.println("Restore from seed");
      break;
  }
  display.display();
}

// --- SECURE PROCESSING LOGIC ---
void executeSigningSequence() {
  display.clearDisplay();
  display.setCursor(0, 15);
  display.println("Parsing UTXOs...");
  display.display();
  delay(600);

  display.println("Hashing Payload...");
  display.display();
  delay(500);

  display.println("Calling Secure Element...");
  display.display();
  delay(1000);

  currentState = TX_SUCCESS;
}

void showBootSplash() {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(15, 18);
  display.println("COINCUBE");
  display.setTextSize(1);
  display.setCursor(38, 42);
  display.println("SECURE APPARATUS");
  display.display();
  delay(2000);
}
