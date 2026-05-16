#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <ArduinoOTA.h>
#include "secrets.h"

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
enum WalletState { MAIN_MENU, SHOW_BALANCE, SHOW_ADDRESS, SIGN_TX, PQC_STATUS, TX_SUCCESS };
WalletState currentState = MAIN_MENU;

int menuIndex = 0;
const int TOTAL_MENU_ITEMS = 4;
const char* menuItems[] = {
  "1. View Balance",
  "2. Receive (Addr)",
  "3. Sign Transaction",
  "4. PQC Quantum Sec"
};

// --- REAL BITCOIN DATA (MOCK MINTED) ---
const char* BTC_ADDRESS = "bc1p5d7txrekgvk0llknw8vkm6680zhv93"; // Bitcoin Taproot (Bech32m)
uint64_t walletSats = 42050000; // 0.42050000 BTC

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
  while (WiFi.status() != WL_CONNECTED && timeout < 8) { // 4 seconds max
    delay(500);
    timeout++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    ArduinoOTA.setHostname("coincube-wallet");
    ArduinoOTA.setPassword("cube526");
    ArduinoOTA.begin();
    Serial.println("OTA Active");
  }

  currentState = MAIN_MENU;
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    ArduinoOTA.handle();
  }
  
  handleNavigation();
  renderCurrentState();
  delay(30); // Yield to system threads
}

// --- UNIVERSAL 2-BUTTON NAVIGATION ENGINE ---
void handleNavigation() {
  bool confirmPressed = (digitalRead(BTN_CONFIRM) == LOW);
  bool cancelPressed = (digitalRead(BTN_CANCEL) == LOW);

  if (!confirmPressed && !cancelPressed) return; // No input, exit fast

  // Small debounce delay to prevent double-clicks
  delay(180); 

  switch (currentState) {
    case MAIN_MENU:
      if (cancelPressed) {
        // Cancel cycles down through menu options
        menuIndex = (menuIndex + 1) % TOTAL_MENU_ITEMS;
      } 
      else if (confirmPressed) {
        // Confirm enters the selected submenu state
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
      // Inside submenus, hitting either button returns to main menu
      if (cancelPressed || confirmPressed) {
        currentState = MAIN_MENU;
      }
      break;

    case SIGN_TX:
      if (cancelPressed) {
        // Cancel Rejects and exits back to menu safely
        currentState = MAIN_MENU;
      } 
      else if (confirmPressed) {
        // Confirm signs the transaction
        executeSigningSequence();
      }
      break;
  }
}

// --- SCREEN RENDERERS ---
void renderCurrentState() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);

  switch (currentState) {
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
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE); // Invert text for button label
      display.print(" [BACK] ");
      break;

    case SHOW_ADDRESS:
      display.setCursor(0, 0);
      display.println("BTC RECEIVE ADDRESS");
      display.println("---------------------");
      display.setTextSize(1);
      display.setCursor(0, 20);
      // Chunking long Taproot address to fit screen elegantly
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
      display.print("Hardware: "); display.println("ATECC608 (ECC)");
      display.print("FPGA Bus: "); display.println("Ready/Isolated");
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
  // This is where Wire.write transfers the hash to your ATECC608
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