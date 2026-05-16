#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#ifdef DEV_BUILD
#include <WiFi.h>
#include <ArduinoOTA.h>
#include "secrets.h"
#endif
#if !defined(DEV_BUILD) && defined(ESP32)
#include <esp_wifi.h>
#endif
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

// --- HARDWARE CONFIG ---
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define SDA_PIN 8
#define SCL_PIN 9
#define BTN_CONFIRM 1
#define BTN_CANCEL 2

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

#ifdef DEV_BUILD
const char* ssid = SECRET_SSID;
const char* password = SECRET_PASS;
#endif

// --- WALLET STATE MACHINE ---
enum WalletState {
  BOOT_MENU,
  MNEMONIC_DISPLAY,
  MNEMONIC_VERIFY,
  MNEMONIC_RESTORE_LETTER,
  MNEMONIC_RESTORE_WORD,
  RESTORE_ERROR,
  RESTORE_COMPLETE,
  RESTORE_PASSPHRASE,
  PASSPHRASE_PROMPT,
  PASSPHRASE_ENTRY,
  BOOT_PASSPHRASE,
  PIN_SETUP,
  PIN_ENTRY,
  MAIN_MENU,
  SHOW_BALANCE,
  SHOW_ADDRESS,
  QR_DISPLAY,
  SIGN_TX,
  WAIT_PSBT,
  TX_FEE_REVIEW,
  TX_OUTPUT_REVIEW,
  PQC_STATUS,
  TX_SUCCESS,
  TX_SIGN_ERROR,
  WALLET_WIPED,
  VERIFY_ADDRESS,
  VERIFY_MATCH,
  VERIFY_MISMATCH,
  DEVICE_ID_DISPLAY,
  ACCOUNT_SELECT,
  ACCOUNT_RENAME,
  COIN_CONTROL,
  SETTINGS_MENU,
  SETTINGS_TIMEOUT,
  SETTINGS_AUTOLOCK,
  SETTINGS_CONTRAST,
  SETTINGS_CHANGE_PIN_OLD,
  SETTINGS_CHANGE_PIN_NEW,
  SETTINGS_CHANGE_PIN_CONFIRM,
  SETTINGS_PIN_MISMATCH,
  SETTINGS_ABOUT,
  SETTINGS_FACTORY_RESET_CONFIRM,
  SETTINGS_FACTORY_RESET_SURE,
  WATCHDOG_RECOVERY
};
WalletState currentState = PIN_SETUP;

int menuIndex = 0;
const int TOTAL_MENU_ITEMS = 8;
const char* menuItems[] = {
  "1. View Balance",
  "2. Receive (Addr)",
  "3. Sign Transaction",
  "4. PQC Quantum Sec",
  "5. Demo Sign (PSBT)",
  "6. Verify Address",
  "7. Account",
  "8. Settings"
};

// --- PIN STATE ---
uint8_t pinDigits[6] = {0};
uint8_t pinPosition = 0;
uint8_t pinDigitValue = 0;
uint8_t pinAttempts = 0;

// --- MNEMONIC CEREMONY STATE ---
char mnemonicWords[24][9];
uint8_t mnemonicWordIndex = 0;
uint8_t mnemonicVerifyIndices[3] = {0};
uint8_t mnemonicVerifyStep = 0;
uint8_t mnemonicVerifyScroll = 0;
bool displayOn = true;
unsigned long lastActivityMs = 0;

// --- WALLET RESTORE STATE ---
char restoreWords[24][9];
uint8_t restoreWordIdx = 0;
char restorePrefix[5];
uint8_t restorePrefixLen = 0;
char restoreLetter = 'a';
uint16_t restoreMatchStart = 0;
uint16_t restoreMatchCount = 0;
uint16_t restoreMatchPos = 0;
unsigned long restoreStartTime = 0;
char restoreError[32] = "";
bool restorePassphrase = false;

// --- PASSPHRASE ENTRY STATE ---
static const char PASSPHRASE_CHARS[] =
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "0123456789"
  "!@#$%^&*()-_=+.,;:'\"[]{}<>?/";
#define PASSPHRASE_CHAR_COUNT (sizeof(PASSPHRASE_CHARS) - 1)
char passphrase[65];
uint8_t passphraseLen;
uint16_t passphraseCharIdx;
bool passphraseDone;
char sessionPassphrase[65];
bool passphraseIsNewWallet;

// --- ADDRESS STATE ---
char currentAddressStr[MAX_ADDRESS_LEN] = "";
uint8_t addressTypeIdx = 1;
uint32_t addressIndex = 0;

// --- ACCOUNT STATE ---
uint32_t activeAccount = 0;

// --- ACCOUNT RENAME STATE ---
static const char ACCT_NAME_CHARS[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789"
  "-_.";
#define ACCT_NAME_CHAR_COUNT (sizeof(ACCT_NAME_CHARS) - 1)
char acctNameBuf[7];
uint8_t acctNamePos;
uint16_t acctNameCharIdx;
bool acctNameDone;

// --- QR STATE ---
uint8_t qrBuffer[QR_MAX_BUFFER_SIZE];
QRCode qrCode;
bool qrValid = false;

// --- VERIFY ADDRESS STATE ---
char verifyReceivedAddr[MAX_ADDRESS_LEN];
bool verifyMatchResult;
unsigned long verifyResultEnteredMs;

// --- TRANSACTION REVIEW STATE ---
psbt_t txReviewPsbt;
uint32_t txReviewOutputIdx;
uint64_t txTotalInputSats;
uint64_t txTotalOutputSats;
int64_t txFeeSats;
uint32_t txFeeRateSatPerVb;
bool txHasRBF;
bool txHighFee;
uint32_t txNonChangeOutputCount;
uint32_t txNonChangeIndices[PSBT_MAX_OUTPUTS];
char txReviewAddressBuf[MAX_ADDRESS_LEN];
bool txReviewReady;
int txSignCount = 0;
int txSignError = 0;
bool psbtFromUsb = false;

// --- COIN CONTROL STATE ---
bool txInputSelected[PSBT_MAX_INPUTS];
uint8_t coinControlScrollIdx;
uint8_t coinControlOwnedCount;

// --- SETTINGS STATE ---
uint8_t settingsMenuIdx = 0;
const int SETTINGS_ITEM_COUNT = 6;
const char* settingsItems[] = {
  "Display Timeout",
  "Auto-Lock Timeout",
  "Display Contrast",
  "Change PIN",
  "Factory Reset",
  "About"
};
uint8_t settingsSubIdx = 0;
uint8_t settingsContrastVal = 128;
// --- CHANGE PIN STATE ---
uint8_t changePinOldDigits[6] = {0};
uint8_t changePinNewDigits[6] = {0};
uint8_t changePinConfirmDigits[6] = {0};
uint8_t changePinPosition = 0;
uint8_t changePinDigitValue = 0;

// --- ANTI-PHISHING DEVICE ID ---
char antiPhishWords[4][9] = {{0}};
unsigned long deviceIdEnteredMs = 0;

const char *const TX_SEND_LABEL = "SEND";
const char *const TX_CHANGE_LABEL = "CHANGE";

// --- DEVICE UID (ESP32) ---
void pin_get_device_uid(uint8_t uid[8]) {
  uint64_t mac = ESP.getEfuseMac();
  memset(uid, 0, 8);
  for (int i = 0; i < 6; i++) {
    uid[6 - i] = (mac >> (i * 8)) & 0xFF;
  }
}

// --- TRANSACTION REVIEW DEMO PSBT ---
// 1 input (100M sats) → 2 outputs (51.2M send + 48.75M change), fee=50K sats, RBF enabled
static const uint8_t DEMO_PSBT[] = {
  0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x71, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
  0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x02, 0x00, 0x40, 0x0d, 0x03, 0x00,
  0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
  0x13, 0x14, 0xb0, 0xdd, 0xe7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
  0x14, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
  0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x01, 0x1f, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00,
  0x00, 0x16, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
  0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x19, 0x06, 0xaa, 0xbb, 0xcc,
  0xdd, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x02, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
  0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x00, 0x19, 0x02, 0xaa, 0xbb,
  0xcc, 0xdd, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
  0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x02,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
  0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x00, 0x19, 0x02, 0xaa,
  0xbb, 0xcc, 0xdd, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
  0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21,
  0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
  0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x00
};
static const size_t DEMO_PSBT_LEN = sizeof(DEMO_PSBT);

// --- TRANSACTION REVIEW HELPERS ---

void format_btc(uint64_t sats, char *buf, size_t buf_len) {
  uint64_t btc = sats / 100000000ULL;
  uint64_t frac = sats % 100000000ULL;
  snprintf(buf, buf_len, "%llu.%08llu", (unsigned long long)btc, (unsigned long long)frac);
}

void format_sats(uint64_t sats, char *buf, size_t buf_len) {
  if (sats >= 1000000) {
    snprintf(buf, buf_len, "%llu,%03llu,%03llu",
             (unsigned long long)(sats / 1000000),
             (unsigned long long)((sats / 1000) % 1000),
             (unsigned long long)(sats % 1000));
  } else if (sats >= 1000) {
    snprintf(buf, buf_len, "%llu,%03llu",
             (unsigned long long)(sats / 1000),
             (unsigned long long)(sats % 1000));
  } else {
    snprintf(buf, buf_len, "%llu", (unsigned long long)sats);
  }
}

bool is_output_change(const psbt_output_t *output) {
  if (!output->bip32_derivation.present) return false;
  if (output->bip32_derivation.path_len < 5) return false;
  return output->bip32_derivation.path[3] == 1;
}

bool tx_detect_rbf(const psbt_t *psbt) {
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    if (psbt->inputs[i].sequence < 0xFFFFFFFE) return true;
  }
  return false;
}

uint32_t tx_estimate_vsize(const psbt_t *psbt) {
  uint32_t base_size = 10 + psbt->input_count * 41 + psbt->output_count * 31;
  uint32_t witness_size = psbt->input_count * 107;
  return (base_size * 4 + witness_size + 3) / 4;
}

void build_output_address(const psbt_output_t *output, char *out, size_t out_len) {
  if (output->bip32_derivation.present && output->bip32_derivation.path_len >= 5) {
    uint32_t purpose = output->bip32_derivation.path[0];
    uint32_t account = output->bip32_derivation.path[2] & ~HD_HARDENED;
    uint32_t change = output->bip32_derivation.path[3];
    uint32_t addr_idx = output->bip32_derivation.path[4];
    address_type_t atype;
    if (purpose == 0x80000054) atype = ADDRESS_P2WPKH;
    else if (purpose == 0x8000002C) atype = ADDRESS_P2PKH;
    else if (purpose == 0x80000056) atype = ADDRESS_P2TR;
    else { atype = ADDRESS_P2WPKH; }
    address_generate_with_path(atype, account, change, addr_idx, out);
    return;
  }
  if (output->script_pubkey_len == 22 &&
      output->script_pubkey[0] == 0x00 && output->script_pubkey[1] == 0x14) {
    char bech[128];
    if (bech32_encode("bc", 0, output->script_pubkey + 2, 20, bech)) {
      strncpy(out, bech, out_len);
      return;
    }
  }
  if (output->script_pubkey_len == 34 &&
      output->script_pubkey[0] == 0x51 && output->script_pubkey[1] == 0x20) {
    char bech[128];
    if (bech32m_encode("bc", 1, output->script_pubkey + 2, 32, bech)) {
      strncpy(out, bech, out_len);
      return;
    }
  }
  snprintf(out, out_len, "hex:%.4x...", (unsigned)output->script_pubkey[2]);
}

void initTransactionReviewFromBuffer(const uint8_t *psbt_data, size_t psbt_len) {
  memset(&txReviewPsbt, 0, sizeof(txReviewPsbt));
  txReviewOutputIdx = 0;
  txTotalInputSats = 0;
  txTotalOutputSats = 0;
  txFeeSats = 0;
  txFeeRateSatPerVb = 0;
  txHasRBF = false;
  txHighFee = false;
  txNonChangeOutputCount = 0;
  memset(txNonChangeIndices, 0, sizeof(txNonChangeIndices));
  memset(txReviewAddressBuf, 0, sizeof(txReviewAddressBuf));
  txReviewReady = false;
  memset(txInputSelected, 0, sizeof(txInputSelected));
  coinControlScrollIdx = 0;
  coinControlOwnedCount = 0;

  psbt_err_t err = psbt_parse(psbt_data, psbt_len, &txReviewPsbt);
  if (err != PSBT_OK) {
    txReviewReady = false;
    return;
  }

  for (uint32_t i = 0; i < txReviewPsbt.input_count; i++) {
    if (txReviewPsbt.inputs[i].bip32_derivation.present &&
        txReviewPsbt.inputs[i].bip32_derivation.path_len > 0) {
      txInputSelected[i] = true;
      coinControlOwnedCount++;
    }
  }

  txTotalInputSats = psbt_get_total_input_value(&txReviewPsbt);
  txTotalOutputSats = psbt_get_total_output_value(&txReviewPsbt);
  txFeeSats = psbt_get_fee(&txReviewPsbt);
  if (txFeeSats < 0) txFeeSats = 0;

  uint32_t vsize = tx_estimate_vsize(&txReviewPsbt);
  if (vsize > 0) {
    txFeeRateSatPerVb = (uint32_t)((uint64_t)txFeeSats / vsize);
  }

  txHasRBF = tx_detect_rbf(&txReviewPsbt);
  txHighFee = (txFeeRateSatPerVb > 500);

  for (uint32_t i = 0; i < txReviewPsbt.output_count; i++) {
    if (!is_output_change(&txReviewPsbt.outputs[i])) {
      if (txNonChangeOutputCount < PSBT_MAX_OUTPUTS) {
        txNonChangeIndices[txNonChangeOutputCount] = i;
      }
      txNonChangeOutputCount++;
    }
  }

  txReviewReady = true;
}

void initTransactionReview() {
  initTransactionReviewFromBuffer(DEMO_PSBT, DEMO_PSBT_LEN);
}

void setup() {
  Serial.begin(115200);
  serial_init();
  Wire.begin(SDA_PIN, SCL_PIN);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) for(;;);

  pinMode(BTN_CONFIRM, INPUT_PULLUP);
  pinMode(BTN_CANCEL, INPUT_PULLUP);

  showBootSplash();

#ifdef DEV_BUILD
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
#else
  esp_wifi_stop();
  esp_wifi_deinit();
#endif

  se051_init();

  watchdog_init();

  account_init();

  settings_init();
  display.ssd1306_command(SSD1306_SETCONTRAST);
  display.ssd1306_command(settings_get_contrast());

  if (watchdog_is_signing_active()) {
    watchdog_clear_signing_active();
    currentState = WATCHDOG_RECOVERY;
    return;
  }

  if (watchdog_last_reset_was_wdt()) {
    currentState = WATCHDOG_RECOVERY;
    return;
  }

  if (pin_is_set()) {
    currentState = PIN_ENTRY;
    pinAttempts = pin_get_attempts();
    pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
    pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
    pinPosition = 0;
    pinDigitValue = 0;
  } else if (!wallet_is_initialized()) {
    currentState = BOOT_MENU;
  } else {
    currentState = PIN_SETUP;
    pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
    pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
    pinPosition = 0;
    pinDigitValue = 0;
  }
}

void loop() {
  watchdog_feed();

#ifdef DEV_BUILD
  if (WiFi.status() == WL_CONNECTED) {
    ArduinoOTA.handle();
  }
#endif

  if (currentState == WAIT_PSBT) {
    serial_msg_t msg = serial_poll();
    if (msg.cmd == SERIAL_CMD_PSBT && msg.data_len > 0) {
      psbtFromUsb = true;
      initTransactionReviewFromBuffer(msg.data, msg.data_len);
      if (txReviewReady) {
        if (coinControlOwnedCount > 1) {
          currentState = COIN_CONTROL;
        } else {
          currentState = TX_FEE_REVIEW;
        }
      } else {
        serial_send_error(-1);
        currentState = MAIN_MENU;
      }
    }
  }

  if (currentState == VERIFY_ADDRESS) {
    serial_msg_t msg = serial_poll();
    if (msg.cmd == SERIAL_CMD_VERIFY && msg.data_len > 0 && msg.data_len < MAX_ADDRESS_LEN) {
      memcpy(verifyReceivedAddr, msg.data, msg.data_len + 1);
      updateAddressDisplay();
      verifyMatchResult = (strcmp(currentAddressStr, verifyReceivedAddr) == 0);
      verifyResultEnteredMs = millis();
      currentState = verifyMatchResult ? VERIFY_MATCH : VERIFY_MISMATCH;
    }
  }

  if ((currentState == MNEMONIC_DISPLAY || currentState == MNEMONIC_VERIFY) &&
      (millis() - lastActivityMs > 30000)) {
    displayOn = false;
  }

  if (currentState == DEVICE_ID_DISPLAY &&
      (millis() - deviceIdEnteredMs > 3000)) {
    currentState = MAIN_MENU;
  }

  if (currentState == WALLET_WIPED &&
      (millis() - lastActivityMs > 4000)) {
    ESP.restart();
  }

  if ((currentState == MNEMONIC_DISPLAY || currentState == MNEMONIC_VERIFY) &&
      displayOn && (millis() - lastActivityMs > 30000)) {
    displayOn = false;
  }

  if ((currentState == MNEMONIC_RESTORE_LETTER || currentState == MNEMONIC_RESTORE_WORD) &&
      (millis() - restoreStartTime > 300000)) {
    memset(restoreWords, 0, sizeof(restoreWords));
    restoreWordIdx = 0;
    restorePrefixLen = 0;
    restorePrefix[0] = '\0';
    restoreLetter = 'a';
    restoreMatchPos = 0;
    currentState = BOOT_MENU;
  }

  if (currentState == MAIN_MENU ||
      currentState == SHOW_BALANCE ||
      currentState == SHOW_ADDRESS ||
      currentState == QR_DISPLAY ||
      currentState == PQC_STATUS ||
      currentState == MNEMONIC_DISPLAY ||
      currentState == MNEMONIC_VERIFY ||
      currentState == SETTINGS_MENU ||
      currentState == SETTINGS_TIMEOUT ||
      currentState == SETTINGS_AUTOLOCK ||
      currentState == SETTINGS_CONTRAST ||
      currentState == SETTINGS_ABOUT ||
      currentState == SETTINGS_FACTORY_RESET_CONFIRM ||
      currentState == SETTINGS_FACTORY_RESET_SURE) {
    uint32_t auto_lock_ms = settings_auto_lock_ms(settings_get_auto_lock());
    if (auto_lock_ms > 0 &&
        millis() - lastActivityMs > auto_lock_ms) {
      currentState = PIN_ENTRY;
      pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
      pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
      pinPosition = 0;
      pinDigitValue = 0;
      pinAttempts = pin_get_attempts();
    }

    uint32_t disp_ms = settings_disp_timeout_ms(settings_get_display_timeout());
    if (disp_ms > 0 && displayOn &&
        millis() - lastActivityMs > disp_ms) {
      displayOn = false;
    }
  }

  if (currentState == SETTINGS_CONTRAST &&
      millis() - lastActivityMs > 5000) {
    settings_set_contrast(settingsContrastVal);
    currentState = SETTINGS_MENU;
  }

  handleNavigation();
  renderCurrentState();
  delay(30);
}

// Enter DEVICE_ID_DISPLAY after PIN entry on every boot.
// On first setup (no anti-phish stored), generates new 4-word identity
// and exports PAIRING:<words>\n over USB. The companion app MUST store
// these words and visually display them on every connection so the user
// can verify the device OLED matches. See wallet_storage.cpp for the
// full anti-phishing threat model documentation.
void enterDeviceIdDisplay() {
  if (wallet_has_anti_phish()) {
    wallet_get_anti_phish(antiPhishWords);
  } else {
    wallet_generate_anti_phish();
    wallet_get_anti_phish(antiPhishWords);
    char pairingBuf[48];
    snprintf(pairingBuf, sizeof(pairingBuf), "%s %s %s %s",
             antiPhishWords[0], antiPhishWords[1],
             antiPhishWords[2], antiPhishWords[3]);
    serial_send_pairing(pairingBuf);
  }
  deviceIdEnteredMs = millis();
  currentState = DEVICE_ID_DISPLAY;
}

// --- UNIVERSAL 2-BUTTON NAVIGATION ENGINE ---
void handleNavigation() {
  bool confirmPressed = (digitalRead(BTN_CONFIRM) == LOW);
  bool cancelPressed = (digitalRead(BTN_CANCEL) == LOW);

  if (!confirmPressed && !cancelPressed) return;

  if (!displayOn) {
    displayOn = true;
    lastActivityMs = millis();
    return;
  }

  delay(180);

  switch (currentState) {
    case BOOT_MENU:
      if (cancelPressed) {
        menuIndex = (menuIndex + 1) % 2;
      } else if (confirmPressed) {
        if (menuIndex == 0) {
          startMnemonicCeremony();
        } else {
          startRestoreProcess();
        }
      }
      break;

    case MNEMONIC_DISPLAY:
      lastActivityMs = millis();
      if (confirmPressed && mnemonicWordIndex == 23) {
        startVerification();
      } else if (cancelPressed) {
        mnemonicWordIndex = (mnemonicWordIndex + 1) % 24;
      }
      break;

    case MNEMONIC_VERIFY:
      if (confirmPressed || cancelPressed) {
        lastActivityMs = millis();
        displayOn = true;
      }
      if (cancelPressed) {
        mnemonicVerifyScroll = (mnemonicVerifyScroll + 1) % 2048;
      } else if (confirmPressed) {
        uint8_t pos = mnemonicVerifyIndices[mnemonicVerifyStep];
        if (strcmp(bip39_wordlist[mnemonicVerifyScroll], mnemonicWords[pos]) == 0) {
          mnemonicVerifyStep++;
          mnemonicVerifyScroll = 0;
          if (mnemonicVerifyStep >= 3) {
            passphraseIsNewWallet = true;
            menuIndex = 0;
            currentState = PASSPHRASE_PROMPT;
          }
        } else {
          mnemonicWordIndex = 0;
          mnemonicVerifyStep = 0;
          mnemonicVerifyScroll = 0;
          currentState = MNEMONIC_DISPLAY;
        }
      }
      break;

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
            enterDeviceIdDisplay();
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
          if (pinAttempts < PIN_MAX_ATTEMPTS) {
            pin_increment_attempts();
            pinAttempts = pin_get_attempts();
          }
          if (pin_verify(pinDigits)) {
            pin_reset_attempts();
            pinAttempts = 0;
            if (wallet_has_passphrase()) {
              initSessionPassphraseEntry();
              currentState = BOOT_PASSPHRASE;
            } else {
              enterDeviceIdDisplay();
            }
          } else {
            if (pinAttempts >= PIN_MAX_ATTEMPTS) {
              wallet_factory_reset();
              currentState = WALLET_WIPED;
              lastActivityMs = millis();
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

    case MNEMONIC_RESTORE_LETTER:
      restoreStartTime = millis();
      if (confirmPressed) {
        restoreLetter = (restoreLetter == 'z') ? 'a' : restoreLetter + 1;
        updateRestoreMatchesPreview();
      } else if (cancelPressed) {
        if (restorePrefixLen >= 4) {
          if (restoreMatchCount > 0) {
            restoreMatchPos = 0;
            currentState = MNEMONIC_RESTORE_WORD;
          }
          break;
        }
        restorePrefix[restorePrefixLen] = restoreLetter;
        restorePrefixLen++;
        restorePrefix[restorePrefixLen] = '\0';
        updateRestoreMatches();
        if (restorePrefixLen >= 3 && restoreMatchCount > 0 && restoreMatchCount <= 30) {
          restoreMatchPos = 0;
          currentState = MNEMONIC_RESTORE_WORD;
        } else {
          restoreLetter = 'a';
        }
      }
      break;

    case MNEMONIC_RESTORE_WORD:
      restoreStartTime = millis();
      if (restoreMatchCount == 0) {
        restorePrefixLen = 0;
        restorePrefix[0] = '\0';
        restoreLetter = 'a';
        restoreMatchPos = 0;
        updateRestoreMatches();
        currentState = MNEMONIC_RESTORE_LETTER;
        break;
      }
      if (cancelPressed) {
        restoreMatchPos = (restoreMatchPos + 1) % restoreMatchCount;
      } else if (confirmPressed) {
        uint16_t selectedIdx = restoreMatchStart + restoreMatchPos;
        strncpy(restoreWords[restoreWordIdx], bip39_wordlist[selectedIdx], 9);
        restoreWords[restoreWordIdx][8] = '\0';
        restoreWordIdx++;
        if (restoreWordIdx >= 24) {
          if (bip39_validate(restoreWords)) {
            currentState = RESTORE_PASSPHRASE;
            menuIndex = 0;
          } else {
            strncpy(restoreError, "Bad checksum - retry", 32);
            restoreStartTime = millis();
            currentState = RESTORE_ERROR;
          }
        } else {
          restorePrefixLen = 0;
          restorePrefix[0] = '\0';
          restoreLetter = 'a';
          restoreMatchPos = 0;
          updateRestoreMatches();
          currentState = MNEMONIC_RESTORE_LETTER;
        }
      }
      break;

    case RESTORE_PASSPHRASE:
      if (cancelPressed) {
        menuIndex = (menuIndex + 1) % 2;
      } else if (confirmPressed) {
        restorePassphrase = (menuIndex == 1);
        if (restorePassphrase) {
          passphraseIsNewWallet = false;
          initPassphraseEntry();
          currentState = PASSPHRASE_ENTRY;
        } else {
          wallet_generate_seed(restoreWords, NULL);
          wallet_set_passphrase_flag(false);
          secureZeroRestore();
          currentState = PIN_SETUP;
          pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
          pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
          pinPosition = 0;
          pinDigitValue = 0;
        }
      }
      break;

    case RESTORE_ERROR:
      if (confirmPressed || cancelPressed) {
        restoreWordIdx = 0;
        restorePrefixLen = 0;
        restorePrefix[0] = '\0';
        restoreLetter = 'a';
        restoreMatchPos = 0;
        updateRestoreMatches();
        currentState = MNEMONIC_RESTORE_LETTER;
      }
      break;

    case RESTORE_COMPLETE:
      break;

    case PASSPHRASE_PROMPT:
      if (cancelPressed) {
        menuIndex = (menuIndex + 1) % 2;
      } else if (confirmPressed) {
        if (menuIndex == 1) {
          initPassphraseEntry();
          currentState = PASSPHRASE_ENTRY;
        } else {
          if (passphraseIsNewWallet) {
            wallet_generate_seed(mnemonicWords, NULL);
            wallet_set_passphrase_flag(false);
            secureZeroMnemonic();
          } else {
            wallet_generate_seed(restoreWords, NULL);
            wallet_set_passphrase_flag(false);
            secureZeroRestore();
          }
          currentState = PIN_SETUP;
          pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
          pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
          pinPosition = 0;
          pinDigitValue = 0;
        }
      }
      break;

    case PASSPHRASE_ENTRY:
      if (cancelPressed) {
        passphraseCharIdx = (passphraseCharIdx + 1) % (PASSPHRASE_CHAR_COUNT + 1);
      } else if (confirmPressed) {
        if (passphraseCharIdx >= PASSPHRASE_CHAR_COUNT) {
          passphraseDone = true;
          if (passphraseIsNewWallet) {
            wallet_generate_seed(mnemonicWords, passphrase);
            wallet_set_passphrase_flag(passphraseLen > 0);
            secureZeroMnemonic();
            secureZeroPassphrase();
          } else {
            wallet_generate_seed(restoreWords, passphrase);
            wallet_set_passphrase_flag(passphraseLen > 0);
            secureZeroRestore();
            secureZeroPassphrase();
          }
          currentState = PIN_SETUP;
          pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
          pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
          pinPosition = 0;
          pinDigitValue = 0;
        } else if (passphraseLen < 64) {
          passphrase[passphraseLen] = PASSPHRASE_CHARS[passphraseCharIdx];
          passphraseLen++;
          passphrase[passphraseLen] = '\0';
        }
      }
      break;

    case BOOT_PASSPHRASE:
      if (cancelPressed) {
        passphraseCharIdx = (passphraseCharIdx + 1) % (PASSPHRASE_CHAR_COUNT + 1);
      } else if (confirmPressed) {
        if (passphraseCharIdx >= PASSPHRASE_CHAR_COUNT) {
          passphraseDone = true;
          strncpy(sessionPassphrase, passphrase, sizeof(sessionPassphrase) - 1);
          sessionPassphrase[sizeof(sessionPassphrase) - 1] = '\0';
          secureZeroPassphrase();
          enterDeviceIdDisplay();
        } else if (passphraseLen < 64) {
          passphrase[passphraseLen] = PASSPHRASE_CHARS[passphraseCharIdx];
          passphraseLen++;
          passphrase[passphraseLen] = '\0';
        }
      }
      break;

    case MAIN_MENU:
      if (cancelPressed) {
        menuIndex = (menuIndex + 1) % TOTAL_MENU_ITEMS;
      } else if (confirmPressed) {
        if (menuIndex == 0) currentState = SHOW_BALANCE;
        if (menuIndex == 1) {
          addressTypeIdx = 1;
          uint32_t acct = account_get_active();
          account_get_address_index(acct, &addressIndex);
          updateAddressDisplay();
          currentState = SHOW_ADDRESS;
        }
        if (menuIndex == 2) currentState = SIGN_TX;
        if (menuIndex == 3) currentState = PQC_STATUS;
        if (menuIndex == 4) {
          psbtFromUsb = false;
          initTransactionReview();
          if (txReviewReady) {
            if (coinControlOwnedCount > 1) {
              currentState = COIN_CONTROL;
            } else {
              currentState = TX_FEE_REVIEW;
            }
          } else {
            currentState = MAIN_MENU;
          }
        }
        if (menuIndex == 5) {
          updateAddressDisplay();
          currentState = VERIFY_ADDRESS;
        }
        if (menuIndex == 6) {
          activeAccount = account_get_active();
          currentState = ACCOUNT_SELECT;
        }
        if (menuIndex == 7) {
          settingsMenuIdx = 0;
          currentState = SETTINGS_MENU;
        }
      }
      break;

    case SHOW_ADDRESS:
      if (cancelPressed) {
        addressTypeIdx = (addressTypeIdx + 1) % 3;
        updateAddressDisplay();
      } else if (confirmPressed) {
        qrValid = (qr_init(currentAddressStr, &qrCode, qrBuffer) == 0);
        currentState = QR_DISPLAY;
      }
      break;

    case QR_DISPLAY:
      if (cancelPressed) {
        currentState = SHOW_ADDRESS;
      } else if (confirmPressed) {
        uint32_t acct = account_get_active();
        account_increment_address_index(acct);
        currentState = MAIN_MENU;
      }
      break;

    case SHOW_BALANCE:
    case PQC_STATUS:
    case TX_SUCCESS:
    case TX_SIGN_ERROR:
      if (cancelPressed || confirmPressed) {
        currentState = MAIN_MENU;
      }
      break;

    case SIGN_TX:
      if (cancelPressed) {
        currentState = MAIN_MENU;
      } else if (confirmPressed) {
        psbtFromUsb = false;
        serial_send_ready();
        currentState = WAIT_PSBT;
      }
      break;

    case WAIT_PSBT:
      if (cancelPressed) {
        if (psbtFromUsb) {
          serial_send_rejected();
        }
        psbtFromUsb = false;
        currentState = MAIN_MENU;
      }
      break;

    case TX_FEE_REVIEW:
      if (cancelPressed) {
        if (psbtFromUsb) {
          serial_send_rejected();
        }
        psbtFromUsb = false;
        currentState = MAIN_MENU;
      } else if (confirmPressed) {
        if (txNonChangeOutputCount > 0) {
          txReviewOutputIdx = 0;
          build_output_address(&txReviewPsbt.outputs[txNonChangeIndices[0]],
                               txReviewAddressBuf, sizeof(txReviewAddressBuf));
          currentState = TX_OUTPUT_REVIEW;
        } else {
          initTransactionReview();
        }
      }
      break;

    case TX_OUTPUT_REVIEW:
      if (cancelPressed) {
        txReviewOutputIdx++;
        if (txReviewOutputIdx >= txNonChangeOutputCount) {
          if (psbtFromUsb) {
            serial_send_rejected();
          }
          psbtFromUsb = false;
          currentState = MAIN_MENU;
        } else {
          build_output_address(&txReviewPsbt.outputs[txNonChangeIndices[txReviewOutputIdx]],
                               txReviewAddressBuf, sizeof(txReviewAddressBuf));
        }
      } else if (confirmPressed) {
        executeSigningSequence();
      }
      break;

    case WALLET_WIPED:
      if (confirmPressed || cancelPressed) {
        ESP.restart();
      }
      break;

    case VERIFY_ADDRESS:
      if (confirmPressed) {
        currentState = MAIN_MENU;
      } else if (cancelPressed) {
        addressTypeIdx = (addressTypeIdx + 1) % 3;
        updateAddressDisplay();
      }
      break;

    case VERIFY_MATCH:
      if (confirmPressed || cancelPressed) {
        serial_send_verified();
        currentState = MAIN_MENU;
      }
      break;

    case VERIFY_MISMATCH:
      if (confirmPressed || cancelPressed) {
        serial_send_mismatch();
        currentState = MAIN_MENU;
      }
      break;

    case DEVICE_ID_DISPLAY:
      if (confirmPressed || cancelPressed) {
        currentState = MAIN_MENU;
      }
      break;

    case ACCOUNT_SELECT:
      if (cancelPressed) {
        activeAccount = (activeAccount + 1) % (MAX_ACCOUNTS + 1);
      } else if (confirmPressed) {
        if (activeAccount == MAX_ACCOUNTS) {
          acctNamePos = 0;
          acctNameCharIdx = 0;
          acctNameDone = false;
          memset(acctNameBuf, 0, sizeof(acctNameBuf));
          uint32_t cur = account_get_active();
          char existing[7];
          if (account_get_name(cur, existing, sizeof(existing))) {
            strncpy(acctNameBuf, existing, sizeof(acctNameBuf) - 1);
            acctNamePos = (uint8_t)strlen(acctNameBuf);
          }
          currentState = ACCOUNT_RENAME;
        } else {
          account_set_active(activeAccount);
          currentState = MAIN_MENU;
        }
      }
      break;

    case ACCOUNT_RENAME:
      if (cancelPressed) {
        acctNameCharIdx = (acctNameCharIdx + 1) % (ACCT_NAME_CHAR_COUNT + 1);
      } else if (confirmPressed) {
        if (acctNameCharIdx >= ACCT_NAME_CHAR_COUNT) {
          acctNameDone = true;
          if (acctNamePos > 0) {
            acctNameBuf[acctNamePos] = '\0';
          }
          uint32_t cur = account_get_active();
          account_set_name(cur, acctNameBuf);
          activeAccount = cur;
          currentState = ACCOUNT_SELECT;
        } else if (acctNamePos < 6) {
          acctNameBuf[acctNamePos] = ACCT_NAME_CHARS[acctNameCharIdx];
          acctNamePos++;
          acctNameBuf[acctNamePos] = '\0';
        }
      }
      break;

    case SETTINGS_MENU:
      lastActivityMs = millis();
      displayOn = true;
      if (cancelPressed) {
        settingsMenuIdx = (settingsMenuIdx + 1) % SETTINGS_ITEM_COUNT;
      } else if (confirmPressed) {
        if (settingsMenuIdx == 0) {
          settingsSubIdx = settings_get_display_timeout();
          currentState = SETTINGS_TIMEOUT;
        } else if (settingsMenuIdx == 1) {
          settingsSubIdx = settings_get_auto_lock();
          currentState = SETTINGS_AUTOLOCK;
        } else if (settingsMenuIdx == 2) {
          settingsContrastVal = settings_get_contrast();
          currentState = SETTINGS_CONTRAST;
        } else if (settingsMenuIdx == 3) {
          changePinPosition = 0;
          changePinDigitValue = 0;
          memset(changePinOldDigits, 0, sizeof(changePinOldDigits));
          memset(changePinNewDigits, 0, sizeof(changePinNewDigits));
          memset(changePinConfirmDigits, 0, sizeof(changePinConfirmDigits));
          currentState = SETTINGS_CHANGE_PIN_OLD;
        } else if (settingsMenuIdx == 4) {
          currentState = SETTINGS_FACTORY_RESET_CONFIRM;
        } else if (settingsMenuIdx == 5) {
          currentState = SETTINGS_ABOUT;
        }
      }
      break;

    case SETTINGS_TIMEOUT:
      lastActivityMs = millis();
      if (cancelPressed) {
        settingsSubIdx = (settingsSubIdx + 1) % SETTINGS_DISP_TIMEOUT_COUNT;
      } else if (confirmPressed) {
        settings_set_display_timeout(settingsSubIdx);
        currentState = SETTINGS_MENU;
      }
      break;

    case SETTINGS_AUTOLOCK:
      lastActivityMs = millis();
      if (cancelPressed) {
        settingsSubIdx = (settingsSubIdx + 1) % SETTINGS_AUTOLOCK_COUNT;
      } else if (confirmPressed) {
        settings_set_auto_lock(settingsSubIdx);
        currentState = SETTINGS_MENU;
      }
      break;

    case SETTINGS_CONTRAST:
      lastActivityMs = millis();
      if (cancelPressed) {
        if (settingsContrastVal >= SETTINGS_CONTRAST_STEP) {
          settingsContrastVal -= SETTINGS_CONTRAST_STEP;
        } else {
          settingsContrastVal = SETTINGS_CONTRAST_MAX;
        }
        display.ssd1306_command(SSD1306_SETCONTRAST);
        display.ssd1306_command(settingsContrastVal);
      } else if (confirmPressed) {
        if (settingsContrastVal + SETTINGS_CONTRAST_STEP <= SETTINGS_CONTRAST_MAX) {
          settingsContrastVal += SETTINGS_CONTRAST_STEP;
        } else {
          settingsContrastVal = SETTINGS_CONTRAST_MIN;
        }
        display.ssd1306_command(SSD1306_SETCONTRAST);
        display.ssd1306_command(settingsContrastVal);
      }
      break;

    case SETTINGS_CHANGE_PIN_OLD:
      lastActivityMs = millis();
      if (confirmPressed) {
        changePinDigitValue = (changePinDigitValue + 1) % 10;
      } else if (cancelPressed) {
        changePinOldDigits[changePinPosition] = changePinDigitValue;
        changePinPosition++;
        changePinDigitValue = 0;
        if (changePinPosition >= 6) {
          if (pin_verify(changePinOldDigits)) {
            changePinPosition = 0;
            changePinDigitValue = 0;
            currentState = SETTINGS_CHANGE_PIN_NEW;
          } else {
            currentState = SETTINGS_MENU;
          }
        }
      }
      break;

    case SETTINGS_CHANGE_PIN_NEW:
      lastActivityMs = millis();
      if (confirmPressed) {
        changePinDigitValue = (changePinDigitValue + 1) % 10;
      } else if (cancelPressed) {
        changePinNewDigits[changePinPosition] = changePinDigitValue;
        changePinPosition++;
        changePinDigitValue = 0;
        if (changePinPosition >= 6) {
          changePinPosition = 0;
          changePinDigitValue = 0;
          currentState = SETTINGS_CHANGE_PIN_CONFIRM;
        }
      }
      break;

    case SETTINGS_CHANGE_PIN_CONFIRM:
      lastActivityMs = millis();
      if (confirmPressed) {
        changePinDigitValue = (changePinDigitValue + 1) % 10;
      } else if (cancelPressed) {
        changePinConfirmDigits[changePinPosition] = changePinDigitValue;
        changePinPosition++;
        changePinDigitValue = 0;
        if (changePinPosition >= 6) {
          if (memcmp(changePinNewDigits, changePinConfirmDigits, 6) == 0) {
            pin_change(changePinOldDigits, changePinNewDigits);
            memset(changePinOldDigits, 0, sizeof(changePinOldDigits));
            memset(changePinNewDigits, 0, sizeof(changePinNewDigits));
            memset(changePinConfirmDigits, 0, sizeof(changePinConfirmDigits));
            currentState = SETTINGS_MENU;
          } else {
            currentState = SETTINGS_PIN_MISMATCH;
          }
        }
      }
      break;

    case SETTINGS_PIN_MISMATCH:
      if (confirmPressed || cancelPressed) {
        currentState = SETTINGS_MENU;
      }
      break;

    case SETTINGS_ABOUT:
      lastActivityMs = millis();
      if (confirmPressed || cancelPressed) {
        currentState = SETTINGS_MENU;
      }
      break;

    case SETTINGS_FACTORY_RESET_CONFIRM:
      lastActivityMs = millis();
      if (confirmPressed) {
        currentState = SETTINGS_FACTORY_RESET_SURE;
      } else if (cancelPressed) {
        currentState = SETTINGS_MENU;
      }
      break;

    case SETTINGS_FACTORY_RESET_SURE:
      lastActivityMs = millis();
      if (confirmPressed) {
        display.clearDisplay();
        display.setCursor(0, 20);
        display.setTextSize(2);
        display.println("Wiping...");
        display.display();
        wallet_factory_reset();
        settings_nvs_erase();
        account_nvs_erase();
        currentState = WALLET_WIPED;
        lastActivityMs = millis();
      } else if (cancelPressed) {
        currentState = SETTINGS_MENU;
      }
      break;

    case WATCHDOG_RECOVERY:
      if (confirmPressed || cancelPressed) {
        currentState = PIN_ENTRY;
        pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
        pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
        pinPosition = 0;
        pinDigitValue = 0;
        pinAttempts = pin_get_attempts();
      }
      break;

    case COIN_CONTROL: {
      uint8_t totalItems = coinControlOwnedCount + 1;
      if (cancelPressed) {
        coinControlScrollIdx = (coinControlScrollIdx + 1) % totalItems;
      } else if (confirmPressed) {
        if (coinControlScrollIdx < coinControlOwnedCount) {
          uint8_t inputIdx = 0;
          for (uint32_t i = 0; i < txReviewPsbt.input_count; i++) {
            if (txReviewPsbt.inputs[i].bip32_derivation.present &&
                txReviewPsbt.inputs[i].bip32_derivation.path_len > 0) {
              if (inputIdx == coinControlScrollIdx) {
                txInputSelected[i] = !txInputSelected[i];
                break;
              }
              inputIdx++;
            }
          }
        } else {
          bool anySelected = false;
          for (uint32_t i = 0; i < txReviewPsbt.input_count; i++) {
            if (txInputSelected[i]) { anySelected = true; break; }
          }
          if (anySelected) {
            currentState = TX_FEE_REVIEW;
          }
        }
      }
      break;
    }
  }
}

// --- SCREEN RENDERERS ---
void renderCurrentState() {
  if (!displayOn) {
    display.clearDisplay();
    display.display();
    return;
  }

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);

  switch (currentState) {
    case BOOT_MENU:
      display.setCursor(0, 0);
      display.println("COINCUBE WALLET");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.setTextSize(2);
      display.println("SETUP");
      display.setTextSize(1);
      display.setCursor(0, 38);
      if (menuIndex == 0) {
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print(" New Wallet ");
      } else {
        display.print("  New Wallet");
      }
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(0, 48);
      if (menuIndex == 1) {
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print(" Restore     ");
      } else {
        display.print("  Restore");
      }
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=select");
      break;

    case MNEMONIC_DISPLAY:
      display.setCursor(0, 0);
      display.println("YOUR SEED WORDS");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.print("Word ");
      display.print(mnemonicWordIndex + 1);
      display.print(" of 24");
      display.setCursor(0, 30);
      display.setTextSize(2);
      display.println(mnemonicWords[mnemonicWordIndex]);
      display.setTextSize(1);
      if (mnemonicWordIndex == 23) {
        display.setCursor(0, 56);
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print(" [VERIFY] ");
      } else {
        display.setCursor(0, 56);
        display.print("CANCEL=next CONFIRM on last=verify");
      }
      break;

    case MNEMONIC_VERIFY:
      display.setCursor(0, 0);
      display.println("VERIFY SEED");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.print("Step ");
      display.print(mnemonicVerifyStep + 1);
      display.print(" of 3");
      display.setCursor(0, 30);
      display.print("Word #");
      display.print(mnemonicVerifyIndices[mnemonicVerifyStep] + 1);
      display.print("?");
      display.setCursor(0, 42);
      display.setTextSize(2);
      display.println(bip39_wordlist[mnemonicVerifyScroll]);
      display.setTextSize(1);
      display.setCursor(0, 56);
      display.print("CANCEL=scroll CONFIRM=select");
      break;

    case MNEMONIC_RESTORE_LETTER:
      display.setCursor(0, 0);
      display.println("RESTORE WALLET");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.print("Word ");
      display.print(restoreWordIdx + 1);
      display.print(" of 24");
      display.setCursor(0, 28);
      display.print("Prefix: ");
      for (uint8_t i = 0; i < restorePrefixLen; i++) {
        display.print(restorePrefix[i]);
      }
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(restoreLetter);
      display.setTextColor(SSD1306_WHITE);
      for (uint8_t i = restorePrefixLen + 1; i < 4; i++) {
        display.print('_');
      }
      display.setCursor(0, 38);
      display.print("Matches: ");
      display.print(restoreMatchCount);
      display.print(" words");
      if (restoreMatchCount > 0 && restoreMatchCount <= 30) {
        display.setCursor(0, 50);
        display.print(bip39_wordlist[restoreMatchStart]);
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=cycle CANCEL=lock");
      break;

    case MNEMONIC_RESTORE_WORD:
      display.setCursor(0, 0);
      display.print("Word ");
      display.print(restoreWordIdx + 1);
      display.print(" of 24  [");
      display.print(restoreMatchCount);
      display.println("]");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.setTextSize(2);
      display.println(bip39_wordlist[restoreMatchStart + restoreMatchPos]);
      display.setTextSize(1);
      display.setCursor(0, 40);
      if (restoreMatchCount > 1) {
        if (restoreMatchPos > 0) {
          display.print("^ ");
          display.println(bip39_wordlist[restoreMatchStart + restoreMatchPos - 1]);
        } else {
          display.println("  (first match)");
        }
      }
      display.setCursor(0, 50);
      if (restoreMatchPos + 1 < restoreMatchCount) {
        display.print("v ");
        display.println(bip39_wordlist[restoreMatchStart + restoreMatchPos + 1]);
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=select CANCEL=scroll");
      break;

    case RESTORE_ERROR:
      display.setCursor(0, 0);
      display.println("RESTORE ERROR");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.setTextSize(1);
      display.println(restoreError);
      display.setCursor(0, 40);
      display.println("Restarting...");
      display.setCursor(0, 56);
      display.print("Any button to retry");
      break;

    case RESTORE_PASSPHRASE:
      display.setCursor(0, 0);
      display.println("MNEMONIC ACCEPTED");
      display.println("---------------------");
      display.setCursor(0, 20);
      display.println("24 words accepted.");
      display.setCursor(0, 32);
      display.println("Passphrase (25th word)?");
      display.setCursor(0, 44);
      display.print(menuIndex == 0 ? "> NO (skip)" : "  NO (skip)");
      display.setCursor(0, 54);
      display.print(menuIndex == 1 ? "> YES" : "  YES");
      break;

    case PASSPHRASE_PROMPT:
      display.setCursor(0, 0);
      display.println("SEED CONFIRMED");
      display.println("---------------------");
      display.setCursor(0, 20);
      display.println("Add Passphrase?");
      display.setCursor(0, 32);
      display.println("(BIP39 25th word)");
      display.setCursor(0, 44);
      display.print(menuIndex == 0 ? "> NO (skip)" : "  NO (skip)");
      display.setCursor(0, 54);
      display.print(menuIndex == 1 ? "> YES" : "  YES");
      break;

    case PASSPHRASE_ENTRY:
    case BOOT_PASSPHRASE: {
      const char *title = (currentState == BOOT_PASSPHRASE) ? "ENTER PASSPHRASE" : "SET PASSPHRASE";
      display.setCursor(0, 0);
      display.println(title);
      display.println("---------------------");
      display.setCursor(0, 18);
      display.print("Len: ");
      display.print(passphraseLen);
      display.print("/64  Chars");
      display.setCursor(0, 28);
      display.print("...");
      uint8_t previewStart = (passphraseLen > 3) ? passphraseLen - 3 : 0;
      for (uint8_t i = previewStart; i < passphraseLen; i++) {
        display.print('*');
      }
      display.setCursor(0, 40);
      bool atDone = (passphraseCharIdx >= PASSPHRASE_CHAR_COUNT);
      if (atDone) {
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print("> [DONE]");
      } else {
        display.print("> ");
        if (PASSPHRASE_CHARS[passphraseCharIdx] == ' ') {
          display.print("[SPACE]");
        } else {
          display.print(PASSPHRASE_CHARS[passphraseCharIdx]);
        }
      }
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=sel");
      break;
    }

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
      if (pinAttempts >= 3 && pinAttempts < PIN_MAX_ATTEMPTS) {
        display.setCursor(0, 40);
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print("WARNING: ");
        display.print(pin_attempts_remaining());
        display.print(" attempts remaining");
        display.setTextColor(SSD1306_WHITE);
      } else if (pinAttempts > 0) {
        display.setCursor(0, 40);
        display.print("Attempt ");
        display.print(pinAttempts);
        display.print(" of ");
        display.print(PIN_MAX_ATTEMPTS);
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=change CANCEL=next");
      break;

    case MAIN_MENU:
      display.setCursor(0, 0);
      {
        char name_buf[ACCOUNT_NAME_LEN];
        uint32_t acct = account_get_active();
        if (account_get_name(acct, name_buf, sizeof(name_buf))) {
          display.print("COINCUBE [");
          display.print(name_buf);
          display.println("]");
        } else {
          display.print("COINCUBE [Acct ");
          display.print(acct);
          display.println("]");
        }
      }
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
      {
        uint32_t acct = account_get_active();
        char name_buf[ACCOUNT_NAME_LEN];
        if (account_get_name(acct, name_buf, sizeof(name_buf))) {
          display.print("BTC RECEIVE [");
          display.print(name_buf);
          display.println("]");
        } else {
          display.print("BTC RECEIVE [Acct ");
          display.print(acct);
          display.println("]");
        }
      }
      display.println("---------------------");
      display.setTextSize(1);
      display.setCursor(0, 18);
      display.println(currentAddressStr);
      display.setCursor(0, 38);
      display.print("Type: ");
      display.println(address_type_name((address_type_t)addressTypeIdx));
      display.setCursor(0, 48);
      display.print("Addr #");
      display.print(addressIndex);
      display.setCursor(0, 56);
      display.print("CANCEL=cycle type  CONFIRM=QR");
      break;

    case QR_DISPLAY:
      if (qrValid) {
        uint8_t size = qrCode.size;
        uint8_t scale = 1;
        if (size <= 21) scale = 3;
        else if (size <= 25) scale = 2;
        else scale = 1;
        int offsetX = (128 - size * scale) / 2;
        int offsetY = (64 - size * scale) / 2;
        for (uint8_t y = 0; y < size; y++) {
          for (uint8_t x = 0; x < size; x++) {
            if (qrcode_getModule(&qrCode, x, y)) {
              display.fillRect(offsetX + x * scale, offsetY + y * scale, scale, scale, SSD1306_WHITE);
            }
          }
        }
      } else {
        display.setCursor(0, 20);
        display.println("Address too long");
        display.setCursor(0, 32);
        display.println("for QR - use");
        display.setCursor(0, 44);
        display.println("text view");
      }
      display.setCursor(0, 56);
      display.print("CANCEL=text  CONFIRM=menu");
      break;

    case SIGN_TX:
      display.setCursor(0, 0);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.println("  CONFIRM TRANSACTION  ");
      display.setTextColor(SSD1306_WHITE);
      display.println("---------------------");
      display.println("Ready to sign");
      display.println("a PSBT transaction");
      display.setCursor(0, 36);
      display.println("Review details");
      display.println("before signing.");
      display.setCursor(0, 56);
      display.print("[CANCEL=no]  [CONFIRM=yes]");
      break;

    case WAIT_PSBT:
      display.setCursor(0, 0);
      display.println("PSBT SIGNING");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.println("Waiting for PSBT");
      display.println("over USB CDC...");
      display.setCursor(0, 42);
      display.println("Send PSBT as base64");
      display.setTextSize(1);
      display.setCursor(0, 56);
      display.print("CANCEL to abort");
      break;

    case TX_FEE_REVIEW:
      display.setCursor(0, 0);
      display.println("REVIEW TRANSACTION");
      display.println("---------------------");
      display.setCursor(0, 18);
      {
        char btc_buf[32];
        uint64_t send_amt = txTotalOutputSats;
        for (uint32_t i = 0; i < txReviewPsbt.output_count; i++) {
          if (is_output_change(&txReviewPsbt.outputs[i]))
            send_amt -= txReviewPsbt.outputs[i].amount;
        }
        format_btc(send_amt, btc_buf, sizeof(btc_buf));
        display.print("Sending: ");
        display.println(btc_buf);
      }
      display.setCursor(0, 30);
      {
        char fee_buf[32];
        format_sats((uint64_t)txFeeSats, fee_buf, sizeof(fee_buf));
        display.print("Fee: ");
        display.print(fee_buf);
        display.println(" sats");
      }
      display.setCursor(0, 42);
      display.print("Rate: ");
      display.print(txFeeRateSatPerVb);
      display.print(" sat/vB  ");
      if (txHasRBF) {
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print("RBF:ON");
      } else {
        display.print("RBF:OFF");
      }
      display.setTextColor(SSD1306_WHITE);
      if (txHighFee) {
        display.setCursor(0, 52);
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        display.print("HIGH FEE - Confirm?");
        display.setTextColor(SSD1306_WHITE);
      }
      display.setCursor(0, 56);
      display.print("CANCEL=cancel CONFIRM=ok");
      break;

    case TX_OUTPUT_REVIEW:
      display.setCursor(0, 0);
      {
        uint32_t actual_idx = txNonChangeIndices[txReviewOutputIdx];
        bool is_change = is_output_change(&txReviewPsbt.outputs[actual_idx]);
        if (is_change) {
          display.println("CHANGE to You");
        } else {
          display.print("SEND  Output ");
          display.print(txReviewOutputIdx + 1);
          display.print("/");
          display.println(txNonChangeOutputCount);
        }
      }
      display.println("---------------------");
      {
        uint32_t actual_idx = txNonChangeIndices[txReviewOutputIdx];
        uint64_t amt = txReviewPsbt.outputs[actual_idx].amount;
        char btc_buf[32];
        format_btc(amt, btc_buf, sizeof(btc_buf));
        display.setCursor(0, 18);
        display.setTextSize(2);
        display.println(btc_buf);
        display.setTextSize(1);
        display.setCursor(0, 36);
        display.print("to: ");
        display.println(txReviewAddressBuf);
      }
      {
        bool is_last = (txReviewOutputIdx + 1 >= txNonChangeOutputCount);
        display.setCursor(0, 56);
        if (is_last)
          display.print("CANCEL=menu CONFIRM=sign");
        else
          display.print("CANCEL=next CONFIRM=sign");
      }
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
      if (txSignCount > 0) {
        display.println("TX SIGNED!");
        display.setTextSize(1);
        display.println("");
        char msg[32];
        snprintf(msg, sizeof(msg), "%d input(s) signed.", txSignCount);
        display.println(msg);
        if (psbtFromUsb) {
          uint8_t out_buf[PSBT_MAX_BUFFER];
          size_t out_len = psbt_serialize(&txReviewPsbt, out_buf, sizeof(out_buf));
          if (out_len > 0) {
            serial_send_signed(out_buf, out_len);
          }
          psbtFromUsb = false;
        }
      } else {
        display.println("NO INPUTS");
        display.setTextSize(1);
        display.println("");
        display.println("No owned inputs found");
        display.println("in this PSBT.");
        if (psbtFromUsb) {
          serial_send_error(-2);
          psbtFromUsb = false;
        }
      }
      display.println("Returning to menu...");
      display.display();
      delay(2500);
      currentState = MAIN_MENU;
      break;

    case TX_SIGN_ERROR:
      display.setCursor(0, 10);
      display.setTextSize(2);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.println("SIGN FAILED");
      display.setTextColor(SSD1306_WHITE);
      display.setTextSize(1);
      display.println("");
      display.print("SE error: ");
      display.println(txSignError);
      display.println("No PSBT returned.");
      if (psbtFromUsb) {
        serial_send_error(txSignError);
        psbtFromUsb = false;
      }
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
      display.setCursor(0, 56);
      display.print("Reboot to begin");
      break;

    case VERIFY_ADDRESS:
      display.setCursor(0, 0);
      {
        uint32_t acct = account_get_active();
        char name_buf[ACCOUNT_NAME_LEN];
        if (account_get_name(acct, name_buf, sizeof(name_buf))) {
          display.print("VERIFY [");
          display.print(name_buf);
          display.println("]");
        } else {
          display.print("VERIFY [Acct ");
          display.print(acct);
          display.println("]");
        }
      }
      display.println("---------------------");
      display.setTextSize(1);
      display.setCursor(0, 18);
      display.println(currentAddressStr);
      display.setCursor(0, 38);
      display.print("Type: ");
      display.println(address_type_name((address_type_t)addressTypeIdx));
      display.setCursor(0, 48);
      display.print("Addr #");
      display.print(addressIndex);
      display.setCursor(0, 56);
      display.print("CANCEL=cycle type CONFIRM=back");
      break;

    case VERIFY_MATCH:
      display.setCursor(0, 0);
      display.println("ADDRESS VERIFIED");
      display.println("---------------------");
      display.setTextSize(1);
      display.setCursor(0, 18);
      display.println(currentAddressStr);
      display.setCursor(0, 48);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(" VERIFIED OK ");
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(0, 56);
      display.print("Any button to return");
      break;

    case VERIFY_MISMATCH: {
      unsigned long elapsed = millis() - verifyResultEnteredMs;
      int cycle = (int)(elapsed / 300);

      if (cycle < 6 && (cycle % 2 == 0)) {
        display.invertDisplay(true);
      } else {
        display.invertDisplay(false);
      }

      display.setTextColor(SSD1306_WHITE);
      display.setCursor(0, 10);
      display.setTextSize(2);
      display.println("ADDRESS");
      display.println("MISMATCH!");
      display.setTextSize(1);
      display.setCursor(0, 56);
      display.print("Any button to return");
      break;
    }

    case DEVICE_ID_DISPLAY:
      display.setCursor(0, 0);
      display.println("COINCUBE DEVICE ID");
      display.println("---------------------");
      display.setCursor(0, 20);
      display.print(antiPhishWords[0]);
      display.print("  ");
      display.println(antiPhishWords[1]);
      display.setCursor(0, 32);
      display.print(antiPhishWords[2]);
      display.print("  ");
      display.println(antiPhishWords[3]);
      display.setCursor(0, 48);
      display.println("Match companion app");
      display.setCursor(0, 56);
      display.print("Any button to continue");
      break;

    case ACCOUNT_SELECT:
      display.setCursor(0, 0);
      display.println("SELECT ACCOUNT");
      display.println("---------------------");
      {
        int totalItems = (int)MAX_ACCOUNTS + 1;
        int visibleCount = (totalItems < 5) ? totalItems : 5;
        int halfWin = visibleCount / 2;
        int firstIdx = (int)activeAccount - halfWin;
        if (firstIdx < 0) firstIdx = 0;
        int lastIdx = firstIdx + visibleCount;
        if (lastIdx > totalItems) {
          lastIdx = totalItems;
          firstIdx = lastIdx - visibleCount;
          if (firstIdx < 0) firstIdx = 0;
        }
        for (int i = firstIdx; i < lastIdx; i++) {
          int row = 20 + (i - firstIdx) * 8;
          display.setCursor(0, row);
          bool isSelected = ((uint32_t)i == activeAccount);
          if (isSelected) {
            display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
          }
          if (i < (int)MAX_ACCOUNTS) {
            display.print("Acct ");
            display.print(i);
            char name_buf[ACCOUNT_NAME_LEN];
            if (account_get_name((uint32_t)i, name_buf, sizeof(name_buf))) {
              display.print(" ");
              display.print(name_buf);
            }
            if (isSelected) {
              int labelLen = 7 + (name_buf[0] ? (int)strlen(name_buf) + 1 : 0);
              int pad = 21 - labelLen;
              while (pad-- > 0) display.print(" ");
              display.setTextColor(SSD1306_WHITE);
            }
          } else {
            display.print("  Rename Acct");
            if (isSelected) {
              while (display.getCursorX() < 21 * 6) display.print(" ");
              display.setTextColor(SSD1306_WHITE);
            }
          }
        }
      }
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=select");
      break;

    case ACCOUNT_RENAME:
      display.setCursor(0, 0);
      {
        uint32_t cur = account_get_active();
        display.print("RENAME ACCT ");
        display.println(cur);
      }
      display.println("---------------------");
      display.setCursor(0, 18);
      if (acctNamePos > 0) {
        display.print(acctNameBuf);
      }
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      bool atDone = (acctNameCharIdx >= ACCT_NAME_CHAR_COUNT);
      if (acctNamePos < 6) {
        if (atDone) {
          display.print("[DONE]");
        } else {
          display.print(ACCT_NAME_CHARS[acctNameCharIdx]);
        }
      } else {
        display.print("[DONE]");
      }
      display.setTextColor(SSD1306_WHITE);
      for (int i = acctNamePos + 1; i < 6; i++) display.print("_");
      display.setCursor(0, 40);
      display.print("Pos: ");
      display.print(acctNamePos);
      display.print("/6");
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=select");
      break;

    case SETTINGS_MENU:
      display.setCursor(0, 0);
      display.println("SETTINGS");
      display.println("---------------------");
      {
        int visibleItems = (SETTINGS_ITEM_COUNT < 4) ? SETTINGS_ITEM_COUNT : 4;
        int half = visibleItems / 2;
        int firstIdx = (int)settingsMenuIdx - half;
        if (firstIdx < 0) firstIdx = 0;
        int lastIdx = firstIdx + visibleItems;
        if (lastIdx > SETTINGS_ITEM_COUNT) {
          lastIdx = SETTINGS_ITEM_COUNT;
          firstIdx = lastIdx - visibleItems;
          if (firstIdx < 0) firstIdx = 0;
        }
        for (int i = firstIdx; i < lastIdx; i++) {
          int row = 18 + (i - firstIdx) * 9;
          display.setCursor(0, row);
          if (i == (int)settingsMenuIdx) {
            display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
            display.print("> ");
            display.print(settingsItems[i]);
            while (display.getCursorX() < 21 * 6) display.print(" ");
            display.setTextColor(SSD1306_WHITE);
          } else {
            display.print("  ");
            display.print(settingsItems[i]);
          }
        }
      }
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=select");
      break;

    case SETTINGS_TIMEOUT:
      display.setCursor(0, 0);
      display.println("DISPLAY TIMEOUT");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.setTextSize(2);
      display.println(settings_disp_timeout_label(settingsSubIdx));
      display.setTextSize(1);
      display.setCursor(0, 48);
      display.print("Current: ");
      display.println(settings_disp_timeout_label(settings_get_display_timeout()));
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=save");
      break;

    case SETTINGS_AUTOLOCK:
      display.setCursor(0, 0);
      display.println("AUTO-LOCK TIMEOUT");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.setTextSize(2);
      display.println(settings_auto_lock_label(settingsSubIdx));
      display.setTextSize(1);
      display.setCursor(0, 48);
      display.print("Current: ");
      display.println(settings_auto_lock_label(settings_get_auto_lock()));
      display.setCursor(0, 56);
      display.print("CANCEL=cycle CONFIRM=save");
      break;

    case SETTINGS_CONTRAST:
      display.setCursor(0, 0);
      display.println("DISPLAY CONTRAST");
      display.println("---------------------");
      display.setCursor(0, 22);
      display.setTextSize(2);
      display.print(settingsContrastVal);
      display.setTextSize(1);
      display.setCursor(0, 36);
      int barW = map(settingsContrastVal, 0, 255, 0, 120);
      display.fillRect(2, 42, 124, 6, SSD1306_BLACK);
      display.drawRect(2, 42, 124, 6, SSD1306_WHITE);
      display.fillRect(2, 42, barW, 6, SSD1306_WHITE);
      display.setCursor(0, 56);
      display.print("CANCEL= <  CONFIRM= >");
      break;

    case SETTINGS_CHANGE_PIN_OLD:
      display.setCursor(0, 0);
      display.println("CURRENT PIN");
      display.println("---------------------");
      display.setCursor(20, 24);
      for (int i = 0; i < 6; i++) {
        if (i < changePinPosition) {
          display.print("*");
        } else if (i == changePinPosition) {
          display.print("[");
          display.print(changePinDigitValue);
          display.print("]");
        } else {
          display.print("_");
        }
        if (i < 5) display.print(" ");
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=change CANCEL=next");
      break;

    case SETTINGS_CHANGE_PIN_NEW:
      display.setCursor(0, 0);
      display.println("NEW PIN");
      display.println("---------------------");
      display.setCursor(20, 24);
      for (int i = 0; i < 6; i++) {
        if (i < changePinPosition) {
          display.print("*");
        } else if (i == changePinPosition) {
          display.print("[");
          display.print(changePinDigitValue);
          display.print("]");
        } else {
          display.print("_");
        }
        if (i < 5) display.print(" ");
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=change CANCEL=next");
      break;

    case SETTINGS_CHANGE_PIN_CONFIRM:
      display.setCursor(0, 0);
      display.println("CONFIRM NEW PIN");
      display.println("---------------------");
      display.setCursor(20, 24);
      for (int i = 0; i < 6; i++) {
        if (i < changePinPosition) {
          display.print("*");
        } else if (i == changePinPosition) {
          display.print("[");
          display.print(changePinDigitValue);
          display.print("]");
        } else {
          display.print("_");
        }
        if (i < 5) display.print(" ");
      }
      display.setCursor(0, 56);
      display.print("CONFIRM=change CANCEL=next");
      break;

    case SETTINGS_PIN_MISMATCH:
      display.setCursor(0, 0);
      display.println("PIN CHANGE");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.setTextSize(1);
      display.println("PINs do not match");
      display.setCursor(0, 42);
      display.println("Try again.");
      display.setCursor(0, 56);
      display.print("Any button to return");
      break;

    case SETTINGS_ABOUT:
      display.setCursor(0, 0);
      display.println("ABOUT");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.print("FW: ");
      display.println(FIRMWARE_VERSION);
      display.print("Hash: ");
      display.println(BUILD_HASH);
      display.print("SE: ");
      {
        char serial[32];
        if (se051_get_serial(serial, sizeof(serial)) == SE_OK) {
          display.println(serial);
        } else {
          display.println("unknown");
        }
      }
      display.print("Addr type: ");
      {
        address_type_t at = (address_type_t)addressTypeIdx;
        display.println(address_type_name(at));
      }
      display.print("Active acct: ");
      display.println(account_get_active());
      {
        const char *crash = watchdog_get_last_crash();
        if (crash) {
          display.setCursor(0, 56);
          display.print("Last crash: ");
          display.println(crash);
        } else {
          display.setCursor(0, 56);
          display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
          display.print(" [BACK] ");
          display.setTextColor(SSD1306_WHITE);
        }
      }
      break;

    case SETTINGS_FACTORY_RESET_CONFIRM:
      display.setCursor(0, 0);
      display.println("FACTORY RESET");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.setTextSize(1);
      display.println("Reset wallet?");
      display.setCursor(0, 42);
      display.println("All keys & settings");
      display.println("will be erased.");
      display.setCursor(0, 56);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(" CANCEL=No CONFIRM=Yes ");
      display.setTextColor(SSD1306_WHITE);
      break;

    case SETTINGS_FACTORY_RESET_SURE:
      display.setCursor(0, 0);
      display.println("FACTORY RESET");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.setTextSize(1);
      display.println("Are you sure?");
      display.setCursor(0, 42);
      display.println("This cannot be undone.");
      display.setCursor(0, 56);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.print(" CANCEL=No CONFIRM=WIPE ");
      display.setTextColor(SSD1306_WHITE);
      break;

    case WATCHDOG_RECOVERY:
      display.setCursor(0, 0);
      display.println("DEVICE RECOVERED");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.println("Unexpected restart.");
      display.setCursor(0, 36);
      display.println("Re-enter PIN to");
      display.println("continue.");
      display.setCursor(0, 56);
      display.print("Any button to continue");
      break;

    case COIN_CONTROL:
      display.setCursor(0, 0);
      display.println("COIN CONTROL");
      display.println("---------------------");
      {
        uint8_t ownedIndices[PSBT_MAX_INPUTS];
        uint8_t ownedCount = 0;
        for (uint32_t i = 0; i < txReviewPsbt.input_count; i++) {
          if (txReviewPsbt.inputs[i].bip32_derivation.present &&
              txReviewPsbt.inputs[i].bip32_derivation.path_len > 0) {
            ownedIndices[ownedCount] = (uint8_t)i;
            ownedCount++;
          }
        }
        for (uint32_t i = 0; i < txReviewPsbt.input_count; i++) {
          bool owned = (txReviewPsbt.inputs[i].bip32_derivation.present &&
                        txReviewPsbt.inputs[i].bip32_derivation.path_len > 0);
          if (!owned) {
            display.setCursor(0, 20 + (int)i * 8);
            display.print("(E) EXTERNAL - skip");
          }
        }
        uint8_t totalItems = ownedCount + 1;
        int visibleCount = (totalItems < 5) ? (int)totalItems : 5;
        int halfWin = visibleCount / 2;
        int firstIdx = (int)coinControlScrollIdx - halfWin;
        if (firstIdx < 0) firstIdx = 0;
        int lastIdx = firstIdx + visibleCount;
        if (lastIdx > (int)totalItems) {
          lastIdx = (int)totalItems;
          firstIdx = lastIdx - visibleCount;
          if (firstIdx < 0) firstIdx = 0;
        }
        for (int item = firstIdx; item < lastIdx; item++) {
          int row = 20 + (item - firstIdx) * 9;
          display.setCursor(0, row);
          bool isHighlighted = ((uint8_t)item == coinControlScrollIdx);
          if (isHighlighted) {
            display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
          }
          if (item < (int)ownedCount) {
            uint32_t inputIdx = ownedIndices[item];
            bool sel = txInputSelected[inputIdx];
            display.print(sel ? "[*] " : "[ ] ");
            for (int b = 0; b < 4; b++) {
              if (txReviewPsbt.inputs[inputIdx].txid[b] < 0x10) display.print('0');
              display.print(txReviewPsbt.inputs[inputIdx].txid[b], HEX);
            }
            display.print(" v:");
            display.print(txReviewPsbt.inputs[inputIdx].vout);
            display.print(" ");
            char amt_buf[16];
            format_sats(txReviewPsbt.inputs[inputIdx].witness_utxo.amount, amt_buf, sizeof(amt_buf));
            display.print(amt_buf);
            display.print(" sats");
          } else {
            display.print("> PROCEED TO REVIEW");
          }
          if (isHighlighted) {
            while (display.getCursorX() < 21 * 6) display.print(" ");
            display.setTextColor(SSD1306_WHITE);
          }
        }
      }
      {
        uint64_t selectedSats = 0;
        for (uint32_t i = 0; i < txReviewPsbt.input_count; i++) {
          if (txInputSelected[i]) {
            selectedSats += txReviewPsbt.inputs[i].witness_utxo.amount;
          }
        }
        display.setCursor(0, 56);
        display.print("Sel: ");
        char sel_buf[16];
        format_sats(selectedSats, sel_buf, sizeof(sel_buf));
        display.print(sel_buf);
        display.print(" CANCEL=scroll CONFIRM=toggle");
      }
      break;
  }
  display.display();
}

// --- SECURE PROCESSING LOGIC ---
void executeSigningSequence() {
  watchdog_set_signing_active(true);
  int signed_count = psbt_sign(&txReviewPsbt, txInputSelected);
  watchdog_set_signing_active(false);
  if (signed_count < 0) {
    txSignError = signed_count;
    currentState = TX_SIGN_ERROR;
  } else {
    txSignCount = signed_count;
    currentState = TX_SUCCESS;
  }
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

// --- MNEMONIC CEREMONY HELPERS ---
void secureZeroMnemonic() {
  volatile uint8_t *p = (volatile uint8_t *)mnemonicWords;
  for (size_t i = 0; i < sizeof(mnemonicWords); i++) *p++ = 0;
}

void startMnemonicCeremony() {
  memset(mnemonicWords, 0, sizeof(mnemonicWords));
  mnemonicWordIndex = 0;
  mnemonicVerifyIndices[0] = 0;
  mnemonicVerifyIndices[1] = 0;
  mnemonicVerifyIndices[2] = 0;
  mnemonicVerifyStep = 0;
  mnemonicVerifyScroll = 0;
  displayOn = true;
  lastActivityMs = millis();

  if (!bip39_generate(mnemonicWords)) {
    currentState = WALLET_WIPED;
    return;
  }
  currentState = MNEMONIC_DISPLAY;
}

void startVerification() {
  mnemonicVerifyStep = 0;
  mnemonicVerifyScroll = 0;

  for (int i = 0; i < 3; i++) {
    uint8_t rnd;
    bool distinct;
    do {
      se051_get_random(&rnd, 1);
      rnd = rnd % 24;
      distinct = true;
      for (int j = 0; j < i; j++) {
        if (mnemonicVerifyIndices[j] == rnd) {
          distinct = false;
          break;
        }
      }
    } while (!distinct);
    mnemonicVerifyIndices[i] = rnd;
  }

  currentState = MNEMONIC_VERIFY;
}

// --- WALLET RESTORE HELPERS ---
void updateRestoreMatches() {
  restoreMatchCount = bip39_find_prefix(restorePrefix, &restoreMatchStart);
}

void updateRestoreMatchesPreview() {
  char preview[6];
  uint8_t i;
  for (i = 0; i < restorePrefixLen && i < 4; i++) {
    preview[i] = restorePrefix[i];
  }
  preview[i] = restoreLetter;
  preview[i + 1] = '\0';
  restoreMatchCount = bip39_find_prefix(preview, &restoreMatchStart);
}

void secureZeroRestore() {
  volatile uint8_t *p = (volatile uint8_t *)restoreWords;
  for (size_t i = 0; i < sizeof(restoreWords); i++) *p++ = 0;
  restoreWordIdx = 0;
  restorePrefixLen = 0;
  restorePrefix[0] = '\0';
  restoreLetter = 'a';
  restoreMatchPos = 0;
}

void initPassphraseEntry() {
  memset(passphrase, 0, sizeof(passphrase));
  passphraseLen = 0;
  passphraseCharIdx = 0;
  passphraseDone = false;
}

void initSessionPassphraseEntry() {
  memset(passphrase, 0, sizeof(passphrase));
  memset(sessionPassphrase, 0, sizeof(sessionPassphrase));
  passphraseLen = 0;
  passphraseCharIdx = 0;
  passphraseDone = false;
  passphraseIsNewWallet = false;
}

void secureZeroPassphrase() {
  volatile uint8_t *p = (volatile uint8_t *)passphrase;
  for (size_t i = 0; i < sizeof(passphrase); i++) *p++ = 0;
  passphraseLen = 0;
  passphraseCharIdx = 0;
  passphraseDone = false;
}

void startRestoreProcess() {
  memset(restoreWords, 0, sizeof(restoreWords));
  restoreWordIdx = 0;
  restorePrefixLen = 0;
  restorePrefix[0] = '\0';
  restoreLetter = 'a';
  restoreMatchStart = 0;
  restoreMatchCount = 0;
  restoreMatchPos = 0;
  restoreStartTime = millis();
  restoreError[0] = '\0';
  restorePassphrase = false;
  updateRestoreMatches();
  currentState = MNEMONIC_RESTORE_LETTER;
}

void updateAddressDisplay() {
  address_type_t type = (address_type_t)addressTypeIdx;
  uint32_t acct = account_get_active();
  if (!address_generate(type, acct, addressIndex, currentAddressStr)) {
    strncpy(currentAddressStr, "Address gen error", MAX_ADDRESS_LEN);
  }
}
