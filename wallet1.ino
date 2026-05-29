#define SKIP_INTEGRITY_CHECK
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
#include <esp_system.h>   // esp_random() fallback TRNG
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
#include "esp_partition.h"
#include "sha256.h"
#include "fw_integrity.h"

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
  TX_RBF_CONFIRM,
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
  TX_HISTORY,
  WATCHDOG_RECOVERY,
  SE_ERROR,  // Secure element failed to initialise — shown instead of BOOT_MENU
  BIP39_PREDICTIVE_INPUT  // US-032: Unified predictive BIP39 keyboard (restore & verify)
};
WalletState currentState = PIN_SETUP;
bool seAvailable = false;
se051_err_t seInitErr = SE_OK;  // Last SE init error code, shown on SE_ERROR screen

int menuIndex = 0;
const int TOTAL_MENU_ITEMS = 9;
const char* menuItems[] = {
  "1. View Balance",
  "2. Receive (Addr)",
  "3. Sign Transaction",
  "4. PQC Quantum Sec",
  "5. Demo Sign (PSBT)",
  "6. Verify Address",
  "7. Account",
  "8. Settings",
  "9. TX History"
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

// --- PREDICTIVE BIP39 KEYBOARD STATE (US-032) ---
char predictivePrefix[5];
uint8_t predictivePrefixLen = 0;
char predictiveLetter = 'a';
uint16_t predictiveMatchIndices[3];
uint8_t predictiveMatchCount = 0;
uint8_t predictiveTotalCount = 0;
uint8_t predictiveHighlight = 0;
bool predictiveSelectMode = false;
unsigned long predictiveCancelHoldStart = 0;
bool predictiveLongPressDone = false;
bool predictiveIsVerify = false;

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
uint8_t txMetaPage;
int txSignCount = 0;
int txSignError = 0;
bool psbtFromUsb = false;

// --- COIN CONTROL STATE ---
bool txInputSelected[PSBT_MAX_INPUTS];
uint8_t coinControlScrollIdx;
uint8_t coinControlOwnedCount;

// --- BALANCE STATE ---
unsigned long balanceFetchStartMs = 0;
uint64_t balanceConfirmed   = 0;
uint64_t balanceUnconfirmed = 0;
uint8_t  balanceResponsesExpected = 0;
uint8_t  balanceResponsesReceived = 0;
bool     balanceFetchDone   = false;
bool     balanceUsingCache  = false;

// --- TX HISTORY STATE ---
unsigned long txHistoryFetchStartMs = 0;
uint8_t  txHistoryResponsesExpected = 0;
uint8_t  txHistoryResponsesReceived = 0;
bool     txHistoryFetchDone   = false;
bool     txHistoryUsingCache  = false;
uint8_t  txHistoryScrollIdx   = 0;

// --- PQC STATE ---
uint8_t pqcScrollOffset = 0;
static const uint8_t PQC_LINE_COUNT = 9;
static const char* const pqcLines[] = {
  "SE: NXP SE051C2",
  "Sig: secp256k1 ECDSA/Schnorr",
  "PQC Roadmap: Phase 1 (Classical)",
  "Phase 2: Hybrid ECDSA+ML-KEM-512",
  "Phase 3: Full ML-KEM-512",
  "FIPS 203: ML-KEM-512 standard",
  "Status: Not yet implemented",
  "BTC quantum risk estimate:",
  "~2030+ (per NIST timeline)"
};

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

const char* get_input_segwit_label(const psbt_input_t *input) {
  if (!input->witness_utxo.present) return "Legacy";
  const uint8_t *spk = input->witness_utxo.script_pubkey;
  uint8_t len = input->witness_utxo.script_pubkey_len;
  if (len > 1 && spk[0] < 0xFD && (uint8_t)(spk[0] + 1) == len) {
    spk++;
    len = spk[-1];
  }
  if (len >= 2 && spk[0] == 0x00 && spk[1] == 0x14) return "SegWit v0";
  if (len >= 2 && spk[0] == 0x00 && spk[1] == 0x20) return "SegWit v0 (P2WSH)";
  if (len >= 2 && spk[0] == 0x51 && spk[1] == 0x20) return "Taproot v1";
  return "Legacy";
}

void format_locktime(uint32_t locktime, char *buf, size_t len) {
  if (locktime == 0) {
    snprintf(buf, len, "Locktime: none");
    return;
  }
  if (locktime < 500000000) {
    snprintf(buf, len, "Locktime: Block %u", (unsigned)locktime);
  } else {
    time_t t = (time_t)locktime;
    struct tm *tm_info = gmtime(&t);
    snprintf(buf, len, "Locktime: %04d-%02d-%02d",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
  }
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
  txMetaPage = 0;
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


// ─── US-030: Firmware Integrity Self-Test ────────────────────────────────────
//
// Reads the expected SHA-256 hash from SE object 0x06 (written at factory
// provisioning via US-031), computes SHA-256 over the running firmware
// partition, and compares.  If no hash is provisioned (SE_ERR_NOTFOUND),
// the check is skipped gracefully.  Build with -DSKIP_INTEGRITY_CHECK to
// bypass entirely (dev builds that haven't been through provisioning).

#ifndef SKIP_INTEGRITY_CHECK

// Returns true  → firmware OK (or hash not provisioned yet)
// Returns false → hash mismatch, tamper detected
static bool firmware_integrity_check(void) {
  if (!seAvailable) return true;   // SE offline → cannot verify, allow boot

  uint8_t stored_hash[SHA256_DIGEST_LENGTH];
  size_t  stored_len = 0;
  se051_err_t rc = se051_read_object(SE051_OBJ_FW_HASH,
                                     stored_hash, sizeof(stored_hash),
                                     &stored_len);
  if (rc == SE_ERR_NOTFOUND || stored_len != SHA256_DIGEST_LENGTH)
    return true;   // not provisioned yet — skip
  if (rc != SE_OK) return true;    // SE read error → fail-open in dev

  const esp_partition_t *part = esp_partition_find_first(
    ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
  if (!part) return false;

  sha256_ctx ctx;
  sha256_init(&ctx);
  static uint8_t chunk[4096];      // static: avoids 4 KB stack frame
  uint32_t offset    = 0;
  uint32_t remaining = part->size;
  while (remaining > 0) {
    uint32_t to_read = (remaining < sizeof(chunk)) ? remaining
                                                   : (uint32_t)sizeof(chunk);
    if (esp_partition_read(part, offset, chunk, to_read) != ESP_OK)
      return false;
    sha256_update(&ctx, chunk, (size_t)to_read);
    offset    += to_read;
    remaining -= to_read;
    watchdog_feed();               // keep TWDT happy during long hash
  }
  uint8_t computed[SHA256_DIGEST_LENGTH];
  sha256_final(&ctx, computed);
  return memcmp(computed, stored_hash, SHA256_DIGEST_LENGTH) == 0;
}

// Calls firmware_integrity_check(); halts forever on tamper.
static void run_integrity_check(void) {
  if (firmware_integrity_check()) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(16, 22);
    display.println("Integrity OK");
    display.display();
    delay(1000);
    return;
  }
  // ── TAMPER DETECTED ──────────────────────────────────────────────────────
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
  // Do NOT feed the watchdog — let TWDT reboot the device so the tamper
  // screen re-appears on every restart until the firmware is replaced.
  for (;;) { delay(500); }
}

#endif // SKIP_INTEGRITY_CHECK

// ─── US-031: Factory hash provisioning handler ───────────────────────────────
//
// Accepts PROVISION_HASH only before the wallet is initialised, preventing a
// post-setup attacker from overwriting the stored hash to bypass US-030.
static void handle_provision_hash(const uint8_t *hash32) {
  if (!hash32 || wallet_is_initialized() || !seAvailable) {
    serial_send_hash_err();
    return;
  }
  se051_err_t rc = se051_store_key(SE051_OBJ_FW_HASH, hash32, 32);
  if (rc == SE_OK) serial_send_hash_ok();
  else             serial_send_hash_err();
}

void setup() {
  Serial.begin(115200);
  Serial.println("[BOOT] setup() start");
  serial_init();
  Wire.begin(SDA_PIN, SCL_PIN);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    display.begin(SSD1306_EXTERNALVCC, 0x3C);
  }

  pinMode(BTN_CONFIRM, INPUT_PULLUP);
  pinMode(BTN_CANCEL, INPUT_PULLUP);

  showBootSplash();

  seInitErr = se051_init();
  seAvailable = (seInitErr == SE_OK);

#ifndef SKIP_INTEGRITY_CHECK
  run_integrity_check();
#endif

  watchdog_init();

  account_init();

  settings_init();
  balance_init();
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

  if (!seAvailable) {
    // Route to a dedicated error screen so the user gets a clear message
    // instead of a menu they can cycle but never confirm.
    currentState = SE_ERROR;
  } else if (pin_is_set()) {
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

// File-scope static: keeps the 8 KB serial_msg_t off the loopTask stack
// (default 8 KB).  Using serial_poll_into() writes directly into this
// buffer — no copy, no stack growth.  (US-031 / stack-canary fix.)
static serial_msg_t g_serial_msg;

void loop() {
  watchdog_feed();

  // ── US-031 factory provisioning (accepted only pre-wallet-init) ─────
  serial_poll_into(&g_serial_msg);
  if (g_serial_msg.cmd == SERIAL_CMD_PROVISION_HASH && g_serial_msg.data_len == 32) {
    handle_provision_hash(g_serial_msg.data);
  }

  // ── USB desktop-app handshake (US-HW-011) ────────────────────────────
  // Respond to probe / info queries at any time so the desktop app can
  // detect the device regardless of which wallet state is active.
  if (g_serial_msg.cmd == SERIAL_CMD_GET_INFO) {
    // Bare READY triggers the Rust legacy_handshake path in coincube_hw.rs,
    // which follows up with GET_XPUB:m/84'/0'/0'.
    serial_send_ready();
  } else if (g_serial_msg.cmd == SERIAL_CMD_GET_XPUB) {
    static char s_xpub_buf[XPUB_STR_LEN];
    if (wallet_get_account_xpub(s_xpub_buf)) {
      serial_send_xpub(s_xpub_buf);
    } else {
      // Wallet not yet initialised — device detected but xpub unavailable.
      serial_send_error(1);
    }
  }

#ifdef DEV_BUILD
  if (WiFi.status() == WL_CONNECTED) {
    ArduinoOTA.handle();
  }
#endif

  if (currentState == WAIT_PSBT) {
    if (g_serial_msg.cmd == SERIAL_CMD_PSBT && g_serial_msg.data_len > 0) {
      psbtFromUsb = true;
      initTransactionReviewFromBuffer(g_serial_msg.data, g_serial_msg.data_len);
      if (txReviewReady) {
        if (coinControlOwnedCount > 1) {
          currentState = COIN_CONTROL;
        } else {
          txMetaPage = 0;
          currentState = TX_FEE_REVIEW;
        }
      } else {
        serial_send_error(-1);
        currentState = MAIN_MENU;
      }
    }
  }

  if (currentState == VERIFY_ADDRESS) {
    if (g_serial_msg.cmd == SERIAL_CMD_VERIFY && g_serial_msg.data_len > 0 && g_serial_msg.data_len < MAX_ADDRESS_LEN) {
      memcpy(verifyReceivedAddr, g_serial_msg.data, g_serial_msg.data_len + 1);
      updateAddressDisplay();
      verifyMatchResult = (strcmp(currentAddressStr, verifyReceivedAddr) == 0);
      verifyResultEnteredMs = millis();
      currentState = verifyMatchResult ? VERIFY_MATCH : VERIFY_MISMATCH;
    }
  }

  if (currentState == SHOW_BALANCE && !balanceFetchDone) {
    if (g_serial_msg.cmd == SERIAL_CMD_BALANCE && g_serial_msg.data_len >= 16) {
      uint64_t conf, unconf;
      memcpy(&conf, g_serial_msg.data, 8);
      memcpy(&unconf, g_serial_msg.data + 8, 8);
      balanceConfirmed += conf;
      balanceUnconfirmed += unconf;
      balanceResponsesReceived++;
    }
    if (millis() - balanceFetchStartMs > 2000 ||
        balanceResponsesReceived >= balanceResponsesExpected) {
      balanceFetchDone = true;
      if (balanceResponsesReceived > 0) {
        balance_set_cached(balanceConfirmed, balanceUnconfirmed);
      } else if (balance_has_cached()) {
        balanceUsingCache = true;
        balance_get_cached(&balanceConfirmed, &balanceUnconfirmed);
      }
    }
  }

  if (currentState == TX_HISTORY && !txHistoryFetchDone) {
    if (g_serial_msg.cmd == SERIAL_CMD_TX_ENTRY && g_serial_msg.data_len >= 45) {
      uint8_t txid[32];
      memcpy(txid, g_serial_msg.data, 32);
      char dir = (char)g_serial_msg.data[32];
      uint64_t amount;
      uint32_t confs;
      memcpy(&amount, g_serial_msg.data + 33, 8);
      memcpy(&confs, g_serial_msg.data + 41, 4);
      tx_history_add_entry(txid, dir, amount, confs);
      txHistoryResponsesReceived++;
    }
    if (millis() - txHistoryFetchStartMs > 2000 ||
        txHistoryResponsesReceived >= txHistoryResponsesExpected) {
      txHistoryFetchDone = true;
      if (txHistoryResponsesReceived > 0) {
      } else if (tx_history_has_cached()) {
        txHistoryUsingCache = true;
      }
    }
  }

  if (currentState == DEVICE_ID_DISPLAY &&
      (millis() - deviceIdEnteredMs > 3000)) {
    currentState = MAIN_MENU;
  }

  if (currentState == WALLET_WIPED &&
      (millis() - lastActivityMs > 4000)) {
    ESP.restart();
  }

  if ((currentState == MNEMONIC_DISPLAY ||
       (currentState == BIP39_PREDICTIVE_INPUT && predictiveIsVerify)) &&
      displayOn && (millis() - lastActivityMs > 30000)) {
    displayOn = false;
  }

  if ((currentState == BIP39_PREDICTIVE_INPUT && !predictiveIsVerify) &&
      (millis() - restoreStartTime > 300000)) {
    memset(restoreWords, 0, sizeof(restoreWords));
    restoreWordIdx = 0;
    predictivePrefixLen = 0;
    predictivePrefix[0] = '\0';
    predictiveLetter = 'a';
    currentState = BOOT_MENU;
  }

  if (currentState == MAIN_MENU ||
      currentState == SHOW_BALANCE ||
      currentState == SHOW_ADDRESS ||
      currentState == QR_DISPLAY ||
      currentState == PQC_STATUS ||
      currentState == TX_HISTORY ||
      currentState == MNEMONIC_DISPLAY ||
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
    case SE_ERROR:
      // Both buttons attempt a soft SE re-init so the user can recover
      // without a full power cycle if the failure was transient (e.g. I2C glitch).
      if (confirmPressed || cancelPressed) {
        seInitErr = se051_init();
        seAvailable = (seInitErr == SE_OK);
        if (seAvailable) {
          // Recovered — continue to normal boot decision
          if (pin_is_set()) {
            currentState = PIN_ENTRY;
            pinAttempts = pin_get_attempts();
            pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
            pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
            pinPosition = 0;
            pinDigitValue = 0;
          } else {
            currentState = BOOT_MENU;
          }
        }
        // If still failing, stay on SE_ERROR — screen will refresh with same error
      }
      break;

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
        restoreError[0] = '\0';
        predictivePrefixLen = 0;
        predictivePrefix[0] = '\0';
        predictiveLetter = 'a';
        predictiveSelectMode = false;
        predictiveHighlight = 0;
        predictiveIsVerify = false;
        updatePredictiveMatches();
        currentState = BIP39_PREDICTIVE_INPUT;
      }
      break;

    case RESTORE_COMPLETE:
      break;

    case BIP39_PREDICTIVE_INPUT:
      restoreStartTime = millis();
      if (confirmPressed || cancelPressed) {
        lastActivityMs = millis();
        displayOn = true;
      }

      if (cancelPressed) {
        if (predictiveCancelHoldStart == 0) {
          predictiveCancelHoldStart = millis();
          predictiveLongPressDone = false;
        }

        if (!predictiveLongPressDone && (millis() - predictiveCancelHoldStart) >= 2000) {
          predictivePrefixLen = 0;
          predictivePrefix[0] = '\0';
          predictiveLetter = 'a';
          predictiveSelectMode = false;
          predictiveHighlight = 0;
          updatePredictiveMatches();
          predictiveLongPressDone = true;
        } else if (!predictiveLongPressDone) {
          if (predictiveSelectMode) {
            if (predictiveMatchCount > 0) {
              predictiveHighlight = (predictiveHighlight + 1) % predictiveMatchCount;
            }
          } else {
            if (predictiveLetter == 'z') {
              predictiveLetter = '<';
            } else if (predictiveLetter == '<') {
              if (predictivePrefixLen > 0) {
                predictivePrefixLen--;
                predictivePrefix[predictivePrefixLen] = '\0';
              }
              predictiveLetter = 'a';
            } else {
              predictiveLetter++;
            }
            updatePredictiveMatches();
          }
        }
      } else {
        predictiveCancelHoldStart = 0;
        predictiveLongPressDone = false;
      }

      if (confirmPressed) {
        predictiveCancelHoldStart = 0;
        predictiveLongPressDone = false;

        if (predictiveSelectMode) {
          uint16_t selectedIdx = predictiveMatchIndices[predictiveHighlight];
          predictiveWordSelected(selectedIdx);
        } else {
          if (predictiveLetter == '<') {
            if (predictivePrefixLen > 0) {
              predictivePrefixLen--;
              predictivePrefix[predictivePrefixLen] = '\0';
              predictiveLetter = 'a';
              updatePredictiveMatches();
            }
          } else if (predictiveTotalCount == 1) {
            uint16_t selectedIdx = predictiveMatchIndices[0];
            predictiveWordSelected(selectedIdx);
          } else if (predictiveTotalCount >= 2 && predictiveTotalCount <= 3) {
            predictiveSelectMode = true;
            predictiveHighlight = 0;
          } else if (predictiveTotalCount > 3) {
            if (predictivePrefixLen < 4) {
              predictivePrefix[predictivePrefixLen] = predictiveLetter;
              predictivePrefixLen++;
              predictivePrefix[predictivePrefixLen] = '\0';
              predictiveLetter = 'a';
              updatePredictiveMatches();
            }
          }
        }
      }
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
        if (menuIndex == 0) {
          balanceFetchStartMs = millis();
          balanceConfirmed = 0;
          balanceUnconfirmed = 0;
          balanceResponsesExpected = 0;
          balanceResponsesReceived = 0;
          balanceFetchDone = false;
          balanceUsingCache = false;
          uint32_t acct = account_get_active();
          uint32_t maxIdx = 0;
          account_get_address_index(acct, &maxIdx);
          if (maxIdx > 5) maxIdx = 5;
          char addrBuf[MAX_ADDRESS_LEN];
          for (int t = 0; t < 3; t++) {
            for (uint32_t i = 0; i <= maxIdx; i++) {
              if (address_generate((address_type_t)t, acct, i, addrBuf)) {
                serial_send_balance_request(addrBuf);
                balanceResponsesExpected++;
              }
            }
          }
          currentState = SHOW_BALANCE;
        }
        if (menuIndex == 1) {
          addressTypeIdx = 1;
          uint32_t acct = account_get_active();
          account_get_address_index(acct, &addressIndex);
          updateAddressDisplay();
          currentState = SHOW_ADDRESS;
        }
        if (menuIndex == 2) currentState = SIGN_TX;
        if (menuIndex == 3) { pqcScrollOffset = 0; currentState = PQC_STATUS; }
        if (menuIndex == 4) {
          psbtFromUsb = false;
          initTransactionReview();
          if (txReviewReady) {
            if (coinControlOwnedCount > 1) {
              currentState = COIN_CONTROL;
            } else {
              txMetaPage = 0;
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
        if (menuIndex == 8) {
          tx_history_init();
          txHistoryFetchStartMs = millis();
          txHistoryResponsesExpected = 0;
          txHistoryResponsesReceived = 0;
          txHistoryFetchDone   = false;
          txHistoryUsingCache  = false;
          txHistoryScrollIdx   = 0;
          uint32_t acct = account_get_active();
          uint32_t maxIdx = 0;
          account_get_address_index(acct, &maxIdx);
          if (maxIdx > 5) maxIdx = 5;
          char addrBuf[MAX_ADDRESS_LEN];
          for (int t = 0; t < 3; t++) {
            for (uint32_t i = 0; i <= maxIdx; i++) {
              if (address_generate((address_type_t)t, acct, i, addrBuf)) {
                serial_send_tx_history_request(addrBuf);
                txHistoryResponsesExpected++;
              }
            }
          }
          currentState = TX_HISTORY;
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
      lastActivityMs = millis();
      if (balanceFetchDone && (cancelPressed || confirmPressed)) {
        currentState = MAIN_MENU;
      }
      break;

    case TX_SUCCESS:
    case TX_SIGN_ERROR:
      if (cancelPressed || confirmPressed) {
        currentState = MAIN_MENU;
      }
      break;

    case PQC_STATUS:
      lastActivityMs = millis();
      if (cancelPressed) {
        pqcScrollOffset = (pqcScrollOffset + 1) % PQC_LINE_COUNT;
      } else if (confirmPressed) {
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

    case TX_FEE_REVIEW: {
      if (cancelPressed) {
        txMetaPage++;
        bool has_locktime = (txReviewPsbt.locktime != 0);
        uint8_t maxPage = 1 + (has_locktime ? 1u : 0u) + (uint8_t)txReviewPsbt.input_count;
        if (txMetaPage >= maxPage) {
          if (psbtFromUsb) {
            serial_send_rejected();
          }
          psbtFromUsb = false;
          currentState = MAIN_MENU;
        }
      } else if (confirmPressed) {
        if (txNonChangeOutputCount > 0) {
          txReviewOutputIdx = 0;
          build_output_address(&txReviewPsbt.outputs[txNonChangeIndices[0]],
                               txReviewAddressBuf, sizeof(txReviewAddressBuf));
          if (txHasRBF) {
            currentState = TX_RBF_CONFIRM;
          } else {
            currentState = TX_OUTPUT_REVIEW;
          }
        } else {
          initTransactionReview();
        }
      }
      break;
    }

    case TX_RBF_CONFIRM:
      if (cancelPressed) {
        if (psbtFromUsb) {
          serial_send_rejected();
        }
        psbtFromUsb = false;
        currentState = MAIN_MENU;
      } else if (confirmPressed) {
        currentState = TX_OUTPUT_REVIEW;
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
        balance_nvs_erase();
        tx_history_nvs_erase();
        currentState = WALLET_WIPED;
        lastActivityMs = millis();
      } else if (cancelPressed) {
        currentState = SETTINGS_MENU;
      }
      break;

    case TX_HISTORY:
      lastActivityMs = millis();
      if (txHistoryFetchDone) {
        if (cancelPressed) {
          uint8_t count = tx_history_get_count();
          if (count > 1) {
            txHistoryScrollIdx = (txHistoryScrollIdx + 1) % count;
          }
        } else if (confirmPressed) {
          currentState = MAIN_MENU;
        }
      }
      break;

    case WATCHDOG_RECOVERY:
      if (confirmPressed || cancelPressed) {
        if (!seAvailable) {
          currentState = SE_ERROR;
        } else {
          currentState = PIN_ENTRY;
          pinDigits[0] = 0; pinDigits[1] = 0; pinDigits[2] = 0;
          pinDigits[3] = 0; pinDigits[4] = 0; pinDigits[5] = 0;
          pinPosition = 0;
          pinDigitValue = 0;
          pinAttempts = pin_get_attempts();
        }
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
            txMetaPage = 0;
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
    case SE_ERROR:
      display.setCursor(0, 0);
      display.setTextSize(1);
      display.println("!! SE COMM FAILURE !!");
      display.println("---------------------");
      display.setCursor(0, 18);
      display.setTextSize(2);
      display.println("SE FAULT");
      display.setTextSize(1);
      display.setCursor(0, 40);
      display.print("Err: 0x");
      display.println(seInitErr, HEX);
      display.setCursor(0, 50);
      display.print("Press any key: retry");
      display.setCursor(0, 58);
      display.print("Power cycle if stuck");
      break;

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

    case BIP39_PREDICTIVE_INPUT: {
      // Title and progress
      display.setCursor(0, 0);
      if (predictiveIsVerify) {
        display.println("VERIFY SEED");
        display.println("---------------------");
        display.setCursor(0, 18);
        display.print("Step ");
        display.print(mnemonicVerifyStep + 1);
        display.print(" of 3");
        display.setCursor(0, 28);
        display.print("Word #");
        display.print(mnemonicVerifyIndices[mnemonicVerifyStep] + 1);
        display.print("?");
      } else {
        display.println("RESTORE WALLET");
        display.println("---------------------");
        display.setCursor(0, 18);
        display.print("Word ");
        display.print(restoreWordIdx + 1);
        display.print(" of 24");
      }

      // Prefix display line
      display.setCursor(0, 36);
      if (predictivePrefixLen == 0 && predictiveLetter == 'a') {
        display.print("_");
      } else {
        display.print(predictivePrefix);
        if (predictiveLetter == '<') {
          display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
          display.print("< DEL");
          display.setTextColor(SSD1306_WHITE);
        } else {
          display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
          display.print(predictiveLetter);
          display.setTextColor(SSD1306_WHITE);
        }
        uint8_t visible = predictivePrefixLen + 1;
        for (uint8_t i = visible; i < 4; i++) {
          display.print('_');
        }
      }

      // Candidate words display
      display.setCursor(0, 48);
      if (predictiveMatchCount > 0) {
        for (uint8_t i = 0; i < predictiveMatchCount && i < 3; i++) {
          if (predictiveSelectMode && i == predictiveHighlight) {
            display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
            display.print(bip39_wordlist[predictiveMatchIndices[i]]);
            display.setTextColor(SSD1306_WHITE);
          } else {
            display.print(bip39_wordlist[predictiveMatchIndices[i]]);
          }
          if (i + 1 < predictiveMatchCount && i < 2) display.print(" ");
        }
        if (predictiveTotalCount > 3) {
          display.print(" ...");
        }
      } else if (predictivePrefixLen > 0 || predictiveLetter != 'a') {
        display.print("(no matches)");
      }

      // Footer
      display.setCursor(0, 56);
      if (predictiveSelectMode) {
        display.print("CONFIRM=select CANCEL=next");
      } else {
        display.print("CANCEL=letter CONFIRM=select");
      }
      break;
    }

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
      if (!balanceFetchDone) {
        display.setCursor(0, 25);
        display.println("Fetching...");
      } else if (balanceResponsesReceived == 0 && !balanceUsingCache) {
        display.setCursor(0, 25);
        display.println("No balance data");
        display.setCursor(0, 40);
        display.println("Connect companion app");
      }
#ifdef MOCK_DATA
      else if (balanceResponsesReceived == 0 && !balanceUsingCache) {
        display.setCursor(0, 20);
        display.setTextSize(2);
        display.print("0.42050");
        display.setTextSize(1);
        display.println(" BTC");
        display.setCursor(0, 42);
        display.println("Sats: 42,050,000");
      }
#endif
      else {
        display.setCursor(0, 20);
        display.setTextSize(2);
        char btcBuf[24];
        format_btc(balanceConfirmed, btcBuf, sizeof(btcBuf));
        display.print(btcBuf);
        display.setTextSize(1);
        display.println(" BTC");
        display.setCursor(0, 42);
        char satsBuf[32];
        format_sats(balanceConfirmed, satsBuf, sizeof(satsBuf));
        display.print("Sats: ");
        display.println(satsBuf);
        if (balanceUnconfirmed > 0) {
          display.setCursor(0, 50);
          display.print("+ ");
          char unconBuf[24];
          format_sats(balanceUnconfirmed, unconBuf, sizeof(unconBuf));
          display.print(unconBuf);
          display.println(" unconf.");
        }
      }
      if (balanceFetchDone) {
        display.setCursor(0, 56);
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        if (balanceUsingCache) {
          display.print(" [BACK] (cached) ");
        } else {
          display.print(" [BACK] ");
        }
      }
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
      if (txMetaPage == 0) {
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
        display.print("CANCEL=details CONFIRM=next");
      } else {
        bool has_locktime = (txReviewPsbt.locktime != 0);
        uint8_t metaOff = txMetaPage - 1;
        uint8_t maxPage = 1 + (has_locktime ? 1u : 0u) + (uint8_t)txReviewPsbt.input_count;
        bool is_last = (txMetaPage + 1 >= maxPage);
        if (has_locktime && metaOff == 0) {
          display.setCursor(0, 0);
          display.println("LOCKTIME DETAIL");
          display.println("---------------------");
          display.setCursor(0, 24);
          char lt_buf[32];
          format_locktime(txReviewPsbt.locktime, lt_buf, sizeof(lt_buf));
          display.println(lt_buf);
          display.setCursor(0, 56);
          display.print(is_last ? "CANCEL=menu CONFIRM=next" : "CANCEL=next CONFIRM=next");
        } else {
          uint8_t inputIdx = has_locktime ? (metaOff - 1) : metaOff;
          display.setCursor(0, 0);
          display.print("INPUT ");
          display.print(inputIdx + 1);
          display.print("/");
          display.println((unsigned)txReviewPsbt.input_count);
          display.println("---------------------");
          display.setCursor(0, 20);
          if (txReviewPsbt.inputs[inputIdx].is_multisig) {
            display.print("MULTISIG ");
            display.print(txReviewPsbt.inputs[inputIdx].multisig_m);
            display.print("-of-");
            display.println(txReviewPsbt.inputs[inputIdx].multisig_n);
            display.setCursor(0, 32);
            display.print("Sigs: ");
            display.print(txReviewPsbt.inputs[inputIdx].multisig_existing_sigs);
            display.print("/");
            display.println(txReviewPsbt.inputs[inputIdx].multisig_m);
          } else {
            display.print("Sig: ");
            display.println(get_input_segwit_label(&txReviewPsbt.inputs[inputIdx]));
          }
          display.setCursor(0, 44);
          display.print("Seq: 0x");
          display.println(txReviewPsbt.inputs[inputIdx].sequence, HEX);
        display.setCursor(0, 56);
        display.print(is_last ? "CANCEL=menu CONFIRM=next" : "CANCEL=next CONFIRM=next");
        }
      }
      break;

    case TX_RBF_CONFIRM:
      display.setCursor(0, 0);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.println("  RBF ENABLED  ");
      display.setTextColor(SSD1306_WHITE);
      display.println("---------------------");
      display.setCursor(0, 22);
      display.println("Tx can be replaced");
      display.println("by another tx with");
      display.println("higher fee.");
      display.println("");
      display.print("Continue?");
      display.setCursor(0, 56);
      display.print("CANCEL=No CONFIRM=Yes");
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
      {
        uint8_t visibleLines = 5;
        for (uint8_t i = 0; i < visibleLines; i++) {
          uint8_t li = (pqcScrollOffset + i) % PQC_LINE_COUNT;
          display.setCursor(0, 18 + i * 8);
          display.println(pqcLines[li]);
        }
      }
      display.setCursor(0, 56);
      display.print("CANCEL=scroll   CONFIRM=back");
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
      if (txSignError == PSBT_SIGN_ERR_NO_PARTICIPANT) {
        display.println("No inputs to sign -");
        display.println("not a participant");
        display.println("in any input.");
      } else {
        display.print("SE error: ");
        display.println(txSignError);
        display.println("No PSBT returned.");
      }
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

    case ACCOUNT_RENAME: {
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
      } break;

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

    case SETTINGS_CONTRAST: {
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
      } break;

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

    case TX_HISTORY:
      display.setCursor(0, 0);
      display.println("TX HISTORY");
      display.println("---------------------");
      if (!txHistoryFetchDone) {
        display.setCursor(0, 25);
        display.println("Fetching...");
      } else if (!txHistoryUsingCache && tx_history_get_count() == 0) {
        display.setCursor(0, 25);
        display.println("No transaction data");
        display.setCursor(0, 40);
        display.println("Connect companion app");
      } else {
        tx_history_entry_t entry;
        uint8_t count = tx_history_get_count();
        if (count > 0 && tx_history_get_entry(txHistoryScrollIdx, &entry)) {
          display.setCursor(0, 20);
          if (entry.direction == '+') {
            display.println("RECEIVED");
          } else {
            display.println("SENT");
          }
          display.setCursor(0, 28);
          char btcBuf[24];
          format_btc(entry.amount_sats, btcBuf, sizeof(btcBuf));
          display.print(btcBuf);
          display.println(" BTC");
          display.setCursor(0, 36);
          for (int i = 0; i < 4; i++) {
            if (entry.txid[i] < 0x10) display.print('0');
            display.print(entry.txid[i], HEX);
          }
          display.print("...");
          for (int i = 28; i < 32; i++) {
            if (entry.txid[i] < 0x10) display.print('0');
            display.print(entry.txid[i], HEX);
          }
          display.setCursor(0, 44);
          if (entry.confirmations == 0) {
            display.println("UNCONFIRMED");
          } else if (entry.confirmations >= 100) {
            display.println("100+ confirmations");
          } else {
            display.print(entry.confirmations);
            display.println(" confirmations");
          }
        }
      }
      if (txHistoryFetchDone) {
        display.setCursor(0, 56);
        display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
        uint8_t count = tx_history_get_count();
        if (txHistoryUsingCache) {
          display.print(" [BACK] (cached) ");
        } else if (count > 1 && tx_history_get_count() > 0) {
          char footer[22];
          snprintf(footer, sizeof(footer), " %u/%u BACK=CONFIRM ",
                   (unsigned)(txHistoryScrollIdx + 1), (unsigned)count);
          display.print(footer);
        } else {
          display.print(" [BACK] ");
        }
        display.setTextColor(SSD1306_WHITE);
      }
      break;

    case WATCHDOG_RECOVERY:
      display.setCursor(0, 0);
      display.println("DEVICE RECOVERED");
      display.println("---------------------");
      display.setCursor(0, 24);
      display.println("Unexpected restart.");
      display.setCursor(0, 36);
      if (!seAvailable) {
        display.println("SE offline.");
        display.println("Press any key.");
      } else {
        display.println("Re-enter PIN to");
        display.println("continue.");
      }
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
    // SE failed to produce entropy mid-operation (passed init but failed
    // during the actual GET_RND command).  WALLET_WIPED is wrong here —
    // nothing was erased — so route to SE_ERROR instead so the standard
    // "press any button to retry" recovery path handles it cleanly.
    seInitErr = se051_init();          // attempt a soft re-init
    seAvailable = (seInitErr == SE_OK);
    currentState = SE_ERROR;
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
      if (seAvailable && se051_get_random(&rnd, 1) == SE_OK) {
        rnd = rnd % 24;
      } else {
        rnd = (uint8_t)(esp_random() % 24);
      }
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

  // US-032: use predictive BIP39 keyboard for verification word selection
  predictivePrefixLen = 0;
  predictivePrefix[0] = '\0';
  predictiveLetter = 'a';
  predictiveSelectMode = false;
  predictiveHighlight = 0;
  predictiveIsVerify = true;
  updatePredictiveMatches();
  currentState = BIP39_PREDICTIVE_INPUT;
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

// --- PREDICTIVE BIP39 KEYBOARD HELPERS (US-032) ---
void updatePredictiveMatches() {
  char search[6];
  uint8_t len = predictivePrefixLen;
  memcpy(search, predictivePrefix, len);

  if (predictiveLetter != '<') {
    search[len] = predictiveLetter;
    search[len + 1] = '\0';
  } else {
    search[len] = '\0';
  }

  predictiveMatchCount = bip39_prefix_match(search, predictiveMatchIndices, 3);
  predictiveTotalCount = bip39_find_prefix(search, NULL);
}

void predictiveWordSelected(uint16_t selectedIdx) {
  if (predictiveIsVerify) {
    uint8_t pos = mnemonicVerifyIndices[mnemonicVerifyStep];
    if (strcmp(bip39_wordlist[selectedIdx], mnemonicWords[pos]) == 0) {
      mnemonicVerifyStep++;
      if (mnemonicVerifyStep >= 3) {
        passphraseIsNewWallet = true;
        menuIndex = 0;
        currentState = PASSPHRASE_PROMPT;
        return;
      }
    } else {
      mnemonicWordIndex = 0;
      mnemonicVerifyStep = 0;
      currentState = MNEMONIC_DISPLAY;
      return;
    }
  } else {
    strncpy(restoreWords[restoreWordIdx], bip39_wordlist[selectedIdx], 9);
    restoreWords[restoreWordIdx][8] = '\0';
    restoreWordIdx++;

    if (restoreWordIdx >= 24) {
      if (bip39_validate(restoreWords)) {
        currentState = RESTORE_PASSPHRASE;
        menuIndex = 0;
        return;
      } else {
        strncpy(restoreError, "Bad checksum - retry", 32);
        restoreStartTime = millis();
        currentState = RESTORE_ERROR;
        return;
      }
    }
  }

  predictivePrefixLen = 0;
  predictivePrefix[0] = '\0';
  predictiveLetter = 'a';
  predictiveSelectMode = false;
  predictiveHighlight = 0;
  updatePredictiveMatches();
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
  restoreStartTime = millis();
  restoreError[0] = '\0';
  restorePassphrase = false;

  predictivePrefixLen = 0;
  predictivePrefix[0] = '\0';
  predictiveLetter = 'a';
  predictiveSelectMode = false;
  predictiveHighlight = 0;
  predictiveIsVerify = false;
  updatePredictiveMatches();
  currentState = BIP39_PREDICTIVE_INPUT;
}

void updateAddressDisplay() {
  address_type_t type = (address_type_t)addressTypeIdx;
  uint32_t acct = account_get_active();
  if (!address_generate(type, acct, addressIndex, currentAddressStr)) {
    strncpy(currentAddressStr, "Address gen error", MAX_ADDRESS_LEN);
  }
}
