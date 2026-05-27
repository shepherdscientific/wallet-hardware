#ifdef USE_TERNARYCORE_SE

#include "se051_hal.h"
#include <Arduino.h>

// ─── TernaryCore SE — UART HAL (Phase 1: boot-probe + stub) ──────────────
//
// The TernaryCore Secure Element (Tang Nano 9K / GW1NR-9) communicates over
// a UART at 115200 8N1.  On Phase 1 the FPGA only emits a boot banner:
//
//   "TernaryCore-SE booting...\r\n"
//
// No AT-command protocol exists yet (defined in Phase 2 once the full crypto
// stack — AES-256-GCM, SHA-3, Kyber-768 — is implemented in RTL).
//
// This HAL therefore:
//   • Opens Serial1 on TC_SE_UART_TX_PIN / TC_SE_UART_RX_PIN
//   • Attempts to observe the boot banner to confirm the link is alive
//   • Returns SE_OK from se051_init() so the wallet can run in degraded mode
//   • Returns SE_ERR_NOTFOUND from all crypto operations (Phase 2 placeholder)
//
// When Phase 2 lands, replace the SE_ERR_NOTFOUND stubs with:
//   tc_cmd("AT+RAND\n",   "OK:", TC_SE_UART_TIMEOUT_MS)   → get_random
//   tc_cmd("AT+PUBKEY\n", "PUB:", TC_SE_SIGN_TIMEOUT_MS)  → get_pubkey
//   tc_cmd("AT+SIGN\n",   "SIG:", TC_SE_SIGN_TIMEOUT_MS)  → ecdsa_sign
//   etc.

static bool g_tc_ready = false;

// ─── UART helpers ─────────────────────────────────────────────────────────

// Drain Serial1 and look for a line containing `token` within `timeout_ms`.
// Returns true if found.
static bool tc_wait_for(const char *token, uint32_t timeout_ms) {
  uint32_t deadline = millis() + timeout_ms;
  String line;
  line.reserve(64);

  while (millis() < deadline) {
    while (Serial1.available()) {
      char c = (char)Serial1.read();
      if (c == '\n') {
        if (line.indexOf(token) >= 0) return true;
        line = "";
      } else if (c != '\r') {
        line += c;
      }
    }
    delay(1);
  }
  return false;
}

// ─── Public HAL implementation ────────────────────────────────────────────

se051_err_t se051_init(void) {
  // ESP32-S3 Serial1 constructor: (baud, config, RX_pin, TX_pin)
  Serial1.begin(TC_SE_UART_BAUD, SERIAL_8N1,
                TC_SE_UART_RX_PIN, TC_SE_UART_TX_PIN);
  delay(100);  // line settle

  // Flush any stale data from a prior session.
  while (Serial1.available()) Serial1.read();

  // Wait for TernaryCore boot banner.  If the FPGA was already running before
  // this init (e.g. no hardware reset), no banner will appear — that is normal.
  bool banner = tc_wait_for("TernaryCore-SE", TC_SE_UART_TIMEOUT_MS);

#ifdef DEV_BUILD
  if (banner) {
    Serial.println("[TC-SE] init OK — boot banner received");
  } else {
    Serial.println("[TC-SE] init OK — no banner seen (FPGA may already be running)");
  }
  Serial.printf("[TC-SE] UART: baud=%u TX=GPIO%d RX=GPIO%d\n",
                (unsigned)TC_SE_UART_BAUD,
                (int)TC_SE_UART_TX_PIN,
                (int)TC_SE_UART_RX_PIN);
#else
  (void)banner;
#endif

  g_tc_ready = true;
  return SE_OK;
}

// ─── Phase 2 stubs ───────────────────────────────────────────────────────
// All crypto operations require the Phase 2 AT-command protocol.

se051_err_t se051_get_random(uint8_t *buf, size_t len) {
  (void)buf; (void)len;
  // Phase 2: AT+RAND:<len>\n → RND:<hex>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_ecdsa_sign(uint8_t key_id,
                              const uint8_t hash[SE051_HASH_LEN],
                              uint8_t sig_out[SE051_ECDSA_MAX_DER_LEN],
                              size_t *sig_len) {
  (void)key_id; (void)hash; (void)sig_out; (void)sig_len;
  // Phase 2: AT+SIGN:ECDSA:<slot>:<hash_hex>\n → SIG:<der_hex>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_schnorr_sign(uint8_t key_id,
                                const uint8_t hash[SE051_HASH_LEN],
                                uint8_t sig_out[SE051_SCHNORR_SIG_LEN]) {
  (void)key_id; (void)hash; (void)sig_out;
  // Phase 3: Kyber-based post-quantum signing
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_store_key(uint8_t key_id,
                             const uint8_t *key_material,
                             size_t key_len) {
  (void)key_id; (void)key_material; (void)key_len;
  // Phase 2: AT+STORE:<slot>:<key_hex>\n → OK\n / ERR:<n>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_delete_key(uint8_t key_id) {
  (void)key_id;
  // Phase 2: AT+DEL:<slot>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_get_pubkey(uint8_t key_id,
                              uint8_t pubkey_out[SE051_PUBKEY_COMPRESSED]) {
  (void)key_id; (void)pubkey_out;
  // Phase 2: AT+PUBKEY:<slot>\n → PUB:<compressed_hex>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_selftest(void) {
  if (!g_tc_ready) return SE_ERR_COMM;
  // Phase 2: AT+TEST\n → OK\n
  // For Phase 1, a successful se051_init() is the only available health check.
  return SE_OK;
}

se051_err_t se051_get_serial(char *buf, size_t buf_len) {
  if (!buf || buf_len == 0) return SE_ERR_PARAM;
  // Phase 2: AT+INFO\n → INFO:<serial>:<fw_ver>\n
  snprintf(buf, buf_len, "TernaryCore-SE-Phase1");
  return SE_OK;
}

se051_err_t se051_read_object(uint8_t obj_id,
                               uint8_t *buf, size_t buf_len,
                               size_t *out_len) {
  (void)obj_id; (void)buf; (void)buf_len; (void)out_len;
  // Phase 2: AT+READ:<obj_id>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_monotonic_counter_get(uint8_t counter_id,
                                         uint32_t *value) {
  (void)counter_id;
  if (value) *value = 0;
  // Phase 2: AT+CTR:GET:<id>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_monotonic_counter_increment(uint8_t counter_id) {
  (void)counter_id;
  // Phase 2: AT+CTR:INC:<id>\n
  return SE_ERR_NOTFOUND;
}

se051_err_t se051_monotonic_counter_reset(uint8_t counter_id) {
  (void)counter_id;
  // Phase 2: AT+CTR:RST:<id>\n
  return SE_ERR_NOTFOUND;
}

#endif // USE_TERNARYCORE_SE
