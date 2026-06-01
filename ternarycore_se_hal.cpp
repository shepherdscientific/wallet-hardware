#ifdef USE_TERNARYCORE_SE

#include "se051_hal.h"

// ─── TernaryCore SE — UART HAL ────────────────────────────────────────────
//
// The TernaryCore Secure Element (Tang Nano 9K / GW1NR-9) communicates over
// a UART at 115200 8N1 using an AT-command protocol:
//
//   Command                           → Response
//   ────────────                      → ────────────
//   AT+RAND:<len>\n                   → RND:<hex>\n
//   AT+SIGN:ECDSA:<slot>:<hash>\n     → SIG:<der_hex>\n
//   AT+SIGN:SCHNORR:<slot>:<hash>\n   → SIG:<hex>\n        (Phase 3: Kyber PQC)
//   AT+STORE:<slot>:<key_hex>\n       → OK\n / ERR:<n>\n
//   AT+DEL:<slot>\n                   → OK\n / ERR:<n>\n
//   AT+PUBKEY:<slot>\n                → PUB:<compressed_hex>\n
//   AT+TEST\n                         → OK\n / ERR:<n>\n
//   AT+INFO\n                         → INFO:<serial>:<fw_ver>\n
//   AT+READ:<obj_id>\n                → DATA:<hex>\n / ERR:<n>\n
//   AT+CTR:GET:<id>\n                 → CTR:<value>\n / ERR:<n>\n
//   AT+CTR:INC:<id>\n                 → OK\n / ERR:<n>\n
//   AT+CTR:RST:<id>\n                 → OK\n / ERR:<n>\n
//
// FPGA error codes mapped to se051_err_t:
//   ERR:1 → SE_ERR_PARAM, ERR:2 → SE_ERR_AUTH, ERR:3 → SE_ERR_LOCKED,
//   ERR:5 → SE_ERR_NOTFOUND, ERR:6 → SE_ERR_MEMORY, other → SE_ERR_INTERNAL
//

// ─── Platform Abstraction (UART + timing) ──────────────────────────────────
#if defined(ARDUINO) && defined(ESP32)

#include <Arduino.h>

static void tc_uart_begin(int baud, int config, int rx, int tx) {
  Serial1.begin((unsigned long)baud, (uint32_t)config, rx, tx);
}
static void tc_uart_flush(void) {
  while (Serial1.available()) (void)Serial1.read();
}
static int tc_uart_available(void) { return Serial1.available(); }
static char tc_uart_read(void) { return (char)Serial1.read(); }
static void tc_uart_write(const char *s) { Serial1.print(s); }
static uint32_t tc_millis(void) { return millis(); }
static void tc_delay_ms(uint32_t ms) { delay(ms); }

#else
// ─── Host mock (test_ternarycore_se.cpp) ───────────────────────────────────

#ifndef SERIAL_8N1
#define SERIAL_8N1 0
#endif

#include <cstring>
#include <cstdio>
#include <cstdlib>

static char g_mock_rx[4096];
static size_t g_mock_rx_pos = 0;
static size_t g_mock_rx_len = 0;
static char g_mock_tx[4096];
static size_t g_mock_tx_len = 0;
static uint32_t g_mock_millis = 0;

void tc_mock_reset(void) {
  g_mock_rx_pos = 0;
  g_mock_rx_len = 0;
  g_mock_tx_len = 0;
  g_mock_millis = 0;
  memset(g_mock_rx, 0, sizeof(g_mock_rx));
  memset(g_mock_tx, 0, sizeof(g_mock_tx));
}
void tc_mock_feed(const char *data) {
  size_t len = strlen(data);
  if (len >= sizeof(g_mock_rx)) len = sizeof(g_mock_rx) - 1;
  memcpy(g_mock_rx, data, len);
  g_mock_rx[len] = '\0';
  g_mock_rx_len = len;
  g_mock_rx_pos = 0;
}
const char *tc_mock_sent(void) { return g_mock_tx; }
void tc_mock_advance_ms(uint32_t ms) { g_mock_millis += ms; }

static void tc_uart_begin(int baud, int config, int rx, int tx) {
  (void)baud; (void)config; (void)rx; (void)tx;
}
static void tc_uart_flush(void) {
  g_mock_rx_pos = 0;
  g_mock_rx_len = 0;
}
static int tc_uart_available(void) {
  return (int)(g_mock_rx_len - g_mock_rx_pos);
}
static char tc_uart_read(void) {
  return g_mock_rx[g_mock_rx_pos++];
}
static void tc_uart_write(const char *s) {
  size_t len = strlen(s);
  if (g_mock_tx_len + len < sizeof(g_mock_tx) - 1) {
    memcpy(g_mock_tx + g_mock_tx_len, s, len);
    g_mock_tx_len += len;
    g_mock_tx[g_mock_tx_len] = '\0';
  }
}
static uint32_t tc_millis(void) { return g_mock_millis; }
static void tc_delay_ms(uint32_t ms) { g_mock_millis += ms; }
#endif

// ─── Internal state ────────────────────────────────────────────────────────

static bool g_tc_ready = false;

// ─── Hex helpers ───────────────────────────────────────────────────────────

static size_t tc_hex_decode(uint8_t *out, size_t out_cap, const char *hex) {
  size_t count = 0;
  const char *p = hex;
  while (*p && count < out_cap) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    char hi = *p++;
    if (!*p) break;
    char lo = *p++;

    auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };

    int h = nibble(hi);
    int l = nibble(lo);
    if (h < 0 || l < 0) return count;
    out[count++] = (uint8_t)((h << 4) | l);
  }
  return count;
}

static void tc_hex_encode(char *out, size_t out_cap,
                          const uint8_t *in, size_t len) {
  size_t pos = 0;
  for (size_t i = 0; i < len && pos + 2 < out_cap; i++) {
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%02x", in[i]);
  }
  if (pos < out_cap) out[pos] = '\0';
}

// ─── UART command/response engine ──────────────────────────────────────────

static bool tc_wait_for(const char *token, uint32_t timeout_ms) {
  uint32_t deadline = tc_millis() + timeout_ms;
  char line[256];
  size_t pos = 0;

  while (tc_millis() < deadline) {
    while (tc_uart_available() > 0) {
      char c = tc_uart_read();
      if (c == '\n') {
        line[pos] = '\0';
        if (strstr(line, token) != NULL) return true;
        pos = 0;
      } else if (c != '\r' && pos < sizeof(line) - 1) {
        line[pos++] = c;
      }
    }
    tc_delay_ms(1);
  }
  return false;
}

static se051_err_t tc_cmd(const char *cmd, const char *prefix,
                           char *data_out, size_t data_cap,
                           uint32_t timeout_ms) {
  tc_uart_write(cmd);

  uint32_t deadline = tc_millis() + timeout_ms;
  char line[256];
  size_t pos = 0;
  size_t prefix_len = strlen(prefix);

  while (tc_millis() < deadline) {
    while (tc_uart_available() > 0) {
      char c = tc_uart_read();
      if (c == '\n') {
        line[pos] = '\0';
        pos = 0;

        if (strncmp(line, "ERR:", 4) == 0) {
          if (data_out && data_cap > 0) data_out[0] = '\0';
          int code = atoi(line + 4);
          switch (code) {
            case 1: return SE_ERR_PARAM;
            case 2: return SE_ERR_AUTH;
            case 3: return SE_ERR_LOCKED;
            case 5: return SE_ERR_NOTFOUND;
            case 6: return SE_ERR_MEMORY;
            default: return SE_ERR_INTERNAL;
          }
        }

        if (strncmp(line, prefix, prefix_len) == 0) {
          const char *data = line + prefix_len;
          if (data_out) {
            strncpy(data_out, data, data_cap - 1);
            data_out[data_cap - 1] = '\0';
          }
          return SE_OK;
        }
      } else if (c != '\r' && pos < sizeof(line) - 1) {
        line[pos++] = c;
      }
    }
    tc_delay_ms(1);
  }

  if (data_out && data_cap > 0) data_out[0] = '\0';
  return SE_ERR_NOTFOUND;
}

// ─── Public HAL implementation ────────────────────────────────────────────

se051_err_t se051_init(void) {
  tc_uart_begin(TC_SE_UART_BAUD, SERIAL_8N1,
                TC_SE_UART_RX_PIN, TC_SE_UART_TX_PIN);
  tc_delay_ms(500);  // let FPGA boot if it just powered up
  tc_uart_flush();

  // Active probe: send AT+INFO to confirm FPGA is alive.
  // Uses the structured response protocol instead of waiting for
  // a one-shot boot banner (which may have already been sent).
  char info[128];
  se051_err_t err = tc_cmd("AT+INFO\n", "INFO:", info, sizeof(info),
                           TC_SE_UART_TIMEOUT_MS);

#if defined(ARDUINO) && defined(ESP32) && defined(DEV_BUILD)
  if (err == SE_OK) {
    Serial.printf("[TC-SE] init OK — INFO:%s\n", info);
  } else {
    Serial.printf("[TC-SE] init FAIL — no response (err=%d)\n", (int)err);
  }
  Serial.printf("[TC-SE] UART: baud=%u TX=GPIO%d RX=GPIO%d\n",
                (unsigned)TC_SE_UART_BAUD,
                (int)TC_SE_UART_TX_PIN,
                (int)TC_SE_UART_RX_PIN);
#endif

  g_tc_ready = (err == SE_OK);
  return err;
}

se051_err_t se051_get_random(uint8_t *buf, size_t len) {
  if (!buf || len == 0 || len > SE051_RANDOM_LEN) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+RAND:%u\n", (unsigned)len);

  char hex[SE051_RANDOM_LEN * 2 + 1];
  se051_err_t err = tc_cmd(cmd, "RND:", hex, sizeof(hex),
                           TC_SE_UART_TIMEOUT_MS);
  if (err != SE_OK) return err;

  size_t decoded = tc_hex_decode(buf, len, hex);
  return (decoded == len) ? SE_OK : SE_ERR_INTERNAL;
}

se051_err_t se051_ecdsa_sign(uint8_t key_id,
                             const uint8_t hash[SE051_HASH_LEN],
                             uint8_t sig_out[SE051_ECDSA_MAX_DER_LEN],
                             size_t *sig_len) {
  if (!hash || !sig_out || !sig_len) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;

  char hash_hex[SE051_HASH_LEN * 2 + 1];
  tc_hex_encode(hash_hex, sizeof(hash_hex), hash, SE051_HASH_LEN);

  char cmd[128];
  snprintf(cmd, sizeof(cmd), "AT+SIGN:ECDSA:%u:%s\n",
           (unsigned)key_id, hash_hex);

  char hex[SE051_ECDSA_MAX_DER_LEN * 2 + 1];
  se051_err_t err = tc_cmd(cmd, "SIG:", hex, sizeof(hex),
                           TC_SE_SIGN_TIMEOUT_MS);
  if (err != SE_OK) return err;

  size_t decoded = tc_hex_decode(sig_out, SE051_ECDSA_MAX_DER_LEN, hex);
  if (decoded == 0) return SE_ERR_INTERNAL;
  *sig_len = decoded;
  return SE_OK;
}

se051_err_t se051_schnorr_sign(uint8_t key_id,
                               const uint8_t hash[SE051_HASH_LEN],
                               uint8_t sig_out[SE051_SCHNORR_SIG_LEN]) {
  if (!hash || !sig_out) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;

  char hash_hex[SE051_HASH_LEN * 2 + 1];
  tc_hex_encode(hash_hex, sizeof(hash_hex), hash, SE051_HASH_LEN);

  char cmd[128];
  snprintf(cmd, sizeof(cmd), "AT+SIGN:SCHNORR:%u:%s\n",
           (unsigned)key_id, hash_hex);

  char hex[SE051_SCHNORR_SIG_LEN * 2 + 1];
  se051_err_t err = tc_cmd(cmd, "SIG:", hex, sizeof(hex),
                           TC_SE_SIGN_TIMEOUT_MS);
  if (err != SE_OK) return err;

  size_t decoded = tc_hex_decode(sig_out, SE051_SCHNORR_SIG_LEN, hex);
  return (decoded == SE051_SCHNORR_SIG_LEN) ? SE_OK : SE_ERR_INTERNAL;
}

se051_err_t se051_store_key(uint8_t key_id,
                            const uint8_t *key_material,
                            size_t key_len) {
  if (!key_material || key_len == 0) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;

  char key_hex[256 * 2 + 1];
  size_t hex_max = sizeof(key_hex) / 2;
  if (key_len > hex_max) return SE_ERR_PARAM;
  tc_hex_encode(key_hex, sizeof(key_hex), key_material, key_len);

  char cmd[640];
  snprintf(cmd, sizeof(cmd), "AT+STORE:%u:%s\n",
           (unsigned)key_id, key_hex);

  char dummy[4];
  return tc_cmd(cmd, "OK", dummy, sizeof(dummy), TC_SE_SIGN_TIMEOUT_MS);
}

se051_err_t se051_delete_key(uint8_t key_id) {
  if (!g_tc_ready) return SE_ERR_COMM;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+DEL:%u\n", (unsigned)key_id);

  char dummy[4];
  return tc_cmd(cmd, "OK", dummy, sizeof(dummy), TC_SE_UART_TIMEOUT_MS);
}

se051_err_t se051_get_pubkey(uint8_t key_id,
                             uint8_t pubkey_out[SE051_PUBKEY_COMPRESSED]) {
  if (!pubkey_out) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+PUBKEY:%u\n", (unsigned)key_id);

  char hex[SE051_PUBKEY_COMPRESSED * 2 + 1];
  se051_err_t err = tc_cmd(cmd, "PUB:", hex, sizeof(hex),
                           TC_SE_SIGN_TIMEOUT_MS);
  if (err != SE_OK) return err;

  size_t decoded = tc_hex_decode(pubkey_out, SE051_PUBKEY_COMPRESSED, hex);
  return (decoded == SE051_PUBKEY_COMPRESSED) ? SE_OK : SE_ERR_INTERNAL;
}

se051_err_t se051_selftest(void) {
  if (!g_tc_ready) return SE_ERR_COMM;

  char dummy[4];
  se051_err_t err = tc_cmd("AT+TEST\n", "OK", dummy, sizeof(dummy),
                           TC_SE_UART_TIMEOUT_MS);
  if (err != SE_OK) return err;
  return SE_OK;
}

se051_err_t se051_get_serial(char *buf, size_t buf_len) {
  if (!buf || buf_len == 0) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;

  char info[128];
  se051_err_t err = tc_cmd("AT+INFO\n", "INFO:", info, sizeof(info),
                           TC_SE_UART_TIMEOUT_MS);
  if (err != SE_OK) {
    snprintf(buf, buf_len, "TernaryCore-SE");
    return err;
  }

  const char *colon = strchr(info, ':');
  if (colon) {
    size_t serial_len = (size_t)(colon - info);
    size_t copy = (serial_len < buf_len - 1) ? serial_len : buf_len - 1;
    memcpy(buf, info, copy);
    buf[copy] = '\0';
  } else {
    strncpy(buf, info, buf_len - 1);
    buf[buf_len - 1] = '\0';
  }
  return SE_OK;
}

se051_err_t se051_read_object(uint8_t obj_id,
                              uint8_t *buf, size_t buf_len,
                              size_t *out_len) {
  if (!buf || buf_len == 0 || !out_len) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;
  *out_len = 0;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+READ:%u\n", (unsigned)obj_id);

  char hex[512];
  se051_err_t err = tc_cmd(cmd, "DATA:", hex, sizeof(hex),
                           TC_SE_UART_TIMEOUT_MS);
  if (err != SE_OK) return err;

  *out_len = tc_hex_decode(buf, buf_len, hex);
  return (*out_len > 0) ? SE_OK : SE_ERR_INTERNAL;
}

se051_err_t se051_monotonic_counter_get(uint8_t counter_id,
                                        uint32_t *value) {
  if (!value) return SE_ERR_PARAM;
  if (!g_tc_ready) return SE_ERR_COMM;
  *value = 0;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+CTR:GET:%u\n", (unsigned)counter_id);

  char ctr_str[16];
  se051_err_t err = tc_cmd(cmd, "CTR:", ctr_str, sizeof(ctr_str),
                           TC_SE_UART_TIMEOUT_MS);
  if (err != SE_OK) return err;

  *value = (uint32_t)atol(ctr_str);
  return SE_OK;
}

se051_err_t se051_monotonic_counter_increment(uint8_t counter_id) {
  if (!g_tc_ready) return SE_ERR_COMM;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+CTR:INC:%u\n", (unsigned)counter_id);

  char dummy[4];
  return tc_cmd(cmd, "OK", dummy, sizeof(dummy), TC_SE_UART_TIMEOUT_MS);
}

se051_err_t se051_monotonic_counter_reset(uint8_t counter_id) {
  if (!g_tc_ready) return SE_ERR_COMM;

  char cmd[32];
  snprintf(cmd, sizeof(cmd), "AT+CTR:RST:%u\n", (unsigned)counter_id);

  char dummy[4];
  return tc_cmd(cmd, "OK", dummy, sizeof(dummy), TC_SE_UART_TIMEOUT_MS);
}

#endif // USE_TERNARYCORE_SE
