#ifdef USE_ATECC608B

#include "se051_hal.h"
#include "bip32.h"
#include <Arduino.h>
#include <Wire.h>
#include <string.h>

static uint8_t g_se051_ready = 0;

// ─── ATECC608B Constants ──────────────────────────────────────────────────

#define ATECC_CMD_INFO        0x30
#define ATECC_CMD_RANDOM      0x1B
#define ATECC_CMD_SIGN        0x41
#define ATECC_CMD_GENKEY      0x40
#define ATECC_CMD_READ        0x02
#define ATECC_CMD_WRITE       0x12
#define ATECC_CMD_SELFTEST    0x77
#define ATECC_CMD_NONCE       0x16
#define ATECC_CMD_COUNTER     0x24
#define ATECC_CMD_SHA         0x47

#define ATECC_ZONE_CONFIG     0x00
#define ATECC_ZONE_DATA       0x02

#define ATECC_WORD_ADDR       0x03
#define ATECC_WAKE_US         100

#define ATECC_SLOT_MASTER     0x00
#define ATECC_SLOT_CHAINCODE  0x08
#define ATECC_SLOT_PIN_HASH   0x09
#define ATECC_SLOT_ANTI_PHISH 0x0A
#define ATECC_SLOT_PIN_COUNTER 0x0B
#define ATECC_SLOT_FW_HASH    0x0C
#define ATECC_SLOT_PASSPHRASE 0x0D

// ─── Slot Mapping ───────────────────────────────────────────────────────── ─

static uint8_t map_key_id(uint8_t key_id) {
  switch (key_id) {
    case SE051_KEY_BIP32_MASTER:   return ATECC_SLOT_MASTER;
    case SE051_KEY_CHAIN_CODE:     return ATECC_SLOT_CHAINCODE;
    case SE051_OBJ_PIN_HASH:       return ATECC_SLOT_PIN_HASH;
    case SE051_OBJ_ANTI_PHISH:     return ATECC_SLOT_ANTI_PHISH;
    case SE051_OBJ_PIN_COUNTER:    return ATECC_SLOT_PIN_COUNTER;
    case SE051_OBJ_FW_HASH:        return ATECC_SLOT_FW_HASH;
    case SE051_OBJ_HAS_PASSPHRASE: return ATECC_SLOT_PASSPHRASE;
    default: return 0xFF;
  }
}

// ─── CRC-16 (ATECC608B / Microchip CryptoAuthLib variant) ────────────────
// The ATECC608B uses polynomial 0x8005 with LSB-first bit processing.
// This matches Microchip's atcac_sw_crc16() in CryptoAuthLib exactly.
// Note: this is NOT standard CRC-16/CCITT which is MSB-first — using the
// wrong bit order causes every command to be rejected with a parse error.

static uint16_t crc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; i++) {
    for (uint8_t bit = 0x01; bit != 0x00; bit <<= 1) {   // LSB first
      uint8_t data_bit = (data[i] & bit) ? 1 : 0;
      uint8_t crc_bit  = (uint8_t)(crc >> 15);
      crc <<= 1;
      if (data_bit != crc_bit) crc ^= 0x8005;
    }
  }
  return crc;
}

// ─── Wake Sequence ────────────────────────────────────────────────────────

static bool atecc_wake(void) {
  Wire.setTimeOut(50);

  // Fast path: if the chip already ACKs its address it is awake and ready.
  // This happens when the I2C bus sweep in setup() woke it moments earlier.
  Wire.beginTransmission(SE051_I2C_ADDR);
  if (Wire.endTransmission() == 0) {
    return true;
  }

  // Chip is sleeping — send wake token.  Addressing 0x00 transmits an all-zero
  // byte on SDA (~80 µs at 100 kHz) which exceeds the tWLO minimum of 60 µs.
  Wire.beginTransmission(0x00);
  Wire.endTransmission();
  delayMicroseconds(2500);  // tWHI ≥ 1500 µs; use 2.5 ms for margin

  // Read and verify 4-byte wake response: 04 11 33 43
  Wire.requestFrom(SE051_I2C_ADDR, (uint8_t)4, (uint8_t)1);
  if (Wire.available() < 4) return false;
  uint8_t r[4];
  for (int i = 0; i < 4; i++) r[i] = Wire.read();
  return (r[0] == 0x04 && r[1] == 0x11 && r[2] == 0x33 && r[3] == 0x43);
}

static void atecc_bus_sweep(void) {
  for (uint8_t addr = 1; addr < 128; addr++) {
    Wire.beginTransmission(addr);
    Wire.endTransmission();
  }
}

// ─── Command Send / Receive ────────────────────────────────────────────────

static se051_err_t atecc_send_cmd(uint8_t opcode, uint8_t p1,
                                   uint16_t p2, const uint8_t *data,
                                   size_t data_len) {
  // Packet layout: [word_addr(1)][count(1)][opcode(1)][p1(1)][p2(2)][data(n)][crc(2)]
  size_t total = 1 + 1 + 1 + 1 + 2 + data_len + 2;  // wa + count + opcode + p1 + p2 + data + CRC
  uint8_t buf[128];
  buf[0] = ATECC_WORD_ADDR;
  buf[1] = (uint8_t)(total - 1);  // count = bytes from count field to end (excludes word_addr)
  buf[2] = opcode;
  buf[3] = p1;
  buf[4] = (uint8_t)(p2 & 0xFF);
  buf[5] = (uint8_t)(p2 >> 8);
  if (data && data_len > 0) memcpy(buf + 6, data, data_len);
  uint16_t crc = crc16(buf + 1, total - 3);
  buf[total - 2] = (uint8_t)(crc & 0xFF);
  buf[total - 1] = (uint8_t)(crc >> 8);

  for (uint8_t retry = 0; retry < SE051_I2C_RETRY_COUNT; retry++) {
    Wire.beginTransmission(SE051_I2C_ADDR);
    Wire.write(buf, total);
    uint8_t result = Wire.endTransmission();
    if (result == 0) return SE_OK;
    if (retry < SE051_I2C_RETRY_COUNT - 1) delay(SE051_I2C_RETRY_MS);
  }
  return SE_ERR_COMM;
}

static se051_err_t atecc_recv_resp(uint8_t *resp, size_t *resp_len,
                                    size_t max_len) {
  delay(5);  // INFO max tEXEC = 1 ms; 5 ms gives ample margin before first read
  size_t total = 0;
  uint8_t raw[130];

  for (uint8_t retry = 0; retry < SE051_I2C_RETRY_COUNT; retry++) {
    Wire.requestFrom(SE051_I2C_ADDR, (uint8_t)max_len, (uint8_t)1);
    if (Wire.available() >= 1) {
      uint8_t count = Wire.read();
      // count is inclusive of itself: packet = count + data + CRC (min 3 bytes)
      if (count < 3 || count > max_len) return SE_ERR_PARAM;
      total = count;   // count already includes the count byte itself
      raw[0] = count;
      for (size_t i = 1; i < total && Wire.available(); i++) {
        raw[i] = Wire.read();
      }
      if (total >= 3) {
        uint16_t calc = crc16(raw, total - 2);  // CRC over count..last_data_byte
        uint16_t recv = raw[total - 2] | ((uint16_t)raw[total - 1] << 8);
        if (calc != recv) {
          if (retry < SE051_I2C_RETRY_COUNT - 1) delay(SE051_I2C_RETRY_MS);
          continue;
        }
      }
      if (resp && resp_len) {
        size_t copy = total - 3;  // strip count byte and 2 CRC bytes; keep payload
        if (copy > max_len) copy = max_len;
        memcpy(resp, raw + 1, copy);
        *resp_len = copy;
      }
      return SE_OK;
    }
    if (retry < SE051_I2C_RETRY_COUNT - 1) delay(SE051_I2C_RETRY_MS);
  }
  return SE_ERR_COMM;
}

// ─── Public HAL Implementation ────────────────────────────────────────────

se051_err_t se051_init(void) {
  Wire.setTimeOut(50);

  // Wake the chip (or confirm it is already awake).
  if (!atecc_wake()) {
#ifdef DEV_BUILD
    Serial.println("[ATECC] wake failed — chip not responding on I2C");
#endif
    return SE_ERR_COMM;
  }
#ifdef DEV_BUILD
  Serial.println("[ATECC] wake OK");
#endif

  // INFO Revision mode: opcode=0x30, param1=0x00, param2=0x0000, no data.
  // Returns 4-byte revision info on success.
  se051_err_t err = atecc_send_cmd(ATECC_CMD_INFO, 0x00, 0x0000, NULL, 0);
  if (err != SE_OK) {
#ifdef DEV_BUILD
    Serial.printf("[ATECC] INFO send failed: %d\n", (int)err);
#endif
    return err;
  }

  uint8_t resp[8];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK) {
#ifdef DEV_BUILD
    Serial.printf("[ATECC] INFO recv failed: %d\n", (int)err);
#endif
    return err;
  }
  if (rlen < 4) {
#ifdef DEV_BUILD
    Serial.printf("[ATECC] INFO rlen too short: %u\n", (unsigned)rlen);
#endif
    return SE_ERR_COMM;
  }

#ifdef DEV_BUILD
  Serial.printf("[ATECC] revision: %02X %02X %02X %02X\n",
                resp[0], resp[1], resp[2], resp[3]);
#endif

  // Diagnostic: Check Config Zone lock status (word 21, bytes 84-87)
  err = atecc_send_cmd(ATECC_CMD_READ, 0x00, 21, NULL, 0);
  if (err != SE_OK) {
#ifdef DEV_BUILD
    Serial.printf("[ATECC] LOCK_STATUS read send failed: %d\n", (int)err);
#endif
  } else {
    rlen = 0;
    err = atecc_recv_resp(resp, &rlen, sizeof(resp));
    if (err == SE_OK && rlen >= 4) {
#ifdef DEV_BUILD
      Serial.printf("[ATECC] LockConfig=0x%02X LockValue=0x%02X (0x55 means locked)\n", 
                    resp[3], resp[2]);
#endif
    } else {
#ifdef DEV_BUILD
      Serial.printf("[ATECC] LOCK_STATUS read recv failed: %d, rlen=%u\n", (int)err, (unsigned)rlen);
#endif
    }
  }

  g_se051_ready = 1;
  return SE_OK;
}

se051_err_t se051_get_random(uint8_t *buf, size_t len) {
  if (!buf || len == 0 || len > 32) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  atecc_wake();

  uint8_t mode[2] = { 0x01, 0x00 };
  se051_err_t err = atecc_send_cmd(ATECC_CMD_RANDOM, 0x00, 0x0000, mode, 2);
  if (err != SE_OK) return err;

  uint8_t resp[40];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK) return err;
  if (rlen < 32) return SE_ERR_COMM;

  memcpy(buf, resp, (len < rlen) ? len : rlen);
  return SE_OK;
}

se051_err_t se051_ecdsa_sign(uint8_t key_id,
                             const uint8_t hash[SE051_HASH_LEN],
                             uint8_t sig_out[SE051_ECDSA_MAX_DER_LEN],
                             size_t *sig_len) {
  if (!hash || !sig_out || !sig_len) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t slot = map_key_id(key_id);
  if (slot > 7) return SE_ERR_PARAM;

  atecc_wake();

  uint8_t cmd_data[2 + SE051_HASH_LEN];
  cmd_data[0] = slot;
  cmd_data[1] = 0x00;
  memcpy(cmd_data + 2, hash, SE051_HASH_LEN);

  se051_err_t err = atecc_send_cmd(ATECC_CMD_SIGN, 0x80, 0x0000,
                                    cmd_data, sizeof(cmd_data));
  if (err != SE_OK) return err;

  uint8_t resp[80];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK) return err;

  if (rlen < 64) return SE_ERR_COMM;

  memcpy(sig_out, resp, 64);
  *sig_len = 64;
  return SE_OK;
}

se051_err_t se051_schnorr_sign(uint8_t key_id,
                                const uint8_t hash[SE051_HASH_LEN],
                                uint8_t sig_out[SE051_SCHNORR_SIG_LEN]) {
  (void)key_id; (void)hash; (void)sig_out;
  return SE_ERR_NOTFOUND;
}

// ─── ATECC608B Data-Zone Read/Write helpers ────────────────────────────────
// P1 zone byte: bit 7 = 1 → 32-byte transfer; bits 1:0 = zone (10 = Data).
// P2 address: bits 2:0 = offset (32-byte blocks within slot), bits 6:3 = slot,
// bits 15:8 = block. Slots 8-15 hold ≥ 32 bytes so block 0 / offset 0 is fine
// for a single 32-byte object like the firmware hash.

#define ATECC_RW_P1_DATA_32  0x82

static uint16_t atecc_slot_addr(uint8_t slot) {
  return (uint16_t)((slot & 0x0F) << 3);
}

static se051_err_t atecc_read_slot32(uint8_t slot, uint8_t out[32]) {
  atecc_wake();
  se051_err_t err = atecc_send_cmd(ATECC_CMD_READ,
                                   ATECC_RW_P1_DATA_32,
                                   atecc_slot_addr(slot), NULL, 0);
  if (err != SE_OK) return err;

  uint8_t resp[40];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK) return err;
  // A 1-byte response equals an ATECC status word (0x00 = OK is unexpected
  // here; non-zero means error such as ParseError / ExecError).  Any reply
  // shorter than 32 bytes therefore means the slot is unreadable or blank.
  if (rlen < 32) return SE_ERR_NOTFOUND;

  memcpy(out, resp, 32);
  return SE_OK;
}

static se051_err_t atecc_write_slot32(uint8_t slot, const uint8_t in[32]) {
  atecc_wake();
  se051_err_t err = atecc_send_cmd(ATECC_CMD_WRITE,
                                   ATECC_RW_P1_DATA_32,
                                   atecc_slot_addr(slot), in, 32);
  if (err != SE_OK) return err;

  uint8_t resp[4];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK) return err;
  if (rlen < 1) return SE_ERR_COMM;
  // ATECC Write returns a single status byte: 0x00 == success.  Anything else
  // (e.g. 0x01 ExecError when slot is unlocked or config disallows the write,
  // 0x04 ParseError) is surfaced as a locked / auth failure.
  if (resp[0] != 0x00) return SE_ERR_LOCKED;
  return SE_OK;
}

se051_err_t se051_store_key(uint8_t key_id,
                            const uint8_t *key_material,
                            size_t key_len) {
  if (!key_material || key_len == 0 || key_len > 32) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t slot = map_key_id(key_id);
  if (slot == 0xFF) return SE_ERR_PARAM;

  // Pad to 32 bytes (shorter objects like anti-phish=8 B, passphrase flag=1 B).
  uint8_t padded[32];
  memset(padded, 0, sizeof(padded));
  memcpy(padded, key_material, key_len);
  return atecc_write_slot32(slot, padded);
}

se051_err_t se051_delete_key(uint8_t key_id) {
  if (!g_se051_ready) return SE_ERR_COMM;
  uint8_t slot = map_key_id(key_id);
  if (slot == 0xFF) return SE_ERR_NOTFOUND;
  // Overwrite with zeros — se051_read_object treats all-zero as SE_ERR_NOTFOUND.
  uint8_t zeros[32];
  memset(zeros, 0, sizeof(zeros));
  return atecc_write_slot32(slot, zeros);
}

se051_err_t se051_get_pubkey(uint8_t key_id,
                             uint8_t pubkey_out[SE051_PUBKEY_COMPRESSED]) {
  if (!pubkey_out) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t slot = map_key_id(key_id);
  if (slot == 0xFF) return SE_ERR_PARAM;

  if (key_id == SE051_KEY_BIP32_MASTER) {
    // The master private key is stored raw in the slot.
    // Read it back and derive the compressed public key in software.
    uint8_t privkey[32];
    se051_err_t err = atecc_read_slot32(slot, privkey);
    if (err != SE_OK) return err;
    bool all_zero = true;
    for (int i = 0; i < 32; i++) { if (privkey[i]) { all_zero = false; break; } }
    if (all_zero) { memset(privkey, 0, 32); return SE_ERR_NOTFOUND; }
    bool ok = hd_pubkey_from_priv(privkey, pubkey_out);
    memset(privkey, 0, 32);
    return ok ? SE_OK : SE_ERR_COMM;
  }

  if (key_id == SE051_KEY_CHAIN_CODE) {
    // Chain code is not an EC key — just confirm the slot has been written.
    uint8_t raw[32];
    se051_err_t err = atecc_read_slot32(slot, raw);
    if (err != SE_OK) return err;
    bool all_zero = true;
    for (int i = 0; i < 32; i++) { if (raw[i]) { all_zero = false; break; } }
    if (all_zero) return SE_ERR_NOTFOUND;
    // Caller only checks SE_OK; pubkey_out content is not used for chain code.
    memcpy(pubkey_out, raw, 32);
    pubkey_out[32] = 0x00;
    return SE_OK;
  }

  return SE_ERR_PARAM;
}

se051_err_t se051_selftest(void) {
  if (!g_se051_ready) return SE_ERR_COMM;

  atecc_wake();

  uint8_t mode = 0x01;
  se051_err_t err = atecc_send_cmd(ATECC_CMD_SELFTEST, 0x00, 0x0000,
                                    &mode, 1);
  if (err != SE_OK) return err;

  uint8_t resp[4];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK) return err;
  if (rlen < 1 || resp[0] != 0x00) return SE_ERR_COMM;

  return SE_OK;
}

se051_err_t se051_get_serial(char *buf, size_t buf_len) {
  if (!buf || buf_len == 0) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  atecc_wake();

  uint8_t mode[5] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
  se051_err_t err = atecc_send_cmd(ATECC_CMD_INFO, ATECC_ZONE_CONFIG, 0x0000,
                                    mode, sizeof(mode));
  if (err != SE_OK) {
    snprintf(buf, buf_len, "ATECC608B");
    return err;
  }

  uint8_t resp[36];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK || rlen < 8) {
    snprintf(buf, buf_len, "ATECC608B");
    return SE_OK;
  }

  int w = snprintf(buf, buf_len, "ATEC-%02X%02X%02X%02X%02X%02X%02X%02X",
                   resp[0], resp[1], resp[2], resp[3],
                   resp[4], resp[5], resp[6], resp[7]);
  if (w < 0) buf[0] = '\0';
  return SE_OK;
}

se051_err_t se051_read_object(uint8_t obj_id,
                              uint8_t *buf, size_t buf_len,
                              size_t *out_len) {
  if (!buf || buf_len == 0 || !out_len) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;
  *out_len = 0;

  uint8_t slot = map_key_id(obj_id);
  if (slot == 0xFF) return SE_ERR_PARAM;

  uint8_t raw[32];
  se051_err_t err = atecc_read_slot32(slot, raw);
  if (err != SE_OK) return err;

  // All-zero = slot was never written or was deleted via se051_delete_key.
  bool all_zero = true;
  for (int i = 0; i < 32; i++) { if (raw[i]) { all_zero = false; break; } }
  if (all_zero) return SE_ERR_NOTFOUND;

  // FW_HASH: additionally reject factory-blank all-FF value.
  if (obj_id == SE051_OBJ_FW_HASH) {
    bool all_ff = true;
    for (int i = 0; i < 32; i++) { if (raw[i] != 0xFF) { all_ff = false; break; } }
    if (all_ff) return SE_ERR_NOTFOUND;
  }

  size_t copy = (buf_len < 32) ? buf_len : 32;
  memcpy(buf, raw, copy);
  *out_len = copy;
  return SE_OK;
}

se051_err_t se051_monotonic_counter_get(uint8_t counter_id,
                                        uint32_t *value) {
  if (!value || !g_se051_ready) return SE_ERR_PARAM;

  atecc_wake();

  uint8_t cmd_data[5] = { 0x00, (uint8_t)counter_id, 0x00, 0x00, 0x00 };
  se051_err_t err = atecc_send_cmd(ATECC_CMD_COUNTER, 0x00, 0x0000,
                                    cmd_data, sizeof(cmd_data));
  if (err != SE_OK) {
    *value = 0;
    return err;
  }

  uint8_t resp[8];
  size_t rlen = 0;
  err = atecc_recv_resp(resp, &rlen, sizeof(resp));
  if (err != SE_OK || rlen < 4) {
    *value = 0;
    return SE_OK;
  }

  *value = resp[0] | ((uint32_t)resp[1] << 8) |
           ((uint32_t)resp[2] << 16) | ((uint32_t)resp[3] << 24);
  return SE_OK;
}

se051_err_t se051_monotonic_counter_increment(uint8_t counter_id) {
  if (!g_se051_ready) return SE_ERR_COMM;

  atecc_wake();

  uint8_t cmd_data[5] = { 0x01, (uint8_t)counter_id, 0x00, 0x00, 0x00 };
  se051_err_t err = atecc_send_cmd(ATECC_CMD_COUNTER, 0x00, 0x0000,
                                    cmd_data, sizeof(cmd_data));
  if (err != SE_OK) return err;
  // Must drain the response to keep the I2C bus clean.
  uint8_t resp[8];
  size_t rlen = 0;
  atecc_recv_resp(resp, &rlen, sizeof(resp));
  return SE_OK;
}

se051_err_t se051_monotonic_counter_reset(uint8_t counter_id) {
  (void)counter_id;
  return SE_ERR_NOTFOUND;
}

#endif // USE_ATECC608B
