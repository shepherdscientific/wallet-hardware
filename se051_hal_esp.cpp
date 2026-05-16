#ifdef USE_SE051

#include "se051_hal.h"
#include <Arduino.h>
#include <Wire.h>

static uint8_t g_se051_ready = 0;

// ─── Low-level I2C transport with retry ──────────────────────────────────

static se051_err_t i2c_write(uint8_t address,
                             const uint8_t *data,
                             size_t len) {
  if (!data || len == 0) return SE_ERR_PARAM;

  for (uint8_t retry = 0; retry < SE051_I2C_RETRY_COUNT; retry++) {
    Wire.beginTransmission(address);
    Wire.write(data, len);
    uint8_t result = Wire.endTransmission();

    if (result == 0) {
      return SE_OK;
    }

    if (retry < SE051_I2C_RETRY_COUNT - 1) {
      delay(SE051_I2C_RETRY_MS);
    }
  }
  return SE_ERR_COMM;
}

static se051_err_t i2c_read(uint8_t address,
                            uint8_t *buf,
                            size_t len) {
  if (!buf || len == 0) return SE_ERR_PARAM;
  if (len > 255) return SE_ERR_PARAM;

  for (uint8_t retry = 0; retry < SE051_I2C_RETRY_COUNT; retry++) {
    uint8_t bytes_read = Wire.requestFrom(address, (uint8_t)len);

    if (bytes_read == len) {
      for (size_t i = 0; i < len; i++) {
        buf[i] = Wire.read();
      }
      return SE_OK;
    }

    while (Wire.available()) Wire.read();

    if (retry < SE051_I2C_RETRY_COUNT - 1) {
      delay(SE051_I2C_RETRY_MS);
    }
  }
  return SE_ERR_COMM;
}

static se051_err_t i2c_xfer(uint8_t address,
                            const uint8_t *tx_data,
                            size_t tx_len,
                            uint8_t *rx_data,
                            size_t rx_len) {
  se051_err_t err = i2c_write(address, tx_data, tx_len);
  if (err != SE_OK) return err;

  if (rx_len > 0) {
    delay(5);
    err = i2c_read(address, rx_data, rx_len);
  }
  return err;
}

// ─── SCP03 / APDU helpers ────────────────────────────────────────────────

#define APDU_CLA          0x80
#define APDU_INS_GET_DATA  0xCA
#define APDU_INS_PUT_DATA  0xDA
#define APDU_INS_DELETE_KEY 0xE0
#define APDU_INS_GET_RND   0x84
#define APDU_INS_INIT_AUTH 0x82
#define APDU_INS_EXT_AUTH  0x86
#define APDU_INS_VERIFY_PIN 0x20
#define APDU_INS_KEY_PAIR  0xFA
#define APDU_INS_INTERNAL_AUTH 0x88

static se051_err_t apdu_send_recv(const uint8_t *apdu,
                                  size_t apdu_len,
                                  uint8_t *resp,
                                  size_t resp_buf_size,
                                  size_t *resp_len) {
  se051_err_t err = i2c_write(SE051_I2C_ADDR, apdu, apdu_len);
  if (err != SE_OK) return err;

  delay(10);

  uint8_t header[2];
  err = i2c_read(SE051_I2C_ADDR, header, 2);
  if (err != SE_OK) return err;

  size_t sw_offset = 2;
  uint8_t status_word_1 = header[0];
  uint8_t status_word_2 = header[1];

  if (status_word_1 != 0x00 || (status_word_2 != 0x00 && status_word_2 != 0x90)) {
    if (status_word_1 == 0x69 && (status_word_2 == 0x82 || status_word_2 == 0x83)) {
      return SE_ERR_LOCKED;
    }
    if (status_word_1 == 0x69 && status_word_2 == 0x85) {
      return SE_ERR_LOCKED;
    }
    return SE_ERR_COMM;
  }

  if (resp && resp_len) {
    size_t data_len = 0;
    if (status_word_2 == 0x00 && resp_buf_size >= 2) {
      delay(5);
      err = i2c_read(SE051_I2C_ADDR, resp, resp_buf_size);
      if (err != SE_OK) return err;
      data_len = resp_buf_size;
    }
    *resp_len = data_len;
  }

  return SE_OK;
}

// ─── Public HAL Implementation ───────────────────────────────────────────

se051_err_t se051_init(void) {
  Wire.begin(8, 9);
  Wire.setClock(400000);

  uint8_t select_apdu[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
  se051_err_t err = i2c_write(SE051_I2C_ADDR, select_apdu, sizeof(select_apdu));
  if (err != SE_OK) return err;

  g_se051_ready = 1;
  return SE_OK;
}

se051_err_t se051_get_random(uint8_t *buf, size_t len) {
  if (!buf || len == 0 || len > 255) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t apdu[] = { APDU_CLA, APDU_INS_GET_RND, 0x00, 0x00, (uint8_t)len };
  size_t rx_len = 0;

  return i2c_xfer(SE051_I2C_ADDR, apdu, sizeof(apdu), buf, len);
}

se051_err_t se051_ecdsa_sign(uint8_t key_id,
                             const uint8_t hash[SE051_HASH_LEN],
                             uint8_t sig_out[SE051_ECDSA_MAX_DER_LEN],
                             size_t *sig_len) {
  if (!hash || !sig_out || !sig_len) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t apdu[5 + 1 + SE051_HASH_LEN];
  apdu[0] = APDU_CLA;
  apdu[1] = APDU_INS_INTERNAL_AUTH;
  apdu[2] = key_id;
  apdu[3] = 0x01; // ECDSA algorithm ref
  apdu[4] = (uint8_t)(1 + SE051_HASH_LEN);
  apdu[5] = 0x00; // private key ref tag
  memcpy(&apdu[6], hash, SE051_HASH_LEN);

  size_t rx_len = 0;
  se051_err_t err = i2c_xfer(SE051_I2C_ADDR, apdu, sizeof(apdu),
                             sig_out, SE051_ECDSA_MAX_DER_LEN);
  if (err != SE_OK) return err;
  *sig_len = SE051_ECDSA_MAX_DER_LEN;
  return SE_OK;
}

se051_err_t se051_schnorr_sign(uint8_t key_id,
                               const uint8_t hash[SE051_HASH_LEN],
                               uint8_t sig_out[SE051_SCHNORR_SIG_LEN]) {
  if (!hash || !sig_out) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t apdu[5 + 1 + SE051_HASH_LEN];
  apdu[0] = APDU_CLA;
  apdu[1] = APDU_INS_INTERNAL_AUTH;
  apdu[2] = key_id;
  apdu[3] = 0x02; // Schnorr algorithm ref
  apdu[4] = (uint8_t)(1 + SE051_HASH_LEN);
  apdu[5] = 0x00; // private key ref tag
  memcpy(&apdu[6], hash, SE051_HASH_LEN);

  return i2c_xfer(SE051_I2C_ADDR, apdu, sizeof(apdu),
                  sig_out, SE051_SCHNORR_SIG_LEN);
}

se051_err_t se051_store_key(uint8_t key_id,
                            const uint8_t *key_material,
                            size_t key_len) {
  if (!key_material || key_len == 0 || key_len > 128)
    return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t apdu[5 + 128];
  apdu[0] = APDU_CLA;
  apdu[1] = APDU_INS_PUT_DATA;
  apdu[2] = 0x00;
  apdu[3] = key_id;
  apdu[4] = (uint8_t)key_len;
  memcpy(&apdu[5], key_material, key_len);

  return i2c_write(SE051_I2C_ADDR, apdu, 5 + key_len);
}

se051_err_t se051_delete_key(uint8_t key_id) {
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t apdu[] = { APDU_CLA, APDU_INS_DELETE_KEY, 0x00, key_id, 0x00 };
  return i2c_write(SE051_I2C_ADDR, apdu, sizeof(apdu));
}

se051_err_t se051_get_pubkey(uint8_t key_id,
                             uint8_t pubkey_out[SE051_PUBKEY_COMPRESSED]) {
  if (!pubkey_out) return SE_ERR_PARAM;
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t apdu[] = { APDU_CLA, APDU_INS_GET_DATA, 0x00, key_id, 0x00 };
  return i2c_xfer(SE051_I2C_ADDR, apdu, sizeof(apdu),
                  pubkey_out, SE051_PUBKEY_COMPRESSED);
}

se051_err_t se051_selftest(void) {
  if (!g_se051_ready) return SE_ERR_COMM;

  uint8_t test_buf[32];
  se051_err_t err = se051_get_random(test_buf, 32);
  if (err != SE_OK) return err;

  uint8_t all_zero = 1;
  uint8_t all_ff   = 1;
  for (int i = 0; i < 32; i++) {
    if (test_buf[i] != 0x00) all_zero = 0;
    if (test_buf[i] != 0xFF) all_ff   = 0;
  }
  if (all_zero || all_ff) return SE_ERR_COMM;

  return SE_OK;
}

#endif // USE_SE051
