#ifdef USE_SE_STUB

#include "se051_hal.h"
#include <string.h>
#include <stdlib.h>
#include <cstdio>

static uint8_t g_initialized = 0;
static uint32_t g_rand_seed = 0xDEADBEEF;

static const uint8_t g_test_pubkey_01[SE051_PUBKEY_COMPRESSED] = {
  0x02,
  0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
  0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
  0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
  0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};

static const uint8_t g_test_sig_ecdsa[SE051_ECDSA_MAX_DER_LEN] = {
  0x30, 0x45,
  0x02, 0x21, 0x00,
  0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
  0x21,
  0x02, 0x20,
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
  0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50
};

static const uint8_t g_test_sig_schnorr[SE051_SCHNORR_SIG_LEN] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
};

// Key store simulation: single key slot supporting up to 128 bytes
static uint8_t g_key_store_valid[256];
static uint8_t g_key_store_data[256][128];
static size_t  g_key_store_len[256];

static uint32_t lcg_rand(void) {
  g_rand_seed = g_rand_seed * 1664525 + 1013904223;
  return g_rand_seed;
}

se051_err_t se051_init(void) {
  memset(g_key_store_valid, 0, sizeof(g_key_store_valid));
  g_initialized = 1;
  return SE_OK;
}

se051_err_t se051_get_random(uint8_t *buf, size_t len) {
  if (!buf || len == 0) return SE_ERR_PARAM;
  size_t full_words = len / 4;
  size_t rem        = len % 4;
  uint32_t *wbuf    = (uint32_t *)buf;

  for (size_t i = 0; i < full_words; i++) {
    wbuf[i] = lcg_rand();
  }
  if (rem) {
    uint32_t last = lcg_rand();
    memcpy(&wbuf[full_words], &last, rem);
  }
  return SE_OK;
}

se051_err_t se051_ecdsa_sign(uint8_t key_id,
                             const uint8_t hash[SE051_HASH_LEN],
                             uint8_t sig_out[SE051_ECDSA_MAX_DER_LEN],
                             size_t *sig_len) {
  (void)hash;
  if (!sig_out || !sig_len) return SE_ERR_PARAM;
  if (!g_key_store_valid[key_id]) return SE_ERR_NOTFOUND;
  memcpy(sig_out, g_test_sig_ecdsa, sizeof(g_test_sig_ecdsa));
  *sig_len = 0x47; // 71-byte DER signature
  return SE_OK;
}

se051_err_t se051_schnorr_sign(uint8_t key_id,
                               const uint8_t hash[SE051_HASH_LEN],
                               uint8_t sig_out[SE051_SCHNORR_SIG_LEN]) {
  (void)hash;
  if (!sig_out) return SE_ERR_PARAM;
  if (!g_key_store_valid[key_id]) return SE_ERR_NOTFOUND;
  memcpy(sig_out, g_test_sig_schnorr, SE051_SCHNORR_SIG_LEN);
  return SE_OK;
}

se051_err_t se051_store_key(uint8_t key_id,
                            const uint8_t *key_material,
                            size_t key_len) {
  if (!key_material || key_len == 0 || key_len > 128)
    return SE_ERR_PARAM;

  memcpy(g_key_store_data[key_id], key_material, key_len);
  g_key_store_len[key_id]   = key_len;
  g_key_store_valid[key_id] = 1;
  return SE_OK;
}

se051_err_t se051_delete_key(uint8_t key_id) {
  memset(g_key_store_data[key_id], 0, g_key_store_len[key_id]);
  g_key_store_len[key_id]   = 0;
  g_key_store_valid[key_id] = 0;
  return SE_OK;
}

se051_err_t se051_get_pubkey(uint8_t key_id,
                             uint8_t pubkey_out[SE051_PUBKEY_COMPRESSED]) {
  if (!pubkey_out) return SE_ERR_PARAM;
  if (!g_key_store_valid[key_id]) return SE_ERR_NOTFOUND;
  memcpy(pubkey_out, g_test_pubkey_01, SE051_PUBKEY_COMPRESSED);
  return SE_OK;
}

se051_err_t se051_read_object(uint8_t obj_id,
                              uint8_t *buf, size_t buf_len,
                              size_t *out_len) {
  if (!buf || buf_len == 0) return SE_ERR_PARAM;
  if (!g_key_store_valid[obj_id]) return SE_ERR_NOTFOUND;
  size_t copy_len = g_key_store_len[obj_id] < buf_len ? g_key_store_len[obj_id] : buf_len;
  memcpy(buf, g_key_store_data[obj_id], copy_len);
  if (out_len) *out_len = copy_len;
  return SE_OK;
}

se051_err_t se051_selftest(void) {
  if (!g_initialized) return SE_ERR_COMM;
  return SE_OK;
}

se051_err_t se051_get_serial(char *buf, size_t buf_len) {
  if (!buf || buf_len == 0) return SE_ERR_PARAM;
  if (!g_initialized) return SE_ERR_COMM;
  snprintf(buf, buf_len, "SE051-00000001");
  return SE_OK;
}

se051_err_t se051_monotonic_counter_get(uint8_t counter_id,
                                        uint32_t *value) {
  if (!value) return SE_ERR_PARAM;
  if (!g_key_store_valid[counter_id]) {
    *value = 0;
    return SE_OK;
  }
  *value = g_key_store_data[counter_id][0];
  return SE_OK;
}

se051_err_t se051_monotonic_counter_increment(uint8_t counter_id) {
  uint32_t current = 0;
  if (g_key_store_valid[counter_id]) {
    current = g_key_store_data[counter_id][0];
  }
  if (current >= 255) return SE_ERR_MEMORY;
  current++;
  g_key_store_data[counter_id][0] = (uint8_t)current;
  g_key_store_len[counter_id] = 1;
  g_key_store_valid[counter_id] = 1;
  return SE_OK;
}

se051_err_t se051_monotonic_counter_reset(uint8_t counter_id) {
  g_key_store_data[counter_id][0] = 0;
  g_key_store_len[counter_id] = 1;
  g_key_store_valid[counter_id] = 1;
  return SE_OK;
}

#endif // USE_SE_STUB
