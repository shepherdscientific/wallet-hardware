#include "pin_manager.h"
#include "se051_hal.h"
#include "hmac_sha256.h"
#include <string.h>

#define DEVICE_UID_LEN 8

static void secure_zero(void *buf, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)buf;
  while (len--) *p++ = 0;
}

#ifdef USE_SE_STUB
void pin_get_device_uid(uint8_t uid[DEVICE_UID_LEN]) {
  static const uint8_t test_uid[DEVICE_UID_LEN] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
  };
  memcpy(uid, test_uid, DEVICE_UID_LEN);
}
#endif

bool pin_is_set(void) {
  uint8_t dummy[SE051_HASH_LEN];
  size_t out_len = 0;
  return se051_read_object(SE051_OBJ_PIN_HASH, dummy, sizeof(dummy), &out_len) == SE_OK;
}

bool pin_setup(const uint8_t pin[PIN_LEN]) {
  if (!pin) return false;

  uint8_t uid[DEVICE_UID_LEN];
  pin_get_device_uid(uid);
  uint8_t hash[HMAC_SHA256_OUTPUT_SIZE];
  hmac_sha256(uid, DEVICE_UID_LEN, pin, PIN_LEN, hash);

  se051_err_t err = se051_store_key(SE051_OBJ_PIN_HASH, hash, HMAC_SHA256_OUTPUT_SIZE);

  secure_zero(uid, DEVICE_UID_LEN);
  secure_zero(hash, HMAC_SHA256_OUTPUT_SIZE);

  return err == SE_OK;
}

bool pin_verify(const uint8_t pin[PIN_LEN]) {
  if (!pin) return false;

  if (!pin_is_set()) return false;

  uint8_t stored_hash[HMAC_SHA256_OUTPUT_SIZE];
  size_t out_len = 0;
  if (se051_read_object(SE051_OBJ_PIN_HASH, stored_hash, sizeof(stored_hash), &out_len) != SE_OK) {
    return false;
  }
  if (out_len != HMAC_SHA256_OUTPUT_SIZE) {
    return false;
  }

  uint8_t uid[DEVICE_UID_LEN];
  pin_get_device_uid(uid);
  uint8_t computed_hash[HMAC_SHA256_OUTPUT_SIZE];
  hmac_sha256(uid, DEVICE_UID_LEN, pin, PIN_LEN, computed_hash);

  secure_zero(uid, DEVICE_UID_LEN);

  bool match = (memcmp(computed_hash, stored_hash, HMAC_SHA256_OUTPUT_SIZE) == 0);

  secure_zero(computed_hash, HMAC_SHA256_OUTPUT_SIZE);
  secure_zero(stored_hash, HMAC_SHA256_OUTPUT_SIZE);

  return match;
}

bool pin_change(const uint8_t old_pin[PIN_LEN],
                const uint8_t new_pin[PIN_LEN]) {
  if (!pin_verify(old_pin)) return false;
  return pin_setup(new_pin);
}

void pin_reset(void) {
  se051_delete_key(SE051_OBJ_PIN_HASH);
}

uint8_t pin_get_attempts(void) {
  uint32_t value = 0;
  if (se051_monotonic_counter_get(SE051_OBJ_PIN_COUNTER, &value) != SE_OK) {
    return 0;
  }
  return (uint8_t)value;
}

bool pin_increment_attempts(void) {
  uint32_t before = 0;
  se051_monotonic_counter_get(SE051_OBJ_PIN_COUNTER, &before);
  if (before >= 255) return false;
  return se051_monotonic_counter_increment(SE051_OBJ_PIN_COUNTER) == SE_OK;
}

void pin_reset_attempts(void) {
  se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
}

uint8_t pin_attempts_remaining(void) {
  uint8_t attempts = pin_get_attempts();
  if (attempts >= PIN_MAX_ATTEMPTS) return 0;
  return PIN_MAX_ATTEMPTS - attempts;
}

bool pin_is_near_lockout(void) {
  return pin_get_attempts() >= 3;
}

void wallet_factory_reset(void) {
  se051_delete_key(SE051_KEY_BIP32_MASTER);
  se051_delete_key(SE051_KEY_CHAIN_CODE);
  se051_delete_key(SE051_OBJ_PIN_HASH);
  se051_delete_key(SE051_OBJ_ANTI_PHISH);
  se051_delete_key(SE051_OBJ_PIN_COUNTER);
  se051_delete_key(SE051_OBJ_FW_HASH);
  se051_delete_key(SE051_OBJ_HAS_PASSPHRASE);
}
