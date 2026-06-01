#include "base58.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>

static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool base58check_encode(uint8_t version, const uint8_t *payload, size_t payload_len,
                        char out[BASE58_MAX_ENCODED_LEN]) {
  if (payload_len > 32) return false;
  uint8_t buf[37];
  buf[0] = version;
  memcpy(buf + 1, payload, payload_len);

  uint8_t hash1[32], hash2[32];
  sha256(buf, 1 + payload_len, hash1);
  sha256(hash1, 32, hash2);
  memcpy(buf + 1 + payload_len, hash2, 4);

  size_t bin_len = 1 + payload_len + 4;

  size_t zero_count = 0;
  while (zero_count < bin_len && buf[zero_count] == 0) zero_count++;

  uint8_t encoded[BASE58_MAX_ENCODED_LEN];
  memset(encoded, 0, BASE58_MAX_ENCODED_LEN);
  size_t idx = BASE58_MAX_ENCODED_LEN;

  for (size_t i = zero_count; i < bin_len; i++) {
    uint32_t carry = buf[i];
    for (size_t j = BASE58_MAX_ENCODED_LEN - 1; j >= idx || carry; j--) {
      carry += (uint32_t)encoded[j] * 256;
      encoded[j] = (uint8_t)(carry % 58);
      carry /= 58;
      if (j < idx && carry == 0 && j > 0) idx = j;
    }
  }

  while (idx < BASE58_MAX_ENCODED_LEN && encoded[idx] == 0) idx++;

  char *p = out;
  for (size_t i = 0; i < zero_count; i++) *p++ = BASE58_ALPHABET[0];
  for (size_t i = idx; i < BASE58_MAX_ENCODED_LEN; i++) *p++ = BASE58_ALPHABET[encoded[i]];
  *p = '\0';

  return true;
}
