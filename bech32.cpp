#include "bech32.h"
#include <string.h>

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
  uint32_t gen[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  uint32_t chk = 1;
  for (size_t i = 0; i < len; i++) {
    uint32_t top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (int j = 0; j < 5; j++)
      if ((top >> j) & 1) chk ^= gen[j];
  }
  return chk;
}

static void hrp_expand(const char *hrp, uint8_t *dst) {
  size_t hrp_len = strlen(hrp);
  for (size_t i = 0; i < hrp_len; i++)
    dst[i] = (uint8_t)(hrp[i] >> 5);
  dst[hrp_len] = 0;
  for (size_t i = 0; i < hrp_len; i++)
    dst[hrp_len + 1 + i] = (uint8_t)(hrp[i] & 31);
}

static bool convert_8to5(const uint8_t *data, size_t data_len,
                         uint8_t *out, size_t *out_len) {
  uint32_t bits = 0;
  int bit_count = 0;
  size_t idx = 0;
  for (size_t i = 0; i < data_len; i++) {
    bits = (bits << 8) | data[i];
    bit_count += 8;
    while (bit_count >= 5) {
      bit_count -= 5;
      out[idx++] = (bits >> bit_count) & 31;
    }
  }
  if (bit_count > 0)
    out[idx++] = (bits << (5 - bit_count)) & 31;
  *out_len = idx;
  return true;
}

static bool bech32_encode_with_const(const char *hrp, int witver,
                                     const uint8_t *witprog, size_t witprog_len,
                                     uint32_t checksum_const,
                                     char out[BECH32_MAX_ENCODED_LEN]) {
  size_t hrp_len = strlen(hrp);
  if (hrp_len < 1 || hrp_len > 83) return false;
  if (witver < 0 || witver > 16) return false;
  if (witprog_len < 2 || witprog_len > 40) return false;

  size_t expanded_hrp_len = 2 * hrp_len + 1;
  uint8_t expanded_hrp[167];
  hrp_expand(hrp, expanded_hrp);

  uint8_t data5[65];
  data5[0] = (uint8_t)(witver & 31);

  size_t data5_len;
  if (!convert_8to5(witprog, witprog_len, data5 + 1, &data5_len))
    return false;
  data5_len++;

  size_t total = expanded_hrp_len + data5_len + 6;
  uint8_t values[256];
  memcpy(values, expanded_hrp, expanded_hrp_len);
  memcpy(values + expanded_hrp_len, data5, data5_len);
  memset(values + expanded_hrp_len + data5_len, 0, 6);

  uint32_t mod = bech32_polymod(values, total) ^ checksum_const;

  for (int i = 0; i < 6; i++)
    values[expanded_hrp_len + data5_len + i] = (mod >> (5 * (5 - i))) & 31;

  char *p = out;
  for (size_t i = 0; i < hrp_len; i++) *p++ = (char)(hrp[i] | 0x20);
  *p++ = '1';
  for (size_t i = 0; i < data5_len; i++)
    *p++ = CHARSET[data5[i]];
  for (int i = 0; i < 6; i++)
    *p++ = CHARSET[(mod >> (5 * (5 - i))) & 31];
  *p = '\0';

  return true;
}

bool bech32_encode(const char *hrp, int witver,
                   const uint8_t *witprog, size_t witprog_len,
                   char out[BECH32_MAX_ENCODED_LEN]) {
  return bech32_encode_with_const(hrp, witver, witprog, witprog_len,
                                  1, out);
}

bool bech32m_encode(const char *hrp, int witver,
                    const uint8_t *witprog, size_t witprog_len,
                    char out[BECH32_MAX_ENCODED_LEN]) {
  return bech32_encode_with_const(hrp, witver, witprog, witprog_len,
                                  0x2bc830a3, out);
}
