#include "hmac_sha256.h"
#include "sha256.h"
#include <string.h>

void cc_hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[HMAC_SHA256_OUTPUT_SIZE]) {
  uint8_t key_block[HMAC_SHA256_BLOCK_SIZE];
  uint8_t ipad[HMAC_SHA256_BLOCK_SIZE];
  uint8_t opad[HMAC_SHA256_BLOCK_SIZE];
  uint8_t inner_hash[SHA256_DIGEST_LENGTH];

  memset(key_block, 0, sizeof(key_block));

  if (key_len > HMAC_SHA256_BLOCK_SIZE) {
    sha256(key, key_len, key_block);
  } else {
    memcpy(key_block, key, key_len);
  }

  for (int i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
    ipad[i] = key_block[i] ^ 0x36;
    opad[i] = key_block[i] ^ 0x5C;
  }

  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, ipad, HMAC_SHA256_BLOCK_SIZE);
  if (msg && msg_len > 0) {
    sha256_update(&ctx, msg, msg_len);
  }
  sha256_final(&ctx, inner_hash);

  sha256_init(&ctx);
  sha256_update(&ctx, opad, HMAC_SHA256_BLOCK_SIZE);
  sha256_update(&ctx, inner_hash, SHA256_DIGEST_LENGTH);
  sha256_final(&ctx, mac);

  memset(key_block, 0, sizeof(key_block));
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  memset(inner_hash, 0, sizeof(inner_hash));
}
