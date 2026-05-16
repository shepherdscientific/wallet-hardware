#include "hmac_sha512.h"
#include "sha512.h"
#include <string.h>

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[HMAC_SHA512_OUTPUT_SIZE]) {
  uint8_t key_block[HMAC_SHA512_BLOCK_SIZE];
  uint8_t ipad[HMAC_SHA512_BLOCK_SIZE];
  uint8_t opad[HMAC_SHA512_BLOCK_SIZE];
  uint8_t inner_hash[SHA512_DIGEST_LENGTH];

  memset(key_block, 0, sizeof(key_block));

  if (key_len > HMAC_SHA512_BLOCK_SIZE) {
    sha512(key, key_len, key_block);
  } else {
    memcpy(key_block, key, key_len);
  }

  for (int i = 0; i < HMAC_SHA512_BLOCK_SIZE; i++) {
    ipad[i] = key_block[i] ^ 0x36;
    opad[i] = key_block[i] ^ 0x5C;
  }

  sha512_ctx ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, ipad, HMAC_SHA512_BLOCK_SIZE);
  if (msg && msg_len > 0) {
    sha512_update(&ctx, msg, msg_len);
  }
  sha512_final(&ctx, inner_hash);

  sha512_init(&ctx);
  sha512_update(&ctx, opad, HMAC_SHA512_BLOCK_SIZE);
  sha512_update(&ctx, inner_hash, SHA512_DIGEST_LENGTH);
  sha512_final(&ctx, mac);

  memset(key_block, 0, sizeof(key_block));
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  memset(inner_hash, 0, sizeof(inner_hash));
}
