#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
  uint8_t opaque[200];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[SHA256_DIGEST_LENGTH]);

void sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
